// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#include "tunnel_protocol.hpp"

#include <rohccxx.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace
{
volatile sig_atomic_t stopping = 0;

void stop_handler(int) { stopping = 1; }

struct CompDelete { void operator()(rohc_comp* p) const { rohc_comp_free(p); } };
struct DecompDelete { void operator()(rohc_decomp* p) const { rohc_decomp_free(p); } };
using CompPtr = std::unique_ptr<rohc_comp, CompDelete>;
using DecompPtr = std::unique_ptr<rohc_decomp, DecompDelete>;

struct Config
{
    std::string tun_name;
    sockaddr_in local{};
    sockaddr_in peer{};
    std::size_t maximum_packet = 65507U - rohccxx::tun::envelope_size;
    unsigned statistics_interval = 5U;
};

struct Statistics
{
    std::uint64_t tx_packets = 0, rx_packets = 0;
    std::uint64_t original_inner_bytes = 0, rohc_compressed_bytes = 0;
    std::uint64_t complete_tunnel_bytes = 0;
    std::uint64_t drops = 0, malformed = 0;
    std::uint64_t compression_failures = 0, decompression_failures = 0;
    std::uint64_t feedback_sent = 0, feedback_received = 0;
    std::uint64_t flow_assignments = 0, active_contexts = 0, evictions = 0;
    std::uint64_t context_resets = 0, mapping_failures = 0;
};

void usage(const char* program)
{
    std::fprintf(stderr,
        "Usage: %s --tun NAME --local IPv4:PORT --peer IPv4:PORT "
        "[--max-packet BYTES] [--stats-interval SECONDS]\n", program);
}

bool parse_endpoint(const char* text, sockaddr_in& endpoint)
{
    if(!text)
        return false;
    const std::string value(text);
    const std::size_t colon = value.rfind(':');
    if(colon == std::string::npos || colon == 0U || colon + 1U == value.size())
        return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long port = std::strtoul(value.c_str() + colon + 1U, &end, 10);
    if(errno != 0 || !end || *end != '\0' || port == 0U || port > 65535U)
        return false;
    endpoint = {};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(static_cast<std::uint16_t>(port));
    return inet_pton(AF_INET, value.substr(0U, colon).c_str(), &endpoint.sin_addr) == 1;
}

bool parse_size(const char* text, std::size_t minimum, std::size_t maximum,
                std::size_t& output)
{
    if(!text)
        return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long long value = std::strtoull(text, &end, 10);
    if(errno != 0 || !end || *end != '\0' || value < minimum || value > maximum)
        return false;
    output = static_cast<std::size_t>(value);
    return true;
}

bool parse_arguments(int argc, char** argv, Config& config)
{
    bool have_local = false, have_peer = false;
    static const option options[] = {
        {"tun", required_argument, nullptr, 't'},
        {"local", required_argument, nullptr, 'l'},
        {"peer", required_argument, nullptr, 'p'},
        {"max-packet", required_argument, nullptr, 'm'},
        {"stats-interval", required_argument, nullptr, 's'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };
    for(;;)
    {
        const int selected = getopt_long(argc, argv, "t:l:p:m:s:h", options, nullptr);
        if(selected == -1)
            break;
        std::size_t value = 0U;
        switch(selected)
        {
        case 't': config.tun_name = optarg; break;
        case 'l': have_local = parse_endpoint(optarg, config.local); if(!have_local) return false; break;
        case 'p': have_peer = parse_endpoint(optarg, config.peer); if(!have_peer) return false; break;
        case 'm':
            if(!parse_size(optarg, 68U, 65507U - rohccxx::tun::envelope_size, value)) return false;
            config.maximum_packet = value;
            break;
        case 's':
            if(!parse_size(optarg, 1U, 86400U, value)) return false;
            config.statistics_interval = static_cast<unsigned>(value);
            break;
        case 'h': usage(argv[0]); std::exit(0);
        default: return false;
        }
    }
    return optind == argc && !config.tun_name.empty() &&
           config.tun_name.size() < IFNAMSIZ && have_local && have_peer;
}

int open_tun(const std::string& requested, std::string& actual)
{
    const int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if(fd < 0)
        return -1;
    ifreq request{};
    request.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI);
    std::strncpy(request.ifr_name, requested.c_str(), IFNAMSIZ - 1U);
    if(ioctl(fd, TUNSETIFF, &request) < 0)
    {
        close(fd);
        return -1;
    }
    actual = request.ifr_name;
    return fd;
}

struct CodecContext
{
    std::array<CompPtr, 16>* compressors;
    rohc_comp* selected_comp;
    rohc_decomp* decomp;
    Statistics* stats;
};

int decompress_adapter(void* context, const std::uint8_t* in, std::size_t in_len,
                       std::uint8_t* out, std::size_t* out_len)
{
    return rohc_decompress4(static_cast<CodecContext*>(context)->decomp,
                            in, in_len, out, out_len);
}

int compress_combined_adapter(void* context, const std::uint8_t* in, std::size_t in_len,
                              std::uint8_t* out, std::size_t* out_len)
{
    return rohc_compress4(static_cast<CodecContext*>(context)->selected_comp,
                          in, in_len, out, out_len);
}

void feedback_adapter(void* context, std::uint32_t cid, std::uint8_t type)
{
    auto& state = *static_cast<CodecContext*>(context);
    if(cid >= state.compressors->size() || !(*state.compressors)[cid])
        ++state.stats->mapping_failures;
    else
        rohc_comp_handle_feedback((*state.compressors)[cid].get(), cid, type);
}

bool write_all_packet(int fd, const std::uint8_t* data, std::size_t length)
{
    const ssize_t written = write(fd, data, length);
    return written >= 0 && static_cast<std::size_t>(written) == length;
}

bool send_datagram(int fd, const std::uint8_t* data, std::size_t length)
{
    const ssize_t sent = send(fd, data, length, 0);
    return sent >= 0 && static_cast<std::size_t>(sent) == length;
}

void account_tunnel(Statistics& stats, std::size_t datagram_len)
{
    stats.complete_tunnel_bytes += datagram_len + rohccxx::tun::estimated_outer_ipv4_udp_size;
}

void print_statistics(const Statistics& s)
{
    const double reduction = s.original_inner_bytes == 0U ? 0.0 :
        100.0 * (1.0 - static_cast<double>(s.rohc_compressed_bytes) /
                        static_cast<double>(s.original_inner_bytes));
    std::fprintf(stderr,
        "stats tx_packets=%llu rx_packets=%llu inner_bytes=%llu rohc_bytes=%llu "
        "complete_udp_tunnel_bytes=%llu compression_reduction=%.2f%% drops=%llu "
        "malformed=%llu compression_failures=%llu decompression_failures=%llu "
        "feedback_sent=%llu feedback_received=%llu flow_assignments=%llu "
        "active_contexts=%llu evictions=%llu resets=%llu mapping_failures=%llu\n",
        static_cast<unsigned long long>(s.tx_packets),
        static_cast<unsigned long long>(s.rx_packets),
        static_cast<unsigned long long>(s.original_inner_bytes),
        static_cast<unsigned long long>(s.rohc_compressed_bytes),
        static_cast<unsigned long long>(s.complete_tunnel_bytes), reduction,
        static_cast<unsigned long long>(s.drops),
        static_cast<unsigned long long>(s.malformed),
        static_cast<unsigned long long>(s.compression_failures),
        static_cast<unsigned long long>(s.decompression_failures),
        static_cast<unsigned long long>(s.feedback_sent),
        static_cast<unsigned long long>(s.feedback_received),
        static_cast<unsigned long long>(s.flow_assignments),
        static_cast<unsigned long long>(s.active_contexts),
        static_cast<unsigned long long>(s.evictions),
        static_cast<unsigned long long>(s.context_resets),
        static_cast<unsigned long long>(s.mapping_failures));
}
}

int main(int argc, char** argv)
{
    Config config{};
    if(!parse_arguments(argc, argv, config))
    {
        usage(argv[0]);
        return 2;
    }
    std::string actual_tun;
    const int tun_fd = open_tun(config.tun_name, actual_tun);
    if(tun_fd < 0)
    {
        std::perror("open/configure TUN");
        return 1;
    }
    const int udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if(udp_fd < 0 || bind(udp_fd, reinterpret_cast<const sockaddr*>(&config.local), sizeof(config.local)) < 0 ||
       connect(udp_fd, reinterpret_cast<const sockaddr*>(&config.peer), sizeof(config.peer)) < 0)
    {
        std::perror("configure UDP socket");
        if(udp_fd >= 0) close(udp_fd);
        close(tun_fd);
        return 1;
    }

    DecompPtr decomp(rohc_decomp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
    if(!decomp)
    {
        std::fprintf(stderr, "failed to initialize ROHCCXX contexts\n");
        close(udp_fd); close(tun_fd); return 1;
    }
    std::array<CompPtr, 16> compressors{};
    rohccxx::tun::FlowTable flows;
    Statistics stats{};
    CodecContext codec_context{&compressors, nullptr, decomp.get(), &stats};
    const rohccxx::tun::Codec codec{&codec_context, compress_combined_adapter,
                                    decompress_adapter, feedback_adapter};
    const std::size_t datagram_capacity = 65507U;
    std::vector<std::uint8_t> inner(config.maximum_packet);
    std::vector<std::uint8_t> compressed(65535U);
    std::vector<std::uint8_t> datagram(datagram_capacity + 1U);
    std::vector<std::uint8_t> feedback_payload(rohccxx::tun::feedback_payload_size);

    struct sigaction action{};
    action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);
    auto next_stats = std::chrono::steady_clock::now() +
        std::chrono::seconds(config.statistics_interval);
    std::fprintf(stderr, "ready tun=%s (no encryption)\n", actual_tun.c_str());

    while(!stopping)
    {
        pollfd fds[2] = {{tun_fd, POLLIN, 0}, {udp_fd, POLLIN, 0}};
        const int ready = poll(fds, 2, 250);
        if(ready < 0 && errno != EINTR) { std::perror("poll"); break; }
        if((fds[0].revents | fds[1].revents) & (POLLERR | POLLHUP | POLLNVAL))
        {
            std::fprintf(stderr, "poll reported an endpoint error\n");
            break;
        }
        if(fds[0].revents & POLLIN)
        {
            const ssize_t count = read(tun_fd, inner.data(), inner.size());
            if(count <= 0) { ++stats.drops; }
            else
            {
                rohccxx::tun::FlowAssignment assignment{};
                const auto mapping = flows.select(inner.data(), static_cast<std::size_t>(count), assignment);
                if(mapping != rohccxx::tun::Result::Ok)
                {
                    ++stats.drops; ++stats.mapping_failures;
                    continue;
                }
                stats.flow_assignments = flows.assignments();
                stats.active_contexts = flows.active_contexts();
                stats.evictions = flows.evictions();
                if(assignment.newly_assigned)
                {
                    CompPtr replacement(rohc_comp_new2(15U, ROHCCXX_DIRECTION_UPLINK));
                    if(!replacement || rohc_comp_set_cid(replacement.get(), assignment.cid) != 0)
                    {
                        ++stats.drops; ++stats.mapping_failures;
                        continue;
                    }
                    compressors[assignment.cid] = std::move(replacement);
                    if(assignment.evicted) ++stats.context_resets;
                }
                codec_context.selected_comp = compressors[assignment.cid].get();
                std::size_t rohc_len = 0U, frame_len = 0U;
                const auto result = rohccxx::tun::prepare_compressed_datagram(
                    codec, inner.data(), static_cast<std::size_t>(count),
                    config.maximum_packet, compressed.data(), compressed.size(),
                    datagram.data(), datagram_capacity, rohc_len, frame_len);
                if(result != rohccxx::tun::Result::Ok)
                {
                    ++stats.drops;
                    if(result == rohccxx::tun::Result::CodecFailure) ++stats.compression_failures;
                    else ++stats.malformed;
                }
                else if(!send_datagram(udp_fd, datagram.data(), frame_len))
                    ++stats.drops;
                else
                {
                    ++stats.tx_packets;
                    stats.original_inner_bytes += static_cast<std::size_t>(count);
                    stats.rohc_compressed_bytes += rohc_len;
                    account_tunnel(stats, frame_len);
                }
            }
        }
        if(fds[1].revents & POLLIN)
        {
            iovec iov{datagram.data(), datagram.size()};
            msghdr message{}; message.msg_iov = &iov; message.msg_iovlen = 1U;
            const ssize_t count = recvmsg(udp_fd, &message, MSG_TRUNC);
            if(count <= 0 || (message.msg_flags & MSG_TRUNC) != 0 ||
               static_cast<std::size_t>(count) > datagram_capacity)
            {
                ++stats.drops; ++stats.malformed;
            }
            else
            {
                std::size_t inner_len = 0U;
                rohccxx::tun::MessageType type{};
                const auto result = rohccxx::tun::consume_datagram(
                    codec, datagram.data(), static_cast<std::size_t>(count),
                    config.maximum_packet, inner.data(), inner.size(), inner_len, type);
                if(result == rohccxx::tun::Result::Ok && type == rohccxx::tun::MessageType::Feedback)
                {
                    ++stats.feedback_received;
                }
                else if(result == rohccxx::tun::Result::Ok && write_all_packet(tun_fd, inner.data(), inner_len))
                {
                    ++stats.rx_packets;
                }
                else
                {
                    ++stats.drops;
                    if(result == rohccxx::tun::Result::CodecFailure)
                    {
                        ++stats.decompression_failures;
                        if(rohc_decomp_has_feedback(decomp.get()) == 1)
                        {
                            std::uint32_t cid = 0U; std::uint8_t feedback_type = 0U;
                            std::size_t payload_len = 0U, frame_len = 0U;
                            if(rohc_decomp_get_feedback(decomp.get(), &cid, &feedback_type) == 0 &&
                               rohccxx::tun::encode_feedback(cid, feedback_type,
                                   feedback_payload.data(), feedback_payload.size(), payload_len) == rohccxx::tun::Result::Ok &&
                               rohccxx::tun::encode_frame(rohccxx::tun::MessageType::Feedback,
                                   feedback_payload.data(), payload_len, datagram.data(),
                                   datagram_capacity, frame_len) == rohccxx::tun::Result::Ok &&
                               send_datagram(udp_fd, datagram.data(), frame_len))
                            {
                                ++stats.feedback_sent; account_tunnel(stats, frame_len);
                            }
                        }
                    }
                    else ++stats.malformed;
                }
            }
        }
        if(std::chrono::steady_clock::now() >= next_stats)
        {
            print_statistics(stats);
            next_stats = std::chrono::steady_clock::now() +
                std::chrono::seconds(config.statistics_interval);
        }
    }
    print_statistics(stats);
    close(udp_fd);
    close(tun_fd);
    return 0;
}
