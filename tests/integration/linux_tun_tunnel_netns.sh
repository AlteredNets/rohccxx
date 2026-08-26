#!/usr/bin/env bash
# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

set -euo pipefail

tunnel=${1:?usage: linux_tun_tunnel_netns.sh /path/to/rohccxx-tun-tunnel}
if [[ $(uname -s) != Linux || ! -x ${tunnel} || ! -c /dev/net/tun ]] ||
   ! command -v ip >/dev/null || ! command -v python3 >/dev/null; then
    echo "SKIP: Linux, /dev/net/tun, iproute2, Python 3, and the tunnel executable are required"
    exit 77
fi

suffix="$$"
ns_a="rohccxx-a-${suffix}"
ns_b="rohccxx-b-${suffix}"
tmp_dir=$(mktemp -d "/tmp/rohccxx-tun-${suffix}.XXXXXX")

cleanup() {
    set +e
    [[ -n ${pid_a:-} ]] && kill "${pid_a}" 2>/dev/null
    [[ -n ${pid_b:-} ]] && kill "${pid_b}" 2>/dev/null
    [[ -n ${relay_a:-} ]] && kill "${relay_a}" 2>/dev/null
    [[ -n ${relay_b:-} ]] && kill "${relay_b}" 2>/dev/null
    ip netns del "${ns_a}" 2>/dev/null
    ip netns del "${ns_b}" 2>/dev/null
    rm -rf -- "${tmp_dir}"
}

diagnostics() {
    set +e
    echo "===== integration failure diagnostics =====" >&2
    for namespace in "${ns_a}" "${ns_b}"; do
        echo "----- ${namespace}: addresses -----" >&2
        ip -n "${namespace}" address show >&2
        echo "----- ${namespace}: routes -----" >&2
        ip -n "${namespace}" route show >&2
        echo "----- ${namespace}: UDP sockets -----" >&2
        ip netns exec "${namespace}" ss -uapn >&2
    done
    [[ -n ${pid_a:-} ]] && kill -TERM "${pid_a}" 2>/dev/null
    [[ -n ${pid_b:-} ]] && kill -TERM "${pid_b}" 2>/dev/null
    [[ -n ${pid_a:-} ]] && wait "${pid_a}" 2>/dev/null
    [[ -n ${pid_b:-} ]] && wait "${pid_b}" 2>/dev/null
    pid_a=""
    pid_b=""
    for log in a.log b.log relay-a.log relay-b.log udp-server.log udp-client.log; do
        echo "----- ${log} -----" >&2
        if [[ -e ${tmp_dir}/${log} ]]; then
            sed -n '1,240p' "${tmp_dir}/${log}" >&2
        else
            echo "missing" >&2
        fi
    done
}

finish() {
    status=$?
    trap - EXIT INT TERM
    if [[ ${status} -ne 0 ]]; then
        diagnostics
    fi
    cleanup
    exit "${status}"
}
trap finish EXIT
trap 'exit 130' INT TERM

if ! ip netns add "${ns_a}" 2>/dev/null; then
    echo "SKIP: CAP_NET_ADMIN is required for the namespace integration test"
    exit 77
fi
if ! ip netns add "${ns_b}" 2>/dev/null; then
    echo "SKIP: CAP_NET_ADMIN is required for the namespace integration test"
    exit 77
fi

ip link add "vetha${suffix}" type veth peer name "vethb${suffix}"
ip link set "vetha${suffix}" netns "${ns_a}"
ip link set "vethb${suffix}" netns "${ns_b}"
ip -n "${ns_a}" addr add 192.0.2.1/24 dev "vetha${suffix}"
ip -n "${ns_b}" addr add 192.0.2.2/24 dev "vethb${suffix}"
ip -n "${ns_a}" link set lo up
ip -n "${ns_b}" link set lo up
ip -n "${ns_a}" link set "vetha${suffix}" up
ip -n "${ns_b}" link set "vethb${suffix}" up

cat > "${tmp_dir}/relay.py" <<'PY'
import os, select, socket, sys
local_port, local_target, underlay, peer, marker, log_path = sys.argv[1:]
local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
local.bind(("127.0.0.1", int(local_port)))
transport = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host, port = underlay.rsplit(":", 1)
transport.bind((host, int(port)))
host, port = peer.rsplit(":", 1)
transport.connect((host, int(port)))
log = open(log_path, "w", buffering=1)
while True:
    readable, _, _ = select.select([local, transport], [], [])
    for source in readable:
        data = bytearray(source.recv(65535))
        if source is local:
            corrupted = False
            if os.path.exists(marker) and len(data) > 8 and data[:4] == b"RHCT" and data[5] == 1:
                data[8] ^= 1
                os.unlink(marker)
                corrupted = True
            log.write(f"local-to-underlay length={len(data)} type={data[5] if len(data) > 5 else -1} corrupted={int(corrupted)}\n")
            transport.send(data)
        else:
            log.write(f"underlay-to-local length={len(data)} type={data[5] if len(data) > 5 else -1}\n")
            local.sendto(data, ("127.0.0.1", int(local_target)))
PY

ip netns exec "${ns_a}" python3 "${tmp_dir}/relay.py" 20001 20000 192.0.2.1:10000 192.0.2.2:10000 "${tmp_dir}/corrupt-a" "${tmp_dir}/relay-a.log" &
relay_a=$!
ip netns exec "${ns_b}" python3 "${tmp_dir}/relay.py" 20001 20000 192.0.2.2:10000 192.0.2.1:10000 "${tmp_dir}/corrupt-b" "${tmp_dir}/relay-b.log" &
relay_b=$!

ip netns exec "${ns_a}" "${tunnel}" --tun rohca --local 127.0.0.1:20000 --peer 127.0.0.1:20001 --max-packet 2000 --stats-interval 1 >"${tmp_dir}/a.log" 2>&1 &
pid_a=$!
ip netns exec "${ns_b}" "${tunnel}" --tun rohcb --local 127.0.0.1:20000 --peer 127.0.0.1:20001 --max-packet 2000 --stats-interval 1 >"${tmp_dir}/b.log" 2>&1 &
pid_b=$!

for _ in $(seq 1 50); do
    ip -n "${ns_a}" link show rohca >/dev/null 2>&1 &&
    ip -n "${ns_b}" link show rohcb >/dev/null 2>&1 && break
    sleep 0.1
done
ip -n "${ns_a}" addr add 10.44.0.1/30 dev rohca
ip -n "${ns_b}" addr add 10.44.0.2/30 dev rohcb
ip -n "${ns_a}" link set rohca up mtu 1400
ip -n "${ns_b}" link set rohcb up mtu 1400

ip netns exec "${ns_a}" ping -c 2 -W 2 10.44.0.2 >/dev/null
ip netns exec "${ns_b}" ping -c 2 -W 2 10.44.0.1 >/dev/null
echo "PASS: bidirectional ping"

cat > "${tmp_dir}/udp_echo.py" <<'PY'
import hashlib, socket, sys
ready_path, log_path = sys.argv[1:]
with open(log_path, "w", buffering=1) as log:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    sock.bind(("10.44.0.2", 32123))
    open(ready_path, "w").close()
    log.write("READY\n")
    data, peer = sock.recvfrom(4096)
    log.write(f"REQUEST length={len(data)} sha256={hashlib.sha256(data).hexdigest()} peer={peer}\n")
    expected = bytes(range(256)) * 4
    if data != expected:
        raise RuntimeError("request payload mismatch")
    sent = sock.sendto(data, peer)
    log.write(f"REPLY length={sent} sha256={hashlib.sha256(data).hexdigest()}\n")
    if sent != len(data):
        raise RuntimeError("short UDP reply")
PY
cat > "${tmp_dir}/udp_client.py" <<'PY'
import hashlib, socket, sys
log_path = sys.argv[1]
payload = bytes(range(256)) * 4
with open(log_path, "w", buffering=1) as log:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    sent = sock.sendto(payload, ("10.44.0.2", 32123))
    log.write(f"REQUEST length={sent} sha256={hashlib.sha256(payload).hexdigest()}\n")
    if sent != len(payload):
        raise RuntimeError("short UDP request")
    reply, peer = sock.recvfrom(4096)
    log.write(f"REPLY length={len(reply)} sha256={hashlib.sha256(reply).hexdigest()} peer={peer}\n")
    if reply != payload:
        raise RuntimeError("reply payload mismatch")
PY

ip netns exec "${ns_b}" python3 "${tmp_dir}/udp_echo.py" "${tmp_dir}/udp-ready" "${tmp_dir}/udp-server.log" &
udp_server=$!
for _ in $(seq 1 50); do
    [[ -e ${tmp_dir}/udp-ready ]] && break
    sleep 0.1
done
if [[ ! -e ${tmp_dir}/udp-ready ]]; then
    echo "UDP echo server did not become ready" >&2
    exit 1
fi
ip netns exec "${ns_a}" python3 "${tmp_dir}/udp_client.py" "${tmp_dir}/udp-client.log"
wait "${udp_server}"
echo "PASS: byte-exact UDP payload delivery"

touch "${tmp_dir}/corrupt-a"
if ip netns exec "${ns_a}" ping -c 1 -W 1 10.44.0.2 >/dev/null 2>&1; then
    echo "corrupted compressed datagram unexpectedly delivered" >&2
    exit 1
fi
echo "PASS: corrupted compressed datagram rejected"
ip netns exec "${ns_a}" ping -c 2 -W 2 10.44.0.2 >/dev/null
echo "PASS: recovery after corrupted compressed datagram"

kill -TERM "${pid_a}" "${pid_b}"
wait "${pid_a}"
wait "${pid_b}"
pid_a=""
pid_b=""
if ! grep -Eq 'feedback_received=[1-9][0-9]*' "${tmp_dir}/a.log" ||
   ! grep -Eq 'feedback_sent=[1-9][0-9]*' "${tmp_dir}/b.log"; then
    echo "feedback was not sent and received after corruption" >&2
    exit 1
fi
echo "PASS: decompressor feedback sent and compressor feedback received"

cleanup
trap - EXIT INT TERM
namespaces=$(ip netns list)
if grep -Fq "${ns_a}" <<<"${namespaces}" || grep -Fq "${ns_b}" <<<"${namespaces}"; then
    echo "network namespace cleanup failed" >&2
    exit 1
fi
echo "PASS: processes, TUN devices, veth interfaces, and namespaces cleaned up"
