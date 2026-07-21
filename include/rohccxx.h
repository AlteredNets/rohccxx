// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

#ifndef ROHCCXX_H
#define ROHCCXX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#include <rohccxx/version.h>

/*
 * Symbol visibility & ABI control
 *
 * - ROHCCXX_API   : exported symbols
 * - ROHCCXX_LOCAL : internal symbols (not exported)
 */
#if defined(_WIN32) || defined(_WIN64)

# ifdef ROHCCXX_BUILD_DLL
#  define ROHCCXX_API   __declspec(dllexport)
# else
#  define ROHCCXX_API   __declspec(dllimport)
# endif
# define ROHCCXX_LOCAL

#else /* ELF platforms */

# if __GNUC__ >= 4
#  define ROHCCXX_API   __attribute__((visibility("default")))
#  define ROHCCXX_LOCAL __attribute__((visibility("hidden")))
# else
#  define ROHCCXX_API
#  define ROHCCXX_LOCAL
# endif

#endif

/*
 * ABI policy:
 * - C API only
 * - No struct layout exposed
 * - No STL types
 */

struct rohc_comp;
struct rohc_decomp;

typedef enum
{
    ROHCCXX_DIRECTION_UPLINK   = 0,
    ROHCCXX_DIRECTION_DOWNLINK = 1
} rohccxx_direction_t;

typedef enum
{
    ROHCCXX_MODE_U = 0,
    ROHCCXX_MODE_O = 1,
    ROHCCXX_MODE_R = 2
} rohccxx_mode_t;


#define ROHCCXX_PROFILE_UNCOMPRESSED 0x0000
#define ROHCCXX_PROFILE_LLA_RTP 0x0005
#define ROHCCXX_PROFILE_RTP 0x0101
#define ROHCCXX_PROFILE_UDP 0x0102
#define ROHCCXX_PROFILE_ESP 0x0103
#define ROHCCXX_PROFILE_IP 0x0104
#define ROHCCXX_PROFILE_RTP_UDP_LITE 0x0107
#define ROHCCXX_PROFILE_UDP_LITE 0x0108

#define ROHCCXX_PPP_MAX_PROFILES 16


#define ROHCCXX_ROHCOIPSEC_MAX_PROFILES 16
#define ROHCCXX_ROHCOIPSEC_MAX_INTEGRITY_ALGORITHMS 8
#define ROHCCXX_ROHCOIPSEC_PROTOCOL_NUMBER 142
#define ROHCCXX_ROHCOIPSEC_KEY_MAX 128
#define ROHCCXX_IPPROTO_ESP 50
#define ROHCCXX_IPPROTO_AH 51

typedef enum
{
    ROHCCXX_ROHCOIPSEC_INTEGRITY_NONE = 0,
    ROHCCXX_ROHCOIPSEC_INTEGRITY_HMAC_SHA256 = 12
} rohccxx_rohcoipsec_integrity_t;

typedef struct
{
    int identifies_packet_types;
    int preserves_order;
    int reports_loss;
    int reports_residual_errors;
    int delivers_feedback;
    int protects_context_packets;
    int supports_context_synchronization;
    int supports_context_check;
    int supports_reliable_mode;
    int delivers_ack;
    int delivers_static_nack;
} rohccxx_lla_contract_t;

typedef struct
{
    int ipv4_udp_rtp;
    int udp_checksum_disabled;
    int rtp_sequence_increments_by_one;
    int compressor_observed_in_order;
    int synchronized_timing;
} rohccxx_lla_flow_t;


#define ROHCCXX_LLA_MISSING_PACKET_TYPE_IDENTIFICATION (1u << 0u)
#define ROHCCXX_LLA_MISSING_IN_ORDER_DELIVERY (1u << 1u)
#define ROHCCXX_LLA_MISSING_LOSS_INDICATION (1u << 2u)
#define ROHCCXX_LLA_MISSING_RESIDUAL_ERROR_INDICATION (1u << 3u)
#define ROHCCXX_LLA_MISSING_FEEDBACK_DELIVERY (1u << 4u)
#define ROHCCXX_LLA_MISSING_CONTEXT_PACKET_PROTECTION (1u << 5u)
#define ROHCCXX_LLA_MISSING_CONTEXT_SYNCHRONIZATION (1u << 6u)
#define ROHCCXX_LLA_MISSING_CONTEXT_CHECK (1u << 7u)
#define ROHCCXX_LLA_MISSING_RELIABLE_MODE (1u << 8u)
#define ROHCCXX_LLA_MISSING_ACK_DELIVERY (1u << 9u)
#define ROHCCXX_LLA_MISSING_STATIC_NACK_DELIVERY (1u << 10u)
#define ROHCCXX_LLA_MISSING_IPV4_UDP_RTP_FLOW (1u << 11u)
#define ROHCCXX_LLA_MISSING_DISABLED_UDP_CHECKSUM (1u << 12u)
#define ROHCCXX_LLA_MISSING_RTP_SEQUENCE_PROGRESSION (1u << 13u)
#define ROHCCXX_LLA_MISSING_COMPRESSOR_SIDE_ORDERING (1u << 14u)
#define ROHCCXX_LLA_MISSING_SYNCHRONIZED_TIMING (1u << 15u)
#define ROHCCXX_LLA_PACKET_NHP 0xF9
#define ROHCCXX_LLA_PACKET_CSP 0xFA
#define ROHCCXX_LLA_PACKET_CCP 0xFB

typedef struct
{
    uint16_t max_cid;
    uint16_t profiles[ROHCCXX_ROHCOIPSEC_MAX_PROFILES];
    size_t profile_count;
    uint16_t integrity_algorithms[ROHCCXX_ROHCOIPSEC_MAX_INTEGRITY_ALGORITHMS];
    size_t integrity_algorithm_count;
    uint16_t icv_len;
    int has_icv_len;
    uint16_t mrru;
    int has_mrru;
} rohccxx_rohcoipsec_channel_t;

typedef struct
{
    uint16_t max_cid;
    uint16_t mrru;
    uint16_t max_header;
    uint16_t profiles[ROHCCXX_PPP_MAX_PROFILES];
    size_t profile_count;
} rohccxx_ppp_rohc_option_t;


typedef struct
{
    uint16_t max_cid;
    int large_cids;
    uint16_t integrity_algorithm;
    uint16_t icv_len;
    uint16_t mrru;
    int has_mrru;
    uint8_t key[ROHCCXX_ROHCOIPSEC_KEY_MAX];
    size_t key_len;
    uint32_t feedback_for;
    int has_feedback_for;
} rohccxx_rohcoipsec_sa_t;


ROHCCXX_API const char*
rohccxx_version_string(void);

ROHCCXX_API unsigned
rohccxx_version_major(void);

ROHCCXX_API unsigned
rohccxx_version_minor(void);

ROHCCXX_API unsigned
rohccxx_version_patch(void);


ROHCCXX_API int
rohc_profile_is_supported(uint16_t profile);

ROHCCXX_API int
rohc_profile_is_rohcv2(uint16_t profile);

ROHCCXX_API int
rohc_ppp_is_rohc_protocol(uint16_t protocol);

ROHCCXX_API int
rohc_ppp_uses_large_cid_protocol(uint16_t protocol);

ROHCCXX_API int
rohc_ppp_validate_rohc_option(const rohccxx_ppp_rohc_option_t* option);

ROHCCXX_API int
rohc_ppp_write_rohc_option(const rohccxx_ppp_rohc_option_t* option,
                           uint8_t* out,
                           size_t* out_len);

ROHCCXX_API int
rohc_ppp_parse_rohc_option(const uint8_t* data,
                           size_t data_len,
                           rohccxx_ppp_rohc_option_t* option);

ROHCCXX_API int
rohc_ppp_merge_rohc_options(const rohccxx_ppp_rohc_option_t* a,
                            const rohccxx_ppp_rohc_option_t* b,
                            rohccxx_ppp_rohc_option_t* merged);

ROHCCXX_API int
rohc_lla_validate_rfc3243_zero_byte_assumptions(const rohccxx_lla_contract_t* contract,
                                                uint32_t* missing);

ROHCCXX_API int
rohc_lla_validate_rfc3243_zero_byte_flow(const rohccxx_lla_contract_t* contract,
                                         const rohccxx_lla_flow_t* flow,
                                         uint32_t* missing);

ROHCCXX_API int
rohc_lla_validate_rfc3408_r_mode_zero_byte_support(const rohccxx_lla_contract_t* contract,
                                                   uint32_t* missing);

ROHCCXX_API int
rohc_lla_validate_rfc3409_lower_layer_guidelines(const rohccxx_lla_contract_t* contract,
                                                 uint32_t* missing);

ROHCCXX_API int
rohc_lla_can_emit_no_header_packet(const rohccxx_lla_contract_t* contract);

ROHCCXX_API int
rohc_lla_can_emit_no_header_packet_for_flow(const rohccxx_lla_contract_t* contract,
                                            const rohccxx_lla_flow_t* flow);

ROHCCXX_API int
rohc_lla_can_emit_reliable_mode_no_header_packet(const rohccxx_lla_contract_t* contract);

ROHCCXX_API int
rohc_lla_can_emit_context_synchronization_packet(const rohccxx_lla_contract_t* contract);

ROHCCXX_API int
rohc_lla_can_emit_context_check_packet(const rohccxx_lla_contract_t* contract);

ROHCCXX_API uint8_t
rohc_rohcoipsec_protocol_number(void);

ROHCCXX_API int
rohc_rohcoipsec_write_supported(const rohccxx_rohcoipsec_channel_t* params,
                                uint8_t* out,
                                size_t* out_len);

ROHCCXX_API int
rohc_rohcoipsec_parse_supported(const uint8_t* data,
                                size_t data_len,
                                rohccxx_rohcoipsec_channel_t* params);

ROHCCXX_API int
rohc_rohcoipsec_negotiate(const rohccxx_rohcoipsec_channel_t* local,
                          const rohccxx_rohcoipsec_channel_t* peer,
                          rohccxx_rohcoipsec_channel_t* negotiated);


ROHCCXX_API int
rohc_rohcoipsec_append_icv(uint16_t algorithm,
                           const uint8_t* key,
                           size_t key_len,
                           const uint8_t* authenticated_packet,
                           size_t authenticated_packet_len,
                           const uint8_t* rohc_packet,
                           size_t rohc_packet_len,
                           uint8_t* out,
                           size_t* out_len,
                           size_t icv_len);

ROHCCXX_API int
rohc_rohcoipsec_strip_verify_icv(uint16_t algorithm,
                                 const uint8_t* key,
                                 size_t key_len,
                                 const uint8_t* authenticated_packet,
                                 size_t authenticated_packet_len,
                                 const uint8_t* rohcoipsec_packet,
                                 size_t rohcoipsec_packet_len,
                                 uint8_t* rohc_packet,
                                 size_t* rohc_packet_len,
                                 size_t icv_len);


ROHCCXX_API int
rohc_rohcoipsec_derive_directional_keys(const uint8_t* keymat,
                                        size_t keymat_len,
                                        size_t key_len,
                                        uint8_t* outbound_key,
                                        size_t* outbound_key_len,
                                        uint8_t* inbound_key,
                                        size_t* inbound_key_len);

ROHCCXX_API int
rohc_rohcoipsec_build_sa(const rohccxx_rohcoipsec_channel_t* negotiated,
                         uint16_t integrity_algorithm,
                         const uint8_t* key,
                         size_t key_len,
                         uint32_t feedback_for,
                         int has_feedback_for,
                         rohccxx_rohcoipsec_sa_t* sa);

ROHCCXX_API uint8_t
rohc_rohcoipsec_security_next_header(uint8_t original_next_header,
                                     int compressed);

ROHCCXX_API uint8_t
rohc_rohcoipsec_outbound_next_header(int compressed);

ROHCCXX_API int
rohc_rohcoipsec_inbound_requires_decompression(uint8_t next_header);


/* ---- Compressor API ---- */

ROHCCXX_API void
rohc_comp_handle_feedback(struct rohc_comp* comp,
                          uint32_t cid,
                          uint8_t feedback_type);

ROHCCXX_API int
rohc_comp_deliver_feedback_packet(struct rohc_comp* comp,
                                  const uint8_t* packet,
                                  size_t packet_len);

ROHCCXX_API int
rohc_comp_set_mode(struct rohc_comp* comp,
                   rohccxx_mode_t mode);

ROHCCXX_API int
rohc_comp_get_mode(const struct rohc_comp* comp,
                   rohccxx_mode_t* mode);

/* Configure RFC 5795 segmentation MRRU. Use 0 to disable segmentation. */
ROHCCXX_API int
rohc_comp_set_mrru(struct rohc_comp* comp,
                   size_t mrru);

/* Returns 1 when additional segmented output is pending after rohc_compress4. */
ROHCCXX_API int
rohc_comp_has_segment(const struct rohc_comp* comp);

/* Retrieves the next pending RFC 5795 segment packet. */
ROHCCXX_API int
rohc_comp_get_segment(struct rohc_comp* comp,
                      uint8_t* rohc_packet,
                      size_t* rohc_packet_len);

ROHCCXX_API struct rohc_comp*
rohc_comp_new2(uint32_t max_cid,
               rohccxx_direction_t direction);

ROHCCXX_API int
rohc_comp_set_cid(struct rohc_comp* comp,
                  uint32_t cid);

/* Enables RFC 5858 ROHCoIPsec payload processing with NONE integrity. */
ROHCCXX_API int
rohc_comp_enable_rohcoipsec(struct rohc_comp* comp);


ROHCCXX_API int
rohc_comp_set_rohcoipsec_integrity(struct rohc_comp* comp,
                                   uint16_t algorithm,
                                   const uint8_t* key,
                                   size_t key_len,
                                   size_t icv_len);

ROHCCXX_API uint8_t
rohc_comp_rohcoipsec_next_header(const struct rohc_comp* comp);


ROHCCXX_API int
rohc_comp_apply_rohcoipsec_sa(struct rohc_comp* comp,
                              const rohccxx_rohcoipsec_sa_t* sa);


ROHCCXX_API int
rohc_comp_enable_rfc4362_lla(struct rohc_comp* comp,
                             const rohccxx_lla_contract_t* contract,
                             const rohccxx_lla_flow_t* flow);

ROHCCXX_API int
rohc_comp_rfc4362_emit_nhp(struct rohc_comp* comp,
                           const uint8_t* ip_packet,
                           size_t ip_packet_len,
                           uint8_t* rohc_packet,
                           size_t* rohc_packet_len);

ROHCCXX_API int
rohc_comp_rfc4362_emit_csp(struct rohc_comp* comp,
                           const uint8_t* ip_packet,
                           size_t ip_packet_len,
                           uint8_t* csp_packet,
                           size_t* csp_packet_len);

ROHCCXX_API int
rohc_comp_rfc4362_emit_ccp(struct rohc_comp* comp,
                           uint8_t* ccp_packet,
                           size_t* ccp_packet_len);


ROHCCXX_API void
rohc_comp_free(struct rohc_comp* comp);

ROHCCXX_API int
rohc_compress4(struct rohc_comp* comp,
               const uint8_t* ip_packet,
               size_t ip_packet_len,
               uint8_t* rohc_packet,
               size_t* rohc_packet_len);

/* ---- Decompressor API ---- */

// Returns 1 if feedback is available, 0 otherwise
ROHCCXX_API int
rohc_decomp_has_feedback(const struct rohc_decomp* decomp);

// Retrieves last feedback; returns 0 on success, -1 if none available
ROHCCXX_API int
rohc_decomp_get_feedback(const struct rohc_decomp* decomp,
                          uint32_t* cid,
                          uint8_t* feedback_type);

ROHCCXX_API struct rohc_decomp*
rohc_decomp_new2(uint32_t max_cid,
                 rohccxx_direction_t direction);

ROHCCXX_API int
rohc_decomp_set_mode(struct rohc_decomp* decomp,
                     rohccxx_mode_t mode);

ROHCCXX_API int
rohc_decomp_get_mode(const struct rohc_decomp* decomp,
                     rohccxx_mode_t* mode);

/* Configure RFC 5795 segmentation MRRU. Use 0 to disable reassembly. */
ROHCCXX_API int
rohc_decomp_set_mrru(struct rohc_decomp* decomp,
                     size_t mrru);

/* Enables RFC 5858 ROHCoIPsec payload processing with NONE integrity. */
ROHCCXX_API int
rohc_decomp_enable_rohcoipsec(struct rohc_decomp* decomp);


ROHCCXX_API int
rohc_decomp_set_rohcoipsec_integrity(struct rohc_decomp* decomp,
                                     uint16_t algorithm,
                                     const uint8_t* key,
                                     size_t key_len,
                                     size_t icv_len);

ROHCCXX_API int
rohc_decomp_rohcoipsec_requires_decompression(const struct rohc_decomp* decomp,
                                              uint8_t next_header);


ROHCCXX_API int
rohc_decomp_apply_rohcoipsec_sa(struct rohc_decomp* decomp,
                                const rohccxx_rohcoipsec_sa_t* sa);


ROHCCXX_API int
rohc_decomp_enable_rfc4362_lla(struct rohc_decomp* decomp,
                               const rohccxx_lla_contract_t* contract,
                               const rohccxx_lla_flow_t* flow);

ROHCCXX_API int
rohc_decomp_rfc4362_receive_nhp(struct rohc_decomp* decomp,
                                const uint8_t* payload,
                                size_t payload_len,
                                uint8_t* ip_packet,
                                size_t* ip_packet_len);

ROHCCXX_API int
rohc_decomp_rfc4362_receive_nhp_for_cid(struct rohc_decomp* decomp,
                                        uint32_t cid,
                                        const uint8_t* payload,
                                        size_t payload_len,
                                        uint8_t* ip_packet,
                                        size_t* ip_packet_len);

ROHCCXX_API int
rohc_decomp_rfc4362_receive_csp(struct rohc_decomp* decomp,
                                const uint8_t* csp_packet,
                                size_t csp_packet_len,
                                uint8_t* ip_packet,
                                size_t* ip_packet_len);

ROHCCXX_API int
rohc_decomp_rfc4362_receive_ccp(struct rohc_decomp* decomp,
                                const uint8_t* ccp_packet,
                                size_t ccp_packet_len);

ROHCCXX_API int
rohc_decomp_rfc4362_receive_ccp_for_cid(struct rohc_decomp* decomp,
                                        uint32_t cid,
                                        const uint8_t* ccp_packet,
                                        size_t ccp_packet_len);

ROHCCXX_API int
rohc_decomp_rfc4362_report_loss(struct rohc_decomp* decomp,
                                uint32_t cid);

ROHCCXX_API int
rohc_decomp_rfc4362_report_residual_error(struct rohc_decomp* decomp,
                                          uint32_t cid);


ROHCCXX_API void
rohc_decomp_free(struct rohc_decomp* decomp);

/*
 * Decompress one ROHC packet. Returns 0 when an IP packet is produced,
 * 1 when an RFC 5795 segmented packet was accepted and more segments are
 * required, and -1 on malformed input or failed decompression.
 */
ROHCCXX_API int
rohc_decompress4(struct rohc_decomp* decomp,
                 const uint8_t* rohc_packet,
                 size_t rohc_packet_len,
                 uint8_t* ip_packet,
                 size_t* ip_packet_len);

#ifdef __cplusplus
}
#endif

#endif /* ROHCCXX_H */