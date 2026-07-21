// Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
// See LICENSE.md for licensing details.

// tests/interop/rohc_lib_compat.h

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <rohc/rohc.h>
#include <rohc/rohc_decomp.h>

static inline rohc_status_t
rohc_decompress_compat(struct rohc_decomp *decomp,
                       const uint8_t *rohc_packet,
                       size_t rohc_len,
                       uint8_t *uncomp_packet,
                       size_t *uncomp_len)
{
    struct rohc_buf rohc_input =
        rohc_buf_init_full((uint8_t*)rohc_packet,
                           rohc_len,
                           rohc_len);

    struct rohc_buf rohc_output =
        rohc_buf_init_empty(uncomp_packet,
                            *uncomp_len);

    uint8_t feedback_storage[64] = {0};
    uint8_t crc_storage[64] = {0};
    struct rohc_buf feedback = rohc_buf_init_empty(feedback_storage,
                                                   sizeof(feedback_storage));
    struct rohc_buf crc      = rohc_buf_init_empty(crc_storage,
                                                   sizeof(crc_storage));

    rohc_status_t status =
        rohc_decompress3(decomp,
                          rohc_input,
                          &rohc_output,
                          &feedback,
                          &crc);

    *uncomp_len = rohc_output.len;
    return status;
}

#ifdef __cplusplus
}
#endif
