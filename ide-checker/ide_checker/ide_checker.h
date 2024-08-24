/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#ifndef __IDE_CHECKER_H__
#define __IDE_CHECKER_H__

#include "base.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_secured_message.h"

#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"
#include "library/spdm_crypt_lib.h"

#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"
#include "hal/library/cryptlib.h"

#include "os_include.h"
#include <stddef.h>
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

/* PCIE/CXL spec begin */
#define AES_GCM_32_KEY_SIZE 32
#define AES_GCM_32_IV_SIZE 12
#define AES_GCM_32_MAC_SIZE_IDE 12
/* PCIE/CXL spec end */

/* CXL spec begin */
#define CXL_FLIT_68B_FLIT_SIZE 64
#define CXL_FLIT_68B_FLIT_HEADER_SIZE 4
#define CXL_FLIT_68B_FLIT_BODY_SIZE (CXL_FLIT_68B_FLIT_SIZE - CXL_FLIT_68B_FLIT_HEADER_SIZE)
/* CXL spec end */

#define IDE_TYPE_PCIE 0
#define IDE_TYPE_CXL  1

#define IDE_ATTRIB_PARTIAL_HEADER_MODE_MASK 0xF
#define IDE_ATTRIB_PARTIAL_HEADER_MODE_0    0x0
#define IDE_ATTRIB_PARTIAL_HEADER_MODE_17   0x1
#define IDE_ATTRIB_PARTIAL_HEADER_MODE_25   0x2
#define IDE_ATTRIB_PARTIAL_HEADER_MODE_33   0x3
#define IDE_ATTRIB_PARTIAL_HEADER_MODE_41   0x4
#define IDE_ATTRIB_PCRC 0x10
#define IDE_ATTRIB_NONE_FLIT_MODE 0x20

typedef struct {
    char *name;
    uint8_t type;
    uint32_t attrib;
    uint8_t *gcm_key;
    size_t gcm_key_size;
    uint8_t *gcm_iv;
    size_t gcm_iv_size;
    uint8_t *gcm_aad;
    size_t gcm_aad_size;
    uint8_t *gcm_pt;
    size_t gcm_pt_size;
    uint8_t *gcm_ct;
    size_t gcm_ct_size;
    uint8_t *gcm_tag;
    size_t gcm_tag_size;
    size_t pcrc_partial_head_size;
} ide_test_data_t;

typedef struct {
    char *name;
    uint8_t type;
    uint32_t attrib;
    uint8_t *ide_key;
    uint8_t *ide_iv;
    uint8_t *ide_packet_pt;
    size_t ide_packet_pt_size;
    uint8_t *ide_packet_ct;
    size_t ide_packet_ct_size;
    uint8_t *ide_tag;
} ide_test_packet_data_t;

void dump_hex(const uint8_t *data, size_t size);

bool libspdm_aead_aes_gcm_decrypt_no_auth(const uint8_t *key, size_t key_size,
                                          const uint8_t *iv, size_t iv_size,
                                          const uint8_t *a_data, size_t a_data_size,
                                          const uint8_t *data_in, size_t data_in_size,
                                          uint8_t *tag_out, size_t tag_size,
                                          uint8_t *data_out, size_t *data_out_size);

extern ide_test_data_t m_test_aes_256_gcm_data;

extern ide_test_packet_data_t m_pcie_ide_nfm_wo_ph_gcm_packet_data;
extern ide_test_packet_data_t m_pcie_ide_fm_wo_ph_gcm_packet_data;
extern ide_test_packet_data_t m_pcie_ide_nfm_w_ph_gcm_packet_data;
extern ide_test_packet_data_t m_pcie_ide_fm_w_ph_gcm_packet_data;

extern ide_test_packet_data_t m_cxl_flit_68b_containment_gcm_packet_data;

extern ide_test_packet_data_t m_cxl_sim_data1_m2s_dev_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_sim_data1_s2m_dev_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_sim_data2_m2s_dev_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_sim_data2_s2m_dev_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_sim_data3_m2s_dev_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_sim_data3_s2m_dev_gcm_packet_data;

extern ide_test_packet_data_t m_cxl_sim_data1_m2s_pcrc_dev_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_sim_data1_s2m_pcrc_dev_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_sim_data2_m2s_pcrc_dev_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_sim_data2_s2m_pcrc_dev_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_sim_data3_m2s_pcrc_dev_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_sim_data3_s2m_pcrc_dev_gcm_packet_data;

extern ide_test_packet_data_t m_cxl_trace_data1_m2s_containment_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data1_s2m_containment_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data2_m2s_containment_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data2_s2m_containment_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data3_m2s_containment_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data3_s2m_containment_gcm_packet_data;

extern ide_test_packet_data_t m_cxl_trace_data1_m2s_skid_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data1_s2m_skid_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data2_m2s_skid_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data2_s2m_skid_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data3_m2s_skid_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data1_m2s_skid2_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data1_s2m_skid2_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data2_m2s_skid2_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data2_s2m_skid2_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data3_m2s_skid2_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data3_s2m_skid2_gcm_packet_data;
extern ide_test_packet_data_t m_cxl_trace_data4_s2m_skid2_gcm_packet_data;

ide_test_data_t *ide_test_data_create_from_packet(
    const ide_test_packet_data_t *ide_test_packet_data
    );
void ide_test_data_delete(
    ide_test_data_t *ide_test_data
    );

uint8_t pcie_partial_header_mode_to_cipher_byte_size (uint8_t mode);
uint64_t pcie_partial_header_mode_to_cipher_addr_mask (uint8_t mode);
uint8_t pcie_partial_header_mode_to_cipher_addr_offset (uint8_t mode);
uint64_t pcie_partial_header_mode_to_plain_addr_mask (uint8_t mode);

bool pcie_is_ide_tlp (bool is_nfm, const uint8_t *tlp);
uint16_t pcie_tlp_header_length (bool is_nfm, const uint8_t *tlp);
size_t pcie_tlp_address_offset (bool is_nfm, const uint8_t *tlp);
size_t pcie_tlp_last_first_dw_offset (bool is_nfm, const uint8_t *tlp);
size_t pcie_tlp_last_first_dw_size (bool is_nfm, const uint8_t *tlp);
uint16_t pcie_tlp_payload_length (bool is_nfm, const uint8_t *tlp);

bool test_aes_256_gcm(const ide_test_data_t *test_data);

bool test_aes_256_gcm_pcie_pcrc(const ide_test_data_t *test_data);
bool test_aes_256_gcm_cxl_pcrc(const ide_test_data_t *test_data);

uint32_t pcie_calc_pcrc (uint8_t *data, size_t data_size);
uint32_t cxl_calc_pcrc (uint8_t *data, size_t data_size);

#endif
