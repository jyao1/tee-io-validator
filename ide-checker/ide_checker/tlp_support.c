/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/test_aes_256_gcm/blob/main/LICENSE.md
 **/

#include "ide_checker.h"

typedef struct {
    uint8_t mode;
    uint8_t cipher_byte_size;
    uint64_t cipher_addr_mask;
    uint8_t cipher_addr_offset;
    uint8_t plain_byte_size;
    uint64_t plain_addr_mask;
    uint8_t plain_addr_offset;
} pcie_partial_header_struct_t;

pcie_partial_header_struct_t m_pcie_partial_header_struct[] = {
    {IDE_ATTRIB_PARTIAL_HEADER_MODE_0,  0, 0, 0, 0, 0},
    {IDE_ATTRIB_PARTIAL_HEADER_MODE_17, 2, 0x000000000003FFFCull, 46, 6, 0xFFFFFFFFFFFC0000, 0},
    {IDE_ATTRIB_PARTIAL_HEADER_MODE_25, 3, 0x0000000003FFFFFCull, 38, 5, 0xFFFFFFFFFC000000, 0},
    {IDE_ATTRIB_PARTIAL_HEADER_MODE_33, 4, 0x00000003FFFFFFFCull, 30, 4, 0xFFFFFFFC00000000, 0},
    {IDE_ATTRIB_PARTIAL_HEADER_MODE_41, 5, 0x000003FFFFFFFFFCull, 22, 3, 0xFFFFFC0000000000, 0},
};

uint8_t pcie_partial_header_mode_to_cipher_byte_size (uint8_t mode)
{
    size_t index;
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_pcie_partial_header_struct); index++) {
        if (m_pcie_partial_header_struct[index].mode == mode) {
            return m_pcie_partial_header_struct[index].cipher_byte_size;
        }
    }
    return 0;
}

uint64_t pcie_partial_header_mode_to_cipher_addr_mask (uint8_t mode)
{
    size_t index;
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_pcie_partial_header_struct); index++) {
        if (m_pcie_partial_header_struct[index].mode == mode) {
            return m_pcie_partial_header_struct[index].cipher_addr_mask;
        }
    }
    return 0;
}

uint8_t pcie_partial_header_mode_to_cipher_addr_offset (uint8_t mode)
{
    size_t index;
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_pcie_partial_header_struct); index++) {
        if (m_pcie_partial_header_struct[index].mode == mode) {
            return m_pcie_partial_header_struct[index].cipher_addr_offset;
        }
    }
    return 0;
}

uint64_t pcie_partial_header_mode_to_plain_addr_mask (uint8_t mode)
{
    size_t index;
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_pcie_partial_header_struct); index++) {
        if (m_pcie_partial_header_struct[index].mode == mode) {
            return m_pcie_partial_header_struct[index].plain_addr_mask;
        }
    }
    return 0;
}

bool pcie_nfm_is_ide_tlp (const uint8_t *tlp)
{
    if (tlp[0] == 0x92) {
        return true;
    } else {
        return false;
    }
}

bool pcie_fm_is_ide_tlp (const uint8_t *tlp)
{
    if ((tlp[1] & 0x04) != 0) {
        return true;
    } else {
        return false;
    }
}

bool pcie_is_ide_tlp (bool is_nfm, const uint8_t *tlp)
{
    if (is_nfm) {
        return pcie_nfm_is_ide_tlp(tlp);
    } else {
        return pcie_fm_is_ide_tlp(tlp);
    }
}

uint16_t pcie_nfm_tlp_header_length (const uint8_t *tlp)
{
    uint16_t header_length_in_dw;
    uint8_t fmt;

    fmt = ((tlp[0] >> 5) & 0x7);
    switch (fmt) {
    case 0:
    case 2:
        header_length_in_dw = 3;
        break;
    case 1:
    case 3:
        header_length_in_dw = 4;
        break;
    default:
        return 0;
    }
    return header_length_in_dw * 4;
}

uint16_t pcie_fm_tlp_header_length (const uint8_t *tlp)
{
    uint16_t header_length_in_dw;
    uint8_t type;

    type = tlp[0];
    if ((type == 0) ||
        (type >= 128 && type <= 143)) {
        header_length_in_dw = 1;
    } else if ((type >= 1 && type <= 5) ||
               (type >= 8 && type <= 15) ||
               (type >= 28 && type <= 29) ||
               (type == 64) ||
               (type == 66) ||
               (type >= 68 && type <= 78) ||
               (type >= 88 && type <= 89) ||
               (type == 91)) {
        header_length_in_dw = 3;
    } else if ((type >= 6 && type <= 7) ||
               (type >= 32 && type <= 45) ||
               (type >= 48 && type <= 61) ||
               (type == 79) ||
               (type == 90) ||
               (type >= 92 && type <= 93) ||
               (type >= 96 && type <= 127) ||
               (type >= 144 && type <= 147) ||
               (type >= 224 && type <= 225) ||
               (type >= 228 && type <= 229) ||
               (type >= 240 && type <= 241)) {
        header_length_in_dw = 4;
    } else if ((type >= 16 && type <= 21) ||
               (type >= 46 && type <= 47) ||
               (type >= 62 && type <= 63) ||
               (type >= 94 && type <= 95) ||
               (type >= 148 && type <= 151) ||
               (type >= 160 && type <= 167) ||
               (type >= 172 && type <= 173) ||
               (type >= 176 && type <= 191) ||
               (type >= 202 && type <= 203) ||
               (type >= 242 && type <= 243)) {
        header_length_in_dw = 5;
    } else if ((type >= 30 && type <= 31) ||
               (type == 65) ||
               (type == 67) ||
               (type >= 80 && type <= 85) ||
               (type >= 152 && type <= 155) ||
               (type >= 168 && type <= 169) ||
               (type >= 174 && type <= 175) ||
               (type >= 192 && type <= 199) ||
               (type >= 204 && type <= 205) ||
               (type >= 208 && type <= 223) ||
               (type >= 226 && type <= 227) ||
               (type >= 230 && type <= 231) ||
               (type >= 244 && type <= 245)) {
        header_length_in_dw = 6;
    } else if ((type >= 22 && type <= 27) ||
               (type >= 86 && type <= 87) ||
               (type >= 156 && type <= 159) ||
               (type >= 170 && type <= 171) ||
               (type >= 200 && type <= 201) ||
               (type >= 206 && type <= 207) ||
               (type >= 232 && type <= 239) ||
               (type >= 246 && type <= 255)) {
        header_length_in_dw = 7;
    } else {
        return 0;
    }
    return header_length_in_dw * 4;
}

uint16_t pcie_tlp_header_length (bool is_nfm, const uint8_t *tlp)
{
    if (is_nfm) {
        return pcie_nfm_tlp_header_length(tlp);
    } else {
        return pcie_fm_tlp_header_length(tlp);
    }
}

size_t pcie_nfm_tlp_address_offset (const uint8_t *tlp)
{
    uint16_t header_length_in_dw;

    header_length_in_dw = pcie_nfm_tlp_header_length (tlp) / 4;
    switch (header_length_in_dw) {
    case 3:
        /* 32bit address */
        return 8;
    case 4:
        /* 64bit address */
        return 8;
    }
    return 0;
}

size_t pcie_fm_tlp_address_offset (const uint8_t *tlp)
{
    uint16_t header_length_in_dw;

    header_length_in_dw = pcie_fm_tlp_header_length (tlp) / 4;
    switch (header_length_in_dw) {
    case 3:
        /* 32bit address */
        return 8;
    case 4:
    case 5:
    case 6:
    case 7:
        /* 64bit address */
        return 8;
    }
    return 0;
}

size_t pcie_tlp_address_offset (bool is_nfm, const uint8_t *tlp)
{
    if (is_nfm) {
        return pcie_nfm_tlp_address_offset(tlp);
    } else {
        return pcie_fm_tlp_address_offset(tlp);
    }
}

size_t pcie_nfm_tlp_last_first_dw_offset (const uint8_t *tlp)
{
    uint8_t type;
    uint8_t th;

    type = tlp[0] & 0x1F;
    th = tlp[1] & 0x1;
    /* TBD
     * In NFM, the First DW BE and Last DW BE fields must be encrypted in all Memory Requests, except for
     * AtomicOp Requests, Translation Requests, and Memory Read/DMWr Requests with the TH bit Set.*/
    if ((type == 0) || (type == 1) || (type == 0x1B)) {
        if (th == 0) {
            return 7;
        }
    }
    return 0;
}

size_t pcie_fm_tlp_last_first_dw_offset (const uint8_t *tlp)
{
    uint16_t header_length;
    uint8_t ohc;
    uint8_t type;

    header_length = pcie_fm_tlp_header_length (tlp);
    ohc = tlp[1] & 0x1F;
    type = tlp[0];
    /* TBD
     * In FM, for Memory Requests, if OHC-A1 is present, then the First DW BE and Last DW BE fields must be
     * encrypted.
     * 
     * OHC-A1:
     * Memory Requests with explicit Byte Enables and/or PASID
     * Address Routed Messages with PASID and Route to Root Complex Messages with PASID
     * Translation Requests */
    if ((ohc & 0x1) != 0) {
        if ((type == 1) ||
            (type == 3) ||
            (type == 32) ||
            (type == 33) ||
            (type == 64) ||
            (type == 91) ||
            (type == 96) ||
            (type == 123)) {
            return header_length + 3;
        }
    }
    return 0;
}

size_t pcie_tlp_last_first_dw_offset (bool is_nfm, const uint8_t *tlp)
{
    if (is_nfm) {
        return pcie_nfm_tlp_last_first_dw_offset(tlp);
    } else {
        return pcie_fm_tlp_last_first_dw_offset(tlp);
    }
}

size_t pcie_tlp_last_first_dw_size (bool is_nfm, const uint8_t *tlp)
{
    size_t offset;
    if (is_nfm) {
        offset = pcie_nfm_tlp_last_first_dw_offset(tlp);
    } else {
        offset = pcie_fm_tlp_last_first_dw_offset(tlp);
    }
    return (offset == 0) ? 0 : 1;
}

uint16_t pcie_tlp_payload_length (bool is_nfm, const uint8_t *tlp)
{
    uint16_t payload_length_in_dw;

    payload_length_in_dw = tlp[3] | ((tlp[2] & 0x3) << 8);
    return payload_length_in_dw * 4;
}
