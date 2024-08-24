/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/cxl_flit_68b_containment/blob/main/LICENSE.md
 **/

#include "ide_checker.h"

uint64_t swap_64(uint64_t value)
{
    return (((value & 0x00000000000000ff) << 56) |
            ((value & 0x000000000000ff00) << 40) |
            ((value & 0x0000000000ff0000) << 24) |
            ((value & 0x00000000ff000000) << 8) |
            ((value & 0x000000ff00000000) >> 8) |
            ((value & 0x0000ff0000000000) >> 24) |
            ((value & 0x00ff000000000000) >> 40) |
            ((value & 0xff00000000000000) >> 56));
}

ide_test_data_t *ide_test_data_create(
    const char *name,
    uint8_t type,
    uint32_t attrib
    )
{
    ide_test_data_t *ide_test_data;

    ide_test_data = (ide_test_data_t *)malloc(sizeof(ide_test_data_t));
    if (ide_test_data == NULL) {
        return NULL;
    }
    memset(ide_test_data, 0, sizeof(ide_test_data_t));
    ide_test_data->name = _strdup(name);
    if (ide_test_data->name == NULL) {
        free(ide_test_data);
        return NULL;
    }
    ide_test_data->type = type;
    ide_test_data->attrib = attrib;

    return ide_test_data;
}

void ide_test_data_delete(
    ide_test_data_t *ide_test_data
    )
{
    if (ide_test_data == NULL) {
        return ;
    }
    if (ide_test_data->name != NULL) {
        free(ide_test_data->name);
    }
    if (ide_test_data->gcm_key != NULL) {
        free(ide_test_data->gcm_key);
    }
    if (ide_test_data->gcm_iv != NULL) {
        free(ide_test_data->gcm_iv);
    }
    if (ide_test_data->gcm_aad != NULL) {
        free(ide_test_data->gcm_aad);
    }
    if (ide_test_data->gcm_pt != NULL) {
        free(ide_test_data->gcm_pt);
    }
    if (ide_test_data->gcm_ct != NULL) {
        free(ide_test_data->gcm_ct);
    }
    if (ide_test_data->gcm_tag != NULL) {
        free(ide_test_data->gcm_tag);
    }
    free(ide_test_data);
    return;
}

ide_test_data_t *ide_test_data_set_key_iv(
    ide_test_data_t *ide_test_data,
    const uint8_t *ide_key,
    const uint8_t *ide_iv
    )
{
    ide_test_data->gcm_key_size = AES_GCM_32_KEY_SIZE;
    ide_test_data->gcm_key = (uint8_t *)malloc(AES_GCM_32_KEY_SIZE);
    if (ide_test_data->gcm_key == NULL) {
        return NULL;
    }
    memcpy (ide_test_data->gcm_key, ide_key, AES_GCM_32_KEY_SIZE);

    ide_test_data->gcm_iv_size = AES_GCM_32_IV_SIZE;
    ide_test_data->gcm_iv = malloc(AES_GCM_32_IV_SIZE);
    if (ide_test_data->gcm_iv == NULL) {
        return NULL;
    }
    memcpy (ide_test_data->gcm_iv, ide_iv, AES_GCM_32_IV_SIZE);

    return ide_test_data;
}

ide_test_data_t *ide_test_data_set_cxl_ide_flit(
    ide_test_data_t *ide_test_data,
    const uint8_t *ide_packet_pt,
    size_t ide_packet_pt_size,
    const uint8_t *ide_packet_ct,
    size_t ide_packet_ct_size,
    const uint8_t *ide_tag
    )
{
    size_t ide_packet_count;
    size_t index;

    if (ide_test_data->type != IDE_TYPE_CXL) {
        printf("ide_test_data->type error: %d\n", ide_test_data->type);
        return NULL;
    }

    if ((ide_packet_pt_size % CXL_FLIT_68B_FLIT_SIZE) != 0) {
        printf("ide_packet_pt_size error: 0x%zx\n", ide_packet_pt_size);
        return NULL;
    }
    if ((ide_packet_ct_size % CXL_FLIT_68B_FLIT_SIZE) != 0) {
        printf("ide_packet_ct_size error: 0x%zx\n", ide_packet_ct_size);
        return NULL;
    }
    if (((ide_packet_ct_size == 0) && (ide_packet_ct != NULL)) || 
        ((ide_packet_ct_size != 0) && (ide_packet_ct == NULL))) {
        printf("ide_packet_ct mismatch: 0x%zx, %p\n", ide_packet_ct_size, ide_packet_ct);
        return NULL;
    }
    if (((ide_packet_pt_size == 0) && (ide_packet_pt != NULL)) || 
        ((ide_packet_pt_size != 0) && (ide_packet_pt == NULL))) {
        printf("ide_packet_pt mismatch: 0x%zx, %p\n", ide_packet_pt_size, ide_packet_pt);
        return NULL;
    }
    if ((ide_packet_ct_size != 0) && (ide_packet_pt_size != 0) &&
        (ide_packet_ct_size != ide_packet_pt_size)) {
        printf("ide_packet_pc/ct_size mismatch: 0x%zx-0x%zx\n", ide_packet_pt_size, ide_packet_ct_size);
        return NULL;
    }
    if ((ide_packet_ct_size == 0) && (ide_packet_pt_size == 0)) {
        printf("ide_packet_pc/ct_size all zero\n");
        return NULL;
    }

    if (ide_packet_pt_size != 0) {
        ide_packet_count = ide_packet_pt_size / CXL_FLIT_68B_FLIT_SIZE;
    }
    if (ide_packet_ct_size != 0) {
        ide_packet_count = ide_packet_ct_size / CXL_FLIT_68B_FLIT_SIZE;
    }

    if (ide_packet_pt_size != 0) {
        ide_test_data->gcm_pt_size = ide_packet_count * CXL_FLIT_68B_FLIT_BODY_SIZE;
        ide_test_data->gcm_pt = malloc(ide_test_data->gcm_pt_size);
        if (ide_test_data->gcm_pt == NULL) {
            return NULL;
        }
        for (index = 0; index < ide_packet_count; index++) {
            memcpy (
                ide_test_data->gcm_pt + index * CXL_FLIT_68B_FLIT_BODY_SIZE,
                ide_packet_pt + index * CXL_FLIT_68B_FLIT_SIZE + CXL_FLIT_68B_FLIT_HEADER_SIZE,
                CXL_FLIT_68B_FLIT_BODY_SIZE);
        }
    }

    if (ide_packet_ct_size != 0) {
        ide_test_data->gcm_ct_size = ide_packet_count * CXL_FLIT_68B_FLIT_BODY_SIZE;
        ide_test_data->gcm_ct = malloc(ide_test_data->gcm_ct_size);
        if (ide_test_data->gcm_ct == NULL) {
            return NULL;
        }
        for (index = 0; index < ide_packet_count; index++) {
            memcpy (
                ide_test_data->gcm_ct + index * CXL_FLIT_68B_FLIT_BODY_SIZE,
                ide_packet_ct + index * CXL_FLIT_68B_FLIT_SIZE + CXL_FLIT_68B_FLIT_HEADER_SIZE,
                CXL_FLIT_68B_FLIT_BODY_SIZE);
        }
    }

    ide_test_data->gcm_aad_size = ide_packet_count * CXL_FLIT_68B_FLIT_HEADER_SIZE;
    ide_test_data->gcm_aad = malloc(ide_test_data->gcm_aad_size);
    if (ide_test_data->gcm_aad == NULL) {
        return NULL;
    }
    if (ide_packet_ct_size != 0) {
        for (index = 0; index < ide_packet_count; index++) {
            memcpy (
                ide_test_data->gcm_aad + index * CXL_FLIT_68B_FLIT_HEADER_SIZE,
                ide_packet_ct + index * CXL_FLIT_68B_FLIT_SIZE,
                CXL_FLIT_68B_FLIT_HEADER_SIZE);
        }
    } else {
        for (index = 0; index < ide_packet_count; index++) {
            memcpy (
                ide_test_data->gcm_aad + index * CXL_FLIT_68B_FLIT_HEADER_SIZE,
                ide_packet_pt + index * CXL_FLIT_68B_FLIT_SIZE,
                CXL_FLIT_68B_FLIT_HEADER_SIZE);
        }
    }
    
    if (ide_tag != NULL) {
        ide_test_data->gcm_tag_size = AES_GCM_32_MAC_SIZE_IDE;
        ide_test_data->gcm_tag = malloc(AES_GCM_32_MAC_SIZE_IDE);
        if (ide_test_data->gcm_tag == NULL) {
            return NULL;
        }
        memcpy (ide_test_data->gcm_tag, ide_tag, AES_GCM_32_MAC_SIZE_IDE);
    }

    return ide_test_data;
}

ide_test_data_t *ide_test_data_set_pcie_ide_tlp(
    ide_test_data_t *ide_test_data,
    const uint8_t *ide_packet_pt,
    size_t ide_packet_pt_size,
    const uint8_t *ide_packet_ct,
    size_t ide_packet_ct_size,
    const uint8_t *ide_tag
    )
{
    bool is_nfm;
    uint8_t partial_header_mode;
    size_t header_offset;
    size_t payload_length;
    size_t header_length;
    size_t total_header_length;
    size_t address_offset;
    size_t partial_header_size;
    size_t last_first_dw_offset;
    size_t last_first_dw_size;
    uint64_t address;
    uint64_t partial_address;
    uint64_t cipher_addr_mask;
    uint8_t cipher_addr_offset;
    uint64_t plain_addr_mask;
    size_t index;
    size_t dest_index;
    uint8_t *partial_address_byte;
    bool need_pcrc;

    if (ide_test_data->type != IDE_TYPE_PCIE) {
        printf("ide_test_data->type error: %d\n", ide_test_data->type);
        return NULL;
    }

    partial_header_mode = (ide_test_data->attrib & IDE_ATTRIB_PARTIAL_HEADER_MODE_MASK);
    is_nfm = ((ide_test_data->attrib & IDE_ATTRIB_NONE_FLIT_MODE) != 0);
    need_pcrc = ((ide_test_data->attrib & IDE_ATTRIB_PCRC) != 0);

    if (((ide_packet_ct_size == 0) && (ide_packet_ct != NULL)) || 
        ((ide_packet_ct_size != 0) && (ide_packet_ct == NULL))) {
        printf("ide_packet_ct mismatch: 0x%zx, %p\n", ide_packet_ct_size, ide_packet_ct);
        return NULL;
    }
    if (((ide_packet_pt_size == 0) && (ide_packet_pt != NULL)) || 
        ((ide_packet_pt_size != 0) && (ide_packet_pt == NULL))) {
        printf("ide_packet_pt mismatch: 0x%zx, %p\n", ide_packet_pt_size, ide_packet_pt);
        return NULL;
    }
    if ((ide_packet_ct_size == 0) && (ide_packet_pt_size == 0)) {
        printf("ide_packet_pc/ct_size all zero\n");
        return NULL;
    }

    if ((ide_packet_pt != NULL) && (!pcie_is_ide_tlp(is_nfm, ide_packet_pt))) {
        printf("ide_packet_pt IDE header error\n");
        return NULL;
    }
    if ((ide_packet_ct != NULL) && (!pcie_is_ide_tlp(is_nfm, ide_packet_ct))) {
        printf("ide_packet_ct IDE header error\n");
        return NULL;
    }

    if (partial_header_mode != 0) {
        cipher_addr_mask = pcie_partial_header_mode_to_cipher_addr_mask(partial_header_mode);
        cipher_addr_offset = pcie_partial_header_mode_to_cipher_addr_offset(partial_header_mode);
        partial_header_size = pcie_partial_header_mode_to_cipher_byte_size(partial_header_mode);
        plain_addr_mask = pcie_partial_header_mode_to_plain_addr_mask(partial_header_mode);
    }

    if (is_nfm) {
        /* NFM header
         * The 1st DW is IDE Prefix
         * The 2nd DW is NFM header */
        header_offset = 4;
    } else {
        /* FM header
         * The 1st DW is FM header */
        header_offset = 0;
    }

    if (ide_packet_pt_size != 0) {
        payload_length = pcie_tlp_payload_length (is_nfm, ide_packet_pt + header_offset);
        total_header_length = ide_packet_pt_size - payload_length;
        if (partial_header_mode == 0) {
            ide_test_data->gcm_pt_size = payload_length;
        } else {
            header_length = pcie_tlp_header_length (is_nfm, ide_packet_pt + header_offset);
            address_offset = header_offset + pcie_tlp_address_offset (is_nfm, ide_packet_pt + header_offset);
            last_first_dw_offset = header_offset + pcie_tlp_last_first_dw_offset (is_nfm, ide_packet_pt + header_offset);
            last_first_dw_size = pcie_tlp_last_first_dw_size (is_nfm, ide_packet_pt + header_offset);
            ide_test_data->gcm_pt_size = payload_length + last_first_dw_size + partial_header_size;
        }
        ide_test_data->gcm_pt = malloc(ide_test_data->gcm_pt_size);
        if (ide_test_data->gcm_pt == NULL) {
            return NULL;
        }
        if (partial_header_mode == 0) {
            memcpy (
                ide_test_data->gcm_pt,
                ide_packet_pt + total_header_length,
                ide_test_data->gcm_pt_size);
        } else {
            memcpy (
                ide_test_data->gcm_pt,
                ide_packet_pt + last_first_dw_offset,
                last_first_dw_size);
            address = (*(uint64_t*)(ide_packet_pt + address_offset));
            address = swap_64(address);
            address &= 0xFFFFFFFFFFFFFFFCull;
            partial_address = (address & cipher_addr_mask) << cipher_addr_offset;
            partial_address = swap_64(partial_address);
            memcpy (
                ide_test_data->gcm_pt + last_first_dw_size,
                &partial_address,
                partial_header_size);
            memcpy (
                ide_test_data->gcm_pt + last_first_dw_size + partial_header_size,
                ide_packet_pt + total_header_length,
                ide_test_data->gcm_pt_size - last_first_dw_size - partial_header_size);
            ide_test_data->pcrc_partial_head_size = last_first_dw_size + partial_header_size;
        }
    } else {
        ide_test_data->gcm_pt = NULL;
    }

    if (ide_packet_ct_size != 0) {
        payload_length = pcie_tlp_payload_length (is_nfm, ide_packet_ct + header_offset);
        total_header_length = ide_packet_ct_size - payload_length;
        total_header_length -= AES_GCM_32_MAC_SIZE_IDE;
        if (need_pcrc) {
            total_header_length -= 4;
        }
        if (partial_header_mode == 0) {
            ide_test_data->gcm_ct_size = payload_length;
        } else {
            header_length = pcie_tlp_header_length (is_nfm, ide_packet_ct + header_offset);
            address_offset = header_offset + pcie_tlp_address_offset (is_nfm, ide_packet_ct + header_offset);
            last_first_dw_offset = header_offset + pcie_tlp_last_first_dw_offset (is_nfm, ide_packet_ct + header_offset);
            last_first_dw_size = pcie_tlp_last_first_dw_size (is_nfm, ide_packet_ct + header_offset);
            ide_test_data->gcm_ct_size = payload_length + last_first_dw_size + partial_header_size;
        }
        if (need_pcrc) {
            ide_test_data->gcm_ct_size += 4;
        }
        ide_test_data->gcm_ct = malloc(ide_test_data->gcm_ct_size);
        if (ide_test_data->gcm_ct == NULL) {
            return NULL;
        }
        if (partial_header_mode == 0) {
            memcpy (
                ide_test_data->gcm_ct,
                ide_packet_ct + total_header_length,
                ide_test_data->gcm_ct_size);
        } else {
            memcpy (
                ide_test_data->gcm_ct,
                ide_packet_ct + last_first_dw_offset,
                last_first_dw_size);
            address = (*(uint64_t *)(ide_packet_ct + address_offset));
            address = swap_64(address);
            address &= 0xFFFFFFFFFFFFFFFCull;
            partial_address = (address & cipher_addr_mask) << cipher_addr_offset;
            partial_address = swap_64(partial_address);
            memcpy (
                ide_test_data->gcm_ct + last_first_dw_size,
                &partial_address,
                partial_header_size);
            memcpy (
                ide_test_data->gcm_ct + last_first_dw_size + partial_header_size,
                ide_packet_ct + total_header_length,
                ide_test_data->gcm_ct_size - last_first_dw_size - partial_header_size);
            ide_test_data->pcrc_partial_head_size = last_first_dw_size + partial_header_size;
        }
    } else {
        ide_test_data->gcm_ct = NULL;
    }

    if (partial_header_mode == 0) {
        ide_test_data->gcm_aad_size = total_header_length;
    } else {
        ide_test_data->gcm_aad_size = total_header_length - last_first_dw_size - partial_header_size;
    }
    ide_test_data->gcm_aad = malloc(ide_test_data->gcm_aad_size);
    if (ide_test_data->gcm_aad == NULL) {
        return NULL;
    }
    if (ide_packet_ct_size != 0) {
        if (partial_header_mode == 0) {
            memcpy (
                ide_test_data->gcm_aad,
                ide_packet_ct,
                total_header_length);
        } else {
            address = (*(uint64_t*)(ide_packet_ct + address_offset));
            address = swap_64(address);
            address &= 0xFFFFFFFFFFFFFFFCull;
            partial_address = (address & plain_addr_mask);
            partial_address = swap_64(partial_address);
            partial_address_byte = (uint8_t *)&partial_address;
            dest_index = 0;
            for (index = 0; index < total_header_length; index++) {
                if ((last_first_dw_size != 0) && (index == last_first_dw_offset)) {
                    continue;
                }
                if ((index >= address_offset) && (index <= address_offset + 7)) {
                    if (index < address_offset + 8 - partial_header_size) {
                        ide_test_data->gcm_aad[dest_index] = partial_address_byte[index - address_offset];
                        dest_index++;
                    }
                    continue;
                }
                ide_test_data->gcm_aad[dest_index] = ide_packet_ct[index];
                dest_index++;
            }
        }
    } else {
        if (partial_header_mode == 0) {
            memcpy (
                ide_test_data->gcm_aad,
                ide_packet_pt,
                total_header_length);
        } else {
            address = (*(uint64_t*)(ide_packet_pt + address_offset));
            address = swap_64(address);
            address &= 0xFFFFFFFFFFFFFFFCull;
            partial_address = (address & plain_addr_mask);
            partial_address = swap_64(partial_address);
            partial_address_byte = (uint8_t *)&partial_address;
            dest_index = 0;
            for (index = 0; index < total_header_length; index++) {
                if ((last_first_dw_size != 0) && (index == last_first_dw_offset)) {
                    continue;
                }
                if ((index >= address_offset) && (index <= address_offset + 7)) {
                    if (index < address_offset + 8 - partial_header_size) {
                        ide_test_data->gcm_aad[dest_index] = partial_address_byte[index - address_offset];
                        dest_index++;
                    }
                    continue;
                }
                ide_test_data->gcm_aad[dest_index] = ide_packet_pt[index];
                dest_index++;
            }
        }
    }
    
    if (ide_tag != NULL || ide_packet_ct != NULL) {
        ide_test_data->gcm_tag_size = AES_GCM_32_MAC_SIZE_IDE;
        ide_test_data->gcm_tag = malloc(AES_GCM_32_MAC_SIZE_IDE);
        if (ide_test_data->gcm_tag == NULL) {
            return NULL;
        }
        if (ide_tag != NULL) {
            memcpy (ide_test_data->gcm_tag, ide_tag, AES_GCM_32_MAC_SIZE_IDE);
        } else {
            memcpy (
                ide_test_data->gcm_tag,
                ide_packet_ct + ide_packet_ct_size - AES_GCM_32_MAC_SIZE_IDE,
                AES_GCM_32_MAC_SIZE_IDE);
        }
    }

    return ide_test_data;
}

ide_test_data_t *ide_test_data_create_from_packet(
    const ide_test_packet_data_t *ide_test_packet_data
    )
{
    ide_test_data_t *ide_test_data;
    ide_test_data_t *result;

    ide_test_data = ide_test_data_create (
        ide_test_packet_data->name,
        ide_test_packet_data->type,
        ide_test_packet_data->attrib
        );
    if (ide_test_data == NULL) {
        printf("ide_test_data_create: failed\n");
        return NULL;
    }

    result = ide_test_data_set_key_iv (
        ide_test_data,
        ide_test_packet_data->ide_key,
        ide_test_packet_data->ide_iv
        );
    if (result == NULL) {
        printf("ide_test_data_set_key_iv: failed\n");
        ide_test_data_delete (ide_test_data);
        return NULL;
    }

    if (ide_test_packet_data->type == IDE_TYPE_CXL) {
        result = ide_test_data_set_cxl_ide_flit (
            ide_test_data,
            ide_test_packet_data->ide_packet_pt,
            ide_test_packet_data->ide_packet_pt_size,
            ide_test_packet_data->ide_packet_ct,
            ide_test_packet_data->ide_packet_ct_size,
            ide_test_packet_data->ide_tag
            );
        if (result == NULL) {
            printf("ide_test_data_set_cxl_ide_flit: failed\n");
            ide_test_data_delete (ide_test_data);
            return NULL;
        }
    } else {
        result = ide_test_data_set_pcie_ide_tlp (
            ide_test_data,
            ide_test_packet_data->ide_packet_pt,
            ide_test_packet_data->ide_packet_pt_size,
            ide_test_packet_data->ide_packet_ct,
            ide_test_packet_data->ide_packet_ct_size,
            ide_test_packet_data->ide_tag
            );
        if (result == NULL) {
            printf("ide_test_data_set_pcie_ide_tlp: failed\n");
            ide_test_data_delete (ide_test_data);
            return NULL;
        }
    }

    return ide_test_data;
}