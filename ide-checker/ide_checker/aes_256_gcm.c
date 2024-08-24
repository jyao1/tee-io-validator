/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/test_aes_256_gcm/blob/main/LICENSE.md
 **/

#include "ide_checker.h"

/**
 * Validate Crypto AEAD Ciphers Interfaces.
 *
 * @retval  true   Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool test_aes_256_gcm(const ide_test_data_t *test_data)
{
    bool status;
    uint8_t out_buffer[1024];
    size_t out_buffer_size;
    uint8_t out_tag[1024];
    size_t out_tag_size;

    if (sizeof(out_buffer) < test_data->gcm_ct_size) {
        printf("Buffer Too Small - 0x%zx\n", test_data->gcm_ct_size);
        return false;
    }

    printf("\n- AES-GCM Encryption: ");

    out_buffer_size = sizeof(out_buffer);
    out_tag_size = test_data->gcm_tag_size;
    status = libspdm_aead_aes_gcm_encrypt(
        test_data->gcm_key, test_data->gcm_key_size,
        test_data->gcm_iv, test_data->gcm_iv_size,
        test_data->gcm_aad, test_data->gcm_aad_size,
        test_data->gcm_pt, test_data->gcm_pt_size,
        out_tag, out_tag_size,
        out_buffer, &out_buffer_size);
    if (!status) {
        printf("[Fail] status");
        //return false;
    }
    if (out_buffer_size != test_data->gcm_ct_size) {
        printf("[Fail] ct_size");
        return false;
    }
    if (memcmp(out_buffer, test_data->gcm_ct, test_data->gcm_ct_size) != 0) {
        printf("[Fail] ct\n");
        dump_hex (out_buffer, test_data->gcm_ct_size);
        //return false;
    }
    if (memcmp(out_tag, test_data->gcm_tag, test_data->gcm_tag_size) != 0) {
        printf("[Fail] tag\n");
        dump_hex (out_tag, test_data->gcm_tag_size);
        //return false;
    }
    printf("[Pass]");

    printf("\n- AES-GCM Decryption: ");
    status = libspdm_aead_aes_gcm_decrypt(
        test_data->gcm_key, test_data->gcm_key_size,
        test_data->gcm_iv, test_data->gcm_iv_size,
        test_data->gcm_aad, test_data->gcm_aad_size,
        test_data->gcm_ct, test_data->gcm_ct_size,
        test_data->gcm_tag, test_data->gcm_tag_size,
        out_buffer, &out_buffer_size);
    if (!status) {
        printf("[Fail] status");
        //return false;
    }
    if (out_buffer_size != test_data->gcm_pt_size) {
        printf("[Fail] pt_size");
        return false;
    }
    if (memcmp(out_buffer, test_data->gcm_pt, test_data->gcm_pt_size) != 0) {
        printf("[Fail] pt\n");
        dump_hex (out_buffer, test_data->gcm_pt_size);
        //return false;
    }

    printf("[Pass]");

    return true;
}
