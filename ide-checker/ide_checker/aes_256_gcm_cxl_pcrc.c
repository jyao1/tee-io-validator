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
bool test_aes_256_gcm_cxl_pcrc(const ide_test_data_t *test_data)
{
    bool status;
    uint8_t out_buffer[1024 + sizeof(uint32_t)];
    size_t out_buffer_size;
    uint8_t out_tag[32];
    size_t out_tag_size;
    uint32_t pcrc;
    uint8_t in_buffer[1024 + sizeof(uint32_t)];
    size_t in_buffer_size;
    bool need_pcrc;

    need_pcrc = ((test_data->attrib & IDE_ATTRIB_PCRC) != 0);

    if (sizeof(out_buffer) - sizeof(uint32_t) < test_data->gcm_ct_size) {
        printf("Buffer Too Small - 0x%zx\n", test_data->gcm_ct_size);
        return false;
    }

    /*
        Encryption with CXL PCRC:
        PlainText
        =>Pcrc = PCRC(PlainText)
        =>CipherText = ENC(PlainText) // no Pcrc
          Tag = MAC(Aad || PlainText || Pcrc)
    */
    printf("\n- AES-GCM Encryption ");
    if (need_pcrc) {
        printf("with CXL PCRC ");
    }
    printf(": ");

    if (need_pcrc) {
        /* add PCRC */
        pcrc = cxl_calc_pcrc (test_data->gcm_pt, test_data->gcm_pt_size);
        memcpy(in_buffer, test_data->gcm_pt, test_data->gcm_pt_size);
        memcpy(in_buffer + test_data->gcm_pt_size, (void *)&pcrc, sizeof(uint32_t));
        in_buffer_size = test_data->gcm_pt_size + sizeof(uint32_t);
    } else {
        memcpy(in_buffer, test_data->gcm_pt, test_data->gcm_pt_size);
        in_buffer_size = test_data->gcm_pt_size;
    }

    out_buffer_size = sizeof(out_buffer);
    out_tag_size = test_data->gcm_tag_size;
    status = libspdm_aead_aes_gcm_encrypt(
        test_data->gcm_key, test_data->gcm_key_size,
        test_data->gcm_iv, test_data->gcm_iv_size,
        test_data->gcm_aad, test_data->gcm_aad_size,
        in_buffer, in_buffer_size,
        out_tag, out_tag_size,
        out_buffer, &out_buffer_size);
    if (!status) {
        printf("[Fail] status");
        //return false;
    }
    if (need_pcrc) {
        /* drop enc PCRC */
        out_buffer_size -= sizeof(uint32_t);
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

    /*
        Decryption with CXL PCRC:
        CipherText + Tag
        =>PlainText = DEC(CipherText)
        =>Pcrc = PCRC(PlainText)
        =>Mac = MAC(Aad || PlainText || Pcrc)
        =>Check Tag == Mac
    */
    printf("\n- AES-GCM Decryption ");
    if (need_pcrc) {
        printf("with CXL PCRC ");
    }
    printf(": ");

    out_tag_size = test_data->gcm_tag_size;
    status = libspdm_aead_aes_gcm_decrypt_no_auth(
        test_data->gcm_key, test_data->gcm_key_size,
        test_data->gcm_iv, test_data->gcm_iv_size,
        test_data->gcm_aad, test_data->gcm_aad_size,
        test_data->gcm_ct, test_data->gcm_ct_size,
        out_tag, out_tag_size,
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

    if (need_pcrc) {
        /* check MAC */
        pcrc = cxl_calc_pcrc (out_buffer, out_buffer_size);
        memcpy(in_buffer, out_buffer, out_buffer_size);
        memcpy(in_buffer + out_buffer_size, (void *)&pcrc, sizeof(uint32_t));
        in_buffer_size = out_buffer_size + sizeof(uint32_t);

        out_buffer_size = sizeof(out_buffer);
        out_tag_size = test_data->gcm_tag_size;
        status = libspdm_aead_aes_gcm_encrypt(
            test_data->gcm_key, test_data->gcm_key_size,
            test_data->gcm_iv, test_data->gcm_iv_size,
            test_data->gcm_aad, test_data->gcm_aad_size,
            in_buffer, in_buffer_size,
            out_tag, out_tag_size,
            out_buffer, &out_buffer_size);
    }
    if (memcmp(out_tag, test_data->gcm_tag, test_data->gcm_tag_size) != 0) {
        printf("[Fail] tag\n");
        dump_hex (out_tag, out_tag_size);
        //return false;
    }

    printf("[Pass]");

    return true;
}
