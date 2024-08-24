/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "ide_checker.h"


uint8_t m_cxl_trace_data1_s2m_skid2[] = {
    0x70, 0x00, 0x00, 0x88, // flit header:
                            // 0x70: Type[0]=0(protocol),AK[2]=0b(ack),BE[3]=0,SZ[4]=1,slot0[7:5]=011b(H3)
                            // 0x00: slot1[2:0]=000b(G0),slot2[5:3]=000b(G0),slot3[7:6]=00b
                            // 0x00: slot3[0]=0b(G0),RspCrd[7:4]=0000b
                            // 0x88: ReqCrd[3:0]=1000b,DataCrd[7:4]=1000b
    0x01, 0x7e, 0x81, 0x00, // header
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xaa, 0xaa, 0xaa, 0xaa, // Generic
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, // Generic
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, // Generic
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,

    0x80, 0x68, 0x01, 0x88, // flit header:
                            // 0x80: Type[0]=0(protocol),AK[2]=0b(ack),BE[3]=0,SZ[4]=0,slot0[7:5]=100b(H4)
                            // 0x00: slot1[2:0]=000b(G0),slot2[5:3]=101b(G5),slot3[7:6]=01b
                            // 0x01: slot3[0]=1b(G5),RspCrd[7:4]=0000b
                            // 0x88: ReqCrd[3:0]=1000b,DataCrd[7:4]=1000b
    0x00, 0x00, 0x00, 0x00, // header
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xaa, 0xaa, 0xaa, 0xaa, // Generic
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,
    0x00, 0x00, 0x00, 0x00, // Generic
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, // Generic
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

uint8_t m_cxl_trace_data1_s2m_skid2_ide_flit[] = {
    0x70, 0x00, 0x00, 0x88, // flit header:
    0xc1, 0x64, 0x56, 0xc5, // flit 0 enc
    0xce, 0x4c, 0xa9, 0x52,
    0x62, 0xb7, 0x17, 0xfd,
    0x77, 0xca, 0xa6, 0x60,
    0xd9, 0x88, 0x89, 0x88,
    0x10, 0xb0, 0xcb, 0x5a,
    0x90, 0xa0, 0xfe, 0x61,
    0x7f, 0x11, 0xae, 0x6d,
    0xcf, 0x62, 0x62, 0x9c,
    0x66, 0x4f, 0x71, 0x13,
    0x1f, 0x87, 0x3b, 0xde,
    0xfa, 0x5a, 0x6f, 0x9c,
    0x0a, 0x3c, 0x3b, 0x88,
    0x66, 0x20, 0x05, 0x2e,
    0x57, 0x9e, 0x2f, 0x23,

    0x80, 0x68, 0x01, 0x88, // flit header:
    0x8b, 0x84, 0x8f, 0xef, // flit 1 enc
    0x08, 0x1d, 0xf4, 0x7b,
    0x08, 0x81, 0x1c, 0x6f,
    0xd2, 0xc4, 0x48, 0x33,
    0xb7, 0x7b, 0x3b, 0xc7,
    0x28, 0x89, 0x45, 0x73,
    0xd6, 0x5f, 0xae, 0x7a,
    0xa6, 0x72, 0x1e, 0xa9,
    0xcb, 0xdc, 0x33, 0x55,
    0x42, 0x57, 0xc4, 0x7a,
    0xbb, 0x26, 0x58, 0x9d,
    0x08, 0x74, 0x27, 0xce,
    0x42, 0x3d, 0x06, 0x30,
    0xe1, 0x85, 0xc5, 0xf8,
    0xd5, 0xb0, 0xa2, 0xa2,
};

uint8_t m_cxl_trace_data1_s2m_skid2_gcm_key[] = {
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
};

uint8_t m_cxl_trace_data1_s2m_skid2_gcm_iv[] = {
    0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
};

uint8_t m_cxl_trace_data1_s2m_skid2_gcm_tag[] = {
    0xdb, 0x21, 0xc8, 0xe8,
    0x17, 0xa7, 0xaa, 0x94,
    0x74, 0x85, 0x27, 0x43,
};

ide_test_packet_data_t m_cxl_trace_data1_s2m_skid2_gcm_packet_data = {
    "cxl_trace_data1_s2m_skid2_gcm", IDE_TYPE_CXL, IDE_ATTRIB_PCRC,
    m_cxl_trace_data1_s2m_skid2_gcm_key,
    m_cxl_trace_data1_s2m_skid2_gcm_iv,
    m_cxl_trace_data1_s2m_skid2, sizeof(m_cxl_trace_data1_s2m_skid2),
    m_cxl_trace_data1_s2m_skid2_ide_flit, sizeof(m_cxl_trace_data1_s2m_skid2_ide_flit),
    m_cxl_trace_data1_s2m_skid2_gcm_tag,
};