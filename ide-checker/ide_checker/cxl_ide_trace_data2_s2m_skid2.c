/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "ide_checker.h"


uint8_t m_cxl_trace_data2_s2m_skid2[] = {
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

uint8_t m_cxl_trace_data2_s2m_skid2_ide_flit[] = {
    0x70, 0x00, 0x00, 0x88, // flit header:
    0x4c, 0x8a, 0x33, 0xb4, // flit 0 enc
    0x1c, 0xf2, 0x6a, 0x2c,
    0xf8, 0x3f, 0x5a, 0xfb,
    0x4c, 0xa4, 0x23, 0x2a,
    0x04, 0x3b, 0xca, 0x46,
    0x2a, 0x09, 0x00, 0xb0,
    0x00, 0xde, 0x02, 0xaf,
    0xf8, 0x79, 0xd0, 0x43,
    0xed, 0x2e, 0xb2, 0x25,
    0xd6, 0x7f, 0x7a, 0x3e,
    0x9a, 0xc8, 0xae, 0xaf,
    0x47, 0xc9, 0xc5, 0x01,
    0x86, 0xde, 0xd0, 0xc5,
    0x60, 0x6b, 0x74, 0xb6,
    0x35, 0x5c, 0x9a, 0x14,

    0x80, 0x68, 0x01, 0x88, // flit header:
    0xd1, 0x7c, 0x3b, 0x24, // flit 1 enc
    0x8c, 0x7f, 0x82, 0xb0,
    0x21, 0xdc, 0x3c, 0x89,
    0xd9, 0xd2, 0x25, 0x2e,
    0x81, 0xc8, 0x3c, 0x00,
    0xe0, 0x80, 0xa3, 0xa5,
    0x59, 0xbf, 0x54, 0x35,
    0x60, 0xc0, 0x43, 0xbf,
    0x42, 0x3c, 0x9a, 0x03,
    0xd3, 0xfe, 0xd6, 0xb7,
    0x93, 0x2d, 0x92, 0xa3,
    0xf6, 0x14, 0x6c, 0x68,
    0x65, 0xd3, 0xab, 0x6b,
    0x8a, 0xa0, 0x11, 0x91,
    0x65, 0xb4, 0x10, 0x71,
};

uint8_t m_cxl_trace_data2_s2m_skid2_gcm_key[] = {
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22,
};

uint8_t m_cxl_trace_data2_s2m_skid2_gcm_iv[] = {
    0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02,
};

uint8_t m_cxl_trace_data2_s2m_skid2_gcm_tag[] = {
    0xf1, 0xdf, 0xa6, 0xe3,
    0x57, 0x22, 0x90, 0x30,
    0xa7, 0xec, 0xdd, 0x2d,
};

ide_test_packet_data_t m_cxl_trace_data2_s2m_skid2_gcm_packet_data = {
    "cxl_trace_data2_s2m_skid2_gcm", IDE_TYPE_CXL, IDE_ATTRIB_PCRC,
    m_cxl_trace_data2_s2m_skid2_gcm_key,
    m_cxl_trace_data2_s2m_skid2_gcm_iv,
    m_cxl_trace_data2_s2m_skid2, sizeof(m_cxl_trace_data2_s2m_skid2),
    m_cxl_trace_data2_s2m_skid2_ide_flit, sizeof(m_cxl_trace_data2_s2m_skid2_ide_flit),
    m_cxl_trace_data2_s2m_skid2_gcm_tag,
};
