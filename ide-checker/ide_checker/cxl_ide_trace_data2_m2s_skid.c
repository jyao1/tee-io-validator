/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "ide_checker.h"


uint8_t m_cxl_trace_data2_m2s_skid[] = {
    0xa0, 0x25, 0x01, 0x00, // flit header:
                            // 0xa0: Type[0]=0(protocol),AK[2]=0b(ack),BE[3]=0,SZ[4]=0,slot0[7:5]=101b(H5)
                            // 0x25: slot1[2:0]=101b(G5),slot2[5:3]=100b(G4),slot3[7:6]=00b
                            // 0x01: slot3[0]=1b(G4),RspCrd[7:4]=0000b
                            // 0x00: ReqCrd[3:0]=0000b,DataCrd[7:4]=0000b
    0x03, 0xa7, 0xa5, 0x48, // header
    0x00, 0x8c, 0xbe, 0x24,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, // Generic
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, // Generic
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, // Generic
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

uint8_t m_cxl_trace_data2_m2s_skid_ide_flit[] = {
    0xa0, 0x25, 0x01, 0x00, // flit header:
    0x0d, 0x8e, 0x33, 0x8c, // flit 0 enc
    0xef, 0x23, 0x4e, 0xd7,
    0x01, 0x58, 0xb7, 0x58,
    0x23, 0xcf, 0x06, 0x71,
    0x8b, 0x11, 0x70, 0xb3,
    0x1e, 0x03, 0x81, 0x12,
    0x88, 0x46, 0x23, 0xae,
    0xe5, 0x6e, 0xfd, 0x67,
    0x7f, 0xc8, 0x41, 0x54,
    0xba, 0x0d, 0x2e, 0x95,
    0xbc, 0xed, 0x10, 0xe9,
    0xb6, 0x2d, 0xf2, 0x74,
    0xc6, 0xf6, 0x3d, 0x84,
    0xd8, 0x3b, 0xb9, 0x29,
    0x1b, 0x80, 0x23, 0xc7,
};

uint8_t m_cxl_trace_data2_m2s_skid_gcm_key[] = {
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
};

uint8_t m_cxl_trace_data2_m2s_skid_gcm_iv[] = {
    0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02,
};

uint8_t m_cxl_trace_data2_m2s_skid_gcm_tag[] = {
    0x45, 0x5d, 0x34, 0xf0,
    0x7a, 0x04, 0xfe, 0x1d,
    0x5b, 0x07, 0x23, 0x6b,
};

ide_test_packet_data_t m_cxl_trace_data2_m2s_skid_gcm_packet_data = {
    "cxl_trace_data2_m2s_skid_gcm", IDE_TYPE_CXL, IDE_ATTRIB_PCRC,
    m_cxl_trace_data2_m2s_skid_gcm_key,
    m_cxl_trace_data2_m2s_skid_gcm_iv,
    m_cxl_trace_data2_m2s_skid, sizeof(m_cxl_trace_data2_m2s_skid),
    m_cxl_trace_data2_m2s_skid_ide_flit, sizeof(m_cxl_trace_data2_m2s_skid_ide_flit),
    m_cxl_trace_data2_m2s_skid_gcm_tag,
};
