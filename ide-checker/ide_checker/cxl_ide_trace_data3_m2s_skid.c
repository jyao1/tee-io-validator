/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "ide_checker.h"


uint8_t m_cxl_trace_data3_m2s_skid[] = {
    0x98, 0x00, 0x00, 0x00, // flit header:
                            // 0x98: Type[0]=0(protocol),AK[2]=0b(ack),BE[3]=1,SZ[4]=1,slot0[7:5]=100b(H5)
                            // 0x00: slot1[2:0]=000b(G5),slot2[5:3]=000b(G4),slot3[7:6]=00b
                            // 0x00: slot3[0]=0b(G4),RspCrd[7:4]=0000b
                            // 0x00: ReqCrd[3:0]=0000b,DataCrd[7:4]=0000b
    0x05, 0xb0, 0xa5, 0x28, // header
    0x00, 0x46, 0x5f, 0x12,
    0x00, 0x00, 0x00, 0x00,
    0xbb, 0x00, 0x00, 0x00, // Generic
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

    0xa0, 0x00, 0x01, 0x00, // flit header:
                            // 0xa0: Type[0]=0(protocol),AK[2]=0b(ack),BE[3]=0,SZ[4]=0,slot0[7:5]=101b(H5)
                            // 0x00: slot1[2:0]=000b(G5),slot2[5:3]=000b(G4),slot3[7:6]=00b
                            // 0x01: slot3[0]=1b(G4),RspCrd[7:4]=0000b
                            // 0x00: ReqCrd[3:0]=0000b,DataCrd[7:4]=0000b
    0x00, 0x00, 0x00, 0x00, // header
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, // Generic
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, // Generic
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, // Generic
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

uint8_t m_cxl_trace_data3_m2s_skid_ide_flit[] = {
    0x98, 0x00, 0x00, 0x00, // flit header:
    0x65, 0xce, 0x16, 0xac, // flit 0 enc
    0x92, 0xbd, 0x45, 0x1e,
    0xa0, 0x9c, 0x73, 0x78,
    0xde, 0x1c, 0xce, 0x82,
    0x18, 0x33, 0x16, 0x9e,
    0x11, 0x21, 0x85, 0xb3,
    0x46, 0x12, 0xa8, 0x96,
    0x72, 0xd2, 0x90, 0x41,
    0x93, 0xf1, 0xc2, 0x0d,
    0x48, 0x63, 0xbb, 0x76,
    0xd3, 0x6c, 0x70, 0xfb,
    0xbf, 0xb9, 0xcc, 0x90,
    0x65, 0x88, 0xf6, 0xcd,
    0xd2, 0x6a, 0x19, 0xf0,
    0xd3, 0xf8, 0x82, 0x16,

    0xa0, 0x00, 0x01, 0x00, // flit header:
    0x5c, 0x2d, 0x13, 0xb0, // flit 0 enc
    0xc1, 0x63, 0xd9, 0xcc,
    0xf3, 0x47, 0xb1, 0xdb,
    0x3d, 0xed, 0x8a, 0x81,
    0x53, 0xa1, 0x6e, 0xec,
    0x7f, 0xcb, 0x9a, 0x32,
    0xbf, 0x3d, 0x69, 0x06,
    0x8c, 0x3f, 0x47, 0x53,
    0x18, 0xd4, 0x52, 0x38,
    0xdc, 0xbe, 0x0c, 0x36,
    0x52, 0xe4, 0x71, 0x8c,
    0x4a, 0xdc, 0xe1, 0xa1,
    0x65, 0xad, 0x82, 0x90,
    0x7b, 0x3b, 0xcd, 0x76,
    0x91, 0xcb, 0xb1, 0x34,
};

uint8_t m_cxl_trace_data3_m2s_skid_gcm_key[] = {
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
};

uint8_t m_cxl_trace_data3_m2s_skid_gcm_iv[] = {
    0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03,
};

uint8_t m_cxl_trace_data3_m2s_skid_gcm_tag[] = {
    0xf1, 0x66, 0xc5, 0x69,
    0xef, 0xae, 0x47, 0x04,
    0x46, 0xf0, 0xe6, 0xc2,
};

ide_test_packet_data_t m_cxl_trace_data3_m2s_skid_gcm_packet_data = {
    "cxl_trace_data3_m2s_skid_gcm", IDE_TYPE_CXL, IDE_ATTRIB_PCRC,
    m_cxl_trace_data3_m2s_skid_gcm_key,
    m_cxl_trace_data3_m2s_skid_gcm_iv,
    m_cxl_trace_data3_m2s_skid, sizeof(m_cxl_trace_data3_m2s_skid),
    m_cxl_trace_data3_m2s_skid_ide_flit, sizeof(m_cxl_trace_data3_m2s_skid_ide_flit),
    m_cxl_trace_data3_m2s_skid_gcm_tag,
};