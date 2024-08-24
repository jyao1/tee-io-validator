/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "ide_checker.h"


uint8_t m_cxl_sim_data1_m2s_pcrc_dev[] = {
    0xb0, 0xa5, 0x80, 0x88, // flit header:
                            // 0xb0: Type[0]=0(protocol),AK[2]=0b(ack),BE[3]=0,SZ[4]=1,slot0[7:5]=101b(H5)
                            // 0xa5: slot1[2:0]=101b(G5),slot2[5:3]=100b(G4),slot3[7:6]=10b
                            // 0x80: slot3[0]=0b(G2),RspCrd[7:4]=1000b
                            // 0x88: ReqCrd[3:0]=1000b,DataCrd[7:4]=1000b
    0x03, 0x13, 0x00, 0x00, // header
    0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00,
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

uint8_t m_cxl_sim_data1_m2s_pcrc_dev_ide_flit[] = {
    0xb0, 0xa5, 0x80, 0x88, // flit header:
    0x54, 0xa7, 0x4e, 0x0b, // flit 0 enc
    0x17, 0x2a, 0x26, 0x16,
    0x80, 0xeb, 0x29, 0x88,
    0x99, 0x99, 0xdb, 0x14,
    0xdb, 0x8a, 0x4c, 0x6c,
    0xba, 0x50, 0x47, 0x82,
    0x5a, 0x48, 0xce, 0x05,
    0xc0, 0x43, 0x39, 0xc5,
    0x07, 0xa5, 0xe4, 0x74,
    0xa5, 0xb9, 0x02, 0xde,
    0x84, 0x06, 0x53, 0xf9,
    0x61, 0xa2, 0x57, 0xc9,
    0xea, 0xdc, 0xa8, 0x7c,
    0x88, 0x4f, 0x33, 0xb6,
    0x45, 0xfe, 0x79, 0x66,
};

uint8_t m_cxl_sim_data1_m2s_pcrc_dev_gcm_key[] = {
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
};

uint8_t m_cxl_sim_data1_m2s_pcrc_dev_gcm_iv[] = {
    0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
};

uint8_t m_cxl_sim_data1_m2s_pcrc_dev_gcm_tag[] = {
    0xc9, 0x2e, 0x92, 0x7f,
    0x92, 0x61, 0x1a, 0x81,
    0xff, 0xdf, 0xe6, 0x23,
};

ide_test_packet_data_t m_cxl_sim_data1_m2s_pcrc_dev_gcm_packet_data = {
    "cxl_sim_data1_m2s_pcrc_dev_gcm", IDE_TYPE_CXL, IDE_ATTRIB_PCRC,
    m_cxl_sim_data1_m2s_pcrc_dev_gcm_key,
    m_cxl_sim_data1_m2s_pcrc_dev_gcm_iv,
    m_cxl_sim_data1_m2s_pcrc_dev, sizeof(m_cxl_sim_data1_m2s_pcrc_dev),
    m_cxl_sim_data1_m2s_pcrc_dev_ide_flit, sizeof(m_cxl_sim_data1_m2s_pcrc_dev_ide_flit),
    m_cxl_sim_data1_m2s_pcrc_dev_gcm_tag,
};
