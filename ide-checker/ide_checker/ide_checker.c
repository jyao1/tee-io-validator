/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "ide_checker.h"

bool test_ide(const ide_test_data_t *test_data)
{
    bool status;

    printf("\n\n%s: ", test_data->name);

    switch (test_data->type) {
    case IDE_TYPE_PCIE:
        status = test_aes_256_gcm_pcie_pcrc (test_data);
        if (!status) {
            //return false;
        }
        break;
    case IDE_TYPE_CXL:
        status = test_aes_256_gcm_cxl_pcrc (test_data);
        if (!status) {
            //return false;
        }
        break;
    }
    return true;
}

bool test_ide_packet(const ide_test_packet_data_t *test_packet_data)
{
    ide_test_data_t *ide_test_data;
    bool result;

    ide_test_data = ide_test_data_create_from_packet(test_packet_data);

    result = test_ide (ide_test_data);

    ide_test_data_delete (ide_test_data);

    return result;
}

int main(int argc, char *argv[])
{
    printf("%s version 0.1\n", "ide_checker");

    test_ide_packet (&m_pcie_ide_nfm_wo_ph_gcm_packet_data);
    test_ide_packet (&m_pcie_ide_fm_wo_ph_gcm_packet_data);
    test_ide_packet (&m_pcie_ide_nfm_w_ph_gcm_packet_data);
    test_ide_packet (&m_pcie_ide_fm_w_ph_gcm_packet_data);

    test_ide_packet(&m_cxl_flit_68b_containment_gcm_packet_data);

    test_ide_packet (&m_cxl_sim_data1_m2s_dev_gcm_packet_data);
    test_ide_packet (&m_cxl_sim_data1_s2m_dev_gcm_packet_data);
    test_ide_packet (&m_cxl_sim_data2_m2s_dev_gcm_packet_data);
    test_ide_packet (&m_cxl_sim_data2_s2m_dev_gcm_packet_data);
    test_ide_packet (&m_cxl_sim_data3_m2s_dev_gcm_packet_data);
    test_ide_packet (&m_cxl_sim_data3_s2m_dev_gcm_packet_data);

    test_ide_packet (&m_cxl_sim_data1_m2s_pcrc_dev_gcm_packet_data);
    test_ide_packet (&m_cxl_sim_data1_s2m_pcrc_dev_gcm_packet_data);
    test_ide_packet (&m_cxl_sim_data2_m2s_pcrc_dev_gcm_packet_data);
    test_ide_packet (&m_cxl_sim_data2_s2m_pcrc_dev_gcm_packet_data);
    test_ide_packet (&m_cxl_sim_data3_m2s_pcrc_dev_gcm_packet_data);
    test_ide_packet (&m_cxl_sim_data3_s2m_pcrc_dev_gcm_packet_data);

    test_ide_packet (&m_cxl_trace_data1_m2s_containment_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data1_s2m_containment_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data2_m2s_containment_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data2_s2m_containment_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data3_m2s_containment_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data3_s2m_containment_gcm_packet_data);

    test_ide_packet (&m_cxl_trace_data1_m2s_skid_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data1_s2m_skid_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data2_m2s_skid_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data2_s2m_skid_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data3_m2s_skid_gcm_packet_data);

    test_ide_packet (&m_cxl_trace_data1_m2s_skid2_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data1_s2m_skid2_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data2_m2s_skid2_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data2_s2m_skid2_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data3_m2s_skid2_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data3_s2m_skid2_gcm_packet_data);
    test_ide_packet (&m_cxl_trace_data4_s2m_skid2_gcm_packet_data);

    return 0;
}
