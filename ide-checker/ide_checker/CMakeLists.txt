cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/ide_checker
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
                    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include/mbedtls
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include/mbedtls
)

SET(src_ide_checker
    ide_checker.c
    aes_256_gcm.c
    aes_256_gcm_pcie_pcrc.c
    aes_256_gcm_cxl_pcrc.c
    aead_aes_gcm_online_mbedtls.c
    test_data_support.c
    support.c
    pcrc_support.c
    tlp_support.c
    pcie_ide_nfm_wo_ph.c
    pcie_ide_fm_wo_ph.c
    pcie_ide_nfm_w_ph.c
    pcie_ide_fm_w_ph.c
    cxl_ide_flit_68b_containment.c
    cxl_ide_sim_data1_m2s_dev.c
    cxl_ide_sim_data1_s2m_dev.c
    cxl_ide_sim_data2_m2s_dev.c
    cxl_ide_sim_data2_s2m_dev.c
    cxl_ide_sim_data3_m2s_dev.c
    cxl_ide_sim_data3_s2m_dev.c
    cxl_ide_sim_data1_m2s_pcrc_dev.c
    cxl_ide_sim_data1_s2m_pcrc_dev.c
    cxl_ide_sim_data2_m2s_pcrc_dev.c
    cxl_ide_sim_data2_s2m_pcrc_dev.c
    cxl_ide_sim_data3_m2s_pcrc_dev.c
    cxl_ide_sim_data3_s2m_pcrc_dev.c
    cxl_ide_trace_data1_m2s_containment.c
    cxl_ide_trace_data1_s2m_containment.c
    cxl_ide_trace_data2_m2s_containment.c
    cxl_ide_trace_data2_s2m_containment.c
    cxl_ide_trace_data3_m2s_containment.c
    cxl_ide_trace_data3_s2m_containment.c
    cxl_ide_trace_data1_m2s_skid.c
    cxl_ide_trace_data1_s2m_skid.c
    cxl_ide_trace_data2_m2s_skid.c
    cxl_ide_trace_data2_s2m_skid.c
    cxl_ide_trace_data3_m2s_skid.c
    cxl_ide_trace_data1_m2s_skid2.c
    cxl_ide_trace_data1_s2m_skid2.c
    cxl_ide_trace_data2_m2s_skid2.c
    cxl_ide_trace_data2_s2m_skid2.c
    cxl_ide_trace_data3_m2s_skid2.c
    cxl_ide_trace_data3_s2m_skid2.c
    cxl_ide_trace_data4_s2m_skid2.c
)

SET(ide_checker_LIBRARY
    memlib
    debuglib
    spdm_common_lib
    ${CRYPTO_LIB_PATHS}
    rnglib
    cryptlib_${CRYPTO}
    malloclib
    spdm_crypt_lib
)

ADD_EXECUTABLE(ide_checker ${src_ide_checker})
TARGET_LINK_LIBRARIES(ide_checker ${ide_checker_LIBRARY})
