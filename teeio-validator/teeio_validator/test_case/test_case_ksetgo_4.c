/**
 *  Copyright Notice:
 *  Copyright 2023-2024 Intel. All rights reserved.
 *  License: BSD 3-Clause License.
 **/

#include <stdlib.h>
#include <ctype.h>

#include "assert.h"
#include "hal/base.h"
#include "hal/library/debuglib.h"
#include "hal/library/platform_lib.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/pci_ide_km_requester_lib.h"
#include "ide_test.h"
#include "utils.h"
#include "teeio_debug.h"

//
// case 3.4
// IDE_KM responder shall return valid K_GOSTOP_ACK, if it receives a K_SET_GO switch KeySet from 1 to 0
//

extern const char *k_set_names[];

bool setup_ide_stream(void* doe_context, void* spdm_context,
                                uint32_t* session_id, uint8_t* kcbar_addr,
                                uint8_t stream_id, uint8_t ks,
                                ide_key_set_t* k_set, uint8_t rp_stream_index,
                                uint8_t port_index, IDE_TEST_TOPOLOGY_TYPE top_type,
                                ide_common_test_port_context_t* upper_port,
                                ide_common_test_port_context_t* lower_port,
                                bool skip_ksetgo);


bool enable_ide_stream_in_ecap(int cfg_space_fd, uint32_t ecap_offset, TEST_IDE_TYPE ide_type, uint8_t ide_id, bool enable);
void enable_host_ide_stream(int cfg_space_fd, uint32_t ecap_offset, TEST_IDE_TYPE ide_type, uint8_t ide_id, uint8_t *kcbar_addr, uint8_t rp_stream_index, bool enable);
void set_host_ide_key_set(
    INTEL_KEYP_ROOT_COMPLEX_KCBAR *const kcbar_ptr,
    const uint8_t rp_stream_index,
    const uint8_t key_set_select);

bool ide_key_switch_to(void* doe_context, void* spdm_context,
                    uint32_t* session_id, uint8_t* kcbar_addr,
                    uint8_t stream_id, ide_key_set_t* k_set, uint8_t rp_stream_index,
                    uint8_t port_index, IDE_TEST_TOPOLOGY_TYPE top_type,
                    ide_common_test_port_context_t* upper_port,
                    ide_common_test_port_context_t* lower_port,
                    uint8_t ks, bool skip_ksetgo);

uint32_t read_host_stream_status_in_ecap(int cfg_space_fd, uint32_t ecap_offset, TEST_IDE_TYPE ide_type, uint8_t ide_id);
bool pre_alloc_slot_ids(uint8_t rp_stream_index, ide_key_set_t* k_set, uint8_t num_rx_key_slots, bool ide_key_refresh);
libspdm_return_t test_ide_km_key_set_go(const void *pci_doe_context,
                                   void *spdm_context, const uint32_t *session_id,
                                   uint8_t stream_id, uint8_t key_sub_stream,
                                   uint8_t port_index,
                                   bool phase1, const char *assertion_msg);
// case 3.4
bool test_ksetgo_4_setup(void *test_context)
{
  ide_common_test_case_context_t *case_context = (ide_common_test_case_context_t *)test_context;
  assert(case_context);
  assert(case_context->signature == CASE_CONTEXT_SIGNATURE);

  ide_common_test_group_context_t *group_context = case_context->group_context;
  assert(group_context);
  assert(group_context->signature == GROUP_CONTEXT_SIGNATURE);

  ide_common_test_port_context_t* upper_port = &group_context->upper_port;
  ide_common_test_port_context_t* lower_port = &group_context->lower_port;

  // by default slot_ids are not allocated for key_refresh.
  // this case need to re-allocate slot_ids for key_refresh
  if(!pre_alloc_slot_ids(group_context->rp_stream_index, group_context->k_set, upper_port->stream_cap.num_rx_key_slots, true)) {
    return false;
  }

  // first setup ide_stream for KS1 (skip ksetgo)
  bool res = setup_ide_stream(group_context->doe_context, group_context->spdm_context, &group_context->session_id,
                          upper_port->mapped_kcbar_addr, group_context->stream_id, PCI_IDE_KM_KEY_SET_K1,
                          group_context->k_set, group_context->rp_stream_index,
                          0, group_context->top->type, upper_port, lower_port, true);
  if(!res) {
    return false;
  }

  return true;
}

bool test_ksetgo_4_run_phase1(void* doe_context, void* spdm_context, uint32_t* session_id,
                              uint8_t stream_id, uint8_t rp_stream_index,
                              uint8_t* kcbar_addr, IDE_TEST_TOPOLOGY_TYPE top_type,
                              ide_common_test_port_context_t* upper_port,
                              ide_common_test_port_context_t* lower_port)
{
  libspdm_return_t status;

  // Now KSetGo
  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|RX|PR\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_PR, 0, true, "  Assertion 3.3");
  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|RX|PR failed with 0x%x\n", k_set_names[PCI_IDE_KM_KEY_SET_K1], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|RX|NPR\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, 0, true, "  Assertion 3.3");

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|RX|NPR failed with 0x%x\n", k_set_names[PCI_IDE_KM_KEY_SET_K1], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|RX|CPL\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, 0, true, "  Assertion 3.3");

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|RX|CPL failed with 0x%x\n", k_set_names[PCI_IDE_KM_KEY_SET_K1], status));
    return false;
  }

  // set key_set_select in host ide
  INTEL_KEYP_ROOT_COMPLEX_KCBAR *kcbar = (INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr;
  set_host_ide_key_set(kcbar, rp_stream_index, PCI_IDE_KM_KEY_SET_K1);

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|TX|PR\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_PR, 0, true, "  Assertion 3.3");
  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|TX|PR failed with 0x%x\n", k_set_names[PCI_IDE_KM_KEY_SET_K1], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|TX|NPR\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, 0, true, "  Assertion 3.3");

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|TX|NPR failed with 0x%x\n", k_set_names[PCI_IDE_KM_KEY_SET_K1], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|TX|CPL\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, 0, true, "  Assertion 3.3");

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|TX|CPL failed with 0x%x\n", k_set_names[PCI_IDE_KM_KEY_SET_K1], status));
    return false;
  }

  // enable dev ide
  TEST_IDE_TYPE ide_type = TEST_IDE_TYPE_SEL_IDE;
  if (top_type == IDE_TEST_TOPOLOGY_TYPE_LINK_IDE)
  {
    ide_type = IDE_TEST_TOPOLOGY_TYPE_LINK_IDE;
  }
  else if(top_type == IDE_TEST_TOPOLOGY_TYPE_SEL_LINK_IDE)
  {
    NOT_IMPLEMENTED("selective_and_link_ide topoplogy");
  }
  enable_ide_stream_in_ecap(lower_port->cfg_space_fd, lower_port->ecap_offset, ide_type, lower_port->ide_id, true);

  // enable host ide stream
  enable_host_ide_stream(upper_port->cfg_space_fd,
                         upper_port->ecap_offset,
                         ide_type, upper_port->ide_id,
                         kcbar_addr,
                         rp_stream_index, true);

  // wait for 10 ms for device to get ide ready
  libspdm_sleep(10 * 1000);

  // Now ide stream shall be in secure state
  uint32_t data = read_host_stream_status_in_ecap(upper_port->cfg_space_fd, upper_port->ecap_offset, ide_type, upper_port->ide_id);
  PCIE_SEL_IDE_STREAM_STATUS stream_status = {.raw = data};
  if (stream_status.state != IDE_STREAM_STATUS_SECURE)
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "ide_stream state is %x.\n", stream_status.state));
    return false;
  }

  return true;
}

bool test_ksetgo_4_run_phase2(void* doe_context, void* spdm_context, uint32_t* session_id,
                              uint8_t stream_id, uint8_t rp_stream_index, uint8_t ide_id,
                              uint8_t* kcbar_addr, IDE_TEST_TOPOLOGY_TYPE top_type)
{
  libspdm_return_t status;
  bool res = false;

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetGo K0|RX|PR\n"));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_PR, 0,
                             false, "  Assertion 3.3");
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    goto Done;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetGo K0|RX|NPR\n"));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                              PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, 0,
                              false, "  Assertion 3.3");
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    goto Done;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetGo K0|RX|CPL\n"));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, 0,
                             false, "  Assertion 3.3");
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    goto Done;
  }

  // set key_set_select in host ide
  INTEL_KEYP_ROOT_COMPLEX_KCBAR *kcbar = (INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr;
  set_host_ide_key_set(kcbar, rp_stream_index, PCIE_IDE_STREAM_KS1);

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetGo K0|TX|PR\n"));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_PR, 0,
                             false, "  Assertion 3.3");
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    goto Done;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetGo K0|TX|NPR\n"));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                              PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, 0,
                              false, "  Assertion 3.3");
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    goto Done;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetGo K0|TX|CPL\n"));
  status = test_ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                              PCI_IDE_KM_KEY_SET_K0 | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, 0,
                              false, "  Assertion 3.3");
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    goto Done;
  }

  res = true;

  // wait for 10 ms for device to get ide ready
  libspdm_sleep(10 * 1000);

Done:

  return res;
}

bool test_ksetgo_4_run(void *test_context)
{
  bool res = false;

  ide_common_test_case_context_t *case_context = (ide_common_test_case_context_t *)test_context;
  assert(case_context);
  assert(case_context->signature == CASE_CONTEXT_SIGNATURE);

  ide_common_test_group_context_t *group_context = (ide_common_test_group_context_t *)case_context->group_context;
  assert(group_context);
  assert(group_context->signature == GROUP_CONTEXT_SIGNATURE);

  uint8_t stream_id = group_context->stream_id;
  void *doe_context = group_context->doe_context;
  void *spdm_context = group_context->spdm_context;
  uint32_t session_id = group_context->session_id;

  ide_common_test_port_context_t* upper_port = &group_context->upper_port;
  ide_common_test_port_context_t* lower_port = &group_context->lower_port;

  // phase 1
  res = test_ksetgo_4_run_phase1(doe_context, spdm_context, &session_id,
                                stream_id, group_context->rp_stream_index,
                                upper_port->mapped_kcbar_addr, group_context->top->type,
                                upper_port, lower_port);
  if(!res) {
    goto Done;
  }

  // then switch to KS0 (skip ksetgo)
  res = ide_key_switch_to(group_context->doe_context, group_context->spdm_context, &group_context->session_id,
                          upper_port->mapped_kcbar_addr, group_context->stream_id,
                          group_context->k_set, group_context->rp_stream_index,
                          0, group_context->top->type, upper_port, lower_port,
                          PCIE_IDE_STREAM_KS0, true);
  if(!res) {
    goto Done;
  }

  // phase 2
  res = test_ksetgo_4_run_phase2(doe_context, spdm_context, &session_id,
                                stream_id, group_context->rp_stream_index, upper_port->ide_id,
                                upper_port->mapped_kcbar_addr, group_context->top->type);

Done:
  case_context->result = res ? IDE_COMMON_TEST_CASE_RESULT_SUCCESS : IDE_COMMON_TEST_CASE_RESULT_FAILED;

  return true;
}

bool test_ksetgo_4_teardown(void *test_context)
{
  return true;
}
