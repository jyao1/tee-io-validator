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

extern const char *k_set_names[];

bool setup_ide_stream(void* doe_context, void* spdm_context,
                                uint32_t* session_id, uint8_t* kcbar_addr,
                                uint8_t stream_id, uint8_t ks,
                                ide_key_set_t* k_set, uint8_t rp_stream_index,
                                uint8_t port_index, IDE_TEST_TOPOLOGY_TYPE top_type,
                                ide_common_test_port_context_t* upper_port,
                                ide_common_test_port_context_t* lower_port,
                                bool skip_ksetgo);

bool ide_key_switch_to(void* doe_context, void* spdm_context,
                    uint32_t* session_id, uint8_t* kcbar_addr,
                    uint8_t stream_id, ide_key_set_t* k_set, uint8_t rp_stream_index,
                    uint8_t port_index, IDE_TEST_TOPOLOGY_TYPE top_type,
                    ide_common_test_port_context_t* upper_port,
                    ide_common_test_port_context_t* lower_port,
                    uint8_t ks, bool skip_ksetgo);
bool enable_ide_stream_in_ecap(int cfg_space_fd, uint32_t ecap_offset, TEST_IDE_TYPE ide_type, uint8_t ide_id, bool enable);
void enable_host_ide_stream(int cfg_space_fd, uint32_t ecap_offset, TEST_IDE_TYPE ide_type, uint8_t ide_id, uint8_t *kcbar_addr, uint8_t rp_stream_index, bool enable);
bool test_pci_ide_km_key_set_stop(const void *pci_doe_context,
                            void *spdm_context, const uint32_t *session_id,
                            uint8_t stream_id, uint8_t key_sub_stream,
                            uint8_t port_index, const char* case_msg);
bool pre_alloc_slot_ids(uint8_t rp_stream_index, ide_key_set_t* k_set, uint8_t num_rx_key_slots, bool ide_key_refresh);

// KSetStop Case 4.3
bool test_ksetstop_3_setup(void *test_context)
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

  // first setup ide_stream for KS0
  bool res = setup_ide_stream(group_context->doe_context, group_context->spdm_context, &group_context->session_id,
                          upper_port->mapped_kcbar_addr, group_context->stream_id, PCI_IDE_KM_KEY_SET_K0,
                          group_context->k_set, group_context->rp_stream_index,
                          0, group_context->top->type, upper_port, lower_port, false);
  if(!res) {
    return false;
  }

  // then switch to KS1
  res = ide_key_switch_to(group_context->doe_context, group_context->spdm_context, &group_context->session_id,
                          upper_port->mapped_kcbar_addr, group_context->stream_id,
                          group_context->k_set, group_context->rp_stream_index,
                          0, group_context->top->type, upper_port, lower_port, PCIE_IDE_STREAM_KS1, false);

  return res;
}

bool test_ksetstop_3_run(void *test_context)
{
  ide_common_test_case_context_t *case_context = (ide_common_test_case_context_t *)test_context;
  assert(case_context);
  assert(case_context->signature == CASE_CONTEXT_SIGNATURE);

  ide_common_test_group_context_t *group_context = case_context->group_context;
  assert(group_context);
  assert(group_context->signature == GROUP_CONTEXT_SIGNATURE);

  ide_common_test_port_context_t* upper_port = &group_context->upper_port;
  ide_common_test_port_context_t* lower_port = &group_context->lower_port;

  IDE_TEST_TOPOLOGY_TYPE top_type = group_context->top->type;

  // disable dev ide
  TEST_IDE_TYPE ide_type = TEST_IDE_TYPE_SEL_IDE;
  if (top_type == IDE_TEST_TOPOLOGY_TYPE_LINK_IDE)
  {
    ide_type = IDE_TEST_TOPOLOGY_TYPE_LINK_IDE;
  }
  else if(top_type == IDE_TEST_TOPOLOGY_TYPE_SEL_LINK_IDE)
  {
    NOT_IMPLEMENTED("selective_and_link_ide topoplogy");
  }
  enable_ide_stream_in_ecap(lower_port->cfg_space_fd, lower_port->ecap_offset, ide_type, lower_port->ide_id, false);

  // disable host ide stream
  enable_host_ide_stream(upper_port->cfg_space_fd,
                         upper_port->ecap_offset,
                         ide_type, upper_port->ide_id,
                         upper_port->mapped_kcbar_addr,
                         group_context->rp_stream_index, false);

  void* doe_context = group_context->doe_context;
  void* spdm_context = group_context->spdm_context;
  uint32_t session_id = group_context->session_id;
  uint8_t stream_id = group_context->stream_id;
  uint8_t port_index = 0;
  bool res = false;

  // then test KSetStop  
  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|RX|PR\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  res = test_pci_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_PR, port_index,
                             "  Assertion 4.3");
  if(!res) {
    goto TestKSetStopCase3Done;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|RX|NPR\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  res = test_pci_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, port_index,
                             "  Assertion 4.3");
  if(!res) {
    goto TestKSetStopCase3Done;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|RX|CPL\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  res = test_pci_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, port_index,
                             "  Assertion 4.3");
  if(!res) {
    goto TestKSetStopCase3Done;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|TX|PR\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  res = test_pci_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_PR, port_index,
                             "  Assertion 4.3");
  if(!res) {
    goto TestKSetStopCase3Done;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|TX|NPR\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  res = test_pci_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, port_index,
                             "  Assertion 4.3");
  if(!res) {
    goto TestKSetStopCase3Done;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|TX|CPL\n", k_set_names[PCI_IDE_KM_KEY_SET_K1]));
  res = test_pci_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             PCI_IDE_KM_KEY_SET_K1 | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, port_index,
                             "  Assertion 4.3");

TestKSetStopCase3Done:
  case_context->result = res ? IDE_COMMON_TEST_CASE_RESULT_SUCCESS : IDE_COMMON_TEST_CASE_RESULT_FAILED;

  return true;
}

bool test_ksetstop_3_teardown(void *test_context)
{
  return true;
}
