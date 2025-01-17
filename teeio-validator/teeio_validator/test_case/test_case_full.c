/**
 *  Copyright Notice:
 *  Copyright 2023-2024 Intel. All rights reserved.
 *  License: BSD 3-Clause License.
 **/

#include <stdlib.h>
#include <stdio.h>
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

void dump_host_registers(uint8_t *kcbar_addr, uint8_t rp_stream_index, int cfg_space_fd, uint8_t ide_id, uint32_t ecap_offset, TEST_IDE_TYPE ide_type);
void dump_dev_registers(int cfg_space_fd, uint8_t ide_id, uint32_t ecap_offset, TEST_IDE_TYPE ide_type);

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

bool test_full_1_setup(void *test_context)
{
  ide_common_test_case_context_t *case_context = (ide_common_test_case_context_t *)test_context;
  assert(case_context);
  assert(case_context->signature == CASE_CONTEXT_SIGNATURE);

  ide_common_test_group_context_t *group_context = case_context->group_context;
  assert(group_context);
  assert(group_context->signature == GROUP_CONTEXT_SIGNATURE);

  ide_common_test_port_context_t* upper_port = &group_context->upper_port;
  ide_common_test_port_context_t* lower_port = &group_context->lower_port;

  return setup_ide_stream(group_context->doe_context, group_context->spdm_context, &group_context->session_id,
                          upper_port->mapped_kcbar_addr, group_context->stream_id, PCI_IDE_KM_KEY_SET_K0,
                          group_context->k_set, group_context->rp_stream_index,
                          0, group_context->top->type, upper_port, lower_port, false);

}

bool test_full_1_run(void *test_context)
{
  ide_common_test_case_context_t *case_context = (ide_common_test_case_context_t *)test_context;
  assert(case_context);
  assert(case_context->signature == CASE_CONTEXT_SIGNATURE);

  ide_common_test_group_context_t *group_context = (ide_common_test_group_context_t *)case_context->group_context;
  assert(group_context);
  assert(group_context->signature == GROUP_CONTEXT_SIGNATURE);

  TEST_IDE_TYPE ide_type = TEST_IDE_TYPE_SEL_IDE;
  if (group_context->top->type == IDE_TEST_TOPOLOGY_TYPE_LINK_IDE)
  {
    ide_type = IDE_TEST_TOPOLOGY_TYPE_LINK_IDE;
  }
  else if(group_context->top->type == IDE_TEST_TOPOLOGY_TYPE_SEL_LINK_IDE)
  {
    NOT_IMPLEMENTED("selective_and_link_ide topoplogy");
  }

  // dump registers
  TEEIO_PRINT(("\nPrint host registers.\n"));
  dump_host_registers(group_context->upper_port.mapped_kcbar_addr,
                    group_context->rp_stream_index,
                    group_context->upper_port.cfg_space_fd,
                    group_context->upper_port.ide_id,
                    group_context->upper_port.ecap_offset,
                    ide_type);

  TEEIO_PRINT(("\nPrint device registers.\n"));
  dump_dev_registers(group_context->lower_port.cfg_space_fd,
                    group_context->lower_port.ide_id,
                    group_context->lower_port.ecap_offset,
                    ide_type);

  TEEIO_PRINT(("ide_stream is setup. Press any key to continue.\n"));
  getchar();

  case_context->result = IDE_COMMON_TEST_CASE_RESULT_SUCCESS;
  return true;
}

static bool test_full_ide_km_key_set_stop(const void *pci_doe_context,
                            void *spdm_context, const uint32_t *session_id,
                            uint8_t stream_id, uint8_t key_sub_stream,
                            uint8_t port_index)
{
    libspdm_return_t status;
    pci_ide_km_k_set_stop_t request;
    size_t request_size;
    pci_ide_km_k_gostop_ack_t response;
    size_t response_size;

    libspdm_zero_mem (&request, sizeof(request));
    request.header.object_id = PCI_IDE_KM_OBJECT_ID_K_SET_STOP;
    request.stream_id = stream_id;
    request.key_sub_stream = key_sub_stream;
    request.port_index = port_index;

    request_size = sizeof(request);
    response_size = sizeof(response);
    status = pci_ide_km_send_receive_data(spdm_context, session_id,
                                          &request, request_size,
                                          &response, &response_size);
    // Assertion.0
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
      TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "         key_set_stop: send_receive_datra failed with 0x%08x.\n", status));
      return false;
    }

    bool res = response_size == sizeof(pci_ide_km_k_gostop_ack_t);
    if(!res) {
      TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "         key_set_stop: failed with response_size error.\n"));
      return false;
    }

    // Assertion.2
    res = response.header.object_id == PCI_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK;
    if(!res) {
      TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "         key_set_stop: failed with response.header.object_id error.\n"));
      return false;
    }

    // Assertion.3
    res = (response.port_index == request.port_index);
    if(!res) {
      TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "         key_set_stop: failed with response.port_index error.\n"));
      return false;
    }

    // Assertion.4
    res = (response.stream_id == request.stream_id);
    if(!res) {
      TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "         key_set_stop: failed with response.stream_id error.\n"));
        return false;
    }

    // Assertion.5
    res = (response.key_sub_stream == request.key_sub_stream);
    if(!res) {
      TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "         key_set_stop: failed with response.key_sub_stream error.\n"));
      return false;
    }

    return true;
}

bool test_full_teardown_common(void *test_context)
{
  // first diable dev_ide and host_ide
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
  uint8_t ks = PCI_IDE_KM_KEY_SET_K0;
  uint8_t port_index = 0;
  bool res = false;

  // then test KSetStop  
  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|RX|PR\n", k_set_names[ks]));
  res = test_full_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_PR, port_index);
  if(!res) {
    goto TestFullTeardownDone;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|RX|NPR\n", k_set_names[ks]));
  res = test_full_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, port_index);
  if(!res) {
    goto TestFullTeardownDone;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|RX|CPL\n", k_set_names[ks]));
  res = test_full_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, port_index);
  if(!res) {
    goto TestFullTeardownDone;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|TX|PR\n", k_set_names[ks]));
  res = test_full_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_PR, port_index);
  if(!res) {
    goto TestFullTeardownDone;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|TX|NPR\n", k_set_names[ks]));
  res = test_full_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, port_index);
  if(!res) {
    goto TestFullTeardownDone;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[idetest]       Test KSetStop %s|TX|CPL\n", k_set_names[ks]));
  res = test_full_ide_km_key_set_stop(doe_context, spdm_context, &session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, port_index);

TestFullTeardownDone:

  return res;
}

bool test_full_1_teardown(void *test_context)
{
  return test_full_teardown_common(test_context);
}
