/**
 *  Copyright Notice:
 *  Copyright 2023-2024 Intel. All rights reserved.
 *  License: BSD 3-Clause License.
 **/

#include "teeio_validator.h"

void *m_pci_doe_context;

libspdm_return_t pci_doe_init_request()
{
    pci_doe_data_object_protocol_t data_object_protocol[6];
    size_t data_object_protocol_size;
    libspdm_return_t status;
    uint32_t index;

    data_object_protocol_size = sizeof(data_object_protocol);
    status =
        pci_doe_discovery (m_pci_doe_context, data_object_protocol, &data_object_protocol_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    for (index = 0; index < data_object_protocol_size/sizeof(pci_doe_data_object_protocol_t);
         index++) {
        TEEIO_DEBUG((TEEIO_DEBUG_INFO, "DOE(0x%x) VendorId-0x%04x, DataObjectType-0x%02x\n",
                        index, data_object_protocol[index].vendor_id,
                        data_object_protocol[index].data_object_type));
    }

    return LIBSPDM_STATUS_SUCCESS;
}
