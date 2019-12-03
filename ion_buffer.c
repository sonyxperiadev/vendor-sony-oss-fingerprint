/**
 *
 *
 */

#include "ion_buffer.h"

#define LOG_TAG "FPC"
#include <log/log.h>

#define ION_ALIGN 0x1000
#define ION_ALIGN_MASK (ION_ALIGN - 1)

static int open_ion_device() {
    int ion_dev_fd = ion_open();

    LOG_ALWAYS_FATAL_IF(ion_dev_fd < 0, "Failed to open /dev/ion: %s", strerror(errno));

    return ion_dev_fd;
}

int32_t qcom_km_ion_memalloc(struct qcom_km_ion_info_t *handle, size_t size) {
    size_t aligned_size = (size + ION_ALIGN_MASK) & ~ION_ALIGN_MASK;
    int rc = 0;
    int ion_data_fd = -1;
    unsigned char *mapped = NULL;
    int ion_fd = open_ion_device();

    /* Allocate buffer */
    rc = ion_alloc_fd(ion_fd, aligned_size, ION_ALIGN,
                      ION_HEAP(ION_QSECOM_HEAP_ID),
                      /* flags: */ 0, &ion_data_fd);
    LOG_ALWAYS_FATAL_IF(rc, "Failed to allocate ION buffer");

    /* Map buffer to memory */
    mapped = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE,
                  MAP_SHARED, ion_data_fd, 0);
    LOG_ALWAYS_FATAL_IF(mapped == MAP_FAILED, "Failed to map ION buffer");

    *handle = (struct qcom_km_ion_info_t){
        .ion_fd = ion_fd,
        .ifd_data_fd = ion_data_fd,
        .ion_sbuffer = mapped,
        .sbuf_len = aligned_size,
        .req_len = size,
    };

    return 0;
}

int32_t qcom_km_ion_dealloc(struct qcom_km_ion_info_t *handle) {
    int rc = 0;

    if (handle->ion_sbuffer) {
        rc = munmap(handle->ion_sbuffer, handle->sbuf_len);
        LOG_ALWAYS_FATAL_IF(rc, "Failed to munmap ION buffer");
        handle->ion_sbuffer = NULL;
    }

    if (handle->ifd_data_fd >= 0) {
        rc = close(handle->ifd_data_fd);
        LOG_ALWAYS_FATAL_IF(rc, "Failed to close ION buffer");
        handle->ifd_data_fd = -1;
    }

    if (handle->ion_fd >= 0) {
        rc = ion_close(handle->ion_fd);
        LOG_ALWAYS_FATAL_IF(rc, "Failed to close ION device");
        handle->ion_fd = -1;
    }

    return rc;
}
