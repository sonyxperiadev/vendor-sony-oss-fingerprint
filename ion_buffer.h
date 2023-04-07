
#ifndef __ION_WRAPPER_H_
#define __ION_WRAPPER_H_

#include <stdint.h>
// WARNING: Must include stdint before msm_ion, or it'll miss the size_t definition!
#include <errno.h>
#include <fcntl.h>
#include <ion/ion.h>
#include <linux/msm_ion.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

__BEGIN_DECLS

struct qcom_km_ion_info_t {
    int ion_fd;
    int ifd_data_fd;
    unsigned char *ion_sbuffer;
    uint32_t req_len, sbuf_len;
};

typedef int32_t (*ion_free_def)(struct qcom_km_ion_info_t *handle);
typedef int32_t (*ion_alloc_def)(struct qcom_km_ion_info_t *handle, size_t size);

int32_t qcom_km_ion_memalloc(struct qcom_km_ion_info_t *handle, size_t size);
int32_t qcom_km_ion_dealloc(struct qcom_km_ion_info_t *handle);

__END_DECLS

#endif
