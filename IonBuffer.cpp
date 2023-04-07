#include "IonBuffer.h"

#include <algorithm>

#define LOG_TAG "FPC"
#include <log/log.h>

IonBuffer::IonBuffer(size_t sz) {
    qcom_km_ion_memalloc(&ion_info, sz);
}

IonBuffer::~IonBuffer() {
    qcom_km_ion_dealloc(&ion_info);
}

IonBuffer::IonBuffer(IonBuffer &&other) {
    std::swap(ion_info, other.ion_info);
}

IonBuffer &IonBuffer::operator=(IonBuffer &&other) {
    // Invoke move constructor:
    return *new (this) IonBuffer(std::move(other));
}

size_t IonBuffer::requestedSize() const {
    return ion_info.req_len;
}

int IonBuffer::fd() const {
    return ion_info.ifd_data_fd;
}

void *IonBuffer::operator()() {
    return ion_info.ion_sbuffer;
}

const void *IonBuffer::operator()() const {
    return ion_info.ion_sbuffer;
}
