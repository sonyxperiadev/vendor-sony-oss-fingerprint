#include "DmaBuffer.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#define LOG_TAG "FPC DmaBuffer"
#include <log/log.h>

DmaBuffer::DmaBuffer(BufferAllocator &allocator, size_t len) : len(len) {
    allocFd = allocator.Alloc(DMABUF_QCOM_QSEECOM_HEAP_NAME, len);
    LOG_ALWAYS_FATAL_IF(allocFd < 0, "Failed to allocate DMA heap buffer on qseecom heap");
    map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, allocFd, 0);
    ALOGD("Mapped %p", map);

    LOG_ALWAYS_FATAL_IF(!map, "Failed to map DMA heap buffer");
}

DmaBuffer::~DmaBuffer() {
    munmap(map, len);
    close(allocFd);
}

size_t DmaBuffer::requestedSize() const {
    return len;
}

int DmaBuffer::fd() const {
    return allocFd;
}

void *DmaBuffer::operator()() {
    return map;
}
const void *DmaBuffer::operator()() const {
    return map;
}
