#include <BufferAllocator/BufferAllocator.h>
#include <stddef.h>

#define DMABUF_QCOM_QSEECOM_HEAP_NAME "qcom,qseecom"

class DmaBuffer {
    int allocFd;
    size_t len;
    void *map;

   public:
    DmaBuffer(BufferAllocator &allocator, size_t len);
    ~DmaBuffer();

    DmaBuffer(DmaBuffer &) = delete;
    const DmaBuffer &operator=(const DmaBuffer &) = delete;

    size_t requestedSize() const;
    int fd() const;

    void *operator()();
    const void *operator()() const;
};

template <typename T>
class TypedDmaBuffer : public DmaBuffer {
   public:
    TypedDmaBuffer(BufferAllocator &allocator) : DmaBuffer(allocator, sizeof(T)) {
    }

    T *operator()() {
        return (T *)DmaBuffer::operator()();
    }
    const T *operator()() const {
        return (T *)DmaBuffer::operator()();
    }
    T *operator->() {
        return (T *)DmaBuffer::operator()();
    }
    const T *operator->() const {
        return (T *)DmaBuffer::operator()();
    }
    T &operator*() {
        return *operator()();
    }
    const T &operator*() const {
        return *operator()();
    }
};
