#pragma once

#include "ion_buffer.h"

class IonBuffer {
    qcom_km_ion_info ion_info;

   public:
    IonBuffer(size_t);
    ~IonBuffer();

    IonBuffer(IonBuffer &&);
    IonBuffer &operator=(IonBuffer &&);
    IonBuffer(IonBuffer &) = delete;
    const IonBuffer &operator=(const IonBuffer &) = delete;

    size_t requestedSize() const;
    int fd() const;

    void *operator()();
    const void *operator()() const;
};

template <typename T>
class TypedIonBuffer : public IonBuffer {
   public:
    TypedIonBuffer() : IonBuffer(sizeof(T)) {
    }

    T *operator()() {
        return (T *)IonBuffer::operator()();
    }
    const T *operator()() const {
        return (T *)IonBuffer::operator()();
    }
    T *operator->() {
        return (T *)IonBuffer::operator()();
    }
    const T *operator->() const {
        return (T *)IonBuffer::operator()();
    }
    T &operator*() {
        return *operator()();
    }
    const T &operator*() const {
        return *operator()();
    }
};
