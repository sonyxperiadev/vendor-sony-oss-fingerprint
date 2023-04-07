#include "QSEETrustlet.h"

#include "FormatException.hpp"

#include <dlfcn.h>
#include <errno.h>
#include <string.h>

#include <algorithm>

#define LOG_TAG "FPC QSEETrustlet"
// #define LOG_NDEBUG 0
#include <log/log.h>

#ifndef QSEE_LIBRARY
#define QSEE_LIBRARY "libQSEEComAPI.so"
// #warning "No QSEE Library defined! Defaulting to " QSEE_LIBRARY
#endif

void *QSEETrustlet::libHandle = nullptr;
QSEETrustlet::start_app_def QSEETrustlet::start_app = nullptr;
QSEETrustlet::shutdown_app_def QSEETrustlet::shutdown_app = nullptr;
QSEETrustlet::send_cmd_def QSEETrustlet::send_cmd = nullptr;
QSEETrustlet::send_modified_cmd_def QSEETrustlet::send_modified_cmd = nullptr;

QSEETrustlet::QSEETrustlet(const char *app_name, uint32_t shared_buffer_size, const char *path) {
    EnsureInitialized();

    int rc = start_app(&mHandle, path, app_name, shared_buffer_size);
    if (rc)
        throw FormatException("start_app failed with rc=%d", rc);
}

QSEETrustlet::~QSEETrustlet() {
    if (mHandle != NULL)
        shutdown_app(&mHandle);
}

QSEETrustlet::QSEETrustlet(QSEETrustlet &&other) : mHandle(other.mHandle) {
    // Make the moved-from object invalid (preventing unlock()).
    other.mHandle = nullptr;
}

QSEETrustlet &QSEETrustlet::operator=(QSEETrustlet &&other) {
    std::swap(mHandle, other.mHandle);
    return *this;
}

void QSEETrustlet::EnsureInitialized() {
    if (libHandle)
        return;

    ALOGV("Using Target Lib : %s\n", QSEE_LIBRARY);
    libHandle = dlopen(QSEE_LIBRARY, RTLD_NOW);
    ALOGV("Loaded QSEECom API library at %p\n", libHandle);

    start_app = (start_app_def)dlsym(libHandle, "QSEECom_start_app");
    if (start_app == nullptr) {
        ALOGE("Error loading QSEECom_start_app: %s\n", strerror(errno));
        throw FormatException("Failed to load QSEECom_start_app!");
    }

    shutdown_app = (shutdown_app_def)dlsym(libHandle, "QSEECom_shutdown_app");
    if (shutdown_app == nullptr) {
        ALOGE("Error loading QSEECom_shutdown_app: %s\n", strerror(errno));
        throw FormatException("Failed to load QSEECom_shutdown_app!");
    }

    send_cmd = (send_cmd_def)dlsym(libHandle, "QSEECom_send_cmd");
    if (send_cmd == nullptr) {
        ALOGE("Error loading QSEECom_send_cmd: %s\n", strerror(errno));
        throw FormatException("Failed to load QSEECom_send_cmd!");
    }

    send_modified_cmd = (send_modified_cmd_def)dlsym(libHandle, "QSEECom_send_modified_cmd");
    if (send_modified_cmd == nullptr) {
        ALOGE("Error loading QSEECom_send_modified_cmd: %s\n", strerror(errno));
        throw FormatException("Failed to load QSEECom_send_modified_cmd!");
    }
}

QSEETrustlet::LockedIONBuffer QSEETrustlet::GetLockedBuffer() {
    return LockedIONBuffer(this);
}

QSEETrustlet::LockedIONBuffer::LockedIONBuffer(QSEETrustlet *trustlet) : mTrustlet(trustlet) {
    if (trustlet) {
        ALOGV("Locking %p", mTrustlet);
        mTrustlet->mBufferMutex.lock();
    }
}

QSEETrustlet::LockedIONBuffer::~LockedIONBuffer() {
    if (mTrustlet) {
        ALOGV("Unlocking %p", mTrustlet);
        mTrustlet->mBufferMutex.unlock();
    }
}

QSEETrustlet::LockedIONBuffer::LockedIONBuffer(LockedIONBuffer &&other) : mTrustlet(other.mTrustlet) {
    // Not locking; was already locked by the regular constructor.
    // Mark the shortliving object as "invalid" to prevent unlocking.
    // (There exists no swap/move for mutexes to make the other handle invalid)
    other.mTrustlet = nullptr;
}

QSEETrustlet::LockedIONBuffer &QSEETrustlet::LockedIONBuffer::operator=(QSEETrustlet::LockedIONBuffer &&other) {
    std::swap(mTrustlet, other.mTrustlet);
    return *this;
}

void *QSEETrustlet::LockedIONBuffer::operator*() {
    return mTrustlet->mHandle->ion_sbuffer;
}

const void *QSEETrustlet::LockedIONBuffer::operator*() const {
    return mTrustlet->mHandle->ion_sbuffer;
}

int QSEETrustlet::SendCommand(const void *send_buf, uint32_t sbuf_len, void *rcv_buf, uint32_t rbuf_len) {
    return send_cmd(mHandle, send_buf, sbuf_len, rcv_buf, rbuf_len);
}

int QSEETrustlet::SendModifiedCommand(const void *send_buf, uint32_t sbuf_len, void *rcv_buf, uint32_t rbuf_len, QSEECom_ion_fd_info *ifd_data) {
    return send_modified_cmd(mHandle, send_buf, sbuf_len, rcv_buf, rbuf_len, ifd_data);
}
