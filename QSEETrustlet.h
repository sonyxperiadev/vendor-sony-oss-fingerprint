#pragma once

#include "QSEEComAPI.h"

#include <inttypes.h>

#include <mutex>

class QSEETrustlet {
   public:
    QSEETrustlet(const char *app_name, uint32_t shared_buffer_size, const char *path = "/vendor/firmware_mnt/image");
    ~QSEETrustlet();

    // QSEETrustlet(const QSEETrustlet &) = delete;
    // Move constructor implicitly forbids copy constructor,
    // preventing accidental duplicate handles to the same trustlet.
    QSEETrustlet(QSEETrustlet &&);
    QSEETrustlet &operator=(QSEETrustlet &&);
    // QSEETrustlet &operator=(const QSEETrustlet &) = delete;

   protected:
    class LockedIONBuffer {
        QSEETrustlet *mTrustlet;

        LockedIONBuffer(QSEETrustlet *trustlet);

       public:
        ~LockedIONBuffer();
        // Only allow moves.
        LockedIONBuffer(LockedIONBuffer &&);
        LockedIONBuffer &operator=(LockedIONBuffer &&);
        LockedIONBuffer(LockedIONBuffer &) = delete;
        const LockedIONBuffer &operator=(const LockedIONBuffer &) = delete;

        void *operator*();
        const void *operator*() const;

        friend class QSEETrustlet;
    };
    friend class LockedIONBuffer;

    LockedIONBuffer GetLockedBuffer();
    int SendCommand(const void *send_buf, uint32_t sbuf_len, void *rcv_buf, uint32_t rbuf_len);
    int SendModifiedCommand(const void *send_buf, uint32_t sbuf_len, void *rcv_buf, uint32_t rbuf_len, QSEECom_ion_fd_info *ifd_data);

   private:
    std::mutex mBufferMutex;
    QSEECom_handle *mHandle = nullptr;

    typedef int (*start_app_def)(struct QSEECom_handle **clnt_handle, const char *path, const char *fname, uint32_t sb_size);
    typedef int (*shutdown_app_def)(struct QSEECom_handle **clnt_handle);
    typedef int (*send_cmd_def)(struct QSEECom_handle *handle, const void *send_buf, uint32_t sbuf_len, void *rcv_buf, uint32_t rbuf_len);
    typedef int (*send_modified_cmd_def)(struct QSEECom_handle *handle, const void *send_buf, uint32_t sbuf_len, void *resp_buf, uint32_t rbuf_len, struct QSEECom_ion_fd_info *ifd_data);

    static void *libHandle;
    static start_app_def start_app;
    static shutdown_app_def shutdown_app;
    static send_cmd_def send_cmd;
    static send_modified_cmd_def send_modified_cmd;

    static void EnsureInitialized();
};
