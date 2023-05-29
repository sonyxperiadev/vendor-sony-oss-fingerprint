#include "EGISAPTrustlet.h"

#include "FormatException.hpp"

#include <string.h>

#define LOG_TAG "FPC ET"
// #define LOG_NDEBUG 0
#include <log/log.h>

// Defined in a different kernel header depending on the
// kernel version.
#define ION_QSECOM_HEAP_NAME "qsecom"

namespace egistec::current {

void log_hex(const char *data, int length) {
    if (length <= 0 || data == NULL)
        return;

    // Trim leading nulls, 4 bytes at a time:
    int cnt = 0;
    for (; length > 0 && !*(const uint32_t *)data; cnt++, data += 4, length -= 4)
        ;

    // Trim trailing nulls:
    for (; length > 0 && !data[length - 1]; --length)
        ;

    if (length <= 0) {
        ALOGV("All data is 0!");
        return;
    }

    if (cnt)
        ALOGV("Skipped %d integers (%d bytes)", cnt, cnt * 4);

    // Format the byte-buffer into hexadecimals:
    char *buf = (char *)malloc(length * 3 + 10);
    char *base = buf;
    for (int i = 0; i < length; i++) {
        sprintf(buf, "%02X", data[i]);
        buf += 2;
        *buf++ = ' ';

        if (i % 16 == 15 || i + 1 == length) {
            *buf = '\0';
            ALOGV("%s", base);
            buf = base;
        }
    }

    free(base);
}

EGISAPTrustlet::EGISAPTrustlet() : QSEETrustlet(EGIS_QSEE_APP_NAME, 0x2400
#ifdef EGIS_QSEE_APP_PATH
                                                ,
                                                EGIS_QSEE_APP_PATH
#endif
                                   ) {
    if (dmabuf_allocator.CheckIonSupport()) {
        // Provide legacy mapping to ION devices
        int ret = dmabuf_allocator.MapNameToIonHeap(DMABUF_QCOM_QSEECOM_HEAP_NAME, ION_QSECOM_HEAP_NAME);
        LOG_ALWAYS_FATAL_IF(ret, "Failed to map DMABUF heap name to ION heap name: %d", ret);
    }
}

#define CAPTURE_ERROR(cmd)                                    \
    ({                                                        \
        int rc = cmd;                                         \
        ALOGE_IF(rc, "%s failed with rc = %d", __func__, rc); \
        rc;                                                   \
    })

int EGISAPTrustlet::SendCommand(EGISAPTrustlet::API &api) {
    // TODO: += !
    api.GetRequest().process = 0xe0;
    auto &base = api.PrepareBase(api.GetRequest().process);

    // Already covered by memset:
    // base.no_extra_buffer = 0;
    // base.extra_buffer_size = 0;

#if !LOG_NDEBUG
    log_hex(reinterpret_cast<const char *>(&api.GetRequest()), sizeof(trustlet_buffer_t));
#endif

    int rc = QSEETrustlet::SendCommand(&base, 0x880, &base, 0x840);
    if (rc) {
        ALOGE("%s failed with rc = %d", __func__, rc);
        return rc;
    }

#if !LOG_NDEBUG
    ALOGV("Response:");
    log_hex(reinterpret_cast<const char *>(&api.GetResponse()), sizeof(trustlet_buffer_t));
#endif

    // TODO: List expected response codes in an enum.
    rc = base.ret_val;
    ALOGE_IF(rc, "%s ret_val = %#x", __func__, rc);
    return rc;
}

int EGISAPTrustlet::SendCommand(EGISAPTrustlet::API &buffer, CommandId commandId, uint32_t gid) {
    buffer.GetRequest().command = commandId;
    buffer.GetRequest().gid = gid;
    return SendCommand(buffer);
}

int EGISAPTrustlet::SendCommand(CommandId commandId, uint32_t gid) {
    auto api = GetLockedAPI();
    return SendCommand(api, commandId, gid);
}

int EGISAPTrustlet::SendModifiedCommand(EGISAPTrustlet::API &api, DmaBuffer &ionBuffer) {
    // TODO: += !
    api.GetRequest().process = 0xe0;
    auto &base = api.PrepareBase(api.GetRequest().process);

    QSEECom_ion_fd_info ifd_data = {};

    base.extra_buffer_size = ionBuffer.requestedSize();
    base.extra_flags = 0x5a;
    ifd_data.data[0] = {ionBuffer.fd(), 4};
    // TODO: Return buffer??
    ifd_data.data[1] = {ionBuffer.fd(), 8};

#if !LOG_NDEBUG
    log_hex(reinterpret_cast<const char *>(&api.GetRequest()), sizeof(trustlet_buffer_t));
#endif

    int rc = QSEETrustlet::SendModifiedCommand(&base, 0x880, &base, 0x840, &ifd_data);
    if (rc) {
        ALOGE("%s failed with rc = %d", __func__, rc);
        return rc;
    }

#if !LOG_NDEBUG
    ALOGV("Response:");
    log_hex(reinterpret_cast<const char *>(&api.GetResponse()), sizeof(trustlet_buffer_t));
#endif

    // Return size of the extra buffer:
    size_t returnSize = base.extra_buffer_size;
    ALOGD("Extra buffer return size: %zu", returnSize);

    // TODO: List expected response codes in an enum.
    rc = base.ret_val;
    ALOGE_IF(rc, "%s ret_val = %#x", __func__, rc);
    return rc;
}

int EGISAPTrustlet::SendModifiedCommand(EGISAPTrustlet::API &api, DmaBuffer &ionBuffer, CommandId commandId, uint32_t gid) {
    api.GetRequest().command = commandId;
    api.GetRequest().gid = gid;
    return SendModifiedCommand(api, ionBuffer);
}

int EGISAPTrustlet::SendModifiedCommand(DmaBuffer &ionBuffer, CommandId commandId, uint32_t gid) {
    auto api = GetLockedAPI();
    return SendModifiedCommand(api, ionBuffer, commandId, gid);
}

int EGISAPTrustlet::SendDataCommand(EGISAPTrustlet::API &buffer, CommandId commandId, const void *data, size_t length, uint32_t gid) {
    auto &req = buffer.GetRequest();
    req.buffer_size = length;
    memcpy(req.data, data, length);

    return SendCommand(buffer, commandId, gid);
}

int EGISAPTrustlet::SendDataCommand(CommandId commandId, const void *data, size_t length, uint32_t gid) {
    auto api = GetLockedAPI();
    return SendDataCommand(api, commandId, data, length, gid);
}

/**
 * Prepare buffer for use.
 */
EGISAPTrustlet::API EGISAPTrustlet::GetLockedAPI() {
    auto lockedBuffer = GetLockedBuffer();
    memset(*lockedBuffer, 0, EGISAPTrustlet::API::BufferSize());
    return lockedBuffer;
}

int EGISAPTrustlet::Calibrate() {
    return CAPTURE_ERROR(SendCommand(CommandId::Calibrate));
}

/**
 * Returns negative on error,
 * positive on event */
int EGISAPTrustlet::GetNavEvent(int &which) {
    TypedDmaBuffer<int> keycode_buf(dmabuf_allocator);

    auto api = GetLockedAPI();
    int rc = CAPTURE_ERROR(SendModifiedCommand(api, keycode_buf, CommandId::GetNavEvent, /* GID: */ 0));
    if (rc)
        return rc;

    LOG_ALWAYS_FATAL_IF(api.Base().extra_buffer_size != sizeof(which),
                        "%s: did not return exactly %zu bytes!",
                        __func__,
                        sizeof(which));

    which = *keycode_buf;
    ALOGV("%s: which=%d", __func__, which);

    return 0;
}

int EGISAPTrustlet::InitializeAlgo() {
    return CAPTURE_ERROR(SendCommand(CommandId::InitializeAlgo));
}

int EGISAPTrustlet::InitializeSensor() {
    return CAPTURE_ERROR(SendCommand(CommandId::InitializeSensor));
}

int EGISAPTrustlet::SetDataPath(const char *data_path) {
    return CAPTURE_ERROR(SendDataCommand(CommandId::SetDataPath, data_path, strlen(data_path), 1));
}

int EGISAPTrustlet::SetMasterKey(const MasterKey &key) {
    return CAPTURE_ERROR(SendDataCommand(CommandId::SetMasterKey, key.data(), key.size()));
}

int EGISAPTrustlet::SetUserDataPath(uint32_t gid, const char *data_path) {
    return CAPTURE_ERROR(SendDataCommand(CommandId::SetUserDataPath, data_path, strlen(data_path), gid));
}

int EGISAPTrustlet::SetWorkMode(WorkMode workMode) {
    // WARNING: Work mode is passed in through gid!
    return CAPTURE_ERROR(SendCommand(CommandId::SetWorkMode, (uint32_t)workMode));
}

int EGISAPTrustlet::UninitializeAlgo() {
    return CAPTURE_ERROR(SendCommand(CommandId::UninitializeAlgo));
}

int EGISAPTrustlet::UninitializeSdk() {
    return CAPTURE_ERROR(SendCommand(CommandId::UninitializeSdk));
}

int EGISAPTrustlet::UninitializeSensor() {
    return CAPTURE_ERROR(SendCommand(CommandId::UninitializeSensor));
}

uint32_t EGISAPTrustlet::GetHwId() {
    TypedDmaBuffer<uint32_t> id(dmabuf_allocator);
    int rc = CAPTURE_ERROR(SendModifiedCommand(id, CommandId::GetHwId));
    LOG_ALWAYS_FATAL_IF(rc, "Failed to get hardware ID!");
    return *id;
}

uint64_t EGISAPTrustlet::GetAuthenticatorId() {
    TypedDmaBuffer<uint64_t> id(dmabuf_allocator);
    auto api = GetLockedAPI();

    int rc = CAPTURE_ERROR(SendModifiedCommand(api, id, CommandId::GetAuthenticatorId));
    LOG_ALWAYS_FATAL_IF(rc, "Failed to get authenticator id!");

    // Nothing is returned when no prints are set up:
    ALOGW_IF(api.Base().extra_buffer_size != sizeof(uint64_t),
             "%s: did not return exactly sizeof(uint64_t) bytes!",
             __func__);
    if (api.Base().extra_buffer_size != sizeof(uint64_t))
        return -1;

    return *id;
}

int EGISAPTrustlet::GetImage(ImageResult &quality) {
    TypedDmaBuffer<ImageResult> ionBuffer(dmabuf_allocator);
    int rc = CAPTURE_ERROR(SendModifiedCommand(ionBuffer, CommandId::GetImage));
    if (rc)
        return rc;
    quality = *ionBuffer;
    ALOGD("GetImage quality = %d", quality);
    return 0;
}

int EGISAPTrustlet::IsFingerLost(uint32_t timeout, ImageResult &status) {
    TypedDmaBuffer<ImageResult> ionBuffer(dmabuf_allocator);
    // WARNING: timeout doesn't seem to change anything in terms of blocking.
    int rc = CAPTURE_ERROR(SendModifiedCommand(ionBuffer, CommandId::IsFingerLost, timeout));
    if (rc)
        return rc;
    status = *ionBuffer;
    ALOGD("IsFingerLost = %d", status);
    return 0;
}

int EGISAPTrustlet::SetSpiState(uint32_t on) {
    int rc = 0;
    ALOGD("Setting SPI state to %d", on);
    if (on)
        rc = CAPTURE_ERROR(SendCommand(CommandId::OpenSpi));
    else
        rc = CAPTURE_ERROR(SendCommand(CommandId::CloseSpi));
    ALOGE_IF(rc, "Failed to set SPI state to %d: %d", on, rc);
    return rc;
}

int EGISAPTrustlet::CheckAuthToken(const hw_auth_token_t &h) {
    return CAPTURE_ERROR(SendDataCommand(CommandId::CheckAuthToken, &h, sizeof(h)));
}

int EGISAPTrustlet::CheckSecureId(uint32_t gid, uint64_t user_id) {
    return CAPTURE_ERROR(SendDataCommand(CommandId::CheckSecureId, &user_id, sizeof(user_id), gid));
}

int EGISAPTrustlet::Enroll(uint32_t gid, uint32_t fid, enroll_result_t &result) {
    auto api = GetLockedAPI();
    api.GetRequest().fid = fid;
    TypedDmaBuffer<enroll_result_t> ionBuffer(dmabuf_allocator);

    int rc = CAPTURE_ERROR(SendModifiedCommand(api, ionBuffer, CommandId::Enroll, gid));
    if (rc)
        return rc;
    memcpy(&result, ionBuffer(), sizeof(result));
    return 0;
}

/**
 * Returns whether a print can be enrolled, and if the
 * chosen id is available.
 */
int EGISAPTrustlet::GetNewPrintId(uint32_t gid, uint32_t &new_print_id) {
    // Use a seed other than the default 1:
    srand(clock());

    std::vector<uint32_t> prints;
    int rc = GetPrintIds(gid, prints);
    if (rc)
        return rc;

    if (prints.size() >= 5)
        return -2;

    bool match;

    do {
        match = false;
        new_print_id = rand();

        ALOGD("%s: Trying %u", __func__, new_print_id);

        for (auto p : prints)
            if (p == new_print_id) {
                match = true;
                break;
            }
    } while (match);

    return 0;
}

int EGISAPTrustlet::InitializeEnroll() {
    return CAPTURE_ERROR(SendCommand(CommandId::InitializeEnroll));
}

int EGISAPTrustlet::SaveEnrolledPrint(uint32_t gid, uint64_t fid) {
    auto api = GetLockedAPI();
    api.GetRequest().fid = fid;
    return CAPTURE_ERROR(SendCommand(api, CommandId::SaveEnrolledPrint, gid));
}

int EGISAPTrustlet::FinalizeEnroll() {
    return CAPTURE_ERROR(SendCommand(CommandId::FinalizeEnroll));
}

int EGISAPTrustlet::GetPrintIds(uint32_t gid, std::vector<uint32_t> &list) {
    struct print_ids_t {
        uint32_t ids[5];
        uint32_t num_prints;
    };

    TypedDmaBuffer<print_ids_t> prints(dmabuf_allocator);
    auto api = GetLockedAPI();

    int rc = CAPTURE_ERROR(SendModifiedCommand(api, prints, CommandId::GetPrintIds, gid));
    if (rc)
        return rc;

    LOG_ALWAYS_FATAL_IF(api.Base().extra_buffer_size != sizeof(print_ids_t),
                        "%s: did not return exactly sizeof(print_ids_t) bytes!",
                        __func__);

    ALOGD("GetFingerList reported %d fingers", prints->num_prints);

    list.clear();
    list.reserve(prints->num_prints);
    std::copy(prints->ids,
              prints->ids + prints->num_prints,
              std::back_inserter(list));

    for (auto p : list)
        ALOGD("Print: %u", p);

    return 0;
}

int EGISAPTrustlet::RemovePrint(uint32_t gid, uint32_t fid) {
    auto api = GetLockedAPI();
    api.GetRequest().fid = fid;
    return CAPTURE_ERROR(SendCommand(api, CommandId::RemovePrint, gid));
}

int EGISAPTrustlet::FinalizeIdentify() {
    return CAPTURE_ERROR(SendCommand(CommandId::FinalizeIdentify));
}

int EGISAPTrustlet::GetEnrolledCount(uint32_t &cnt) {
    TypedDmaBuffer<uint32_t> result(dmabuf_allocator);
    int rc = CAPTURE_ERROR(SendModifiedCommand(result, CommandId::GetEnrolledCount));
    if (rc)
        return rc;
    cnt = *result;
    return 0;
}

int EGISAPTrustlet::Identify(uint32_t gid, uint64_t opid, identify_result_t &identify_result) {
    // Modified command with data.
    auto api = GetLockedAPI();

    auto &req = api.GetRequest();

    // Set to true if a HAT is passed and needs to be signed.
    req.fid = opid != 0;
    ALOGI("Needs signed HAT: %d", req.fid);

    req.buffer_size = sizeof(opid);
    *reinterpret_cast<uint64_t *>(req.data) = opid;

    TypedDmaBuffer<identify_result_t> ionBuffer(dmabuf_allocator);

    int rc = CAPTURE_ERROR(SendModifiedCommand(api, ionBuffer, CommandId::Identify, gid));
    if (rc)
        return rc;

    memcpy(&identify_result, ionBuffer(), sizeof(identify_result));
    return 0;
}

int EGISAPTrustlet::InitializeIdentify() {
    return CAPTURE_ERROR(SendCommand(CommandId::InitializeIdentify));
}

int EGISAPTrustlet::SaveTemplate() {
#ifdef EGISTEC_SAVE_TEMPLATE_RETURNS_SIZE
    TypedDmaBuffer<uint32_t> result(dmabuf_allocator);
    int rc = CAPTURE_ERROR(SendModifiedCommand(result, CommandId::SaveTemplate));
    if (rc)
        return rc;

    ALOGD("Template save size = %d", *result);
    return 0;
#else
    return CAPTURE_ERROR(SendCommand(CommandId::SaveTemplate));
#endif
}

int EGISAPTrustlet::UpdateTemplate(bool &updated) {
    TypedDmaBuffer<bool> result(dmabuf_allocator);
    int rc = CAPTURE_ERROR(SendModifiedCommand(result, CommandId::UpdateTemplate));
    if (rc)
        return rc;

    ALOGD("Template update success = %d", *result);
    updated = *result;
    return 0;
}

}  // namespace egistec::current
