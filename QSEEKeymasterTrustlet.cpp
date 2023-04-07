#include "QSEEKeymasterTrustlet.h"

#include "FormatException.hpp"

#include <string.h>

#define LOG_TAG "FPC QSEEKeymasterTrustlet"
#include <log/log.h>

#define KM_TZAPP_NAME "keymaster64"

typedef struct {
    uint32_t cmd_id;
    uint32_t auth_type;
} keymaster_cmd_t;

typedef struct {
    int32_t status;
    uint32_t offset;
    uint32_t length;
} keymaster_return_t;

// TODO: Isn't a buffer of 0x2400 way too large, or is that to accompany potentially large output offsets?
QSEEKeymasterTrustlet::QSEEKeymasterTrustlet() : QSEETrustlet(KM_TZAPP_NAME, 0x2400) {
}

MasterKey QSEEKeymasterTrustlet::GetKey() {
    auto lockedBuffer = GetLockedBuffer();
    auto req = reinterpret_cast<keymaster_cmd_t *>(*lockedBuffer);

    req->cmd_id = 0x205;
    req->auth_type = 0x02;

    int rc = SendCommand(*lockedBuffer, sizeof(keymaster_cmd_t), *lockedBuffer, 0x2400);
    if (rc)
        throw FormatException("keymaster master key retrieval failed, rc = %d", rc);

    auto ret = reinterpret_cast<keymaster_return_t *>(*lockedBuffer);

    ALOGD("Keymaster Response Code: %u\n", ret->status);
    ALOGD("Keymaster Response Length: %u\n", ret->length);
    ALOGD("Keymaster Response Offset: %u\n", ret->offset);

    LOG_ALWAYS_FATAL_IF(ret->status,
                        "Failed to retrieve keymaster key: %d",
                        ret->status);

    if (ret->length > QSEE_KEYMASTER64_MASTER_KEY_SIZE)
        throw FormatException("Keymaster returned too large key, %u > %u!",
                              ret->length,
                              QSEE_KEYMASTER64_MASTER_KEY_SIZE);
    else if (ret->length < QSEE_KEYMASTER64_MASTER_KEY_SIZE)
        ALOGW("Keymaster returned smaller key than expected, %u < %u",
              ret->length,
              QSEE_KEYMASTER64_MASTER_KEY_SIZE);

    const auto keyPtr = reinterpret_cast<const char *>((ptrdiff_t)*lockedBuffer + ret->offset);
    MasterKey key;
    std::copy(keyPtr, keyPtr + ret->length, key.begin());
    return key;
}
