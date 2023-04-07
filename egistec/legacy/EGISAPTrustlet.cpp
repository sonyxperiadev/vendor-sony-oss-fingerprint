#include "EGISAPTrustlet.h"

#include "FormatException.hpp"

#include <string.h>

#define LOG_TAG "FPC ET"
// #define LOG_NDEBUG 0
#include <log/log.h>

namespace egistec::legacy {

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

EGISAPTrustlet::EGISAPTrustlet() : QSEETrustlet("egisap32", 0x2400) {
    int rc = SendDataInit();
    if (rc)
        throw FormatException("SendDataInit failed with rc = %d", rc);
}

bool EGISAPTrustlet::MatchFirmware() {
    // Execute a seemingly harmless command that returns a length
    // of zero (probably meaning something entirely different)
    // on the "new" firmware.
    uint64_t rand;
    auto size = GetBlob(ExtraCommand::GetRand64, &rand, sizeof(rand));
    bool match = size == sizeof(rand);
    ALOGI("Firmware %s original Nile interface", match ? "matches" : "does not match");
    return match;
}

int EGISAPTrustlet::SendCommand(EGISAPTrustlet::API &lockedBuffer) {
    if (lockedBuffer.GetRequest().command == Command::ExtraCommand)
        ALOGD("%s: Sending extra-command %#x", __func__, lockedBuffer.GetRequest().extra_buffer.command);
    else
        ALOGD("%s: Sending command %#x (step = %d)", __func__, lockedBuffer.GetRequest().command, lockedBuffer.GetRequest().command_buffer.step);

    struct __attribute__((__packed__)) APIPrefix {
        uint32_t a;
        char padding[8];
        uint64_t b, c;
    };
    static_assert(offsetof(APIPrefix, b) == 0xc, "");
    static_assert(offsetof(APIPrefix, c) == 0x14, "");
    auto prefix = reinterpret_cast<APIPrefix *>(*lockedBuffer.mLockedBuffer);
    prefix->a = 0xe0;
    prefix->b = 0;
    prefix->c = 0;

    // Always set the fixed size fields of the command and extra buffers, even if they
    // are not used to pass any data.
    lockedBuffer.GetRequest().command_buffer_size = sizeof(command_buffer_t);
    lockedBuffer.GetRequest().extra_buffer_type_size = sizeof(extra_buffer_t);

#if !LOG_NDEBUG
    log_hex(reinterpret_cast<const char *>(&lockedBuffer.GetRequest()), sizeof(trustlet_buffer_t));
#endif

    int rc = QSEETrustlet::SendCommand(prefix, 0x880, prefix, 0x840);
    if (rc) {
        ALOGE("SendCommand failed with rc = %d", rc);
        return rc;
    }

#if !LOG_NDEBUG
    ALOGV("Response:");
    log_hex(reinterpret_cast<const char *>(&lockedBuffer.GetResponse()), sizeof(trustlet_buffer_t));
#endif

    // TODO: List expected response codes in an enum.
    rc = lockedBuffer.GetResponse().result;
    if (rc)
        ALOGE("SendCommand result = %#x", rc);
    return rc;
}

int EGISAPTrustlet::SendCommand(EGISAPTrustlet::API &buffer, Command command) {
    buffer.GetRequest().command = command;
    return SendCommand(buffer);
}

int EGISAPTrustlet::SendCommand(Command command) {
    auto lockedBuffer = GetLockedAPI();
    return SendCommand(lockedBuffer, command);
}

/**
 * Prepare buffer for use.
 */
EGISAPTrustlet::API EGISAPTrustlet::GetLockedAPI() {
    auto lockedBuffer = GetLockedBuffer();
    memset(*lockedBuffer, 0, EGISAPTrustlet::API::BufferSize());
    return lockedBuffer;
}

int EGISAPTrustlet::SendExtraCommand(EGISAPTrustlet::API &buffer) {
    return SendCommand(buffer, Command::ExtraCommand);
}

int EGISAPTrustlet::SendExtraCommand(EGISAPTrustlet::API &buffer, ExtraCommand command) {
    buffer.GetRequest().extra_buffer.command = command;
    return SendExtraCommand(buffer);
}

int EGISAPTrustlet::SendExtraCommand(ExtraCommand command) {
    auto buffer = GetLockedAPI();
    return SendExtraCommand(buffer, command);
}

size_t EGISAPTrustlet::GetBlob(EGISAPTrustlet::API &lockedBuffer, ExtraCommand command, void *data, size_t max_data) {
    const auto &extraOut = lockedBuffer.GetResponse().extra_buffer;
    lockedBuffer.GetRequest().extra_buffer_in_size = 0;
    auto rc = SendExtraCommand(lockedBuffer, command);

    if (rc) {
        ALOGE("%s failed with %d", __func__, rc);
        return -1;
    }
    if ((size_t)extraOut.data_size > max_data) {
        ALOGW("%s returned more data than expected, %d > %zu", __func__, extraOut.data_size, max_data);
    }

    size_t copied = std::min((size_t)extraOut.data_size, max_data);

    memcpy(data, extraOut.data, copied);

    return copied;
}

size_t EGISAPTrustlet::GetBlob(ExtraCommand command, void *data, size_t max_data) {
    auto buffer = GetLockedAPI();
    return GetBlob(buffer, command, data, max_data);
}

uint64_t EGISAPTrustlet::CallFor64BitResponse(EGISAPTrustlet::API &lockedBuffer, ExtraCommand command) {
    uint64_t value;
    auto size = GetBlob(lockedBuffer, command, &value, sizeof(value));

    if (size != sizeof(value)) {
        ALOGE("%s: Received unexpected length %zu", __func__, size);
        return -1;
    }

    ALOGD("%s: %#lx", __func__, value);
    return value;
}

uint64_t EGISAPTrustlet::CallFor64BitResponse(ExtraCommand command) {
    auto lockedBuffer = GetLockedAPI();
    return CallFor64BitResponse(lockedBuffer, command);
}

int EGISAPTrustlet::SendPrepare(EGISAPTrustlet::API &api) {
    return SendCommand(api, Command::Prepare);
}

int EGISAPTrustlet::SendCancel(EGISAPTrustlet::API &api) {
    return SendCommand(api, Command::Cancel);
}

int EGISAPTrustlet::SendDataInit() {
    return SendCommand(Command::DataInit);
}

int EGISAPTrustlet::SendInitEnroll(EGISAPTrustlet::API &api, uint64_t secureUserId) {
    api.GetRequest().secure_user_id = secureUserId;
    return SendCommand(api, Command::InitEnroll);
}

int EGISAPTrustlet::SendEnroll(EGISAPTrustlet::API &api) {
    return SendCommand(api, Command::Enroll);
}

int EGISAPTrustlet::SendFinalizeEnroll(EGISAPTrustlet::API &api) {
    return SendCommand(api, Command::FinalizeEnroll);
}

int EGISAPTrustlet::SendInitAuthenticate(EGISAPTrustlet::API &api) {
    return SendCommand(api, Command::InitAuthenticate);
}

int EGISAPTrustlet::SendAuthenticate(EGISAPTrustlet::API &api) {
    // NOTE: This commands sets `padding5` in trustlet_buffer_t, as well
    // as passing an output buffer through an extra ion buffer.
    // These are unused in the et510/et516 HAL however, and are likely only
    // used for other hardware revisions.
    return SendCommand(api, Command::Authenticate);
}

int EGISAPTrustlet::SendFinalizeAuthenticate(EGISAPTrustlet::API &api) {
    return SendCommand(api, Command::FinalizeAuthenticate);
}

int EGISAPTrustlet::SetUserDataPath(const char *path) {
    auto lockedBuffer = GetLockedAPI();
    auto &extra = lockedBuffer.GetRequest().extra_buffer;

    const auto len = strlen(path);
    if (len >= sizeof(extra.string_field) - 1) {
        ALOGE("%s path %s is too long!", __func__, path);
        return -1;
    }

    // Copy terminating null-character:
    memcpy(extra.string_field, path, len + 1);

    return SendExtraCommand(lockedBuffer, ExtraCommand::SetUserDataPath);
}

int EGISAPTrustlet::SetAuthToken(EGISAPTrustlet::API &lockedBuffer, const hw_auth_token_t &hat) {
    // Copy to ets's non-packed structure:
    auto &token = lockedBuffer.GetExtraRequestDataBuffer<ets_authen_token_t>();
    token.version = hat.version,
    token.challenge = hat.challenge,
    token.user_id = hat.user_id,
    token.authenticator_id = hat.authenticator_id,
    token.authenticator_type = hat.authenticator_type,
    token.timestamp = hat.timestamp,
    memcpy(token.hmac, hat.hmac, sizeof(token.hmac));

    return SendExtraCommand(lockedBuffer, ExtraCommand::SetAuthToken);
}

int EGISAPTrustlet::SetAuthToken(const hw_auth_token_t &hat) {
    auto lockedBuffer = GetLockedAPI();
    return SetAuthToken(lockedBuffer, hat);
}

int EGISAPTrustlet::CheckAuthToken(EGISAPTrustlet::API &api) {
    // NOTE: Locked buffer is only passed to keep this in the same locked session.
    // No data needs to be passed to this function.
    int rc = SendExtraCommand(api, ExtraCommand::CheckAuthToken);

    switch (rc) {
        case EGISAPError::InvalidHatChallenge:
            ALOGE("%s: hw_auth_token_t challenge is invalid", __func__);
            break;
        case EGISAPError::InvalidHatVersion:
            ALOGE("%s: hw_auth_token_t version is invalid", __func__);
            break;
        case EGISAPError::InvalidSecureUserId:
            ALOGE("%s: Yet-unknown InitEnroll error, potentially something to do with the secure user id", __func__);
            break;
    }

    return rc;
}

int EGISAPTrustlet::GetFingerList(std::vector<uint32_t> &list) {
    auto lockedBuffer = GetLockedAPI();
    auto &extraIn = lockedBuffer.GetRequest().extra_buffer;
    const auto &extraOut = lockedBuffer.GetResponse().extra_buffer;
    int rc = SendExtraCommand(lockedBuffer, ExtraCommand::GetFingerList);
    if (rc)
        return rc;
    list.clear();
    list.reserve(extraIn.number_of_prints);
    ALOGD("GetFingerList reported %d fingers", extraOut.number_of_prints);
    std::copy(extraOut.finger_list, extraOut.finger_list + extraOut.number_of_prints, std::back_inserter(list));
    return 0;
}

int EGISAPTrustlet::SetSecureUserId(EGISAPTrustlet::API &api, uint64_t secureUserId) {
    // TODO: Should the buffer be passed around?
    // It's cleared once, then reused for all enroll commands.
    // What even does this call do? Prepare the bufer??
    api.GetRequest().extra_buffer.secure_user_id = secureUserId;
    return SendExtraCommand(api, ExtraCommand::SetSecureUserId);
}

int EGISAPTrustlet::RemoveFinger(uint32_t fid) {
    auto lockedBuffer = GetLockedAPI();
    auto &extra = lockedBuffer.GetRequest().extra_buffer;
    extra.remove_fid = fid;
    return SendExtraCommand(lockedBuffer, ExtraCommand::RemoveFinger);
}

// Provide variant that operates on an already-locked buffer
uint64_t EGISAPTrustlet::GetRand64(EGISAPTrustlet::API &api) {
    return CallFor64BitResponse(api, ExtraCommand::GetRand64);
}

uint64_t EGISAPTrustlet::GetRand64() {
    return CallFor64BitResponse(ExtraCommand::GetRand64);
}

uint64_t EGISAPTrustlet::GetChallenge() {
    return CallFor64BitResponse(ExtraCommand::GetChallenge);
}

int EGISAPTrustlet::ClearChallenge() {
    return SendExtraCommand(ExtraCommand::ClearChallenge);
}

int EGISAPTrustlet::SetMasterKey(const MasterKey &key) {
    auto lockedBuffer = GetLockedAPI();

    auto &mkey = lockedBuffer.GetExtraRequestDataBuffer<typename MasterKey::value_type[QSEE_KEYMASTER64_MASTER_KEY_SIZE]>();
    static_assert(sizeof(mkey) == std::tuple_size<MasterKey>::value, "");
    memcpy(&mkey, key.data(), key.size());

    return SendExtraCommand(lockedBuffer, ExtraCommand::SetMasterKey);
}

}  // namespace egistec::legacy
