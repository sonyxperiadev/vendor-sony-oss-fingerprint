#include "BiometricsFingerprint.h"

#include "../../FormatException.hpp"

#define LOG_TAG "FPC ET"
#include <log/log.h>

namespace egistec::legacy {

BiometricsFingerprint::BiometricsFingerprint(EgisFpDevice &&dev) : loops(reinterpret_cast<uint64_t>(this), std::move(dev)) {
    QSEEKeymasterTrustlet keymaster;
    mMasterKey = keymaster.GetKey();

    int rc = loops.Prepare();
    if (rc)
        throw FormatException("Prepare failed with rc = %d", rc);

    rc = loops.SetMasterKey(mMasterKey);
    if (rc)
        throw FormatException("SetMasterKey failed with rc = %d", rc);
}

Return<uint64_t> BiometricsFingerprint::setNotify(const sp<IBiometricsFingerprintClientCallback> &clientCallback) {
    loops.SetNotify(clientCallback);
    // This is here because HAL 2.1 doesn't have a way to propagate a
    // unique token for its driver. Subsequent versions should send a unique
    // token for each call to setNotify(). This is fine as long as there's only
    // one fingerprint device on the platform.
    return reinterpret_cast<uint64_t>(this);
}

Return<uint64_t> BiometricsFingerprint::preEnroll() {
    // TODO: Original service aborts+retries on failure.
    auto challenge = loops.GetChallenge();
    ALOGI("%s: Generated enroll challenge %#lx", __func__, challenge);
    return challenge;
}

Return<RequestStatus> BiometricsFingerprint::enroll(const hidl_array<uint8_t, 69> &hat, uint32_t gid, uint32_t timeoutSec) {
    if (gid != mGid) {
        ALOGE("Cannot enroll finger for different gid! Caller needs to update storePath first with setActiveGroup()!");
        return RequestStatus::SYS_EINVAL;
    }

    const auto h = reinterpret_cast<const hw_auth_token_t *>(hat.data());
    if (!h) {
        // This seems to happen when locking the device while enrolling.
        // It is unknown why this function is called again.
        ALOGE("%s: authentication token is unset!", __func__);
        return RequestStatus::SYS_EINVAL;
    }

    ALOGI("Starting enroll for challenge %#lx", h->challenge);
    return loops.Enroll(*h, timeoutSec) ? RequestStatus::SYS_EINVAL : RequestStatus::SYS_OK;
}

Return<RequestStatus> BiometricsFingerprint::postEnroll() {
    ALOGI("%s: clearing challenge", __func__);
    // TODO: Original service aborts+retries on failure.
    return loops.ClearChallenge() ? RequestStatus::SYS_UNKNOWN : RequestStatus::SYS_OK;
}

Return<uint64_t> BiometricsFingerprint::getAuthenticatorId() {
    return loops.GetAuthenticatorId();
}

Return<RequestStatus> BiometricsFingerprint::cancel() {
    ALOGI("Cancel requested");
    bool success = loops.Cancel();
    return success ? RequestStatus::SYS_OK : RequestStatus::SYS_UNKNOWN;
}

Return<RequestStatus> BiometricsFingerprint::enumerate() {
    return loops.Enumerate() ? RequestStatus::SYS_UNKNOWN : RequestStatus::SYS_OK;
}

Return<RequestStatus> BiometricsFingerprint::remove(uint32_t gid, uint32_t fid) {
    ALOGI("%s: gid = %d, fid = %d", __func__, gid, fid);
    if (gid != mGid) {
        ALOGE("Change group and userpath through setActiveGroup first!");
        return RequestStatus::SYS_EINVAL;
    }
    return loops.RemoveFinger(fid) ? RequestStatus::SYS_EINVAL : RequestStatus::SYS_OK;
}

Return<RequestStatus> BiometricsFingerprint::setActiveGroup(uint32_t gid, const hidl_string &storePath) {
    ALOGI("%s: gid = %u, path = %s", __func__, gid, storePath.c_str());
    mGid = gid;
    int rc = loops.SetUserDataPath(mGid, storePath.c_str());
    return rc ? RequestStatus::SYS_EINVAL : RequestStatus::SYS_OK;
}

Return<RequestStatus> BiometricsFingerprint::authenticate(uint64_t operationId, uint32_t gid) {
    ALOGI("%s: gid = %d, secret = %lu", __func__, gid, operationId);
    if (gid != mGid) {
        ALOGE("Cannot authenticate finger for different gid! Caller needs to update storePath first with setActiveGroup()!");
        return RequestStatus::SYS_EINVAL;
    }

    return loops.Authenticate(operationId) ? RequestStatus::SYS_EINVAL : RequestStatus::SYS_OK;
}

}  // namespace egistec::legacy
