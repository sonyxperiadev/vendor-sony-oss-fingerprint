/**
 * Fingerprint HAL implementation for Egistec sensors.
 */

#pragma once

#include "../../QSEEKeymasterTrustlet.h"
#include "EgisOperationLoops.h"

#include <android/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprint.h>

#include <array>

namespace egistec::legacy {

using ::android::sp;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprint;
using ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprintClientCallback;
using ::android::hardware::biometrics::fingerprint::V2_1::RequestStatus;

struct BiometricsFingerprint : public IBiometricsFingerprint {
   public:
    BiometricsFingerprint(EgisFpDevice &&);

    // Methods from ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprint follow.
    Return<uint64_t> setNotify(const sp<IBiometricsFingerprintClientCallback> &clientCallback) override;
    Return<uint64_t> preEnroll() override;
    Return<RequestStatus> enroll(const hidl_array<uint8_t, 69> &hat, uint32_t gid, uint32_t timeoutSec) override;
    Return<RequestStatus> postEnroll() override;
    Return<uint64_t> getAuthenticatorId() override;
    Return<RequestStatus> cancel() override;
    Return<RequestStatus> enumerate() override;
    Return<RequestStatus> remove(uint32_t gid, uint32_t fid) override;
    Return<RequestStatus> setActiveGroup(uint32_t gid, const hidl_string &storePath) override;
    Return<RequestStatus> authenticate(uint64_t operationId, uint32_t gid) override;

   private:
    MasterKey mMasterKey;
    uint32_t mGid;
    EgisOperationLoops loops;
};

}  // namespace egistec::legacy
