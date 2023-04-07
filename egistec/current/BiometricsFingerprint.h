/**
 * Fingerprint HAL implementation for Egistec sensors.
 */

#pragma once

#include "../../EventMultiplexer.h"
#include "../../SynchronizedWorkerThread.h"
#include "../EgisFpDevice.h"
#include "EGISAPTrustlet.h"
#include "QSEEKeymasterTrustlet.h"
#include "UInput.h"

#include <android/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprint.h>

#include <array>

namespace egistec::current {

using ::android::sp;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintAcquiredInfo;
using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintError;
using ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprint;
using ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprintClientCallback;
using ::android::hardware::biometrics::fingerprint::V2_1::RequestStatus;

struct BiometricsFingerprint : public IBiometricsFingerprint, public ::SynchronizedWorker::WorkHandler {
   public:
    BiometricsFingerprint(EgisFpDevice &&);
    ~BiometricsFingerprint();

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
    EGISAPTrustlet mTrustlet;
    EgisFpDevice mDev;
    MasterKey mMasterKey;
    sp<IBiometricsFingerprintClientCallback> mClientCallback;
    std::mutex mClientCallbackMutex;
    UInput uinput;
    uint32_t mGid = -1;
    uint32_t mHwId;
    ::SynchronizedWorker::Thread mWt;
    EventMultiplexer mMux;

    int mEnrollTimeout = -1;
    uint32_t mNewPrintId = -1;
    uint64_t mEnrollChallenge = 0;

    int64_t mOperationId;

    // WorkHandler implementations:
    ::SynchronizedWorker::Thread &getWorker();
    void AuthenticateAsync() override;
    void EnrollAsync() override;
    void IdleAsync() override;

    int ResetSensor();
    void NotifyAcquired(FingerprintAcquiredInfo);
    void NotifyAuthenticated(uint32_t fid, const hw_auth_token_t &hat);
    void NotifyEnrollResult(uint32_t fid, uint32_t remaining);
    void NotifyError(FingerprintError);
    void NotifyRemove(uint32_t fid, uint32_t remaining);
};

}  // namespace egistec::current
