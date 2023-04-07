#pragma once

#include "../../EventMultiplexer.h"
#include "../../SynchronizedWorkerThread.h"
#include "../EgisFpDevice.h"
#include "EGISAPTrustlet.h"

#include <android/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprintClientCallback.h>
#include <sys/eventfd.h>

#include <mutex>

namespace egistec::legacy {

using ::android::sp;
using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintAcquiredInfo;
using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintError;
using ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprintClientCallback;

/**
 * External wrapper class containing TZ communication logic
 * (Separated from datastructural/architectural choices).
 */
class EgisOperationLoops : public EGISAPTrustlet, public ::SynchronizedWorker::WorkHandler {
    const uint64_t mDeviceId;
    EgisFpDevice mDev;
    sp<IBiometricsFingerprintClientCallback> mClientCallback;
    std::mutex mClientCallbackMutex;
    uint32_t mGid;
    uint64_t mAuthenticatorId;
    ::SynchronizedWorker::Thread mWt;
    EventMultiplexer mMux;

   public:
    EgisOperationLoops(uint64_t deviceId, EgisFpDevice &&);

   private:
    void ProcessOpcode(const command_buffer_t &);
    int ConvertReturnCode(int);
    /**
     * Convert error code from the device.
     * Some return codes indicate a special state which do not imply an error has occured.
     * @return True when an error occured.
     */
    bool ConvertAndCheckError(int &, EGISAPTrustlet::API &);
    /**
     * Atomically check if the current operation is requested to cancel.
     * If cancelled, TZ cancel will be invoked and the service will be
     * notified before returning.
     * Requires a locked buffer to atomically cancel the current operation without
     * interfering with another command.
     */
    bool CheckAndHandleCancel(EGISAPTrustlet::API &);
    /**
     * Invoked when an operation encounters a cancellation as requested by cancel() from the Android service.
     * Propagates the cancel operation to the TZ-app so that it can do its cleanup.
     */
    int RunCancel(EGISAPTrustlet::API &);

    // Temporaries for asynchronous operation:
    uint64_t mSecureUserId;
    hw_auth_token_t mCurrentChallenge;
    int mEnrollTimeout;

    // Notify functions:
    void NotifyError(FingerprintError);
    void NotifyRemove(uint32_t fid, uint32_t remaining);
    void NotifyAcquired(FingerprintAcquiredInfo);
    void NotifyAuthenticated(uint32_t fid, const hw_auth_token_t &hat);
    void NotifyEnrollResult(uint32_t fid, uint32_t remaining);
    void NotifyBadImage(int);

    /**
     * Process the next step of the main section of enroll() or authenticate().
     */
    FingerprintError HandleMainStep(command_buffer_t &, int timeoutSec = -1);

    // WorkHandler implementations:
    // These should run asynchronously from HAL calls:
    ::SynchronizedWorker::Thread &getWorker();
    void AuthenticateAsync() override;
    void EnrollAsync() override;

   public:
    uint64_t GetAuthenticatorId();

    void SetNotify(const sp<IBiometricsFingerprintClientCallback>);
    int SetUserDataPath(uint32_t gid, const char *path);
    int RemoveFinger(uint32_t fid);
    int Prepare();
    bool Cancel();
    int Enumerate();
    int Enroll(const hw_auth_token_t &, uint32_t timeoutSec);
    int Authenticate(uint64_t challenge);
};

}  // namespace egistec::legacy
