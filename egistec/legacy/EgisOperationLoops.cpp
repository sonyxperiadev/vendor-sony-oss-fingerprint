// TODO: Come up with a much better name!

#if PLATFORM_SDK_VERSION >= 28
#include <bits/epoll_event.h>
#endif
#include "EgisOperationLoops.h"
#include "FormatException.hpp"

#include <arpa/inet.h>
#include <hardware/hw_auth_token.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <unistd.h>

#include <algorithm>

#define LOG_TAG "FPC ET"
#define LOG_NDEBUG 0
#include <log/log.h>

namespace egistec::legacy {

using ::android::hardware::hidl_vec;
using namespace ::SynchronizedWorker;

EgisOperationLoops::EgisOperationLoops(uint64_t deviceId, EgisFpDevice &&dev) : mDeviceId(deviceId), mDev(std::move(dev)), mAuthenticatorId(GetRand64()), mWt(this), mMux(mDev.GetFd(), mWt.getEventFd()) {
    mWt.Start();
}

void EgisOperationLoops::ProcessOpcode(const command_buffer_t &cmd) {
    switch (cmd.step) {
        case Step::WaitFingerprint:
            ALOGE("%s: Expected to wait for finger in non-interactive state!", __func__);
            // Waiting for a finger event (hardware gpio trigger for that matter) should
            // not happen for anything other than enroll and authenticate, where this case
            // is handled explicitly.
            break;
        case Step::NotReady:
            ALOGV("%s: Device not ready, sleeping for %dms", __func__, cmd.timeout);
            usleep(1000 * cmd.timeout);
            break;
        case Step::Error:
            ALOGV("%s: Device error, resetting...", __func__);
            mDev.Reset();
            break;
        default:
            break;
    }
}

int EgisOperationLoops::ConvertReturnCode(int rc) {
    // TODO: Check if this is still accurate.

    if (rc <= 0)
        return rc;
    if (rc > 0x3d)
        return 0;
    switch (rc) {
        case 0x15:
            return ~0x25;
        case 0x1d:
            return -1;
        case 0x24:
        case 0x25:
        case 0x26:
        case 0x28:
            return ~0x6;  // -5
        case 0x30:
            return ~0x5;  // -6: recalibrate
    }
    ALOGE("Invalid return code %#x", rc);
    return -1;
}

bool EgisOperationLoops::ConvertAndCheckError(int &rc, EGISAPTrustlet::API &lockedBuffer) {
    if ((rc - 0x27 & ~2) == 0 || (rc & ~0x20 /* 0xffffffdf*/) == 0)
        return false;

    rc = ConvertReturnCode(rc);
    NotifyError((FingerprintError)rc);
    RunCancel(lockedBuffer);
    return true;
}

bool EgisOperationLoops::CheckAndHandleCancel(EGISAPTrustlet::API &lockedBuffer) {
    auto cancelled = mWt.isEventAvailable();
    ALOGV("%s: %d", __func__, cancelled);
    if (cancelled)
        RunCancel(lockedBuffer);
    return cancelled;
}

int EgisOperationLoops::RunCancel(EGISAPTrustlet::API &lockedBuffer) {
    ALOGD("Sending cancel command to TZ");
    int rc = 0;
    auto &cmdIn = lockedBuffer.GetRequest().command_buffer;
    const auto &cmdOut = lockedBuffer.GetResponse().command_buffer;
    do {
        cmdIn.step = Step::Cancel;
        rc = SendCancel(lockedBuffer);
        if (rc)
            break;
    } while (cmdOut.step != Step::Done);
    rc = ConvertReturnCode(rc);
    if (rc)
        ALOGE("Failed to cancel, rc = %d", rc);

    // Even if cancelling failed on the hardware side, still notify the
    // HAL to prevent deadlocks.
    NotifyError(FingerprintError::ERROR_CANCELED);
    return rc;
}

void EgisOperationLoops::NotifyError(FingerprintError e) {
    if ((uint32_t)e >= (uint32_t)FingerprintError::ERROR_VENDOR)
        // No custom error strings for vendor codes are defined.
        // Convert every unknown error code to the generic unable_to_proces.

        // Do not use HW_UNAVAILABLE here, that causes the FingerprintService
        // to move on to "the next" HAL (which will loop around to use this HAL again),
        // but messes up state in the process (for example, receiving a second
        // authentication request when leaving the menu).
        e = FingerprintError::ERROR_UNABLE_TO_PROCESS;

    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback == nullptr)
        ALOGW("Client callback not set");
    else
        mClientCallback->onError(mDeviceId, e, 0);
}

void EgisOperationLoops::NotifyRemove(uint32_t fid, uint32_t remaining) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback == nullptr)
        ALOGW("Client callback not set");
    else
        mClientCallback->onRemoved(
            mDeviceId,
            fid,
            mGid,
            remaining);
}

void EgisOperationLoops::NotifyAcquired(FingerprintAcquiredInfo acquiredInfo) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    // Same here: No vendor acquire strings have been defined in an overlay.
    if (mClientCallback == nullptr)
        ALOGW("Client callback not set");
    else
        mClientCallback->onAcquired(mDeviceId,
                                    std::min(acquiredInfo, FingerprintAcquiredInfo::ACQUIRED_VENDOR),
                                    acquiredInfo >= FingerprintAcquiredInfo::ACQUIRED_VENDOR ? (int32_t)acquiredInfo : 0);
}

void EgisOperationLoops::NotifyAuthenticated(uint32_t fid, const hw_auth_token_t &hat) {
    auto hat_p = reinterpret_cast<const uint8_t *>(&hat);
    const hidl_vec<uint8_t> token(hat_p, hat_p + sizeof(hw_auth_token_t));
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback == nullptr)
        ALOGW("Client callback not set");
    else
        mClientCallback->onAuthenticated(mDeviceId,
                                         fid,
                                         mGid,
                                         token);
}

void EgisOperationLoops::NotifyEnrollResult(uint32_t fid, uint32_t remaining) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback == nullptr)
        ALOGW("Client callback not set");
    else
        mClientCallback->onEnrollResult(mDeviceId, fid, mGid, remaining);
}

void EgisOperationLoops::NotifyBadImage(int reason) {
    FingerprintAcquiredInfo acquiredInfo;
    if (reason & 1 << 1)  // 0x80000002
        acquiredInfo = FingerprintAcquiredInfo::ACQUIRED_TOO_FAST;
    else if (reason & 1 << 0x1b)  // 0x88000000
        acquiredInfo = FingerprintAcquiredInfo::ACQUIRED_PARTIAL;
    else if (reason & (1 << 3 | 1 << 7))
        // NOTE: 1 << 3 caused by "redundant image"
        // WARNING: Probably different meaning! (first free vendor code)
        acquiredInfo = FingerprintAcquiredInfo::ACQUIRED_VENDOR;
    else if (reason & 1 << 0x18)  // 0x81000000
        acquiredInfo = FingerprintAcquiredInfo::ACQUIRED_IMAGER_DIRTY;
    else  // 0x80000000 usually
        acquiredInfo = FingerprintAcquiredInfo::ACQUIRED_INSUFFICIENT;

    NotifyAcquired(acquiredInfo);
}

FingerprintError EgisOperationLoops::HandleMainStep(command_buffer_t &cmd, int timeoutSec) {
    switch (cmd.step) {
        case Step::WaitFingerprint: {
            auto reason = mMux.waitForEvent(timeoutSec);
            switch (reason) {
                case WakeupReason::Timeout:
                    // Return timeout: this notifies the service and stops the current loop.
                    return FingerprintError::ERROR_TIMEOUT;
                case WakeupReason::Event:
                    // Nothing to do. The two callers check for a cancel event at the next loop
                    // iteration, which is the only thing that can trigger an event while an
                    // enroll or authenticate session is in progress.
                    break;
                case WakeupReason::Finger:
                    // Continue processing
                    break;
            }
            break;
        }
        case Step::FingerDetected: {
            if (cmd.result_length != sizeof(cmd.match_result))
                ALOGW("Unexpected result_length = %d, should be %zu!",
                      cmd.result_length, sizeof(cmd.match_result));
            const auto &result = cmd.match_result;
            ALOGI("Detection result: quantity = %d, num_corners = %d, coverage = %d, [%d %d] [%d %d %d] %d",
                  result.qty,
                  result.corner_count,
                  result.coverage,
                  result.mat1[1],
                  result.mat1[0],
                  result.mat2[0],
                  result.mat2[1],
                  result.mat2[2],
                  result.other);
            break;
        }
        case Step::FingerAcquired:
            NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_GOOD);
            break;
        default:
            // NOTE: Most cases were handled as duplicates here.
            ProcessOpcode(cmd);
            break;
    }
    return FingerprintError::ERROR_NO_ERROR;
}

Thread &EgisOperationLoops::getWorker() {
    return mWt;
}

void EgisOperationLoops::EnrollAsync() {
    DeviceEnableGuard<EgisFpDevice> guard{mDev};
    int rc = 0;
    auto lockedBuffer = GetLockedAPI();
    auto &cmdOut = lockedBuffer.GetResponse().command_buffer;

    // NOTE: Due to bad API design, this section is more error-prone than necessary.
    // Responses are placed at a 14-byte offset with regards to the request, but
    // are expected to be moved back in consecutive calls in this loop. Thus cmdOut
    // may or may not point to the right data, depending on the point at which it is evaluated.

    // Intial step is 0, already cleared from GetLockedAPI

    // TODO: check_return_code_error, which does some weird
    // and-ops. On false, converts the return code and calls cancel()

    for (bool finished = false; !finished;) {
        do {
            if (CheckAndHandleCancel(lockedBuffer))
                return;
            // First call has no effect, since all data is still zero.
            lockedBuffer.MoveResponseToRequest();
            rc = SendInitEnroll(lockedBuffer, mSecureUserId);
            ALOGD("Enroll: init step, rc = %d, next step = %d", rc, cmdOut.step);
            // TODO: Check return code, recalibrate on convert()==-6

            if (ConvertAndCheckError(rc, lockedBuffer))
                return;

            ProcessOpcode(cmdOut);
        } while (cmdOut.step != Step::Done);

        do {
            if (CheckAndHandleCancel(lockedBuffer))
                return;
            lockedBuffer.MoveResponseToRequest();
            rc = SendEnroll(lockedBuffer);
            ALOGD("Enroll: step, rc = %d, next step = %d", rc, cmdOut.step);
            // TODO: if convert(rc) == -9, restart from init_enroll

            if (ConvertAndCheckError(rc, lockedBuffer))
                return;

            if (rc == 0x29) {
                ALOGD("Enroll: failed; rc = %#x", rc);
                // TODO: Original code does not notify error here. It only prints
                // a "to do" to the log, after which it continues processing.
                // NotifyError((FingerprintError)rc);
            } else if (rc == 0x27) {
                ALOGD("Enroll: bad image %#x, next step = %d", cmdOut.bad_image_reason, cmdOut.step);
                NotifyBadImage(cmdOut.bad_image_reason);
            } else if (!rc) {
                auto fe = HandleMainStep(cmdOut, mEnrollTimeout);
                if (fe != FingerprintError::ERROR_NO_ERROR) {
                    RunCancel(lockedBuffer);
                    return NotifyError(fe);
                }
            }

        } while (cmdOut.step != Step::Done);

        if (cmdOut.enroll_status == 0x64) {
            ALOGI("Enroll: complete in %d steps", cmdOut.enroll_steps_done);
            // It's possible for enrollment to finish before the predicated amount of steps.
            // In that case, make sure cmd.enroll_steps_required - cmd.enroll_steps_done == 0:
            cmdOut.enroll_steps_done = cmdOut.enroll_steps_required;
            finished = true;
        } else
            ALOGI("Enroll: %d steps remaining", cmdOut.enroll_steps_required - cmdOut.enroll_steps_done);

        // Notify that an enrollment step was done:
        if (!rc)
            NotifyEnrollResult(cmdOut.enroll_finger_id, cmdOut.enroll_steps_required - cmdOut.enroll_steps_done);

        do {
            if (CheckAndHandleCancel(lockedBuffer))
                return;
            lockedBuffer.MoveResponseToRequest();
            rc = SendFinalizeEnroll(lockedBuffer);
            ALOGD("Enroll: finalize step, rc = %d, next step = %d", rc, cmdOut.step);

            if (ConvertAndCheckError(rc, lockedBuffer))
                return;

            ProcessOpcode(cmdOut);
        } while (cmdOut.step != Step::Done);
    }

    // AuthenticatorId is a token associated with the current fp set. It must be
    // changed if the set is altered:
    mAuthenticatorId = GetRand64(lockedBuffer);
}

void EgisOperationLoops::AuthenticateAsync() {
    DeviceEnableGuard<EgisFpDevice> guard{mDev};
    int rc = 0;
    auto lockedBuffer = GetLockedAPI();
    auto &cmdOut = lockedBuffer.GetResponse().command_buffer;

    for (bool authenticated = false; !authenticated;) {
        // Zero step:
        cmdOut.step = Step::Done;

        // Sidenote: It is possible to specify a range through cmdOut.finger_list.
        cmdOut.finger_count = 0;

        // Output size of match_result
        cmdOut.result_length = 0;

        do {
            if (CheckAndHandleCancel(lockedBuffer))
                return;
            lockedBuffer.MoveResponseToRequest();
            rc = SendInitAuthenticate(lockedBuffer);
            ALOGD("Authenticate: init step, rc = %d, next step = %d", rc, cmdOut.step);

            if (rc == 0x33) {
                // Best guess
                ALOGE("Authenticate: no fingerprints");
                return NotifyError(FingerprintError::ERROR_UNABLE_TO_PROCESS);
            }

            if (ConvertAndCheckError(rc, lockedBuffer))
                // TODO: Handle rc == -6 -> calibrate error.
                return;

            ProcessOpcode(cmdOut);
        } while (cmdOut.step != Step::Done);

        do {
            if (CheckAndHandleCancel(lockedBuffer))
                return;
            lockedBuffer.MoveResponseToRequest();
            rc = SendAuthenticate(lockedBuffer);
            ALOGD("Authenticate: step, rc = %d, next step = %d", rc, cmdOut.step);
            // TODO: if convert(rc) == -9, restart from init_enroll

            if (ConvertAndCheckError(rc, lockedBuffer))
                return;

            if (rc == 0x20) {
                ALOGD("Authenticate: Finger not recognized");
                NotifyAuthenticated(0, mCurrentChallenge);
            } else if (rc == 0x27) {
                ALOGD("Authenticate: bad image %#x, next step = %d", cmdOut.bad_image_reason, cmdOut.step);
                NotifyBadImage(cmdOut.bad_image_reason);
            } else if (!rc) {
                auto fe = HandleMainStep(cmdOut);
                if (fe != FingerprintError::ERROR_NO_ERROR) {
                    RunCancel(lockedBuffer);
                    return NotifyError(fe);
                }
            }

        } while (cmdOut.step != Step::Done);

        if (cmdOut.result_length != sizeof(cmdOut.authenticate_result))
            ALOGW("Unexpected result_length = %d, should be %zu!",
                  cmdOut.result_length, sizeof(cmdOut.authenticate_result));

        // Store whether authentication was successful or not. Even when finalize/cancel fails, the
        // finger was still valid and should result in a successful unlock.
        authenticated = !rc;

        do {
            if (CheckAndHandleCancel(lockedBuffer))
                return;
            lockedBuffer.MoveResponseToRequest();
            // It is possible to retrieve a buffer with "image data" here,
            // but this is unused by the current HAL.
            rc = SendFinalizeAuthenticate(lockedBuffer);
            ALOGD("Authenticate: finalize step, rc = %d, next step = %d", rc, cmdOut.step);

            if (ConvertAndCheckError(rc, lockedBuffer))
                return;

            ProcessOpcode(cmdOut);
        } while (cmdOut.step != Step::Done);

        // NOTE: This special cancel operation is only in the codepath that
        // doesn't wait until the finger leaves the sensor. The other
        // codepath is never used.
        do {
            // Special version of cancel?
            cmdOut.step = Step::CancelFingerprintWait;
            lockedBuffer.MoveResponseToRequest();
            rc = SendCancel(lockedBuffer);
            ALOGD("Authenticate: cancel instead of wait-finger-off step, rc = %d, next step = %d", rc, cmdOut.step);

            ProcessOpcode(cmdOut);
        } while (cmdOut.step != Step::Done);
    }

    // On loop exit, authentication was successful. Otherwise, the session is
    // either restarted or the the function has returned on error/cancel.

    ALOGI("Authentication successful: fid = %d, score = %d", cmdOut.finger_id, cmdOut.match_score);

    const auto &result = cmdOut.authenticate_result;
    ALOGD("Authentication match result: cov=%d, quality=%d, score=%d, index=%d, template_cnt=%d, capture_time=%d, identify_time=%d",
          result.coverage,
          result.quality,
          result.score,
          result.index,
          result.template_cnt,
          result.capture_time,
          result.identify_time);
    ALOGD("hmac timestamp: %lu secure_user_id: %lu ", result.hmac_timestamp, result.secure_user_id);

    // Finalize challenge buffer by filling in the cryptographic response:
    mCurrentChallenge.timestamp = result.hmac_timestamp;
    mCurrentChallenge.user_id = result.secure_user_id;
    memcpy(mCurrentChallenge.hmac, result.hmac, sizeof(result.hmac));

    NotifyAuthenticated(cmdOut.finger_id, mCurrentChallenge);
    // Clear "sensitive" authentication tokens:
    memset(&mCurrentChallenge, 0, sizeof(mCurrentChallenge));
}

uint64_t EgisOperationLoops::GetAuthenticatorId() {
    return mAuthenticatorId;
}

void EgisOperationLoops::SetNotify(const sp<IBiometricsFingerprintClientCallback> callback) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    mClientCallback = callback;
}

int EgisOperationLoops::SetUserDataPath(uint32_t gid, const char *path) {
    mGid = gid;
    return EGISAPTrustlet::SetUserDataPath(path);
}

int EgisOperationLoops::RemoveFinger(uint32_t fid) {
    int rc = 0;

    if (fid == 0) {
        // Delete all fingerprints when fid is zero:
        std::vector<uint32_t> fids;
        rc = GetFingerList(fids);
        if (rc)
            return rc;
        auto remaining = fids.size();
        for (auto fid : fids) {
            rc = EGISAPTrustlet::RemoveFinger(fid);
            if (rc)
                break;
            NotifyRemove(fid, --remaining);
        }
    } else {
        rc = EGISAPTrustlet::RemoveFinger(fid);
        if (!rc)
            NotifyRemove(fid, 0);
    }

    // Although not explicitly mentioned in the documentation, removing a fingerprint
    // definitely changes the current set of fingers, thus requiring an authid change:
    mAuthenticatorId = GetRand64();
    if (rc)
        NotifyError(FingerprintError::ERROR_UNABLE_TO_REMOVE);
    return rc;
}

int EgisOperationLoops::Prepare() {
    DeviceEnableGuard<EgisFpDevice> guard{mDev};
    int rc = 0;
    auto lockedBuffer = GetLockedAPI();
    auto &cmdIn = lockedBuffer.GetRequest().command_buffer;
    const auto &cmdOut = lockedBuffer.GetResponse().command_buffer;
    // Initial Step is 1:
    cmdIn.step = Step::Init;

    // Process step until it is 0 (meaning done):
    for (;;) {
        rc = SendPrepare(lockedBuffer);
        // 0x26, or -7 after conversion happens when the hardware is turned off.

        rc = ConvertReturnCode(rc);
        ALOGD("Prepare rc = %d, next step = %d", rc, cmdOut.step);
        if (rc)
            break;

        ProcessOpcode(cmdOut);

        if (cmdOut.step == Step::Done)
            // Preparation complete
            break;

        lockedBuffer.MoveResponseToRequest();
    }
    return rc;
}

bool EgisOperationLoops::Cancel() {
    ALOGI("Requesting thread to cancel current operation...");
    // Always let the thread handle cancel requests to prevent concurrency issues.
    return mWt.moveToState(AsyncState::Idle);
}

int EgisOperationLoops::Enumerate() {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    std::vector<uint32_t> fids;
    int rc = GetFingerList(fids);
    if (rc)
        return rc;
    auto remaining = fids.size();
    ALOGD("Enumerating %zu fingers", remaining);
    if (!remaining)
        // If no fingerprints exist, notify that the enumeration is done with remaining=0.
        // Use fid=0 to indicate that this is not a fingerprint.
        mClientCallback->onEnumerate(mDeviceId, 0, mGid, 0);
    else
        for (auto fid : fids)
            mClientCallback->onEnumerate(mDeviceId, fid, mGid, --remaining);
    return 0;
}

int EgisOperationLoops::Enroll(const hw_auth_token_t &hat, uint32_t timeoutSec) {
    auto api = GetLockedAPI();
    int rc = 0;

    // TODO: Check if any of the functions in this or the async codepath throw
    // an error for >5 fingerprints (and are eligible for throwing ERROR_NO_SPACE).

    rc = SetAuthToken(api, hat);
    if (rc) {
        ALOGE("Failed to set auth token, rc = %d", rc);
        goto error;
    }

    // WARNING: Not clearing the buffer here causes a continuous EGISAPError::InvalidSecureUserId.
    // Even with a clear buffer this error still occurs incredibly often.
    // Cause/meaning unknown.
    memset(&api.GetRequest().extra_buffer, 0, sizeof(api.GetRequest().extra_buffer));

    rc = SetSecureUserId(api, hat.user_id);
    if (rc) {
        ALOGE("Failed to set secure user id, rc = %d", rc);
        goto error;
    }

    mSecureUserId = hat.user_id;
    mEnrollTimeout = timeoutSec;

    api.MoveResponseToRequest();
    rc = CheckAuthToken(api);
    if (rc) {
        ALOGE("Auth token invalid, rc = %d", rc);
        goto error;
    }

    rc = !mWt.moveToState(AsyncState::Enroll);
    if (!rc)
        return 0;

error:
    ALOGD("%s: TODO: Determine meaning of rc = %#x", __func__, rc);
    NotifyError(FingerprintError::ERROR_UNABLE_TO_PROCESS);
    return rc;
}

int EgisOperationLoops::Authenticate(uint64_t challenge) {
    int rc = 0;

    memset(&mCurrentChallenge, 0, sizeof(mCurrentChallenge));
    mCurrentChallenge.authenticator_type = htonl(hw_authenticator_type_t::HW_AUTH_FINGERPRINT);
    mCurrentChallenge.challenge = challenge;
    mCurrentChallenge.authenticator_id = mAuthenticatorId;

    ALOGD("Sending auth token...");
    rc = SetAuthToken(mCurrentChallenge);
    if (rc) {
        ALOGE("Failed to set challenge authentication token");
        goto error;
    }

    rc = !mWt.moveToState(AsyncState::Authenticate);
    if (!rc)
        return 0;

error:
    ALOGD("%s: TODO: Determine meaning of rc = %#x", __func__, rc);
    NotifyError(FingerprintError::ERROR_UNABLE_TO_PROCESS);
    return rc;
}

}  // namespace egistec::legacy
