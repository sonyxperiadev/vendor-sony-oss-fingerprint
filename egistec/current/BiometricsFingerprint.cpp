#include "BiometricsFingerprint.h"

#include "FormatException.hpp"

#define LOG_TAG "FPC ET"
#include <log/log.h>

namespace egistec::current {

using namespace ::SynchronizedWorker;

BiometricsFingerprint::BiometricsFingerprint(EgisFpDevice &&dev) : mDev(std::move(dev)), mWt(this), mMux(mDev.GetFd(), mWt.getEventFd()) {
    QSEEKeymasterTrustlet keymaster;
    int rc = 0;

#ifdef HAS_DYNAMIC_POWER_MANAGEMENT
    DeviceEnableGuard<EgisFpDevice> guard{mDev};
#else
    mDev.Enable();
#endif
    mDev.Reset();

    mMasterKey = keymaster.GetKey();

    rc = mTrustlet.SetDataPath("/data/system/users/0/fpdata");
    LOG_ALWAYS_FATAL_IF(rc, "SetDataPath failed with rc = %d", rc);

    rc = mTrustlet.SetMasterKey(mMasterKey);
    LOG_ALWAYS_FATAL_IF(rc, "SetMasterKey failed with rc = %d", rc);

    rc = mTrustlet.InitializeSensor();
    LOG_ALWAYS_FATAL_IF(rc, "InitializeSensor failed with rc = %d", rc);

    rc = mTrustlet.InitializeAlgo();
    LOG_ALWAYS_FATAL_IF(rc, "InitializeAlgo failed with rc = %d", rc);

    rc = mTrustlet.Calibrate();
    LOG_ALWAYS_FATAL_IF(rc, "Calibrate failed with rc = %d", rc);

    mHwId = mTrustlet.GetHwId();
    ALOGI("HWID: %x", mHwId);

    mWt.Start();
}

BiometricsFingerprint::~BiometricsFingerprint() {
    int rc = 0;

    rc = mTrustlet.UninitializeSensor();
    ALOGE_IF(rc, "UninitializeSensor failed with rc = %d", rc);

    rc = mTrustlet.UninitializeAlgo();
    ALOGE_IF(rc, "UninitializeAlgo failed with rc = %d", rc);

    rc = mTrustlet.UninitializeSdk();
    ALOGE_IF(rc, "UninitializeSdk failed with rc = %d", rc);

    // Even though DeviceEnableGuard takes care of this, make extra
    // sure the device is powered down.
    mDev.Disable();
}

Return<uint64_t> BiometricsFingerprint::setNotify(const sp<IBiometricsFingerprintClientCallback> &clientCallback) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    mClientCallback = clientCallback;
    // This is here because HAL 2.1 doesn't have a way to propagate a
    // unique token for its driver. Subsequent versions should send a unique
    // token for each call to setNotify(). This is fine as long as there's only
    // one fingerprint device on the platform.
    return reinterpret_cast<uint64_t>(this);
}

Return<uint64_t> BiometricsFingerprint::preEnroll() {
    mEnrollChallenge = (uint64_t)rand() | (uint64_t)rand() << 0x20;
    ALOGI("%s: Generated enroll challenge %#lx", __func__, mEnrollChallenge);
    return mEnrollChallenge;
}

Return<RequestStatus> BiometricsFingerprint::enroll(const hidl_array<uint8_t, 69> &hat, uint32_t gid, uint32_t timeoutSec) {
    int rc = 0;

    if (!hat.data()) {
        // This seems to happen when locking the device while enrolling.
        // It is unknown why this function is called again.
        ALOGE("%s: authentication token is unset!", __func__);
        return RequestStatus::SYS_EINVAL;
    }

    if (gid != mGid) {
        ALOGE("Cannot enroll finger for different gid! Caller needs to update storePath first with setActiveGroup()!");
        return RequestStatus::SYS_EINVAL;
    }

    const auto &h = *reinterpret_cast<const hw_auth_token_t *>(hat.data());

    ALOGI("Starting enroll for challenge %#lx", h.challenge);

    if (mEnrollChallenge != h.challenge) {
        ALOGE("HAT challenge doesn't match preEnroll-provided challenge!");
        return RequestStatus::SYS_EINVAL;
    }

    rc = mTrustlet.CheckAuthToken(h);
    if (rc) {
        ALOGE("Auth token invalid, rc = %d", rc);
        return RequestStatus::SYS_EINVAL;
    }

    rc = mTrustlet.CheckSecureId(gid, h.user_id);
    if (rc) {
        ALOGE("Secure id invalid, rc = %d", rc);
        // TODO: This is where the HAL removes all fingerprints.
        ALOGW("Not removing fingerprints. If you see this, delete the database and report the issue");
        return RequestStatus::SYS_EINVAL;
    }

    rc = mTrustlet.GetNewPrintId(gid, mNewPrintId);
    if (rc == -2) {
        ALOGE("%s: No space for new fingerprint", __func__);
        return RequestStatus::SYS_ENOSPC;
    } else if (rc) {
        ALOGE("%s: Failed to get new print id, rc = %d", __func__, rc);
        return RequestStatus::SYS_EFAULT;
    }

    ALOGI("New print id = %u", mNewPrintId);

    mEnrollTimeout = timeoutSec;

    if (mWt.moveToState(AsyncState::Enroll))
        return RequestStatus::SYS_OK;

    return RequestStatus::SYS_EFAULT;
}

Return<RequestStatus> BiometricsFingerprint::postEnroll() {
    ALOGI("%s: clearing challenge", __func__);

    mEnrollTimeout = -1;
    mNewPrintId = -1;
    mEnrollChallenge = 0;

    return RequestStatus::SYS_OK;
}

Return<uint64_t> BiometricsFingerprint::getAuthenticatorId() {
    auto id = mTrustlet.GetAuthenticatorId();
    ALOGI("%s: id = %lu", __func__, id);
    return id;
}

Return<RequestStatus> BiometricsFingerprint::cancel() {
    ALOGI("Cancel requested");

    if (mWt.moveToState(AsyncState::Idle))
        return RequestStatus::SYS_OK;

    return RequestStatus::SYS_EFAULT;
}

Return<RequestStatus> BiometricsFingerprint::enumerate() {
    std::vector<uint32_t> fids;
    int rc = mTrustlet.GetPrintIds(mGid, fids);
    if (rc)
        return RequestStatus::SYS_EINVAL;

    auto remaining = fids.size();
    ALOGD("Enumerating %zu fingers", remaining);

    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (!remaining)
        // If no fingerprints exist, notify that the enumeration is done with remaining=0.
        // Use fid=0 to indicate that this is not a fingerprint.
        mClientCallback->onEnumerate(reinterpret_cast<uint64_t>(this), 0, mGid, 0);
    else
        for (auto fid : fids)
            mClientCallback->onEnumerate(reinterpret_cast<uint64_t>(this), fid, mGid, --remaining);

    return RequestStatus::SYS_OK;
}

Return<RequestStatus> BiometricsFingerprint::remove(uint32_t gid, uint32_t fid) {
    ALOGI("%s: gid = %d, fid = %d", __func__, gid, fid);
    if (gid != mGid) {
        ALOGE("Change group and userpath through setActiveGroup first!");
        return RequestStatus::SYS_EINVAL;
    }

    int rc = 0;

    if (fid == 0) {
        // Delete all fingerprints when fid is zero:
        ALOGI("Deleting all fingerprints");
        std::vector<uint32_t> fids;
        rc = mTrustlet.GetPrintIds(gid, fids);
        if (!rc) {
            auto remaining = fids.size();
            for (auto fid : fids) {
                rc = mTrustlet.RemovePrint(gid, fid);
                if (rc)
                    break;
                NotifyRemove(fid, --remaining);
            }
        }
    } else {
        ALOGI("Deleting print %d", fid);
        rc = mTrustlet.RemovePrint(gid, fid);
        if (!rc)
            NotifyRemove(fid, 0);
    }

    if (rc) {
        NotifyError(FingerprintError::ERROR_UNABLE_TO_REMOVE);
        return RequestStatus::SYS_EFAULT;
    }
    return RequestStatus::SYS_OK;
}

Return<RequestStatus> BiometricsFingerprint::setActiveGroup(uint32_t gid, const hidl_string &storePath) {
    ALOGI("%s: gid = %u, path = %s", __func__, gid, storePath.c_str());
    mGid = gid;
    int rc = mTrustlet.SetUserDataPath(gid, storePath.c_str());
    return rc ? RequestStatus::SYS_EINVAL : RequestStatus::SYS_OK;
}

Return<RequestStatus> BiometricsFingerprint::authenticate(uint64_t operationId, uint32_t gid) {
    ALOGI("%s: gid = %d, secret = %lu", __func__, gid, operationId);
    if (gid != mGid) {
        ALOGE("Cannot authenticate finger for different gid! Caller needs to update storePath first with setActiveGroup()!");
        return RequestStatus::SYS_EINVAL;
    }

    uint32_t cnt = 0;
    int rc = 0;

    rc = mTrustlet.GetEnrolledCount(cnt);
    if (rc) {
        ALOGE("%s: Failed to get finger count, rc = %d", __func__, rc);
        return RequestStatus::SYS_EFAULT;
    }
    ALOGI("%s: Have %d enrolled fingers", __func__, cnt);
    if (cnt == 0) {
        ALOGE("Error %s called without enrolled fingerprints!", __func__);
        return RequestStatus::SYS_EINVAL;
    }

    mOperationId = operationId;

    if (mWt.moveToState(AsyncState::Authenticate))
        return RequestStatus::SYS_OK;

    return RequestStatus::SYS_EFAULT;
}

Thread &BiometricsFingerprint::getWorker() {
    return mWt;
}

void BiometricsFingerprint::AuthenticateAsync() {
#ifdef HAS_DYNAMIC_POWER_MANAGEMENT
    DeviceEnableGuard<EgisFpDevice> guard{mDev};
#endif

    enum IdentifyState {
        WaitFingerDown = 1,
        GetImage = 2,
        Identify = 3,
        WaitFingerLost = 4,
    };

    int rc = 0;
    IdentifyState state = WaitFingerDown;
    bool done = false, canceled = false, timeout = false;

    bool updated;
    identify_result_t identify_result;
    ImageResult image_result;
    WakeupReason wakeup_reason;
    int reImaged = 0;
    bool force_retry = false;

    rc = mTrustlet.InitializeIdentify();
    if (rc) {
        ALOGE("%s: Failed to initialize identify, rc = %d", __func__, rc);
        NotifyError(FingerprintError::ERROR_UNABLE_TO_PROCESS);
        return;
    }

    while (!done && !rc && !canceled && !timeout) {
        if (mWt.isEventAvailable() && !force_retry) {
            canceled = true;
            break;
        }

        switch (state) {
            case WaitFingerDown:
                rc = mTrustlet.SetWorkMode(WorkMode::Detect);
                ALOGE_IF(rc, "%s: Failed to set detect mode, rc = %d", __func__, rc);
                if (rc)
                    break;

                wakeup_reason = mMux.waitForEvent();
                if (wakeup_reason == WakeupReason::Finger) {
                    state = GetImage;
                } else if (wakeup_reason == WakeupReason::Timeout) {
                    timeout = true;
                }
                break;
            case GetImage:
                rc = mTrustlet.GetImage(image_result);

                ALOGE_IF(rc, "%s: Failed to get image, rc = %d", __func__, rc);
                if (rc)
                    break;

                state = WaitFingerLost;
                force_retry = false;

                switch (image_result) {
                    case ImageResult::Good:
                        NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_GOOD);

                        // Proceed to enroll step:
                        state = Identify;
                        reImaged = 0;
                        break;
                    case ImageResult::TooFast:
                        NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_TOO_FAST);
                        break;
                    case ImageResult::ImagerDirty:
                    case ImageResult::ImagerDirty9:
                        if (reImaged > 6) {
                            NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_IMAGER_DIRTY);
                            usleep(100000);
                            reImaged = 0;
                        } else {
                            // Disable the sensor: the TZAPP will reset it completely!
                            rc = ResetSensor();
                            if (rc) {
                                // If it fails, our sensor is KO.
                                rc = mDev.Reset();
                                break;
                            }

                            // ...And acquire a new image!
                            reImaged++;
                            force_retry = true;
                            state = GetImage;
                            usleep(150000);
                        }
                        break;
                    case ImageResult::Partial:
                        if (reImaged > 6) {
                            NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_PARTIAL);
                            reImaged = 0;
                        } else {
                            // Disable the sensor: the TZAPP will reset it completely!
                            rc = ResetSensor();
                            if (rc) {
                                // If it fails, our sensor is KO.
                                rc = mDev.Reset();
                                break;
                            }

                            // ...And acquire a new image!
                            reImaged++;
                            force_retry = true;
                            state = GetImage;
                            usleep(150000);
                        }
                        break;
                    case ImageResult::Mediocre:
                        // This seems to be a mediocre image. Use the result from Identify to determine
                        // whether this is an accurate match
                        image_result = ImageResult::ImagerDirty;
                        NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_GOOD);
                        state = Identify;
                        break;
                    default:
                        state = WaitFingerDown;
                        break;
                }
                break;
            case Identify:
                // VSTATE_VERIFY
                rc = mTrustlet.Identify(mGid, mOperationId, identify_result);
                if (rc)
                    break;

                ALOGI("Identify status = %d, match_id = %d",
                      identify_result.status,
                      identify_result.match_id);

                if (identify_result.status == 0) {
                    if (image_result == ImageResult::ImagerDirty) {
                        ALOGW("%s: Special edgecase: identify 0 (good?), but imager was seemingly dirty...", __func__);
                        NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_IMAGER_DIRTY);
                    } else {
                        NotifyAuthenticated(identify_result.match_id, identify_result.hat);
                    }
                } else if (identify_result.status < 3) {
                    done = true;
                }

                rc = mTrustlet.UpdateTemplate(updated);
                if (rc)
                    break;

                if (updated) {
                    rc = mTrustlet.SaveTemplate();
                    if (rc)
                        break;
                }

                state = WaitFingerLost;
                break;
            case WaitFingerLost:
                // VSTATE_FINGER_OFF
                rc = mTrustlet.SetSpiState(1);
                if (rc)
                    break;
                rc = mTrustlet.IsFingerLost(30, image_result);
                if (rc)
                    break;

                if (image_result == ImageResult::Lost) {
                    rc = mTrustlet.SetSpiState(0);
                    state = WaitFingerDown;
                } else {
                    wakeup_reason = mMux.waitForEvent();
                    if (wakeup_reason == WakeupReason::Finger) {
                        rc = mTrustlet.SetSpiState(0);
                        state = WaitFingerDown;
                    } else if (wakeup_reason == WakeupReason::Timeout) {
                        timeout = true;
                    }
                }
                break;
        }

        if (rc == 99) {
            ALOGW("Resetting device...");
            rc = mDev.Reset();
            ALOGE_IF(rc, "%s: Failed to reset device, rc = %d", __func__, rc);
        }
    }

    mTrustlet.SetSpiState(0);
    rc = mTrustlet.FinalizeIdentify();

    ALOGE_IF(rc, "%s: Failed to finish identify, rc = %d", __func__, rc);

    // Clear challenge:
    mOperationId = 0;

    if (canceled) {
        ALOGI("%s: Canceled", __func__);
        NotifyError(FingerprintError::ERROR_CANCELED);
    } else if (timeout) {
        ALOGI("%s: Timeout", __func__);
        NotifyError(FingerprintError::ERROR_TIMEOUT);
    } else if (rc) {
        ALOGI("%s: Finalizing with error %d", __func__, rc);
        NotifyError(FingerprintError::ERROR_UNABLE_TO_PROCESS);
    } else if (done) {
        ALOGI("Authentication successful: fid = %d, score = %d",
              identify_result.match_id,
              identify_result.score);

        ALOGD(
            "Authentication match result: hwid=%d, cov=%d, quality=%d, score=%d,"
            " index=%d, template_cnt=%d, learn_update=%d, capture_time=%d, identify_time=%d",
            identify_result.sensor_hwid,
            identify_result.cov,
            identify_result.quality,
            identify_result.score,
            identify_result.index,
            identify_result.template_cnt,
            identify_result.learn_update,
            identify_result.capture_time,
            identify_result.identify_time);

        if (identify_result.hat.challenge)
            ALOGD("Result for challenge %lu: hmac timestamp = %lu user_id = %lu ",
                  identify_result.hat.challenge,
                  identify_result.hat.timestamp,
                  identify_result.hat.user_id);

        NotifyAuthenticated(identify_result.match_id, identify_result.hat);
    } else {
        ALOGE("Finished enroll without cancel, timeout, rc or successful auth");
    }
}

void BiometricsFingerprint::IdleAsync() {
    int rc = 0;
    int which;

    if (mHwId >= 0x600 || mHwId == 0x37) {
        // 6xx does not support gestures.
        rc = mTrustlet.SetWorkMode(WorkMode::Sleep);
        LOG_ALWAYS_FATAL_IF(rc, "SetWorkMode(WorkMode::Sleep) failed with rc=%d", rc);
        return WorkHandler::IdleAsync();
    }

#ifdef HAS_DYNAMIC_POWER_MANAGEMENT
    DeviceEnableGuard<EgisFpDevice> guard{mDev};
#endif

    rc = mTrustlet.SetWorkMode(WorkMode::NavigationDetect);
    LOG_ALWAYS_FATAL_IF(rc, "SetWorkMode(WorkMode::NavigationDetect) failed with rc=%d", rc);

    for (;;) {
        rc = mTrustlet.GetNavEvent(which);
        LOG_ALWAYS_FATAL_IF(rc, "GetNavEvent failed!");

        // Note that keycodes look like those defined in input-event-codes.h,
        // but are actually mirrored in both axes.

        switch (which) {
            case -1:
                ALOGI("%s: Nothing", __func__);
                break;
            case 111:
                ALOGI("%s: Doubletap", __func__);
                break;
            case 106:
                ALOGI("%s: Down", __func__);
                uinput.Click(KEY_DOWN);
                break;
            case 105:
                ALOGI("%s: Up", __func__);
                uinput.Click(KEY_UP);
                break;
            case 103:
                ALOGI("%s: Left", __func__);
                uinput.Click(KEY_LEFT);
                break;
            case 108:
                ALOGI("%s: Right", __func__);
                uinput.Click(KEY_RIGHT);
                break;
            case 28:
                ALOGI("%s: Hold", __func__);
                break;
        }

        WakeupReason wakeup_reason = mMux.waitForEvent();
        if (wakeup_reason == WakeupReason::Finger) {
            ALOGV("Gesture event!");
        } else if (wakeup_reason == WakeupReason::Event) {
            ALOGD("%s: Breaking to handle event", __func__);
            break;
        }
    }

    rc = mTrustlet.SetWorkMode(WorkMode::Sleep);
    LOG_ALWAYS_FATAL_IF(rc, "SetWorkMode(WorkMode::Sleep) failed with rc=%d", rc);
}

void BiometricsFingerprint::EnrollAsync() {
#ifdef HAS_DYNAMIC_POWER_MANAGEMENT
    DeviceEnableGuard<EgisFpDevice> guard{mDev};
#endif

    enum EnrollState {
        WaitFingerDown,
        GetImage,
        EnrollStep,
        WaitFingerLost,
    };

    int rc = 0;
    EnrollState state = WaitFingerDown;
    bool canceled = false, timeout = false;

    // Progress reporting:
    int finger_state = 0;
    int percentage_done = 0;
    int steps_done = 0;

    // Only for local use within case statements:
    enroll_result_t enroll_result;
    ImageResult image_result;
    int steps_needed;
    WakeupReason wakeup_reason;
    int reImaged = 0;
    bool force_retry = false;

    rc = mTrustlet.InitializeEnroll();
    if (rc) {
        ALOGE("%s: Failed to initialize enroll, rc = %d", __func__, rc);
        NotifyError(FingerprintError::ERROR_UNABLE_TO_PROCESS);
        return;
    }

    while (percentage_done < 100 && !canceled && !timeout && !rc) {
        if (mWt.isEventAvailable() && !force_retry) {
            canceled = true;
            break;
        }

        ALOGI("%s: State = %d (reImaged = %d)", __func__, state, reImaged);
        force_retry = false;

        switch (state) {
            case WaitFingerDown:
                rc = mTrustlet.SetWorkMode(WorkMode::Detect);
                ALOGE_IF(rc, "%s: Failed to set detect mode, rc = %d", __func__, rc);
                if (rc)
                    break;

                wakeup_reason = mMux.waitForEvent(mEnrollTimeout);
                if (wakeup_reason == WakeupReason::Finger) {
                    finger_state = 1;
                    state = GetImage;
                } else if (wakeup_reason == WakeupReason::Timeout) {
                    timeout = true;
                }
                break;
            case GetImage:
                rc = mTrustlet.GetImage(image_result);
                ALOGE_IF(rc, "%s: Failed to get image, rc = %d", __func__, rc);
                if (rc)
                    break;

                state = WaitFingerLost;

                switch (image_result) {
                    case ImageResult::Good:
                        NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_GOOD);

                        // Proceed to enroll step and reset reImaged state:
                        state = EnrollStep;
                        reImaged = 0;
                        break;
                    case ImageResult::TooFast:
                        NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_TOO_FAST);
                        break;
                    case ImageResult::Partial:
                        if (reImaged > 6) {
                            NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_PARTIAL);
                            usleep(10000);
                            reImaged = 0;
                        } else {
                            // Disable the sensor: the TZAPP will reset it completely!
                            rc = ResetSensor();
                            if (rc) {
                                // If it fails, our sensor is KO.
                                rc = mDev.Reset();
                                break;
                            }

                            // ...And acquire a new image!
                            reImaged++;
                            force_retry = true;
                            state = GetImage;
                            usleep(150000);
                        }
                        break;
                    case ImageResult::ImagerDirty:
                    case ImageResult::ImagerDirty9:
                        if (reImaged > 6) {
                            NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_IMAGER_DIRTY);
                            usleep(10000);
                            reImaged = 0;
                        } else {
                            // Disable the sensor: the TZAPP will reset it completely!
                            rc = ResetSensor();
                            if (rc) {
                                // If it fails, our sensor is KO.
                                rc = mDev.Reset();
                                break;
                            }

                            // ...And acquire a new image!
                            reImaged++;
                            force_retry = true;
                            state = GetImage;
                            usleep(150000);
                        }
                        break;
                    default:
                        state = WaitFingerDown;
                        break;
                }

                break;
            case EnrollStep:
                // Enroll only seems to do something when finger_state = 1
                // Not sure what happens with finger_state = 2 below.
                rc = mTrustlet.Enroll(finger_state, 0, enroll_result);
                ALOGE_IF(rc, "%s: Failed to enroll, rc = %d", __func__, rc);
                if (rc)
                    break;

                ALOGI("Enroll status = %d, at %d%%", enroll_result.status, enroll_result.percentage);
                ALOGI("Enroll dx = %d, dy = %d, score = %d",
                      enroll_result.dx, enroll_result.dy, enroll_result.score);

                // Reset finger state for next step:
                finger_state = 0;
                state = WaitFingerLost;

                percentage_done = enroll_result.percentage;

                switch (enroll_result.status) {
                    case ImageResult::Good: {
                        steps_done++;

                        // Usually 10 steps are needed:
                        steps_needed = 10;
                        if (percentage_done > 0)
                            // Calculate required number of steps based on reported percentage (without floats):
                            steps_needed = (100 * steps_done + percentage_done - 1) / percentage_done;

                        // Delay the final notify until after we have saved the fingerprint, otherwise
                        // there might be a race with postEnroll
                        if (percentage_done < 100) {
                            NotifyEnrollResult(mNewPrintId, steps_needed - steps_done);
                        }
                        break;
                    }
                    case ImageResult::Detected1:
                    case ImageResult::Detected3:
                        ALOGI("%s: Enroll() detected finger", __func__);
                        // Sends ACQUIRED_VENDOR, or FINGERPRINT_ACQUIRED_DETECTED in old-skool libhardware
                        break;
                    case ImageResult::ImagerDirty:
                    case ImageResult::ImagerDirty9:
                        NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_IMAGER_DIRTY);
                        break;
                    case ImageResult::Partial:
                        NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_PARTIAL);
                        break;
                    case ImageResult::Nothing:
                        // Nothing to add or improve, continue with the loop
                        break;
                    default:
                        ALOGE("Unknown enroll state %d", enroll_result.status);
                        rc = -1;
                        break;
                }
                break;
            case WaitFingerLost:
                rc = mTrustlet.SetSpiState(1);
                ALOGE_IF(rc, "%s: Failed to set SPI on, rc = %d", __func__, rc);
                if (rc)
                    break;
                rc = mTrustlet.IsFingerLost(30, image_result);
                if (rc)
                    break;

                if (image_result == ImageResult::Lost) {
                    finger_state = 2;

                    // If couldn't recalibrate, the sensor may be imprecise,
                    // warn the user, but that's not a critical issue.
                    rc = mTrustlet.Calibrate();
                    ALOGE_IF(rc,
                             "%s: Failed to recalibrate sensor "
                             "on FingerLost, rc = %d",
                             __func__, rc);

                    rc = mTrustlet.Enroll(finger_state, 0, enroll_result);
                    ALOGE_IF(rc, "%s: Failed to Enroll(2), rc = %d", __func__, rc);
                    if (rc)
                        break;
                    rc = mTrustlet.SetSpiState(0);
                    ALOGE_IF(rc, "%s: Failed to set SPI off, rc = %d", __func__, rc);
                    if (rc)
                        break;
                    // Proceed to next touch-step
                    state = WaitFingerDown;
                } else {
                    // NOTE: Based on authentication loop!

                    wakeup_reason = mMux.waitForEvent(mEnrollTimeout);
                    if (wakeup_reason == WakeupReason::Timeout)
                        timeout = true;
                }
                break;
        }

        if (rc == 99) {
            ALOGW("Resetting device...");
            rc = mDev.Reset();
            ALOGE_IF(rc, "%s: Failed to reset device, rc = %d", __func__, rc);
        }
    }

    ALOGI("%s: Finalizing, Percentage = %d%%", __func__, percentage_done);

    rc = mTrustlet.FinalizeEnroll();
    ALOGE_IF(rc, "%s: Failed to uninitialize enroll, rc = %d", __func__, rc);

    if (canceled) {
        ALOGI("%s: Canceled", __func__);
        NotifyError(FingerprintError::ERROR_CANCELED);
    } else if (timeout) {
        ALOGI("%s: Timeout", __func__);
        NotifyError(FingerprintError::ERROR_TIMEOUT);
    } else if (rc) {
        ALOGI("%s: Finalizing with error %d", __func__, rc);
        NotifyError(FingerprintError::ERROR_UNABLE_TO_PROCESS);
    } else if (percentage_done >= 100) {
        rc = mTrustlet.SaveEnrolledPrint(mGid, mNewPrintId);
        NotifyEnrollResult(mNewPrintId, 0);
        ALOGE_IF(rc, "%s: Failed to save print, rc = %d", __func__, rc);
    }
}

int BiometricsFingerprint::ResetSensor() {
    int rc = 0;

    // Disable the sensor: the TZAPP will reset it completely!
    rc = mTrustlet.SetWorkMode(WorkMode::Sleep);

    // Not fatal... but warn the user
    ALOGE_IF(rc, "%s: Cannot set sleep workmode...\n", __func__);

    mTrustlet.SetSpiState(0);
    usleep(150000);

    // Set it back up
    mTrustlet.SetSpiState(1);
    usleep(10000);
    rc = mTrustlet.SetWorkMode(WorkMode::Detect);
    ALOGE_IF(rc, "%s: Cannot set DETECT mode!!\n", __func__);

    return rc;
}

void BiometricsFingerprint::NotifyAcquired(FingerprintAcquiredInfo acquiredInfo) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    // Same here: No vendor acquire strings have been defined in an overlay.
    if (mClientCallback == nullptr)
        ALOGW("Client callback not set");
    else
        mClientCallback->onAcquired(reinterpret_cast<uint64_t>(this),
                                    std::min(acquiredInfo, FingerprintAcquiredInfo::ACQUIRED_VENDOR),
                                    acquiredInfo >= FingerprintAcquiredInfo::ACQUIRED_VENDOR ? (int32_t)acquiredInfo : 0);
}

void BiometricsFingerprint::NotifyAuthenticated(uint32_t fid, const hw_auth_token_t &hat) {
    auto hat_p = reinterpret_cast<const uint8_t *>(&hat);
    const hidl_vec<uint8_t> token(hat_p, hat_p + sizeof(hw_auth_token_t));
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback == nullptr)
        ALOGW("Client callback not set");
    else
        mClientCallback->onAuthenticated(reinterpret_cast<uint64_t>(this),
                                         fid,
                                         mGid,
                                         token);
}

void BiometricsFingerprint::NotifyEnrollResult(uint32_t fid, uint32_t remaining) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback == nullptr)
        ALOGW("Client callback not set");
    else
        mClientCallback->onEnrollResult(reinterpret_cast<uint64_t>(this), fid, mGid, remaining);
}

void BiometricsFingerprint::NotifyError(FingerprintError e) {
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
        mClientCallback->onError(reinterpret_cast<uint64_t>(this), e, 0);
}

void BiometricsFingerprint::NotifyRemove(uint32_t fid, uint32_t remaining) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback == nullptr)
        ALOGW("Client callback not set");
    else
        mClientCallback->onRemoved(
            reinterpret_cast<uint64_t>(this),
            fid,
            mGid,
            remaining);
}

}  // namespace egistec::current
