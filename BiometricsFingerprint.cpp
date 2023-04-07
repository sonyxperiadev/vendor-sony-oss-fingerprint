/*
 * Copyright (C) 2018 Shane Francis / Jens Andersen
 * Copyright (C) 2019 Marijn Suijten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "AOSP FPC HAL (Binder)"
#define LOG_VERBOSE "AOSP FPC HAL (Binder)"
// #define LOG_NDEBUG 0

#include "BiometricsFingerprint.h"

#include "android-base/macros.h"

#include <byteswap.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fpc {

using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintAcquiredInfo;
using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintError;
using ::android::hardware::biometrics::fingerprint::V2_1::RequestStatus;
using namespace ::SynchronizedWorker;

BiometricsFingerprint::BiometricsFingerprint() : mWt(this) {
    if (fpc_init(&fpc, mWt.getEventFd()) < 0)
        LOG_ALWAYS_FATAL("Could not init FPC device");

    mWt.Start();
}

BiometricsFingerprint::~BiometricsFingerprint() {
    ALOGV(__func__);
    if (fpc == nullptr) {
        ALOGE("%s: No valid device", __func__);
        return;
    }
    mWt.Stop();
    fpc_close(&fpc);
}

Return<RequestStatus> BiometricsFingerprint::ErrorFilter(int32_t error) {
    switch (error) {
        case 0:
            return RequestStatus::SYS_OK;
        case -2:
            return RequestStatus::SYS_ENOENT;
        case -4:
            return RequestStatus::SYS_EINTR;
        case -5:
            return RequestStatus::SYS_EIO;
        case -11:
            return RequestStatus::SYS_EAGAIN;
        case -12:
            return RequestStatus::SYS_ENOMEM;
        case -13:
            return RequestStatus::SYS_EACCES;
        case -14:
            return RequestStatus::SYS_EFAULT;
        case -16:
            return RequestStatus::SYS_EBUSY;
        case -22:
            return RequestStatus::SYS_EINVAL;
        case -28:
            return RequestStatus::SYS_ENOSPC;
        case -110:
            return RequestStatus::SYS_ETIMEDOUT;
        default:
            ALOGE("An unknown error returned from fingerprint vendor library: %d", error);
            return RequestStatus::SYS_UNKNOWN;
    }
}

Return<uint64_t> BiometricsFingerprint::setNotify(
    const sp<IBiometricsFingerprintClientCallback> &clientCallback) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    mClientCallback = clientCallback;
    // This is here because HAL 2.1 doesn't have a way to propagate a
    // unique token for its driver. Subsequent versions should send a unique
    // token for each call to setNotify(). This is fine as long as there's only
    // one fingerprint device on the platform.
    return reinterpret_cast<uint64_t>(this);
}

Return<uint64_t> BiometricsFingerprint::preEnroll() {
    enroll_challenge = fpc_load_auth_challenge(fpc);
    ALOGI("%s : Challenge is : %ju", __func__, enroll_challenge);
    return enroll_challenge;
}

Return<RequestStatus> BiometricsFingerprint::enroll(const hidl_array<uint8_t, 69> &hat,
                                                    uint32_t gid ATTRIBUTE_UNUSED,
                                                    uint32_t timeoutSec ATTRIBUTE_UNUSED) {
    const hw_auth_token_t *authToken =
        reinterpret_cast<const hw_auth_token_t *>(hat.data());

    if (!mWt.Pause())
        return RequestStatus::SYS_EBUSY;

    ALOGI("%s : hat->challenge %lu", __func__, (unsigned long)authToken->challenge);
    ALOGI("%s : hat->user_id %lu", __func__, (unsigned long)authToken->user_id);
    ALOGI("%s : hat->authenticator_id %lu", __func__, (unsigned long)authToken->authenticator_id);
    ALOGI("%s : hat->authenticator_type %d", __func__, authToken->authenticator_type);
    ALOGI("%s : hat->timestamp %lu", __func__, (unsigned long)authToken->timestamp);
    ALOGI("%s : hat size %lu", __func__, (unsigned long)sizeof(hw_auth_token_t));

    int rc = fpc_verify_auth_challenge(fpc, (void *)authToken, sizeof(hw_auth_token_t));
    if (rc)
        return ErrorFilter(rc);

    bool success = mWt.waitForState(AsyncState::Enroll);
    return success ? RequestStatus::SYS_OK : RequestStatus::SYS_EAGAIN;
}

Return<RequestStatus> BiometricsFingerprint::postEnroll() {
    ALOGI("%s: Resetting challenge", __func__);
    enroll_challenge = 0;
    return RequestStatus::SYS_OK;
}

Return<uint64_t> BiometricsFingerprint::getAuthenticatorId() {
    uint64_t id = fpc_load_db_id(fpc);
    ALOGI("%s : ID : %ju", __func__, id);
    return id;
}

Return<RequestStatus> BiometricsFingerprint::cancel() {
    ALOGI("%s", __func__);

    if (mWt.Resume()) {
        ALOGI("%s : Successfully moved to pause state", __func__);
        return RequestStatus::SYS_OK;
    }

    ALOGE("%s : Failed to move to pause state", __func__);
    return RequestStatus::SYS_UNKNOWN;
}

Return<RequestStatus> BiometricsFingerprint::enumerate() {
    const uint64_t devId = reinterpret_cast<uint64_t>(this);
    if (mClientCallback == nullptr) {
        ALOGE("Client callback not set");
        return RequestStatus::SYS_EFAULT;
    }

    ALOGV(__func__);

    if (!mWt.Pause())
        return RequestStatus::SYS_EBUSY;

    fpc_fingerprint_index_t print_indices;
    int rc = fpc_get_print_index(fpc, &print_indices);

    if (!rc) {
        if (!print_indices.print_count)
            // When there are no fingers, the service still needs to know that (potentially async)
            // enumeration has finished. By convention, send fid=0 and remaining=0 to signal this:
            mClientCallback->onEnumerate(devId, 0, gid, 0);
        else
            for (size_t i = 0; i < print_indices.print_count; i++) {
                ALOGD("%s : found print : %lu at index %zu", __func__, (unsigned long)print_indices.prints[i], i);

                uint32_t remaining_templates = (uint32_t)(print_indices.print_count - i - 1);

                mClientCallback->onEnumerate(devId, print_indices.prints[i], gid, remaining_templates);
            }
    }

    mWt.Resume();

    return ErrorFilter(rc);
}

Return<RequestStatus> BiometricsFingerprint::remove(uint32_t gid, uint32_t fid) {
    const uint64_t devId = reinterpret_cast<uint64_t>(this);

    if (mClientCallback == nullptr) {
        ALOGE("Client callback not set");
        return RequestStatus::SYS_EINVAL;
    }

    if (!mWt.Pause())
        return RequestStatus::SYS_EBUSY;

    int rc = 0;

    if (fid == 0) {
        // Delete all fingerprints when fid is zero:
        ALOGD("Deleting all fingerprints for gid %d", gid);

        fpc_fingerprint_index_t print_indices;
        rc = fpc_get_print_index(fpc, &print_indices);
        if (!rc)
            for (auto remaining = print_indices.print_count; remaining--;) {
                auto fid = print_indices.prints[remaining];
                ALOGD("Deleting print %d, %d remaining", fid, remaining);
                rc = fpc_del_print_id(fpc, fid);
                if (rc)
                    break;
                mClientCallback->onRemoved(devId, fid, gid, remaining);
            }
    } else {
        ALOGD("Removing finger %u for gid %u", fid, gid);
        rc = fpc_del_print_id(fpc, fid);
        if (!rc)
            mClientCallback->onRemoved(devId, fid, gid, 0);
    }

    if (rc) {
        mClientCallback->onError(devId, FingerprintError::ERROR_UNABLE_TO_REMOVE, 0);
    } else {
        rc = fpc_store_user_db(fpc, db_path);
    }

    mWt.Resume();

    return ErrorFilter(rc);
}

int BiometricsFingerprint::__setActiveGroup(uint32_t gid) {
    int result;
    bool created_empty_db = false;
    struct stat sb;

    if (stat(db_path, &sb) == -1) {
        // No existing database, load an empty one
        if ((result = fpc_load_empty_db(fpc)) != 0) {
            ALOGE("Error creating empty user database: %d\n", result);
            return result;
        }
        created_empty_db = true;
    } else {
        if ((result = fpc_load_user_db(fpc, db_path)) != 0) {
            ALOGE("Error loading existing user database: %d\n", result);
            return result;
        }
    }

    if ((result = fpc_set_gid(fpc, gid)) != 0) {
        ALOGE("Error setting current gid: %d\n", result);
    }

    // if user database was created in this instance, store it directly
    if (created_empty_db) {
        if ((result = fpc_store_user_db(fpc, db_path))) {
            ALOGE("Failed to store empty user database: %d\n", result);
            return result;
        }
        if ((result = fpc_load_user_db(fpc, db_path))) {
            ALOGE("Error loading empty user database: %d\n", result);
            return result;
        }
    }
    return result;
}

Return<RequestStatus> BiometricsFingerprint::setActiveGroup(uint32_t gid,
                                                            const hidl_string &storePath) {
    int result;

    if (storePath.size() >= PATH_MAX || storePath.size() <= 0) {
        ALOGE("Bad path length: %zd", storePath.size());
        return RequestStatus::SYS_EINVAL;
    }
    if (access(storePath.c_str(), W_OK)) {
        return RequestStatus::SYS_EINVAL;
    }

    sprintf(db_path, "%s/user.db", storePath.c_str());
    this->gid = gid;

    ALOGI("%s : storage path set to : %s", __func__, db_path);

    if (!mWt.Pause())
        return RequestStatus::SYS_EBUSY;

    result = __setActiveGroup(gid);

    mWt.Resume();

    return ErrorFilter(result);
}

Return<RequestStatus> BiometricsFingerprint::authenticate(uint64_t operation_id,
                                                          uint32_t gid ATTRIBUTE_UNUSED) {
    err_t r;

    ALOGI("%s: operation_id=%ju", __func__, operation_id);

    if (!mWt.Pause())
        return RequestStatus::SYS_EBUSY;

    r = fpc_set_auth_challenge(fpc, operation_id);
    auth_challenge = operation_id;
    if (r < 0) {
        ALOGE("%s: Error setting auth challenge to %ju. r=0x%08X", __func__, operation_id, r);
        return RequestStatus::SYS_EAGAIN;
    }

    bool success = mWt.waitForState(AsyncState::Authenticate);
    return success ? RequestStatus::SYS_OK : RequestStatus::SYS_EAGAIN;
}

void BiometricsFingerprint::IdleAsync() {
    ALOGD(__func__);
    int rc;

    if (!fpc_navi_supported(fpc)) {
        WorkHandler::IdleAsync();
        return;
    }

    // Wait for a new state for at most 500ms before entering navigation mode.
    // This gives the service some time to execute multiple commands on the HAL
    // sequentially before needlessly going into navigation mode and exit it
    // almost immediately after.
    else if (mWt.isEventAvailable(500)) {
        ALOGD("%s: EXIT: Handle event instead of navigation", __func__);
        return;
    }

    ALOGD("%s: Start gesture polling", __func__);

    if (fpc_set_power(&fpc->event, FPC_PWRON) < 0) {
        ALOGE("Error starting device");
        return;
    }

    rc = fpc_navi_enter(fpc);
    ALOGE_IF(rc, "Failed to enter navigation state: rc=%d", rc);

    if (!rc) {
        rc = fpc_navi_poll(fpc);
        ALOGE_IF(rc, "Failed to poll navigation: rc=%d", rc);

        rc = fpc_navi_exit(fpc);
        ALOGE_IF(rc, "Failed to exit navigation: rc=%d", rc);
    }

    if (fpc_set_power(&fpc->event, FPC_PWROFF) < 0)
        ALOGE("Error stopping device");
}

void BiometricsFingerprint::EnrollAsync() {
    // WARNING: Not implemented on any platform
    int32_t print_count = 0;
    // ALOGD("%s : print count is : %u", __func__, print_count);

    const uint64_t devId = reinterpret_cast<uint64_t>(this);

    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback == nullptr) {
        ALOGE("Receiving callbacks before the client callback is registered.");
        return;
    }

    if (fpc_set_power(&fpc->event, FPC_PWRON) < 0) {
        ALOGE("Error starting device");
        mClientCallback->onError(devId, FingerprintError::ERROR_UNABLE_TO_PROCESS, 0);
        return;
    }

    int ret = fpc_enroll_start(fpc, print_count);
    if (ret < 0) {
        ALOGE("Starting enroll failed: %d\n", ret);
    }

    int status = 1;

    while ((status = fpc_capture_image(fpc)) >= 0) {
        ALOGD("%s : Got Input status=%d", __func__, status);

        if (mWt.isEventAvailable()) {
            mClientCallback->onError(devId, FingerprintError::ERROR_CANCELED, 0);
            break;
        }

        FingerprintAcquiredInfo hidlStatus = (FingerprintAcquiredInfo)status;

        if (hidlStatus <= FingerprintAcquiredInfo::ACQUIRED_TOO_FAST)
            mClientCallback->onAcquired(devId, hidlStatus, 0);

        // image captured
        if (status == FINGERPRINT_ACQUIRED_GOOD) {
            ALOGI("%s : Enroll Step", __func__);
            uint32_t remaining_touches = 0;
            int ret = fpc_enroll_step(fpc, &remaining_touches);
            ALOGI("%s: step: %d, touches=%d\n", __func__, ret, remaining_touches);
            if (ret > 0) {
                ALOGI("%s : Touches Remaining : %d", __func__, remaining_touches);
                if (remaining_touches > 0) {
                    mClientCallback->onEnrollResult(devId, 0, 0, remaining_touches);
                }
            } else if (ret == 0) {
                uint32_t print_id = 0;
                int print_index = fpc_enroll_end(fpc, &print_id);

                if (print_index < 0) {
                    ALOGE("%s : Error getting new print index : %d", __func__, print_index);
                    mClientCallback->onError(devId, FingerprintError::ERROR_UNABLE_TO_PROCESS, 0);
                    break;
                }

                fpc_store_user_db(fpc, db_path);
                ALOGI("%s : Got print id : %lu", __func__, (unsigned long)print_id);
                mClientCallback->onEnrollResult(devId, print_id, gid, 0);
                break;
            } else {
                ALOGE("Error in enroll step, aborting enroll: %d\n", ret);
                mClientCallback->onError(devId, FingerprintError::ERROR_UNABLE_TO_PROCESS, 0);
                break;
            }
        }
    }

    if (fpc_set_power(&fpc->event, FPC_PWROFF) < 0)
        ALOGE("Error stopping device");

    if (status < 0)
        mClientCallback->onError(devId, FingerprintError::ERROR_HW_UNAVAILABLE, 0);
}

void BiometricsFingerprint::AuthenticateAsync() {
    int result;
    int status = 1;

    const uint64_t devId = reinterpret_cast<uint64_t>(this);

    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback == nullptr) {
        ALOGE("Receiving callbacks before the client callback is registered.");
        return;
    }

    if (fpc_set_power(&fpc->event, FPC_PWRON) < 0) {
        ALOGE("Error starting device");
        mClientCallback->onError(devId, FingerprintError::ERROR_UNABLE_TO_PROCESS, 0);
        return;
    }

    fpc_auth_start(fpc);

    while ((status = fpc_capture_image(fpc)) >= 0) {
        ALOGV("%s : Got Input with status %d", __func__, status);

        if (mWt.isEventAvailable()) {
            mClientCallback->onError(devId, FingerprintError::ERROR_CANCELED, 0);
            break;
        }

        FingerprintAcquiredInfo hidlStatus = (FingerprintAcquiredInfo)status;

        if (hidlStatus <= FingerprintAcquiredInfo::ACQUIRED_TOO_FAST)
            mClientCallback->onAcquired(devId, hidlStatus, 0);

        if (status == FINGERPRINT_ACQUIRED_GOOD) {
            uint32_t print_id = 0;
            int verify_state = fpc_auth_step(fpc, &print_id);
            ALOGI("%s : Auth step = %d", __func__, verify_state);

            /* After getting something that ought to have been
             * recognizable: Either send proper notification, or
             * dummy one where fid=zero stands for unrecognized.
             */
            uint32_t fid = 0;

            if (verify_state >= 0) {
                result = fpc_update_template(fpc);
                if (result < 0) {
                    ALOGE("Error updating template: %d", result);
                } else if (result) {
                    ALOGI("Storing db");
                    result = fpc_store_user_db(fpc, db_path);
                    if (result) ALOGE("Error storing database: %d", result);
                }

                if (print_id > 0) {
                    hw_auth_token_t hat;
                    ALOGI("%s : Got print id : %u", __func__, print_id);

                    if (auth_challenge) {
                        fpc_get_hw_auth_obj(fpc, &hat, sizeof(hw_auth_token_t));

                        ALOGW_IF(auth_challenge != hat.challenge,
                                 "Local auth challenge %ju does not match hat challenge %ju",
                                 auth_challenge, hat.challenge);

                        ALOGI("%s : hat->challenge %ju", __func__, hat.challenge);
                        ALOGI("%s : hat->user_id %ju", __func__, hat.user_id);
                        ALOGI("%s : hat->authenticator_id %ju", __func__, hat.authenticator_id);
                        ALOGI("%s : hat->authenticator_type %u", __func__, ntohl(hat.authenticator_type));
                        ALOGI("%s : hat->timestamp %lu", __func__, bswap_64(hat.timestamp));
                        ALOGI("%s : hat size %zu", __func__, sizeof(hw_auth_token_t));
                    } else {
                        // Without challenge, there's no reason to bother the TZ to
                        // provide an "invalid" response token.
                        ALOGD("No authentication challenge set. Reporting empty HAT");
                        memset(&hat, 0, sizeof(hat));
                    }

                    fid = print_id;

                    const uint8_t *hat2 = reinterpret_cast<const uint8_t *>(&hat);
                    const hidl_vec<uint8_t> token(std::vector<uint8_t>(hat2, hat2 + sizeof(hat)));

                    mClientCallback->onAuthenticated(devId, fid, gid, token);
                    break;
                } else {
                    ALOGI("%s : Got print id : %u", __func__, print_id);
                    mClientCallback->onAuthenticated(devId, fid, gid, hidl_vec<uint8_t>());
                }

            } else if (verify_state == -EAGAIN) {
                ALOGI("%s : retrying due to receiving -EAGAIN", __func__);
                mClientCallback->onAuthenticated(devId, fid, gid, hidl_vec<uint8_t>());
            } else {
                /*
                 * Reinitialize the TZ app and parameters
                 * to clear the TZ error generated by flooding it
                 */
                result = fpc_close(&fpc);
                LOG_ALWAYS_FATAL_IF(result < 0, "REINITIALIZE: Failed to close fpc: %d", result);
                sleep(1);
                result = fpc_init(&fpc, mWt.getEventFd());
                LOG_ALWAYS_FATAL_IF(result < 0, "REINITIALIZE: Failed to init fpc: %d", result);
#ifdef USE_FPC_YOSHINO
                int grp_err = __setActiveGroup(gid);
                if (grp_err)
                    ALOGE("%s : Cannot reinitialize database", __func__);
#else
                // Break out of the loop, and make sure ERROR_HW_UNAVAILABLE
                // is raised afterwards, similar to the stock hal:
                status = -1;
                break;
#endif
            }
        }
    }

    if (fpc_set_power(&fpc->event, FPC_PWROFF) < 0)
        ALOGE("Error stopping device");

    if (status < 0)
        mClientCallback->onError(devId, FingerprintError::ERROR_HW_UNAVAILABLE, 0);
}

}  // namespace fpc
