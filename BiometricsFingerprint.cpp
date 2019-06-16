/*
 * Copyright (C) 2018 Shane Francis / Jens Andersen
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

#include "BiometricsFingerprint.h"

#include <chrono>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <byteswap.h>

#include "android-base/macros.h"

namespace fpc {

using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintAcquiredInfo;
using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintError;
using ::android::hardware::biometrics::fingerprint::V2_1::RequestStatus;

BiometricsFingerprint::BiometricsFingerprint() : mClientCallback(nullptr), mDevice(nullptr) {
    mDevice = openHal();
    if (!mDevice) {
        ALOGE("Can't open HAL module");
        return;
    }

    if (!startWorker())
        return;
}

BiometricsFingerprint::~BiometricsFingerprint() {
    ALOGV("~BiometricsFingerprint()");
    if (mDevice == nullptr) {
        ALOGE("No valid device");
        return;
    }
    mDevice = nullptr;
}

Return<RequestStatus> BiometricsFingerprint::ErrorFilter(int32_t error) {
    switch(error) {
        case 0: return RequestStatus::SYS_OK;
        case -2: return RequestStatus::SYS_ENOENT;
        case -4: return RequestStatus::SYS_EINTR;
        case -5: return RequestStatus::SYS_EIO;
        case -11: return RequestStatus::SYS_EAGAIN;
        case -12: return RequestStatus::SYS_ENOMEM;
        case -13: return RequestStatus::SYS_EACCES;
        case -14: return RequestStatus::SYS_EFAULT;
        case -16: return RequestStatus::SYS_EBUSY;
        case -22: return RequestStatus::SYS_EINVAL;
        case -28: return RequestStatus::SYS_ENOSPC;
        case -110: return RequestStatus::SYS_ETIMEDOUT;
        default:
            ALOGE("An unknown error returned from fingerprint vendor library: %d", error);
            return RequestStatus::SYS_UNKNOWN;
    }
}

Return<uint64_t> BiometricsFingerprint::setNotify(
        const sp<IBiometricsFingerprintClientCallback>& clientCallback) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    mClientCallback = clientCallback;
    // This is here because HAL 2.1 doesn't have a way to propagate a
    // unique token for its driver. Subsequent versions should send a unique
    // token for each call to setNotify(). This is fine as long as there's only
    // one fingerprint device on the platform.
    return reinterpret_cast<uint64_t>(mDevice);
}

Return<uint64_t> BiometricsFingerprint::preEnroll()  {
    mDevice->challenge = fpc_load_auth_challenge(mDevice->fpc);
    ALOGI("%s : Challenge is : %ju",__func__, mDevice->challenge);
    return mDevice->challenge;
}

Return<RequestStatus> BiometricsFingerprint::enroll(const hidl_array<uint8_t, 69>& hat,
        uint32_t gid ATTRIBUTE_UNUSED,
        uint32_t timeoutSec ATTRIBUTE_UNUSED) {
    const hw_auth_token_t* authToken =
        reinterpret_cast<const hw_auth_token_t*>(hat.data());

    if (!clearThread())
        return RequestStatus::SYS_EBUSY;

    ALOGI("%s : hat->challenge %lu",__func__,(unsigned long) authToken->challenge);
    ALOGI("%s : hat->user_id %lu",__func__,(unsigned long) authToken->user_id);
    ALOGI("%s : hat->authenticator_id %lu",__func__,(unsigned long) authToken->authenticator_id);
    ALOGI("%s : hat->authenticator_type %d",__func__,authToken->authenticator_type);
    ALOGI("%s : hat->timestamp %lu",__func__,(unsigned long) authToken->timestamp);
    ALOGI("%s : hat size %lu",__func__,(unsigned long) sizeof(hw_auth_token_t));

    fpc_verify_auth_challenge(mDevice->fpc, (void*) authToken, sizeof(hw_auth_token_t));

    bool success = waitForState(STATE_ENROLL);
    return success ? RequestStatus::SYS_OK : RequestStatus::SYS_EAGAIN;
}

Return<RequestStatus> BiometricsFingerprint::postEnroll() {
    ALOGI("%s: Resetting challenge", __func__);
    mDevice->challenge = 0;
    return ErrorFilter(0);
}

Return<uint64_t> BiometricsFingerprint::getAuthenticatorId() {
    uint64_t id = fpc_load_db_id(mDevice->fpc);
    ALOGI("%s : ID : %ju",__func__,id );
    return id;
}

Return<RequestStatus> BiometricsFingerprint::cancel() {
    ALOGI("%s",__func__);

    // Resuming navigation queues a STATE_CANCEL and waits
    // for STATE_IDLE:
    if (resumeNavigation()) {
        ALOGI("%s : Successfully moved to idle state", __func__);
        return RequestStatus::SYS_OK;
    }

    ALOGE("%s : Failed to move to idle state", __func__);
    return RequestStatus::SYS_UNKNOWN;
}

Return<RequestStatus> BiometricsFingerprint::enumerate() {

    const uint64_t devId = reinterpret_cast<uint64_t>(mDevice);
    if (mClientCallback == nullptr) {
        ALOGE("Client callback not set");
        return RequestStatus::SYS_EFAULT;
    }

    ALOGV(__func__);

    if (!clearThread())
        return RequestStatus::SYS_EBUSY;

    fpc_fingerprint_index_t print_indexs;
    int rc = fpc_get_print_index(mDevice->fpc, &print_indexs);

    if (rc)
        return ErrorFilter(rc);

    if (!print_indexs.print_count)
        // When there are no fingers, the service still needs to know that (potentially async)
        // enumeration has finished. By convention, send fid=0 and remaining=0 to signal this:
        mClientCallback->onEnumerate(devId, 0, mDevice->gid, 0);
    else
        for (size_t i = 0; i < print_indexs.print_count; i++) {
            ALOGD("%s : found print : %lu at index %zu", __func__, (unsigned long) print_indexs.prints[i], i);

            uint32_t  remaining_templates = (uint32_t)(print_indexs.print_count - i - 1);

            mClientCallback->onEnumerate(devId, print_indexs.prints[i], mDevice->gid, remaining_templates);
        }

    resumeNavigation();

    return ErrorFilter(0);
}

Return<RequestStatus> BiometricsFingerprint::remove(uint32_t gid, uint32_t fid) {

    const uint64_t devId = reinterpret_cast<uint64_t>(mDevice);

    if (mClientCallback == nullptr) {
        ALOGE("Client callback not set");
        return ErrorFilter(-1);
    }

    if (!clearThread())
        return RequestStatus::SYS_EBUSY;

    Return<RequestStatus> ret = RequestStatus::SYS_OK;

    if (fpc_del_print_id(mDevice->fpc, fid) == 0){

        mClientCallback->onRemoved(devId, fid, gid,0);

        uint32_t db_length = fpc_get_user_db_length(mDevice->fpc);
        ALOGD("%s : User Database Length Is : %lu", __func__,(unsigned long) db_length);
        fpc_store_user_db(mDevice->fpc, db_length, mDevice->db_path);
        ret = ErrorFilter(0);
    } else {
        mClientCallback->onError(devId, FingerprintError::ERROR_UNABLE_TO_REMOVE, -1);
        ret = ErrorFilter(-1);
    }

    resumeNavigation();

    return ret;
}

int BiometricsFingerprint::__setActiveGroup(uint32_t gid) {
    int result;
    bool created_empty_db = false;
    struct stat sb;

    if(stat(mDevice->db_path, &sb) == -1) {
        // No existing database, load an empty one
        if ((result = fpc_load_empty_db(mDevice->fpc)) != 0) {
            ALOGE("Error creating empty user database: %d\n", result);
            return result;
        }
        created_empty_db = true;
    } else {
        if ((result = fpc_load_user_db(mDevice->fpc, mDevice->db_path)) != 0) {
            ALOGE("Error loading existing user database: %d\n", result);
            return result;
        }
    }

    if((result = fpc_set_gid(mDevice->fpc, gid)) != 0)
    {
        ALOGE("Error setting current gid: %d\n", result);
    }

    // if user database was created in this instance, store it directly
    if(created_empty_db)
    {
        int length  = fpc_get_user_db_length(mDevice->fpc);
        fpc_store_user_db(mDevice->fpc, length, mDevice->db_path);
        if ((result = fpc_load_user_db(mDevice->fpc, mDevice->db_path)) != 0) {
            ALOGE("Error loading empty user database: %d\n", result);
            return result;
        }
    }
    return result;
}

Return<RequestStatus> BiometricsFingerprint::setActiveGroup(uint32_t gid,
        const hidl_string& storePath) {

    int result;

    if (storePath.size() >= PATH_MAX || storePath.size() <= 0) {
        ALOGE("Bad path length: %zd", storePath.size());
        return RequestStatus::SYS_EINVAL;
    }
    if (access(storePath.c_str(), W_OK)) {
        return RequestStatus::SYS_EINVAL;
    }

    sprintf(mDevice->db_path,"%s/user.db", storePath.c_str());
    mDevice->gid = gid;

    ALOGI("%s : storage path set to : %s", __func__, mDevice->db_path);

    if (!clearThread())
        return RequestStatus::SYS_EBUSY;

    result = __setActiveGroup(gid);

    resumeNavigation();

    return ErrorFilter(result);
}

Return<RequestStatus> BiometricsFingerprint::authenticate(uint64_t operation_id,
        uint32_t gid ATTRIBUTE_UNUSED) {

    err_t r;

    ALOGI("%s: operation_id=%ju", __func__, operation_id);

    if (!clearThread())
        return RequestStatus::SYS_EBUSY;

    r = fpc_set_auth_challenge(mDevice->fpc, operation_id);
    auth_challenge = operation_id;
    if (r < 0) {
        ALOGE("%s: Error setting auth challenge to %ju. r=0x%08X",__func__, operation_id, r);
        return RequestStatus::SYS_EAGAIN;
    }

    bool success = waitForState(STATE_AUTH);
    return success ? RequestStatus::SYS_OK : RequestStatus::SYS_EAGAIN;
}

sony_fingerprint_device_t *BiometricsFingerprint::openHal() {
    ALOGI("%s",__func__);

    fpc_imp_data_t *fpc_data = NULL;

    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*) malloc(sizeof(sony_fingerprint_device_t));
    memset(sdev, 0, sizeof(sony_fingerprint_device_t));

    sdev->worker.event_fd = eventfd(0, EFD_NONBLOCK);

    if (fpc_init(&fpc_data, sdev->worker.event_fd) < 0) {
        ALOGE("Could not init FPC device");
        return nullptr;
    }
    sdev->fpc = fpc_data;

    sdev->worker.epoll_fd = epoll_create1(0);
    struct epoll_event evnt = {
        .data.fd = sdev->worker.event_fd,
        .events = EPOLLIN | EPOLLET,
    };

    epoll_ctl(sdev->worker.epoll_fd, EPOLL_CTL_ADD, sdev->worker.event_fd, &evnt);

    return sdev;
}

bool BiometricsFingerprint::startWorker() {
    if(pthread_create(&mDevice->worker.thread, NULL, worker_thread, (void *)this)) {
        ALOGE("%s : Error creating worker thread\n", __func__);
        mDevice->worker.thread_running  = false;
        return false;
    }

    mDevice->worker.running_state = STATE_INVALID;

    return true;
}

worker_state BiometricsFingerprint::getNextState() {
    eventfd_t requestedState;
    worker_state state = STATE_IDLE;

    int rc = eventfd_read(mDevice->worker.event_fd, &requestedState);
    if (!rc)
        state = (worker_state)requestedState;

    ALOGV("%s : %d", __func__, state);
    return state;
}

bool BiometricsFingerprint::isEventAvailable(int timeout) {
    struct epoll_event event;

    int cnt = epoll_wait(mDevice->worker.epoll_fd, &event, 1, timeout);

    if (cnt < 0) {
        ALOGE("Failed polling eventfd: %d", cnt);
        return false;
    }

    bool available = cnt > 0;
    ALOGV("%s : available=%d", __func__, available);

    return available;
}

bool BiometricsFingerprint::setState(worker_state state) {
    std::unique_lock<std::mutex> lock(mEventfdMutex);
    return setState(state, lock);
}

/**
 * Write a different eventfd state, assuming the caller locked the mutex.
 *
 * The unique_lock is passed in for the caller to prove that it owns mEventfdMutex.
 */
bool BiometricsFingerprint::setState(worker_state state, const std::unique_lock<std::mutex> &lock) {
    LOG_ALWAYS_FATAL_IF(lock.mutex() != &mEventfdMutex || !lock.owns_lock(),
                        "Caller didn't lock mEventfdMutex!");

    worker_state current_state = mDevice->worker.running_state;

    // Safety checks. It makes no sense to transition away from or towards a certain combination of states:
    bool cant_transition_away = current_state != STATE_POLL && current_state != STATE_IDLE;
    bool cant_transition_to = state != STATE_POLL && state != STATE_CANCEL;

    if (cant_transition_away && cant_transition_to) {
        ALOGE("%s : Invalid state transition to %d when still processing %d", __func__, state, current_state);
        return false;
    }

    if (current_state == state) {
        ALOGW("%s : Already running in state = %d", __func__, state);
        // Still okay - this is a very unlikely sitation.
        return true;
    }

    ALOGD("%s : Setting state to = %d", __func__, state);
    int rc = eventfd_write(mDevice->worker.event_fd, state);
    if (rc)
        ALOGE("%s : Failed to write state to eventfd: %d", __func__, rc);
    return !rc;
}

/**
 * Request the thread to switch to \p state, and wait for the transition
 * to happen.
 * Optionally takes a desired state to compare against. This is used when
 * the requested transition results in a different state.
 * For example, requesting STATE_CANCEL results in the thread waking up and
 * going into STATE_IDLE directly after.
 */
bool BiometricsFingerprint::waitForState(worker_state state, worker_state cmp_state) {
    constexpr auto wait_timeout = std::chrono::seconds(3);

    if (cmp_state == STATE_INVALID)
        cmp_state = state;

    std::unique_lock<std::mutex> lock(mEventfdMutex);

    ALOGD("%s: set=%d, wait_for=%d", __func__, state, cmp_state);

    if (mDevice->worker.running_state == cmp_state) {
        ALOGD("%s: Already in state %d", __func__, cmp_state);
        // Writing `state` will cause trouble, as the condition below
        // will most likely return true while `state` is still in-flight.
        return true;
    }

    if (!setState(state, lock)) {
        ALOGE("Failed to transition to %d from %d",
            state, mDevice->worker.running_state);
        return false;
    }

    // Wait for the thread to enter the new state:
    bool success = mThreadStateChanged.wait_for(lock, wait_timeout, [&]() {
        return mDevice->worker.running_state == cmp_state;
    });

    // Always crash, instead of blocking forever:
    LOG_ALWAYS_FATAL_IF(!success,
        "Timed out waiting for %d for %llds, after setting state %d. Are you writing race conditions??",
        cmp_state, wait_timeout.count(), state);

    ALOGD("%s: Successfully switched to %d", __func__, cmp_state);

    return true;
}

/**
 * Update the current running_state and notify any waiters.
 */
void BiometricsFingerprint::setRunningState(worker_state running_state) {
    std::unique_lock<std::mutex> lock(mEventfdMutex);
    mDevice->worker.running_state = running_state;
    mThreadStateChanged.notify_all();
}

/**
 * Free the thread from doing anything, waiting for the next state
 * to be written.
 *
 * Why?
 * Instead of engineering a separate state for navigation gesture handling,
 * which involves switching to it at the right time (eg. when exiting
 * auth/enroll state) while being resilient against race conditions.
 * Those happen when the Service using this HAL calls another state
 * just as we are setState'ing to the navigation state. Mutexes, peeking
 * into the eventfd and the like are just not as elegant.
 *
 * The upside of having this in a non-zero state (much like STATE_CANCEL)
 * means that any poll on the eventfd returns immediately; when an operation
 * is blocking on the irq and eventfd it'll wake up, finalize and give
 * control back to the worker_thread.
 */
// TODO: Find a MUCH better name for this
bool BiometricsFingerprint::clearThread() {
    ALOGD("%s", __func__);
    auto ret = waitForState(STATE_POLL);
    ALOGE_IF(!ret, "%s failed", __func__);
    return ret;
}

/**
 * Cancels the current operation, and waits until the thread
 * is idling again.
 *
 * Usually used to cancel a STATE_POLL.
 */
bool BiometricsFingerprint::resumeNavigation() {
    ALOGD("%s", __func__);
    auto ret = waitForState(STATE_CANCEL, STATE_IDLE);
    ALOGE_IF(!ret, "%s failed", __func__);
    return ret;
}

void * BiometricsFingerprint::worker_thread(void *args) {
    BiometricsFingerprint* thisPtr = static_cast<BiometricsFingerprint*>(args);

    if (!thisPtr) {
        ALOGE("%s : No BiometricsFingerprint instance set!", __func__);
        return NULL;
    }

    thisPtr->workerThread();
    return NULL;
}

void BiometricsFingerprint::workerThread() {
    bool navi_supported = fpc_navi_supported(mDevice->fpc);
    bool thread_running = true;
    bool event_available;

    ALOGI("%s : START", __func__);

    while (thread_running) {
        // Never poll on an event. If nothing is going on, switch
        // to navigation/gesture capture state.
        worker_state nextState = getNextState();

        switch (nextState) {
            case STATE_IDLE:
                ALOGI("%s : IDLE", __func__);
                setRunningState(STATE_IDLE);
                // Wait for a new state for at most 200ms before entering navigation mode.
                // This gives the service some time to execute multiple commands on the HAL
                // sequentially before needlessly going into navigation mode and exit it
                // almost immediately after.
                event_available = isEventAvailable(navi_supported ? 200 : -1);
                if (navi_supported && !event_available)
                    // Only enter navigation state when no event triggered
                    processNavigation();
                else if (navi_supported)
                    ALOGD("IDLE exit: Handle event instead of navigation");
                break;
            case STATE_POLL:
                ALOGI("%s : POLL", __func__);
                setRunningState(STATE_POLL);
                isEventAvailable(-1);
                // Poll always returns if the data in the eventfd is non-zero.
                break;
            case STATE_ENROLL:
                setRunningState(STATE_ENROLL);
                ALOGI("%s : ENROLL", __func__);
                processEnroll();
                break;
            case STATE_AUTH:
                setRunningState(STATE_AUTH);
                ALOGI("%s : AUTH", __func__);
                processAuth();
                break;
            case STATE_EXIT:
                setRunningState(STATE_EXIT);
                ALOGI("%s : EXIT", __func__);
                thread_running = false;
                break;
            case STATE_CANCEL:
                // Non-zero eventfd state to unblock pollers
                break;
            default:
                ALOGW("%s : UNKNOWN worker state %d", __func__, nextState);
                break;
        }
    }

    ALOGI("%s -", __func__);
}

void BiometricsFingerprint::processNavigation() {
    ALOGD(__func__);
    int rc;

    if (fpc_set_power(&mDevice->fpc->event, FPC_PWRON) < 0) {
        ALOGE("Error starting device");
        return;
    }

    rc = fpc_navi_enter(mDevice->fpc);
    ALOGE_IF(rc, "Failed to enter navigation state: rc=%d", rc);

    if (!rc) {
        rc = fpc_navi_poll(mDevice->fpc);
        ALOGE_IF(rc, "Failed to poll navigation: rc=%d", rc);

        rc = fpc_navi_exit(mDevice->fpc);
        ALOGE_IF(rc, "Failed to exit navigation: rc=%d", rc);
    }

    if (fpc_set_power(&mDevice->fpc->event, FPC_PWROFF) < 0)
        ALOGE("Error stopping device");
}

void BiometricsFingerprint::processEnroll() {
    // WARNING: Not implemented on any platform
    int32_t print_count = 0;
    // ALOGD("%s : print count is : %u", __func__, print_count);

    const uint64_t devId = reinterpret_cast<uint64_t>(mDevice);

    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback == nullptr) {
        ALOGE("Receiving callbacks before the client callback is registered.");
        return;
    }

    if (fpc_set_power(&mDevice->fpc->event, FPC_PWRON) < 0) {
        ALOGE("Error starting device");
        setRunningState(STATE_IDLE);
        mClientCallback->onError(devId, FingerprintError::ERROR_UNABLE_TO_PROCESS, 0);
        return;
    }

    int ret = fpc_enroll_start(mDevice->fpc, print_count);
    if(ret < 0)
    {
        ALOGE("Starting enroll failed: %d\n", ret);
    }

    int status = 1;

    while((status = fpc_capture_image(mDevice->fpc)) >= 0) {
        ALOGD("%s : Got Input status=%d", __func__, status);


        if (isEventAvailable()) {
            setRunningState(STATE_IDLE);
            mClientCallback->onError(devId, FingerprintError::ERROR_CANCELED, 0);
            break;
        }

        FingerprintAcquiredInfo hidlStatus = (FingerprintAcquiredInfo)status;

        if (hidlStatus <= FingerprintAcquiredInfo::ACQUIRED_TOO_FAST)
            mClientCallback->onAcquired(devId, hidlStatus, 0);

        //image captured
        if (status == FINGERPRINT_ACQUIRED_GOOD) {
            ALOGI("%s : Enroll Step", __func__);
            uint32_t remaining_touches = 0;
            int ret = fpc_enroll_step(mDevice->fpc, &remaining_touches);
            ALOGI("%s: step: %d, touches=%d\n", __func__, ret, remaining_touches);
            if (ret > 0) {
                ALOGI("%s : Touches Remaining : %d", __func__, remaining_touches);
                if (remaining_touches > 0) {
                    mClientCallback->onEnrollResult(devId, 0, 0,remaining_touches);
                }
            }
            else if (ret == 0) {
                uint32_t print_id = 0;
                int print_index = fpc_enroll_end(mDevice->fpc, &print_id);

                if (print_index < 0){
                    ALOGE("%s : Error getting new print index : %d", __func__,print_index);
                    setRunningState(STATE_IDLE);
                    mClientCallback->onError(devId, FingerprintError::ERROR_UNABLE_TO_PROCESS, 0);
                    break;
                }

                uint32_t db_length = fpc_get_user_db_length(mDevice->fpc);
                ALOGI("%s : User Database Length Is : %lu", __func__,(unsigned long) db_length);
                fpc_store_user_db(mDevice->fpc, db_length, mDevice->db_path);
                ALOGI("%s : Got print id : %lu", __func__,(unsigned long) print_id);
                setRunningState(STATE_IDLE);
                mClientCallback->onEnrollResult(devId, print_id, mDevice->gid, 0);
                break;
            }
            else {
                ALOGE("Error in enroll step, aborting enroll: %d\n", ret);
                setRunningState(STATE_IDLE);
                mClientCallback->onError(devId, FingerprintError::ERROR_UNABLE_TO_PROCESS, 0);
                break;
            }
        }
    }

    if (fpc_set_power(&mDevice->fpc->event, FPC_PWROFF) < 0)
        ALOGE("Error stopping device");

    if (status < 0)
        mClientCallback->onError(devId, FingerprintError::ERROR_HW_UNAVAILABLE, 0);
}


void BiometricsFingerprint::processAuth() {
    int result;
    int status = 1;

    const uint64_t devId = reinterpret_cast<uint64_t>(mDevice);

    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback == nullptr) {
        ALOGE("Receiving callbacks before the client callback is registered.");
        return;
    }

    if (fpc_set_power(&mDevice->fpc->event, FPC_PWRON) < 0) {
        ALOGE("Error starting device");
        setRunningState(STATE_IDLE);
        mClientCallback->onError(devId, FingerprintError::ERROR_UNABLE_TO_PROCESS, 0);
        return;
    }

    fpc_auth_start(mDevice->fpc);

    while((status = fpc_capture_image(mDevice->fpc)) >= 0 ) {
        ALOGV("%s : Got Input with status %d", __func__, status);

        if (isEventAvailable()) {
            setRunningState(STATE_IDLE);
            mClientCallback->onError(devId, FingerprintError::ERROR_CANCELED, 0);
            break;
        }

        FingerprintAcquiredInfo hidlStatus = (FingerprintAcquiredInfo)status;

        if (hidlStatus <= FingerprintAcquiredInfo::ACQUIRED_TOO_FAST)
            mClientCallback->onAcquired(devId, hidlStatus, 0);

        if (status == FINGERPRINT_ACQUIRED_GOOD) {

            uint32_t print_id = 0;
            int verify_state = fpc_auth_step(mDevice->fpc, &print_id);
            ALOGI("%s : Auth step = %d", __func__, verify_state);

            /* After getting something that ought to have been
             * recognizable: Either send proper notification, or
             * dummy one where fid=zero stands for unrecognized.
             */
            uint32_t gid = mDevice->gid;
            uint32_t fid = 0;

            if (verify_state >= 0) {
                if(print_id > 0)
                {
                    hw_auth_token_t hat;
                    ALOGI("%s : Got print id : %u", __func__, print_id);

                    result = fpc_update_template(mDevice->fpc);
                    if(result)
                    {
                        ALOGE("Error updating template: %d", result);
                    } else {
                        result = fpc_store_user_db(mDevice->fpc, 0, mDevice->db_path);
                        if (result) ALOGE("Error storing database: %d", result);
                    }

                    if (auth_challenge) {
                        fpc_get_hw_auth_obj(mDevice->fpc, &hat, sizeof(hw_auth_token_t));

                        ALOGW_IF(auth_challenge != hat.challenge,
                                "Local auth challenge %ju does not match hat challenge %ju",
                                auth_challenge, hat.challenge);

                        ALOGI("%s : hat->challenge %ju", __func__, hat.challenge);
                        ALOGI("%s : hat->user_id %ju", __func__, hat.user_id);
                        ALOGI("%s : hat->authenticator_id %ju",  __func__, hat.authenticator_id);
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

                    const uint8_t* hat2 = reinterpret_cast<const uint8_t *>(&hat);
                    const hidl_vec<uint8_t> token(std::vector<uint8_t>(hat2, hat2 + sizeof(hat)));

                    setRunningState(STATE_IDLE);
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
                result = fpc_close(&mDevice->fpc);
                LOG_ALWAYS_FATAL_IF(result < 0, "REINITIALIZE: Failed to close fpc: %d", result);
                result = fpc_init(&mDevice->fpc, mDevice->worker.event_fd);
                LOG_ALWAYS_FATAL_IF(result < 0, "REINITIALIZE: Failed to init fpc: %d", result);
#ifdef USE_FPC_YOSHINO
                int grp_err = __setActiveGroup(mDevice, gid);
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

    if (fpc_set_power(&mDevice->fpc->event, FPC_PWROFF) < 0)
        ALOGE("Error stopping device");

    if (status < 0)
        mClientCallback->onError(devId, FingerprintError::ERROR_HW_UNAVAILABLE, 0);
}

}  // namespace fpc
