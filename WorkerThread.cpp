#include "WorkerThread.h"

#if PLATFORM_SDK_VERSION >= 28
#include <bits/epoll_event.h>
#endif
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <FormatException.hpp>

#define LOG_TAG "FPC"
#define LOG_NDEBUG 0
#include <log/log.h>

WorkerThread::WorkerThread(WorkHandler *handler, int dev_fd) : dev_fd(dev_fd), mHandler(handler) {
    int rc = 0;

    LOG_ALWAYS_FATAL_IF(!mHandler, "WorkHandler is null!");

    event_fd = eventfd((eventfd_t)AsyncState::Idle, EFD_NONBLOCK);
    LOG_ALWAYS_FATAL_IF(event_fd < 0, "Failed to create eventfd: %s", strerror(errno));
    epoll_fd = epoll_create1(0);
    LOG_ALWAYS_FATAL_IF(epoll_fd < 0, "Failed to create epoll: %s", strerror(errno));

    struct epoll_event ev = {
        .data.fd = event_fd,
        .events = EPOLLIN,
    };
    rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &ev);
    LOG_ALWAYS_FATAL_IF(rc, "Failed to add eventfd %d to epoll: %s", event_fd, strerror(errno));

    ev = {
        .data.fd = dev_fd,
        .events = EPOLLIN,
    };
    rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
    LOG_ALWAYS_FATAL_IF(rc, "Failed to add fingerprint device %d to epoll: %s", dev_fd, strerror(errno));
}

void *WorkerThread::ThreadStart(void *arg) {
    auto &self = *static_cast<WorkerThread *>(arg);
    self.RunThread();
    return nullptr;
}

void WorkerThread::RunThread() {
    ALOGD("Async thread up");
    for (;;) {
        auto nextState = ReadState();
        currentState = nextState;
        switch (nextState) {
            case AsyncState::Idle: {
                // Notify the handler, such that it can force a
                // power-saving mode on the hardware.
                mHandler->OnEnterIdle();

                // NOTE: Not using WaitForEvent() here, because we are not interested
                // in wakeups from the fp device, only in events.
                struct pollfd pfd = {
                    .fd = event_fd,
                    .events = POLLIN,
                };
                int cnt = poll(&pfd, 1, -1);
                if (cnt <= 0)
                    ALOGW("Infinite poll returned with %d", cnt);
                break;
            }
            case AsyncState::Cancel:
                // Non-zero eventfd state to unblock pollers
                break;
            case AsyncState::Authenticate:
                mHandler->AuthenticateAsync();
                break;
            case AsyncState::Enroll:
                mHandler->EnrollAsync();
                break;
            case AsyncState::Stop:
                ALOGI("Stopping WorkerThread");
                return;
            default:
                ALOGW("Unexpected AsyncState %lu", nextState);
                break;
        }
        currentState = AsyncState::Idle;
    }
}

void WorkerThread::Start() {
    thread = std::thread(ThreadStart, this);
}

void WorkerThread::Stop() {
    ALOGI("Requesting thread to stop");
    MoveToState(AsyncState::Stop);
    thread.join();
}

AsyncState WorkerThread::ReadState() const {
    eventfd_t requestedState;
    AsyncState state = AsyncState::Idle;

    int rc = eventfd_read(event_fd, &requestedState);
    // When nothing is read (no event is available), it's Idle.
    if (!rc)
        state = static_cast<AsyncState>(requestedState);

    return state;
}

bool WorkerThread::IsEventAvailable() const {
    struct pollfd pfd = {
        .fd = event_fd,
        .events = POLLIN,
    };

    // 0 = do not block at all:
    int cnt = poll(&pfd, 1, 0);

    if (cnt < 0) {
        ALOGE("%s: Failed polling eventfd: %d", __func__, cnt);
        return false;
    }

    bool available = cnt > 0;
    ALOGV("%s: available=%d", __func__, available);

    return available;
}

bool WorkerThread::MoveToState(AsyncState nextState) {
    ALOGD("Attempting to move to state %lu", nextState);
    // TODO: This is racy (eg. does not look at in-flight state),
    // but it does not matter because async operations are not supposed to be
    // invoked concurrently (how can a device run any combination of authenticate or
    // enroll simultaneously??). The thread will simply reject it in that case.

    // Currently, the service that uses this HAL (FingerprintService.java) calls cancel() in
    // such a case, and only starts the next operation upon receiving FingerprintError::ERROR_CANCELED.

    if (nextState != AsyncState::Cancel && currentState != AsyncState::Idle) {
        ALOGW("Thread already in state %lu, refusing to move to %lu", currentState, nextState);
        return false;
    }

    int rc = eventfd_write(event_fd, (eventfd_t)nextState);
    if (rc) {
        ALOGE("Failed to write next state to eventfd: %s", strerror(errno));
        return false;
    }
    return true;
}

WakeupReason WorkerThread::WaitForEvent(int timeoutSec) {
    constexpr auto EVENT_COUNT = 2;
    struct epoll_event events[EVENT_COUNT];
    ALOGD("%s: TimeoutSec = %d", __func__, timeoutSec);
    int cnt = epoll_wait(epoll_fd, events, EVENT_COUNT, 1000 * timeoutSec);

    if (cnt < 0) {
        ALOGE("%s: epoll_wait failed: %s", __func__, strerror(errno));
        // Let the current operation continue as if nothing happened:
        return WakeupReason::Timeout;
    }

    if (!cnt) {
        ALOGD("%s: WakeupReason = Timeout", __func__);
        return WakeupReason::Timeout;
    }

    bool finger_event = false;

    for (auto ei = 0; ei < cnt; ++ei)
        if (events[ei].events & EPOLLIN) {
            // Control events have priority over finger events, since
            // this is probably a request to cancel the current operation.
            if (events[ei].data.fd == event_fd) {
                ALOGD("%s: WakeupReason = Event", __func__);
                return WakeupReason::Event;
            } else if (events[ei].data.fd == dev_fd) {
                finger_event = true;
            }
        }

    if (finger_event) {
        ALOGD("%s: WakeupReason = Finger", __func__);
        return WakeupReason::Finger;
    }

    throw FormatException("Invalid fd source!");
}
