#include "EventMultiplexer.h"

#if PLATFORM_SDK_VERSION >= 28
#include <bits/epoll_event.h>
#endif
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#define LOG_TAG "FPC Mux"
#define LOG_NDEBUG 0
#include <log/log.h>

EventMultiplexer::EventMultiplexer(int dev_fd, int event_fd) : dev_fd(dev_fd), event_fd(event_fd) {
    int rc = 0;

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

EventMultiplexer::~EventMultiplexer() {
    close(epoll_fd);
}

WakeupReason EventMultiplexer::waitForEvent(int timeoutSec) {
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

    // This should never happen, as only event_fd and dev_fd are added to the epoll:
    LOG_ALWAYS_FATAL_IF(!finger_event, "Invalid wakeup source!");

    ALOGD("%s: WakeupReason = Finger", __func__);
    return WakeupReason::Finger;
}
