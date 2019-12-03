#pragma once

enum class WakeupReason {
    Timeout,
    Event,
    Finger,  // Hardware
};

class EventMultiplexer {
    int dev_fd;
    int epoll_fd;
    int event_fd;

   public:
    EventMultiplexer(int event_fd, int dev_fd);
    ~EventMultiplexer();

    WakeupReason waitForEvent(int timeoutSec = -1);
};
