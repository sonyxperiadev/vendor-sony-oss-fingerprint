#pragma once

#include <sys/eventfd.h>
#include <thread>

enum class AsyncState : eventfd_t {
    Idle = 0,
    Cancel,
    Authenticate,
    Enroll,
    Stop,
};

enum class WakeupReason {
    Timeout,
    Event,
    Finger,  // Hardware
};

struct WorkHandler {
    virtual void AuthenticateAsync() = 0;
    virtual void EnrollAsync() = 0;
    inline virtual void OnEnterIdle() {
    }
    inline virtual void HandleGesturesAsync() {
    }

    inline virtual ~WorkHandler() {
    }
};

class WorkerThread {
    AsyncState currentState = AsyncState::Idle;
    int dev_fd;
    int epoll_fd;
    int event_fd;
    std::thread thread;
    WorkHandler *mHandler;

    static void *ThreadStart(void *);
    void RunThread();

   public:
    WorkerThread(WorkHandler *handler, int dev_fd);

    void Start();
    void Stop();

    AsyncState ReadState() const;
    bool IsEventAvailable() const;
    bool MoveToState(AsyncState);
    WakeupReason WaitForEvent(int timeoutSec = -1);
};
