/*
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

#pragma once

#include <condition_variable>
#include <mutex>
#include <thread>

namespace SynchronizedWorker {

class Thread;

enum class AsyncState {
    Invalid,
    Idle,
    Pause,
    Authenticate,
    Enroll,
    Stop,
};

struct WorkHandler {
    virtual Thread &getWorker() = 0;

    virtual void AuthenticateAsync() = 0;
    virtual void EnrollAsync() = 0;

    virtual void IdleAsync();

    inline virtual ~WorkHandler() {
    }
};

class Thread {
    AsyncState currentState = AsyncState::Invalid, desiredState = AsyncState::Invalid;
    int event_fd;
    std::condition_variable mThreadStateChanged;
    /**
     * Two mutexes are required to syncronize between multiple invocations of moveToState/waitForState,
     * and between waitForState and consumeState (called in the worker thread).
     */
    std::mutex mEventWriterMutex,
        mThreadMutex;
    std::thread thread;
    WorkHandler *mHandler;

    static void *ThreadStart(void *);
    void RunThread();

   public:
    Thread(WorkHandler *handler);
    ~Thread();

    int getEventFd() const;

    void Start();
    void Stop();
    bool Pause();
    bool Resume();

    AsyncState consumeState();
    bool isEventAvailable(int timeout = /* Do not block at all: */ 0) const;
    bool moveToState(AsyncState);
    bool waitForState(AsyncState);

   private:
    // Unsafe functions, both locks need to lock private mEventWriterMutex
    bool moveToState(AsyncState, std::unique_lock<std::mutex> &writerLock, std::unique_lock<std::mutex> &threadLock);
    bool waitForState(AsyncState, std::unique_lock<std::mutex> &writerLock, std::unique_lock<std::mutex> &threadLock);
};

}  // namespace SynchronizedWorker
