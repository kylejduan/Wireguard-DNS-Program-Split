// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "bounded-log.h"
#include <atomic>

namespace wgps {
// Child output never holds a file open across rotations. The pump sleeps in a blocking read
// instead of polling; shutdown cancels that read, so it stays bounded even if a descendant
// inherited the pipe's write end and outlives the controller.
class LogPipe {
public:
    explicit LogPipe(BoundedLog& log) : log_(log) {
        SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
        if (!CreatePipe(&reader_, &writer_, &security, 65536)) return;
        if (!SetHandleInformation(reader_, HANDLE_FLAG_INHERIT, 0)) { close(); return; }
        pump_ = CreateThread(nullptr, 0, [](void* self) -> DWORD {
            // An exception must not escape the thread: losing log output is better than ending the host.
            try { static_cast<LogPipe*>(self)->drain(); } catch (...) {}
            return 0;
        }, this, 0, nullptr);
        if (!pump_) close();
    }
    ~LogPipe() {
        stopping_ = true;
        if (pump_) {
            // Without other holders of the write end, closing ours lets the pump drain and see
            // end-of-pipe. Otherwise cancel the blocked read; retry in case it was between reads.
            CloseHandle(writer_);
            writer_ = nullptr;
            while (WaitForSingleObject(pump_, 100) == WAIT_TIMEOUT) CancelSynchronousIo(pump_);
            CloseHandle(pump_);
        }
        close();
    }
    HANDLE writer() const { return writer_; }
    LogPipe(const LogPipe&) = delete;
    LogPipe& operator=(const LogPipe&) = delete;
private:
    void drain() {
        char buffer[4096];
        size_t finalBytes = 65536;
        DWORD read{};
        while (ReadFile(reader_, buffer, sizeof(buffer), &read, nullptr)) {
            log_.write(std::string_view(buffer, read));
            if (stopping_ && !(finalBytes -= std::min<size_t>(finalBytes, read))) return;
        }
    }
    void close() {
        if (reader_) CloseHandle(reader_);
        if (writer_) CloseHandle(writer_);
        reader_ = writer_ = nullptr;
    }
    BoundedLog& log_;
    HANDLE reader_{}, writer_{}, pump_{};
    std::atomic_bool stopping_{};
};
} // namespace wgps
