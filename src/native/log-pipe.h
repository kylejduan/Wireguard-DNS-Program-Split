// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "bounded-log.h"
#include <atomic>
#include <thread>

namespace wgps {
// Child output never holds a file open across rotations. Peek before ReadFile keeps shutdown
// bounded even if a descendant inherited the pipe's write end and outlives the controller.
class LogPipe {
public:
    explicit LogPipe(BoundedLog& log) : log_(log) {
        SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
        if (!CreatePipe(&reader_, &writer_, &security, 65536)) return;
        if (!SetHandleInformation(reader_, HANDLE_FLAG_INHERIT, 0)) { close(); return; }
        try { pump_ = std::thread([this] { drain(); }); }
        catch (...) { close(); }
    }
    ~LogPipe() {
        stopping_ = true;
        if (pump_.joinable()) pump_.join();
        close();
    }
    HANDLE writer() const { return writer_; }
    LogPipe(const LogPipe&) = delete;
    LogPipe& operator=(const LogPipe&) = delete;
private:
    void drain() {
        char buffer[4096];
        size_t finalBytes = 65536;
        while (true) {
            DWORD available{};
            if (!PeekNamedPipe(reader_, nullptr, 0, nullptr, &available, nullptr)) return;
            if (stopping_ && (!available || !finalBytes)) return;
            if (!available) { Sleep(50); continue; }
            DWORD read{};
            if (!ReadFile(reader_, buffer, std::min<DWORD>(available, sizeof(buffer)), &read, nullptr)) return;
            log_.write(std::string_view(buffer, read));
            if (stopping_) finalBytes -= std::min<size_t>(finalBytes, read);
        }
    }
    void close() {
        if (reader_) CloseHandle(reader_);
        if (writer_) CloseHandle(writer_);
        reader_ = writer_ = nullptr;
    }
    BoundedLog& log_;
    HANDLE reader_{}, writer_{};
    std::atomic_bool stopping_{};
    std::thread pump_;
};
} // namespace wgps
