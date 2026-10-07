// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <windows.h>
#include <algorithm>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>

namespace wgps {
// One owning writer, with readers allowed across rotation. Logging is best effort: disk errors
// must neither grow the file beyond the cap nor tear down an otherwise healthy network stack.
class BoundedLog {
public:
    explicit BoundedLog(std::filesystem::path path, size_t limit = 8 * 1024 * 1024)
        : path_(std::move(path)), limit_(limit) {}
    ~BoundedLog() { close(); }
    BoundedLog(const BoundedLog&) = delete;
    BoundedLog& operator=(const BoundedLog&) = delete;

    bool write(std::string_view bytes) noexcept {
        try {
            std::lock_guard lock(mutex_);
            if (!open()) return false;
            const size_t count = std::min({bytes.size(), limit_, size_t(65536)});
            if (size_ > limit_ - count) {
                close();
                for (unsigned index = 3; index > 0; --index) {
                    auto source = index == 1 ? path_ : archive(index - 1);
                    const auto target = archive(index);
                    if (!MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING) &&
                        GetLastError() != ERROR_FILE_NOT_FOUND) return false;
                }
                if (!open()) return false;
            }
            DWORD written{};
            const bool ok = WriteFile(file_, bytes.data(), static_cast<DWORD>(count), &written, nullptr);
            size_ += written;
            return ok && written == count;
        } catch (...) { return false; }
    }

private:
    std::filesystem::path archive(unsigned index) const {
        return std::filesystem::path(path_.wstring() + L"." + std::to_wstring(index));
    }
    void close() {
        if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
    }
    bool open() {
        if (file_ != INVALID_HANDLE_VALUE) return true;
        file_ = CreateFileW(path_.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file_, &size)) { close(); return false; }
        size_ = static_cast<size_t>(size.QuadPart);
        return true;
    }
    std::filesystem::path path_;
    size_t limit_, size_{};
    HANDLE file_{INVALID_HANDLE_VALUE};
    std::mutex mutex_;
};

inline std::string utf8(const std::wstring& text) {
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string bytes(size, '\0');
    if (size) WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), bytes.data(), size, nullptr, nullptr);
    return bytes;
}
} // namespace wgps
