// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <shellapi.h>
#include "inherited-process.h"
#include <algorithm>
#include <atomic>
#include <charconv>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace wgps::tray {
struct Handle {
    HANDLE value{};
    explicit Handle(HANDLE h = nullptr) : value(h == INVALID_HANDLE_VALUE ? nullptr : h) {}
    ~Handle() { if (value) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
inline std::wstring quote(const std::wstring& value) {
    std::wstring result = L"\"";
    size_t slashes{};
    for (const wchar_t c : value) {
        if (c == L'\\') { ++slashes; continue; }
        result.append(slashes * (c == L'"' ? 2 : 1), L'\\');
        if (c == L'"') result += L'\\';
        result += c; slashes = 0;
    }
    result.append(slashes * 2, L'\\');
    return result + L'"';
}
inline std::wstring wide(const std::string& text) {
    if (text.empty()) return {};
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!count) throw std::runtime_error("Invalid UTF-8 in tray data");
    std::wstring result(count, 0);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), count);
    return result;
}
inline std::string utf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!count) throw std::runtime_error("Invalid Unicode in tray data");
    std::string result(count, 0);
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), count, nullptr, nullptr);
    return result;
}
inline std::string readFile(const std::wstring& path, size_t limit = 4 * 1024 * 1024) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.value) throw std::runtime_error("Cannot read tray input");
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file.value, &length) || length.QuadPart < 0 ||
        static_cast<ULONGLONG>(length.QuadPart) > limit) throw std::runtime_error("Tray input exceeds its limit");
    std::string result(static_cast<size_t>(length.QuadPart), 0);
    DWORD received{};
    if (!result.empty() && (!ReadFile(file.value, result.data(), static_cast<DWORD>(result.size()), &received, nullptr) ||
        received != result.size())) throw std::runtime_error("Cannot finish reading tray input");
    return result;
}
inline std::vector<std::wstring> applications(const std::string& bytes) {
    std::wstring text = wide(bytes);
    if (!text.empty() && text.front() == 0xfeff) text.erase(0, 1);
    std::vector<std::wstring> result;
    size_t start{};
    while (start < text.size()) {
        const size_t end = text.find(L'\n', start);
        std::wstring line = text.substr(start, end == std::wstring::npos ? end : end - start);
        const auto first = line.find_first_not_of(L" \t\r");
        const auto last = line.find_last_not_of(L" \t\r");
        if (first != std::wstring::npos && line[first] != L'#') result.push_back(line.substr(first, last - first + 1));
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    if (result.size() > 60000) throw std::runtime_error("Too many applications for the tray menu");
    return result;
}
inline bool exists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}
inline std::wstring status(const std::wstring& root) {
    if (exists(root + L"\\state\\active")) return L"Enabled";
    if (exists(root + L"\\state\\enabled")) return L"Starting / recovering";
    return L"Disabled";
}
inline std::wstring menuText(std::wstring text) {
    size_t at{};
    while ((at = text.find(L'&', at)) != std::wstring::npos) { text.insert(at, 1, L'&'); at += 2; }
    return text;
}
inline std::wstring base64(const std::wstring& command) {
    const auto* bytes = reinterpret_cast<const BYTE*>(command.data());
    const DWORD size = static_cast<DWORD>(command.size() * sizeof(wchar_t));
    DWORD count{};
    if (!CryptBinaryToStringW(bytes, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &count))
        throw std::runtime_error("Cannot encode tray action");
    std::wstring result(count, 0);
    if (!CryptBinaryToStringW(bytes, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, result.data(), &count))
        throw std::runtime_error("Cannot encode tray action");
    while (!result.empty() && result.back() == 0) result.pop_back();
    return result;
}
inline std::string unbase64(const std::string& text) {
    if (text.empty()) return {};
    DWORD count{};
    if (!CryptStringToBinaryA(text.data(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64,
                             nullptr, &count, nullptr, nullptr)) throw std::runtime_error("Invalid action result");
    std::string result(count, 0);
    if (!CryptStringToBinaryA(text.data(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64,
                             reinterpret_cast<BYTE*>(result.data()), &count, nullptr, nullptr))
        throw std::runtime_error("Invalid action result");
    result.resize(count);
    return result;
}
struct Result { bool ok{}; std::wstring message; };
inline Result resultFrame(const std::string& frame) {
    std::map<std::string, std::string> fields;
    size_t start{};
    bool header{};
    while (start < frame.size()) {
        const size_t end = frame.find('\n', start);
        std::string line = frame.substr(start, end == std::string::npos ? end : end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!header) {
            if (line != "WGPS-RUN 1") throw std::runtime_error("Invalid action result header");
            header = true;
        } else if (!line.empty()) {
            const size_t equals = line.find('=');
            if (equals == std::string::npos || !fields.emplace(line.substr(0, equals), line.substr(equals + 1)).second)
                throw std::runtime_error("Invalid action result fields");
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (const auto error = fields.find("error"); error != fields.end()) return {false, wide(error->second)};
    for (const auto* key : {"exit", "timedout", "stdout-truncated", "stderr-truncated", "stdout", "stderr"})
        if (!fields.contains(key)) throw std::runtime_error("Incomplete action result");
    if (fields["timedout"] != "0") return {false, L"The operation exceeded its deadline."};
    if (fields["stdout-truncated"] != "0" || fields["stderr-truncated"] != "0")
        return {false, L"The operation produced too much output."};
    int code{};
    const auto& exit = fields["exit"];
    const auto parsed = std::from_chars(exit.data(), exit.data() + exit.size(), code);
    if (parsed.ec != std::errc() || parsed.ptr != exit.data() + exit.size()) throw std::runtime_error("Invalid action exit code");
    std::wstring message = wide(unbase64(fields[code ? "stderr" : "stdout"]));
    if (message.empty()) message = wide(unbase64(fields[code ? "stdout" : "stderr"]));
    return {code == 0, message.empty() ? (code ? L"The operation failed." : L"The operation completed.") : message};
}
// Only one operation runs at a time. Its bounded runner owns the PowerShell
// process tree. The UI thread performs no waits or pipe reads.
class Action {
    struct State {
        Handle done{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        std::atomic_bool stop{};
        std::mutex mutex;
        Result result;
    };
    std::shared_ptr<State> state_;
    std::thread thread_;
    static Result run(const std::wstring& root, const std::wstring& child, DWORD timeout,
                      const std::shared_ptr<State>& state) {
        const std::wstring runner = root + L"\\bin\\controller-service.exe";
        std::wstring command = quote(runner) + L" --run " + std::to_wstring(timeout) + L" " + base64(child);
        SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
        HANDLE read{}, write{};
        if (!CreatePipe(&read, &write, &security, 0)) throw std::runtime_error("Cannot create action pipe");
        Handle output(read), writer(write);
        if (!SetHandleInformation(output.value, HANDLE_FLAG_INHERIT, 0)) throw std::runtime_error("Cannot protect action pipe");
        Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr));
        Handle error(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr));
        if (!input.value || !error.value) throw std::runtime_error("Cannot create action streams");
        PROCESS_INFORMATION childProcess{};
        if (!wgps::createWithInheritedHandles(runner.c_str(), command.data(), root.c_str(), CREATE_NO_WINDOW,
            {input.value, writer.value, error.value}, input.value, writer.value, error.value, childProcess))
            throw std::runtime_error("Cannot start bounded tray action");
        Handle process(childProcess.hProcess), thread(childProcess.hThread);
        CloseHandle(writer.value); writer.value = nullptr;
        const ULONGLONG deadline = GetTickCount64() + timeout + 5000;
        std::string frame;
        bool overflow{};
        try {
            for (;;) {
                if (state->stop || GetTickCount64() >= deadline) throw std::runtime_error("Tray action cancelled or timed out");
                DWORD available{};
                if (PeekNamedPipe(output.value, nullptr, 0, nullptr, &available, nullptr) && available) {
                    char buffer[4096]; DWORD received{};
                    if (!ReadFile(output.value, buffer, std::min<DWORD>(available, sizeof(buffer)), &received, nullptr))
                        throw std::runtime_error("Cannot read action result");
                    if (frame.size() + received <= 256 * 1024) frame.append(buffer, received);
                    else overflow = true;
                    continue;
                }
                if (WaitForSingleObject(process.value, 20) == WAIT_OBJECT_0) {
                    if (PeekNamedPipe(output.value, nullptr, 0, nullptr, &available, nullptr) && available) continue;
                    break;
                }
            }
        } catch (...) {
            TerminateProcess(process.value, 1); // Closing this runner ends its job's descendants.
            WaitForSingleObject(process.value, 5000);
            throw;
        }
        if (overflow) throw std::runtime_error("Tray action result exceeds its limit");
        return resultFrame(frame);
    }
    static Result execute(const std::wstring& root, std::wstring action,
                          std::wstring value, const std::shared_ptr<State>& state) {
        if (action == L"PickAdd" || action == L"PickImport") {
            const auto selected = run(root, quote(root + L"\\bin\\tray.exe") +
                (action == L"PickAdd" ? L" --pick-app" : L" --pick-profile"), 600000, state);
            if (!selected.ok) return selected;
            if (selected.message == L"CANCEL") return {true, {}};
            if (!selected.message.starts_with(L"SELECT:") || selected.message.size() <= 7)
                throw std::runtime_error("Invalid file-picker result");
            value = selected.message.substr(7);
            action = action == L"PickAdd" ? L"Add" : L"Import";
        }
        wchar_t system[MAX_PATH]{};
        if (!GetSystemDirectoryW(system, MAX_PATH)) throw std::runtime_error("Cannot find Windows PowerShell");
        const std::wstring ps = std::wstring(system) + L"\\WindowsPowerShell\\v1.0\\powershell.exe";
        std::wstring child = quote(ps) + L" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " +
            quote(root + L"\\src\\TrayActions.ps1") + L" -Action " + quote(action);
        if (!value.empty()) child += L" -InputPath " + quote(value);
        return run(root, child, action == L"Import" ? 180000 : 30000, state);
    }

public:
    ~Action() {
        if (!thread_.joinable()) return;
        state_->stop = true;
        if (WaitForSingleObject(state_->done.value, 6000) == WAIT_OBJECT_0) thread_.join();
        else thread_.detach(); // Shared state, never a borrowed UI pointer.
    }
    bool busy() const { return state_ && WaitForSingleObject(state_->done.value, 0) != WAIT_OBJECT_0; }
    HANDLE event() const { return state_ ? state_->done.value : nullptr; }
    void start(std::wstring root, std::wstring action, std::wstring value) {
        if (busy()) throw std::runtime_error("Another tray operation is still running");
        if (thread_.joinable()) thread_.join();
        auto state = std::make_shared<State>();
        if (!state->done.value) throw std::runtime_error("Cannot create action completion event");
        std::thread worker([state, root = std::move(root), action = std::move(action), value = std::move(value)] {
            Result result{false, L"The operation failed."};
            try { result = execute(root, action, value, state); }
            catch (const std::exception& e) {
                try { result = {false, wide(e.what())}; }
                catch (...) { result.ok = false; }
            }
            catch (...) { result = {false, L"The operation failed."}; }
            { std::lock_guard lock(state->mutex); state->result = std::move(result); }
            SetEvent(state->done.value);
        });
        state_ = std::move(state);
        thread_ = std::move(worker);
    }
    Result take() {
        if (!state_ || busy()) return {};
        if (thread_.joinable()) thread_.join();
        Result result;
        { std::lock_guard lock(state_->mutex); result = state_->result; }
        state_.reset();
        return result;
    }
};
} // namespace wgps::tray
