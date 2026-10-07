// SPDX-License-Identifier: GPL-3.0-or-later
// Private native self-test; fixtures stay beside the tested executable in build/.
#include <fstream>

namespace wgps {
inline bool logSelfTest() {
    wchar_t executable[32768]{};
    if (!GetModuleFileNameW(nullptr, executable, 32768)) return false;
    const auto directory = std::filesystem::path(executable).parent_path() /
        (L"log-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    if (!std::filesystem::create_directory(directory)) return false;
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
    } cleanup{directory};
    const auto path = directory / L"test.log";
    {
        BoundedLog log(path, 512);
        for (unsigned i = 0; i < 100; ++i) {
            if (!log.write(std::string(127, 'x') + '\n')) return false;
        }
        for (const auto& file : std::filesystem::directory_iterator(directory)) {
            if (file.file_size() > 512) return false;
        }
        if (std::distance(std::filesystem::directory_iterator(directory), std::filesystem::directory_iterator{}) != 4) return false;
        // A reader refusing delete sharing prevents rotation: refuse the next append, stay capped.
        HANDLE reader = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (reader == INVALID_HANDLE_VALUE) return false;
        const bool refused = !log.write(std::string(512, 'y'));
        CloseHandle(reader);
        if (!refused || std::filesystem::file_size(path) > 512) return false;
        if (!log.write("recovered\n")) return false;
    }
    {
        BoundedLog log(directory / L"pipe.log", 512);
        LogPipe pipe(log);
        if (!pipe.writer()) return false;
        for (unsigned i = 0; i < 100; ++i) {
            DWORD written{};
            const std::string data(1024, 'p');
            if (!WriteFile(pipe.writer(), data.data(), static_cast<DWORD>(data.size()), &written, nullptr) ||
                written != data.size()) return false;
        }
        Sleep(150);
    }
    for (const auto& file : std::filesystem::directory_iterator(directory)) {
        if (file.file_size() > 512) return false;
    }
    return std::filesystem::exists(directory / L"pipe.log.3");
}
} // namespace wgps
