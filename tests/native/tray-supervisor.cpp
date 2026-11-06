// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../src/native/tray-supervisor.h"
#include <cwchar>
#include <fstream>
#include <iostream>
int wmain(int argc, wchar_t** argv) {
    using namespace wgps::tray;
    if (argc == 4 && std::wcscmp(argv[1], L"--child") == 0) {
        const std::filesystem::path marker(argv[3]);
        unsigned count{}; { std::ifstream input(marker); input >> count; }
        { std::ofstream output(marker); output << count + 1; }
        if (!count) {
            SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
            if (std::wcscmp(argv[2], L"access") == 0)
                RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, nullptr);
            if (std::wcscmp(argv[2], L"fastfail") == 0) RaiseFailFastException(nullptr, nullptr, 0);
            if (std::wcscmp(argv[2], L"one") == 0) return 1;
            if (std::wcscmp(argv[2], L"minus-one") == 0) return -1;
        }
        if (count && std::wcscmp(argv[2], L"always") != 0) return 0;
        return std::wcscmp(argv[2], L"clean") == 0 ||
            (std::wcscmp(argv[2], L"once") == 0 && count) ? 0 : 7;
    }
    if (argc != 2) return 2;
    try {
        TrayRestartBudget budget;
        if (budget.failed(0) != 2000 || budget.failed(0) != 4000 || budget.failed(599999) != 8000 ||
            budget.failed(0) || budget.failed(600000) != 2000)
            throw std::runtime_error("awake-time retry budget reset");
        wchar_t image[32768]{};
        if (!GetModuleFileNameW(nullptr, image, 32768)) throw std::runtime_error("test image");
        const std::wstring root = argv[1];
        std::vector<const wchar_t*> modes{L"clean", L"once", L"always", L"one", L"minus-one"};
        if (GetEnvironmentVariableW(L"CI", nullptr, 0)) { modes.push_back(L"access"); modes.push_back(L"fastfail"); }
        for (const auto* mode : modes) {
            const auto marker = root + L"\\supervisor-" + mode + L".txt";
            DeleteFileW(marker.c_str());
            std::wstring arguments = L"--child "; arguments += mode;
            arguments += L" "; arguments += quote(marker);
            const DWORD code = supervise(image, arguments, root, 10);
            unsigned count{}; { std::ifstream input{std::filesystem::path(marker)}; input >> count; }
            const unsigned expected = std::wcscmp(mode, L"clean") == 0 ? 1 : std::wcscmp(mode, L"always") == 0 ? 4 : 2;
            if (count != expected || (code == 0) != (expected != 4))
                throw std::runtime_error("supervisor retry/clean-exit contract");
        }
        if (supervise(root + L"\\absent-supervisor-child.exe", L"", root, 1) != ERROR_FILE_NOT_FOUND)
            throw std::runtime_error("bounded launch-failure retries");
        std::cout << "PASS: native supervisor respects clean exit, recovers a crash and bounds repeated failures.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
