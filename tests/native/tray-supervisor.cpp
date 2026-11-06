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
        return std::wcscmp(argv[2], L"clean") == 0 ||
            (std::wcscmp(argv[2], L"once") == 0 && count) ? 0 : 7;
    }
    if (argc != 2) return 2;
    try {
        wchar_t image[32768]{};
        if (!GetModuleFileNameW(nullptr, image, 32768)) throw std::runtime_error("test image");
        const std::wstring root = argv[1];
        for (const auto* mode : {L"clean", L"once", L"always"}) {
            const auto marker = root + L"\\supervisor-" + mode + L".txt";
            DeleteFileW(marker.c_str());
            std::wstring arguments = L"--child "; arguments += mode;
            arguments += L" "; arguments += quote(marker);
            const DWORD code = supervise(image, arguments, root, 10);
            unsigned count{}; { std::ifstream input{std::filesystem::path(marker)}; input >> count; }
            const unsigned expected = std::wcscmp(mode, L"clean") == 0 ? 1 : std::wcscmp(mode, L"once") == 0 ? 2 : 4;
            if (count != expected || (code == 0) != (expected != 4))
                throw std::runtime_error("supervisor retry/clean-exit contract");
        }
        std::cout << "PASS: native supervisor respects clean exit, recovers a crash and bounds repeated failures.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
