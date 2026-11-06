// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../src/native/tray-supervisor.h"
#include <fstream>
#include <iostream>
int wmain(int argc, wchar_t** argv) {
    using namespace wgps::tray;
    if (argc == 4 && std::wstring(argv[1]) == L"--child") {
        const std::filesystem::path marker(argv[3]);
        unsigned count{}; { std::ifstream input(marker); input >> count; }
        { std::ofstream output(marker); output << count + 1; }
        const std::wstring mode(argv[2]);
        return mode == L"clean" || (mode == L"once" && count) ? 0 : 7;
    }
    if (argc != 2) return 2;
    try {
        wchar_t image[32768]{};
        if (!GetModuleFileNameW(nullptr, image, 32768)) throw std::runtime_error("test image");
        const std::wstring root = argv[1];
        for (const auto* mode : {L"clean", L"once", L"always"}) {
            const auto marker = root + L"\\supervisor-" + mode + L".txt";
            DeleteFileW(marker.c_str());
            const DWORD code = supervise(image, L"--child " + std::wstring(mode) + L" " + quote(marker), root, 10);
            unsigned count{}; { std::ifstream input{std::filesystem::path(marker)}; input >> count; }
            const unsigned expected = std::wstring(mode) == L"clean" ? 1 : std::wstring(mode) == L"once" ? 2 : 4;
            if (count != expected || (code == 0) != (expected != 4))
                throw std::runtime_error("supervisor retry/clean-exit contract");
        }
        std::cout << "PASS: native supervisor respects clean exit, recovers a crash and bounds repeated failures.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
