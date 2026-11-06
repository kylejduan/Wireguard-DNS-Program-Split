// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../src/native/tray-support.h"
#include <iostream>
int wmain(int argc, wchar_t** argv) {
    if (argc < 3 || argc > 4) return 2;
    try {
        wgps::tray::Action action;
        action.start(argv[1], std::wstring(argv[2]) == L"Cancel" ? L"Status" : (std::wstring(argv[2]) == L"Finish" ? L"Add" : argv[2]), argc == 4 ? argv[3] : L"");
        if (std::wstring(argv[2]) == L"Cancel" || std::wstring(argv[2]) == L"Finish") {
            const auto deadline = GetTickCount64() + 10000;
            while (!wgps::tray::exists(std::wstring(argv[1]) + L"\\child-pid.txt") && action.busy() && GetTickCount64() < deadline)
                Sleep(50);
            return wgps::tray::exists(std::wstring(argv[1]) + L"\\child-pid.txt") ? 0 : 5;
        }
        if (WaitForSingleObject(action.event(), 135000) != WAIT_OBJECT_0) return 3;
        return action.take().ok ? 0 : 1;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 4; }
}
