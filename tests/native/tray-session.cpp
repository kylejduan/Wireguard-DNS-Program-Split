// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise the real window procedure without asking Windows to end a session.
#define wWinMain trayApplicationEntry
#include "../../src/native/tray.cpp"
#undef wWinMain
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    const HDESK original = GetThreadDesktop(GetCurrentThreadId());
    const auto name = L"WgpsSessionTest-" + std::to_wstring(GetCurrentProcessId());
    HDESK desktop = CreateDesktopW(name.c_str(), nullptr, nullptr, 0, GENERIC_ALL, nullptr);
    if (!desktop || !SetThreadDesktop(desktop)) return 3;
    int result{};
    try {
        Tray tray; tray.root = argv[1];
        WNDCLASSW cls{}; cls.lpfnWndProc = windowProcedure; cls.hInstance = GetModuleHandleW(nullptr);
        cls.lpszClassName = L"WgpsSessionTest";
        require(RegisterClassW(&cls) != 0, "session class");
        HWND window = CreateWindowExW(0, cls.lpszClassName, L"test", 0, 0, 0, 0, 0, nullptr, nullptr, cls.hInstance, &tray);
        require(window != nullptr, "session window");
        struct WindowGuard { HWND window; ~WindowGuard() { DestroyWindow(window); } } guard{window};
        tray.action.start(tray.root, L"Add", L"");
        const auto deadline = GetTickCount64() + 5000;
        while (!tray.action.mutating() && tray.action.busy() && GetTickCount64() < deadline) Sleep(10);
        require(tray.action.mutating(), "mutation started");
        require(SendMessageW(window, WM_QUERYENDSESSION, 0, 0) == FALSE, "mutation blocks session end");
        wchar_t reason[256]{}; DWORD length = 256;
        require(ShutdownBlockReasonQuery(window, reason, &length) && reason[0], "shutdown reason");
        require(WaitForSingleObject(tray.action.event(), 10000) == WAIT_OBJECT_0, "mutation completed");
        require(wgps::tray::exists(tray.root + L"\\finished.txt"), "mutation reached its completion marker");
        tray.complete();
        require(SendMessageW(window, WM_QUERYENDSESSION, 0, 0) == TRUE, "completed action permits session end");
        std::cout << "PASS: session end waits for mutation and is released on completion.\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; result = 1; }
    SetThreadDesktop(original); CloseDesktop(desktop);
    return result;
}
