// SPDX-License-Identifier: GPL-3.0-or-later
#include "tray-support.h"
#include <commdlg.h>
#include <cwchar>
#include <cstring>
#include <iostream>
#include <objbase.h>

namespace {
using namespace wgps::tray;
constexpr UINT callback = WM_APP + 1;
constexpr UINT toggle = 1, add = 2, importProfile = 3, logs = 4, lastError = 5, quit = 6, removeBase = 100;
const wchar_t* title = L"WireGuard Program Split";
struct ComScope {
    HRESULT status{CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)};
    ComScope() { if (FAILED(status)) throw std::runtime_error("Cannot initialize the Windows shell"); }
    ~ComScope() { CoUninitialize(); }
};
struct Menu {
    HMENU value{CreatePopupMenu()};
    ~Menu() { if (value) DestroyMenu(value); }
};
std::wstring selectFile(bool profile) {
    ComScope com;
    std::vector<wchar_t> path(32768);
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.lpstrFilter = profile ? L"WireGuard profiles (*.conf)\0*.conf\0\0" : L"Applications (*.exe)\0*.exe\0\0";
    dialog.lpstrFile = path.data(); dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_DONTADDTORECENT | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&dialog)) return path.data();
    if (CommDlgExtendedError()) throw std::runtime_error("The file dialog failed.");
    return {};
}
struct Tray {
    std::wstring root;
    HWND window{};
    NOTIFYICONDATAW icon{};
    Action action;
    UINT taskbarCreated{RegisterWindowMessageW(L"TaskbarCreated")};
    bool smoke{};
    bool version4{};

    void complete() {
        if (!action.event() || action.busy()) return;
        auto result = action.take();
        ShutdownBlockReasonDestroy(window);
        if (!result.message.empty()) notice(result.message, result.ok);
    }

    void notice(const std::wstring& message, bool ok) {
        wcsncpy_s(icon.szInfoTitle, title, _TRUNCATE);
        wcsncpy_s(icon.szInfo, message.c_str(), _TRUNCATE);
        icon.dwInfoFlags = ok ? NIIF_INFO : NIIF_ERROR;
        icon.uFlags = NIF_INFO | NIF_SHOWTIP;
        Shell_NotifyIconW(NIM_MODIFY, &icon);
    }
    void update(bool create = false) {
        const std::wstring text = std::wstring(title) + L" - " + status(root);
        if (create) {
            icon = {};
            icon.cbSize = sizeof(icon); icon.hWnd = window; icon.uID = 1;
            icon.uCallbackMessage = callback;
            icon.hIcon = LoadIconW(nullptr, IDI_SHIELD);
            icon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        } else {
            if (text == icon.szTip) return;
            icon.uFlags = NIF_TIP | NIF_SHOWTIP;
        }
        wcsncpy_s(icon.szTip, text.c_str(), _TRUNCATE);
        bool updated = Shell_NotifyIconW(create ? NIM_ADD : NIM_MODIFY, &icon);
        if (!updated && create) updated = Shell_NotifyIconW(NIM_MODIFY, &icon);
        if (!updated) {
            // Explorer may be starting. The next timer retries registration.
            icon.szTip[0] = 0;
            return;
        }
        if (create) {
            icon.uVersion = NOTIFYICON_VERSION_4;
            version4 = Shell_NotifyIconW(NIM_SETVERSION, &icon) != FALSE;
        }
    }
    void start(const std::wstring& name, const std::wstring& input = {}) {
        complete();
        try { action.start(root, name, input); }
        catch (const std::exception& e) { notice(wide(e.what()), false); }
    }
    void menu() {
        complete();
        Menu menu;
        if (!menu.value) return;
        const UINT enabled = action.busy() ? MF_GRAYED : MF_ENABLED;
        AppendMenuW(menu.value, MF_STRING | MF_GRAYED, 0, (L"Status: " + status(root)).c_str());
        AppendMenuW(menu.value, MF_STRING | enabled, toggle, exists(root + L"\\state\\enabled") ? L"Disable" : L"Enable");
        AppendMenuW(menu.value, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu.value, MF_STRING | enabled, add, L"Add application...");
        std::vector<std::wstring> apps;
        HMENU removal = CreatePopupMenu();
        try { apps = applications(readFile(root + L"\\state\\included-apps.txt")); }
        catch (...) { /* Other controls remain usable when the list is unavailable. */ }
        if (removal) {
            for (size_t i = 0; i < apps.size(); ++i)
                AppendMenuW(removal, MF_STRING | enabled, removeBase + i, menuText(apps[i]).c_str());
            AppendMenuW(menu.value, MF_POPUP | (apps.empty() ? MF_GRAYED : enabled),
                        reinterpret_cast<UINT_PTR>(removal), L"Remove application");
        }
        AppendMenuW(menu.value, MF_STRING | enabled, importProfile, L"Import WireGuard profile...");
        AppendMenuW(menu.value, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu.value, MF_STRING, logs, L"Open logs");
        AppendMenuW(menu.value, MF_STRING, lastError, L"Show last error");
        AppendMenuW(menu.value, MF_STRING | enabled, quit, L"Exit tray (VPN stays as set)");
        POINT point{}; GetCursorPos(&point); SetForegroundWindow(window);
        const UINT command = TrackPopupMenu(menu.value, TPM_RETURNCMD | TPM_RIGHTBUTTON,
                                            point.x, point.y, 0, window, nullptr);
        PostMessageW(window, WM_NULL, 0, 0);
        Shell_NotifyIconW(NIM_SETFOCUS, &icon);
        if (command >= removeBase && command - removeBase < apps.size() && !action.busy()) {
            start(L"Remove", apps[command - removeBase]); return;
        }
        switch (command) {
        case toggle: if (!action.busy()) start(L"Toggle"); break;
        case add: case importProfile:
            if (!action.busy()) start(command == add ? L"PickAdd" : L"PickImport");
            break;
        case logs:
        {
            ComScope com;
            if (reinterpret_cast<INT_PTR>(ShellExecuteW(window, L"open", (root + L"\\logs").c_str(), nullptr, nullptr, SW_SHOWNORMAL)) <= 32)
                notice(L"Could not open the logs directory.", false);
            break;
        }
        case lastError:
            try { MessageBoxW(window, displayWide(readFile(root + L"\\state\\last-error.txt", 65536)).c_str(), title, MB_OK | MB_ICONINFORMATION); }
            catch (...) { notice(L"No readable error has been recorded.", true); }
            break;
        case quit: if (!action.busy()) DestroyWindow(window); break;
        }
    }
    LRESULT message(UINT message, WPARAM wparam, LPARAM lparam) {
        if (message == taskbarCreated && taskbarCreated) { update(true); return 0; }
        switch (message) {
        case WM_CREATE:
            if (taskbarCreated && !ChangeWindowMessageFilterEx(window, taskbarCreated, MSGFLT_ALLOW, nullptr)) return -1;
            update(true);
            if (!SetTimer(window, 1, smoke ? 100 : 2000, nullptr)) return -1;
            return 0;
        case WM_TIMER:
            if (smoke) { DestroyWindow(window); return 0; }
            update(icon.szTip[0] == 0);
            complete();
            return 0;
        case callback:
            if ((version4 && (LOWORD(lparam) == WM_CONTEXTMENU || LOWORD(lparam) == NIN_KEYSELECT)) ||
                (!version4 && LOWORD(lparam) == WM_RBUTTONUP)) menu();
            else if (LOWORD(lparam) == WM_LBUTTONDBLCLK && !action.busy()) start(L"Toggle");
            return 0;
        case WM_CLOSE: if (!action.busy()) DestroyWindow(window); return 0;
        case WM_QUERYENDSESSION:
            if (action.mutating()) {
                ShutdownBlockReasonCreate(window, L"Finishing a WireGuard profile or application change.");
                return FALSE;
            }
            return TRUE;
        case WM_ENDSESSION:
            if (wparam) DestroyWindow(window);
            else ShutdownBlockReasonDestroy(window);
            return 0;
        case WM_DESTROY:
            KillTimer(window, 1); Shell_NotifyIconW(NIM_DELETE, &icon); PostQuitMessage(0); return 0;
        }
        return DefWindowProcW(window, message, wparam, lparam);
    }
};
LRESULT CALLBACK windowProcedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* tray = reinterpret_cast<Tray*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        tray = static_cast<Tray*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
        tray->window = window; SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(tray));
    }
    if (!tray) return DefWindowProcW(window, message, wparam, lparam);
    try { return tray->message(message, wparam, lparam); }
    catch (...) {
        if (message == WM_CREATE) return -1;
        tray->notice(L"The tray operation failed.", false); return 0;
    }
}
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
int selfTest() {
    require(quote(L"") == L"\"\"", "Empty argument");
    require(quote(L"C:\\A B\\") == L"\"C:\\A B\\\\\"", "Trailing slash");
    require(quote(L"a\"b") == L"\"a\\\"b\"", "Embedded quote");
    const auto apps = applications("\xef\xbb\xbf# comment\r\n C:\\Jos\xc3\xa9\\App.exe \r\n\nD:\\App.exe\n");
    require(apps.size() == 2 && apps[0] == L"C:\\Jos\u00e9\\App.exe", "UTF-8 include list");
    require(utf8(apps[0]) == "C:\\Jos\xc3\xa9\\App.exe", "Unicode output");
    require(menuText(L"A&B") == L"A&&B", "Menu escaping");
    require(resultFrame("WGPS-RUN 1\nexit=0\ntimedout=0\nstdout-truncated=0\nstderr-truncated=0\nstdout=T0s=\nstderr=\n").message == L"OK", "Runner output");
    require(!resultFrame("WGPS-RUN 1\nexit=0\ntimedout=1\nstdout-truncated=0\nstderr-truncated=0\nstdout=\nstderr=\n").ok, "Runner deadline");
    require(resultFrame("WGPS-RUN 1\nexit=0\ntimedout=0\nstdout-truncated=0\nstderr-truncated=0\nstdout=/w==\nstderr=\n").ok, "Display decoding preserves success");
    require(!resultFrame("WGPS-RUN 1\nexit=3762504530\ntimedout=0\nstdout-truncated=0\nstderr-truncated=0\nstdout=\nstderr=\n").ok, "Unsigned Windows crash code");
    bool rejected{};
    try { (void)resultFrame("WGPS-RUN 1\nexit=0\nexit=1\n"); } catch (...) { rejected = true; }
    require(rejected, "Duplicate frame");
    rejected = false;
    try { (void)applications("\xff"); } catch (...) { rejected = true; }
    require(rejected, "Invalid UTF-8");
    return 0;
}
}
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    int argc{};
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 2;
    const std::wstring command = argc == 2 ? argv[1] : L"";
    LocalFree(argv);
    if (argc > 2) return 2;
    try {
        if (command == L"--self-test") return selfTest();
        if (command == L"--pick-app" || command == L"--pick-profile") {
            const auto selected = selectFile(command == L"--pick-profile");
            const auto reply = selected.empty() ? std::string("CANCEL") : "SELECT:" + utf8(selected);
            DWORD written{};
            if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), reply.data(), static_cast<DWORD>(reply.size()), &written, nullptr) || written != reply.size()) return 1;
            return 0;
        }
        const bool smoke = command == L"--smoke-test";
        if (!command.empty() && !smoke) return 2;
        std::vector<wchar_t> module(32768);
        const DWORD length = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
        if (!length || length >= module.size()) throw std::runtime_error("Cannot locate tray installation");
        const std::wstring root = std::filesystem::path(module.data()).parent_path().parent_path().wstring();
        if (!smoke) {
            for (const auto* path : {L"\\src\\TrayActions.ps1", L"\\state\\included-apps.txt", L"\\state\\installation.json"})
                if (!exists(root + path)) throw std::runtime_error("Missing tray installation input");
        }
        Handle mutex(CreateMutexW(nullptr, FALSE, smoke ? nullptr : L"Global\\WireGuardProgramSplitTray"));
        if (!mutex.value) throw std::runtime_error("Cannot open tray instance mutex");
        const DWORD held = WaitForSingleObject(mutex.value, 0);
        if (held == WAIT_TIMEOUT) return 0;
        if (held != WAIT_OBJECT_0 && held != WAIT_ABANDONED) throw std::runtime_error("Cannot acquire tray instance mutex");
        Tray tray; tray.root = root; tray.smoke = smoke;
        if (!tray.taskbarCreated) throw std::runtime_error("Cannot register shell recovery message");
        WNDCLASSW cls{}; cls.lpfnWndProc = windowProcedure; cls.hInstance = instance;
        cls.lpszClassName = L"WireGuardProgramSplitTray";
        if (!RegisterClassW(&cls)) throw std::runtime_error("Cannot register tray window");
        // A hidden top-level window receives Explorer's TaskbarCreated broadcast.
        if (!CreateWindowExW(0, cls.lpszClassName, title, WS_OVERLAPPED, 0, 0, 0, 0, nullptr, nullptr, instance, &tray))
            throw std::runtime_error("Cannot create tray window");
        MSG message{}; int result{};
        while ((result = GetMessageW(&message, nullptr, 0, 0)) > 0) { TranslateMessage(&message); DispatchMessageW(&message); }
        ReleaseMutex(mutex.value);
        return result < 0 ? 1 : 0;
    } catch (const std::exception& e) {
        DWORD written{};
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), e.what(), static_cast<DWORD>(std::strlen(e.what())), &written, nullptr);
        if (command != L"--self-test" && command != L"--smoke-test" && command != L"--pick-app" && command != L"--pick-profile")
            MessageBoxA(nullptr, e.what(), "WireGuard Program Split", MB_OK | MB_ICONERROR);
        return 1;
    }
}
