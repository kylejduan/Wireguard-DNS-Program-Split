// SPDX-License-Identifier: GPL-3.0-or-later
#include <windows.h>
int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && wcscmp(argv[1], L"--hold") == 0) {
        HANDLE mutex = CreateMutexW(nullptr, TRUE, argv[2]);
        HANDLE ready = CreateFileW(argv[3], GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
        if (!mutex || ready == INVALID_HANDLE_VALUE) return 3;
        CloseHandle(ready);
        Sleep(300000);
        ReleaseMutex(mutex); CloseHandle(mutex);
        return 0;
    }
    if (argc == 2 && wcscmp(argv[1], L"--run") == 0) { Sleep(300000); return 0; }
    if (argc != 1) return 2;
    Sleep(300000);
    return 0;
}
