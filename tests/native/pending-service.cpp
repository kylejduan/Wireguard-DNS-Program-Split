// SPDX-License-Identifier: GPL-3.0-or-later
// Throwaway service for tests/Test-TunnelRecoveryLive.ps1. Mode "start" reports START_PENDING and never
// finishes starting; mode "stop" runs normally and then hangs in STOP_PENDING when asked to stop. Either
// way the process ends by itself after five minutes so an interrupted test cannot leave it behind.
#define _WIN32_WINNT 0x0A00
#include <windows.h>

#include <string>

namespace {

SERVICE_STATUS_HANDLE gStatusHandle{};
std::wstring gMode;
DWORD gCheckPoint{};

void report(DWORD state, DWORD accepted) {
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = accepted;
    status.dwWaitHint = 600000;
    status.dwCheckPoint = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? ++gCheckPoint : 0;
    SetServiceStatus(gStatusHandle, &status);
}

DWORD WINAPI controlHandler(DWORD control, DWORD, void*, void*) {
    if (control == SERVICE_CONTROL_INTERROGATE) return NO_ERROR;
    if (control == SERVICE_CONTROL_STOP && gMode == L"stop") {
        report(SERVICE_STOP_PENDING, 0);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI serviceMain(DWORD, wchar_t**) {
    gStatusHandle = RegisterServiceCtrlHandlerExW(L"", controlHandler, nullptr);
    if (!gStatusHandle) return;
    report(SERVICE_START_PENDING, 0);
    if (gMode == L"stop") report(SERVICE_RUNNING, SERVICE_ACCEPT_STOP);
    Sleep(300000);
    report(SERVICE_STOPPED, 0);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    gMode = argv[1];
    wchar_t name[] = L"";
    SERVICE_TABLE_ENTRYW services[] = {{name, serviceMain}, {nullptr, nullptr}};
    return StartServiceCtrlDispatcherW(services) ? 0 : 3;
}
