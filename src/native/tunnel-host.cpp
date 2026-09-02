#define _WIN32_WINNT 0x0A00
#include <windows.h>

#include <filesystem>
#include <iostream>
#include <cstring>
#include <string>

using TunnelService = BOOL(__cdecl*)(LPCWSTR);

int wmain(int argc, wchar_t** argv) {
    if (argc != 3 || std::wstring(argv[1]) != L"/service") {
        std::wcerr << L"This helper is launched by the WireGuard Program Split tunnel service.\n";
        return 2;
    }

    wchar_t executable[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, executable, MAX_PATH)) return 3;
    const auto directory = std::filesystem::path(executable).parent_path();
    if (!SetDllDirectoryW(directory.c_str())) return 4;

    HMODULE tunnel = LoadLibraryW((directory / L"tunnel.dll").c_str());
    if (!tunnel) return 5;
    FARPROC procedure = GetProcAddress(tunnel, "WireGuardTunnelService");
    if (!procedure) return 6;
    TunnelService run{};
    static_assert(sizeof(run) == sizeof(procedure));
    std::memcpy(&run, &procedure, sizeof(run));
    return run(argv[2]) ? 0 : 7;
}
