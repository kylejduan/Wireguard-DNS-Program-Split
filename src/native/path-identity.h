// SPDX-License-Identifier: GPL-3.0-or-later
// Executable identity shared by wfp-probe.exe and dns-dispatcher.exe: the final path a running image has.
#pragma once
#include <windows.h>

#include <string>
#include <vector>

namespace wgps {

// The final name of an existing file or directory, following junctions, symbolic links, substituted drives
// and short names. volumeFormat is VOLUME_NAME_DOS (C:\..., \\server\share\...) or VOLUME_NAME_NT
// (\Device\HarddiskVolume3\...). Empty when the path cannot be opened.
inline std::wstring finalPath(const std::wstring& path, DWORD volumeFormat) {
    HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    std::vector<wchar_t> buffer(32768);
    const DWORD size = GetFinalPathNameByHandleW(file, buffer.data(), static_cast<DWORD>(buffer.size()),
                                                 FILE_NAME_NORMALIZED | volumeFormat);
    CloseHandle(file);
    if (!size || size >= buffer.size()) return {};
    std::wstring result(buffer.data(), size);
    if (volumeFormat == VOLUME_NAME_DOS) {
        if (result.rfind(L"\\\\?\\UNC\\", 0) == 0) result.replace(0, 8, L"\\\\");
        else if (result.rfind(L"\\\\?\\", 0) == 0) result.erase(0, 4);
    }
    if (result.size() > 1 && result.back() == L'\\') result.pop_back();
    return result;
}

// The final path of a file that may be absent: the nearest existing ancestor's final path followed by the
// components that do not exist yet, so an alias through a junction names the same file before and after
// it appears. Resolution never climbs past something that exists: a link or junction whose target cannot
// be opened, an inaccessible component or an unavailable volume leaves the path unresolved (empty), and
// the caller keeps the identity it had instead of deriving one from the link's own spelling.
inline std::wstring resolvePath(const std::wstring& path, DWORD volumeFormat) {
    std::wstring existing = path;
    std::wstring remainder;
    while (!existing.empty()) {
        // A drive root opens only with its separator.
        const std::wstring candidate = existing.size() == 2 && existing[1] == L':' ? existing + L"\\" : existing;
        if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
            std::wstring resolved = finalPath(candidate, volumeFormat);
            return resolved.empty() ? std::wstring() : resolved + remainder;
        }
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return {};
        const size_t separator = existing.find_last_of(L'\\');
        if (separator == std::wstring::npos || separator == 0) return {};
        // Above \\server\share there is nothing more to open.
        if (existing.rfind(L"\\\\", 0) == 0 && existing.find(L'\\', 2) == separator) return {};
        remainder = existing.substr(separator) + remainder;
        existing.erase(separator);
    }
    return {};
}

}  // namespace wgps
