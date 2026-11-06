// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../src/native/tray-support.h"
#include <iostream>
namespace wgps::tray {
struct ActionTest {
    static Result run(const std::wstring& root, bool mutating) {
        auto state = std::make_shared<Action::State>();
        state->finishMutation = mutating;
        return Action::run(root, L"ignored", 1, state, false, 2000);
    }
};
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    using namespace wgps::tray;
    try {
        const std::wstring root = argv[1];
        const auto marker = root + L"\\runner-pid.txt";
        for (const bool mutation : {false, true}) {
            DeleteFileW(marker.c_str());
            bool threw{}; Result result;
            try { result = ActionTest::run(root, mutation); } catch (...) { threw = true; }
            const auto until = GetTickCount64() + 5000;
            while (!exists(marker) && GetTickCount64() < until) Sleep(10);
            const DWORD pid = static_cast<DWORD>(std::stoul(readFile(marker)));
            struct Child {
                Handle process;
                Child(DWORD id, const std::wstring& expected) : process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, FALSE, id)) {
                    if (!process.value) return;
                    if (WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0) return;
                    wchar_t path[32768]{}; DWORD size = 32768;
                    if (!QueryFullProcessImageNameW(process.value, 0, path, &size)) {
                        if (WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0) return;
                        throw std::runtime_error("runner image unavailable");
                    }
                    if (_wcsicmp(path, expected.c_str()) != 0)
                        throw std::runtime_error("runner identity changed");
                }
                ~Child() {
                    if (process.value && WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT) {
                        TerminateProcess(process.value, 1); WaitForSingleObject(process.value, 5000);
                    }
                }
            } child(pid, root + L"\\bin\\controller-service.exe");
            const bool running = child.process.value && WaitForSingleObject(child.process.value, 0) == WAIT_TIMEOUT;
            if ((!mutation && (!threw || running)) ||
                (mutation && (threw || result.ok || !running || result.message.find(L"still be finishing") == std::wstring::npos)))
                throw std::runtime_error("backstop containment contract");
        }
        std::cout << "PASS: expired backstops cancel reads but do not kill an in-flight mutation.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
