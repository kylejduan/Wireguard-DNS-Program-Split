// SPDX-License-Identifier: GPL-3.0-or-later
// Disposable Windows CI helper: holds the PIA callout keys in a dynamic WFP session, as the filter host of
// releases before persistent filters did, until it is killed or two minutes pass. Prints READY when held.
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#include <rpcdce.h>

#include <iostream>

namespace {

constexpr GUID kLayerBindV4{0x66978cad, 0xc704, 0x42ac, {0x86, 0xac, 0x7c, 0x1a, 0x23, 0x1b, 0xd2, 0x53}};
constexpr GUID kLayerConnectV4{0xc6e63c8c, 0xb784, 0x4562, {0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3}};
constexpr GUID kCalloutBind{0xb16b0a6e, 0x2b2a, 0x41a3, {0x8b, 0x39, 0xbd, 0x3f, 0xfc, 0x85, 0x5f, 0xf8}};
constexpr GUID kCalloutConnect{0xb80ca14a, 0xa807, 0x4ef2, {0x87, 0x2d, 0x4b, 0x1a, 0x51, 0x82, 0x54, 0x02}};

int fail(const char* step, DWORD status) {
    std::cerr << "ERROR: " << step << " failed with " << status << std::endl;
    return 1;
}

}  // namespace

int main() {
    FWPM_SESSION0 session{};
    session.flags = 1;  // FWPM_SESSION_FLAG_DYNAMIC: everything below ends with this process.
    HANDLE engine{};
    DWORD status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &engine);
    if (status) return fail("FwpmEngineOpen0", status);
    GUID provider{};
    if (CoCreateGuid(&provider) != S_OK) return fail("CoCreateGuid", 0);
    FWPM_PROVIDER0 providerObject{};
    providerObject.providerKey = provider;
    providerObject.displayData.name = const_cast<wchar_t*>(L"WireGuard Program Split CI legacy host");
    status = FwpmProviderAdd0(engine, &providerObject, nullptr);
    if (status) return fail("FwpmProviderAdd0", status);
    const GUID* keys[] = {&kCalloutBind, &kCalloutConnect};
    const GUID* layers[] = {&kLayerBindV4, &kLayerConnectV4};
    for (int i = 0; i < 2; ++i) {
        FWPM_CALLOUT0 callout{};
        callout.calloutKey = *keys[i];
        callout.displayData.name = const_cast<wchar_t*>(L"CI legacy callout");
        callout.providerKey = &provider;
        callout.applicableLayer = *layers[i];
        status = FwpmCalloutAdd0(engine, &callout, nullptr, nullptr);
        if (status) return fail("FwpmCalloutAdd0", status);
    }
    std::cout << "READY" << std::endl;
    Sleep(120000);
    FwpmEngineClose0(engine);
    return 0;
}
