// SPDX-License-Identifier: GPL-3.0-or-later
// Private implementation fragment of wfp-probe.cpp.
int selfTest() {
    if (parseIpv4(L"192.0.2.2") != 0xc0000202) return 2;
    const auto included = parseIncludedText(L"C:\\Apps\\One.exe\r\n# comment\nC:\\Apps\\Two.exe\n");
    if (included.size() != 2 || !included.count(L"c:\\apps\\one.exe") ||
        !included.count(L"c:\\apps\\two.exe")) return 3;
    const ContextData context = contextFor(0xc0000201);
    std::vector<UINT8> contextBytes(reinterpret_cast<const UINT8*>(&context),
                                    reinterpret_cast<const UINT8*>(&context) + sizeof(context));
    if (contextBytes[0] != 0x01 || contextBytes[3] != 0xc0 || contextBytes[4] != 0 || contextBytes[8] != 0) return 4;
    if (!contextMatches(contextBytes, 0xc0000201) || contextMatches(contextBytes, 0xc0000202)) return 5;

    const wchar_t* installArguments[] = {L"wfp-probe.exe", L"install", L"apps.txt", L"192.0.2.1"};
    const wchar_t* verifyArguments[] = {L"wfp-probe.exe", L"verify", L"apps.txt", L"192.0.2.1"};
    const wchar_t* removeArguments[] = {L"wfp-probe.exe", L"remove"};
    const wchar_t* statusArguments[] = {L"wfp-probe.exe", L"status"};
    // The retired long-running form took the list and address without a mode.
    const wchar_t* legacyArguments[] = {L"wfp-probe.exe", L"apps.txt", L"192.0.2.1"};
    if (parseMode(4, installArguments) != Mode::Install || parseMode(4, verifyArguments) != Mode::Verify ||
        parseMode(2, removeArguments) != Mode::Remove || parseMode(2, statusArguments) != Mode::Status ||
        parseMode(3, legacyArguments) != Mode::Invalid || parseMode(3, installArguments) != Mode::Invalid ||
        parseMode(2, installArguments) != Mode::Invalid) return 6;

    // Every application gets IPv4 redirects through the PIA context and hard blocks that need no driver:
    // IPv4 off the tunnel address and all IPv6, each sparing loopback.
    UINT8 oneBytes[] = {'o', 0, 'n', 0, 'e', 0};
    UINT8 twoBytes[] = {'t', 0, 'w', 0, 'o', 0};
    FWP_BYTE_BLOB one{sizeof(oneBytes), oneBytes};
    FWP_BYTE_BLOB two{sizeof(twoBytes), twoBytes};
    wchar_t oneTagText[] = L"c:\\apps\\one.exe\tc:\\real\\one.exe";
    wchar_t twoTagText[] = L"c:\\apps\\two.exe\tc:\\real\\two.exe";
    FWP_BYTE_BLOB oneTag{static_cast<UINT32>(std::wcslen(oneTagText) * sizeof(wchar_t)), reinterpret_cast<UINT8*>(oneTagText)};
    FWP_BYTE_BLOB twoTag{static_cast<UINT32>(std::wcslen(twoTagText) * sizeof(wchar_t)), reinterpret_cast<UINT8*>(twoTagText)};
    const AppEntry oneEntry{&one, &oneTag};
    const AppEntry twoEntry{&two, &twoTag};
    const GUID contextKey{0x01234567, 0x89ab, 0xcdef, {1, 2, 3, 4, 5, 6, 7, 8}};
    constexpr UINT32 kTunnel = 0xc0000201;
    size_t redirects{};
    size_t ipv4Blocks{};
    size_t ipv6Blocks{};
    FilterDraft draft;
    for (const auto& rule : kRules) {
        draftFilter(draft, rule, oneEntry, contextKey, kTunnel);
        const FWPM_FILTER0& filter = draft.filter;
        if (filter.providerData.data != oneTag.data || filter.providerData.size != oneTag.size) return 35;
        if (!(filter.flags & kFilterPersistent) || !ownedBy(filter.providerKey) ||
            !sameGuid(filter.subLayerKey, kSublayer)) return 7;
        if (filter.filterCondition[0].conditionValue.byteBlob != &one ||
            !sameGuid(filter.filterCondition[0].fieldKey, kConditionAppId)) return 8;
        if (filter.action.type == FWP_ACTION_CALLOUT_TERMINATING) {
            if (!(filter.flags & kHasProviderContext) || (filter.flags & kClearActionRight) ||
                !sameGuid(filter.providerContextKey, contextKey) || filter.numFilterConditions != 1) return 9;
            ++redirects;
            continue;
        }
        if (filter.action.type != FWP_ACTION_BLOCK || (filter.flags & kHasProviderContext) ||
            !(filter.flags & kClearActionRight) || filter.numFilterConditions < 2 ||
            !sameGuid(filter.filterCondition[1].fieldKey, kConditionFlags) ||
            filter.filterCondition[1].matchType != FWP_MATCH_FLAGS_NONE_SET ||
            filter.filterCondition[1].conditionValue.uint32 != FWP_CONDITION_FLAG_IS_LOOPBACK) return 10;
        if (sameGuid(filter.layerKey, kLayerAuthConnectV4) || sameGuid(filter.layerKey, kLayerRecvAcceptV4)) {
            if (filter.numFilterConditions != 3 || !sameGuid(filter.filterCondition[2].fieldKey, kConditionLocalAddress) ||
                filter.filterCondition[2].matchType != FWP_MATCH_NOT_EQUAL ||
                filter.filterCondition[2].conditionValue.type != FWP_UINT32 ||
                filter.filterCondition[2].conditionValue.uint32 != kTunnel) return 11;
            ++ipv4Blocks;
        } else if (sameGuid(filter.layerKey, kLayerConnectV6) || sameGuid(filter.layerKey, kLayerRecvAcceptV6)) {
            if (filter.numFilterConditions != 2) return 12;
            ++ipv6Blocks;
        } else {
            return 28;
        }
    }
    if (redirects != 2 || ipv4Blocks != 2 || ipv6Blocks != 2 || std::size(kRules) != 6) return 13;
    draftFilter(draft, kRules[2], oneEntry, contextKey, kTunnel);
    const std::string blockSignature = filterSignature(draft.filter);
    draftFilter(draft, kRules[2], oneEntry, contextKey, kTunnel + 1);
    if (filterSignature(draft.filter) == blockSignature) return 26;
    if (!insideDirectory(L"c:\\program files\\wgps\\bin\\dns-dispatcher.exe", L"c:\\program files\\wgps\\bin\\") ||
        insideDirectory(L"c:\\program files\\wgps\\bin2\\app.exe", L"c:\\program files\\wgps\\bin\\") ||
        insideDirectory(L"c:\\apps\\app.exe", L"")) return 27;

    // Verification accepts exactly the installed set and rejects anything else.
    const std::vector<AppEntry> apps{oneEntry, twoEntry};
    Owned owned;
    owned.provider = true;
    owned.providerFlags = kProviderPersistent;
    owned.sublayers.push_back({kSublayer, kSublayerPersistent, kSublayerWeight});
    for (const auto& rule : kCallouts) owned.callouts.push_back({*rule.key, kCalloutPersistent | kUsesProviderContext, *rule.layer});
    owned.contexts.push_back({contextKey, 7, kContextPersistent, FWPM_GENERAL_CONTEXT, contextBytes});
    UINT64 nextId = 100;
    size_t bootCopies{};
    forEachFilter(apps, contextKey, kTunnel, true, [&](const FWPM_FILTER0& filter) {
        if (filter.flags & kFilterBootTime) {
            // Boot-time copies are the hard blocks alone, outside the persistent set and its sublayer.
            if ((filter.flags & kFilterPersistent) || !(filter.flags & kClearActionRight) ||
                filter.action.type != FWP_ACTION_BLOCK || !sameGuid(filter.subLayerKey, GUID{}) ||
                !ownedBy(filter.providerKey)) bootCopies = 1000;
            ++bootCopies;
        }
        OwnedFilter recorded = ownedFilter(filter);
        recorded.id = nextId++;
        owned.filters.push_back(std::move(recorded));
    });
    if (bootCopies != 8 || owned.filters.size() != 20 || !describeMismatch(owned, apps, 0xc0000201).empty()) return 14;
    if (describeCounts(owned) != "20 filter(s) including 8 boot-time, 1 provider context(s), 2 callout(s), 1 sublayer(s), provider") {
        return 29;
    }
    size_t withoutRedirects{};
    forEachFilter(apps, contextKey, kTunnel, false, [&](const FWPM_FILTER0& filter) {
        withoutRedirects += (filter.action.type & FWP_ACTION_FLAG_CALLOUT) ? 1000 : 1;
    });
    if (withoutRedirects != 16) return 30;
    // Identity: present by the engine, absent by its resolved path, unresolvable by its recorded identity or
    // else its tagged filters, and never by an omitted or guessed one.
    if (owned.filters.front().tag != L"c:\\apps\\one.exe" || owned.filters.front().path != L"c:\\real\\one.exe" ||
        owned.filters.front().appId != std::vector<UINT8>(oneBytes, oneBytes + sizeof(oneBytes))) return 31;
    const std::vector<UINT8> hereId{'h', 0, 0, 0};
    const std::vector<UINT8> linkId{'l', 0, 0, 0};
    const auto resolveTest = [](const std::wstring& entry) {
        if (entry == L"c:\\apps\\here.exe") return std::pair{std::wstring(L"C:\\Real\\here.exe"), std::wstring(L"\\Device\\V\\Real\\here.exe")};
        if (entry == L"c:\\apps\\gone.exe") return std::pair{std::wstring(L"C:\\Real\\gone.exe"), std::wstring(L"\\Device\\V\\Real\\Gone.exe")};
        return std::pair{std::wstring(), std::wstring()};
    };
    const auto presentTest = [&](const std::wstring& path) { return path == L"C:\\Real\\here.exe" ? hereId : std::vector<UINT8>{}; };
    Identities record;
    record[L"c:\\apps\\link.exe"] = {Identity::Retained, L"D:\\Apps\\Real.exe", {linkId}, {}};
    const Identities identified = identifyApps({L"c:\\apps\\here.exe", L"c:\\apps\\gone.exe", L"c:\\apps\\one.exe",
                                                L"c:\\apps\\link.exe", L"c:\\apps\\new.exe"}, record, owned, resolveTest, presentTest);
    const auto& here = identified.at(L"c:\\apps\\here.exe");
    const auto& gone = identified.at(L"c:\\apps\\gone.exe");
    const auto& tagged = identified.at(L"c:\\apps\\one.exe");
    const auto& link = identified.at(L"c:\\apps\\link.exe");
    const auto& unknown = identified.at(L"c:\\apps\\new.exe");
    if (here.source != Identity::Present || here.path != L"c:\\real\\here.exe" || here.ids != std::vector<std::vector<UINT8>>{hereId} ||
        gone.source != Identity::Derived || gone.path != L"c:\\real\\gone.exe" ||
        gone.ids != std::vector<std::vector<UINT8>>{appIdFromNtPath(L"\\device\\v\\real\\gone.exe")} ||
        tagged.source != Identity::Retained || tagged.path != L"c:\\real\\one.exe" ||
        tagged.ids != std::vector<std::vector<UINT8>>{std::vector<UINT8>(oneBytes, oneBytes + sizeof(oneBytes))} ||
        link.source != Identity::Retained || link.path != L"D:\\Apps\\Real.exe" || link.ids != std::vector<std::vector<UINT8>>{linkId} ||
        unknown.source != Identity::None || !unknown.ids.empty()) return 36;
    // An install stopped after committing the filters for a changed alias but before publishing the record,
    // and the alias then stopped resolving: the committed filters' newer identity and the record's older
    // one are both kept, and attribution follows the committed path.
    const std::vector<UINT8> staleId{'a', 0, 0, 0};
    Identities stale;
    stale[L"c:\\apps\\one.exe"] = {Identity::Retained, L"c:\\stale\\a.exe", {staleId}, {}};
    const auto interrupted = identifyApps({L"c:\\apps\\one.exe"}, stale, owned, resolveTest, presentTest).at(L"c:\\apps\\one.exe");
    const std::vector<UINT8> committedId(oneBytes, oneBytes + sizeof(oneBytes));
    if (interrupted.path != L"c:\\real\\one.exe" || interrupted.ids != std::vector<std::vector<UINT8>>{committedId} ||
        interrupted.others.size() != 1 || interrupted.others[0].path != L"c:\\stale\\a.exe" ||
        interrupted.others[0].ids != std::vector<std::vector<UINT8>>{staleId}) return 40;
    // Both pairings survive the record and are tagged on their own filters.
    Identities pair{{L"c:\\apps\\one.exe", interrupted}};
    const Identities rereadPair = parseIdentities(serializeIdentities(pair));
    if (serializeIdentities(rereadPair) != serializeIdentities(pair) || rereadPair.at(L"c:\\apps\\one.exe").others.size() != 1) return 43;
    const AppIds pairIds(pair);
    if (pairIds.get().size() != 2 || pairIds.get()[0].tag == pairIds.get()[1].tag) return 44;
    // A damaged record is rejected whole rather than read in part.
    const std::string valid = serializeIdentities(stale);
    for (const std::string& damaged : {valid.substr(0, valid.size() - 1), valid + "x\n", valid + "e\tp\t0g\n", valid + "e\tp\t0\n",
                                       valid + "e\tp\t00,\n", valid + "e\t\t00\n", valid + "\n", std::string("# wgps-identities 1")}) {
        if (!parseIdentities(damaged).empty()) return 41;
    }
    if (parseIdentities(valid).size() != 1 || !parseIdentities("# wgps-identities 1\n").empty()) return 42;
    // The record round-trips, and an entry without identifiers is not recorded.
    const Identities reread = parseIdentities(serializeIdentities(identified));
    if (reread.size() != 4 || reread.count(L"c:\\apps\\new.exe") || reread.at(L"c:\\apps\\link.exe").path != link.path ||
        reread.at(L"c:\\apps\\gone.exe").ids != gone.ids || serializeIdentities(reread) != serializeIdentities(identified) ||
        !parseIdentities("not a record").empty()) return 39;
    // A set rebuilt from retained entries keeps exactly the filters those entries had.
    const AppIds retainedIds(identifyApps({L"c:\\apps\\one.exe", L"c:\\apps\\two.exe"}, Identities{}, owned,
        [](const std::wstring&) { return std::pair{std::wstring(), std::wstring()}; },
        [](const std::wstring&) { return std::vector<UINT8>{}; }));
    if (!describeMismatch(owned, retainedIds.get(), 0xc0000201).empty()) return 37;
    if (describeMismatch(owned, apps, 0xc0000202).empty()) return 15;
    if (describeMismatch(owned, {oneEntry}, 0xc0000201).empty()) return 16;
    Owned changed = owned;
    changed.filters.pop_back();
    if (describeMismatch(changed, apps, 0xc0000201).empty()) return 17;
    changed = owned;
    changed.filters.push_back(owned.filters.front());
    if (describeMismatch(changed, apps, 0xc0000201).empty()) return 18;
    changed = owned;
    changed.contexts.push_back(owned.contexts.front());
    if (describeMismatch(changed, apps, 0xc0000201).empty()) return 19;
    changed = owned;
    changed.contexts.front().key.Data1 ^= 1;
    if (describeMismatch(changed, apps, 0xc0000201).empty()) return 20;
    changed = owned;
    changed.callouts.front().flags &= ~kCalloutPersistent;
    if (describeMismatch(changed, apps, 0xc0000201).empty()) return 21;
    changed = owned;
    changed.providerFlags = 0;
    if (describeMismatch(changed, apps, 0xc0000201).empty()) return 22;
    changed = owned;
    changed.sublayers.push_back({contextKey, kSublayerPersistent, kSublayerWeight});
    if (describeMismatch(changed, apps, 0xc0000201).empty()) return 23;
    draftFilter(draft, kRules[2], oneEntry, contextKey, kTunnel);
    draft.filter.flags &= ~kClearActionRight;
    changed = owned;
    changed.filters[3].signature = filterSignature(draft.filter);
    if (describeMismatch(changed, apps, 0xc0000201).empty()) return 24;
    if (owned.empty() || !Owned{}.empty()) return 25;
    // The identifier derived without the file equals the filter engine's for an existing one; a build run
    // from a WSL network path, which the engine cannot name, is checked on CI from a local volume.
    std::vector<wchar_t> self(32768);
    const DWORD selfSize = GetModuleFileNameW(nullptr, self.data(), static_cast<DWORD>(self.size()));
    if (!selfSize) return 32;
    const std::wstring selfPath = wgps::finalPath(std::wstring(self.data(), selfSize), VOLUME_NAME_DOS);
    std::vector<UINT8> engineId;
    try { engineId = fileAppId(selfPath); } catch (const std::exception&) { }
    if (!engineId.empty() && (derivedAppId(selfPath) != engineId || derivedAppId(lower(selfPath)) != engineId)) return 32;
    // An absent file resolves through its nearest existing ancestor.
    const std::wstring directory = selfPath.substr(0, selfPath.find_last_of(L'\\'));
    if (wgps::resolvePath(directory + L"\\absent dir\\absent.exe", VOLUME_NAME_DOS) !=
            wgps::finalPath(directory, VOLUME_NAME_DOS) + L"\\absent dir\\absent.exe" ||
        wgps::resolvePath(directory + L"\\absent.exe", VOLUME_NAME_NT) !=
            wgps::finalPath(directory, VOLUME_NAME_NT) + L"\\absent.exe") return 38;
    const std::wstring mixed = L"\\device\\x\\\u00c9 a.exe";
    std::vector<UINT8> mixedId((mixed.size() + 1) * sizeof(wchar_t), 0);
    std::memcpy(mixedId.data(), mixed.c_str(), mixed.size() * sizeof(wchar_t));
    const std::vector<UINT8> loweredId = fullyLowered(mixedId);
    if (loweredId == mixedId || loweredId.size() != mixedId.size() ||
        std::wstring(reinterpret_cast<const wchar_t*>(loweredId.data())) != L"\\device\\x\\\u00e9 a.exe" ||
        fullyLowered(loweredId) != loweredId) return 34;
    if (!derivedAppId(L"nowhere\\app.exe").empty() || lower(L"C:\\\u00c9X.EXE") != L"c:\\\u00c9x.exe") return 33;
    std::wcout << L"PASS: WFP context layout, IPv4 conversion, persistent redirect and block set, verification.\n";
    return 0;
}
