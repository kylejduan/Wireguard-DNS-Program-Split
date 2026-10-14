// SPDX-License-Identifier: GPL-3.0-or-later
// Included by bpf-loader.cpp inside its private namespace: settling a guard.
/* An fexit program sees only calls that enter after it attached. A unix_bind
 * or vfs_rename already running when guard_bound and guard_renamed attached
 * completes unobserved, so a label cached meanwhile could outlive its effect.
 * The programs therefore cache nothing until GUARD_SETTLED. That is set once
 * every task that existed at the first scan (all scans follow attachment, and
 * later tasks are covered by the completion programs) has exited or shown one
 * proven walk of its kernel stack with no return address inside either
 * function. A walk is proven only if the task did not run while it was taken
 * (off CPU at both reads, switch count unchanged; see drain_tasks) and the
 * unwind reached a real stack bottom (the outermost address is in the entry
 * text or the fork return path), with a nonzero length below the depth cap (the buffer or
 * kernel.perf_event_max_stack). Anything else is unknown and retried; an
 * unwinder that stops early still returns a positive length, which the
 * stack-bottom test catches. Unsettled guards decide every call afresh. */
struct Range {
    uint64_t start, end;
    bool contains(uint64_t address) const { return address >= start && address < end; }
};
struct KernelSymbols {
    std::vector<Range> traced, bottoms;
    std::vector<std::pair<uint64_t, std::string>> sorted;
    std::string name(uint64_t address) const {
        auto next = std::upper_bound(sorted.begin(), sorted.end(), std::make_pair(address, std::string("\xff")));
        return next == sorted.begin() ? "?" : std::prev(next)->second;
    }
};
KernelSymbols kernel_symbols() {
    std::ifstream table("/proc/kallsyms");
    std::string line;
    KernelSymbols symbols;
    while (std::getline(table, line)) {
        std::istringstream fields(line);
        std::string address, type, name;
        if (!(fields >> address >> type >> name) || name.find('[') != std::string::npos) continue;
        uint64_t value = std::stoull(address, nullptr, 16);
        if (value) symbols.sorted.emplace_back(value, name);
    }
    std::sort(symbols.sorted.begin(), symbols.sorted.end());
    auto find = [&](const std::string &name) {
        for (const auto &[address, symbol] : symbols.sorted) if (symbol == name) return address;
        return uint64_t{0};
    };
    for (const char *function : {"unix_bind", "vfs_rename"}) {
        auto start = find(function);
        auto next = std::upper_bound(symbols.sorted.begin(), symbols.sorted.end(), std::make_pair(start, std::string("\xff")));
        if (start && next != symbols.sorted.end()) symbols.traced.push_back({start, next->first});
    }
    auto entry_start = find("__entry_text_start"), entry_end = find("__entry_text_end");
    if (entry_start && entry_end > entry_start) symbols.bottoms.push_back({entry_start, entry_end});
    /* Every kernel thread's walk ends here, outside the entry text: the
     * fork return path is the first frame of each new task and an unwind
     * hint marks it as the end of the stack. Verified on the reference
     * kernel: user tasks end in entry_SYSCALL_64_after_hwframe, kernel
     * threads in ret_from_fork_asm, and no other outermost frame appears. */
    auto fork = find("ret_from_fork_asm");
    auto after = std::upper_bound(symbols.sorted.begin(), symbols.sorted.end(), std::make_pair(fork, std::string("\xff")));
    if (fork && after != symbols.sorted.end()) symbols.bottoms.push_back({fork, after->first});
    return symbols;
}
struct DrainRecord { uint32_t tid, flags; uint64_t start, switches_before, switches_after, bytes; };
enum { TASK_EXITED = 1, TASK_SELF = 2, TASK_ON_CPU = 4, TASK_WALK_ERROR = 8 };
enum class Walk { Clear, Unknown, Inside };
size_t depth_cap() {
    size_t cap = sizeof(path_scratch) / 8;
    std::ifstream sysctl("/proc/sys/kernel/perf_event_max_stack");
    size_t limit = 0;
    if (sysctl >> limit) cap = std::min(cap, limit);
    return cap;
}
Walk classify(const DrainRecord &record, const std::vector<uint64_t> &frames, size_t cap,
              const KernelSymbols &symbols) {
    if (record.flags & (TASK_EXITED | TASK_SELF)) return Walk::Clear;
    if (record.flags & (TASK_ON_CPU | TASK_WALK_ERROR) || record.switches_before != record.switches_after ||
        frames.empty() || frames.size() >= cap) return Walk::Unknown;
    for (auto address : frames)
        for (const auto &range : symbols.traced)
            if (range.contains(address)) return Walk::Inside;
    for (const auto &range : symbols.bottoms)
        if (range.contains(frames.back())) return Walk::Clear;
    return Walk::Unknown; // The unwind stopped short of a stack bottom.
}
struct Sample { DrainRecord record; std::vector<uint64_t> frames; };
double monotonic() {
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec + now.tv_nsec / 1e9;
}
/* One pass of the iterator over every task, or only thread TID, into SAMPLES;
 * false if DEADLINE passes first. Reads are bounded so it is checked often. */
bool scan_tasks(bpf_program *iterator, double deadline, std::vector<Sample> &samples, uint32_t tid = 0) {
    bpf_iter_link_info filter{};
    filter.task.tid = tid;
    bpf_iter_attach_opts options{};
    options.sz = sizeof(options);
    options.link_info = &filter;
    options.link_info_len = sizeof(filter);
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> link(
        bpf_program__attach_iter(iterator, tid ? &options : nullptr), bpf_link__destroy);
    if (!link) fail("attach task stack iterator");
    Fd stacks(bpf_iter_create(bpf_link__fd(link.get())));
    std::vector<char> data(1 << 16);
    size_t used = 0;
    for (ssize_t count; (count = read(stacks.value, data.data() + used, std::min<size_t>(data.size() - used, 1 << 16))) != 0;) {
        check(count > 0, "read task stacks");
        used += count;
        scan_delay();
        if (monotonic() > deadline) return false;
        if (data.size() - used < (1 << 16)) data.resize(data.size() * 2);
    }
    samples.clear();
    for (size_t offset = 0; offset + sizeof(DrainRecord) <= used;) {
        Sample sample;
        std::memcpy(&sample.record, data.data() + offset, sizeof(sample.record));
        offset += sizeof(sample.record);
        if (sample.record.bytes % 8 || sample.record.bytes > used - offset) fail("truncated task stack record");
        sample.frames.resize(sample.record.bytes / 8);
        std::memcpy(sample.frames.data(), data.data() + offset, sample.record.bytes);
        offset += sample.record.bytes;
        samples.push_back(std::move(sample));
    }
    return true;
}
/* Rescanning only the pending threads relies on the iterator's thread filter
 * (Linux 6.1 and later). Before that the filter is ignored and every task is
 * returned; a kernel resolving it as a thread group would return nothing for
 * a live non-leader thread, which would read as an exit. So prove it first:
 * a filtered scan of a blocked helper thread returns exactly that thread. */
bool thread_filter_works(bpf_program *iterator, double deadline) {
    int ready[2], release[2];
    if (pipe2(ready, O_CLOEXEC)) return false;
    Fd ready_read(ready[0]), ready_write(ready[1]);
    if (pipe2(release, O_CLOEXEC)) return false;
    Fd release_read(release[0]), release_write(release[1]);
    std::thread helper;
    try {
        helper = std::thread([&] {
            pid_t self = gettid();
            char byte;
            (void)!write(ready_write.value, &self, sizeof(self));
            (void)!read(release_read.value, &byte, 1);
        });
    } catch (const std::system_error &) { return false; }
    pid_t tid = 0;
    bool works = false;
    try {
        if (read(ready_read.value, &tid, sizeof(tid)) == sizeof(tid) && tid != getpid()) {
            std::vector<Sample> samples;
            works = scan_tasks(iterator, deadline, samples, tid) && samples.size() == 1 &&
                    samples.front().record.tid == uint32_t(tid);
        }
    } catch (const std::exception &) {}
    (void)!write(release_write.value, "x", 1);
    helper.join();
    return works;
}
/* Settle DIR once every task present at the first scan is cleared. Everything
 * (symbols, scans, sleeps) shares one monotonic budget far inside the
 * controller's 30-second command timeout; when it runs out, even partway
 * through a scan, the guard is published unsettled and retried later. */
enum class Drain { Settled, Unproven, Deadline };
Drain drain(bpf_object *object, const fs::path &dir) {
    const double deadline = monotonic() + 3;
    auto *iterator = bpf_object__find_program_by_name(object, "drain_tasks");
    auto symbols = kernel_symbols();
    if (!iterator || symbols.traced.size() != 2 || symbols.bottoms.empty()) return Drain::Unproven;
    size_t cap = depth_cap();
    auto clear = [&](const Sample &sample) { return classify(sample.record, sample.frames, cap, symbols) == Walk::Clear; };
    std::vector<Sample> samples;
    if (!scan_tasks(iterator, deadline, samples)) return Drain::Deadline;
    std::set<std::pair<uint32_t, uint64_t>> pending; // (thread ID, start time)
    for (const auto &sample : samples)
        if (!clear(sample)) pending.insert({sample.record.tid, sample.record.start});
    bool filtered = !pending.empty() && thread_filter_works(iterator, deadline);
    while (!pending.empty()) {
        if (monotonic() + 0.01 > deadline) return Drain::Deadline;
        usleep(10000);
        if (filtered && pending.size() <= 64) {
            /* No sample, or another start time under the same ID: it exited. */
            for (auto task = pending.begin(); task != pending.end();) {
                if (!scan_tasks(iterator, deadline, samples, task->first)) return Drain::Deadline;
                bool remains = false;
                for (const auto &sample : samples)
                    if (sample.record.tid == task->first && sample.record.start == task->second) remains = !clear(sample);
                task = remains ? std::next(task) : pending.erase(task);
            }
            continue;
        }
        if (!scan_tasks(iterator, deadline, samples)) return Drain::Deadline;
        std::map<std::pair<uint32_t, uint64_t>, bool> seen;
        for (const auto &sample : samples) seen[{sample.record.tid, sample.record.start}] = clear(sample);
        for (auto task = pending.begin(); task != pending.end();) {
            auto found = seen.find(*task);
            task = found == seen.end() || found->second ? pending.erase(task) : std::next(task);
        }
    }
    Fd config(map_fd(dir, "guard_config", 4, 8, BPF_MAP_TYPE_ARRAY, 1));
    uint32_t zero = 0; uint64_t epoch = 0;
    check(bpf_map_lookup_elem(config.value, &zero, &epoch) == 0, "read guard configuration");
    /* Every stamp includes this word, so setting the bit also invalidates. */
    epoch |= GUARD_SETTLED;
    check(bpf_map_update_elem(config.value, &zero, &epoch, BPF_ANY) == 0, "settle guard");
    return Drain::Settled;
}
/* Diagnostic: one scan, counted by outcome and outermost frame symbol, with
 * the time of a full scan and whether (and how fast) one thread is rescanned. */
void drain_report(bpf_object *object) {
    auto *iterator = bpf_object__find_program_by_name(object, "drain_tasks");
    if (!iterator) fail("task stack iterator missing");
    auto symbols = kernel_symbols();
    size_t cap = depth_cap();
    std::map<std::string, size_t> counts;
    std::vector<Sample> samples;
    double started = monotonic();
    if (!scan_tasks(iterator, started + 30, samples)) fail("task scan exceeded its time limit");
    double scanned = monotonic();
    bool filter = thread_filter_works(iterator, scanned + 30);
    std::cout << "tasks=" << samples.size() << " full_scan_seconds=" << scanned - started << " thread_filter="
              << (filter ? "works" : "unavailable") << " thread_probe_seconds=" << monotonic() - scanned << '\n';
    for (const auto &sample : samples) {
        auto outcome = classify(sample.record, sample.frames, cap, symbols);
        std::string label = outcome == Walk::Clear ? "clear" : outcome == Walk::Inside ? "inside" : "unknown";
        if (sample.record.flags & (TASK_EXITED | TASK_SELF)) label += " exited-or-self";
        else if (sample.frames.empty()) label += " no-frames";
        else label += " " + symbols.name(sample.frames.back());
        counts[label]++;
    }
    for (const auto &[label, count] : counts) std::cout << count << ' ' << label << '\n';
}
