// SPDX-License-Identifier: GPL-3.0-or-later
// Included by bpf-loader.cpp inside its private namespace: owned pin removal.
/* Unpin in reverse pin order, so an interrupted removal leaves invalidators
 * last; unpinning releases a link later, from a kernel work item, so detach
 * the classifier now to free the cgroup before returning. */
void remove_pins(const fs::path &dir) {
    for (auto spec=links.rbegin(); spec!=links.rend(); ++spec) {
        if (!fs::exists(dir/spec->pin)) continue;
        if (spec->kind==LINK_CGROUP) {
            Fd link(bpf_obj_get((dir/spec->pin).c_str()));
            check(bpf_link_detach(link.value)==0,"detach owned classifier");
        }
        check(unlink((dir/spec->pin).c_str())==0,"remove owned link");
        interruption_point(std::string("removed:")+spec->pin);
    }
    for (auto spec=maps.rbegin(); spec!=maps.rend(); ++spec) {
        if (!fs::exists(dir/spec->name)) continue;
        check(unlink((dir/spec->name).c_str())==0,"remove owned map");
        interruption_point(std::string("removed:")+spec->name);
    }
    check(rmdir(dir.c_str()) == 0, "remove owned pin directory");
}
/* The kind of BPF object an FD refers to. Map, link and program IDs are
 * separate namespaces, so an ID is only meaningful together with its kind. */
std::string object_kind(int fd) {
    std::istringstream info(read_text(("/proc/self/fdinfo/"+std::to_string(fd)).c_str()));
    std::string line;
    while (std::getline(info,line)) {
        if (line.rfind("map_id:",0)==0) return "map";
        if (line.rfind("link_id:",0)==0) return "link";
        if (line.rfind("prog_type:",0)==0) return "prog";
    }
    return "";
}
/* Finish a removal that was interrupted: what remains of the directory need
 * not be a complete pin set, so instead of verifying ownership as a whole,
 * every remaining entry must be one of this loader's pins and the same object
 * the caller recorded when it adopted the load: a map of that ID and name
 * ("map NAME ID") or a link of that ID running that program ("link PIN ID
 * PROGRAM"). Nothing else is removed. */
struct Recorded { bool link; uint32_t id, program; };
void discard(const fs::path &dir) {
    std::map<std::string,Recorded> recorded;
    std::string line;
    while (std::getline(std::cin,line)) {
        std::istringstream fields(line);
        std::string kind, name, extra; Recorded entry{false,0,0};
        if (!(fields>>kind>>name>>entry.id)) fail("invalid recorded identity");
        entry.link=kind=="link";
        if (entry.link && !(fields>>entry.program)) fail("invalid recorded identity");
        bool known=false;
        for (const auto &spec:links) known|=entry.link && name==spec.pin;
        for (const auto &spec:maps) known|=kind=="map" && name==spec.name;
        if (fields>>extra || !known || !recorded.emplace(name,entry).second) fail("invalid recorded identity");
    }
    Fd lock(open(dir.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC));
    check(flock(lock.value,LOCK_EX)==0,"lock owned pin directory for removal");
    for (const auto &entry:fs::directory_iterator(dir)) {
        auto found=recorded.find(entry.path().filename());
        if (found==recorded.end()) fail("unrecorded pin-directory entry");
        Fd fd(bpf_obj_get(entry.path().c_str()));
        const auto &expected=found->second;
        bool same=object_kind(fd.value)==(expected.link ? "link" : "map");
        if (same && expected.link) {
            bpf_link_info info{}; uint32_t size=sizeof(info);
            check(bpf_obj_get_info_by_fd(fd.value,&info,&size)==0,"read recorded link");
            same=info.id==expected.id && info.prog_id==expected.program;
        } else if (same) {
            bpf_map_info info{}; uint32_t size=sizeof(info);
            check(bpf_obj_get_info_by_fd(fd.value,&info,&size)==0,"read recorded map");
            same=info.id==expected.id && std::string(info.name)==entry.path().filename().string();
        }
        if (!same) fail("pinned identity differs from the recorded one");
    }
    remove_pins(dir);
}
