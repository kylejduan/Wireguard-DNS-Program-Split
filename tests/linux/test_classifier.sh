#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
mode=${1:-baseline}
probe="$repo/build/linux/probe_socket"
mkdir -p "$repo/build/linux"
cc -O2 -g -std=c11 -Wall -Wextra -Werror -pthread \
    "$repo/tests/linux/probe_socket.c" -o "$probe"
if [[ $mode == baseline || $mode == expect-included ]]; then
    output=$("$probe" identity)
    printf '%s\n' "$output"
    expected=0x00000000
    [[ $mode != expect-included ]] || expected=0x00010000
    if [[ $output != *"mark=$expected "* ]]; then
        echo "FAIL: expected immediate socket mark $expected" >&2
        exit 1
    fi
    exit 0
fi
if [[ $mode == native ]]; then
    # Include the implementation in a test-only translation unit; private path
    # helpers stay private, and no BPF syscalls or attachments are performed.
    cat > "$repo/build/linux/path-key-test.cpp" <<'CPP'
#define main classifier_loader_main
#include BPF_LOADER_SOURCE
#undef main
int main(int argc, char **argv) {
    try {
        if (argc != 3) return 2;
        fs::path base=argv[1], executable=argv[2];
        fs::create_directories(base/"target/inner");
        fs::copy_file(executable,base/"chosen");
        fs::copy_file(executable,base/"target/chosen");
        fs::create_directory_symlink(base/"target/inner",base/"alias");
        auto key=path_key((base/"alias/../chosen").string(),true);
        if (key.pathname!=(base/"target/chosen").string())
            fail("path-add must resolve symlink before parent-directory traversal");
        fs::copy_file(executable,base/"stored");
        auto stored=path_key((base/"stored").string(),true);
        fs::remove(base/"stored");
        fs::create_symlink(base/"target/chosen",base/"stored");
        auto removed=path_key(stored.pathname,false);
        if (std::string(removed.pathname)!=stored.pathname)
            fail("path-del must delete stored policy identity even after symlink replacement");
        std::cout << "PASS: path-add filesystem semantics and stable exact-key deletion\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
CPP
    c++ -O2 -std=c++17 -Wall -Wextra -Werror \
        "-DBPF_LOADER_SOURCE=\"$repo/src/linux/native/bpf-loader.cpp\"" \
        "$repo/build/linux/path-key-test.cpp" -o "$repo/build/linux/path-key-test" \
        $(pkg-config --cflags --libs libbpf)
    native_fixture=$(mktemp -d "$repo/build/linux/path-fixture.XXXXXX")
    trap 'rm -rf -- "$native_fixture"' EXIT
    "$repo/build/linux/path-key-test" "$native_fixture" "$probe"
    cc -O2 -std=c11 -Wall -Wextra -Werror \
        "$repo/tests/linux/probe_exec.c" -o "$repo/build/linux/probe_exec"
    "$repo/build/linux/probe_exec" "$probe" > "$native_fixture/exec.txt"
    python3 - "$native_fixture/exec.txt" <<'PY'
import pathlib, re, sys
output = pathlib.Path(sys.argv[1]).read_text()
assert re.findall(r'mark=(0x[0-9a-f]+)', output) == ['0x00000000'] * 3, output
assert 'launcher_before' in output and 'launcher_after' in output and 'exe=' in output
print('PASS: native launcher observes its own and execed helper sockets without setting marks')
PY
    python3 - "$probe" <<'PY'
import socket, subprocess, sys, threading
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver, \
     socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as responder:
    receiver.bind(('127.0.0.1',0)); receiver.settimeout(3)
    responder.bind(('127.0.0.1',0))
    def echo_from_other_port():
        data,peer=receiver.recvfrom(4096); responder.sendto(data,peer)
    thread=threading.Thread(target=echo_from_other_port); thread.start()
    try:
        result=subprocess.run([sys.argv[1],'udp','127.0.0.1',str(receiver.getsockname()[1])],
                              capture_output=True,text=True,timeout=5)
        assert result.returncode==0,result
        assert f'peer=127.0.0.1:{responder.getsockname()[1]} ' in result.stdout, result.stdout
    finally: thread.join(timeout=4)
print('PASS: unconnected UDP fixture reports observed reply source rather than requested peer')
PY
    exit 0
fi
if [[ $mode != vm || ${WG_CLASSIFIER_DISPOSABLE_VM:-} != 1 || $EUID != 0 ||
      $(uname -r) == *microsoft* || $(hostname) == TV ]]; then
    echo 'vm mode requires root and WG_CLASSIFIER_DISPOSABLE_VM=1 on a disposable native VM' >&2
    exit 2
fi
export WG_TEST_REPO="$repo"
python3 - <<'PY'
import concurrent.futures, json, os, pathlib, re, select, shutil, socket
import statistics, subprocess, threading, time, uuid

repo = pathlib.Path(os.environ['WG_TEST_REPO'])
tag = 'wgps-' + uuid.uuid4().hex[:10]
evidence = repo / 'local/validation' / tag
evidence.mkdir(parents=True)
# Services launched as the login user need executable traversal of this fixture.
evidence.chmod(0o755)
group = pathlib.Path('/sys/fs/cgroup') / tag
pins = pathlib.Path('/sys/fs/bpf') / tag
loader = str(repo / 'build/linux/bpf-loader')
obj = str(repo / 'build/linux/classifier.bpf.o')
included, direct = evidence / 'included', evidence / 'direct'
for path in (included, direct): shutil.copy2(repo / 'build/linux/probe_socket', path)
assert included.read_bytes() == direct.read_bytes()
mark = '0x00010000'
active = False
seed_active = nft_active = False
seed_pin = pathlib.Path('/sys/fs/bpf') / (tag+'-seed')
children, servers, threads = [], [], []
results = []

def scoped_args(args):
    # Only the test cgroup needs a launcher; root-coverage tests exec directly.
    # Avoid Python preexec_fn: the echo/churn fixtures run multiple threads.
    return ['sh','-c','echo $$ > "$1/cgroup.procs"; shift; exec "$@"',
            'classifier-test',str(group),*args]

def command(args, okay=True, scoped=False, **kwargs):
    if scoped: args=scoped_args(args)
    result = subprocess.run([str(x) for x in args], text=True, capture_output=True,
                            timeout=30, **kwargs)
    if okay and result.returncode:
        raise AssertionError(f'{args}: {result.returncode}\n{result.stdout}\n{result.stderr}')
    return result

def probe(path, mode='identity', args=(), expected=mark, scoped=True):
    result = command([path, mode, *args], okay=expected is not None,
                     scoped=scoped)
    if expected is None:
        assert result.returncode == 1 and 'socket_error=1 ' in result.stdout, result
    else:
        observations = re.findall(r'mark=(0x[0-9a-f]+)', result.stdout)
        assert observations and all(x == expected for x in observations), result.stdout
    return result.stdout

def passed(name):
    results.append(name)
    print('PASS', name, flush=True)

def load(target):
    global active
    result = command([loader, 'load', obj, pins, target, '0x00ff0000', mark, included], okay=False)
    (evidence / f'verifier-{len(results)}.txt').write_text(result.stderr)
    assert result.returncode == 0, result.stderr[-4000:]
    active = True

def remove():
    global active
    command([loader, 'remove', pins])
    active = False

def state(value): command([loader, 'state', pins, value])
def add(path): command([loader, 'path-add', pins, path])
def delete(path): command([loader, 'path-del', pins, path])

def control(path):
    proc = subprocess.Popen(scoped_args([str(path),'control']), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True)
    children.append(proc)
    assert proc.stdout.readline().strip() == 'ready'
    return proc

def step(proc, request, expected):
    proc.stdin.write(request + '\n'); proc.stdin.flush()
    assert select.select([proc.stdout], [], [], 5)[0], 'control fixture timeout'
    output = proc.stdout.readline()
    assert expected in output, output

def echo_loop(server, tcp):
    while True:
        try:
            if tcp:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(2)
                    payload = conn.recv(1024)
                    conn.sendall(payload)
            else:
                payload, peer = server.recvfrom(1024)
                server.sendto(payload, peer)
        except socket.timeout: continue
        except OSError: return

def packet_count():
    rules = json.loads(command(['nft','-j','list','table','inet',tag]).stdout)
    return sum(expr['counter']['packets'] for item in rules['nftables']
               for expr in item.get('rule',{}).get('expr',[]) if 'counter' in expr)

def bench(path, label, scoped):
    output = probe(path, 'bench', ('10000',), mark if path == included and scoped else '0x00000000', scoped)
    (evidence / (label + '.txt')).write_text(output)
    values = sorted(int(x) for x in re.findall(r'socket_ns=(\d+)', output))
    summary = {q: values[min(len(values)-1, int(len(values)*p))]
               for q,p in [('p50',.5),('p95',.95),('p99',.99)]}
    summary['cpu_ns'] = int(re.search(r'cpu_ns=(\d+)', output)[1])
    return summary

try:
    group.mkdir()
    (evidence / 'capabilities.txt').write_text(command([loader, 'capabilities']).stdout)
    (evidence / 'links-before.json').write_text(command(['bpftool', '-j', 'link', 'show']).stdout)
    timings = {'lsm_enabled_no_classifier': bench(direct, 'baseline', False)}
    load(group)
    probe(included, expected=None)
    probe(direct, expected='0x00000000')
    passed('blocked selected first socket; unlisted healthy')
    state('ready')
    probe(included); probe(direct, expected='0x00000000')
    passed('identical executable bytes differ by full path before first use')
    for mode in ('ipv6', 'raw', 'packet'): probe(included, mode, expected=None)
    probe(direct, 'ipv6', expected='0x00000000')
    passed('included IPv6/raw/packet denied; unlisted IPv6 healthy')
    competing = command([loader, 'load', obj, str(pins)+'-other', group,
                         '0x00ff0000', mark, included], okay=False)
    assert competing.returncode and 'competing' in competing.stderr
    passed('existing competing cgroup LSM attachment rejected')
    # Test-only cgroup sock-create hook seeds unrelated mark bits BEFORE the LSM
    # post-create hook. It never writes arbitrary kernel socket memory.
    seed = evidence/'seed.bpf.c'
    seed.write_text('''#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
SEC("cgroup/sock_create") int seed(struct bpf_sock *sk) {
    sk->mark = 0x8000002a; return 1;
}
char LICENSE[] SEC("license") = "GPL";
''')
    command(['clang','-O2','-g','-target','bpf','-I'+str(repo/'build/linux'),
             '-c',seed,'-o',str(seed)+'.o'])
    command(['bpftool','prog','load',str(seed)+'.o',seed_pin])
    command(['bpftool','cgroup','attach',group,'sock_create','pinned',seed_pin,'multi'])
    seed_active=True
    probe(included,expected='0x8001002a'); probe(direct,expected='0x8000002a')
    command(['bpftool','cgroup','detach',group,'sock_create','pinned',seed_pin])
    seed_active=False; seed_pin.unlink()
    passed('foreign mark bits preserved from prior cgroup socket-create hook')
    command(['nft','-f','-'],input=f'''table inet {tag} {{
 chain output {{ type filter hook output priority -150; policy accept;
  ip daddr 127.0.0.1 meta mark & 0x00ff0000 == 0x00010000 counter
 }}
}}
''')
    nft_active=True
    for tcp in (True, False):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
        server.bind(('127.0.0.1', 0)); server.settimeout(.2)
        if tcp: server.listen(128)
        servers.append(server)
        thread = threading.Thread(target=echo_loop, args=(server,tcp), daemon=True)
        thread.start(); threads.append(thread)
        port = str(server.getsockname()[1])
        modes = ('tcp',) if tcp else ('udp', 'udp-connected')
        for mode in modes:
            for path, expected in ((included,mark), (direct,'0x00000000')):
                output = ''.join(probe(path, mode, ('127.0.0.1',port), expected) for _ in range(20))
                (evidence / f'{path.name}-{mode}.txt').write_text(output)
        if not tcp:
            time.sleep(.1)
            before=packet_count()
            probe(included,'udp',('127.0.0.1',port)); after=packet_count()
            assert after>before
            probe(direct,'udp',('127.0.0.1',port),'0x00000000'); assert packet_count()==after
            (evidence/'packet-counters.json').write_text(command(['nft','-j','list','table','inet',tag]).stdout)
    passed('first TCP, unconnected UDP and connected UDP request/echo traffic')
    passed('included packet mark visible in output hook; unlisted UDP does not hit selected counter')
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: probe(included), range(80)))
    probe(included, 'threads', ('50',))
    passed('80 concurrent short-lived processes and 200 sockets across four threads')
    alias = evidence / 'symlink'; alias.symlink_to(included)
    hard = evidence / 'hardlink'; os.link(included, hard)
    probe(alias); probe(hard, expected='0x00000000')
    add(hard); probe(hard); delete(hard)
    passed('symlink canonicalization and distinct hard-link executable paths')
    old = control(included)
    step(old, 'o', 'held_mark='+mark)
    destination = evidence / 'renamed'
    shutil.copy2(included,destination); add(destination); destination.unlink()
    included.rename(destination)
    step(old, 's', 'mark='+mark)
    delete(destination)
    step(old, 's', 'mark=0x00000000')
    step(old, 'm', 'held_mark='+mark)
    destination.rename(included)
    step(old, 's', 'mark='+mark)
    replacement = evidence / 'replacement'; shutil.copy2(direct,replacement)
    replacement.replace(included)
    step(old, 's', 'socket_error=1 ')
    probe(included)
    passed('rename and policy updates affect new sockets; held marks stable; atomic replacement fails old image')
    suffix = evidence / 'genuine (deleted)'
    shutil.copy2(direct,suffix); add(suffix); probe(suffix)
    passed('genuine filename ending in deleted suffix remains includable')
    script = evidence / 'script'; script.write_text('#!/bin/sh\nexit 0\n'); script.chmod(0o755)
    refusal = command([loader,'path-add',pins,script], okay=False)
    assert refusal.returncode and 'scripts' in refusal.stderr
    passed('script-only enrollment explicitly rejected')
    # A memfd executable has no normal linked dentry and must not turn into a map miss.
    mem = os.memfd_create('classifier-fixture',0)
    os.write(mem,direct.read_bytes()); os.fchmod(mem,0o755)
    synthetic = command([f'/proc/self/fd/{mem}','identity'], okay=False,
                        pass_fds=(mem,), scoped=True)
    os.close(mem)
    assert synthetic.returncode == 1 and 'socket_error=1 ' in synthetic.stdout
    passed('synthetic memfd image fails closed')
    foreign = command(['unshare','--net',included,'identity'], scoped=True)
    assert 'mark=0x00000000' in foreign.stdout
    refused = command(['unshare','--net',loader,'path-add',pins,included],okay=False)
    assert refused.returncode and 'unsupported enrollment context' in refused.stderr
    passed('foreign network namespace outside coverage; enrollment there rejected')
    # Different filesystem root with the same absolute spelling remains outside
    # coverage. A static fixture avoids any dynamic-loader dependencies in jail.
    static = evidence/'static-probe'
    command(['cc','-static','-O2','-pthread',repo/'tests/linux/probe_socket.c','-o',static])
    probe(static,expected='0x00000000'); add(static); probe(static)
    for mode, server in (('tcp',servers[0]), ('udp',servers[1]), ('udp-connected',servers[1])):
        output = probe(static,mode,('127.0.0.1',str(server.getsockname()[1])))
        (evidence/f'static-{mode}.txt').write_text(output)
    delete(static); probe(static,expected='0x00000000')
    passed('static ELF independent inclusion and first TCP/UDP/connected-UDP traffic')

    launcher, helper = evidence/'launcher', evidence/'helper'
    command(['cc','-O2','-std=c11','-Wall','-Wextra','-Werror',
             repo/'tests/linux/probe_exec.c','-o',launcher])
    shutil.copy2(direct,helper)
    helper_rows=[]
    for action, parent_mark, helper_mark in (
            (None,'0x00000000','0x00000000'),
            (lambda:add(launcher),mark,'0x00000000'),
            (lambda:add(helper),mark,mark),
            (lambda:delete(launcher),'0x00000000',mark),
            (lambda:delete(helper),'0x00000000','0x00000000')):
        if action: action()
        output=command([launcher,helper],scoped=True).stdout
        assert re.findall(r'mark=(0x[0-9a-f]+)',output)==[parent_mark,helper_mark,parent_mark],output
        assert 'exe='+str(helper) in output,output
        helper_rows.append(output)
    (evidence/'helper-launches.txt').write_text(''.join(helper_rows))
    passed('fork-exec helper needs its own entry; parent and helper enrollment remain independent')
    jail=evidence/'jail'; jail.mkdir()
    jail_image=jail/str(included).lstrip('/'); jail_image.parent.mkdir(parents=True)
    shutil.copy2(static,jail_image)
    jailed=command(['chroot',jail,included,'bench','1'],scoped=True)
    assert 'mark=0x00000000' in jailed.stdout,jailed.stdout
    passed('same executable pathname under foreign filesystem root is outside coverage')
    # Move only the fixture into a long path via dirfds so d_path sees >4096 bytes.
    base = evidence / 'deep'; base.mkdir()
    dirs = [os.open(base,os.O_RDONLY|os.O_DIRECTORY)]
    name = 'd'*150
    try:
        for _ in range(29):
            os.mkdir(name,dir_fd=dirs[-1]); dirs.append(os.open(name,os.O_RDONLY|os.O_DIRECTORY,dir_fd=dirs[-1]))
        fd = os.open('probe',os.O_CREAT|os.O_RDWR,0o755,dir_fd=dirs[-1])
        os.write(fd,direct.read_bytes()); os.close(fd)
        fd = os.open('probe',os.O_RDONLY,dir_fd=dirs[-1])
        longpath = command([f'/proc/self/fd/{fd}','identity'],okay=False,pass_fds=(fd,),scoped=True)
        os.close(fd)
        assert longpath.returncode == 1 and 'socket_error=1 ' in longpath.stdout
        os.unlink('probe',dir_fd=dirs[-1])
    finally:
        while len(dirs)>1:
            os.close(dirs.pop()); os.rmdir(name,dir_fd=dirs[-1])
        os.close(dirs.pop()); base.rmdir()
    probe(direct,expected='0x00000000')
    passed('real pathname overflow fails closed without harming ordinary unlisted sockets')
    timings['included'] = bench(included,'included-bench',True)
    timings['unlisted'] = bench(direct,'unlisted-bench',True)
    # Parent-directory renames also invalidate identity synchronously.
    parent=evidence/'parent'; parent.mkdir()
    nested=parent/'probe'; shutil.copy2(direct,nested); add(nested)
    running=control(nested)
    step(running,'s','mark='+mark)
    parent.rename(evidence/'parent-moved')
    step(running,'s','mark=0x00000000')
    (evidence/'parent-moved').rename(parent)
    step(running,'s','mark='+mark)
    # Enroll both destinations so rename contention keeps the expected class.
    other=evidence/'churn-other'; shutil.copy2(direct,other); add(other); other.unlink()
    stop=threading.Event()
    def rename_loop():
        while not stop.is_set():
            nested.rename(other); other.rename(nested)
    churn=threading.Thread(target=rename_loop); churn.start()
    try:
        # Existing image continues to create sockets during directory-entry churn.
        for _ in range(100): step(running,'s','mark='+mark)
    finally:
        stop.set(); churn.join(timeout=3)
    passed('ancestor-directory rename and 100 socket creations under rename contention')
    responses={}
    for path in (included,direct):
        for mode in ('tcp','udp','udp-connected'):
            values=sorted(int(x) for x in re.findall(r'response_ns=(\d+)',
                           (evidence/f'{path.name}-{mode}.txt').read_text()))
            responses[f'{path.name}-{mode}']={q:values[min(len(values)-1,int(len(values)*p))]
                for q,p in [('p50',.5),('p95',.95),('p99',.99)]}
    (evidence/'first-response-timings.json').write_text(json.dumps(responses,indent=2))
    (evidence/'timings.json').write_text(json.dumps(timings,indent=2))
    # Root-cgroup coverage: services and their private mount namespaces are descendants.
    (evidence/'state-test-cgroup.txt').write_text(command([loader,'status',pins]).stdout)
    remove(); load('/sys/fs/cgroup'); state('ready')
    probe(included,scoped=False)
    shell = command(['sh','-c','exec "$1" identity','sh',included])
    assert 'mark='+mark in shell.stdout
    cron = command(['env','-i','PATH=/usr/bin:/bin',included,'identity'])
    assert 'mark='+mark in cron.stdout
    for private in (False,True):
        args=['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+tag+str(private)]
        if private: args+=['-p','PrivateTmp=yes']
        result=command([*args,included,'identity'])
        assert 'mark='+mark in result.stdout, result.stdout
    passed('root descendants: direct exec, shell, cron-compatible environment, system service and PrivateTmp')
    user = os.environ.get('SUDO_USER')
    if not user or user == 'root': raise AssertionError('SUDO_USER needed for real user-service proof')
    import pwd
    uid=pwd.getpwnam(user).pw_uid
    user_result=command(['runuser','-u',user,'--','env',f'XDG_RUNTIME_DIR=/run/user/{uid}',
                         'systemd-run','--user','--quiet','--wait','--pipe','--collect',
                         '--unit='+tag+'-user',included,'identity'])
    assert 'mark='+mark in user_result.stdout,user_result.stdout
    passed('user systemd service automatically included')
    (evidence/'state.txt').write_text(command([loader,'status',pins]).stdout)
    (evidence/'links-active.json').write_text(command(['bpftool','-j','link','show']).stdout)
    passed('pinned policy and link persist after one-shot loader exits')
finally:
    for proc in children:
        if proc.poll() is None:
            proc.stdin.write('q\n'); proc.stdin.flush()
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
    for server in servers: server.close()
    for thread in threads: thread.join(timeout=1)
    if seed_active: command(['bpftool','cgroup','detach',group,'sock_create','pinned',seed_pin])
    if seed_pin.exists(): seed_pin.unlink()
    if nft_active: command(['nft','delete','table','inet',tag])
    if active: remove()
    group.rmdir()
    (evidence/'results.json').write_text(json.dumps(results,indent=2))
    (evidence/'links-after.json').write_text(command(['bpftool','-j','link','show']).stdout)
    assert not pins.exists() and not group.exists()
    print('Evidence:', evidence, flush=True)
print('PASS: implemented classifier tests; see report for remaining release gates')
PY
