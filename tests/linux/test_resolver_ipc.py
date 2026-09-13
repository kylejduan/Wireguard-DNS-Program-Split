#!/usr/bin/env python3
"""Disposable-VM resolver-object proof; subprocess clients use identical Python bytes."""
import argparse
import array
import ctypes
import errno
import json
import mmap
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid


def client(operation, target):
    try:
        if operation in ('stream', 'seqpacket', 'dgram'):
            kind = {'stream': socket.SOCK_STREAM, 'seqpacket': socket.SOCK_SEQPACKET,
                    'dgram': socket.SOCK_DGRAM}[operation]
            with socket.socket(socket.AF_UNIX, kind) as sock:
                if target.startswith('@'): target='\0'+target[1:]
                if operation == 'dgram': sock.sendto(b'fixture', target)
                else: sock.connect(target)
        elif operation == 'mapping':
            with open(target,'rb') as source, mmap.mmap(source.fileno(),4096,prot=mmap.PROT_READ) as memory:
                print(json.dumps({'mapped':True}),flush=True); sys.stdin.readline()
                child=os.fork()
                if child==0:
                    print(json.dumps({'inherited_byte':memory[0]}),flush=True); os._exit(0)
                os.waitpid(child,0)
                print(json.dumps({'retained_byte':memory[0]})); return
        elif operation == 'open':
            with open(target, 'rb') as stream: stream.read(1)
        elif operation in ('mmap', 'none', 'read'):
            fd = int(target)
            if operation == 'read': os.read(fd, 1)
            else:
                with mmap.mmap(fd, 4096, prot=0 if operation == 'none' else mmap.PROT_READ): pass
        elif operation == 'scm':
            with socket.socket(fileno=int(target)) as sock:
                _, messages, _, _ = sock.recvmsg(16,socket.CMSG_SPACE(4))
                descriptors=[]
                for level,kind,data in messages:
                    if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                        values=array.array('i'); values.frombytes(data); descriptors.extend(values)
                for fd in descriptors: os.close(fd)
                print(json.dumps({'fd_count':len(descriptors)})); return
        elif operation == 'ordinary':
            for _ in range(100):
                with open(target,'rb') as source:
                    with mmap.mmap(source.fileno(),4096,prot=mmap.PROT_READ): pass
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as ip:
                ip.sendto(b'probe',('127.0.0.1',9))
        elif operation == 'splice':
            readfd,writefd=os.pipe()
            try:
                count=os.splice(int(target),writefd,7)
                assert os.read(readfd,count)
            finally: os.close(readfd); os.close(writefd)
        elif operation in ('sendfd', 'recvfd'):
            with socket.socket(fileno=int(target)) as sock:
                if operation == 'sendfd': sock.send(b'fixture')
                else: sock.recv(16)
        else: raise ValueError(operation)
    except OSError as error:
        print(json.dumps({'errno': error.errno}))
        return
    print(json.dumps({'errno': 0}))


def run(args, okay=True, **kwargs):
    result = subprocess.run([str(x) for x in args], text=True, capture_output=True,
                            timeout=30, **kwargs)
    if okay and result.returncode:
        raise AssertionError(f'{args}: {result.stdout}\n{result.stderr}')
    return result


def native_json_test(repo):
    # Private serializer tested without privileged BPF calls or a new public API.
    source=repo/'build/linux/json-path-test.cpp'
    source.write_text(r'''#define main hidden_loader_main
#include "../../src/linux/native/bpf-loader.cpp"
#undef main
int main() {
    std::cout<<json_string(std::string("/valid-\xc3\xa9-invalid-\xff-\xed\xa0\x80-\"-\\-\n"))<<'\n';
}
''')
    executable=source.with_suffix('')
    flags=run(['pkg-config','--cflags','--libs','libbpf']).stdout.split()
    run(['c++','-O2','-std=c++17','-Wall','-Wextra','-Werror',source,'-o',executable,*flags])
    value=json.loads(run([executable]).stdout)
    assert os.fsencode(value)==b'/valid-\xc3\xa9-invalid-\xff-\xed\xa0\x80-"-\\-\n'
    print('PASS native JSON preserves valid UTF-8 and surrogateescape filesystem bytes')


def main():
    parser = argparse.ArgumentParser()
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--client', nargs=2)
    modes.add_argument('--baseline', action='store_true')
    modes.add_argument('--native', action='store_true')
    modes.add_argument('--vm', action='store_true')
    args = parser.parse_args()
    if args.client: return client(*args.client)
    repo = Path(__file__).resolve().parents[2]
    if args.native: return native_json_test(repo)
    if args.vm and (os.geteuid()!=0 or os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM')!='1' or
                   'microsoft' in os.uname().release.lower() or os.uname().nodename=='TV' or
                   not Path('/var/lib/wgps-vm-provisioned').is_file()):
        raise SystemExit('VM mode requires root, explicit disposable VM flag, marker, and native non-TV host')
    work = repo / 'local/validation' / ('resolver-' + uuid.uuid4().hex[:10])
    work.mkdir(parents=True)
    included, direct = work/'included-python', work/'direct-python'
    for path in (included,direct): shutil.copy2(sys.executable,path)
    server_path=work/'resolver.sock'
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(server_path)); server.listen(8)
        output=run([included,__file__,'--client','stream',server_path])
        if args.baseline:
            assert json.loads(output.stdout)['errno']==errno.EACCES, 'RED: selected Unix resolver connect succeeds without guards'
            return
    loader=repo/'build/linux/bpf-loader'
    pins=Path('/sys/fs/bpf')/work.name
    group=Path('/sys/fs/cgroup')/work.name
    sockets=[]; descriptors=[]; mounts=[]; host_dirs=[]; active=False; results=[]; mapped_client=None
    prior_pin=Path('/sys/fs/bpf')/(work.name+'-prior')
    script=Path(__file__).resolve()
    native_env={k:v for k,v in os.environ.items() if k!='WG_CLASSIFIER_DISPOSABLE_VM'}
    def control(*args): return run([loader,*args],env=native_env)
    def check(path,operation,target,expected=errno.EACCES,pass_fds=()):
        result=run([path,script,'--client',operation,target],pass_fds=pass_fds,cwd=work)
        observed=json.loads(result.stdout)
        assert observed.get('errno')==expected,(operation,target,observed,expected)
        return observed
    def passed(name): results.append(name); print('PASS',name,flush=True)
    def add(kind,path): control('guard-slot',pins,kind,path)
    def listen(path,kind=socket.SOCK_STREAM):
        sock=socket.socket(socket.AF_UNIX,kind); sock.settimeout(3)
        sock.bind(str(path))
        if kind!=socket.SOCK_DGRAM: sock.listen(128)
        sockets.append(sock); return sock
    def connect(path):
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); sock.settimeout(3)
        sock.connect(str(path)); sockets.append(sock); return sock
    def transfer(fd,path,expected):
        left,right=socket.socketpair(); sockets.extend((left,right))
        left.sendmsg([b'fd'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
        result=run([path,script,'--client','scm',right.fileno()],pass_fds=(right.fileno(),))
        assert json.loads(result.stdout)=={'fd_count':expected},result.stdout
    def stats():
        return dict(line.split('=',1) for line in control('status',pins).stdout.splitlines() if '=' in line)
    try:
        with tempfile.TemporaryDirectory(prefix=work.name+'-host-',dir='/run') as namespace_test:
            visible_loader=Path(namespace_test)/'loader'; shutil.copy2(loader,visible_loader)
            for namespace in (('--net',),('--user','--map-root-user'),('--pid','--fork','--mount-proc')):
                rejected=run(['unshare',*namespace,visible_loader,'path-add-policy',pins,'/missing-image'],okay=False,env=native_env)
                assert rejected.returncode and ('namespace' in rejected.stderr or 'enrollment context' in rejected.stderr),rejected.stderr
        passed('production host checks reject foreign net/user/PID namespaces before mutation')
        group.mkdir()
        server_path.unlink()
        server=listen(server_path)
        old_client=connect(server_path); old_peer,_=server.accept(); sockets.append(old_peer)
        old_peer.send(b'queued before guard')
        mapped_file=work/'preexisting-cache'; mapped_file.write_bytes(b'z'*4096)
        mapped_client=subprocess.Popen([str(included),str(script),'--client','mapping',str(mapped_file)],
                                       stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        assert mapped_client.stdout.readline().strip()=='{"mapped": true}'
        prior_file=work/'prior-denied'; prior_file.write_bytes(b'p'*4096)
        prior=prior_file.stat(); device=(os.major(prior.st_dev)<<20)|os.minor(prior.st_dev)
        prior_source=work/'prior.bpf.c'
        prior_source.write_text(f'''#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
SEC("lsm/file_open") int BPF_PROG(prior_deny,struct file *file,int ret) {{
 (void)ctx; if (ret) return ret;
 return BPF_CORE_READ(file,f_inode,i_ino)=={prior.st_ino}ULL &&
        BPF_CORE_READ(file,f_inode,i_sb,s_dev)=={device}U ? -1 : 0;
}}
char LICENSE[] SEC("license")="GPL";
''')
        run(['clang','-O2','-g','-target','bpf','-I'+str(repo/'build/linux'),
             '-c',prior_source,'-o',str(prior_source)+'.o'])
        run(['bpftool','prog','load',str(prior_source)+'.o',prior_pin,'autoattach'])
        future=work/'future-image'; redirected=work/'stored-symlink'; redirected.symlink_to(direct)
        result=control('load-policy',repo/'build/linux/classifier.bpf.o',pins,group,'0x00ff0000','0x00010000',included,future,redirected)
        active=True; (work/'verifier.log').write_text(result.stderr)
        interpreter=Path(sys.executable).resolve(); control('path-add',pins,interpreter)
        try: assert json.loads(control('probe-dns',pins).stdout)=={'dns':True}
        finally: control('path-del',pins,interpreter)
        passed('native marked DNS probe works while the Python interpreter is selected and policy blocked')
        check(included,'open',prior_file,errno.EPERM); check(direct,'open',prior_file,errno.EPERM)
        passed('preexisting global LSM denial is preserved for selected and unlisted access')
        add('socket',server_path)
        check(included,'stream',server_path); check(direct,'stream',server_path,0)
        passed('actual-peer stream deny for selected while blocked; unlisted allowed')
        expected=sorted(map(str,(included,future,redirected)))
        assert json.loads(control('policy',pins).stdout)==expected
        snapshot=json.loads(control('snapshot',pins).stdout)
        assert snapshot['abi']==2 and snapshot['ready'] is False
        assert len(snapshot['maps'])==12 and len(snapshot['links'])==12
        assert snapshot['mask']==0x00ff0000 and snapshot['mark']==0x00010000
        foreign=pins/'unexpected'
        run(['bpftool','map','pin','id',snapshot['maps']['paths'],foreign])
        try:
            rejected=run([loader,'snapshot',pins],okay=False)
            assert rejected.returncode and 'unknown' in rejected.stderr
        finally: foreign.unlink()
        assert all(v['id']>0 and v['program_id']>0 for v in snapshot['links'].values())
        shutil.copy2(direct,future); check(future,'stream',server_path)
        redirected.unlink(); shutil.copy2(direct,redirected); check(redirected,'stream',server_path)
        control('path-del',pins,redirected)
        assert json.loads(control('policy',pins).stdout)==sorted(map(str,(included,future)))
        pending=work/'pending-image'
        control('path-add-policy',pins,pending)
        assert str(pending) in json.loads(control('policy',pins).stdout)
        shutil.copy2(direct,pending); check(pending,'stream',server_path)
        control('path-del',pins,pending)
        passed('stored policy survives missing/symlink images; JSON readback reports exact owned state')
        add('cache',mapped_file)
        output,errors=mapped_client.communicate('go\n',timeout=10)
        assert mapped_client.returncode==0,(output,errors)
        assert [json.loads(line) for line in output.splitlines()]==[{'inherited_byte':122},{'retained_byte':122}]
        passed('readiness boundary: pre-enrollment mapping and forked copy remain readable and require restart')
        # Exact peer resolution ignores caller aliases.
        aliases=[server_path,Path(str(server_path).replace(str(work),'.',1)),
                 Path('/proc/self/root')/str(server_path).lstrip('/')]
        symlink=work/'socket-link'; symlink.symlink_to(server_path); aliases.append(symlink)
        hardlink=work/'socket-hardlink'; os.link(server_path,hardlink); aliases.append(hardlink)
        bound=work/'socket-bind'; bound.touch(); run(['mount','--bind',server_path,bound]); mounts.append(bound); aliases.append(bound)
        for alias in aliases:
            check(included,'stream',alias); check(direct,'stream',alias,0)
        passed('absolute/relative/symlink/hard-link/bind/proc-root endpoint aliases')
        for kind,operation in ((socket.SOCK_SEQPACKET,'seqpacket'),(socket.SOCK_DGRAM,'dgram')):
            path=work/operation; listen(path,kind); add('socket',path)
            check(included,operation,path); check(direct,operation,path,0)
        passed('actual-peer seqpacket and unconnected datagram denial')
        # Missing endpoint and daemon unlink/rebind are covered by configured slot.
        late=work/'late.sock'; add('socket',late); late_server=listen(late)
        check(included,'stream',late); check(direct,'stream',late,0)
        renamed=work/'renamed.sock'; late.rename(renamed)
        check(included,'stream',renamed)
        late_server.close(); renamed.unlink(); listen(late)
        check(included,'stream',late)
        passed('missing-then-created, bound socket rename and daemon unlink/rebind')
        bind_dir=work/'bind-canonical'; bind_dir.mkdir()
        bind_alias=work/'bind-alias'; bind_alias.symlink_to(bind_dir,target_is_directory=True)
        add('socket',bind_dir/'socket')
        listen(bind_alias/'socket')
        (bind_dir/'socket').rename(bind_dir/'moved-before-connect')
        check(included,'stream',bind_dir/'moved-before-connect')
        passed('server binding through directory alias then renaming before first client remains protected')
        exchange=bind_dir/'exchange'; destination=bind_dir/'destination'; add('socket',exchange)
        listen(bind_alias/'exchange'); listen(destination)
        libc=ctypes.CDLL(None,use_errno=True)
        assert libc.renameat2(-100,os.fsencode(destination),-100,os.fsencode(exchange),2)==0,ctypes.get_errno()
        check(included,'stream',destination); check(included,'stream',exchange)
        passed('rename exchange keeps both moved protected endpoint objects guarded')
        check(included,'sendfd',old_client.fileno(),pass_fds=(old_client.fileno(),))
        check(included,'recvfd',old_client.fileno(),pass_fds=(old_client.fileno(),))
        check(direct,'sendfd',old_client.fileno(),0,pass_fds=(old_client.fileno(),))
        splice_path=work/'splice.sock'; splice_server=listen(splice_path); add('socket',splice_path)
        splice_client=connect(splice_path); splice_peer,_=splice_server.accept(); sockets.append(splice_peer)
        splice_peer.send(b'queued splice data')
        check(included,'splice',splice_client.fileno(),pass_fds=(splice_client.fileno(),))
        check(direct,'splice',splice_client.fileno(),0,pass_fds=(splice_client.fileno(),))
        passed('selected splice of queued protected stream is denied; unlisted splice allowed')
        passed('pre-guard inherited stream and queued reply denied for selected; unlisted preserved')
        connected=connect(server_path); peer,_=server.accept(); sockets.append(peer)
        check(included,'sendfd',connected.fileno(),pass_fds=(connected.fileno(),))
        transfer(connected.fileno(),included,0); transfer(connected.fileno(),direct,1)
        passed('post-guard protected stream survives exec/SCM transfer as protected role')
        other=work/'ordinary.sock'; ordinary_server=listen(other); ordinary=connect(other)
        check(included,'sendfd',ordinary.fileno(),0,pass_fds=(ordinary.fileno(),))
        passed('unrelated post-guard stream retains ordinary selected functionality')
        add('socket',other)
        check(included,'sendfd',ordinary.fileno(),pass_fds=(ordinary.fileno(),))
        passed('new protected endpoint enrollment invalidates older safe stream roles')
        failing=work/'failed-enrollment.sock'; failing_server=listen(failing)
        failing_client=connect(failing); failing_peer,_=failing_server.accept(); sockets.append(failing_peer)
        check(included,'sendfd',failing_client.fileno(),0,pass_fds=(failing_client.fileno(),))
        failing.unlink(); failing.touch()
        rejected=run([loader,'guard-slot',pins,'socket',failing],okay=False)
        assert rejected.returncode and 'wrong file type' in rejected.stderr
        check(included,'sendfd',failing_client.fileno(),pass_fds=(failing_client.fileno(),))
        check(direct,'sendfd',failing_client.fileno(),0,pass_fds=(failing_client.fileno(),))
        passed('partially failed guard enrollment invalidates earlier SAFE streams')

        target=work/'protected-destination'; add('socket',target)
        source=work/'unprotected-source'; listen(source); moving=connect(source)
        source.rename(target)
        check(included,'sendfd',moving.fileno(),pass_fds=(moving.fileno(),))
        passed('moving a safe endpoint into a protected slot invalidates old connected stream roles')
        pair_path=work/'named-pair'; add('socket',pair_path)
        one,two=socket.socketpair(); sockets.extend((one,two)); one.bind(str(pair_path))
        check(included,'sendfd',two.fileno(),pass_fds=(two.fileno(),))
        passed('binding a previously unnamed safe socketpair invalidates both endpoint roles')
        cache=work/'hosts-cache'; cache.write_bytes(b'h'*4096)
        cachefd=os.open(cache,os.O_RDONLY); descriptors.append(cachefd); add('cache',cache)
        aliases=[cache,Path('/proc/self/root')/str(cache).lstrip('/')]
        link=work/'cache-hardlink'; os.link(cache,link); aliases.append(link)
        link=work/'cache-symlink'; link.symlink_to(cache); aliases.append(link)
        for path in aliases:
            check(included,'open',path); check(direct,'open',path,0)
        cache.rename(work/'cache-renamed'); check(included,'open',work/'cache-renamed')
        for op in ('mmap','none','read'):
            check(included,op,cachefd,pass_fds=(cachefd,)); check(direct,op,cachefd,0,pass_fds=(cachefd,))
        transfer(cachefd,included,0); transfer(cachefd,direct,1)
        passed('cache inode aliases/rename, inherited read/mmap/PROT_NONE and SCM_RIGHTS guarded')
        private=work/'nscd-private'; private.mkdir(); add('cache-dir',private)
        temporary=private/'dbABC123'; temporary.write_bytes(b't'*4096)
        fd=os.open(temporary,os.O_RDONLY); descriptors.append(fd); temporary.unlink()
        for op in ('read','mmap','none'): check(included,op,fd,pass_fds=(fd,))
        transfer(fd,included,0)
        passed('newly created then unlinked nscd-style temporary database retains inode label')
        # Native standard slots: no custom guard-slot enrollment for these.
        for path in ('/run/systemd/resolve/io.systemd.Resolve','/run/dbus/system_bus_socket',
                     '/run/user/1000/bus'):
            assert Path(path).exists(),f'reference VM endpoint absent: {path}'
            check(included,'stream',path); check(direct,'stream',path,0)
        passed('real resolved Varlink, system bus and user bus connects selected-denied/unlisted-allowed')
        for directory in ('/run/nscd','/run/avahi-daemon','/var/cache/nscd','/run/user/99996'):
            directory=Path(directory)
            assert not directory.exists(),f'requires absent test-owned standard directory: {directory}'
            directory.mkdir(); host_dirs.append(directory)
        os.chown('/run/user/99996',99996,99996)
        run(['mount','-t','tmpfs','-o','mode=0700,uid=99996,gid=99996','tmpfs','/run/user/99996'])
        mounts.append(Path('/run/user/99996'))
        for path in ('/run/nscd/socket','/run/avahi-daemon/socket','/run/user/99996/bus'):
            listen(path); check(included,'stream',path); check(direct,'stream',path,0)
        dynamic=Path('/var/cache/nscd/dbXYZ123'); dynamic.write_bytes(b'd'*4096)
        dynamicfd=os.open(dynamic,os.O_RDONLY); descriptors.append(dynamicfd); dynamic.unlink()
        check(included,'mmap',dynamicfd,pass_fds=(dynamicfd,))
        passed('late standard nscd/Avahi/user bus directories and unlinked cache covered by ancestor rules')
        abstract='@'+work.name
        abstract_server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        abstract_server.bind('\0'+abstract[1:]); abstract_server.listen(8); sockets.append(abstract_server)
        add('abstract',abstract)
        check(included,'stream',abstract); check(direct,'stream',abstract,0)
        passed('abstract namespace endpoint matches exact byte length and name')
        plain=work/'plain'; plain.write_bytes(b'p'*4096)
        before=int(stats()['guard_path_lookups'])
        check(included,'ordinary',plain,0)
        after=int(stats()['guard_path_lookups'])
        assert before==after,(before,after)
        passed('100 ordinary open/mmap operations and IP payload send perform zero guard executable lookups')
        # Fault-injected crash epoch: no SAFE classification can survive an
        # incomplete update; direct clients retain working unrelated IPC.
        crash=work/'during-update.sock'; listen(crash)
        raw=run(['bpftool','-j','map','lookup','pinned',pins/'guard_config','key','hex','00','00','00','00']).stdout
        epoch=int.from_bytes(bytes(int(v,16) for v in json.loads(raw)['value']),'little')
        def set_epoch(value):
            run(['bpftool','map','update','pinned',pins/'guard_config','key','hex','00','00','00','00',
                 'value','hex',*(f'{x:02x}' for x in value.to_bytes(8,'little'))])
        set_epoch(epoch+1)
        check(included,'stream',crash); check(direct,'stream',crash,0)
        interrupted=run([loader,'state',pins,'ready'],okay=False)
        assert interrupted.returncode and 'incomplete' in interrupted.stderr
        set_epoch(epoch+2)
        check(included,'stream',crash,0)
        passed('interrupted odd guard epoch denies selected SAFE use and readiness; unlisted IPC stays healthy')
        # Protection is active independently of socket/network ready flag.
        control('state',pins,'ready'); check(included,'stream',server_path)
        changed=run([loader,'guard-slot',pins,'socket',other],okay=False)
        assert changed.returncode and 'blocked' in changed.stderr
        passed('guard link verification gates ready; guard changes require blocked state')
        (work/'status.txt').write_text(control('status',pins).stdout)
        (work/'links.json').write_text(run(['bpftool','-j','link','show']).stdout)
    finally:
        if mapped_client and mapped_client.poll() is None:
            mapped_client.kill(); mapped_client.communicate(timeout=10)
        for fd in descriptors: os.close(fd)
        for sock in sockets: sock.close()
        for mount in reversed(mounts): run(['umount',mount])
        for directory in reversed(host_dirs):
            for path in directory.iterdir(): path.unlink()
            directory.rmdir()
        if active: control('remove',pins)
        if prior_pin.exists(): prior_pin.unlink()
        if group.exists(): group.rmdir()
        (work/'results.json').write_text(json.dumps(results,indent=2))
        (work/'links-after.json').write_text(run(['bpftool','-j','link','show']).stdout)
        print('Evidence:',work,flush=True)


if __name__ == '__main__': main()
