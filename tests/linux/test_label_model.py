# SPDX-License-Identifier: GPL-3.0-or-later
"""Exhaustive interleaving model of the resolver guard's stream-label state machine.

Invariant enforced by the BPF programs: a SAFE label stamped with generation g
is stored only by a relabel that read g before resolving both ends, and only
for a socket whose (write-once) peer is already published; every operation
that can make an end's identity protected advances the generation after its
effect is visible (bind, rename). guard_connect labels the connecting socket
from its real peer before publication, so a racing relabel of the still
unconnected socket decides per call and stores nothing that could replace it. A rename's
destination role is held only while the rename runs; only an object's current
or former slot role is ever committed. Every program that caches a label or a
"no role" answer is attached after, and removed before, the programs that
invalidate it.

The model keeps the BPF atomicity: the generation, a label word, a peer
pointer, an address, a directory name and an inode label are each one atomic
access, and a relabel resolves its own end and then its peer with separate
reads. It explores every interleaving of a bounded scenario and checks:
  safety:   a selected send that starts and ends with no identity-changing
            operation in flight never passes while its peer's current
            identity is protected (a stream reaches a resolver through its
            peer; an end's own address only matters for an accepted child,
            whose address is its listener's, and the guard checks it too);
  liveness: once every operation has returned, a selected send on a connected
            end whose ends were never at a protected location passes without
            an unrelated invalidation (an object once at a protected location
            may stay protected: positive inode labels are sticky by design).
A load interrupted after any prefix of the attach order is modelled by the set
of attached programs. Earlier designs are modelled too and must fail on the
interleavings that broke them.
"""
from dataclasses import dataclass, replace
import itertools
import unittest

OLD_ORDER = ('connect', 'pair', 'send', 'rename', 'bind', 'bound', 'renamed')
NEW_ORDER = ('bound', 'renamed', 'rename', 'connect', 'pair', 'send', 'bind')
EVERYTHING = frozenset(OLD_ORDER + NEW_ORDER)


@dataclass(frozen=True)
class Design:
    bind_pre: str = ''         # '', 'safe-bump' (round 3), 'pending' (round 4)
    dir_pre: str = ''          # '', 'bump' (round 1), 'label' (rounds 2 to 4)
    object_pre: str = 'commit' # destination role: 'commit' (to round 5), 'ticket' (round 6), or 'release'
    post: bool = False         # bind and rename advance the generation after the effect
    safe_needs_peer: bool = False  # SAFE is cached only once the peer is published
    drain: bool = False        # nothing is cached until pre-attachment calls drained
    complete_walks: bool = True  # settling needs a complete, reliable walk of each task
    order: tuple = OLD_ORDER


ROUND1 = Design(bind_pre='safe-bump', dir_pre='bump')
ROUND3 = Design(bind_pre='safe-bump', dir_pre='label')
ROUND4 = Design(bind_pre='pending', dir_pre='label')
ROUND5 = Design(post=True)
ROUND6 = Design(object_pre='ticket', post=True, safe_needs_peer=True, order=NEW_ORDER)
ROUND7 = Design(object_pre='release', post=True, safe_needs_peer=True, order=NEW_ORDER)
FIXED = Design(object_pre='release', post=True, safe_needs_peer=True, drain=True, order=NEW_ORDER)
# Round 8 counted an empty, refused (running) or truncated walk as clean, and
# round 9 an early-stopped walk or one the task overlapped by running and
# stopping again, so either could settle while a pre-attachment call ran.
ROUND8 = Design(object_pre='release', post=True, safe_needs_peer=True, drain=True, complete_walks=False,
                order=NEW_ORDER)
INVALIDATORS = {'bind': 'bound', 'directory': 'renamed', 'move': 'renamed', 'exchange': 'renamed'}
TICKET_MASK = 0x3fff  # Round 6 kept 14 bits of the generation in the inode label.
STALE = 'stale'


def put(mapping, key, value):
    return tuple((k, value if k == key else v) for k, v in mapping)


def get(mapping, key):
    return dict(mapping)[key]


@dataclass(frozen=True)
class World:
    generation: int = 0
    labels: tuple = ()        # socket -> None, STALE or (stamp, safe)
    peers: tuple = ()         # socket -> peer socket or None
    bound: tuple = ()         # socket -> None, 'ordinary', 'slot' or 'dir'
    committed: tuple = ()     # socket -> committed inode role
    held: tuple = ()          # socket -> None, or a held role: True, or round 6's 14-bit ticket
    ever: tuple = ()          # socket -> was ever at a protected location (ground truth)
    pending: tuple = ()       # socket -> round 4 bind marker
    directory: str = 'stage'  # 'final' is a standard name
    directory_label: bool = False
    inflight: int = 0
    started: int = 0
    active: frozenset = None  # Attached programs when a scenario attaches them mid-way.
    settled: bool = True      # GUARD_SETTLED: false until the drain proof passed
    unobserved: int = 0       # identity operations in flight that entered before their fexit attached


def at_protected(world, socket, location=None):
    location = get(world.bound, socket) if socket is not None and location is None else location
    return location == 'slot' or (location == 'dir' and world.directory == 'final')


def protected_now(world, socket):
    return socket is not None and at_protected(world, socket)


def mark_ever(world):
    ever = tuple((s, e or at_protected(world, s)) for s, e in world.ever)
    return replace(world, ever=ever)


# Operations are explicit state machines: step(world, local) -> (world, local);
# local ('done', result) ends the operation. One step is one atomic action.

def send_step(design, attached, end, world, local):
    pc = local[0]
    if pc == 'start':
        if 'send' not in attached:
            return world, ('done', True, False, world.started)
        return world, ('label', world.generation, world.inflight == 0, world.started)
    stamp, judged, started = local[1:4]
    if pc == 'label':
        label = get(world.labels, end)
        if label not in (None, STALE) and label[0] == stamp:
            return world, ('done', label[1], judged, started)
        return world, ('peer', stamp, judged, started)
    if pc == 'peer':
        peer = get(world.peers, end)
        return world, ('resolve', stamp, judged, started, peer, end, 0, False)
    peer, who, index, found = local[4:8]
    if pc == 'resolve':
        world, found, finished = resolve(design, world, who, index, found)
        if not finished:
            return world, ('resolve', stamp, judged, started, peer, who, index + 1, found)
        if not found and who == end and peer is not None:
            return world, ('resolve', stamp, judged, started, peer, peer, 0, False)
        return world, ('store', stamp, judged, started, peer, who, 0, found)
    if pc == 'store':
        safe = not found
        if (safe and peer is None and design.safe_needs_peer) or not caching(design, world):
            return world, ('done', safe, judged, started)  # Decided for this call only.
        return replace(world, labels=put(world.labels, end, (stamp, safe))), ('done', safe, judged, started)
    raise AssertionError(local)


def resolve(design, world, socket, index, found):
    """One atomic read of socket's identity; returns (world, protected, finished)."""
    step = ('known', 'pending', 'location', 'name', 'directory-label', 'commit')[index]
    if step == 'known':
        held = get(world.held, socket)
        if design.object_pre == 'ticket':  # The same masked comparison as round 6's BPF.
            holding = held is not None and (world.generation & TICKET_MASK) == held
        else:
            holding = held is True
        return world, get(world.committed, socket) or holding, False
    if found == 'commit':  # label_inode: a computed role is committed to the inode.
        return replace(world, committed=put(world.committed, socket, True)), True, True
    if found:
        return world, True, True
    if step == 'pending':
        marked = design.bind_pre == 'pending' and get(world.pending, socket)
        return world, marked and get(world.bound, socket) is None, False
    if step == 'location':
        location = get(world.bound, socket)
        if location in (None, 'ordinary'):
            return world, False, True
        return world, False, False
    if step == 'name':
        location = get(world.bound, socket)
        if location == 'slot' or world.directory == 'final':
            return world, 'commit', False
        return world, False, design.dir_pre != 'label'
    if step == 'directory-label':
        return world, world.directory_label, True
    raise AssertionError(step)


def caching(design, world):
    return world.settled or not design.drain


def bump(world):
    return replace(world, generation=world.generation + 1)


def begin(world):
    return replace(world, inflight=world.inflight + 1, started=world.started + 1)


def finish(world):
    return replace(world, inflight=world.inflight - 1), ('done', None)


def bind_step(design, attached, end, kind, world, local):
    pc = local[0]
    if pc == 'start':
        world = begin(world)
        return world, ('read',) if design.bind_pre and 'bind' in attached else ('effect',)
    if pc == 'read':
        label = get(world.labels, end)
        if design.bind_pre == 'safe-bump':
            return world, ('bump',) if label not in (None, STALE) and label[1] else ('effect',)
        return world, ('effect',) if label not in (None, STALE) and not label[1] else ('mark',)
    if pc == 'mark':
        return replace(world, pending=put(world.pending, end, True)), ('bump',)
    if pc == 'bump':
        return bump(world), ('effect',)
    if pc == 'effect':
        succeeded = kind != 'fail' and get(world.bound, end) is None
        if succeeded:
            world = mark_ever(replace(world, bound=put(world.bound, end, kind)))
        return world, ('post',) if succeeded and design.post and 'bound' in attached else ('finish',)
    if pc == 'post':
        return bump(world), ('finish',)
    if pc == 'finish':
        return finish(world)
    raise AssertionError(local)


def directory_step(design, attached, destination, world, local):
    pc = local[0]
    if pc == 'start':
        world = begin(world)
        if 'rename' in attached and design.dir_pre == 'bump':
            return world, ('bump',)
        if 'rename' in attached and design.dir_pre == 'label':
            return world, ('label',)
        return world, ('effect',)
    if pc == 'label':
        return replace(world, directory_label=destination == 'final'), ('bump',)
    if pc == 'bump':
        return bump(world), ('effect',)
    if pc == 'effect':
        world = mark_ever(replace(world, directory=destination))
        return world, ('post',) if design.post and 'renamed' in attached else ('finish',)
    if pc == 'post':
        return bump(world), ('finish',)
    if pc == 'finish':
        return finish(world)
    raise AssertionError(local)


def rename_step(design, attached, operation, world, local):
    """A rename of bound sockets' files: ('move', socket, destination, fails) or
    ('exchange', old, new, fails). The hook runs once per moving participant
    (for an exchange first for new, then for old, as security_inode_rename
    does); 'forward' is the destination of old, which round 6 examined."""
    kind, first, second, fails = operation
    pc = local[0]
    if pc == 'start':
        if kind == 'move':
            moves = ((first, second),)
        else:
            moves = ((second, get(world.bound, first)), (first, get(world.bound, second)))
        return begin(world), ('source', moves, 0)
    if pc == 'post':
        return bump(world), ('finish',)
    if pc == 'finish':
        return finish(world)
    moves = local[1]
    if pc == 'source':
        # The rename hook runs inside vfs_rename, after entry: it applies if
        # attached by now, even for a call that entered before attachment.
        if 'rename' not in attached:
            return world, ('effect', moves)
        socket, destination = moves[local[2]]
        # The current role is committed before the name can disappear.
        if at_protected(world, socket):
            world = replace(world, committed=put(world.committed, socket, True))
        return world, ('target', moves, local[2])
    if pc == 'target':
        socket, destination = moves[local[2]]
        following = ('source', moves, local[2] + 1) if local[2] + 1 < len(moves) else ('effect', moves)
        if not at_protected(world, socket, destination):
            return world, following
        if design.object_pre == 'commit':
            return replace(world, committed=put(world.committed, socket, True)), following
        if not caching(design, world):
            return world, following  # Unsettled: nothing is held.
        return bump(world), ('hold', moves, local[2])
    if pc == 'hold':
        socket, _ = moves[local[2]]
        held = world.generation & TICKET_MASK if design.object_pre == 'ticket' else True
        following = ('source', moves, local[2] + 1) if local[2] + 1 < len(moves) else ('effect', moves)
        return replace(world, held=put(world.held, socket, held)), following
    if pc == 'effect':
        succeeded = not fails and all(get(world.bound, socket) is not None for socket, _ in moves)
        if succeeded:
            for socket, destination in moves:
                world = replace(world, bound=put(world.bound, socket, destination))
            world = mark_ever(world)
        if not (design.post and 'renamed' in attached):
            return world, ('finish',)
        if design.object_pre == 'release':
            return world, ('release', moves, 0, False, succeeded)
        forward = moves[-1][1]
        invalidate = at_protected(world, None, forward) or succeeded
        return world, ('post',) if invalidate else ('finish',)
    if pc == 'release':
        # guard_renamed retires what each participant held, success or failure.
        index, released, succeeded = local[2:5]
        socket, _ = moves[index]
        released = released or get(world.held, socket) is not None
        world = replace(world, held=put(world.held, socket, None))
        if index + 1 < len(moves):
            return world, ('release', moves, index + 1, released, succeeded)
        return world, ('post',) if released or succeeded else ('finish',)
    raise AssertionError(local)


def advance_step(design, attached, count, world, local):
    """count unrelated invalidations, such as pathname binds elsewhere."""
    return replace(world, generation=world.generation + count), ('done', None)


def connect_step(design, attached, client, listener, fails, world, local):
    pc = local[0]
    if pc == 'start':
        world = begin(world)
        if 'connect' not in attached:
            return world, ('effect',)
        return world, ('resolve', world.generation, 0, False)
    if pc == 'resolve':
        stamp, index, found = local[1:4]
        world, found, finished = resolve(design, world, listener, index, found)
        if not finished:
            return world, ('resolve', stamp, index + 1, found)
        return world, ('store', stamp, 0, found)
    if pc == 'store':
        stamp, _, found = local[1:4]
        if not caching(design, world):
            return world, ('effect',)
        return replace(world, labels=put(world.labels, client, (stamp, not found))), ('effect',)
    if pc == 'effect':
        if not fails and get(world.peers, client) is None:
            world = replace(world, peers=put(world.peers, client, listener))
        return world, ('finish',)
    if pc == 'finish':
        return finish(world)
    raise AssertionError(local)


def unlink_step(design, attached, socket, world, local):
    """Unlinking a bound socket's name keeps its dentry, name and identity."""
    return world, ('done', None)


def attach_step(design, attached, world, local):
    return replace(world, active=frozenset(design.order)), ('done', None)


def settle_step(design, attached, world, local):
    """The loader's drain proof: possible only once no identity operation that
    entered before its completion program attached is still running.

    The model takes that proof as given for the fixed design; the loader
    earns it per task only from a walk taken while the task did not run (off
    CPU at both reads, switch count unchanged) that reached a stack bottom (the
    outermost frame is in the entry text) below the depth cap. A design that
    accepts any other walk (rounds 8 and 9: running, empty, truncated or
    early-stopped walks) may settle with such an operation in flight."""
    if design.drain and world.unobserved and design.complete_walks:
        return world, local  # Not yet: scan again later.
    return bump(replace(world, settled=True)), ('done', None)


def step(design, attached, operation, world, local):
    attached = world.active if world.active is not None else attached
    kind = operation[0]
    if kind in INVALIDATORS:
        # fexit runs only for calls that entered after it attached.
        if local == ('start',):
            observed = INVALIDATORS[kind] in attached
            world = replace(world, unobserved=world.unobserved + (not observed))
            inner = ('start',)
        else:
            inner, observed = local
        effective = attached if observed else attached - {INVALIDATORS[kind]}
        world, inner = operation_step(design, effective, operation, world, inner)
        if inner[0] == 'done':
            return replace(world, unobserved=world.unobserved - (not observed)), inner
        return world, (inner, observed)
    return operation_step(design, attached, operation, world, local)


def operation_step(design, attached, operation, world, local):
    kind, arguments = operation[0], operation[1:]
    if kind in ('move', 'exchange'):
        return rename_step(design, attached, operation, world, local)
    machine = {'send': send_step, 'bind': bind_step, 'directory': directory_step,
               'connect': connect_step, 'unlink': unlink_step, 'advance': advance_step,
               'attach': attach_step, 'settle': settle_step}[kind]
    return machine(design, attached, *arguments, world, local)


def run_alone(design, attached, world, operation):
    local = ('start',)
    while local[0] != 'done':
        world, local = step(design, attached, operation, world, local)
    return world, local


class Violation(AssertionError):
    pass


def initial(design, attached, setup, directory):
    if setup.startswith('transition-'):
        # The guard is not attached yet: no labels, no hooks, not settled.
        world = initial(design, frozenset(), setup.split('-', 1)[1], directory)
        return replace(world, active=frozenset(), settled=False,
                       labels=tuple((socket, None) for socket, _ in world.labels))
    """'pair': A and B from socketpair. 'client': A unconnected, L bound at a
    location. 'exchange': A unconnected, L ordinary and S at a slot."""
    if setup == 'pair':
        sockets, peers = ('A', 'B'), (('A', 'B'), ('B', 'A'))
        label = (0, True) if 'pair' in attached else None
        labels = (('A', label), ('B', label))
        bound = (('A', None), ('B', None))
    elif setup == 'exchange':
        # A connects to L (ordinary); S is bound at a protected slot.
        sockets, peers = ('A', 'L', 'S'), (('A', None), ('L', None), ('S', None))
        labels = (('A', None), ('L', None), ('S', None))
        bound = (('A', None), ('L', 'ordinary'), ('S', 'slot'))
    else:
        kind = setup.split(':')[1]
        sockets, peers = ('A', 'L'), (('A', None), ('L', None))
        labels = (('A', None), ('L', None))
        bound = (('A', None), ('L', kind))
    world = World(labels=labels, peers=peers, bound=bound,
                  committed=tuple((s, False) for s in sockets), held=tuple((s, None) for s in sockets),
                  ever=tuple((s, False) for s in sockets), pending=tuple((s, False) for s in sockets),
                  directory=directory)
    return mark_ever(world)


def explore(design, scenario, attached=EVERYTHING):
    setup, prelude, programs, directory = scenario
    world = initial(design, attached, setup, directory)
    for operation in prelude:
        world, _ = run_alone(design, attached, world, operation)
    start = (world, tuple((0, ('start',)) for _ in programs))
    seen, stack = {start}, [start]
    while stack:
        world, threads = stack.pop()
        finished = True
        for index, (position, local) in enumerate(threads):
            program = programs[index]
            if position == len(program):
                continue
            finished = False
            operation = program[position]
            after, result = step(design, attached, operation, world, local)
            if result[0] == 'done':
                if operation[0] == 'send':
                    passed, judged, started = result[1:4]
                    end = operation[1]
                    if (passed and judged and after.inflight == 0 and after.started == started and
                            protected_now(after, get(after.peers, end))):
                        raise Violation(f'selected send on {end} passed with a protected peer')
                moved = (position + 1, ('start',))
            else:
                moved = (position, result)
            state = (after, threads[:index] + (moved,) + threads[index + 1:])
            if state not in seen:
                seen.add(state)
                stack.append(state)
        if finished and 'send' in attached:
            for end, peer in world.peers:
                if peer is None:
                    continue
                _, result = run_alone(design, attached, world, ('send', end))
                if protected_now(world, peer):
                    if result[1]:
                        raise Violation(f'quiescent selected send on {end} passed with a protected peer')
                elif not (get(world.ever, end) or get(world.ever, peer)) and not result[1]:
                    raise Violation(f'quiescent selected send on {end} is refused; no end was ever protected')
    return len(seen)


def prefixes(order):
    return [frozenset(order[:count]) for count in range(len(order) + 1)]


SEND_A, SEND_B = ('send', 'A'), ('send', 'B')
INTO, OUT_OF = ('directory', 'final'), ('directory', 'stage')

# Interleavings that defeated earlier designs: (setup, prelude, threads, directory).
FINDINGS = {
    'round 1: rename into a standard name races a relabel':
        (ROUND1, EVERYTHING, ('pair', (('bind', 'A', 'dir'), SEND_B), ((INTO,), (SEND_B, SEND_B)), 'stage')),
    'round 3: bind to a protected slot races a relabel':
        (ROUND3, EVERYTHING, ('pair', (), ((('bind', 'A', 'slot'),), (SEND_B, SEND_B)), 'stage')),
    'round 4: a protected peer label skips a later protected bind':
        (ROUND4, EVERYTHING, ('pair', (), ((('bind', 'A', 'ordinary'), SEND_A, ('bind', 'B', 'slot'), SEND_A),
                                           (SEND_B,)), 'stage')),
    'round 4: an ordinary bind leaves a cached provisional refusal':
        (ROUND4, EVERYTHING, ('pair', (), ((('bind', 'A', 'ordinary'),), (SEND_B,)), 'stage')),
    'round 5: a connect publishes a protected peer under a racing SAFE relabel':
        (ROUND5, EVERYTHING, ('client:slot', (), ((SEND_A, SEND_A), (('connect', 'A', 'L', False),)), 'stage')),
    'round 5: an interrupted load caches labels without its invalidators':
        (ROUND5, frozenset(OLD_ORDER[:OLD_ORDER.index('bind') + 1]),
         ('pair', (), ((('bind', 'A', 'slot'), SEND_B),), 'stage'),
         frozenset(NEW_ORDER[:NEW_ORDER.index('bind') + 1])),
    'round 6: a failed rename is held again when the 14-bit ticket wraps':
        (ROUND6, EVERYTHING, ('client:ordinary', (('connect', 'A', 'L', False), ('move', 'L', 'slot', True),
                                                  ('advance', TICKET_MASK)), ((SEND_A,),), 'stage')),
    'round 6: a failed exchange leaves the ordinary participant held':
        (ROUND6, EVERYTHING, ('exchange', (('connect', 'A', 'L', False),),
                              ((('exchange', 'S', 'L', True),), (SEND_A,)), 'stage')),
    'round 7: a bind entered before attachment completes unobserved under a cached label':
        (ROUND7, EVERYTHING, ('transition-pair', (), ((('bind', 'A', 'slot'),), (('attach',), ('settle',)),
                                                      (SEND_B, SEND_B)), 'stage')),
    'rounds 8 and 9: an unproven stack walk settles while a pre-attachment bind runs':
        (ROUND8, EVERYTHING, ('transition-pair', (), ((('bind', 'A', 'slot'),), (('attach',), ('settle',)),
                                                      (SEND_B, SEND_B)), 'stage')),
    'round 7: a rename entered before attachment holds a role nothing releases':
        (ROUND7, EVERYTHING, ('transition-client:ordinary', (('connect', 'A', 'L', False),),
                              ((('move', 'L', 'slot', True),), (('attach',), ('settle',)), (SEND_A,)), 'stage')),
    'round 5: a failed rename into a slot leaves its socket protected':
        (ROUND5, EVERYTHING, ('client:ordinary', (('connect', 'A', 'L', False),),
                              ((('move', 'L', 'slot', True),), (SEND_A,)), 'stage')),
}


def scenarios(operations_for, setups, sizes=(1, 2, 3)):
    for setup, prelude, directory in setups:
        operations = operations_for(setup)
        for count in sizes:
            for chosen in itertools.product(operations, repeat=count):
                if not any(operation[0] == 'send' for operation in chosen):
                    continue
                for cuts in itertools.product((False, True), repeat=count - 1):
                    programs, current = [], [chosen[0]]
                    for operation, cut in zip(chosen[1:], cuts):
                        if cut:
                            programs.append(tuple(current)); current = []
                        current.append(operation)
                    programs.append(tuple(current))
                    yield setup, prelude, tuple(programs), directory


def operations_for(setup):
    if setup == 'exchange':
        return (SEND_A, ('connect', 'A', 'L', False), ('exchange', 'S', 'L', False), ('exchange', 'S', 'L', True),
                ('exchange', 'L', 'S', False), ('exchange', 'L', 'S', True), ('move', 'L', 'slot', True),
                ('advance', 1))
    if setup == 'pair':
        return (SEND_A, SEND_B, ('bind', 'A', 'ordinary'), ('bind', 'A', 'slot'), ('bind', 'A', 'dir'),
                ('bind', 'A', 'fail'), ('bind', 'B', 'slot'), INTO, OUT_OF, ('move', 'A', 'slot', False),
                ('move', 'A', 'ordinary', False), ('move', 'A', 'slot', True), ('unlink', 'A'))
    return (SEND_A, ('connect', 'A', 'L', False), ('connect', 'A', 'L', True), INTO, OUT_OF,
            ('move', 'L', 'slot', False), ('move', 'L', 'ordinary', False), ('move', 'L', 'slot', True),
            ('bind', 'A', 'slot'), ('unlink', 'L'))


SETUPS = (('pair', (), 'stage'), ('pair', (('bind', 'A', 'dir'),), 'final'),
          ('client:ordinary', (), 'stage'), ('client:slot', (), 'stage'), ('client:dir', (), 'stage'),
          ('client:dir', (), 'final'), ('client:ordinary', (('connect', 'A', 'L', False),), 'stage'),
          ('client:dir', (('connect', 'A', 'L', False),), 'stage'),
          ('exchange', (('connect', 'A', 'L', False),), 'stage'), ('exchange', (), 'stage'))


class LabelModelTests(unittest.TestCase):
    def test_each_earlier_design_fails_on_the_interleaving_that_broke_it(self):
        for name, (design, attached, scenario, *fixed) in FINDINGS.items():
            with self.subTest(finding=name):
                with self.assertRaises(Violation):
                    explore(design, scenario, attached)
                explore(FIXED, scenario, fixed[0] if fixed else attached)

    def test_fixed_design_holds_for_every_bounded_scenario(self):
        explored = count = 0
        for scenario in scenarios(operations_for, SETUPS, sizes=(1, 2)):
            explored += explore(FIXED, scenario)
            count += 1
        # Three operations, two of them concurrent with a send, on every setup.
        for scenario in scenarios(operations_for, SETUPS, sizes=(3,)):
            if len(scenario[2]) >= 2:
                explored += explore(FIXED, scenario)
                count += 1
        self.assertGreater(count, 10000)
        self.assertGreater(explored, count)

    def test_exchanges_in_both_orders_and_wrapped_generations(self):
        for old, new in (('S', 'L'), ('L', 'S')):
            for fails in (False, True):
                with self.subTest(old=old, new=new, fails=fails):
                    scenario = ('exchange', (('connect', 'A', 'L', False),),
                                ((('exchange', old, new, fails),), (SEND_A, SEND_A)), 'stage')
                    explore(FIXED, scenario)
        # Retirement leaves nothing a later generation could match.
        for count in (1, TICKET_MASK, TICKET_MASK + 1, 2 * TICKET_MASK + 1):
            explore(FIXED, ('client:ordinary', (('connect', 'A', 'L', False), ('move', 'L', 'slot', True),
                                                ('advance', count)), ((SEND_A,),), 'stage'))

    def test_fixed_design_holds_across_the_attachment_transition(self):
        """Identity operations that enter before the guard attaches and finish
        after it, while the loader attaches, then proves the drain and settles."""
        count = 0
        for base, prelude in (('pair', ()), ('client:ordinary', (('connect', 'A', 'L', False),)),
                              ('client:slot', ()), ('exchange', (('connect', 'A', 'L', False),))):
            operations = operations_for(base)
            for size in (1, 2):
                for chosen in itertools.product(operations, repeat=size):
                    if not any(operation[0] == 'send' for operation in chosen):
                        chosen = chosen + (SEND_A,)
                    for split in itertools.product((False, True), repeat=len(chosen) - 1):
                        programs, current = [(('attach',), ('settle',))], [chosen[0]]
                        for operation, cut in zip(chosen[1:], split):
                            if cut:
                                programs.append(tuple(current)); current = []
                            current.append(operation)
                        programs.append(tuple(current))
                        explore(FIXED, ('transition-' + base, prelude, tuple(programs), 'stage'))
                        count += 1
        self.assertGreater(count, 200)

    def test_fixed_design_holds_after_every_interrupted_load_prefix(self):
        for attached in prefixes(FIXED.order):
            with self.subTest(attached=sorted(attached)):
                for scenario in scenarios(operations_for, SETUPS, sizes=(1, 2)):
                    explore(FIXED, scenario, attached)

    def test_the_old_attach_order_is_unsafe_for_some_prefix(self):
        failures = 0
        for attached in prefixes(OLD_ORDER):
            try:
                for scenario in scenarios(operations_for, SETUPS[:1], sizes=(2,)):
                    explore(FIXED, scenario, attached)
            except Violation:
                failures += 1
        self.assertGreater(failures, 0)


if __name__ == '__main__':
    unittest.main()
