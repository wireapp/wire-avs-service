#!/usr/bin/env python3
"""
Memory leak soak test for sftd.

Starts one or more sftds (and, for federation, two coturns) and runs
sftloader calls against them for a number of rounds. After each round
it waits until every sftd reports no calls and no participants, lets
them settle, and samples each sftd:

  - live malloc heap (macOS `heap`: node count and bytes; the most
    precise signal, it ignores allocator caching that RSS includes)
  - RSS, open fds, threads

The first --warmup rounds fill caches and pools and are not judged. After
that a leak shows up as steady growth per round: the checks fit a line
through the post-warmup samples and fail if the slope is above the
thresholds. fds, threads, calls and participants must return to their
post-warmup level.

Memory that is only freed when a call ends never shows up between rounds.
--sample-every samples the heap during calls too and reports the growth
rate of each sftd's heap while the call runs (after a ramp-up).

Topologies (--topology):
  single  one sftd, every client on it
  fed2    coturn-A + sftd-host, coturn-B + sftd-2; clients spread over
          both, sftd-2 federates to the host over TURN
  fed3    like fed2 plus sftd-3 on coturn-B (a star around the host)

Call options, combinable with any topology:
  --mode clean|abrupt|mixed   hang up normally / SIGKILL clients mid-call
  --kill-at S                 abrupt kill time; small values hit setup
  --tiles                     each receiver requests 1 stream and rotates
                              it (sftloader -W 1 -R 2500 -Y 6000)
  --calls-per-user N          users rejoin the ongoing call N times
                              (sftloader -n): join/leave churn
  --parallel K                K concurrent calls (one sftloader each)

Leak attribution, used after every judged round (stacks or sites that
grow in at least 75% of rounds, and by at least one block per round, are
reported and fail the run) and for the in-call growth:
  - libre MEM_DEBUG table, per file:line, if sftd's libre has MEM_DEBUG
    (detected automatically; see --sftd ./sftd-memdebug). The arm64
    contrib build uses RELEASE=1, which compiles it out.
  - --leaks (macOS): sftd runs with MallocStackLogging. `malloc_history
    -allByCount` groups live allocations by stack, and `leaks` reports
    unreachable memory after the warmup and at the end.
Both catch leaks that are still referenced (a missing mem_deref, an entry
never removed from a list or dict), which `leaks` alone cannot see.

On macOS the harness runs an ad-hoc signed copy of sftd with the
get-task-allow entitlement, because `heap`/`leaks` cannot read the memory
of a non-debuggable process.

Exit code: 0 = all checks passed, 1 = a check failed, 2 = setup error.
"""

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PROJECTS = os.path.dirname(REPO)


def _load_federation_harness():
    """Reuse Proc, wait_until, port helpers, Coturn and Checks from the
    federation harness. Loaded by path: both scripts are named run.py."""
    import importlib.util
    path = os.path.join(HERE, "..", "federation", "run.py")
    spec = importlib.util.spec_from_file_location("federation_run", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fed = _load_federation_harness()

SetupError = fed.SetupError
Proc = fed.Proc
LOCALHOST = fed.LOCALHOST

DEFAULT_SFTD = os.path.join(REPO, "sftd")
DEFAULT_SFTLOADER = os.path.join(PROJECTS, "wire-avs", "sftloader")
DEFAULT_COTURN = "/tmp/coturn418-build/bin/turnserver"
IS_MAC = platform.system() == "Darwin"
SECRET = "sft-memleak-secret"

ENTITLEMENTS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.get-task-allow</key><true/>
</dict></plist>
"""


# ---------------------------------------------------------------------------
# sftd

def prepare_binary(args, workdir):
    """macOS: heap/leaks need a debuggable process (get-task-allow)."""
    if not IS_MAC:
        return args.sftd
    ent = os.path.join(workdir, "get-task-allow.plist")
    with open(ent, "w") as f:
        f.write(ENTITLEMENTS)
    copy = os.path.join(workdir, "sftd-bin")
    shutil.copy2(args.sftd, copy)
    r = subprocess.run(["codesign", "-s", "-", "-f", "--entitlements",
                        ent, copy], capture_output=True, text=True)
    if r.returncode != 0:
        raise SetupError("codesign failed: %s" % r.stderr.strip())
    return copy


class Sftd:
    def __init__(self, name, port, args, workdir, binary, coturn=None):
        self.name = name
        self.port = port
        self.metrics_port = port + 1
        self.args = args
        self.workdir = workdir
        self.binary = binary
        self.coturn = coturn
        self.proc = None

    def ports(self):
        return [self.port, self.metrics_port]

    @property
    def url(self):
        return "http://%s:%d" % (LOCALHOST, self.port)

    @property
    def pid(self):
        return self.proc.p.pid

    def start(self, secret_path):
        argv = shlex.split(self.args.wrap) if self.args.wrap else []
        argv += [self.binary,
                 "-I", LOCALHOST, "-p", str(self.port),
                 "-M", LOCALHOST, "-r", str(self.metrics_port),
                 "-A", LOCALHOST, "-u", self.url]
        if self.coturn:
            argv += ["-t", self.coturn.turn_url(), "-s", secret_path]
        if not self.args.sftd_verbose:
            argv.append("-q")
        if self.args.workers:
            argv += ["-w", str(self.args.workers)]
        env = dict(os.environ)
        if self.args.leaks:
            env["MallocStackLogging"] = "1"
        self.proc = Proc(self.name, argv, self.workdir, env=env)
        fed.wait_until(self.name, lambda: fed.tcp_open(self.port) and
                       self.metrics() is not None, self.proc,
                       timeout=60 if self.args.wrap else 20)

    def _get(self, path):
        url = "http://%s:%d%s" % (LOCALHOST, self.metrics_port, path)
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return r.read().decode(errors="replace")
        except OSError:
            return None

    def metrics(self):
        text = self._get("/metrics")
        if text is None:
            return None
        return {k: fed.metric_value(text, k) for k in
                ("sft_calls", "sft_participants", "sft_calls_total",
                 "sft_participants_total")}

    def idle(self):
        m = self.metrics()
        return bool(m) and m["sft_calls"] == 0 and \
            m["sft_participants"] == 0

    def mem_sites(self):
        """libre live allocations per file:line via /debug (MEM_DEBUG only).

        /debug makes sftd call mem_debug(), which dumps every live libre
        allocation to stderr (our log). Returns None if nothing was dumped.
        """
        self.proc.logf.flush()
        start = os.path.getsize(self.proc.logpath)
        if self._get("/debug") is None:
            return None
        # The dump is written synchronously before the reply, but give
        # stdio a moment.
        time.sleep(0.5)
        with open(self.proc.logpath, "rb") as f:
            f.seek(start)
            dump = f.read().decode(errors="replace")
        sites = {}
        for m in re.finditer(r"^\s+0x[0-9a-f]+<([^>]+)>: nrefs=\s*\d+\s+"
                             r"size=(\d+)", dump, re.M):
            n, b = sites.get(m.group(1), (0, 0))
            sites[m.group(1)] = (n + 1, b + int(m.group(2)))
        return sites or None


# ---------------------------------------------------------------------------
# Process sampling and attribution

def run_out(argv, timeout=60):
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        return r.stdout + r.stderr
    except (OSError, subprocess.TimeoutExpired):
        return ""


def sample_heap(pid):
    if not IS_MAC:
        return None, None
    out = run_out(["heap", str(pid)], timeout=120)
    m = re.search(r"All zones: (\d+) nodes \((\d+) bytes\)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (None, None)


def sample_rss(pid):
    out = run_out(["ps", "-o", "rss=", "-p", str(pid)]).strip()
    return int(out) if out.isdigit() else None


def sample_proc(pid):
    s = {"rss_kb": sample_rss(pid)}
    s["heap_nodes"], s["heap_bytes"] = sample_heap(pid)
    if IS_MAC:
        out = run_out(["lsof", "-nP", "-p", str(pid), "-F", "f"])
        s["fds"] = sum(1 for l in out.splitlines()
                       if l.startswith("f") and l[1:].isdigit())
        out = run_out(["ps", "-M", "-p", str(pid)])
        s["threads"] = max(0, len(out.splitlines()) - 1)
    else:
        try:
            s["fds"] = len(os.listdir("/proc/%d/fd" % pid))
            s["threads"] = len(os.listdir("/proc/%d/task" % pid))
        except OSError:
            s["fds"] = s["threads"] = None
    return s


def run_leaks(pid, path):
    out = run_out(["leaks", str(pid)], timeout=600)
    with open(path, "w") as f:
        f.write(out)
    m = re.search(r"(\d+) leaks? for (\d+) total leaked bytes", out)
    return (int(m.group(1)), int(m.group(2))) if m else (None, None)


STACK_RE = re.compile(r"^(\d+) calls? for (\d+) bytes: (.*)$", re.M)
FRAME_RE = re.compile(r"0x[0-9a-f]+ \(([^)]+)\) ")
NOISE = re.compile(r"^(?:_?malloc|_?calloc|_?realloc|mem_(?:z?alloc|realloc)"
                   r"|_malloc_zone|.*_instrumented_or_legacy|operator new)")


def run_malloc_history(pid, path=None):
    """Live allocations grouped by stack: {stack: (blocks, bytes)}.

    Needs MallocStackLogging in sftd's environment (--leaks).
    """
    out = run_out(["malloc_history", str(pid), "-allByCount"], timeout=600)
    if path:
        with open(path, "w") as f:
            f.write(out)
    stacks = {}
    for m in STACK_RE.finditer(out):
        # Drop addresses so stacks compare across ASLR'd samples.
        key = FRAME_RE.sub(r"(\1) ", m.group(3)).strip()
        n, b = stacks.get(key, (0, 0))
        stacks[key] = (n + int(m.group(1)), b + int(m.group(2)))
    return stacks


def short_stack(stack, depth=6):
    """The innermost interesting frames, innermost last."""
    if " | " not in stack:
        return stack            # a libre file:line site
    frames = []
    for fr in stack.split(" | "):
        m = re.match(r"\(([^)]+)\) (.*)", fr.strip())
        lib, fn = (m.group(1), m.group(2)) if m else ("?", fr.strip())
        if NOISE.match(fn) or lib.startswith("libsystem_malloc"):
            continue
        frames.append(fn)
    return " > ".join(frames[-depth:])


def snapshots(sftd, args, have_sites, tag):
    """Attribution snapshots: {"sites": {...}, "stacks": {...}}."""
    snap = {}
    if have_sites:
        snap["sites"] = sftd.mem_sites() or {}
    if args.leaks:
        snap["stacks"] = run_malloc_history(sftd.pid, os.path.join(
            sftd.workdir, "malloc-history-%s-%s.txt" % (sftd.name, tag))
            if args.keep_history else None)
    return snap


# Growth that is bounded by design, listed but not failed:
#  - OpenSSL per-thread state (DRBGs, error queue, gmtime/localtime
#    buffers): one set per thread, appears as more workers get used.
#  - usrsctp vtag TIME_WAIT table: sctp_free_assoc ->
#    sctp_add_vtag_to_timewait keeps each closed association's vtag for
#    60s in 32 hash chains of 15-slot blocks (320 bytes). Blocks are
#    reused, never freed, so the table grows to ~32 * closes/min / 15
#    blocks and stops.
KNOWN_BOUNDED = (r"drbg_setup|rand_drbg_new|rand_pool_new|ERR_get_state|"
                 r"OPENSSL_gmtime|\) localtime|\) gmtime|"
                 r"ossl_init_thread_start|sctp_free_assoc \| \(libsystem")


def steady_growers(series):
    """Keys that grew in >= 75% of steps and by >= 1 block per step."""
    steps = len(series) - 1
    if steps < 1:
        return [], 0, 0
    need = max(1, -(-3 * steps // 4))
    out = []
    for key, (n, b) in series[-1].items():
        counts = [s.get(key, (0, 0))[0] for s in series]
        ups = sum(1 for a, c in zip(counts, counts[1:]) if c > a)
        n0, b0 = series[0].get(key, (0, 0))
        if ups >= need and n - n0 >= steps:
            out.append((n - n0, b - b0, ups, key))
    out.sort(key=lambda g: (g[0], g[1]), reverse=True)
    return out, need, steps


def top_growth(first, last, top):
    out = []
    for key, (n, b) in last.items():
        n0, b0 = first.get(key, (0, 0))
        if b - b0 > 0:
            out.append((n - n0, b - b0, key))
    out.sort(key=lambda g: g[1], reverse=True)
    return out[:top]


def slope(xs, ys):
    """Least squares slope; None with fewer than 2 points."""
    pts = [(x, y) for x, y in zip(xs, ys) if y is not None]
    if len(pts) < 2:
        return None
    n = len(pts)
    mx = sum(x for x, _ in pts) / n
    my = sum(y for _, y in pts) / n
    den = sum((x - mx) ** 2 for x, _ in pts)
    if den == 0:
        return None
    return sum((x - mx) * (y - my) for x, y in pts) / den


# ---------------------------------------------------------------------------
# Topology and rounds

def build_topology(args, workdir, binary):
    b = args.base_port
    turns = []
    if args.topology == "single":
        sfts = [Sftd("sftd", b + 400, args, workdir, binary)]
    else:
        cargs = types.SimpleNamespace(
            coturn=args.coturn, certs=args.certs, relay_threads=1,
            federation_no_dtls=False, turn_transport="udp",
            prometheus=False)
        ta = fed.Coturn("coturn-A", b, cargs, workdir)
        tb = fed.Coturn("coturn-B", b + 200, cargs, workdir)
        turns = [ta, tb]
        sfts = [Sftd("sftd-host", b + 400, args, workdir, binary, ta),
                Sftd("sftd-2", b + 410, args, workdir, binary, tb)]
        if args.topology == "fed3":
            sfts.append(Sftd("sftd-3", b + 420, args, workdir, binary, tb))
    return turns, sfts


def users_cfg(args, sfts, k):
    """Users spread round-robin over the SFTs, host first. Users of
    parallel calls differ by userid. (Not by clientid: a custom clientid
    breaks sftloader's video, every pair then gets 0 frames.)"""
    host = sfts[0]
    cfg = []
    for i in range(args.users):
        sft = sfts[i % len(sfts)]
        e = {"userid": "p%duser%02d" % (k, i),
             "sft_url": sft.url, "sfts_all": [sft.url],
             "is_federating": sft is not host}
        if i > 0:
            e["answer_ms"] = 1000 + 500 * i
        cfg.append(e)
    return cfg


def round_mode(args, i):
    if args.mode == "mixed":
        return "abrupt" if i % 2 else "clean"
    return args.mode


def run_round(args, sfts, i, workdir, incall):
    """Run one round. incall(t, final=False) is called every
    --sample-every seconds while the calls run."""
    mode = round_mode(args, i)
    loaders = []
    for k in range(args.parallel):
        name = "r%02d-sftloader%d" % (i, k)
        cfg_path = os.path.join(workdir, "users-%d.json" % k)
        if not os.path.exists(cfg_path):
            with open(cfg_path, "w") as f:
                json.dump(users_cfg(args, sfts, k), f, indent=1)
        argv = [args.sftloader, "-C", cfg_path,
                "-n", str(args.calls_per_user), "-d", str(args.duration),
                "-P", args.pattern,
                "-l", os.path.join(workdir, name + "-wcall.log")]
        argv.append("-V" if args.verify and mode == "clean" else "-v")
        if args.tiles:
            argv += ["-W", "1", "-R", "2500", "-Y", "6000"]
        loaders.append(Proc(name, argv, workdir))

    t0 = time.time()
    call_len = args.duration * args.calls_per_user
    if mode != "abrupt":
        kill_at = None
    elif args.kill_at is not None:
        kill_at = t0 + args.kill_at
    else:
        kill_at = t0 + max(call_len * 0.6, 15)
    deadline = t0 + call_len + args.grace
    next_sample = t0 + args.sample_every if args.sample_every else None
    while any(p.alive() for p in loaders):
        now = time.time()
        if kill_at and now >= kill_at:
            for p in loaders:
                if p.alive():
                    p._signal(signal.SIGKILL)
            break
        if now >= deadline:
            break
        if next_sample and now >= next_sample:
            incall(now - t0)
            next_sample += args.sample_every
        time.sleep(0.5)
    if args.sample_every:
        incall(time.time() - t0, final=True)

    codes = []
    for p in loaders:
        if mode == "abrupt":
            codes.append("killed")
        elif p.alive():
            codes.append("timeout")
        else:
            codes.append(p.p.returncode)
        p.stop(grace=2)

    t1 = time.time()
    drained = False
    while time.time() - t1 < args.drain_timeout:
        if all(s.idle() for s in sfts):
            drained = True
            break
        if not all(s.proc.alive() for s in sfts):
            break
        time.sleep(1.0)
    drain_s = time.time() - t1
    time.sleep(args.settle)
    return {"round": i, "mode": mode, "loader_exit": codes,
            "drained": drained, "drain_s": round(drain_s, 1),
            "metrics": {s.name: s.metrics() for s in sfts}}


def fmt(v, div=1, nd=0):
    if v is None:
        return "-"
    return ("%%.%df" % nd) % (v / div)


HDR = "  %-5s %-10s %-7s %-14s %-7s %9s %10s %10s %6s %4s"


def print_row(r, name, s):
    print(HDR % (r["round"], name, r.get("mode", ""),
                 ",".join(map(str, r.get("loader_exit", []))) or "-",
                 ("%ss" % r["drain_s"]) if "drain_s" in r else "-",
                 fmt(s["rss_kb"], 1024, 1), fmt(s["heap_nodes"]),
                 fmt(s["heap_bytes"], 1024 * 1024, 2), fmt(s["fds"]),
                 fmt(s["threads"])), flush=True)


# ---------------------------------------------------------------------------

def run(args):
    workdir = args.workdir or tempfile.mkdtemp(prefix="sft-memleak-")
    os.makedirs(workdir, exist_ok=True)
    print("logs: %s" % workdir)

    need = [(args.sftd, "sftd"), (args.sftloader, "sftloader")]
    if args.topology != "single":
        need.append((args.coturn, "turnserver"))
    for path, what in need:
        if not os.access(path, os.X_OK):
            raise SetupError("%s binary not found: %s" % (what, path))
    if args.leaks and not IS_MAC:
        raise SetupError("--leaks needs macOS; on Linux use --wrap "
                         "'valgrind --leak-check=full' or an ASan build")
    if args.users < 2:
        raise SetupError("need at least 2 users")

    binary = prepare_binary(args, workdir)
    turns, sfts = build_topology(args, workdir, binary)
    busy = [p for c in turns + sfts for p in c.ports()
            if not fed.port_free(p)]
    if busy:
        raise SetupError("ports already in use: %s (use --base-port)" % busy)
    secret_path = os.path.join(workdir, "secret.txt")
    with open(secret_path, "w") as f:
        f.write(SECRET + "\n")
    fed.SECRET = SECRET     # coturn config uses the module-level secret

    checks = fed.Checks()
    rows = []                       # {"round", ..., "samples": {name: s}}
    series = {s.name: [] for s in sfts}     # attribution, judged rounds
    incall = {s.name: [] for s in sfts}     # (round, t, heap_bytes)
    incall_snaps = {s.name: {} for s in sfts}
    leaks_base, leaks_end = {}, {}
    procs = []
    alive = True
    try:
        for t in turns:
            t.start()
            procs.append(t.proc)
        for s in sfts:
            s.start(secret_path)
            procs.append(s.proc)
            print("started %s pid %d (%s)%s"
                  % (s.name, s.pid, s.url,
                     ", turn " + s.coturn.name if s.coturn else ""))
        time.sleep(args.settle)
        have_sites = sfts[0].mem_sites() is not None
        print("libre MEM_DEBUG allocation table: %s"
              % ("yes" if have_sites else
                 "no (libre built with RELEASE; try --sftd ./sftd-memdebug)"))
        print("stack attribution (malloc_history): %s"
              % ("yes" if args.leaks else "no (--leaks)"))

        base = {"round": "base",
                "samples": {s.name: sample_proc(s.pid) for s in sfts}}
        rows.append(base)
        print("\ntopology %s, %d rounds (%d warmup), %d call(s) x %d users, "
              "%ds x %d call(s) per user, mode %s%s\n"
              % (args.topology, args.rounds, args.warmup, args.parallel,
                 args.users, args.duration, args.calls_per_user, args.mode,
                 ", tiles" if args.tiles else ""))
        print(HDR % ("round", "sftd", "mode", "loader exit", "drain",
                     "rss MB", "heap nodes", "heap MB", "fds", "thr"))
        for s in sfts:
            print_row(base, s.name, base["samples"][s.name])

        for i in range(1, args.rounds + 1):
            if not all(s.proc.alive() for s in sfts):
                break

            def on_incall(t, final=False, i=i):
                for s in sfts:
                    if not s.proc.alive():
                        continue
                    _, hb = sample_heap(s.pid)
                    v = hb if hb is not None else \
                        (sample_rss(s.pid) or 0) * 1024
                    incall[s.name].append((i, t, v))
                    # Attribution at the end of ramp-up and at the latest
                    # sample before hangup (the final sample is taken
                    # after the calls ended, so it is skipped).
                    if final or t < args.ramp_up or \
                            not (have_sites or args.leaks):
                        continue
                    snaps = incall_snaps[s.name].setdefault(i, {})
                    key = "first" if "first" not in snaps else "last"
                    snaps[key] = (t, snapshots(s, args, have_sites,
                                               "r%02d-incall" % i))

            r = run_round(args, sfts, i, workdir, on_incall)
            r["samples"] = {}
            for s in sfts:
                if not s.proc.alive():
                    continue
                r["samples"][s.name] = sample_proc(s.pid)
                print_row(r, s.name, r["samples"][s.name])
                if i >= args.warmup and (have_sites or args.leaks):
                    series[s.name].append(snapshots(s, args, have_sites,
                                                    "r%02d" % i))
                if i == args.warmup and args.leaks:
                    leaks_base[s.name] = run_leaks(s.pid, os.path.join(
                        workdir, "leaks-%s-warmup.txt" % s.name))
            rows.append(r)
            with open(os.path.join(workdir, "samples.json"), "w") as f:
                json.dump({"rounds": rows, "incall": incall}, f, indent=1)

        alive = all(s.proc.alive() for s in sfts)
        if args.leaks:
            for s in sfts:
                if s.proc.alive():
                    leaks_end[s.name] = run_leaks(s.pid, os.path.join(
                        workdir, "leaks-%s-end.txt" % s.name))
    finally:
        for p in reversed(procs):
            p.stop(grace=args.shutdown_grace)

    # ---------------- checks ----------------
    rounds = [r for r in rows if r["round"] != "base"]
    judged = [r for r in rounds if r["round"] >= args.warmup]
    names = [s.name for s in sfts]

    checks.check("servers alive for all rounds",
                 alive and len(rounds) == args.rounds,
                 ", ".join("%s exit=%s" % (p.name, p.p.returncode)
                           for p in procs if p.p.returncode not in
                           (None, 0, -15)))

    undrained = [r["round"] for r in rounds if not r["drained"]]
    checks.check("calls and participants drop to 0 after each round",
                 not undrained,
                 "not drained after %ds in rounds %s"
                 % (args.drain_timeout, undrained) if undrained else
                 "max drain %.1fs" % max([r["drain_s"] for r in rounds]
                                         or [0]))

    # With -n > 1 sftloader keeps waiting to rejoin a call that has
    # ended, so it never exits by itself; the harness stops it.
    ok_codes = (0, "timeout") if args.calls_per_user > 1 else (0,)
    bad = [(r["round"], c) for r in rounds if r["mode"] == "clean"
           for c in r["loader_exit"] if c not in ok_codes]
    checks.check("clean rounds: sftloader exit 0%s"
                 % (" (video verified)" if args.verify else ""), not bad,
                 "round/exit %s" % bad if bad else "")

    for s in sfts:
        m = rounds[-1]["metrics"].get(s.name) if rounds else None
        if m:
            print("info: %s totals: calls=%s participants=%s"
                  % (s.name, fmt(m.get("sft_calls_total")),
                     fmt(m.get("sft_participants_total"))))

    # Growth between rounds
    if len(judged) >= 2:
        print("\n=== Growth per round after warmup (rounds %d..%d) ==="
              % (judged[0]["round"], judged[-1]["round"]))
        for name in names:
            pts = [r for r in judged if name in r["samples"]]
            xs = [r["round"] for r in pts]
            for key, unit, div, limit in (
                    ("heap_bytes", "KB", 1024, args.max_heap_kb),
                    ("heap_nodes", "nodes", 1, args.max_nodes),
                    ("rss_kb", "KB", 1, args.max_rss_kb)):
                ys = [r["samples"][name][key] for r in pts]
                sl = slope(xs, ys)
                if sl is None:
                    continue
                per = sl / div
                print("  %-10s %-10s %+10.1f %s/round  (%s -> %s)"
                      % (name, key, per, unit, fmt(ys[0], div),
                         fmt(ys[-1], div)))
                if limit is not None:
                    checks.check("%s %s growth <= %s %s/round"
                                 % (name, key, limit, unit),
                                 per <= limit, "%+.1f %s/round" % (per, unit))
            for key, slack in (("fds", args.fd_slack), ("threads", 0)):
                ys = [r["samples"][name][key] for r in pts]
                if not ys or ys[0] is None or ys[-1] is None:
                    continue
                checks.check("%s %s back to post-warmup level" % (name, key),
                             ys[-1] <= ys[0] + slack,
                             "%d -> %d (max %d, slack %d)"
                             % (ys[0], ys[-1], max(ys), slack))
    else:
        print("\n(fewer than 2 judged rounds: no between-round trend)")

    # Attribution across rounds
    known = re.compile(args.known_bounded) if args.known_bounded else None
    for name in names:
        for kind, label in (("sites", "libre allocation sites"),
                            ("stacks", "allocation stacks")):
            ser = [snap[kind] for snap in series[name] if kind in snap]
            if len(ser) < 2:
                continue
            grown, need, steps = steady_growers(ser)
            bounded = [g for g in grown if known and known.search(g[3])]
            grown = [g for g in grown if g not in bounded]
            print("\n=== %s: %s growing in >= %d of %d rounds ==="
                  % (name, label, need, steps))
            for dn, db, ups, key in grown[:args.top]:
                print("  %+6d blocks %+9d bytes %2d/%d  %s"
                      % (dn, db, ups, steps, short_stack(key)))
            if not grown:
                print("  none")
            if bounded:
                print("  (known bounded, not judged: %d, +%d blocks, "
                      "+%d bytes)" % (len(bounded),
                                      sum(g[0] for g in bounded),
                                      sum(g[1] for g in bounded)))
            path = os.path.join(workdir, "growth-%s-%s.txt" % (name, kind))
            with open(path, "w") as f:
                for dn, db, ups, key in grown + bounded:
                    f.write("%s%+d blocks %+d bytes, grew in %d/%d rounds\n"
                            "  %s\n\n" % ("[known bounded] "
                                          if (dn, db, ups, key) in bounded
                                          else "", dn, db, ups, steps,
                                          key.replace(" | ", "\n  ")))
            if steps < 3:
                print("  (fewer than 3 judged rounds: not checked)")
                continue
            checks.check("%s: no %s grow round after round" % (name, label),
                         not grown, "%d, +%d blocks, see %s"
                         % (len(grown), sum(g[0] for g in grown), path)
                         if grown else "")

    # In-call growth
    if args.sample_every:
        print("\n=== Heap growth during calls (after %ds ramp-up) ==="
              % args.ramp_up)
        for name in names:
            per_round = {}
            for i, t, v in incall[name]:
                per_round.setdefault(i, []).append((t, v))
            rates = []
            for i, pts in sorted(per_round.items()):
                # Exclude the final sample, taken after hangup/kill.
                pts = [p for p in pts[:-1] if p[0] >= args.ramp_up]
                sl = slope([p[0] for p in pts], [p[1] for p in pts])
                if sl is None:
                    continue
                kbmin = sl * 60 / 1024
                rates.append(kbmin)
                print("  %-10s round %-3d %+9.1f KB/min over %3.0fs "
                      "(%d samples)" % (name, i, kbmin,
                                        pts[-1][0] - pts[0][0], len(pts)))
            if rates and args.max_incall_kb_min is not None:
                worst = max(rates)
                checks.check("%s in-call heap growth <= %s KB/min"
                             % (name, args.max_incall_kb_min),
                             worst <= args.max_incall_kb_min,
                             "worst %+.1f KB/min" % worst)
            # What grew during the longest-sampled call
            best = None
            for i, snaps in incall_snaps[name].items():
                if "first" in snaps and "last" in snaps:
                    span = snaps["last"][0] - snaps["first"][0]
                    if best is None or span > best[0]:
                        best = (span, i, snaps)
            if best:
                span, i, snaps = best
                for kind in ("sites", "stacks"):
                    a = snaps["first"][1].get(kind)
                    b = snaps["last"][1].get(kind)
                    if not a or not b:
                        continue
                    print("  %s round %d, top %s growth over %.0fs in call:"
                          % (name, i, kind, span))
                    for dn, db, key in top_growth(a, b, args.top // 2):
                        print("    %+6d blocks %+9d bytes  %s"
                              % (dn, db, short_stack(key)))

    if args.leaks:
        print()
        for name in names:
            lb = leaks_base.get(name, (None, None))
            le = leaks_end.get(name, (None, None))
            print("info: %s leaks after warmup: %s (%s bytes); at end: %s "
                  "(%s bytes)" % (name, lb[0], lb[1], le[0], le[1]))
            if lb[1] is not None and le[1] is not None:
                checks.check("%s leaks: no new unreachable memory" % name,
                             le[1] <= lb[1], "%s -> %s bytes"
                             % (lb[1], le[1]))

    for s in sfts:
        log = s.proc.log()
        # Only what follows shutdown; /debug dumps earlier in the log
        # also print "Memory leaks (N)".
        log = log[log.rfind("Terminating"):] if "Terminating" in log else ""
        for pat in (r"Memory leaks \(\d+\)", r"ERROR: LeakSanitizer[^\n]*",
                    r"definitely lost:[^\n]*"):
            m = re.search(pat, log)
            if m:
                print("info: %s at exit: %s" % (s.name, m.group(0)))

    checks.report()
    ok = checks.passed()
    print("\nRESULT: %s  (logs in %s)" % ("PASS" if ok else "FAIL", workdir))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="sftd memory leak soak test with sftloader",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--sftd", default=os.environ.get("SFTD_BIN",
                                                     DEFAULT_SFTD),
                    help="sftd binary; ./sftd-memdebug has libre MEM_DEBUG")
    ap.add_argument("--sftloader", default=os.environ.get("SFTLOADER_BIN",
                                                          DEFAULT_SFTLOADER))
    ap.add_argument("--coturn", default=os.environ.get("COTURN_BIN",
                                                       DEFAULT_COTURN))
    ap.add_argument("--certs", default=os.environ.get(
        "COTURN_CERTS", fed.DEFAULT_CERTS))
    ap.add_argument("--topology", choices=["single", "fed2", "fed3"],
                    default="single")
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--warmup", type=int, default=2,
                    help="rounds not judged (caches/pools fill up)")
    ap.add_argument("--mode", choices=["clean", "abrupt", "mixed"],
                    default="mixed")
    ap.add_argument("--users", type=int, default=4, help="users per call")
    ap.add_argument("--parallel", type=int, default=1,
                    help="concurrent calls per round, one sftloader each")
    ap.add_argument("--duration", type=int, default=30,
                    help="call duration in seconds")
    ap.add_argument("--calls-per-user", type=int, default=1,
                    help="sftloader -n: >1 makes users leave and rejoin")
    ap.add_argument("--kill-at", type=float,
                    help="abrupt rounds: SIGKILL clients this many seconds "
                    "after start (default: 60%% of the call, min 15s). "
                    "Small values hit call setup (before ICE/DTLS is done)")
    ap.add_argument("--tiles", action="store_true",
                    help="rotate 1 requested video stream every 2.5s")
    ap.add_argument("--grace", type=int, default=60,
                    help="extra seconds before a clean sftloader is "
                    "given up on")
    ap.add_argument("--drain-timeout", type=int, default=120,
                    help="max seconds for sftd to drop calls after a round")
    ap.add_argument("--settle", type=float, default=5.0,
                    help="seconds to wait after draining before sampling")
    ap.add_argument("--sample-every", type=float, default=0,
                    help="also sample the heap every N seconds during "
                    "calls (0: off)")
    ap.add_argument("--ramp-up", type=float, default=20,
                    help="ignore in-call samples before this many seconds")
    ap.add_argument("--max-incall-kb-min", type=float,
                    help="fail if in-call heap grows faster (KB/min)")
    ap.add_argument("--verify", action="store_true",
                    help="sftloader -V: verify video in clean rounds")
    ap.add_argument("--pattern", choices=["head", "octo"], default="head")
    ap.add_argument("--max-heap-kb", type=float, default=256,
                    help="fail if live heap grows more per round (macOS)")
    ap.add_argument("--max-nodes", type=float, default=100,
                    help="fail if live heap blocks grow more per round "
                    "(macOS)")
    ap.add_argument("--max-rss-kb", type=float,
                    help="fail if RSS grows more per round (default: "
                    "report only on macOS, 1024 on Linux)")
    ap.add_argument("--fd-slack", type=int, default=2)
    ap.add_argument("--leaks", action="store_true",
                    help="macOS: MallocStackLogging, malloc_history stack "
                    "attribution and `leaks` reports")
    ap.add_argument("--known-bounded", default=KNOWN_BOUNDED,
                    help="regex for stacks/sites with bounded growth "
                    "(listed, not failed); '' to judge everything")
    ap.add_argument("--keep-history", action="store_true",
                    help="save every malloc_history report")
    ap.add_argument("--workers", type=int,
                    help="sftd -w worker threads (default: sftd's). Fewer "
                    "workers make per-thread state settle sooner")
    ap.add_argument("--wrap",
                    help="command prefix for sftd, e.g. 'valgrind "
                    "--leak-check=full' (Linux)")
    ap.add_argument("--sftd-verbose", action="store_true",
                    help="do not pass -q to sftd")
    ap.add_argument("--shutdown-grace", type=float, default=15)
    ap.add_argument("--top", type=int, default=20,
                    help="sites/stacks to list")
    ap.add_argument("--base-port", type=int, default=32000)
    ap.add_argument("--workdir", help="log dir (default: new temp dir)")
    args = ap.parse_args()
    if not IS_MAC and args.max_rss_kb is None:
        args.max_rss_kb = 1024      # without `heap`, RSS is the signal
    try:
        return run(args)
    except SetupError as e:
        print("SETUP ERROR: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
