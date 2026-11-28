#!/usr/bin/env python3
"""
Crash stress test for sftd: randomized chaos against one or more sftds
until one of them dies (or the time is up).

Meant for crashes we have no core for: it hammers the paths where
lifetime bugs live (call setup/teardown races, clients vanishing at any
point, federation peers dying, shutdown with calls up) and, with the ASan
build, turns a latent use-after-free into a report with alloc/free stacks
instead of a rare SIGSEGV.

    test/stress/run.py --guard-malloc --time 1800          # macOS
    test/stress/make-asan.sh                              # Linux:
    test/stress/run.py --sftd ./sftd-asan --time 1800      # ASan

(Apple's ASan runtime hangs in __asan_init on macOS 26.5 with Xcode
clang 17, even for an empty program, so on macOS use Guard Malloc.)

Chaos, all randomized from --seed (printed; a run is not fully
reproducible because of timing, but the schedule is):

  clients  --slots K concurrent sftloader "slots". Each slot keeps
           starting calls with 2..--max-users users, a random duration,
           random tile rotation (-W/-R) and join/leave churn (-n), and
           ends each call with a random fate:
             clean   let it hang up normally
             kill    SIGKILL at a random time (often during setup:
                     ICE / DTLS / data channel)
             freeze  SIGSTOP for a random time (sftd sees a client go
                     silent), then SIGCONT or SIGKILL
             term    SIGTERM at a random time
           Slots share conversation ids sometimes (--share), so calls
           join groups that are being torn down.
  peers    fed2/fed3: every --peer-chaos seconds SIGKILL (or SIGSTOP
           for a while) a non-host sftd mid-call and restart it, so the
           host sees federated calls die at random points.
  http     a thread polls /metrics and /debug (and the main HTTP port)
           at random intervals (--http-chaos).
  big call --big-call N: one conversation with N users over --slots
           sftloaders (e.g. 80 over 8). Each slot's users stay ~--big-churn
           seconds, page through tiles (-W 4/9, -R), then leave by their
           fate and rejoin as the same users. No drains or peer chaos
           unless asked for.
  drain    every --term-every seconds, and for every sftd at the end,
           SIGTERM an sftd with calls up (a rollout). sftd then refuses
           new calls and exits once its groups are gone; it must exit 0
           within --drain-timeout. It is restarted after a mid-run drain.

Crash detection: every sftd is watched; if one exits it is reported with
its exit code / signal, the ASan/UBSan report (ASAN_OPTIONS log_path), the
macOS crash report (~/Library/Logs/DiagnosticReports) and the log tail,
next to the last chaos events from events.log. --keep-going restarts it
and continues, otherwise the run stops at the first crash.

Without ASan, on macOS: --guard-malloc runs sftd with libgmalloc (each
allocation on its own page, freed pages unmapped, so a use-after-free or
overrun faults at the bad access, and the crash report has the stack);
--malloc-debug is the cheaper MallocScribble (freed memory is filled
with 0x55, so stale pointers crash sooner).

Exit code: 0 = no crash, 1 = crash / failed check, 2 = setup error.
"""

import argparse
import glob
import importlib.util
import json
import os
import random
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(HERE, "..", rel, "run.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ml = _load("memleak_run", "memleak")    # Sftd, topology, sampling
fed = ml.fed                            # Proc, Coturn, Checks, ports

SetupError = fed.SetupError
Proc = fed.Proc
IS_MAC = ml.IS_MAC
LOCALHOST = fed.LOCALHOST
SECRET = "sft-stress-secret"
CRASH_DIR = os.path.expanduser("~/Library/Logs/DiagnosticReports")


# ---------------------------------------------------------------------------
# Event log

class Events:
    def __init__(self, path):
        self.f = open(path, "w")
        self.t0 = time.time()
        self.lock = threading.Lock()
        self.recent = []

    def __call__(self, fmt, *a):
        line = "%8.2f  %s" % (time.time() - self.t0, fmt % a if a else fmt)
        with self.lock:
            self.f.write(line + "\n")
            self.f.flush()
            self.recent = (self.recent + [line])[-40:]

    def tail(self):
        with self.lock:
            return list(self.recent)


# ---------------------------------------------------------------------------
# sftd processes

def sftd_env(args, workdir, name):
    env = dict(os.environ)
    # ASan/UBSan: report into the workdir, stop at the first error.
    env["ASAN_OPTIONS"] = ":".join([
        "log_path=%s" % os.path.join(workdir, "asan-" + name),
        "halt_on_error=1", "detect_leaks=0", "abort_on_error=1",
        "detect_stack_use_after_return=1", "check_initialization_order=1",
        "strict_string_checks=1", "print_summary=1"])
    env["UBSAN_OPTIONS"] = ":".join([
        "log_path=%s" % os.path.join(workdir, "ubsan-" + name),
        "print_stacktrace=1", "halt_on_error=1"])
    if args.guard_malloc and IS_MAC:
        # Every allocation on its own page(s), freed pages unmapped:
        # use-after-free and overruns fault at the bad access, and the
        # crash report shows where. Slow and memory hungry; keep the
        # load modest (--slots, --workers).
        env.update(DYLD_INSERT_LIBRARIES="/usr/lib/libgmalloc.dylib",
                   MALLOC_PROTECT_BEFORE="1", MALLOC_FILL_SPACE="1",
                   MALLOC_STRICT_SIZE="1")
    elif args.malloc_debug and IS_MAC:
        env.update(MallocScribble="1", MallocPreScribble="1",
                   MallocGuardEdges="1", MallocErrorAbort="1",
                   MallocCheckHeapAbort="1")
    return env


class Sftd(ml.Sftd):
    """memleak's Sftd plus environment, restart and crash bookkeeping."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.incarnation = 0
        self.started_at = None

    def start(self, secret_path, env=None):
        argv = [self.binary,
                "-I", LOCALHOST, "-p", str(self.port),
                "-M", LOCALHOST, "-r", str(self.metrics_port),
                "-A", LOCALHOST, "-u", self.url]
        if self.coturn:
            argv += ["-t", self.coturn.turn_url(), "-s", secret_path]
        if not self.args.sftd_verbose:
            argv.append("-q")
        if self.args.workers:
            argv += ["-w", str(self.args.workers)]
        name = self.name if not self.incarnation else \
            "%s.%d" % (self.name, self.incarnation)
        self.proc = Proc(name, argv, self.workdir, env=env)
        self.started_at = time.time()
        try:
            fed.wait_until(self.name, lambda: fed.tcp_open(self.port) and
                           self.metrics() is not None, self.proc,
                           timeout=60)
        except SetupError:
            if self.args.asan and IS_MAC and self.proc.alive():
                raise SetupError(
                    "%s did not come up. Apple's ASan runtime hangs in "
                    "__asan_init on some macOS versions (even for an "
                    "empty program); use --guard-malloc with ./sftd, or "
                    "an ASan build on Linux" % self.name)
            raise

    def restart(self, secret_path, env):
        if self.proc and self.proc.alive():
            self.proc._signal(signal.SIGKILL)
            self.proc.p.wait()
        if self.proc and not self.proc.logf.closed:
            self.proc.logf.close()
        self.incarnation += 1
        # The old UDP/TCP ports must be released before rebinding.
        fed.wait_until("%s ports" % self.name,
                       lambda: all(fed.port_free(p) for p in self.ports()),
                       None, timeout=30)
        self.start(secret_path, env)


def describe_exit(code):
    if code is None:
        return "running"
    if code < 0:
        try:
            return "killed by %s" % signal.Signals(-code).name
        except ValueError:
            return "killed by signal %d" % -code
    return "exit code %d" % code


def crash_reports(since, pid):
    """macOS .ips crash reports for pid written after `since`."""
    out = []
    for path in glob.glob(os.path.join(CRASH_DIR, "*.ips")):
        try:
            if os.path.getmtime(path) < since - 1:
                continue
            with open(path, errors="replace") as f:
                head = f.read(4096)
        except OSError:
            continue
        if re.search(r'"pid"\s*:\s*%d\b' % pid, head) or \
                "[%d]" % pid in head:
            out.append(path)
    return out


def summarize_ips(path, nframes=25):
    """Exception and crashed thread frames from a JSON .ips report."""
    try:
        with open(path, errors="replace") as f:
            text = f.read()
        nl = text.index("\n")
        body = json.loads(text[nl + 1:])
    except (OSError, ValueError):
        return []
    lines = []
    exc = body.get("exception", {})
    lines.append("exception: %s %s %s" % (
        exc.get("type", "?"), exc.get("signal", ""),
        exc.get("subtype", "")))
    images = body.get("usedImages", [])
    for th in body.get("threads", []):
        if not th.get("triggered"):
            continue
        for fr in th.get("frames", [])[:nframes]:
            img = images[fr.get("imageIndex", 0)] \
                if fr.get("imageIndex", 0) < len(images) else {}
            sym = fr.get("symbol", "0x%x" % fr.get("imageOffset", 0))
            loc = ""
            if "sourceFile" in fr:
                loc = "  %s:%s" % (fr["sourceFile"], fr.get("sourceLine"))
            lines.append("  %-14s %s+%s%s" % (
                img.get("name", "?")[:14], sym,
                fr.get("symbolLocation", 0), loc))
    return lines


def sanitizer_reports(workdir, pid):
    return sorted(glob.glob(os.path.join(workdir, "*san-*.%d" % pid)))


def report_crash(sft, ev, workdir, crashes):
    code = sft.proc.p.returncode
    pid = sft.pid
    print("\n" + "=" * 72)
    print("CRASH: %s (pid %d, incarnation %d) %s after %.0fs"
          % (sft.name, pid, sft.incarnation, describe_exit(code),
             time.time() - sft.started_at))
    ev("CRASH %s pid %d %s", sft.name, pid, describe_exit(code))
    info = {"sftd": sft.name, "pid": pid, "exit": describe_exit(code),
            "log": sft.proc.logpath, "sanitizer": [], "ips": []}
    # ASan writes its report before aborting; the crash reporter takes
    # a few seconds to write the .ips.
    time.sleep(3)
    for path in sanitizer_reports(workdir, pid):
        info["sanitizer"].append(path)
        print("--- %s" % path)
        with open(path, errors="replace") as f:
            rep = f.read().splitlines()
        print("\n".join(rep[:80]))
        if len(rep) > 80:
            print("    ... (%d more lines)" % (len(rep) - 80))
    if IS_MAC:
        deadline = time.time() + 20
        while time.time() < deadline and not info["ips"]:
            info["ips"] = crash_reports(sft.started_at, pid)
            if not info["ips"]:
                time.sleep(1)
        for path in info["ips"]:
            print("--- %s" % path)
            print("\n".join(summarize_ips(path)))
    log = sft.proc.log().splitlines()
    print("--- last lines of %s" % sft.proc.logpath)
    print("\n".join(log[-30:]))
    print("--- last chaos events (events.log)")
    print("\n".join(ev.tail()[-20:]))
    print("=" * 72 + "\n")
    crashes.append(info)


# ---------------------------------------------------------------------------
# Chaos actors

class Slot(threading.Thread):
    """Keeps starting sftloader calls with random shapes and fates."""

    def __init__(self, k, ctx):
        super().__init__(daemon=True, name="slot%d" % k)
        self.k = k
        self.ctx = ctx
        self.rng = random.Random(ctx.args.seed * 1000 + k)
        self.calls = 0
        self.fates = {}

    def users(self, n, convn):
        sfts = self.ctx.sfts
        host = sfts[0]
        start = self.rng.randrange(len(sfts))
        cfg = []
        for i in range(n):
            sft = sfts[(start + i) % len(sfts)]
            # Big call: the same users leave and rejoin.
            uid = "b%du%02d" % (self.k, i) if self.ctx.args.big_call \
                else "s%dc%du%02d" % (self.k, convn, i)
            e = {"userid": uid,
                 "sft_url": sft.url, "sfts_all": [sft.url],
                 "is_federating": sft is not host}
            if i > 0:
                # Sometimes everyone at once, sometimes staggered.
                e["answer_ms"] = self.rng.choice(
                    [0, 0, self.rng.randint(0, 300),
                     self.rng.randint(500, 6000)])
            cfg.append(e)
        return cfg

    def run(self):
        a = self.ctx.args
        rng = self.rng
        while not self.ctx.stop.is_set():
            self.calls += 1
            n = self.calls
            name = "slot%d-%04d" % (self.k, n)
            if a.big_call:
                # One big conversation: this slot's share of the users
                # stays in it for a while, then leaves (by its fate) and
                # rejoins.
                nusers = self.ctx.big_sizes[self.k]
                dur = rng.uniform(0.5, 1.5) * a.big_churn
                cpu = 1
                convid = self.ctx.big_convid
            else:
                nusers = rng.randint(2, a.max_users)
                dur = rng.choice([rng.uniform(3, 10),
                                  rng.uniform(10, a.max_call)])
                cpu = rng.choice([1, 1, 1, 2, 3])
                convid = self.ctx.convid(rng)
            cfg = os.path.join(self.ctx.workdir, "cfg", name + ".json")
            with open(cfg, "w") as f:
                json.dump(self.users(nusers, n), f)
            argv = [a.sftloader, "-C", cfg, "-i", convid,
                    "-n", str(cpu), "-d", str(max(1, int(dur / cpu))),
                    "-P", "octo", "-v"]
            if a.big_call:
                # Clients show a page of tiles and page through them.
                argv += ["-W", str(rng.choice([4, 9, 9, 9]))]
                if rng.random() < 0.7:
                    argv += ["-R", str(rng.choice([500, 1000, 2500,
                                                   5000]))]
            elif rng.random() < 0.5 and nusers > 2:
                argv += ["-W", str(rng.randint(1, nusers - 2) or 1),
                         "-R", str(rng.choice([300, 1000, 2500]))]
            if a.loader_logs:
                argv += ["-l", os.path.join(self.ctx.workdir, "loaders",
                                            name + "-wcall.log")]
            fate = rng.choices(["clean", "kill", "freeze", "term"],
                               weights=a.fate_weights)[0]
            # Early kills hit setup: ICE, DTLS, SCTP, the first SETUP.
            at = rng.choice([rng.uniform(0.2, 4), rng.uniform(0.2, dur)])
            self.fates[fate] = self.fates.get(fate, 0) + 1
            self.ctx.ev("%s start conv %s users %d dur %.1fs n %d %s fate "
                        "%s at %.1fs", name, convid[:8], nusers, dur, cpu,
                        "tiles" if "-W" in argv else "", fate, at)
            p = Proc(name, argv, os.path.join(self.ctx.workdir, "loaders"))
            t0 = time.time()
            try:
                self.drive(p, fate, at, dur, t0)
            finally:
                p.stop(grace=2)
                if not a.keep_loader_logs:
                    for suffix in (".log", ".cmd"):
                        try:
                            os.unlink(os.path.join(
                                self.ctx.workdir, "loaders", name + suffix))
                        except OSError:
                            pass
            # Sometimes start the next call right away.
            self.ctx.stop.wait(rng.choice([0, 0, rng.uniform(0, 3)]))

    def drive(self, p, fate, at, dur, t0):
        rng = self.rng
        stop = self.ctx.stop
        deadline = t0 + dur + 30
        while p.alive() and not stop.is_set():
            now = time.time()
            if fate != "clean" and now - t0 >= at:
                if fate == "kill":
                    self.ctx.ev("%s SIGKILL", p.name)
                    p._signal(signal.SIGKILL)
                elif fate == "term":
                    self.ctx.ev("%s SIGTERM", p.name)
                    p._signal(signal.SIGTERM)
                else:
                    hold = rng.choice([rng.uniform(1, 8),
                                       rng.uniform(8, 70)])
                    self.ctx.ev("%s SIGSTOP for %.1fs", p.name, hold)
                    p._signal(signal.SIGSTOP)
                    stop.wait(hold)
                    if rng.random() < 0.5:
                        self.ctx.ev("%s SIGCONT", p.name)
                        p._signal(signal.SIGCONT)
                    else:
                        self.ctx.ev("%s SIGKILL (frozen)", p.name)
                        p._signal(signal.SIGKILL)
                return
            if now > deadline:
                self.ctx.ev("%s overran, SIGKILL", p.name)
                p._signal(signal.SIGKILL)
                return
            stop.wait(0.1)


class HttpChaos(threading.Thread):
    def __init__(self, ctx):
        super().__init__(daemon=True, name="http")
        self.ctx = ctx
        self.rng = random.Random(ctx.args.seed + 7)
        self.n = 0

    def run(self):
        while not self.ctx.stop.wait(self.rng.uniform(
                0, 2 * self.ctx.args.http_chaos)):
            with self.ctx.lock:
                sfts = [s for s in self.ctx.sfts if s.proc.alive()]
            if not sfts:
                continue
            s = self.rng.choice(sfts)
            path = self.rng.choice(["/metrics", "/metrics", "/debug"])
            self.n += 1
            if path == "/debug":
                self.ctx.ev("http %s %s", s.name, path)
            try:
                urllib.request.urlopen("http://%s:%d%s" % (
                    LOCALHOST, s.metrics_port, path), timeout=10).read()
            except OSError:
                pass


# ---------------------------------------------------------------------------

class Ctx:
    pass


def run(args):
    workdir = args.workdir or tempfile.mkdtemp(prefix="sft-stress-")
    for d in ("", "cfg", "loaders"):
        os.makedirs(os.path.join(workdir, d), exist_ok=True)
    if args.seed is None:
        args.seed = random.randrange(1 << 30)
    print("logs: %s" % workdir)
    print("seed: %d" % args.seed)

    need = [(args.sftd, "sftd"), (args.sftloader, "sftloader")]
    if args.topology != "single":
        need.append((args.coturn, "turnserver"))
    for path, what in need:
        if not os.access(path, os.X_OK):
            raise SetupError("%s binary not found: %s" % (what, path))
    if args.max_users < 2:
        raise SetupError("--max-users must be at least 2")

    with open(args.sftd, "rb") as f:
        args.asan = b"__asan_init" in f.read()
    print("sftd: %s (%s)" % (args.sftd, "ASan" if args.asan else
                             "Guard Malloc" if args.guard_malloc else
                             "MallocScribble" if args.malloc_debug else
                             "no memory checking: see --guard-malloc"))
    args.wrap = None
    args.leaks = False
    turns, sfts = ml.build_topology(args, workdir, args.sftd)
    busy = [p for c in turns + sfts for p in c.ports()
            if not fed.port_free(p)]
    if busy:
        raise SetupError("ports already in use: %s (use --base-port)" % busy)
    sfts = [Sftd(s.name, s.port, args, workdir, s.binary, s.coturn)
            for s in sfts]
    secret_path = os.path.join(workdir, "secret.txt")
    with open(secret_path, "w") as f:
        f.write(SECRET + "\n")
    fed.SECRET = SECRET

    ev = Events(os.path.join(workdir, "events.log"))
    ctx = Ctx()
    ctx.args, ctx.workdir, ctx.ev, ctx.sfts = args, workdir, ev, sfts
    ctx.stop = threading.Event()
    ctx.lock = threading.Lock()
    convs = []

    def convid(rng):
        # Reuse a recent conversation sometimes: calls then join groups
        # that are still up, or being torn down.
        if convs and rng.random() < args.share:
            return rng.choice(convs[-8:])
        c = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        convs.append(c)
        return c
    ctx.convid = convid
    if args.big_call:
        ctx.big_convid = str(uuid.UUID(int=random.Random(
            args.seed).getrandbits(128), version=4))
        q, r = divmod(args.big_call, args.slots)
        ctx.big_sizes = [q + (1 if k < r else 0) for k in range(args.slots)]
        if min(ctx.big_sizes) < 1:
            raise SetupError("--big-call needs at least --slots users")
        print("big call %s: %d users in %d sftloaders (%s), churn ~%.0fs"
              % (ctx.big_convid, args.big_call, args.slots,
                 "/".join(map(str, ctx.big_sizes)), args.big_churn))
    if args.term_every is None:
        args.term_every = 0 if args.big_call else 120
    if args.peer_chaos is None:
        args.peer_chaos = 0 if args.big_call else 60

    envs = {s.name: sftd_env(args, workdir, s.name) for s in sfts}
    crashes = []
    checks = fed.Checks()
    rng = random.Random(args.seed + 1)
    slots = []
    stats = {"peer_kills": 0, "peer_freezes": 0, "terms": 0,
             "drains_ok": 0, "drains_slow": 0}
    frozen = {}                     # sftd -> SIGCONT time
    try:
        for t in turns:
            t.start()
        for s in sfts:
            s.start(secret_path, envs[s.name])
            print("started %s pid %d (%s)" % (s.name, s.pid, s.url))

        slots = [Slot(k, ctx) for k in range(args.slots)]
        for sl in slots:
            sl.start()
        http = HttpChaos(ctx) if args.http_chaos else None
        if http:
            http.start()

        t0 = time.time()
        end = t0 + args.time
        next_peer = t0 + rng.uniform(0.5, 1.5) * args.peer_chaos \
            if args.peer_chaos and len(sfts) > 1 else None
        next_term = t0 + args.term_every if args.term_every else None
        next_status = t0 + 30
        draining = {}               # sftd -> (deadline, metrics at TERM)
        done = set()                # exited after the final SIGTERM

        def start_drain(s):
            if frozen.pop(s, None):
                s.proc._signal(signal.SIGCONT)
            m = s.metrics() or {}
            ev("SIGTERM %s with %s calls / %s participants", s.name,
               m.get("sft_calls"), m.get("sft_participants"))
            s.proc._signal(signal.SIGTERM)
            draining[s] = (time.time() + args.drain_timeout, m)

        def watch(restart):
            """Crashes, finished drains, drains that take too long."""
            now = time.time()
            for s in sfts:
                if s in done:
                    continue
                if s in draining:
                    deadline, m = draining[s]
                    if s.proc.alive() and now < deadline:
                        continue
                    del draining[s]
                    if not restart:
                        done.add(s)
                    if s.proc.alive():
                        left = s.metrics()
                        ev("%s still up %.0fs after SIGTERM: %s", s.name,
                           args.drain_timeout, left)
                        if restart:
                            # Mid-run the clients keep (re)joining the
                            # groups it still has, so a drain may not end.
                            stats["drains_slow"] += 1
                        else:
                            checks.check(
                                "%s drains after SIGTERM once the clients "
                                "are gone" % s.name, False,
                                "still up after %.0fs: %s"
                                % (args.drain_timeout, left))
                        s.proc._signal(signal.SIGKILL)
                        s.proc.p.wait()
                    else:
                        code = s.proc.p.returncode
                        ev("%s exited after SIGTERM: %s", s.name,
                           describe_exit(code))
                        if code != 0 or sanitizer_reports(workdir, s.pid):
                            report_crash(s, ev, workdir, crashes)
                        else:
                            stats["drains_ok"] += 1
                    if restart:
                        s.restart(secret_path, envs[s.name])
                        ev("restarted %s pid %d", s.name, s.pid)
                    continue
                if s.proc.alive():
                    continue
                report_crash(s, ev, workdir, crashes)
                if restart and args.keep_going:
                    s.restart(secret_path, envs[s.name])
                    ev("restarted %s pid %d", s.name, s.pid)

        while time.time() < end:
            time.sleep(0.5)
            now = time.time()
            with ctx.lock:
                watch(restart=True)
            if crashes and not args.keep_going:
                break
            for s in [s for s, t in frozen.items() if now >= t]:
                del frozen[s]
                s.proc._signal(signal.SIGCONT)
                ev("peer %s SIGCONT", s.name)
            if next_peer and now >= next_peer:
                next_peer = now + rng.uniform(0.5, 1.5) * args.peer_chaos
                victim = rng.choice(sfts[1:])
                with ctx.lock:
                    if victim in frozen or victim in draining:
                        pass
                    elif rng.random() < 0.3:
                        hold = rng.uniform(2, 40)
                        stats["peer_freezes"] += 1
                        ev("peer %s SIGSTOP for %.1fs", victim.name, hold)
                        victim.proc._signal(signal.SIGSTOP)
                        frozen[victim] = now + hold
                    else:
                        stats["peer_kills"] += 1
                        ev("peer %s SIGKILL + restart", victim.name)
                        victim.restart(secret_path, envs[victim.name])
                        ev("restarted %s pid %d", victim.name, victim.pid)
            if next_term and now >= next_term:
                next_term = now + args.term_every
                victim = rng.choice([s for s in sfts if s not in draining]
                                    or sfts)
                if victim not in draining:
                    stats["terms"] += 1
                    start_drain(victim)
            if now >= next_status:
                next_status = now + 30
                m = {s.name: s.metrics() or {} for s in sfts}
                print("  %5.0fs  calls started %4d  crashes %d  %s" % (
                    now - t0, sum(sl.calls for sl in slots), len(crashes),
                    "  ".join("%s%s %s/%s" % (
                        n, "(draining)" if any(
                            s.name == n for s in draining) else "",
                        v.get("sft_calls"), v.get("sft_participants"))
                        for n, v in m.items())))
                sys.stdout.flush()

        # The end: SIGTERM every sftd with calls still up, like a
        # rollout. Clients keep calling (and get ESHUTDOWN) while the
        # sftds drain; each must exit 0 once its calls are gone.
        if not crashes or args.keep_going:
            # Stop the clients: loaders get SIGTERM (hang up), frozen
            # ones stay frozen until SIGKILL. sftd then has to time out
            # whatever is left on its own.
            print("  stopping clients, draining every sftd (SIGTERM)")
            ctx.stop.set()
            for s in list(frozen):
                s.proc._signal(signal.SIGCONT)
            frozen.clear()
            for s in sfts:
                if s.proc.alive() and s not in draining:
                    stats["terms"] += 1
                    start_drain(s)
            while draining:
                time.sleep(0.5)
                with ctx.lock:
                    watch(restart=False)
    except KeyboardInterrupt:
        print("interrupted")
    finally:
        ctx.stop.set()
        for sl in slots:
            sl.join(timeout=80)
        for s in sfts:
            if s.proc and s.proc.alive():
                s.proc._signal(signal.SIGCONT)
                s.proc.stop(grace=args.shutdown_grace)
        for t in turns:
            t.proc.stop()

    fates = {}
    for sl in slots:
        for f, c in sl.fates.items():
            fates[f] = fates.get(f, 0) + c
    print("\ncalls: %d  fates: %s  peer kills: %d  peer freezes: %d  "
          "SIGTERM drains: %d (%d exited cleanly, %d mid-run drains "
          "killed after --drain-timeout)"
          % (sum(sl.calls for sl in slots),
             ", ".join("%s %d" % kv for kv in sorted(fates.items())),
             stats["peer_kills"], stats["peer_freezes"], stats["terms"],
             stats["drains_ok"], stats["drains_slow"]))
    checks.check("no sftd crashed", not crashes,
                 "; ".join("%s %s" % (c["sftd"], c["exit"])
                           for c in crashes))
    with open(os.path.join(workdir, "crashes.json"), "w") as f:
        json.dump(crashes, f, indent=1)
    checks.report()
    ok = checks.passed()
    print("\nRESULT: %s  (seed %d, logs in %s)"
          % ("PASS" if ok else "FAIL", args.seed, workdir))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--sftd", default=os.environ.get(
        "SFTD_BIN", ml.DEFAULT_SFTD),
        help="./sftd-asan from make-asan.sh on Linux")
    ap.add_argument("--sftloader", default=os.environ.get(
        "SFTLOADER_BIN", ml.DEFAULT_SFTLOADER))
    ap.add_argument("--coturn", default=os.environ.get(
        "COTURN_BIN", ml.DEFAULT_COTURN))
    ap.add_argument("--certs", default=os.environ.get(
        "COTURN_CERTS", fed.DEFAULT_CERTS))
    ap.add_argument("--topology", choices=["single", "fed2", "fed3"],
                    default="fed3")
    ap.add_argument("--time", type=float, default=600,
                    help="seconds of chaos")
    ap.add_argument("--seed", type=int, help="default: random")
    ap.add_argument("--slots", type=int, default=4,
                    help="concurrent sftloader calls")
    ap.add_argument("--max-users", type=int, default=6)
    ap.add_argument("--max-call", type=float, default=60,
                    help="longest call in seconds")
    ap.add_argument("--fate-weights", type=lambda s: [float(x) for x in
                                                      s.split(",")],
                    default=[3, 4, 2, 1],
                    help="weights of clean,kill,freeze,term")
    ap.add_argument("--share", type=float, default=0.25,
                    help="probability a call reuses a recent conv id")
    ap.add_argument("--peer-chaos", type=float,
                    help="mean seconds between killing/freezing a "
                    "non-host sftd (fed topologies; 0: off; default 60, "
                    "0 with --big-call)")
    ap.add_argument("--http-chaos", type=float, default=2,
                    help="mean seconds between /metrics, /debug polls "
                    "(0: off)")
    ap.add_argument("--term-every", type=float,
                    help="SIGTERM (drain) a random sftd with calls up "
                    "every N seconds, restart it once it exits (0: only "
                    "at the end; default 120, 0 with --big-call)")
    ap.add_argument("--big-call", type=int, default=0, metavar="N",
                    help="instead of many small calls: one conversation "
                    "with N users split over the --slots sftloaders, "
                    "each slot leaving (by its fate) and rejoining")
    ap.add_argument("--big-churn", type=float, default=90,
                    help="--big-call: mean seconds a slot's users stay "
                    "before leaving and rejoining")
    ap.add_argument("--drain-timeout", type=float, default=180,
                    help="max seconds an sftd may take to drain and exit "
                    "after SIGTERM (it waits for its calls to end)")
    ap.add_argument("--shutdown-grace", type=float, default=20)
    ap.add_argument("--keep-going", action="store_true",
                    help="restart a crashed sftd and continue")
    ap.add_argument("--guard-malloc", action="store_true",
                    help="macOS: run sftd with libgmalloc (Guard Malloc), "
                    "use-after-free/overruns fault immediately")
    ap.add_argument("--malloc-debug", action="store_true",
                    help="macOS MallocScribble etc.: cheaper than "
                    "--guard-malloc, freed memory is poisoned")
    ap.add_argument("--workers", type=int, help="sftd -w")
    ap.add_argument("--sftd-verbose", action="store_true",
                    help="no -q: full sftd logs (big, but show what led "
                    "to a crash)")
    ap.add_argument("--loader-logs", action="store_true",
                    help="sftloader -l wcall logs")
    ap.add_argument("--keep-loader-logs", action="store_true")
    ap.add_argument("--base-port", type=int, default=34000)
    ap.add_argument("--workdir")
    args = ap.parse_args()
    try:
        sys.exit(run(args))
    except SetupError as e:
        print("SETUP ERROR: %s" % e)
        sys.exit(2)


if __name__ == "__main__":
    main()
