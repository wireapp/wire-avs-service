#!/usr/bin/env python3
"""
End-to-end test for SFT federation over TURN.

Topology (default "star" case):

    domain A: coturn-A + sftd-host            client usera -> sftd-host
    domain B: coturn-B + sftd-2 + sftd-3      client userb -> sftd-2
                                              client userc -> sftd-3

Each sftd federates through its own domain's coturn (sftd -t). The
non-host SFTs reach the host via coturn-B <-> coturn-A federation link
(DTLS mTLS by default), so both non-host links share one federation link.

All clients run in one sftloader process (-C users.json -V). sftloader
stamps each sender's video and checks that every receiver decodes the
right stamp from every other participant, exiting non-zero otherwise.

The "tiles" case checks tile switching: every receiver requests fewer
video streams than there are senders and rotates which senders it
requests (sftloader -W/-R), so the SFT keeps handing a stream to a
different source. A receiver that decodes the new source's frames on
the old source's reference frames shows the old user's stamp under the
new user's name, which counts as wrong video. That only happens when
the senders' frame ids (libwebrtc starts them at 0) are close, so all
clients start video at the same moment (sftloader -Y).

Everything runs natively on 127.0.0.1. Only the standard library is used.

Exit code: 0 = all checks passed, 1 = a check failed, 2 = setup error.
"""

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PROJECTS = os.path.dirname(REPO)

DEFAULT_SFTD = os.path.join(REPO, "sftd")
DEFAULT_SFTLOADER = os.path.join(PROJECTS, "wire-avs", "sftloader")
# Wire coturn v5.6.0, built from a worktree of ../wire-coturn with a
# small macOS portability patch (see /tmp/coturn-v5.6.0-build-fix.patch).
DEFAULT_COTURN = "/tmp/coturn-v5.6.0-build/bin/turnserver"
DEFAULT_CERTS = os.path.join(PROJECTS, "wire-coturn", "test")

SECRET = "sft-fed-e2e-secret"
REALM = "wire.test"
LOCALHOST = "127.0.0.1"


class SetupError(Exception):
    pass


# ---------------------------------------------------------------------------
# Process handling

class Proc:
    def __init__(self, name, argv, logdir, env=None):
        self.name = name
        self.argv = argv
        self.logpath = os.path.join(logdir, name + ".log")
        self.logf = open(self.logpath, "wb")
        with open(os.path.join(logdir, name + ".cmd"), "w") as f:
            f.write(" ".join(argv) + "\n")
        self.p = subprocess.Popen(argv, stdout=self.logf,
                                  stderr=subprocess.STDOUT,
                                  stdin=subprocess.DEVNULL,
                                  env=env, start_new_session=True)

    def alive(self):
        return self.p.poll() is None

    def log(self):
        if not self.logf.closed:
            self.logf.flush()
        with open(self.logpath, "r", errors="replace") as f:
            return f.read()

    def _signal(self, sig):
        # killpg can fail with EPERM on macOS once the group leader is a
        # zombie; fall back to signalling the process itself.
        try:
            os.killpg(self.p.pid, sig)
        except OSError:
            try:
                self.p.send_signal(sig)
            except OSError:
                pass

    def stop(self, grace=5.0):
        if self.alive():
            self._signal(signal.SIGTERM)
            try:
                self.p.wait(grace)
            except subprocess.TimeoutExpired:
                self._signal(signal.SIGKILL)
                self.p.wait()
        self.logf.close()


def wait_until(what, cond, proc, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return
        if proc is not None and not proc.alive():
            raise SetupError("%s exited during startup (code %s), see %s"
                             % (proc.name, proc.p.returncode, proc.logpath))
        time.sleep(0.2)
    raise SetupError("timed out waiting for %s" % what)


def tcp_open(port):
    try:
        with socket.create_connection((LOCALHOST, port), timeout=0.5):
            return True
    except OSError:
        return False


def port_free(port):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        s = socket.socket(socket.AF_INET, kind)
        # Like the servers themselves, ignore TIME_WAIT leftovers (e.g.
        # from the previous run's metrics scrape); only live binds count.
        if kind == socket.SOCK_STREAM:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((LOCALHOST, port))
        except OSError:
            return False
        finally:
            s.close()
    return True


# ---------------------------------------------------------------------------
# Components

def coturn_has_prometheus(binary):
    """v5.6.0 needs libprom for metrics; builds without it lack --prometheus."""
    try:
        out = subprocess.run([binary, "--help"], capture_output=True,
                             text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "--prometheus" in (out.stdout + out.stderr)


class Coturn:
    def __init__(self, name, base, args, workdir):
        self.name = name
        self.port = base
        self.fed_port = base + 1
        self.prom_port = base + 2
        self.min_port = base + 100
        self.max_port = base + 199
        self.args = args
        self.workdir = workdir
        self.proc = None

    def ports(self):
        return [self.port, self.fed_port, self.prom_port]

    def write_conf(self):
        c = self.args.certs
        lines = [
            "listening-ip=%s" % LOCALHOST,
            "listening-port=%d" % self.port,
            "relay-ip=%s" % LOCALHOST,
            "min-port=%d" % self.min_port,
            "max-port=%d" % self.max_port,
            "relay-threads=%d" % self.args.relay_threads,
            "federation-listening-ip=%s" % LOCALHOST,
            "federation-listening-port=%d" % self.fed_port,
            "federation-no-dtls=%s"
            % ("true" if self.args.federation_no_dtls else "false"),
            "federation-cert=%s" % os.path.join(c, "federation_rsa_cert.pem"),
            "federation-pkey=%s" % os.path.join(c, "federation_rsa_pkey.pem"),
            "federation-remote-whitelist=Server,ServerCA",
            "CA-file=%s" % os.path.join(c, "ca_rsa_cert.pem"),
            "zrest",
            "static-auth-secret=%s" % SECRET,
            "realm=%s" % REALM,
            "allow-loopback-peers",
            "no-tls",
            "no-cli",
            "log-file=stdout",
            "simple-log",
            "verbose",
        ]
        if self.args.prometheus:
            lines += ["prometheus",
                      "prometheus-address=%s" % LOCALHOST,
                      "prometheus-port=%d" % self.prom_port]
        path = os.path.join(self.workdir, self.name + ".conf")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return path

    def start(self):
        conf = self.write_conf()
        self.proc = Proc(self.name, [self.args.coturn, "-c", conf],
                         self.workdir)
        wait_until(self.name,
                   lambda: "Total auth threads:" in self.proc.log(),
                   self.proc)

    def turn_url(self):
        return "turn:%s:%d?transport=%s" % (LOCALHOST, self.port,
                                           self.args.turn_transport)

    def metrics(self):
        url = "http://%s:%d/metrics" % (LOCALHOST, self.prom_port)
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                return r.read().decode(errors="replace")
        except OSError as e:
            return "# scrape failed: %s\n" % e


class Sftd:
    def __init__(self, name, base, coturn, args, workdir):
        self.name = name
        self.port = base
        self.metrics_port = base + 1
        self.coturn = coturn
        self.args = args
        self.workdir = workdir
        self.proc = None

    def ports(self):
        return [self.port, self.metrics_port]

    @property
    def url(self):
        return "http://%s:%d" % (LOCALHOST, self.port)

    def start(self, secret_path):
        argv = [self.args.sftd,
                "-I", LOCALHOST, "-p", str(self.port),
                "-M", LOCALHOST, "-r", str(self.metrics_port),
                "-A", LOCALHOST,
                "-u", self.url,
                "-t", self.coturn.turn_url(),
                "-s", secret_path]
        self.proc = Proc(self.name, argv, self.workdir)
        wait_until(self.name, lambda: tcp_open(self.port), self.proc)


# ---------------------------------------------------------------------------
# Test

def build_topology(args, workdir):
    b = args.base_port
    turn_a = Coturn("coturn-A", b, args, workdir)
    turn_b = Coturn("coturn-B", b + 200, args, workdir)
    host = Sftd("sftd-host", b + 400, turn_a, args, workdir)
    sft2 = Sftd("sftd-2", b + 410, turn_b, args, workdir)
    sft3 = Sftd("sftd-3", b + 420, turn_b, args, workdir)

    # (userid, sft) in start order: the first user starts the call,
    # so the host's client must come first.
    if args.case == "star":
        sfts = [host, sft2, sft3]
        users = [("usera", host), ("userb", sft2), ("userc", sft3)]
    elif args.case == "control":
        sfts = [host, sft2]
        users = [("usera", host), ("userb", sft2)]
    elif args.case == "tiles":
        # Three local sources on the host (on-demand keyframe on switch)
        # and one behind a federated SFT (relies on its periodic FIR).
        sfts = [host, sft2]
        users = [("usera", host), ("userb", host), ("userc", host),
                 ("userd", sft2)]
    else:
        raise SetupError("unknown case %s" % args.case)

    return [turn_a, turn_b], sfts, users


def users_cfg(users, host, args):
    cfg = []
    for i, (userid, sft) in enumerate(users):
        entry = {
            "userid": userid,
            "sft_url": sft.url,
            # Only the user's own SFT, so non-host clients join their own
            # SFT (which federates to the host) instead of the host directly.
            "sfts_all": [sft.url],
            "is_federating": sft is not host,
        }
        if i > 0:
            entry["answer_ms"] = args.answer_ms
        cfg.append(entry)
    return cfg


VRX_RE = re.compile(r"VIDEO_RX\[final\] recv=(\S+) from=(\S+) frames=(\d+) "
                    r"ok=(\d+) wrong=(\d+) unreadable=(\d+) wrong_from=(\S+)")


class Checks:
    def __init__(self):
        self.results = []

    def check(self, name, ok, detail=""):
        self.results.append((name, bool(ok), detail))

    def passed(self):
        return all(ok for _, ok, _ in self.results)

    def report(self):
        print("\n=== Checks ===")
        for name, ok, detail in self.results:
            print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                                   (": " + detail) if detail else ""))


def metric_value(text, name):
    """Sum of all samples of a metric; None if the metric is not exported.

    Labeled counters (e.g. turn_auth_credential_failures{cause=...}) emit
    no samples until the first increment, so a declared metric without
    samples counts as 0.
    """
    total = None
    for line in text.splitlines():
        if re.match(r"^#\s+TYPE\s+%s\s" % re.escape(name), line):
            total = total or 0.0
        elif line.startswith(name):
            m = re.match(r"^%s(\{[^}]*\})?\s+(\S+)" % re.escape(name), line)
            if m:
                total = (total or 0.0) + float(m.group(2))
    return total


def run(args):
    workdir = args.workdir or tempfile.mkdtemp(prefix="sft-fed-e2e-")
    os.makedirs(workdir, exist_ok=True)
    print("logs: %s" % workdir)

    for path, what in ((args.sftd, "sftd"), (args.sftloader, "sftloader"),
                       (args.coturn, "turnserver")):
        if not os.access(path, os.X_OK):
            raise SetupError("%s binary not found: %s" % (what, path))

    args.prometheus = coturn_has_prometheus(args.coturn)
    if not args.prometheus:
        print("note: %s has no Prometheus support, skipping metrics checks"
              % args.coturn)

    turns, sfts, users = build_topology(args, workdir)
    host = sfts[0]

    busy = [p for c in turns + sfts for p in c.ports() if not port_free(p)]
    if busy:
        raise SetupError("ports already in use: %s (stale processes? "
                         "or use --base-port)" % busy)

    secret_path = os.path.join(workdir, "secret.txt")
    with open(secret_path, "w") as f:
        f.write(SECRET + "\n")

    cfg = users_cfg(users, host, args)
    cfg_path = os.path.join(workdir, "users.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=2)

    procs = []
    checks = Checks()
    try:
        for t in turns:
            t.start()
            procs.append(t.proc)
            print("started %s (turn %d, federation %d, metrics %d)"
                  % (t.name, t.port, t.fed_port, t.prom_port))
        for s in sfts:
            s.start(secret_path)
            procs.append(s.proc)
            print("started %s (%s, turn %s)"
                  % (s.name, s.url, s.coturn.name))

        argv = [args.sftloader, "-C", cfg_path, "-V", "-P", args.pattern,
                "-d", str(args.duration), "-n", "1",
                "-l", os.path.join(workdir, "sftloader-wcall.log")]
        if args.max_streams:
            argv += ["-W", str(args.max_streams)]
        if args.rotate_ms:
            argv += ["-R", str(args.rotate_ms)]
        if args.video_sync_ms:
            argv += ["-Y", str(args.video_sync_ms)]
        print("running sftloader for %ds (%s case, %d users%s)"
              % (args.duration, args.case, len(users),
                 ", %d stream(s) per receiver rotating every %dms"
                 % (args.max_streams or 9, args.rotate_ms)
                 if args.rotate_ms else ""))
        sl = Proc("sftloader", argv, workdir)
        procs.append(sl)
        try:
            sl.p.wait(args.duration + args.grace)
            sl_code = sl.p.returncode
        except subprocess.TimeoutExpired:
            sl_code = None

        # Servers must survive the whole call.
        died = {p.name: p.p.returncode for p in procs
                if p is not sl and not p.alive()}

        # Scrape before teardown; coturn's metrics die with it.
        metrics = {}
        for t in turns if args.prometheus else []:
            metrics[t.name] = t.metrics()
            with open(os.path.join(workdir, t.name + ".metrics"), "w") as f:
                f.write(metrics[t.name])
    finally:
        for p in reversed(procs):
            p.stop()

    checks.check("servers alive until teardown", not died,
                 ", ".join("%s exit=%s" % kv for kv in died.items()))

    # --- sftloader / video ---
    out = sl.log()
    checks.check("sftloader finished in time", sl_code is not None,
                 "" if sl_code is not None else
                 "killed after %ds" % (args.duration + args.grace))
    checks.check("sftloader exit code 0", sl_code == 0,
                 "exit=%s" % sl_code)
    checks.check("VIDEO_VERIFY PASS", "VIDEO_VERIFY: PASS" in out,
                 (re.search(r"VIDEO_VERIFY: .*", out) or
                  re.match("", "no VIDEO_VERIFY line")).group(0))

    rows = VRX_RE.findall(out)
    seen = {(r[0], r[1]) for r in rows}
    expected = {(a + ".", b + ".") for a, _ in users for b, _ in users
                if a != b}
    missing = [(r, s) for r, s in expected
               if not any(x[0].startswith(r) and x[1].startswith(s)
                          for x in seen)]
    checks.check("every pair reported", not missing,
                 "missing %s" % missing if missing else
                 "%d pairs" % len(rows))

    print("\n=== Video (receiver <- sender) ===")
    sft_of = {u: s.name for u, s in users}
    for recv, frm, frames, ok, wrong, unread, wfrom in rows:
        ru, fu = recv.split(".")[0], frm.split(".")[0]
        bad = int(ok) == 0 or int(wrong) > 0
        print("  %-5s %s (%s) <- %s (%s): frames=%s ok=%s wrong=%s "
              "unreadable=%s%s"
              % ("FAIL" if bad else "ok", recv, sft_of.get(ru, "?"),
                 frm, sft_of.get(fu, "?"), frames, ok, wrong, unread,
                 " wrong_from=" + wfrom if wfrom != "-" else ""))

    # --- tile switching ---
    if args.rotate_ms:
        sel = re.findall(r"^TILES user=(\S+) streams=\[([^\]]*)\]", out,
                         re.M)
        # The first request per user is the initial selection, not a switch
        last = {}
        switches = 0
        for user, streams in sel:
            if user in last and last[user] != streams:
                switches += 1
            last[user] = streams
        min_switches = len(users) * 2
        checks.check("tile switches happened", switches >= min_switches,
                     "%d switches (need >= %d)" % (switches, min_switches))

    # --- sftd ---
    for s in sfts:
        log = s.proc.log()
        if args.rotate_ms:
            kf = len(re.findall(r"video_source_switch\(.*at keyframe", log))
            waits = len(re.findall(r"video_source_switch\(.*waiting", log))
            print("info: %s source switches at keyframe=%d slow=%d"
                  % (s.name, kf, waits))
        fp_ok = len(re.findall(r"fingerprint OK", log))
        fp_bad = len(re.findall(r"fingerprint mismatch|unknown fingerprint",
                                log))
        checks.check("%s DTLS-SRTP fingerprints" % s.name,
                     fp_ok > 0 and fp_bad == 0,
                     "ok=%d bad=%d" % (fp_ok, fp_bad))

    # --- coturn ---
    for t in turns:
        log = t.proc.log()
        fed_rx = len(re.findall(r"Federation listener received data cid=",
                                log))
        errors = re.findall(r"Error when verifying peer's chain[^\n]*|"
                            r"Found non-matching Issuer Name[^\n]*|"
                            r"invalid (?:channel range )?cid=[^\n]*|"
                            r"Cannot create ioa_socket from SSL[^\n]*", log)
        # Per-packet log only in some coturn versions / verbosity levels,
        # so informational; the video check proves traffic flowed.
        print("info: %s logged %d federation packets" % (t.name, fed_rx))
        checks.check("%s no federation errors" % t.name, not errors,
                     errors[0] if errors else "")
        if not args.federation_no_dtls:
            matched = "Found matching Issuer Name" in log
            checks.check("%s federation peer cert verified" % t.name,
                         matched)
        if args.prometheus:
            fails = metric_value(metrics[t.name],
                                 "turn_auth_credential_failures")
            checks.check("%s no auth failures (metrics)" % t.name,
                         fails is not None and fails == 0,
                         "turn_auth_credential_failures=%s" % fails)

    checks.report()
    ok = checks.passed()
    print("\nRESULT: %s  (logs in %s)" % ("PASS" if ok else "FAIL", workdir))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="SFT federation over TURN end-to-end test")
    ap.add_argument("--case", choices=["star", "control", "tiles"],
                    default="star",
                    help="star: host + 2 non-host SFTs in domain B "
                    "(default); control: host + 1 non-host SFT; tiles: "
                    "3 clients on the host + 1 on a non-host SFT, "
                    "rotating video tiles")
    ap.add_argument("--max-streams", type=int,
                    help="video streams each client requests (sftloader "
                    "-W; default 1 for tiles, else all)")
    ap.add_argument("--video-sync-ms", type=int,
                    help="start all video at once, ms after sftloader "
                    "start (sftloader -Y; default 6000 for tiles, else "
                    "off). Senders' frame ids then stay close, which is "
                    "what lets a receiver decode a new source's delta "
                    "frames on the old source's reference frames")
    ap.add_argument("--rotate-ms", type=int,
                    help="rotate the requested streams every ms "
                    "(sftloader -R; default 2500 for tiles, else off)")
    ap.add_argument("--sftd", default=os.environ.get("SFTD_BIN",
                                                     DEFAULT_SFTD))
    ap.add_argument("--sftloader", default=os.environ.get("SFTLOADER_BIN",
                                                          DEFAULT_SFTLOADER))
    ap.add_argument("--coturn", default=os.environ.get("COTURN_BIN",
                                                       DEFAULT_COTURN))
    ap.add_argument("--certs", default=os.environ.get("COTURN_CERTS",
                                                      DEFAULT_CERTS),
                    help="dir with federation_rsa_{cert,pkey}.pem and "
                    "ca_rsa_cert.pem")
    ap.add_argument("--duration", type=int, default=30,
                    help="call duration in seconds (default 30)")
    ap.add_argument("--grace", type=int, default=60,
                    help="extra seconds before sftloader is killed")
    ap.add_argument("--answer-ms", type=int, default=1000,
                    help="answer delay for non-starting clients")
    ap.add_argument("--pattern", choices=["head", "octo"], default="head")
    ap.add_argument("--relay-threads", type=int, default=1)
    ap.add_argument("--federation-no-dtls", action="store_true",
                    help="plain UDP between the coturns instead of DTLS")
    ap.add_argument("--turn-transport", choices=["udp", "tcp"],
                    default="udp", help="sftd -> coturn transport")
    ap.add_argument("--base-port", type=int, default=31000)
    ap.add_argument("--workdir", help="log dir (default: new temp dir)")
    args = ap.parse_args()
    if args.case == "tiles":
        if args.video_sync_ms is None:
            args.video_sync_ms = 6000
        if args.max_streams is None:
            args.max_streams = 1
        if args.rotate_ms is None:
            args.rotate_ms = 2500
    args.rotate_ms = args.rotate_ms or 0

    try:
        return run(args)
    except SetupError as e:
        print("SETUP ERROR: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
