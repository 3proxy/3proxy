#!/usr/bin/env python3
"""Compares the speed and the cost of proxies on Linux: 3proxy versions, and
other servers doing the same job.

The client, the proxy and the origin each run in a network namespace of their
own, linked by veth pairs, and in a cgroup of their own pinned to separate
CPUs, so they neither share a loopback nor take CPU from each other, and the
proxy's CPU time and memory can be read on their own. See README.md.

Needs root, iproute2, iperf3, wrk and nginx (the origin); haproxy only when
it is one of the proxies compared.

    sudo bench/bench.py --proxy 3proxy:bench/bin/3proxy-1.0.1 \\
        --proxy 3proxy:bench/bin/3proxy-devel --proxy nginx --proxy none
"""

import argparse
import csv
import datetime
import json
import os
import re
import resource
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time

CG = "/sys/fs/cgroup/3proxy-bench"

# client 10.0.1.2 -- 10.0.1.1 proxy 10.0.2.1 -- 10.0.2.2 origin
CLI_ADDR, PRX_IN, PRX_OUT, SRV_ADDR = "10.0.1.2", "10.0.1.1", "10.0.2.1", "10.0.2.2"
HTTP_PORT, TCP_PORT, ORIGIN_HTTP, ORIGIN_TCP = 3128, 5201, 8080, 5201

FILES = {"1k": 1024, "100k": 100 * 1024, "1m": 1024 * 1024}

# name: (kind, parameters)
SCENARIOS = {
    "stream1":       ("stream", {"streams": 1}),
    "stream16":      ("stream", {"streams": 16}),
    "stream1-down":  ("stream", {"streams": 1, "reverse": True}),
    "http-ka-1k":    ("http", {"file": "1k", "conns": 64}),
    "http-ka-1m":    ("http", {"file": "1m", "conns": 16}),
    "http-close-1k": ("http", {"file": "1k", "conns": 64, "close": True}),
}


def sh(cmd, check=True, **kw):
    return subprocess.run(cmd, shell=True, check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw).stdout


def cpulist(spec):
    cpus = []
    for part in spec.split(","):
        a, _, b = part.partition("-")
        cpus.extend(range(int(a), int(b or a) + 1))
    return cpus


def cpumask(spec):
    return "%x" % sum(1 << c for c in cpulist(spec))


# --- namespaces --------------------------------------------------------------

def net_up(args):
    net_down()
    for ns in ("bcli", "bprx", "bsrv"):
        sh(f"ip netns add {ns}")
        sh(f"ip -n {ns} link set lo up")
    sh("ip link add bc0 netns bcli type veth peer name bp0 netns bprx")
    sh("ip link add bp1 netns bprx type veth peer name bs0 netns bsrv")
    for ns, dev, addr in (("bcli", "bc0", CLI_ADDR), ("bprx", "bp0", PRX_IN),
                          ("bprx", "bp1", PRX_OUT), ("bsrv", "bs0", SRV_ADDR)):
        sh(f"ip -n {ns} addr add {addr}/24 dev {dev}")
        sh(f"ip -n {ns} link set {dev} mtu {args.mtu} up")
    # the direct baseline goes through the proxy namespace, routed by the
    # kernel
    sh(f"ip -n bcli route add 10.0.2.0/24 via {PRX_IN}")
    sh(f"ip -n bsrv route add 10.0.1.0/24 via {PRX_OUT}")
    sh("ip netns exec bprx sysctl -qw net.ipv4.ip_forward=1")
    for ns in ("bcli", "bprx", "bsrv"):
        sh(f"ip netns exec {ns} sysctl -qw net.core.somaxconn=65535 "
           "net.ipv4.tcp_max_syn_backlog=65535 net.ipv4.tcp_tw_reuse=1 "
           "net.ipv4.ip_local_port_range='1024 65535'")
    # A veth hands what it receives to the CPU that sent it; steer it to the
    # receiver's own CPUs instead.
    for ns, dev, role in (("bcli", "bc0", "cli"), ("bprx", "bp0", "prx"),
                          ("bprx", "bp1", "prx"), ("bsrv", "bs0", "srv")):
        sh(f"ip netns exec {ns} sh -c 'echo {cpumask(args.cpus[role])} "
           f"> /sys/class/net/{dev}/queues/rx-0/rps_cpus'", check=False)
    if args.netem:
        for ns, dev in (("bcli", "bc0"), ("bprx", "bp0")):
            sh(f"ip netns exec {ns} tc qdisc add dev {dev} root netem {args.netem}")


def net_down():
    for ns in ("bcli", "bprx", "bsrv"):
        sh(f"ip netns del {ns}", check=False)


# --- cgroups -----------------------------------------------------------------

def cg_write(path, value):
    with open(path, "w") as f:
        f.write(value)


def cg_read(path):
    with open(path) as f:
        return f.read()


def cg_up(args):
    os.makedirs(CG, exist_ok=True)
    cg_write("/sys/fs/cgroup/cgroup.subtree_control", "+cpuset +cpu +memory")
    cg_write(f"{CG}/cgroup.subtree_control", "+cpuset +cpu +memory")
    for role in ("cli", "srv"):
        cg_make(role, args.cpus[role])


def cg_make(role, cpus):
    path = f"{CG}/{role}"
    os.makedirs(path, exist_ok=True)
    cg_write(f"{path}/cpuset.cpus", cpus)
    return path


def cg_remove(role):
    path = f"{CG}/{role}"
    if not os.path.isdir(path):
        return
    for _ in range(50):
        try:
            os.rmdir(path)
            return
        except OSError:
            time.sleep(0.1)


def cg_down():
    for role in ("cli", "prx", "srv"):
        cg_remove(role)
    try:
        os.rmdir(CG)
    except OSError:
        pass


def cg_usage(role):
    """CPU seconds used so far by everything in the cgroup."""
    for line in cg_read(f"{CG}/{role}/cpu.stat").splitlines():
        name, value = line.split()
        if name == "usage_usec":
            return int(value) / 1e6
    return 0.0


def cg_peak(role):
    try:
        return int(cg_read(f"{CG}/{role}/memory.peak")) / 2**20
    except OSError:
        return float("nan")


# --- processes ---------------------------------------------------------------

def spawn(ns, role, argv, log):
    """Start a process in a namespace and a cgroup; threads it starts stay
    there with it."""
    procs = f"{CG}/{role}/cgroup.procs"

    def enter():
        cg_write(procs, str(os.getpid()))
        resource.setrlimit(resource.RLIMIT_NOFILE, (1048576, 1048576))
        os.setsid()

    return subprocess.Popen(["ip", "netns", "exec", ns] + argv, stdout=log,
                            stderr=subprocess.STDOUT, preexec_fn=enter)


def run_in(ns, role, argv, timeout):
    p = spawn(ns, role, argv, subprocess.PIPE)
    out, _ = p.communicate(timeout=timeout)
    return out.decode("utf-8", "replace")


def stop(p):
    if p and p.poll() is None:
        try:
            os.killpg(p.pid, signal.SIGTERM)
            p.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()


def wait_port(ns, addr, port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        # /dev/tcp is bash's
        if subprocess.run(["ip", "netns", "exec", ns, "bash", "-c",
                           f"exec 3<>/dev/tcp/{addr}/{port}"],
                          stderr=subprocess.DEVNULL).returncode == 0:
            return True
        time.sleep(0.1)
    return False


# --- the origin --------------------------------------------------------------

def origin_up(args, work):
    www = os.path.join(work, "www")
    os.makedirs(www, exist_ok=True)
    for name, size in FILES.items():
        with open(os.path.join(www, name), "wb") as f:
            f.write(b"x" * size)
    n = len(cpulist(args.cpus["srv"]))
    conf = os.path.join(work, "origin.conf")
    with open(conf, "w") as f:
        f.write(f"""daemon off;
worker_processes {n};
pid {work}/origin.pid;
error_log {work}/origin.err;
worker_rlimit_nofile 1048576;
events {{ worker_connections 65536; }}
http {{
    access_log off;
    sendfile on;
    tcp_nopush on;
    keepalive_requests 1000000;
    keepalive_timeout 120s;
    server {{
        listen {SRV_ADDR}:{ORIGIN_HTTP} backlog=65535 reuseport;
        root {www};
        default_type application/octet-stream;
    }}
}}
""")
    log = open(os.path.join(work, "origin.out"), "w")
    procs = [spawn("bsrv", "srv", ["nginx", "-c", conf, "-p", work], log),
             spawn("bsrv", "srv", ["iperf3", "-s", "-B", SRV_ADDR, "-p", str(ORIGIN_TCP)], log)]
    if not (wait_port("bsrv", SRV_ADDR, ORIGIN_HTTP) and wait_port("bsrv", SRV_ADDR, ORIGIN_TCP)):
        sys.exit("the origin did not start, see " + work)
    return procs


# --- proxies -----------------------------------------------------------------

def proxy_conf(kind, work, ncpu, label, opts=""):
    """Configuration for one proxy: an HTTP proxy on HTTP_PORT and a TCP relay
    on TCP_PORT, both towards the origin. Returns the argv. opts are added to
    both 3proxy services, e.g. -s0 to keep a version from using splice()."""
    if kind == "3proxy":
        conf = os.path.join(work, f"{label}.cfg")
        with open(conf, "w") as f:
            f.write(f"""maxconn 100000
auth none
proxy {opts} -i{PRX_IN} -e{PRX_OUT} -p{HTTP_PORT}
tcppm {opts} -i{PRX_IN} -e{PRX_OUT} {TCP_PORT} {SRV_ADDR} {ORIGIN_TCP}
""")
        return [conf]
    if kind == "nginx":
        conf = os.path.join(work, f"{label}.conf")
        with open(conf, "w") as f:
            # distributions build the stream module as a dynamic one
            stream = "/usr/lib/nginx/modules/ngx_stream_module.so"
            load = f"load_module {stream};\n" if os.path.exists(stream) else ""
            f.write(f"""{load}daemon off;
worker_processes {ncpu};
pid {work}/{label}.pid;
error_log {work}/{label}.err;
worker_rlimit_nofile 1048576;
events {{ worker_connections 65536; }}
http {{
    access_log off;
    upstream origin {{ server {SRV_ADDR}:{ORIGIN_HTTP}; keepalive 1024; }}
    server {{
        listen {PRX_IN}:{HTTP_PORT} backlog=65535 reuseport;
        keepalive_requests 1000000;
        location / {{
            proxy_pass http://origin;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_bind {PRX_OUT};
        }}
    }}
}}
stream {{
    server {{
        listen {PRX_IN}:{TCP_PORT} backlog=65535 reuseport;
        proxy_pass {SRV_ADDR}:{ORIGIN_TCP};
        proxy_bind {PRX_OUT};
    }}
}}
""")
        return ["-c", conf, "-p", work]
    if kind == "haproxy":
        conf = os.path.join(work, f"{label}.cfg")
        with open(conf, "w") as f:
            f.write(f"""global
    nbthread {ncpu}
    maxconn 200000
defaults
    timeout connect 5s
    timeout client 60s
    timeout server 60s
frontend http
    mode http
    bind {PRX_IN}:{HTTP_PORT}
    option http-keep-alive
    default_backend origin
backend origin
    mode http
    http-reuse always
    source {PRX_OUT}
    server origin {SRV_ADDR}:{ORIGIN_HTTP}
listen tcp
    mode tcp
    bind {PRX_IN}:{TCP_PORT}
    source {PRX_OUT}
    server origin {SRV_ADDR}:{ORIGIN_TCP}
""")
        return ["-f", conf]
    raise ValueError(kind)


class Proxy:
    def __init__(self, spec):
        kind, _, path = spec.partition(":")
        self.kind = kind
        self.opts = ""
        if kind == "3proxy":
            path, _, self.opts = path.partition(":")
            if not path:
                sys.exit("--proxy 3proxy:<binary>[:<service options>]")
            self.binary = os.path.abspath(path)
            self.label = os.path.basename(path) + (self.opts.replace(" ", "") if self.opts else "")
        elif kind in ("nginx", "haproxy"):
            self.binary = path or shutil.which(kind)
            self.label = kind
        elif kind == "none":
            self.binary = None
            self.label = "direct"
        else:
            sys.exit("unknown proxy " + spec)

    def start(self, args, work):
        cg_remove("prx")
        cg_make("prx", args.cpus["prx"])
        if self.kind == "none":
            return None
        argv = [self.binary] + proxy_conf(self.kind, work, len(cpulist(args.cpus["prx"])),
                                          self.label, self.opts)
        log = open(os.path.join(work, self.label + ".out"), "a")
        p = spawn("bprx", "prx", argv, log)
        if not (wait_port("bcli", PRX_IN, HTTP_PORT) and wait_port("bcli", PRX_IN, TCP_PORT)):
            stop(p)
            sys.exit(f"{self.label} did not start, see {work}")
        return p


# --- load --------------------------------------------------------------------

WRK_SCRIPT = """
local path, close = "%s", %s
local headers = {["Host"] = "%s:%d"}
if close then headers["Connection"] = "close" end
local req = wrk.format("GET", path, headers)
request = function() return req end
"""

UNITS = {"": 1, "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "KB": 2**10, "MB": 2**20,
         "GB": 2**30, "B": 1}


def to_ms(text):
    m = re.match(r"([\d.]+)(us|ms|s|m)", text)
    v, u = float(m.group(1)), m.group(2)
    return v * {"us": 1e-3, "ms": 1, "s": 1e3, "m": 6e4}[u]


def run_http(proxy, params, args, work):
    direct = proxy.kind == "none"
    host = SRV_ADDR if direct else PRX_IN
    port = ORIGIN_HTTP if direct else HTTP_PORT
    path = "/" + params["file"]
    if not direct:
        path = f"http://{SRV_ADDR}:{ORIGIN_HTTP}{path}"
    script = os.path.join(work, "wrk.lua")
    with open(script, "w") as f:
        f.write(WRK_SCRIPT % (path, "true" if params.get("close") else "false",
                              SRV_ADDR, ORIGIN_HTTP))
    threads = len(cpulist(args.cpus["cli"]))
    conns = max(params["conns"], threads)
    out = run_in("bcli", "cli", ["wrk", "-t", str(threads), "-c", str(conns),
                                 "-d", f"{args.duration}s", "--latency", "-s", script,
                                 f"http://{host}:{port}/"], args.duration + 30)
    res = {"raw": out}
    m = re.search(r"(\d+) requests in", out)
    res["requests"] = int(m.group(1)) if m else 0
    m = re.search(r"Requests/sec:\s+([\d.]+)", out)
    res["rate"] = float(m.group(1)) if m else 0.0
    m = re.search(r"Transfer/sec:\s+([\d.]+)(\w+)", out)
    res["gbit"] = float(m.group(1)) * UNITS[m.group(2)] * 8 / 1e9 if m else 0.0
    for pct in ("50", "99"):
        m = re.search(rf"^\s+{pct}%\s+(\S+)", out, re.M)
        res[f"p{pct}_ms"] = to_ms(m.group(1)) if m else float("nan")
    errors = 0
    m = re.search(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", out)
    if m:
        errors += sum(int(x) for x in m.groups())
    m = re.search(r"Non-2xx or 3xx responses: (\d+)", out)
    if m:
        errors += int(m.group(1))
    res["errors"] = errors
    res["retrans"] = 0
    res["bytes"] = res["gbit"] * 1e9 / 8 * args.duration
    return res


def run_stream(proxy, params, args, work):
    direct = proxy.kind == "none"
    host = SRV_ADDR if direct else PRX_IN
    port = ORIGIN_TCP if direct else TCP_PORT
    argv = ["iperf3", "-c", host, "-p", str(port), "-t", str(args.duration),
            "-P", str(params["streams"]), "-J"]
    if params.get("reverse"):
        argv.append("-R")
    out = run_in("bcli", "cli", argv, args.duration + 30)
    res = {"raw": out, "rate": float("nan"), "p50_ms": float("nan"),
           "p99_ms": float("nan"), "requests": 0, "errors": 0, "retrans": 0}
    try:
        j = json.loads(out)
        s = j["end"]["sum_received"]
        res["gbit"] = s["bits_per_second"] / 1e9
        res["bytes"] = s["bytes"]
        res["retrans"] = j["end"].get("sum_sent", {}).get("retransmits", 0)
        if "error" in j:
            res["errors"] = 1
    except (ValueError, KeyError):
        res["gbit"], res["bytes"], res["errors"] = 0.0, 0, 1
    return res


def measure(proxy, scenario, args, work):
    kind, params = SCENARIOS[scenario]
    p = proxy.start(args, work)
    try:
        time.sleep(0.5)
        before = {r: cg_usage(r) for r in ("cli", "prx", "srv")}
        t0 = time.time()
        res = (run_http if kind == "http" else run_stream)(proxy, params, args, work)
        wall = time.time() - t0
        after = {r: cg_usage(r) for r in ("cli", "prx", "srv")}
        res["peak_mb"] = cg_peak("prx")
    finally:
        stop(p)
    for r in ("cli", "prx", "srv"):
        used = after[r] - before[r]
        res[f"{r}_cpu_s"] = used
        # share of the CPUs given to that role, to see which side was the limit
        res[f"{r}_util"] = used / (wall * len(cpulist(args.cpus[r])))
    gb = res["bytes"] / 1e9
    res["cpu_s_per_gb"] = res["prx_cpu_s"] / gb if gb else float("nan")
    res["cpu_us_per_req"] = (res["prx_cpu_s"] * 1e6 / res["requests"]
                             if res["requests"] else float("nan"))
    return res


# --- main --------------------------------------------------------------------

FIELDS = ["proxy", "scenario", "rep", "gbit", "rate", "p50_ms", "p99_ms", "errors", "retrans",
          "prx_cpu_s", "cpu_s_per_gb", "cpu_us_per_req", "peak_mb",
          "cli_util", "prx_util", "srv_util"]


def summary(rows):
    keys = []
    for r in rows:
        if (r["proxy"], r["scenario"]) not in keys:
            keys.append((r["proxy"], r["scenario"]))
    cols = ["gbit", "rate", "p99_ms", "cpu_s_per_gb", "cpu_us_per_req", "peak_mb",
            "prx_util", "cli_util", "srv_util", "errors"]
    print("\nmedians (" + ", ".join(cols) + ")")
    print("%-24s %-14s " % ("proxy", "scenario") + " ".join("%10s" % c[:10] for c in cols))
    for proxy, scenario in sorted(keys, key=lambda k: (k[1], k[0])):
        sel = [r for r in rows if r["proxy"] == proxy and r["scenario"] == scenario]
        vals = []
        for c in cols:
            xs = [r[c] for r in sel if r[c] == r[c]]
            vals.append("%10.3g" % statistics.median(xs) if xs else "%10s" % "-")
        print("%-24s %-14s " % (proxy, scenario) + " ".join(vals))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--proxy", action="append", required=True,
                    help="3proxy:<binary>[:<service options>], nginx[:<binary>], haproxy[:<binary>] "
                         "or none (the kernel routing, an upper bound); repeat")
    ap.add_argument("--scenario", action="append", choices=sorted(SCENARIOS),
                    help="default: all")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--duration", type=int, default=10, help="seconds per run")
    ap.add_argument("--cpus", default="cli=0-3,prx=4-5,srv=6-7",
                    help="CPUs per role (default %(default)s)")
    ap.add_argument("--mtu", type=int, default=1500)
    ap.add_argument("--netem", help='netem on the client link, e.g. "delay 1ms rate 10gbit"')
    ap.add_argument("--out", default="bench/results", help="directory for the CSV and logs")
    args = ap.parse_args()
    if os.geteuid():
        sys.exit("needs root")
    args.cpus = dict(x.split("=") for x in args.cpus.split(","))
    proxies = [Proxy(s) for s in args.proxy]
    scenarios = args.scenario or list(SCENARIOS)

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs(args.out, exist_ok=True)
    work = tempfile.mkdtemp(prefix="3proxy-bench-")
    os.chmod(work, 0o755)
    csvpath = os.path.join(args.out, f"{stamp}.csv")
    rawpath = os.path.join(args.out, f"{stamp}.raw.txt")
    with open(os.path.join(args.out, f"{stamp}.env.txt"), "w") as f:
        f.write(" ".join(sys.argv) + "\n")
        f.write(sh("uname -a; lscpu | head -20; nproc; "
                   "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null; "
                   "iperf3 --version | head -1; wrk -v 2>&1 | head -1; nginx -v 2>&1; "
                   "haproxy -v 2>/dev/null | head -1", check=False))

    rows = []
    origin = []
    try:
        net_up(args)
        cg_up(args)
        origin = origin_up(args, work)
        with open(csvpath, "w", newline="") as f, open(rawpath, "w") as raw:
            w = csv.DictWriter(f, FIELDS, extrasaction="ignore")
            w.writeheader()
            # Every repetition runs each proxy once, rotating the order, so a
            # drift over time is shared by all of them.
            for rep in range(args.reps):
                for scenario in scenarios:
                    order = proxies[rep % len(proxies):] + proxies[:rep % len(proxies)]
                    for proxy in order:
                        res = measure(proxy, scenario, args, work)
                        res.update(proxy=proxy.label, scenario=scenario, rep=rep)
                        rows.append(res)
                        w.writerow(res)
                        f.flush()
                        raw.write(f"=== {proxy.label} {scenario} {rep}\n{res['raw']}\n")
                        print("%-24s %-14s rep %d: %7.2f Gbit/s %10.0f req/s  proxy cpu %5.2fs  "
                              "util cli %3.0f%% prx %3.0f%% srv %3.0f%%  errors %d" % (
                                  proxy.label, scenario, rep, res["gbit"],
                                  res["rate"] if res["rate"] == res["rate"] else 0,
                                  res["prx_cpu_s"], res["cli_util"] * 100,
                                  res["prx_util"] * 100, res["srv_util"] * 100,
                                  res["errors"]), flush=True)
    finally:
        for p in origin:
            stop(p)
        cg_down()
        net_down()
    summary(rows)
    print(f"\n{csvpath}\nlogs and configurations: {work}")


if __name__ == "__main__":
    main()
