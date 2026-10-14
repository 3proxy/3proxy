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
import threading
import time

CG = "/sys/fs/cgroup/3proxy-bench"

# client 10.0.1.2 -- 10.0.1.1 proxy 10.0.2.1 -- 10.0.2.2 origin
CLI_ADDR, PRX_IN, PRX_OUT, SRV_ADDR = "10.0.1.2", "10.0.1.1", "10.0.2.1", "10.0.2.2"
HTTP_PORT, TCP_PORT, ORIGIN_HTTP, ORIGIN_TCP = 3128, 5201, 8080, 5201
# a TCP relay to the origin's web server, standing in for CONNECT where the
# proxy has none (nginx, haproxy)
RELAY_HTTP = 5280
SOCKS_PORT = 1080
# the mix origin (bench/mix), and what reaches it where a proxy cannot be told
# where to go: an HTTP listener and a relay of their own
ORIGIN_MIX, HTTP_MIX, RELAY_MIX = 8090, 3129, 5281
# Its connections spread over that many of the origin's ports, from that many
# addresses of the client: tens of thousands of connections between one pair
# of addresses leave the kernel looking hard for a free port on every
# connect, and so does what the previous proxy left in TIME_WAIT.
MIX_PORTS = 16
# TLS: the origin's TLS listener, and the proxies' relays which terminate TLS
# (TLS from the client, plain to ORIGIN_HTTP) and initiate it (plain from the
# client, TLS to ORIGIN_TLS). TLS holds the certificate files once made.
ORIGIN_TLS, TLS_TERM, TLS_INIT = 8443, 5443, 5444
# the same for TLS streams: iperf3 has no TLS, so bench/mix wraps its
# connections, on the client (CLI_TLS, for TLS ended by the proxy) and at the
# origin (ORIGIN_TLS_TCP, taking the TLS begun by the proxy)
ORIGIN_TLS_TCP, TLS_TERM_TCP, TLS_INIT_TCP, CLI_TLS = 8444, 5445, 5446, 5202
TLS = None
# Each measurement takes the next of SLOTS sets of addresses: the proxy's to
# connect from, and the mix client's to connect from. What a run leaves in
# TIME_WAIT (the side closing first keeps it: the proxy towards the origin,
# being stopped, and the client towards the proxy, ending first) is then not
# between the addresses the next runs use, and is gone by the time a set is
# taken again.
SLOTS = 8
PRX_OUTS = [f"10.0.2.{10 + i}" for i in range(SLOTS)]


def mix_sources(slot):
    return [f"10.0.1.{100 + 16 * (slot % SLOTS) + i}" for i in range(16)]

FILES = {"1k": 1024, "50k": 50 * 1024, "100k": 100 * 1024, "1m": 1024 * 1024}

# name: (kind, parameters)
SCENARIOS = {
    "stream1":       ("stream", {"streams": 1}),
    "stream16":      ("stream", {"streams": 16}),
    "stream1-down":  ("stream", {"streams": 1, "reverse": True}),
    "http-ka-1k":    ("http", {"file": "1k", "conns": 64}),
    "http-ka-1m":    ("http", {"file": "1m", "conns": 16}),
    "http-ka-50k-2000": ("http", {"file": "50k", "conns": 2000}),
    "http-ka-2k-50k-2000": ("http", {"file": "50k", "conns": 2000, "body": 2048}),
    "http-close-1k": ("http", {"file": "1k", "conns": 64, "close": True}),
    # Through tunnels: the load generators run under proxychains, so each of
    # their connections asks the proxy for one to the origin, with CONNECT
    # (HTTP proxies) or SOCKSv5. And the same load through a TCP relay to a
    # fixed destination (3proxy tcppm, nginx stream, haproxy mode tcp).
    "connect-stream1-down": ("stream", {"streams": 1, "reverse": True, "via": "connect"}),
    "connect-stream16":  ("stream", {"streams": 16, "via": "connect"}),
    "connect-ka-1k":     ("http", {"file": "1k", "conns": 64, "via": "connect"}),
    "connect-ka-50k-2000": ("http", {"file": "50k", "conns": 2000, "via": "connect"}),
    "connect-ka-2k-50k-2000": ("http", {"file": "50k", "conns": 2000, "body": 2048, "via": "connect"}),
    "connect-close-1k":  ("http", {"file": "1k", "conns": 64, "close": True, "via": "connect"}),
    "socks-stream1-down": ("stream", {"streams": 1, "reverse": True, "via": "socks"}),
    "socks-stream16":  ("stream", {"streams": 16, "via": "socks"}),
    "socks-ka-1k":     ("http", {"file": "1k", "conns": 64, "via": "socks"}),
    "socks-ka-50k-2000": ("http", {"file": "50k", "conns": 2000, "via": "socks"}),
    "socks-ka-2k-50k-2000": ("http", {"file": "50k", "conns": 2000, "body": 2048, "via": "socks"}),
    "socks-close-1k":  ("http", {"file": "1k", "conns": 64, "close": True, "via": "socks"}),
    "relay-stream1-down": ("stream", {"streams": 1, "reverse": True, "via": "relay"}),
    "relay-stream16":  ("stream", {"streams": 16, "via": "relay"}),
    "relay-ka-1k":     ("http", {"file": "1k", "conns": 64, "via": "relay"}),
    "relay-ka-50k-2000": ("http", {"file": "50k", "conns": 2000, "via": "relay"}),
    "relay-ka-2k-50k-2000": ("http", {"file": "50k", "conns": 2000, "body": 2048, "via": "relay"}),
    "relay-close-1k":  ("http", {"file": "1k", "conns": 64, "close": True, "via": "relay"}),
    # TLS ended or begun by the proxy, relaying to or from the origin: one
    # handshake for each connection, so the close-1k ones measure handshakes
    "tls-term-ka-1k":    ("http", {"file": "1k", "conns": 64, "via": "tls-term"}),
    "tls-term-ka-2k-50k-2000": ("http", {"file": "50k", "conns": 2000, "body": 2048, "via": "tls-term"}),
    "tls-init-ka-2k-50k-2000": ("http", {"file": "50k", "conns": 2000, "body": 2048, "via": "tls-init"}),
    "tls-term-ka-1m":    ("http", {"file": "1m", "conns": 16, "via": "tls-term"}),
    "tls-term-close-1k": ("http", {"file": "1k", "conns": 64, "close": True, "via": "tls-term"}),
    "tls-init-ka-1k":    ("http", {"file": "1k", "conns": 64, "via": "tls-init"}),
    "tls-init-ka-1m":    ("http", {"file": "1m", "conns": 16, "via": "tls-init"}),
    "tls-init-close-1k": ("http", {"file": "1k", "conns": 64, "close": True, "via": "tls-init"}),
    "tls-term-stream1-down": ("stream", {"streams": 1, "reverse": True, "via": "tls-term"}),
    "tls-term-stream16": ("stream", {"streams": 16, "via": "tls-term"}),
    "tls-init-stream1-down": ("stream", {"streams": 1, "reverse": True, "via": "tls-init"}),
    "tls-init-stream16": ("stream", {"streams": 16, "via": "tls-init"}),
    # a pool of open connections and exchanges on random ones of them, sizes
    # and pieces from a web-like profile (bench/mix): -active of them going
    # at once all the time, or started at a fixed rate whatever the proxy
    # keeps up with
    "mix-http":      ("mix", {}),
    "mix-connect":   ("mix", {"via": "connect"}),
    "mix-socks":     ("mix", {"via": "socks"}),
    "mix-relay":     ("mix", {"via": "relay"}),
    "mix-http-3k":   ("mix", {"rate": 3000}),
    "mix-connect-3k": ("mix", {"via": "connect", "rate": 3000}),
    "mix-socks-3k":  ("mix", {"via": "socks", "rate": 3000}),
    "mix-relay-3k":  ("mix", {"via": "relay", "rate": 3000}),
}


TOOLS = {}


def tool(*names):
    """A tool by its absolute path: sudo's secure_path may leave out where
    it was installed, /usr/local/bin for a wrk built by hand. Several names
    are alternatives."""
    name = names[0]
    if name not in TOOLS:
        for n in names:
            path = shutil.which(n) or shutil.which(
                n, path="/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin")
            if path:
                break
        if not path:
            sys.exit(f"{' or '.join(names)} not found")
        TOOLS[name] = path
    return TOOLS[name]


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
    for addr in PRX_OUTS:
        sh(f"ip -n bprx addr add {addr}/24 dev bp1")
    if args.mix:
        for slot in range(SLOTS):
            for addr in mix_sources(slot):
                sh(f"ip -n bcli addr add {addr}/24 dev bc0")
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
    # The client link, both ways: netem for its delay and loss, fq for a
    # rate of each connection, under netem when both are given. Both ways
    # are shaped in the client's namespace, so the work is the client's
    # CPUs', not charged to the proxy: what the client sends on bc0's way
    # out, what it receives on an ifb its way in is redirected through.
    # Segmentation offload is off on the link, so that what netem drops is
    # one packet rather than a 64 KB burst and fq paces packets the size of
    # the MTU.
    if args.netem or args.flow_rate:
        netem = args.netem or ""
        if netem and "limit" not in netem.split():
            # netem's queue holds 1000 packets by default: too few for
            # thousands of connections, which would lose more than asked
            netem += " limit 1000000"
        fq = f"fq maxrate {args.flow_rate} flow_limit 1000"
        sh("modprobe ifb numifbs=0", check=False)
        sh("ip -n bcli link add bci type ifb")
        sh("ip -n bcli link set bci up")
        sh("ip netns exec bcli tc qdisc add dev bc0 handle ffff: ingress")
        sh("ip netns exec bcli tc filter add dev bc0 parent ffff: matchall "
           "action mirred egress redirect dev bci")
        for ns, dev in (("bcli", "bc0"), ("bprx", "bp0")):
            sh(f"ip netns exec {ns} ethtool -K {dev} gso off tso off gro off", check=False)
        for dev in ("bc0", "bci"):
            if netem and args.flow_rate:
                sh(f"ip netns exec bcli tc qdisc add dev {dev} root handle 1: netem {netem}")
                sh(f"ip netns exec bcli tc qdisc add dev {dev} parent 1:1 handle 10: {fq}")
            elif netem:
                sh(f"ip netns exec bcli tc qdisc add dev {dev} root netem {netem}")
            else:
                sh(f"ip netns exec bcli tc qdisc add dev {dev} root {fq}")

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


def cg_kill(role):
    """Whatever is left in a role's cgroup, e.g. after an interrupted run."""
    try:
        pids = cg_read(f"{CG}/{role}/cgroup.procs").split()
    except OSError:
        return
    for pid in pids:
        try:
            os.kill(int(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def cg_down():
    for role in ("cli", "prx", "srv"):
        cg_kill(role)
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


TICK = os.sysconf("SC_CLK_TCK")


def cpu_busy():
    """Busy and total ticks per CPU. Busy counts interrupts and softirqs too:
    a kernel with IRQ time accounting leaves them out of the cgroup's CPU
    time, and that is where much of the network work is done."""
    busy = {}
    with open("/proc/stat") as f:
        for line in f:
            if not line.startswith("cpu") or line.startswith("cpu "):
                continue
            name, *v = line.split()
            v = [int(x) for x in v]
            # user nice system idle iowait irq softirq steal
            busy[int(name[3:])] = (v[0] + v[1] + v[2] + v[5] + v[6] + v[7], sum(v[:8]))
    return busy


def role_busy(before, after, cpus):
    """Busy seconds of a role's CPUs, and the share of them that was busy."""
    b = t = 0
    for c in cpus:
        b += after[c][0] - before[c][0]
        t += after[c][1] - before[c][1]
    return b / TICK, (b / t if t else 0.0)


def thread_times(role):
    """CPU ticks per thread of everything in a role's cgroup."""
    times = {}
    try:
        tids = cg_read(f"{CG}/{role}/cgroup.threads").split()
    except OSError:
        return times
    for tid in tids:
        try:
            with open(f"/proc/{tid}/stat") as f:
                v = f.read().rsplit(")", 1)[1].split()
            times[tid] = int(v[11]) + int(v[12])
        except (OSError, IndexError, ValueError):
            pass
    return times


def busiest_thread(before, after, wall):
    """The busiest thread's share of one CPU: one thread at 100% is a limit
    however many CPUs its role has (iperf3 runs a stream in a thread)."""
    top = 0
    for tid, t in after.items():
        top = max(top, t - before.get(tid, 0))
    return top / TICK / wall if wall else 0.0


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


LAST_CLIENT_THREAD = [0.0]


def run_in(ns, role, argv, timeout):
    """Run a load generator to its end. Its busiest thread's share of a CPU
    is kept in LAST_CLIENT_THREAD, read just before it exits."""
    p = spawn(ns, role, argv, subprocess.PIPE)
    t0 = time.time()
    top = {}
    buf = []
    reader = threading.Thread(target=lambda: buf.append(p.stdout.read()))
    reader.start()
    while p.poll() is None:
        for tid, t in thread_times(role).items():
            top[tid] = t
        time.sleep(0.5)
    reader.join(timeout)
    wall = time.time() - t0
    LAST_CLIENT_THREAD[0] = max(top.values()) / TICK / wall if top and wall else 0.0
    return (buf[0] if buf else b"").decode("utf-8", "replace")


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
    origin_tls = ""
    if TLS:
        origin_tls = f"""    server {{{{
        listen {SRV_ADDR}:{ORIGIN_TLS} ssl backlog=65535 reuseport;
        ssl_certificate {TLS["cert"]};
        ssl_certificate_key {TLS["key"]};
        root {www};
        default_type application/octet-stream;
        error_page 405 =200 $uri;
    }}}}
""".replace("{{", "{").replace("}}", "}")
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
        # the files answer a POST too, its body read and thrown away
        error_page 405 =200 $uri;
    }}
{origin_tls}}}
""")
    log = open(os.path.join(work, "origin.out"), "w")
    procs = [spawn("bsrv", "srv", [tool("nginx"), "-c", conf, "-p", work], log),
             spawn("bsrv", "srv", [tool("iperf3"), "-s", "-B", SRV_ADDR, "-p", str(ORIGIN_TCP)], log)]
    ports = [ORIGIN_HTTP, ORIGIN_TCP] + ([ORIGIN_TLS] if TLS else [])
    if args.wrap:
        procs.append(spawn("bsrv", "srv", [args.wrap, "tls", "-listen", f"{SRV_ADDR}:{ORIGIN_TLS_TCP}",
                                           "-connect", f"{SRV_ADDR}:{ORIGIN_TCP}",
                                           "-cert", TLS["cert"], "-key", TLS["key"]], log))
        ports.append(ORIGIN_TLS_TCP)
    if args.mix:
        procs.append(spawn("bsrv", "srv", [args.mix, "origin", "-listen", f"{SRV_ADDR}:{ORIGIN_MIX}",
                                           "-ports", str(MIX_PORTS)], log))
        ports += [ORIGIN_MIX, ORIGIN_MIX + MIX_PORTS - 1]
    if not all(wait_port("bsrv", SRV_ADDR, port) for port in ports):
        for p in procs:
            stop(p)
        sys.exit("the origin did not start, see " + work)
    return procs


# --- proxies -----------------------------------------------------------------

def envoy_conf(work, label, out):
    """envoy as nginx and haproxy are measured: an HTTP proxy for the origin
    (absolute URIs taken, the origin's connections pooled), TCP relays, and
    the TLS ones. Its default circuit breakers allow 1024 connections to a
    cluster, far fewer than the scenarios open: they are lifted."""
    def addr(host, port):
        return {"socket_address": {"address": host, "port_value": port}}

    def cluster(name, port, tls=False):
        c = {"name": name, "type": "STATIC", "connect_timeout": "5s",
             "upstream_bind_config": {"source_address": {"address": out, "port_value": 0}},
             "circuit_breakers": {"thresholds": [{"max_connections": 1000000,
                                                  "max_pending_requests": 1000000,
                                                  "max_requests": 1000000}]},
             "load_assignment": {"cluster_name": name, "endpoints": [{"lb_endpoints": [
                 {"endpoint": {"address": addr(SRV_ADDR, port)}}]}]}}
        if tls:
            c["transport_socket"] = {"name": "envoy.transport_sockets.tls", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext"}}
        return c

    def http(name, port, dest):
        return {"name": name, "address": addr(PRX_IN, port), "filter_chains": [{"filters": [{
            "name": "envoy.filters.network.http_connection_manager", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.network."
                         "http_connection_manager.v3.HttpConnectionManager",
                "stat_prefix": name, "codec_type": "HTTP1",
                "route_config": {"virtual_hosts": [{"name": "all", "domains": ["*"], "routes": [
                    {"match": {"prefix": "/"}, "route": {"cluster": dest, "timeout": "0s"}}]}]},
                "http_filters": [{"name": "envoy.filters.http.router", "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]}}]}]}

    def tcp(name, port, dest, tls=False):
        chain = {"filters": [{"name": "envoy.filters.network.tcp_proxy", "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
            "stat_prefix": name, "cluster": dest}}]}
        if tls:
            chain["transport_socket"] = {"name": "envoy.transport_sockets.tls", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                "common_tls_context": {"tls_certificates": [{
                    "certificate_chain": {"filename": TLS["cert"]},
                    "private_key": {"filename": TLS["key"]}}]}}}
        return {"name": name, "address": addr(PRX_IN, port), "filter_chains": [chain]}

    listeners = [http("http", HTTP_PORT, "origin"), http("httpmix", HTTP_MIX, "mix"),
                 tcp("tcp", TCP_PORT, "tcp"), tcp("tcphttp", RELAY_HTTP, "origin"),
                 tcp("tcpmix", RELAY_MIX, "mix")]
    clusters = [cluster("origin", ORIGIN_HTTP), cluster("mix", ORIGIN_MIX), cluster("tcp", ORIGIN_TCP)]
    if TLS:
        listeners += [tcp("tlsterm", TLS_TERM, "origin", True), tcp("tlstermtcp", TLS_TERM_TCP, "tcp", True),
                      tcp("tlsinit", TLS_INIT, "origintls"), tcp("tlsinittcp", TLS_INIT_TCP, "tcptls")]
        clusters += [cluster("origintls", ORIGIN_TLS, True), cluster("tcptls", ORIGIN_TLS_TCP, True)]
    conf = os.path.join(work, f"{label}.json")
    with open(conf, "w") as f:
        json.dump({"static_resources": {"listeners": listeners, "clusters": clusters}}, f, indent=1)
    return conf


def proxy_conf(kind, work, ncpu, label, opts="", out=PRX_OUT):
    """Configuration for one proxy: an HTTP proxy on HTTP_PORT and a TCP relay
    on TCP_PORT, both towards the origin. Returns the argv. opts are added to
    both 3proxy services, e.g. -s0 to keep a version from using splice(). out
    is the address the proxy connects from."""
    if kind == "3proxy":
        # ktls among the options is not a service option: kernel TLS for the
        # TLS services (ssl_ktls)
        words = opts.split()
        ktls = "ssl_ktls\n" if "ktls" in words else ""
        opts = " ".join(w for w in words if w != "ktls")
        conf = os.path.join(work, f"{label}.cfg")
        with open(conf, "w") as f:
            f.write(f"""maxconn 100000
auth none
proxy {opts} -i{PRX_IN} -e{out} -p{HTTP_PORT}
tcppm {opts} -i{PRX_IN} -e{out} {TCP_PORT} {SRV_ADDR} {ORIGIN_TCP}
tcppm {opts} -i{PRX_IN} -e{out} {RELAY_HTTP} {SRV_ADDR} {ORIGIN_HTTP}
tcppm {opts} -i{PRX_IN} -e{out} {RELAY_MIX} {SRV_ADDR} {ORIGIN_MIX}
socks {opts} -i{PRX_IN} -e{out} -p{SOCKS_PORT}
""")
            if TLS:
                f.write(f"""{ktls}ssl_server_cert {TLS["cert"]}
ssl_server_key {TLS["key"]}
ssl_serv
tcppm {opts} -i{PRX_IN} -e{out} {TLS_TERM} {SRV_ADDR} {ORIGIN_HTTP}
tcppm {opts} -i{PRX_IN} -e{out} {TLS_TERM_TCP} {SRV_ADDR} {ORIGIN_TCP}
ssl_noserv
ssl_cli
tcppm {opts} -i{PRX_IN} -e{out} {TLS_INIT} {SRV_ADDR} {ORIGIN_TLS}
tcppm {opts} -i{PRX_IN} -e{out} {TLS_INIT_TCP} {SRV_ADDR} {ORIGIN_TLS_TCP}
ssl_nocli
""")
        return [conf]
    if kind == "envoy":
        return ["-c", envoy_conf(work, label, out), "--concurrency", str(ncpu),
                "--log-level", "error", "--disable-hot-restart"]
    if kind == "stunnel":
        conf = os.path.join(work, f"{label}.conf")
        with open(conf, "w") as f:
            f.write(f"""foreground = yes
pid = {work}/{label}.pid
debug = 3
output = {work}/{label}.log
[term]
accept = {PRX_IN}:{TLS_TERM}
connect = {SRV_ADDR}:{ORIGIN_HTTP}
local = {out}
cert = {TLS["cert"]}
key = {TLS["key"]}
[init]
client = yes
accept = {PRX_IN}:{TLS_INIT}
connect = {SRV_ADDR}:{ORIGIN_TLS}
local = {out}
[termtcp]
accept = {PRX_IN}:{TLS_TERM_TCP}
connect = {SRV_ADDR}:{ORIGIN_TCP}
local = {out}
cert = {TLS["cert"]}
key = {TLS["key"]}
[inittcp]
client = yes
accept = {PRX_IN}:{TLS_INIT_TCP}
connect = {SRV_ADDR}:{ORIGIN_TLS_TCP}
local = {out}
""")
        return [conf]
    if kind == "tinyproxy":
        conf = os.path.join(work, f"{label}.conf")
        with open(conf, "w") as f:
            f.write(f"""Port {HTTP_PORT}
Listen {PRX_IN}
Bind {out}
Timeout 600
MaxClients 100000
LogLevel Critical
LogFile "{work}/{label}.log"
PidFile "{work}/{label}.pid"
DisableViaHeader Yes
""")
        return ["-d", "-c", conf]
    if kind == "squid":
        conf = os.path.join(work, f"{label}.conf")
        with open(conf, "w") as f:
            f.write(f"""http_port {PRX_IN}:{HTTP_PORT}
tcp_outgoing_address {out}
http_access allow all
cache deny all
cache_mem 8 MB
access_log none
cache_log {work}/{label}.log
pid_filename {work}/{label}.pid
coredump_dir {work}
cache_effective_user nobody
max_filedescriptors 65536
shutdown_lifetime 1 seconds
via off
forwarded_for delete
""")
        return ["-N", "-f", conf]
    if kind == "dante":
        conf = os.path.join(work, f"{label}.conf")
        with open(conf, "w") as f:
            f.write(f"""logoutput: {work}/{label}.log
internal: {PRX_IN} port = {SOCKS_PORT}
external: {out}
socksmethod: none
clientmethod: none
user.privileged: root
user.unprivileged: nobody
client pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 }}
socks pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 }}
""")
        return ["-f", conf, "-p", f"{work}/{label}.pid", "-N", "1"]
    if kind == "nginx":
        conf = os.path.join(work, f"{label}.conf")
        with open(conf, "w") as f:
            # distributions build the stream module as a dynamic one
            load = ""
            for d in ("/usr/lib/nginx/modules", "/usr/lib64/nginx/modules"):
                stream = os.path.join(d, "ngx_stream_module.so")
                if os.path.exists(stream):
                    load = f"load_module {stream};\n"
                    break
            nopts = opts.split("+")
            halfclose = "    proxy_half_close on;\n" if "halfclose" in nopts else ""
            # kernel TLS, where nginx's OpenSSL is built with it
            ktls = "ktls" in nopts
            nginx_tls = ""
            if TLS:
                nginx_tls = ""
                for port, dest in ((TLS_TERM, ORIGIN_HTTP), (TLS_TERM_TCP, ORIGIN_TCP)):
                    nginx_tls += (f"    server {{\n        listen {PRX_IN}:{port} ssl backlog=65535 reuseport;\n"
                                  f"        ssl_certificate {TLS['cert']};\n        ssl_certificate_key {TLS['key']};\n"
                                  + ("        ssl_conf_command Options KTLS;\n" if ktls else "") +
                                  f"        proxy_pass {SRV_ADDR}:{dest};\n        proxy_bind {out};\n    }}\n")
                for port, dest in ((TLS_INIT, ORIGIN_TLS), (TLS_INIT_TCP, ORIGIN_TLS_TCP)):
                    nginx_tls += (f"    server {{\n        listen {PRX_IN}:{port} backlog=65535 reuseport;\n"
                                  f"        proxy_pass {SRV_ADDR}:{dest};\n        proxy_ssl on;\n"
                                  + ("        proxy_ssl_conf_command Options KTLS;\n" if ktls else "") +
                                  f"        proxy_bind {out};\n    }}\n")
            f.write(f"""{load}daemon off;
worker_processes {ncpu};
pid {work}/{label}.pid;
error_log {work}/{label}.err;
worker_rlimit_nofile 1048576;
events {{ worker_connections 65536; }}
http {{
    access_log off;
    upstream origin {{ server {SRV_ADDR}:{ORIGIN_HTTP}; keepalive 1024; }}
    upstream mix {{ server {SRV_ADDR}:{ORIGIN_MIX}; keepalive 1024; }}
    server {{
        listen {PRX_IN}:{HTTP_PORT} backlog=65535 reuseport;
        keepalive_requests 1000000;
        location / {{
            proxy_pass http://origin;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_bind {out};
        }}
    }}
    server {{
        listen {PRX_IN}:{HTTP_MIX} backlog=65535 reuseport;
        keepalive_requests 1000000;
        client_max_body_size 0;
        location / {{
            proxy_pass http://mix;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_bind {out};
        }}
    }}
}}
stream {{
{halfclose}    server {{
        listen {PRX_IN}:{TCP_PORT} backlog=65535 reuseport;
        proxy_pass {SRV_ADDR}:{ORIGIN_TCP};
        proxy_bind {out};
    }}
    server {{
        listen {PRX_IN}:{RELAY_HTTP} backlog=65535 reuseport;
        proxy_pass {SRV_ADDR}:{ORIGIN_HTTP};
        proxy_bind {out};
    }}
    server {{
        listen {PRX_IN}:{RELAY_MIX} backlog=65535 reuseport;
        proxy_pass {SRV_ADDR}:{ORIGIN_MIX};
        proxy_bind {out};
    }}
{nginx_tls}}}
""")
        return ["-c", conf, "-p", work]
    if kind == "haproxy":
        # splice-auto: haproxy's heuristic, splicing a direction once reads
        # fill its buffer three times in a row; splice-response, splice-request
        # and splice: the server's data, the client's, or both, always
        # (3proxy's -s1, -s2 and -s3)
        splice = {"": "", "splice-auto": "    option splice-auto\n",
                  "splice-response": "    option splice-response\n",
                  "splice-request": "    option splice-request\n",
                  "splice": "    option splice-request\n    option splice-response\n"}
        if opts not in splice:
            sys.exit("haproxy options: " + ", ".join(k for k in splice if k))
        splice = splice[opts]
        conf = os.path.join(work, f"{label}.cfg")
        with open(conf, "w") as f:
            f.write(f"""global
    nbthread {ncpu}
    maxconn 200000
defaults
    maxconn 200000
{splice}    timeout connect 5s
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
    source {out}
    server origin {SRV_ADDR}:{ORIGIN_HTTP}
listen tcp
    mode tcp
    bind {PRX_IN}:{TCP_PORT}
    source {out}
    server origin {SRV_ADDR}:{ORIGIN_TCP}
listen tcphttp
    mode tcp
    bind {PRX_IN}:{RELAY_HTTP}
    source {out}
    server origin {SRV_ADDR}:{ORIGIN_HTTP}
frontend httpmix
    mode http
    bind {PRX_IN}:{HTTP_MIX}
    option http-keep-alive
    default_backend mix
backend mix
    mode http
    http-reuse always
    source {out}
    server mix {SRV_ADDR}:{ORIGIN_MIX}
listen tcpmix
    mode tcp
    bind {PRX_IN}:{RELAY_MIX}
    source {out}
    server mix {SRV_ADDR}:{ORIGIN_MIX}
""")
            if TLS:
                f.write(f"""listen tlsterm
    mode tcp
    bind {PRX_IN}:{TLS_TERM} ssl crt {TLS["pem"]}
    source {out}
    server origin {SRV_ADDR}:{ORIGIN_HTTP}
listen tlsinit
    mode tcp
    bind {PRX_IN}:{TLS_INIT}
    source {out}
    server origin {SRV_ADDR}:{ORIGIN_TLS} ssl verify none
listen tlstermtcp
    mode tcp
    bind {PRX_IN}:{TLS_TERM_TCP} ssl crt {TLS["pem"]}
    source {out}
    server origin {SRV_ADDR}:{ORIGIN_TCP}
listen tlsinittcp
    mode tcp
    bind {PRX_IN}:{TLS_INIT_TCP}
    source {out}
    server origin {SRV_ADDR}:{ORIGIN_TLS_TCP} ssl verify none
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
            path, _, self.opts = path.partition(":")
            # nginx has no splice(): its one option is halfclose, for
            # proxy_half_close on, which its relays leave off by default
            if kind == "nginx" and not set(self.opts.split("+")) <= {"", "halfclose", "ktls"}:
                sys.exit("nginx options: halfclose, ktls, halfclose+ktls")
            self.binary = path or tool(kind)
            self.label = kind + ("-" + self.opts if self.opts else "")
        elif kind == "envoy":
            self.binary = path or tool("envoy")
            self.label = kind
        elif kind in ("tinyproxy", "squid", "dante", "stunnel"):
            # dante's server is sockd, danted on Debian; stunnel stunnel4 there
            self.binary = path or (tool("sockd", "danted") if kind == "dante" else
                                   tool("stunnel", "stunnel4") if kind == "stunnel" else tool(kind))
            self.label = kind
        elif kind == "none":
            self.binary = None
            self.label = "direct"
        else:
            sys.exit("unknown proxy " + spec)

    # what each proxy listens on, and which scenarios it can take part in:
    # tinyproxy and squid are HTTP proxies, dante a SOCKS server only
    PORTS = {"3proxy": (HTTP_PORT, TCP_PORT, SOCKS_PORT, RELAY_HTTP, RELAY_MIX),
             "nginx": (HTTP_PORT, TCP_PORT, RELAY_HTTP, HTTP_MIX, RELAY_MIX),
             "haproxy": (HTTP_PORT, TCP_PORT, RELAY_HTTP, HTTP_MIX, RELAY_MIX),
             "envoy": (HTTP_PORT, TCP_PORT, RELAY_HTTP, HTTP_MIX, RELAY_MIX),
             "tinyproxy": (HTTP_PORT,), "squid": (HTTP_PORT,), "dante": (SOCKS_PORT,),
             "stunnel": (TLS_TERM, TLS_INIT, TLS_TERM_TCP, TLS_INIT_TCP)}

    def ports(self):
        """What to wait for: with TLS scenarios the relays for them too."""
        extra = (TLS_TERM, TLS_INIT, TLS_TERM_TCP, TLS_INIT_TCP) \
            if TLS and self.kind in ("3proxy", "nginx", "haproxy", "envoy") else ()
        return self.PORTS[self.kind] + extra

    def serves(self, scenario):
        kind, params = SCENARIOS[scenario]
        via = params.get("via")
        # TLS ended or begun on a relay: what 3proxy, nginx, haproxy and
        # stunnel do, and only stunnel
        if via in ("tls-term", "tls-init"):
            return self.kind in ("3proxy", "nginx", "haproxy", "envoy", "stunnel", "none")
        if self.kind == "stunnel":
            return False
        if self.kind == "dante":
            return via == "socks"
        if self.kind in ("tinyproxy", "squid"):
            return via == "connect" or (kind in ("http", "mix") and not via)
        if self.kind in ("nginx", "haproxy", "envoy"):
            # no CONNECT, no SOCKS
            return via in (None, "relay")
        return True

    def start(self, args, work):
        cg_remove("prx")
        cg_make("prx", args.cpus["prx"])
        if self.kind == "none":
            return None
        argv = [self.binary] + proxy_conf(self.kind, work, len(cpulist(args.cpus["prx"])),
                                          self.label, self.opts, PRX_OUTS[args.slot % SLOTS])
        log = open(os.path.join(work, self.label + ".out"), "a")
        p = spawn("bprx", "prx", argv, log)
        if not all(wait_port("bcli", PRX_IN, port, 30) for port in self.ports()):
            stop(p)
            sys.exit(f"{self.label} did not start, see {work}")
        return p


# --- load --------------------------------------------------------------------

WRK_SCRIPT = """
local path, close, size = "%s", %s, %d
local headers = {["Host"] = "%s:%d"}
if close then headers["Connection"] = "close" end
local req
if size > 0 then
    req = wrk.format("POST", path, headers, string.rep("u", size))
else
    req = wrk.format("GET", path, headers)
end
request = function() return req end
"""

UNITS = {"": 1, "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "KB": 2**10, "MB": 2**20,
         "GB": 2**30, "B": 1}


def to_ms(text):
    m = re.match(r"([\d.]+)(us|ms|s|m)", text)
    v, u = float(m.group(1)), m.group(2)
    return v * {"us": 1e-3, "ms": 1, "s": 1e3, "m": 6e4}[u]


def tunnel(via, work):
    """argv prefix running a load generator so that its connections go
    through tunnels of the proxy: CONNECT, or SOCKSv5."""
    conf = os.path.join(work, f"proxychains-{via}.conf")
    line = f"http {PRX_IN} {HTTP_PORT}" if via == "connect" else f"socks5 {PRX_IN} {SOCKS_PORT}"
    with open(conf, "w") as f:
        f.write(f"strict_chain\nquiet_mode\ntcp_read_time_out 15000\n"
                f"tcp_connect_time_out 8000\n[ProxyList]\n{line}\n")
    return [tool("proxychains4"), "-q", "-f", conf]


def target(proxy, params, work, direct_port, proxy_port, relay_port):
    """Where the load generator connects, and what it runs under: the origin
    itself with no proxy or through a tunnel, the proxy's relay otherwise."""
    if proxy.kind == "none":
        return SRV_ADDR, direct_port, []
    if params.get("via") == "relay":
        return PRX_IN, relay_port, []
    if params.get("via"):
        return SRV_ADDR, direct_port, tunnel(params["via"], work)
    return PRX_IN, proxy_port, []


def run_http(proxy, params, args, work, mark):
    via = params.get("via")
    scheme = "http"
    if via in ("tls-term", "tls-init"):
        # with no proxy the client speaks TLS to the origin itself
        host, prefix = (SRV_ADDR, []) if proxy.kind == "none" else (PRX_IN, [])
        port = ORIGIN_TLS if proxy.kind == "none" else TLS_TERM if via == "tls-term" else TLS_INIT
        if proxy.kind == "none" or via == "tls-term":
            scheme = "https"
    else:
        host, port, prefix = target(proxy, params, work, ORIGIN_HTTP, HTTP_PORT, RELAY_HTTP)
    path = "/" + params["file"]
    if host == PRX_IN and port == HTTP_PORT:
        path = f"http://{SRV_ADDR}:{ORIGIN_HTTP}{path}"
    script = os.path.join(work, "wrk.lua")
    with open(script, "w") as f:
        f.write(WRK_SCRIPT % (path, "true" if params.get("close") else "false",
                              params.get("body", 0), SRV_ADDR, ORIGIN_HTTP))
    threads = len(cpulist(args.cpus["cli"]))
    if prefix:
        # proxychains asks for each tunnel inside connect(), blocking the
        # thread: more threads keep the client's CPUs busy meanwhile
        threads = min(params["conns"], threads * 4)
    conns = max(params["conns"], threads)
    out = run_in("bcli", "cli", prefix + [tool("wrk"), "-t", str(threads), "-c", str(conns),
                                 "-d", f"{args.duration}s", "--latency", "-s", script,
                                 f"{scheme}://{host}:{port}/"], args.duration + 30)
    res = {"raw": out}
    m = re.search(r"(\d+) requests in", out)
    res["requests"] = int(m.group(1)) if m else 0
    m = re.search(r"Requests/sec:\s+([\d.]+)", out)
    res["rate"] = float(m.group(1)) if m else 0.0
    m = re.search(r"Transfer/sec:\s+([\d.]+)(\w+)", out)
    res["gbit"] = float(m.group(1)) * UNITS[m.group(2)] * 8 / 1e9 if m else 0.0
    for pct in ("50", "90", "99"):
        m = re.search(rf"^\s+{pct}%\s+(\S+)", out, re.M)
        res[f"p{pct}_ms"] = to_ms(m.group(1)) if m else float("nan")
    errors = 0
    res["timeouts"] = 0
    m = re.search(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", out)
    if m:
        errors += sum(int(x) for x in m.groups()[:3])
        # requests slower than wrk's 2 seconds: a latency tail, not a failure
        res["timeouts"] = int(m.group(4))
    m = re.search(r"Non-2xx or 3xx responses: (\d+)", out)
    if m:
        errors += int(m.group(1))
    if not res["requests"]:
        errors += 1		# wrk did not run, or reported nothing
    res["errors"] = errors
    res["retrans"] = 0
    res["bytes"] = res["gbit"] * 1e9 / 8 * args.duration
    return res


def run_stream(proxy, params, args, work, mark):
    via = params.get("via")
    wrapper = None
    if via in ("tls-term", "tls-init"):
        # iperf3 talks to a wrapper on the client; with TLS ended by the
        # proxy, or with no proxy, it begins TLS there, and the origin's
        # wrapper ends it; with TLS begun by the proxy it passes plain TCP
        if proxy.kind == "none":
            dest, tls = f"{SRV_ADDR}:{ORIGIN_TLS_TCP}", True
        elif via == "tls-term":
            dest, tls = f"{PRX_IN}:{TLS_TERM_TCP}", True
        else:
            dest, tls = f"{PRX_IN}:{TLS_INIT_TCP}", False
        if tls:
            log = open(os.path.join(work, "wrap.out"), "a")
            wrapper = spawn("bcli", "cli", [args.wrap, "tls", "-listen", f"{CLI_ADDR}:{CLI_TLS}",
                                            "-connect", dest], log)
            wait_port("bcli", CLI_ADDR, CLI_TLS, 10)
            host, port = CLI_ADDR, CLI_TLS
        else:
            host, port = PRX_IN, TLS_INIT_TCP
        prefix = []
    else:
        host, port, prefix = target(proxy, params, work, ORIGIN_TCP, TCP_PORT, TCP_PORT)
    argv = prefix + [tool("iperf3"), "-c", host, "-p", str(port), "-t", str(args.duration),
            "-P", str(params["streams"]), "-J"]
    if params.get("reverse"):
        argv.append("-R")
    try:
        out = run_in("bcli", "cli", argv, args.duration + 30)
    finally:
        if wrapper:
            stop(wrapper)
    res = {"raw": out, "rate": float("nan"), "p50_ms": float("nan"), "p90_ms": float("nan"),
           "p99_ms": float("nan"), "requests": 0, "errors": 0, "retrans": 0, "timeouts": 0}
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


def run_mix(proxy, params, args, work, mark):
    """bench/mix: a pool of connections through the proxy and exchanges on
    random ones of them. Opening the pool is not measured: mark() starts
    the measurement when the client says it is READY."""
    via = params.get("via") or "http"
    if proxy.kind == "none":
        via, addr = "direct", ""
    elif via == "relay":
        addr = f"{PRX_IN}:{RELAY_MIX}"
    elif via == "socks":
        addr = f"{PRX_IN}:{SOCKS_PORT}"
    elif via == "http" and proxy.kind in ("nginx", "haproxy", "envoy"):
        addr = f"{PRX_IN}:{HTTP_MIX}"
    else:
        addr = f"{PRX_IN}:{HTTP_PORT}"
    argv = [args.mix, "client", "-via", via, "-origin", f"{SRV_ADDR}:{ORIGIN_MIX}",
            "-origins", str(MIX_PORTS), "-sources", ",".join(mix_sources(args.slot)),
            "-pool", str(args.mix_pool), "-active", str(args.mix_active),
            "-rate", str(params.get("rate", 0)), "-seed", str(args.seed),
            "-duration", f"{args.duration}s"]
    if addr:
        argv += ["-proxy", addr]
    p = spawn("bcli", "cli", argv, subprocess.PIPE)
    lines = []
    ready = threading.Event()

    def read():
        for line in p.stdout:
            line = line.decode("utf-8", "replace")
            lines.append(line)
            if line.strip() == "READY":
                mark()
                ready.set()
    reader = threading.Thread(target=read)
    reader.start()
    top, t0 = {}, None
    deadline = time.time() + args.duration + 300	# opening the pool takes a while
    while p.poll() is None and time.time() < deadline:
        if ready.is_set():
            if t0 is None:
                t0, base = time.time(), thread_times("cli")
            # a thread started since then would bring its time from before
            for tid, t in thread_times("cli").items():
                if tid in base:
                    top[tid] = t - base[tid]
        time.sleep(0.5)
    stop(p)
    reader.join(10)
    wall = time.time() - t0 if t0 else 0
    LAST_CLIENT_THREAD[0] = max(top.values()) / TICK / wall if top and wall else 0.0
    res = {"raw": "".join(lines), "retrans": 0}
    try:
        j = json.loads(lines[-1])
    except (ValueError, IndexError):
        j = {}
    res["requests"] = j.get("exchanges", 0)
    res["rate"] = j.get("rate", 0.0)
    res["gbit"] = j.get("gbit", 0.0)
    res["bytes"] = j.get("bytes", 0)
    for pct in ("50", "90", "99"):
        res[f"p{pct}_ms"] = j.get(f"p{pct}_ms", float("nan"))
    res["timeouts"] = j.get("timeouts", 0)
    # connections of the pool which could not be opened count too
    res["errors"] = j.get("errors", 0) + max(j.get("pool", 0) - j.get("opened", 0), 0)
    if not j or not ready.is_set():
        res["errors"] += 1
    return res


BUSY = 0.9


def measure(proxy, scenario, args, work):
    kind, params = SCENARIOS[scenario]
    args.slot += 1
    p = proxy.start(args, work)
    base = {}

    def mark():
        """Where the measurement starts: now, or later for a load which
        needs setting up first."""
        base.update(task0=cg_usage("prx"), cpu0=cpu_busy(),
                    thr0={r: thread_times(r) for r in ("cli", "srv")}, t0=time.time())
    try:
        time.sleep(0.5)
        mark()
        runner = {"http": run_http, "stream": run_stream, "mix": run_mix}[kind]
        res = runner(proxy, params, args, work, mark)
        res["cli_thread"] = LAST_CLIENT_THREAD[0]
        wall = time.time() - base["t0"]
        cpu1 = cpu_busy()
        # threads of the load generator have ended by now: take what the
        # client's cgroup reports for the run instead
        thr1 = {r: thread_times(r) for r in ("cli", "srv")}
        res["prx_task_s"] = cg_usage("prx") - base["task0"]
        res["peak_mb"] = cg_peak("prx")
    finally:
        stop(p)
    for r in ("cli", "prx", "srv"):
        # the busy time of the role's CPUs, its own processes and the network
        # work done there for it
        res[f"{r}_cpu_s"], res[f"{r}_util"] = role_busy(base["cpu0"], cpu1, cpulist(args.cpus[r]))
    res["srv_thread"] = busiest_thread(base["thr0"]["srv"], thr1["srv"], wall)
    # Which side set the pace: a role whose CPUs, or a single thread of it,
    # were busy all the time. A run limited by the client or the origin says
    # only that the proxy can do at least this much.
    if res["srv_util"] >= BUSY or res["srv_thread"] >= BUSY:
        res["bound"] = "origin"
    elif res["cli_util"] >= BUSY or res["cli_thread"] >= BUSY:
        res["bound"] = "client"
    elif res["prx_util"] >= BUSY:
        res["bound"] = "proxy"
    else:
        res["bound"] = "none"
    gb = res["bytes"] / 1e9
    res["cpu_s_per_gb"] = res["prx_cpu_s"] / gb if gb else float("nan")
    res["cpu_us_per_req"] = (res["prx_cpu_s"] * 1e6 / res["requests"]
                             if res["requests"] else float("nan"))
    return res


# --- main --------------------------------------------------------------------

FIELDS = ["proxy", "scenario", "rep", "gbit", "rate", "p50_ms", "p90_ms", "p99_ms", "errors", "timeouts", "retrans",
          "prx_cpu_s", "prx_task_s", "cpu_s_per_gb", "cpu_us_per_req", "peak_mb",
          "cli_util", "prx_util", "srv_util", "cli_thread", "srv_thread", "bound"]


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
                    help="3proxy:<binary>[:<service options>, ktls for ssl_ktls], "
                         "nginx[:<binary>[:halfclose|ktls|halfclose+ktls]], "
                         "tinyproxy, squid, dante (sockd), "
                         "haproxy[:<binary>[:splice-auto|splice-response|splice-request|splice]] "
                         "or none (the kernel routing, an upper bound); repeat")
    ap.add_argument("--scenario", action="append", choices=sorted(SCENARIOS),
                    help="default: all")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--duration", type=int, default=10, help="seconds per run")
    ap.add_argument("--cpus", default="cli=0-3,prx=4,srv=5-7",
                    help="CPUs per role (default %(default)s)")
    ap.add_argument("--mtu", type=int, default=1500)
    ap.add_argument("--netem", help='netem on the client link, both ways, e.g. '
                    '"delay 5ms loss 0.5%%"')
    ap.add_argument("--flow-rate", help="the client link's rate for each connection, "
                    "each way, e.g. 20mbit (fq maxrate)")
    ap.add_argument("--out", default="bench/results", help="directory for the CSV and logs")
    ap.add_argument("--mix", help="the bench/mix binary for the mix-* scenarios "
                    "(default: bench/mix/mix-linux-<arch>, see bench/mix/build.sh)")
    ap.add_argument("--mix-pool", type=int, default=20000, help="connections kept open (%(default)s)")
    ap.add_argument("--mix-active", type=int, default=2000,
                    help="exchanges going at once at most (%(default)s)")
    ap.add_argument("--seed", type=int, default=1, help="what the mix-* scenarios draw from (%(default)s)")
    args = ap.parse_args()
    if os.geteuid():
        sys.exit("needs root")
    args.cpus = dict(x.split("=") for x in args.cpus.split(","))
    args.slot = -1
    proxies = [Proxy(s) for s in args.proxy]
    scenarios = args.scenario or list(SCENARIOS)
    # fail now rather than after the first scenarios
    for name in ("nginx", "iperf3", "wrk"):
        tool(name)
    if any(SCENARIOS[s][1].get("via") in ("tls-term", "tls-init") for s in scenarios):
        tool("openssl")
    if any(SCENARIOS[s][0] != "mix" and SCENARIOS[s][1].get("via") in ("connect", "socks")
           for s in scenarios):
        tool("proxychains4")
    if any(SCENARIOS[s][0] == "mix" for s in scenarios):
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine, os.uname().machine)
        args.mix = os.path.abspath(args.mix or os.path.join(os.path.dirname(__file__), "mix",
                                                            f"mix-linux-{arch}"))
        if not os.access(args.mix, os.X_OK):
            sys.exit(f"{args.mix} is missing: build it with bench/mix/build.sh")
    else:
        args.mix = None
    # the TLS streams need its TLS wrapper
    args.wrap = None
    if any(SCENARIOS[s][0] == "stream" and SCENARIOS[s][1].get("via") in ("tls-term", "tls-init")
           for s in scenarios):
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine, os.uname().machine)
        args.wrap = os.path.abspath(os.path.join(os.path.dirname(__file__), "mix", f"mix-linux-{arch}"))
        if not os.access(args.wrap, os.X_OK):
            sys.exit(f"{args.wrap} is missing: build it with bench/mix/build.sh")

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    global TLS
    tls_dir = None
    if any(SCENARIOS[s][1].get("via") in ("tls-term", "tls-init") for s in scenarios):
        # a CA and a certificate signed by it for the proxies' and the
        # origin's addresses: ECDSA P-256, what TLS mostly uses now
        tls_dir = tempfile.mkdtemp(prefix="3proxy-bench-tls-")
        o = tool("openssl")
        sh(f"cd {tls_dir} && {o} ecparam -name prime256v1 -genkey -noout -out ca.key && "
           f"{o} req -x509 -new -key ca.key -days 30 -subj /CN=bench-ca -out ca.pem && "
           f"{o} ecparam -name prime256v1 -genkey -noout -out key.pem && "
           f"{o} req -new -key key.pem -subj /CN=bench -out req.csr && "
           f"printf 'subjectAltName=IP:{PRX_IN},IP:{SRV_ADDR},DNS:bench\\n' > ext.cnf && "
           f"{o} x509 -req -in req.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 "
           f"-extfile ext.cnf -out cert.pem && cat cert.pem key.pem > combined.pem")
        os.chmod(tls_dir, 0o755)
        for name in os.listdir(tls_dir):
            os.chmod(os.path.join(tls_dir, name), 0o644)
        TLS = {"cert": f"{tls_dir}/cert.pem", "key": f"{tls_dir}/key.pem", "pem": f"{tls_dir}/combined.pem"}
    os.makedirs(args.out, exist_ok=True)
    work = tempfile.mkdtemp(prefix="3proxy-bench-")
    # squid writes its log and pid file there after giving up root
    os.chmod(work, 0o1777)
    csvpath = os.path.join(args.out, f"{stamp}.csv")
    rawpath = os.path.join(args.out, f"{stamp}.raw.txt")
    with open(os.path.join(args.out, f"{stamp}.env.txt"), "w") as f:
        f.write(" ".join(sys.argv) + "\n")
        f.write(sh("uname -a; lscpu | head -20; nproc; "
                   "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null; "
                   f"{tool('iperf3')} --version | head -1; {tool('wrk')} -v 2>&1 | head -1; "
                   f"{tool('nginx')} -v 2>&1; "
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
                        if not proxy.serves(scenario):
                            continue
                        res = measure(proxy, scenario, args, work)
                        # an origin killed (by the OOM killer, say) would fail
                        # every measurement after it: stop there instead
                        dead = [os.path.basename(p.args[4]) for p in origin if p.poll() is not None]
                        if dead:
                            sys.exit(f"origin exited ({', '.join(map(str, dead))}), "
                                     f"{scenario} rep {rep} on {proxy.label} and later not measured")
                        res.update(proxy=proxy.label, scenario=scenario, rep=rep)
                        rows.append(res)
                        w.writerow(res)
                        f.flush()
                        raw.write(f"=== {proxy.label} {scenario} {rep}\n{res['raw']}\n")
                        print("%-24s %-14s rep %d: %7.2f Gbit/s %10.0f req/s  proxy cpu %5.2fs  "
                              "busy cli %3.0f%% prx %3.0f%% srv %3.0f%% (threads %3.0f%%/%3.0f%%)  "
                              "bound %-6s errors %d" % (
                                  proxy.label, scenario, rep, res["gbit"],
                                  res["rate"] if res["rate"] == res["rate"] else 0,
                                  res["prx_cpu_s"], res["cli_util"] * 100,
                                  res["prx_util"] * 100, res["srv_util"] * 100,
                                  res["cli_thread"] * 100, res["srv_thread"] * 100,
                                  res["bound"], res["errors"]), flush=True)
    finally:
        for p in origin:
            stop(p)
        cg_down()
        net_down()
    summary(rows)
    print(f"\n{csvpath}\nlogs and configurations: {work}")


if __name__ == "__main__":
    main()
