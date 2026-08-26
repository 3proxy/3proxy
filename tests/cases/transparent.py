"""Transparent proxying: the destination comes from the redirection.

A redirected connection no longer says where it was going, so the proxy has
to ask the packet filter. That means a real redirection rule, which needs
privilege, so the case skips unless it can install one and remove it again.

The rule must not catch the proxy's own connection to the origin, or the
traffic goes round for ever. Here the proxy is given an outgoing address of
its own and the rule excludes it, which is the arrangement the documentation
recommends.
"""

import os
import platform
import shutil
import subprocess

ORIGIN_ADDR = "127.0.0.9"      # where the client believes it is going
PROXY_ADDR = "127.0.0.8"       # the source the proxy connects from
DECOY_ADDR = "127.0.0.7"       # a second server, to show where traffic went


def _run(command):
    done = subprocess.run(command, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=30)
    return done.returncode, done.stdout.decode("utf-8", "replace").strip()


def _iptables_rule(action, origin_port, proxy_port):
    return ["iptables", "-t", "nat", action, "OUTPUT",
            "-p", "tcp", "-d", ORIGIN_ADDR, "--dport", str(origin_port),
            "!", "-s", PROXY_ADDR,
            "-j", "REDIRECT", "--to-ports", str(proxy_port)]


def _config(t, name, body):
    """Run a configuration that has no service, and return what it said."""
    return t.run_config(name, body + "\nnot_a_command\n")


def run(t):
    # --- the command and its modes ------------------------------------
    # These need no redirection, so they run wherever the feature is built.
    out = _config(t, "transparent_probe", "log\ntransparent")
    if "'transparent'" in out:
        t.skip("transparent proxying (not built in this configuration)")
        return

    for mode in ("auto", "socket"):
        t.not_contains(_config(t, "mode_" + mode, f"log\ntransparent {mode}"),
                       "transparent:", f"the {mode} mode is accepted")

    t.contains(_config(t, "mode_bogus", "log\ntransparent bogus"),
               "unknown mode", "an unknown mode is refused")

    # A mode the build has no code for is refused rather than ignored, so a
    # configuration written for another platform fails where it is wrong
    # instead of quietly doing something else.
    for mode, built in (("netfilter", platform.system() == "Linux"), ("pf", False)):
        out = _config(t, "mode_" + mode, f"log\ntransparent {mode}")
        if built:
            t.not_contains(out, "not available", f"the {mode} mode is accepted where it exists")
        elif "not available" in out:
            t.ok(f"the {mode} mode is refused where it does not exist")
        else:
            t.skip(f"the {mode} mode (built here, nothing to check)")

    t.not_contains(_config(t, "notransparent", "log\ntransparent\nnotransparent"),
                   "'notransparent'", "notransparent is accepted")

    # A configuration written for the plugin still loads: the line that used
    # to load it is accepted and does nothing, the way the ssl and pcre ones
    # are, so an existing configuration does not have to be edited first.
    out = _config(t, "plugin_line",
                  "log\nplugin /usr/local/lib/TransparentPlugin.ld.so transparent_plugin")
    t.not_contains(out, "failed", "loading the old plugin is accepted and ignored")
    t.contains(_config(t, "plugin_missing", "log\nplugin /nope/NoSuch.so nosuch_plugin"),
               "failed", "an unknown plugin still fails to load")

    # --- and the redirection itself ------------------------------------
    if platform.system() != "Linux":
        # The BSDs need a redirection that leaves the original destination on
        # the socket - divert-to on OpenBSD, ipfw fwd on FreeBSD - and macOS
        # has neither, so there is nothing to set up here.
        t.skip(f"transparent proxying (no redirection to set up on {platform.system()})")
        return
    if os.geteuid() != 0 or not shutil.which("iptables"):
        t.skip("transparent proxying (needs root and iptables to redirect)")
        return

    origin_port = t.free_port()
    decoy_port = t.free_port()
    mapper_port = t.free_port()
    plain_port = t.free_port()

    t.start("transparent", f"""
        log
        auth iponly
        allow *
        http * /echo* echo
        httpsrv -p{origin_port} -i{ORIGIN_ADDR}

        # a second server, to tell apart where a connection actually went
        flush
        auth iponly
        allow *
        http * * data size=13
        httpsrv -p{decoy_port} -i{DECOY_ADDR}

        # a port mapper aimed at the decoy: with the destination taken from
        # the redirection instead, it goes to the origin
        flush
        auth iponly
        allow *
        transparent
        tcppm -e{PROXY_ADDR} {mapper_port} {DECOY_ADDR} {decoy_port}
        notransparent

        # the same mapper without it, which keeps going to the decoy
        flush
        auth iponly
        allow *
        tcppm -e{PROXY_ADDR} {plain_port} {DECOY_ADDR} {decoy_port}
    """, ports=[(ORIGIN_ADDR, origin_port), (DECOY_ADDR, decoy_port),
                mapper_port, plain_port])

    code, out = _run(_iptables_rule("-A", origin_port, mapper_port))
    if code:
        t.skip(f"transparent proxying (could not add a redirect rule: {out})")
        return

    try:
        # The client asks for the address it wants; the rule sends the
        # connection to the mapper instead, and the mapper has to work out
        # where it was headed.
        r = t.http(f"http://{ORIGIN_ADDR}:{origin_port}/echo")
        t.eq(200, r.status, "a redirected connection reaches its destination")
        t.contains(r, "path=/echo", "the request arrives unchanged")
        t.contains(r, f"host={ORIGIN_ADDR}:{origin_port}",
                   "the client still believes it is talking to the origin")
        t.contains(r, f"peer.addr={PROXY_ADDR}",
                   "the origin is reached from the proxy's own address")

        # That address is what the rule excludes, which is what stops the
        # proxy's own connection from being redirected back into itself.
        t.not_contains(r, "size=13", "the connection did not go to the decoy")

        # Without the command the mapper has no reason to look, and goes
        # where it was configured to go.
        _run(_iptables_rule("-D", origin_port, mapper_port))
        code, out = _run(_iptables_rule("-A", origin_port, plain_port))
        if code:
            t.skip("the mapper without the command (could not move the rule)")
        else:
            r = t.http(f"http://{ORIGIN_ADDR}:{origin_port}/echo")
            t.eq(13, r.length,
                 "without the command the connection goes to the configured target")
            t.not_contains(r, "path=/echo",
                           "and never reaches the address the client asked for")
            _run(_iptables_rule("-D", origin_port, plain_port))
    finally:
        # leave the machine as it was found, whatever happened above
        _run(_iptables_rule("-D", origin_port, mapper_port))
        _run(_iptables_rule("-D", origin_port, plain_port))
