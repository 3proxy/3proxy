"""The system's name servers and hosts file as the default resolver: with
no nserver in a configuration, names in the hosts file are answered from
it; with nserver lines, or sysresolve (the system routines), it is not."""

import os
import re
import sys
import time


def hosts_path():
    if sys.platform == "win32":
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


def hosts_localhost():
    """Whether the hosts file maps localhost to 127.0.0.1 itself."""
    try:
        with open(hosts_path(), errors="replace") as f:
            for line in f:
                words = line.split("#", 1)[0].split()
                if len(words) > 1 and words[0] == "127.0.0.1" and "localhost" in [w.lower() for w in words[1:]]:
                    return True
    except OSError:
        pass
    return False


def system_nameserver():
    """Whether there is a name server for 3proxy to find: resolv.conf has
    one, or on Windows the registry is taken to."""
    if sys.platform == "win32":
        return True
    try:
        with open("/etc/resolv.conf") as f:
            return any(re.match(r"nameserver\s+[0-9a-fA-F.:]+\s*$", l.split("#")[0]) for l in f)
    except OSError:
        return False


def wait(t, port, name):
    deadline = time.time() + 5
    while time.time() < deadline:
        if t.dns_query(port, name):
            return


def run(t):
    if not hosts_localhost() or not system_nameserver():
        t.skip("no localhost in the hosts file, or no system name server")
        return

    port = t.free_port()
    t.start("sysdns", f"""
        log
        flush
        auth iponly
        allow *
        dnspr -p{port}
    """)
    wait(t, port, "localhost")
    t.eq(["127.0.0.1"], t.dns_query(port, "localhost"),
         "without nserver, a name of the hosts file is answered from it")
    t.eq(["127.0.0.1"], t.dns_query(port, "LocalHost"),
         "whatever its case")

    # with a name server configured, one that answers nothing, the hosts
    # file is not used
    other = t.free_port()
    t.start("sysdns_nserver", f"""
        log
        flush
        nserver 127.0.0.1:{t.free_port()}
        nscache 1024
        auth iponly
        allow *
        dnspr -p{other}
    """)
    wait(t, other, "localhost")
    t.ne(["127.0.0.1"], t.dns_query(other, "localhost") or [],
         "with nserver, the hosts file is not used")

    # sysresolve: the system routines resolve names, and nothing is imported
    # for dnspr to answer from
    sysport, proxy, srv = t.free_port(), t.free_port(), t.free_port()
    t.start("sysdns_sysresolve", f"""
        log
        flush
        sysresolve
        auth iponly
        allow *
        dnspr -p{sysport}
        proxy -p{proxy}
        flush
        auth iponly
        allow *
        http echo * /echo**
        httpsrv -p{srv}
    """, ports=[proxy, srv])
    wait(t, sysport, "localhost")
    t.ne(["127.0.0.1"], t.dns_query(sysport, "localhost") or [],
         "with sysresolve, dnspr has no hosts file names")
    t.eq(200, t.http(f"http://localhost:{srv}/echo", proxy=f"127.0.0.1:{proxy}").status,
         "and names resolve through the system routines")
