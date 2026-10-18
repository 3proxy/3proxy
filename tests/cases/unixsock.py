"""Unix domain sockets: a service listening on one (-iunix:PATH, and on
Linux an abstract -iunix:@NAME), tcppm forwarding to one (DSTADDR
unix:PATH), a parent reached through one (parent ... unix:PATH), and a
listening one across reloads: each reload's service binding it anew, its
file kept while a service listens on it and removed once none does."""

import os
import socket
import sys
import time


def unix_get(path, url, timeout=10):
    """A GET for url sent to the proxy at the Unix socket path (a leading @
    for an abstract one): (status, body length), or (None, error)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect("\0" + path[1:] if path.startswith("@") else path)
        s.sendall(f"GET {url} HTTP/1.0\r\nHost: unix\r\n\r\n".encode())
        got = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            got += b
    except OSError as e:
        return None, str(e)
    finally:
        s.close()
    head, _, body = got.partition(b"\r\n\r\n")
    try:
        return int(head.split()[1]), len(body)
    except (IndexError, ValueError):
        return None, head[:80]


def run(t):
    if not hasattr(socket, "AF_UNIX") or sys.platform.startswith("win"):
        t.skip("Unix domain sockets (not on this platform)")
        return

    origin = t.free_port()
    mapped = t.free_port()
    chained = t.free_port()
    adm = t.free_port()
    path = os.path.join(t.tmpdir, "px.sock")
    abstract = f"@3proxy-test-{os.getpid()}" if sys.platform.startswith("linux") else None
    url = f"http://127.0.0.1:{origin}/data?size=1000"

    def config(unix=True):
        services = f"""
            flush
            auth iponly
            allow *
            proxy -iunix:{path}
        """ if unix else ""
        if unix and abstract:
            services += f"""
            proxy -iunix:{abstract}
        """
        if unix:
            services += f"""
            flush
            auth iponly
            allow *
            tcppm {mapped} unix:{path} 0

            flush
            auth iponly
            allow *
            parent 1000 http unix:{path} 0
            proxy -p{chained}
        """
        return f"""
            log
            auth iponly
            allow *
            http data * /data
            httpsrv -p{origin}
            {services}
            flush
            auth iponly
            allow *
            admin -p{adm}
        """

    server = t.start("unixsock", config(), ports=[origin, mapped, chained, adm])
    # a build without Unix sockets (NO_UN) never makes the file
    deadline = time.time() + 5
    while time.time() < deadline and not os.path.exists(path):
        time.sleep(0.05)
    if not os.path.exists(path):
        t.skip("Unix domain sockets (not supported by this build)")
        return

    # --- a proxy listening on a Unix socket ---------------------------------
    t.eq((200, 1000), unix_get(path, url), "a proxy listening on a Unix socket answers")
    if abstract:
        t.eq((200, 1000), unix_get(abstract, url),
             "a proxy listening on an abstract Unix socket answers")

    # --- tcppm forwarding to a Unix socket: the proxy behind it answers -----
    r = t.http(url, proxy=f"127.0.0.1:{mapped}")
    t.eq(200, r.status, "tcppm forwards a TCP port to a Unix socket")
    t.eq(1000, r.length, "and the whole answer comes back through it")

    # --- a parent reached through a Unix socket ------------------------------
    r = t.http(url, proxy=f"127.0.0.1:{chained}")
    t.eq(200, r.status, "a proxy chains to a parent on a Unix socket")
    t.eq(1000, r.length, "and the whole answer comes back through the chain")

    # --- reloads: each new service binds the path anew; the old one, closing
    # after, must not remove the new one's file ----------------------------
    for i in range(3):
        before = server.output().count("Accepting connections")
        t.write_config("unixsock", config())
        t.http(f"http://127.0.0.1:{adm}/R")
        deadline = time.time() + 10
        while time.time() < deadline and server.output().count("Accepting connections") < before + 5:
            time.sleep(0.05)
    # the old services stop within a second of each reload
    time.sleep(1.5)
    t.ok("after three reloads the socket file is still there") if os.path.exists(path) else \
        t.fail("after three reloads the socket file is still there", path, "missing")
    t.eq((200, 1000), unix_get(path, url), "and the proxy answers on it")

    # --- no service listens there any more: the file goes -------------------
    t.write_config("unixsock", config(unix=False))
    t.http(f"http://127.0.0.1:{adm}/R")
    deadline = time.time() + 5
    while time.time() < deadline and os.path.exists(path):
        time.sleep(0.1)
    t.ok("once no service listens on it the socket file is removed") \
        if not os.path.exists(path) else \
        t.fail("once no service listens on it the socket file is removed", "no file", path)
    got = unix_get(path, url, timeout=2)
    t.ok("and nothing answers there") if got[0] is None else \
        t.fail("and nothing answers there", "no connection", got)
