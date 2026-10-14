"""splice(): every mode relays what it is given unchanged, small and large,
both ways, the automatic mode's heuristics set or not (-s[N]:MIN,STREAK,SMALL).

Where splice() is not built (anything but Linux) -s is accepted and ignored,
so the same checks then cover copying.
"""

import os
import socket
import threading

MODES = ["-s0", "-s", "-s3", "-s:65536,3,8192", "-s2:32768,2,4096"]


def echo_origin(listener):
    """Sends back whatever each connection sends, until it shuts down its
    side."""
    def serve(c):
        try:
            while True:
                b = c.recv(65536)
                if not b:
                    break
                c.sendall(b)
            c.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        c.close()

    while True:
        try:
            c, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=serve, args=(c,), daemon=True).start()


def echo_through(port, data):
    """data sent through the mapped port while what comes back is read; the
    sending side is shut down once all is sent."""
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    got = []

    def reader():
        while True:
            try:
                b = s.recv(65536)
            except OSError:
                return
            if not b:
                return
            got.append(b)

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    s.sendall(data)
    s.shutdown(socket.SHUT_WR)
    th.join(30)
    s.close()
    return b"".join(got)


def run(t):
    origin = t.free_port()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    echo = listener.getsockname()[1]
    threading.Thread(target=echo_origin, args=(listener,), daemon=True).start()

    proxies, mapped = [], []
    conf = f"""
        log
        auth iponly
        allow *
        http data * /data
        httpsrv -p{origin}

        flush
        auth iponly
        allow *
"""
    for mode in MODES:
        p, m = t.free_port(), t.free_port()
        proxies.append(p)
        mapped.append(m)
        conf += f"        proxy {mode} -p{p}\n        tcppm {mode} {m} 127.0.0.1 {echo}\n"
    t.start("splice", conf, ports=[origin] + proxies + mapped)

    direct = {size: t.http(f"http://127.0.0.1:{origin}/data?size={size}").body
              for size in (1000, 100000, 5000000)}
    chunked = t.http(f"http://127.0.0.1:{origin}/data?size=1000000&chunked=1").body
    up = os.urandom(3000000)

    try:
        for mode, p, m in zip(MODES, proxies, mapped):
            proxy = f"127.0.0.1:{p}"
            for size, body in direct.items():
                got = t.http(f"http://127.0.0.1:{origin}/data?size={size}", proxy=proxy)
                if got.body == body:
                    t.ok(f"{mode}: a {size} byte answer arrives unchanged")
                else:
                    t.fail(f"{mode}: a {size} byte answer arrives unchanged",
                           f"{size} bytes", f"{got.length} different bytes")
            got = t.http(f"http://127.0.0.1:{origin}/data?size=1000000&chunked=1", proxy=proxy)
            if got.body == chunked:
                t.ok(f"{mode}: a chunked answer arrives unchanged")
            else:
                t.fail(f"{mode}: a chunked answer arrives unchanged",
                       f"{len(chunked)} bytes", f"{got.length} different bytes")
            back = echo_through(m, up)
            if back == up:
                t.ok(f"{mode}: 3 MB sent through tcppm come back unchanged")
            else:
                t.fail(f"{mode}: 3 MB sent through tcppm come back unchanged",
                       f"{len(up)} bytes", f"{len(back)} bytes, different")
            small = echo_through(m, b"hello")
            t.eq(b"hello", small, f"{mode}: a few bytes through tcppm come back")
    finally:
        listener.close()
