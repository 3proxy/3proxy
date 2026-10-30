"""maxconn: a service serves at most that many connections at once, and a
connection over the limit waits for one of them to finish."""

import os
import signal
import socket
import time


def run(t):
    if not t.skip_unless("httpsrv"):
        return
    # The origin runs in a process of its own, so the limit only applies to
    # the mapper in front of it.
    origin = t.free_port()
    t.start("maxconn_origin", f"""
        auth iponly
        allow *
        http echo * /echo**
        httpsrv -p{origin}
    """, ports=[origin])

    mapped = t.free_port()
    server = t.start("maxconn", f"""
        log
        maxconn 2
        auth iponly
        allow *
        tcppm {mapped} 127.0.0.1 {origin}
    """, ports=[mapped])

    def connect():
        sock = socket.create_connection(("127.0.0.1", mapped), 5)
        opened.append(sock)
        return sock

    def served(sock, timeout):
        """Ask over a kept alive connection; True once the whole reply is in,
        so the connection is ready for the next request."""
        sock.sendall(b"GET /echo HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        sock.settimeout(timeout)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    return False
                data += chunk
            head, body = data.split(b"\r\n\r\n", 1)
            length = 0
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"content-length":
                    length = int(value)
            while len(body) < length:
                chunk = sock.recv(4096)
                if not chunk:
                    return False
                body += chunk
            return head.startswith(b"HTTP/1.1 200")
        except OSError:
            return False

    opened = []
    try:
        # the probe that saw the port open holds a slot until its session
        # ends, so wait for both slots to be free before taking them
        deadline = time.time() + 5
        while True:
            first, second = connect(), connect()
            both = served(first, 1) and served(second, 1)
            if both or time.time() > deadline:
                break
            first.close()
            second.close()
        t.eq(True, both, "two connections are served under maxconn 2")

        third = connect()
        t.eq(False, served(third, 1.5),
             "a third connection waits while both slots are held")
        t.contains(t.wait_output(server, "too many connected clients"),
                   "too many connected clients",
                   "a service at its limit says so in the log")

        first.close()
        t.eq(True, served(third, 5),
             "the waiting connection is served once a slot is freed")
        t.eq(True, served(second, 5),
             "a connection holding a slot keeps being served")

        if os.name == "nt":
            t.skip("reload while at the limit (no SIGUSR1 on Windows)")
        else:
            waiting = connect()
            t.eq(False, served(waiting, 1),
                 "the limit holds again with two connections open")
            server.proc.send_signal(signal.SIGUSR1)
            # A connection made the instant the signal arrives can land on
            # the listener being replaced and be reset; give the new service
            # the moment it needs.
            time.sleep(1.5)
            fresh = connect()
            t.eq(True, served(fresh, 5),
                 "a reload while the limit is reached starts a service with "
                 "its slots free")
            t.eq(None, server.proc.poll(), "the process survives the reload")
    finally:
        for sock in opened:
            sock.close()
