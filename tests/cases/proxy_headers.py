"""HTTP proxy headers, read whole into the connection's buffer and rewritten
there: what reaches the server and what comes back are checked byte for
byte where it matters, for header blocks bigger than the buffer, a body or
another request in the same packet as the headers, and answers with big
headers."""

import socket
import threading
import time


class Origin:
    """A server recording every request it gets, headers and body, and
    answering each with the answer given, keeping the connection."""

    def __init__(self, answer):
        self.answer = answer
        self.requests = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.conn, args=(c,), daemon=True).start()

    def conn(self, c):
        data = b""
        c.settimeout(10)
        try:
            while True:
                while b"\r\n\r\n" not in data:
                    got = c.recv(65536)
                    if not got:
                        return
                    data += got
                head, _, data = data.partition(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n")[1:]:
                    name, _, value = line.partition(b":")
                    if name.strip().lower() == b"content-length":
                        length = int(value.strip())
                while len(data) < length:
                    got = c.recv(65536)
                    if not got:
                        return
                    data += got
                body, data = data[:length], data[length:]
                self.requests.append((head, body))
                c.sendall(self.answer)
        except OSError:
            pass
        finally:
            c.close()

    def close(self):
        self.sock.close()


def session(port, data, until, timeout=5):
    """Sends data at once and reads until `until` answers have come (each
    ending with the 'ok' body), or the time is up."""
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.sendall(data)
    got = b""
    deadline = time.time() + timeout
    try:
        while got.count(b"\r\n\r\nok") < until and time.time() < deadline:
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
    except OSError:
        pass
    s.close()
    return got


def run(t):
    ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"
    origin = Origin(ok)
    proxy = t.free_port()
    server = t.start("proxy_headers", f"""
        log
        auth iponly
        allow *
        proxy -p{proxy}
    """, ports=[proxy])
    base = f"http://127.0.0.1:{origin.port}"

    def request(path, extra=b"", body=b"", method=b"GET"):
        r = (method + b" " + base.encode() + path + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n" + extra)
        if body:
            r += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        return r + b"\r\n" + body

    # --- a body in the same packet as the headers, headers added and taken
    # out on the way ------------------------------------------------------
    origin.requests.clear()
    body = b"0123456789" * 50
    got = session(proxy, request(b"/post", b"Proxy-Connection: keep-alive\r\n", body, b"POST"), 1)
    t.contains(got.decode("latin-1"), "200 OK", "a POST with its body in the headers' packet is answered")
    head, rbody = origin.requests[0] if origin.requests else (b"", b"")
    t.eq(body, rbody, "its body arrives whole, after the headers rewritten in place")
    t.ok("the proxy's Forwarded header is added") if b"\r\nForwarded: for=" in head else \
        t.fail("the proxy's Forwarded header is added", "Forwarded", head[-200:])
    t.ok("and Proxy-Connection taken out") if b"proxy-connection" not in head.lower() else \
        t.fail("and Proxy-Connection taken out", "no Proxy-Connection", head[-200:])

    # --- a header block bigger than the connection's buffer --------------
    origin.requests.clear()
    big = b"".join(b"X-Big-%d: %s\r\n" % (i, bytes([65 + i]) * 15000) for i in range(3))
    got = session(proxy, request(b"/big", big), 1)
    t.contains(got.decode("latin-1"), "200 OK", "a request with 45 KB of headers is answered")
    head = origin.requests[0][0] if origin.requests else b""
    whole = all((b"X-Big-%d: %s\r\n" % (i, bytes([65 + i]) * 15000)) in head + b"\r\n" for i in range(3))
    t.ok("and every big header arrives whole") if whole else \
        t.fail("and every big header arrives whole", "3 headers of 15000", len(head))

    # --- two requests in one packet, kept alive ---------------------------
    origin.requests.clear()
    got = session(proxy, request(b"/one", b"Connection: keep-alive\r\n") +
                  request(b"/two", b"Connection: keep-alive\r\n"), 2)
    t.eq(2, got.count(b"\r\n\r\nok"), "two pipelined requests are both answered")
    paths = [h.split(b" ")[1] for h, _ in origin.requests]
    t.eq([b"/one", b"/two"], paths, "in order, each with its own path")

    # --- empty lines before a request -------------------------------------
    got = session(proxy, b"\r\n\r\n" + request(b"/after"), 1)
    t.contains(got.decode("latin-1"), "200 OK", "a request after empty lines is answered")

    # --- an answer with headers bigger than the connection's buffer -------
    origin.answer = (b"HTTP/1.1 200 OK\r\nX-Long: " + b"L" * 30000 +
                     b"\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
    got = session(proxy, request(b"/longanswer"), 1)
    t.ok("an answer with a 30 KB header arrives with it whole") if b"X-Long: " + b"L" * 30000 + b"\r\n" in got else \
        t.fail("an answer with a 30 KB header arrives with it whole", "the header", len(got))
    t.ok("and its body after it") if got.endswith(b"\r\n\r\nok") else \
        t.fail("and its body after it", "ok at the end", got[-40:])

    # --- through a parent proxy: the line goes back to absolute form, put
    # in front of the headers in the buffer, one piece with them -----------
    origin.answer = ok
    viaparent = t.free_port()
    t.start("proxy_headers_parent", f"""
        log
        auth iponly
        allow *
        parent 1000 http 127.0.0.1 {origin.port}
        proxy -p{viaparent}
    """, ports=[viaparent])
    origin.requests.clear()
    body = b"abcdefghij" * 30
    got = session(viaparent, request(b"/viaparent", b"", body, b"POST"), 1)
    t.contains(got.decode("latin-1"), "200 OK", "a request through an HTTP parent is answered")
    head, rbody = origin.requests[0] if origin.requests else (b"", b"")
    want = b"POST " + base.encode() + b"/viaparent HTTP/1.1\r\n"
    t.ok("the parent gets the request line in absolute form") if head.startswith(want) else \
        t.fail("the parent gets the request line in absolute form", want, head[:80])
    t.ok("and the headers after it, with Forwarded added") if b"\r\nHost: 127.0.0.1" in head and b"\r\nForwarded: for=" in head else \
        t.fail("and the headers after it, with Forwarded added", "Host, Forwarded", head[:300])
    t.eq(body, rbody, "and the body whole")

    # user and password in the URL: the line put back is the longer for them
    origin.requests.clear()
    user, password = "u" * 120, "p" * 120
    long = (b"GET http://" + user.encode() + b":" + password.encode() + b"@127.0.0.1:" +
            str(origin.port).encode() + b"/longline HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    got = session(viaparent, long, 1)
    t.contains(got.decode("latin-1"), "200 OK", "a request with user and password in its URL is answered")
    head = origin.requests[0][0] if origin.requests else b""
    t.ok("its line arrives in absolute form") if head.startswith(b"GET http://") and b"/longline HTTP/1.1\r\n" in head else \
        t.fail("its line arrives in absolute form", "GET http://...", head[:80])
    t.ok("with the credentials of the URL as Proxy-Authorization for the parent") if b"\r\nProxy-Authorization: Basic " in head else \
        t.fail("with the credentials of the URL as Proxy-Authorization for the parent", "Proxy-Authorization", head[-200:])

    # headers which went to a buffer of their own, here for a data filter
    # to read the body into the connection's: line and headers are put
    # together there, still in one piece
    filtered = t.free_port()
    t.start("proxy_headers_filtered", f"""
        log
        auth iponly
        allow *
        pcre clidata dunno *
        parent 1000 http 127.0.0.1 {origin.port}
        proxy -p{filtered}
    """, ports=[filtered])
    origin.requests.clear()
    body = b"klmnopqrst" * 20
    got = session(filtered, request(b"/filtered", b"", body, b"POST"), 1)
    t.contains(got.decode("latin-1"), "200 OK", "a request with a data filter, through a parent, is answered")
    head, rbody = origin.requests[0] if origin.requests else (b"", b"")
    want = b"POST " + base.encode() + b"/filtered HTTP/1.1\r\n"
    t.ok("its line is in absolute form, put together with the headers") if head.startswith(want) and b"\r\nHost: 127.0.0.1" in head else \
        t.fail("its line is in absolute form, put together with the headers", want, head[:120])
    t.eq(body, rbody, "and its body whole")

    # --- a long request line: served whole, logged cut at REQMAX (4 KB) ---
    origin.answer = ok
    origin.requests.clear()
    got = session(proxy, request(b"/" + b"q" * 7000), 1)
    t.contains(got.decode("latin-1"), "200 OK", "a request line of 7 KB is answered")
    head = origin.requests[0][0] if origin.requests else b""
    t.ok("and reaches the server whole") if (b"/" + b"q" * 7000 + b" HTTP/1.1") in head else \
        t.fail("and reaches the server whole", "7000 q", len(head))
    deadline = time.time() + 3
    while time.time() < deadline and "q" * 3000 not in server.output():
        time.sleep(0.1)
    logged = [l for l in server.output().splitlines() if "qqqq" in l]
    t.ok("and it is logged, cut") if logged and "q" * 4100 not in logged[-1] else \
        t.fail("and it is logged, cut", "a log line", logged[-1][-60:] if logged else None)

    # through a parent: authority put back from the log copy, a path long
    # enough for that copy to be cut
    origin.requests.clear()
    got = session(viaparent, request(b"/" + b"r" * 5000), 1)
    t.contains(got.decode("latin-1"), "200 OK", "a 5 KB line through a parent is answered")
    head = origin.requests[0][0] if origin.requests else b""
    want = b"GET " + base.encode() + b"/" + b"r" * 5000 + b" HTTP/1.1\r\n"
    t.ok("in absolute form, whole") if head.startswith(want) else \
        t.fail("in absolute form, whole", "GET http://.../rrr", head[:80])

    # --- a request too big for any buffer is refused, and the proxy stays --
    huge = b"".join(b"X-Huge-%d: %s\r\n" % (i, b"H" * 30000) for i in range(20))
    got = session(proxy, request(b"/huge", huge), 1, timeout=3)
    t.ok("a 600 KB header block is refused") if b"200 OK" not in got else \
        t.fail("a 600 KB header block is refused", "no 200", got[:60])
    origin.answer = ok
    got = session(proxy, request(b"/again"), 1)
    t.contains(got.decode("latin-1"), "200 OK", "and the proxy answers after it")
    origin.close()
