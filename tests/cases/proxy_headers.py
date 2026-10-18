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
    t.start("proxy_headers", f"""
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

    # --- a request too big for any buffer is refused, and the proxy stays --
    huge = b"".join(b"X-Huge-%d: %s\r\n" % (i, b"H" * 30000) for i in range(20))
    got = session(proxy, request(b"/huge", huge), 1, timeout=3)
    t.ok("a 600 KB header block is refused") if b"200 OK" not in got else \
        t.fail("a 600 KB header block is refused", "no 200", got[:60])
    origin.answer = ok
    got = session(proxy, request(b"/again"), 1)
    t.contains(got.decode("latin-1"), "200 OK", "and the proxy answers after it")
    origin.close()
