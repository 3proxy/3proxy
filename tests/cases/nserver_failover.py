"""Name resolution: a server answering with an error is passed over, one
that says the name is not there ends the search.

A proxy resolves the destination by asking the configured name servers in
order. The first one here answers FORMERR to everything; the second answers
from a list. A request through the proxy reaches its destination, which
proves the second server was asked, and a name the second server says is
not there is not resolved by anyone else.
"""

import socket
import struct
import threading


class DnsServer:
    """Answers every query with a fixed rcode, and A records for names it
    knows: the question is echoed, so the answer parses everywhere."""

    def __init__(self, rcode, records):
        self.rcode = rcode
        self.records = records
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65536)
            except OSError:
                return
            if len(data) >= 12:
                self.sock.sendto(self.reply(data), addr)

    def reply(self, query):
        if self.rcode:
            return (query[:2] + struct.pack("!HHHHH", 0x8180 | self.rcode, 1, 0, 0, 0)
                    + query[12:])
        name = b""
        pos = 12
        while query[pos]:
            name += query[pos + 1:pos + 1 + query[pos]] + b"."
            pos += query[pos] + 1
        name = name[:-1]
        answer = self.records.get(name)
        if not answer:
            return (query[:2] + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0)
                    + query[12:])
        return (query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:]
                + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
                + socket.inet_aton(answer))

    def start(self):
        self.thread.start()
        return self.port


def run(t):
    broken = DnsServer(1, {}).start()
    good = DnsServer(0, {b"here.test": "127.0.0.1"}).start()

    # the destination the resolved name points at: a one-page origin
    origin = t.free_port()
    page = t.raw_server(origin, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                         b"\r\nok", close_after=True)

    proxy = t.free_port()
    t.start("nsfailover", f"""
        log
        flush
        nserver 127.0.0.1:{broken}
        nserver 127.0.0.1:{good}
        auth iponly
        allow *
        proxy -p{proxy}
    """, ports=[origin, proxy])

    url = f"http://here.test:{origin}/"
    t.eq(200, t.http(url, proxy=f"127.0.0.1:{proxy}").status,
         "a name one server breaks is resolved by the next one")

    r = t.http(f"http://gone.test:{origin}/", proxy=f"127.0.0.1:{proxy}")
    t.ne(200, r.status if r else 0,
         "a name the last server says is not there does not resolve")

    page()
