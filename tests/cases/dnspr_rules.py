"""dnspr: rules by the name asked about, and a parent's extip for the socket
a query leaves from.

Access rules accumulate until "flush": each service here stands alone.
"""

import socket
import struct
import threading
import time


class NameServer:
    """Answers an A record for every name, and remembers the address each
    query came from."""

    def __init__(self):
        self.sources = []
        self.lock = threading.Lock()
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
            with self.lock:
                self.sources.append(addr[0])
            if len(data) >= 12:
                self.sock.sendto(self.reply(data), addr)

    def reply(self, query):
        return (query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                + query[12:]
                + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
                + socket.inet_aton("127.0.0.1"))

    def start(self):
        self.thread.start()
        return self


def wait_service(t, port, name):
    """Bound by the clock, not by a number of attempts: a server that
    answers nothing costs seconds rather than minutes."""
    deadline = time.time() + 5
    while time.time() < deadline:
        if t.dns_query(port, name) is not None:
            return
    t.fail("the dnspr service never answered",
           f"no answer from port {port} within 5 seconds")


def bindable_extip():
    """An address a socket can be bound to whose source differs from what
    the kernel would pick on its own.

    Toward a name server on the loopback the kernel picks 127.0.0.1, so
    127.0.0.2 tells the difference; the whole 127/8 is bindable on Linux
    and Windows, but on macOS only the addresses assigned to lo0 are, and
    that one alone. The address of a real interface does there: bound
    explicitly, it is the source even towards the loopback.
    """
    for candidate in ("127.0.0.2", "route"):
        if candidate == "route":
            # no datagram leaves: a connected UDP socket only learns the
            # route's own end of it
            probe = None
            try:
                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                probe.connect(("192.0.2.1", 9))
                candidate = probe.getsockname()[0]
            except OSError:
                return None
            finally:
                if probe is not None:
                    probe.close()
        if candidate == "127.0.0.1":
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((candidate, 0))
            return candidate
        except OSError:
            continue
        finally:
            sock.close()
    return None


def run(t):
    # --- the targetlist is the name asked about ---------------------------
    port = t.free_port()
    t.start("dnspr_names", f"""
        log
        flush
        nserver 127.0.0.1
        nscache 1024
        nsrecord here.test 10.11.12.13
        auth iponly
        allow * 127.0.0.1 here.test
        deny *
        dnspr -p{port}
    """)

    wait_service(t, port, "here.test")
    t.eq(["10.11.12.13"], t.dns_query(port, "here.test"),
         "a name a rule allows is answered")

    # nothing answers a name no rule allows: not the address of another
    # name, not an error, the query is dropped
    t.eq(None, t.dns_query(port, "there.test"),
         "a name no rule allows is not answered at all")

    # --- a parent's extip is the address a query leaves from ---------------
    extip = bindable_extip()
    if not extip:
        t.skip("no address on this machine can be bound as an extip")
        return

    ns = NameServer().start()
    qport = t.free_port()
    t.start("dnspr_extip", f"""
        log
        flush
        nserver 127.0.0.1:{ns.port}
        auth iponly
        allow *
        parent 1000 extip {extip} 0
        dnspr -p{qport}
    """)

    wait_service(t, qport, "from.test")
    t.eq(["127.0.0.1"], t.dns_query(qport, "from.test"),
         "a query through extip is answered")

    with ns.lock:
        sources = list(ns.sources)
    t.ne([], sources, "the name server was asked")
    t.eq([], [s for s in sources if s != extip],
         "every query left from the extip address")

    # a parent of a kind with nowhere to connect a query is passed over,
    # and the resolver goes on without it
    oport = t.free_port()
    t.start("dnspr_otherparent", f"""
        log
        flush
        nserver 127.0.0.1:{ns.port}
        auth iponly
        allow *
        parent 1000 socks5 192.0.2.1 1080
        dnspr -p{oport}
    """)
    wait_service(t, oport, "any.test")
    t.eq(["127.0.0.1"], t.dns_query(oport, "any.test"),
         "a parent of another kind does not stop the resolver")
