"""The port command: a listening socket reserved where the configuration
is read, a service of the same address taking it over.

A privileged port is opened before setuid and chroot take the rights
away, and the service named after them runs on the socket that is
already open: what would be a bind() denied is a takeover instead. A
port no service takes stays reserved, its socket listening on its own.
"""

import time


def run(t):
    if not t.skip_unless("httpsrv"):
        return

    origin = t.free_port()
    t.start("port_origin", f"""
        log
        auth iponly
        allow *
        http data * /data**
        httpsrv -p{origin}
    """, ports=[origin])

    # a port reserved and never taken: the socket listens by itself
    solo = t.free_port()
    t.start("port_solo", f"""
        log
        port tcp 127.0.0.1:{solo}
    """, ports=[solo])
    t.ok("a port with no service is kept listening") \
        if t.wait_port(solo) else \
        t.fail("a port with no service is kept listening",
               f"port {solo} open", "closed")

    # a service after the reservation takes the socket over
    reserved = t.free_port()
    server = t.start("port_taken", f"""
        log
        port tcp 127.0.0.1:{reserved}
        auth iponly
        allow *
        proxy -p{reserved} -i127.0.0.1
    """, ports=[reserved])

    out = t.wait_output(server, "taken over")
    t.contains(out, "taken over",
               "the service runs on the socket the reservation opened")

    t.eq(200, t.http(f"http://127.0.0.1:{origin}/data",
                     proxy=f"127.0.0.1:{reserved}").status,
         "a request through the taken-over port is served")

    # a reserved UDP port is taken over the same way: bound by the
    # reservation, answered by the service
    udpp = t.free_port()
    dns = t.start("port_udp", f"""
        log
        port udp 127.0.0.1:{udpp}
        nserver 127.0.0.1
        nscache 1024
        nsrecord here.test 10.11.12.13
        dnspr -p{udpp} -i127.0.0.1
    """)

    deadline = time.time() + 5
    while time.time() < deadline:
        if t.dns_query(udpp, "here.test"):
            break
        time.sleep(0.05)
    t.eq(["10.11.12.13"], t.dns_query(udpp, "here.test"),
         "a UDP service answers on its reserved port")
