"""dnspr: a caching DNS proxy, answering from what it has been told."""

import time


def run(t):
    port = t.free_port()
    t.start("dnspr", f"""
        log
        flush
        nserver 127.0.0.1
        nscache 1024
        nsrecord host.test 10.11.12.13
        nsrecord other.test 10.11.12.14
        nsrecord blocked.test 0.0.0.0
        auth iponly
        allow *
        dnspr -p{port}
    """)
    # Wait for the service: a datagram sent too early is simply lost. Bound
    # by the clock, not by a number of attempts, so a server that answers
    # nothing costs seconds rather than minutes.
    deadline = time.time() + 5
    while time.time() < deadline:
        if t.dns_query(port, "host.test"):
            break

    t.eq(["10.11.12.13"], t.dns_query(port, "host.test"),
         "a static record is answered")
    t.eq(["10.11.12.14"], t.dns_query(port, "other.test"),
         "and so is another one")

    # asking twice must give the same answer, which is what the cache is for
    t.eq(["10.11.12.13"], t.dns_query(port, "host.test"),
         "the same name answers the same way again")

    # 0.0.0.0 is the documented way to make a name never resolve: the
    # address is handed out, and it is the client that then gets nowhere
    t.eq(["0.0.0.0"], t.dns_query(port, "blocked.test"),
         "a name pointed at 0.0.0.0 answers with that address")

    # a name it knows nothing about cannot be answered from here: the
    # configured server does not exist, so there is nothing to forward to
    t.ne(["10.11.12.13"], t.dns_query(port, "unknown.test") or [],
         "an unknown name does not borrow another answer")
