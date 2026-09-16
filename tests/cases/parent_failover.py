"""parent: what happens to a group when one of its members is down.

A parent which fails is taken out of the random choice for the rest of the
connection, so a retry reaches another member of the group instead of the same
dead one again. A parent of weight 0 is the fallback of its group: it is only
used once every weighted member has failed.

The number of attempts is bounded by parentretries, two by default, so each
case here needs at most one parent to fail before a working one is reached.
"""

import time


def served(server, needle, since=0):
    """How many log lines carrying needle a proxy wrote past offset since."""
    return sum(1 for line in server.output()[since:].splitlines() if needle in line)


def wait_served(server, needle, count, since=0, timeout=5.0):
    """Wait for count such lines: a session is logged once it is over, which
    is a moment after the client has its answer."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        seen = served(server, needle, since)
        if seen >= count:
            return seen
        time.sleep(0.05)
    return served(server, needle, since)


def run(t):
    srv = t.free_port()
    good = t.free_port()
    spare = t.free_port()
    # nothing is ever started here, so connecting to it is refused at once
    dead = t.free_port()

    origin = t.start("failover_origin", f"""
        log
        auth iponly
        allow *
        http echo * /echo**
        httpsrv -p{srv}
    """, ports=[srv])

    goodp = t.start("failover_good", f"""
        log
        auth iponly
        allow *
        proxy -p{good}
    """, ports=[good])

    sparep = t.start("failover_spare", f"""
        log
        auth iponly
        allow *
        proxy -p{spare}
    """, ports=[spare])

    fallback = t.free_port()
    idle = t.free_port()
    group = t.free_port()
    allgone = t.free_port()
    lone = t.free_port()

    t.start("failover_client", f"""
        log
        auth iponly

        # the only weighted parent is dead, the fallback has to take over
        flush
        allow *
        parent 1000 connect 127.0.0.1 {dead}
        parent 0 connect 127.0.0.1 {spare}
        proxy -p{fallback}

        # the weighted parent works, so the fallback stays untouched
        flush
        allow *
        parent 1000 connect 127.0.0.1 {good}
        parent 0 connect 127.0.0.1 {spare}
        proxy -p{idle}

        # one member of a group of two is dead: a retry must not pick it again
        flush
        allow *
        parent 500 connect 127.0.0.1 {dead}
        parent 500 connect 127.0.0.1 {good}
        proxy -p{group}

        # nothing left to fall back to
        flush
        allow *
        parent 1000 connect 127.0.0.1 {dead}
        proxy -p{allgone}

        # a parent of weight 0 on its own is simply the parent to use
        flush
        allow *
        parent 0 connect 127.0.0.1 {good}
        proxy -p{lone}
    """, ports=[fallback, idle, group, allgone, lone])

    url = f"http://127.0.0.1:{srv}/echo"
    needle = f"CONNECT 127.0.0.1:{srv}"

    # --- the fallback takes over --------------------------------------------
    mark = len(sparep.output())
    r = t.http(url, proxy=f"127.0.0.1:{fallback}")
    t.eq(200, r.status, "a dead weighted parent falls back to the parent of weight 0")
    t.eq(1, wait_served(sparep, needle, 1, mark),
         "the fallback parent carried the request")

    # --- and only then ------------------------------------------------------
    mark = len(sparep.output())
    gmark = len(goodp.output())
    for _ in range(4):
        t.eq(200, t.http(url, proxy=f"127.0.0.1:{idle}").status,
             "a working weighted parent serves the request")
    t.eq(4, wait_served(goodp, needle, 4, gmark),
         "every request went through the weighted parent")
    t.eq(0, served(sparep, needle, mark),
         "the fallback is left alone while the weighted parent works")

    # --- a dead member of a weighted group ----------------------------------
    # Whichever of the two the first attempt picks, the request has to end up
    # at the one that is up: the dead one is not offered to the retry again.
    gmark = len(goodp.output())
    statuses = [t.http(url, proxy=f"127.0.0.1:{group}").status for _ in range(8)]
    t.eq([200] * 8, statuses,
         "a dead member of a group never fails a request twice over")
    t.eq(8, wait_served(goodp, needle, 8, gmark),
         "all of them were carried by the member which is up")

    # --- nothing left -------------------------------------------------------
    # With every parent of the group gone the request has to fail. Connecting
    # direct instead would be a way around the rule that asked for a parent.
    omark = len(origin.output())
    r = t.http(url, proxy=f"127.0.0.1:{allgone}")
    t.ne(200, r.status, "a request fails when every parent of the group is down")
    time.sleep(0.5)
    t.eq(0, served(origin, "/echo", omark),
         "and it is not sent direct to the origin instead")

    # --- weight 0 on its own ------------------------------------------------
    gmark = len(goodp.output())
    t.eq(200, t.http(url, proxy=f"127.0.0.1:{lone}").status,
         "a parent of weight 0 alone is used like any other")
    t.eq(1, wait_served(goodp, needle, 1, gmark),
         "through the parent it names")

    # --- what the parser still rejects --------------------------------------
    out = t.run_config("failover_badweight", f"""
        auth iponly
        allow *
        parent 1001 connect 127.0.0.1 {good}
        proxy -p{t.free_port()}
    """)
    t.contains(out, "bad chain weight", "a weight above 1000 is still refused")
