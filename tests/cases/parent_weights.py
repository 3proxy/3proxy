"""parent weights: the fraction notation, and what a group adds up to.

A weight is scanned as an integer into a share of 1000000000. A weight which
starts with 0 or . is a fraction of one, .333 being a third; anything else is
the old notation, thousandths, which may now carry further digits after a dot,
so 123.456 means the same as .123456. 1.0 is the exception, read as it looks,
and a trailing % makes a weight a percentage: 50.5% is .505 is 505.

The values are read back from the admin interface, which dumps the parsed
configuration, so what is checked is the number 3proxy holds rather than the
behaviour it happens to produce.
"""

import re
import time

CHAIN_WEIGHT = re.compile(
    r"parent weight[^<]*</description><value><!\[CDATA\[([0-9]+)")


def weights(t, adm):
    return [int(v) for v in CHAIN_WEIGHT.findall(t.http(f"http://127.0.0.1:{adm}/S").text)]


def served(server, needle, since=0):
    return sum(1 for line in server.output()[since:].splitlines() if needle in line)


def wait_served(server, needle, count, since=0, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        seen = served(server, needle, since)
        if seen >= count:
            return seen
        time.sleep(0.05)
    return served(server, needle, since)


def run(t):
    adm = t.free_port()
    prx = t.free_port()
    dummy = t.free_port()

    t.start("weights_parse", f"""
        auth iponly
        allow *
        admin -p{adm}

        flush
        auth iponly
        allow *
        parent 1000 connect 127.0.0.1 {dummy}
        parent 1.0 connect 127.0.0.1 {dummy}
        parent 1.00000000000000 connect 127.0.0.1 {dummy}
        parent 500 connect 127.0.0.1 {dummy}
        parent 1 connect 127.0.0.1 {dummy}
        parent 1.5 connect 127.0.0.1 {dummy}
        parent 123.456 connect 127.0.0.1 {dummy}
        parent 12.34 connect 127.0.0.1 {dummy}
        parent 1.000001 connect 127.0.0.1 {dummy}
        parent .333 connect 127.0.0.1 {dummy}
        parent 0.333 connect 127.0.0.1 {dummy}
        parent .5 connect 127.0.0.1 {dummy}
        parent .333333333 connect 127.0.0.1 {dummy}
        parent 0.000000001 connect 127.0.0.1 {dummy}
        parent 100% connect 127.0.0.1 {dummy}
        parent 50.5% connect 127.0.0.1 {dummy}
        parent 50% connect 127.0.0.1 {dummy}
        parent 33.3333333% connect 127.0.0.1 {dummy}
        parent 1.0% connect 127.0.0.1 {dummy}
        parent 0.0000001% connect 127.0.0.1 {dummy}
        parent 0 connect 127.0.0.1 {dummy}
        proxy -p{prx}
    """, ports=[adm, prx])

    t.eq([
        1000000000,     # 1000, the old notation for the whole share
        1000000000,     # 1.0, the same share written as a fraction
        1000000000,     # 1.00000000000000, zeroes past the point change nothing
        500000000,      # 500
        1000000,        # 1, a thousandth
        1500000,        # 1.5, one thousandth and a half of one
        123456000,      # 123.456, the old notation carried further
        12340000,       # 12.34
        1000001,        # 1.000001, six digits past the thousandths
        333000000,      # .333
        333000000,      # 0.333, the same thing written out
        500000000,      # .5
        333333333,      # .333333333, the finest the resolution goes
        1,              # 0.000000001, one part of the whole
        1000000000,     # 100%
        505000000,      # 50.5%, the same as .505 and as 505
        500000000,      # 50%
        333333333,      # 33.3333333%, seven digits past the point
        10000000,       # 1.0%, a percent rather than the whole share
        1,              # 0.0000001%, one part again
        0,              # the fallback weight
    ], weights(t, adm), "every notation is scanned into its share")

    # --- what the parser refuses ------------------------------------------
    for bad in ("1001", "1000.1", "1.0000001", ".1234567890", "01", "abc",
                "1.2.3", "-1", "1e9", "101%", "50.55555555%", "%", "5%%",
                "%5"):
        out = t.run_config("weights_bad", f"""
            auth iponly
            allow *
            parent {bad} connect 127.0.0.1 {dummy}
            proxy -p{t.free_port()}
        """)
        t.contains(out, "bad chain weight", f"{bad} is refused as a weight")

    # --- a group that all but adds up ---------------------------------------
    # .999999999 is one part short of the whole share. It still closes its
    # group, so the parent after it is the next hop of a chain rather than
    # another member of the same group.
    srv = t.free_port()
    first = t.free_port()
    second = t.free_port()
    chained = t.free_port()
    grouped = t.free_port()
    thirds = t.free_port()

    t.start("weights_origin", f"""
        log
        auth iponly
        allow *
        http echo * /echo**
        httpsrv -p{srv}
    """, ports=[srv])

    firstp = t.start("weights_first", f"""
        log
        auth iponly
        allow *
        proxy -p{first}
    """, ports=[first])

    secondp = t.start("weights_second", f"""
        log
        auth iponly
        allow *
        proxy -p{second}
    """, ports=[second])

    t.start("weights_client", f"""
        log
        auth iponly

        # one part short of the whole share still ends the group
        flush
        allow *
        parent .999999999 connect 127.0.0.1 {first}
        parent 1000 connect 127.0.0.1 {second}
        proxy -p{chained}

        # two halves, one written each way, are one group and one hop
        flush
        allow *
        parent 500 connect 127.0.0.1 {first}
        parent .5 connect 127.0.0.1 {second}
        proxy -p{grouped}

        # three thirds are a thousandth short of the whole share and still
        # make a group, so the parent after them is the next hop
        flush
        allow *
        parent 333 connect 127.0.0.1 {first}
        parent 333 connect 127.0.0.1 {first}
        parent 333 connect 127.0.0.1 {first}
        parent 1000 connect 127.0.0.1 {second}
        proxy -p{thirds}
    """, ports=[chained, grouped, thirds])

    url = f"http://127.0.0.1:{srv}/echo"
    toorigin = f"CONNECT 127.0.0.1:{srv}"
    tosecond = f"CONNECT 127.0.0.1:{second}"

    fmark, smark = len(firstp.output()), len(secondp.output())
    t.eq(200, t.http(url, proxy=f"127.0.0.1:{chained}").status,
         "a chain of two groups carries the request")
    t.eq(1, wait_served(firstp, tosecond, 1, fmark),
         "the first group's parent was asked for the second one")
    t.eq(1, wait_served(secondp, toorigin, 1, smark),
         "and the second group's parent reached the origin")
    t.eq(0, served(firstp, toorigin, fmark),
         "the first parent never went to the origin itself")

    # both members of one group talk to the origin, never to each other
    fmark, smark = len(firstp.output()), len(secondp.output())
    for _ in range(8):
        t.eq(200, t.http(url, proxy=f"127.0.0.1:{grouped}").status,
             "a group of two halves carries the request")
    t.eq(8, wait_served(firstp, toorigin, 8, fmark, timeout=0.5) +
            wait_served(secondp, toorigin, 8, smark, timeout=0.5),
         "each request took one hop, through either half")
    t.eq(0, served(firstp, tosecond, fmark),
         "the halves are one group, not a chain")

    # --- three thirds -------------------------------------------------------
    # 999000000 is within a thousandth of the whole share, so the group closes
    # there. Were it left open the parent of weight 1000 would join it and
    # carry about half the requests on its own, without the first hop.
    fmark, smark = len(firstp.output()), len(secondp.output())
    for _ in range(8):
        t.eq(200, t.http(url, proxy=f"127.0.0.1:{thirds}").status,
             "a group of three thirds carries the request")
    t.eq(8, wait_served(firstp, tosecond, 8, fmark),
         "every request took a third as its first hop")
    t.eq(8, wait_served(secondp, toorigin, 8, smark),
         "and the parent after them as its second")
