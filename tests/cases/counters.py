"""Traffic counters: a numbered counter keeps what it counted across a
reload, the value belonging to the process rather than to the configuration
read."""

import re
import time


def run(t):
    origin = t.free_port()
    proxy = t.free_port()
    adm = t.free_port()
    server = t.start("counters", f"""
        log
        auth iponly
        allow *
        http data * /data
        httpsrv -p{origin}

        flush
        auth iponly
        allow *
        countin 3/counted D 100 * * *
        proxy -p{proxy}
        admin -p{adm}
    """, ports=[origin, proxy, adm])

    def counted():
        """The counter's value in MB, as the counters page shows it."""
        page = t.http(f"http://127.0.0.1:{adm}/C").text
        m = re.search(r"counted.*?</td><td>([0-9]+\.[0-9])</td>", page, re.S)
        return float(m.group(1)) if m else None

    def wait_counted(least, timeout=5.0):
        deadline = time.time() + timeout
        value = counted()
        while (value is None or value < least) and time.time() < deadline:
            time.sleep(0.1)
            value = counted()
        return value

    reply = t.http(f"http://127.0.0.1:{origin}/data?size=300000",
                   proxy=f"127.0.0.1:{proxy}")
    t.eq(300000, reply.length, "a body passes through the counted proxy")
    before = wait_counted(0.2)
    t.ok("the counter counts it") if before is not None and before >= 0.2 else \
        t.fail("the counter counts it", ">= 0.2", before)

    # reload, and wait for the services of the new configuration to run
    out = server.output()
    accepting = out.count("Accepting connections")
    t.http(f"http://127.0.0.1:{adm}/R")
    deadline = time.time() + 10
    while time.time() < deadline and server.output().count("Accepting connections") < accepting + 3:
        time.sleep(0.05)

    after = wait_counted(0.2)
    t.eq(before, after, "a reload keeps what the numbered counter counted")
