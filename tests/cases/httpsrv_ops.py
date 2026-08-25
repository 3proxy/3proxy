"""The built-in HTTP server: the echo and data operations."""

import time


def run(t):
    srv = t.free_port()
    t.start("httpsrv_ops", f"""
        log
        auth iponly
        allow *
        http * /echo* echo
        http * /data data
        http * /small data size=64
        httpsrv -p{srv}
    """, ports=[srv])

    url = f"http://127.0.0.1:{srv}"

    # --- echo: request introspection ---------------------------------
    r = t.http(url + "/echo?a=1")
    t.eq(200, r.status, "echo answers 200")
    t.contains(r, "method=GET", "echo reports the method")
    t.contains(r, "path=/echo", "echo reports the path")
    t.contains(r, "query=a=1", "echo reports the query")
    t.contains(r, "peer.addr=127.0.0.1", "echo reports the peer address")
    t.contains(r, f"host=127.0.0.1:{srv}", "echo reports the Host header")

    # the glob is the wildcard-matched tail, which is how admin routes its
    # sub-pages
    r = t.http(url + "/echoXYZ")
    t.contains(r, "glob=XYZ", "echo reports the glob text")
    t.contains(r, "glob.len=3", "echo reports the glob length")

    # --- data: generated payload -------------------------------------
    t.eq(1000, t.http(url + "/data?size=1000").length, "data honours size")
    t.eq(0, t.http(url + "/data?size=0").length, "data size=0 sends an empty body")
    t.eq(64, t.http(url + "/small").length, "data takes its size from the rule")
    t.eq(1000, t.http(url + "/small?size=1000").length,
         "the query overrides the rule parameters")

    # a size past one block exercises the send loop
    t.eq(70000, t.http(url + "/data?size=70000").length,
         "data spans several blocks")
    t.eq(70000, t.http(url + "/data?size=70000&block=1024").length,
         "data honours the block size")

    # --- status and framing ------------------------------------------
    t.eq(404, t.http(url + "/data?size=10&status=404").status,
         "data honours the status")
    t.eq(503, t.http(url + "/data?size=10&status=503").status,
         "data returns 503 when asked")
    t.eq(200, t.http(url + "/data?size=10&status=99").status,
         "an out-of-range status falls back to 200")

    r = t.http(url + "/data?size=100")
    t.eq("100", r.header("Content-Length"), "an identity reply sets Content-Length")

    r = t.http(url + "/data?size=100&chunked=1")
    t.eq("chunked", r.header("Transfer-Encoding"),
         "a chunked reply sets Transfer-Encoding")
    t.eq(None, r.header("Content-Length"),
         "a chunked reply omits Content-Length")
    t.eq(100, r.length, "a chunked body decodes to the size asked for")
    t.eq(70000, t.http(url + "/data?size=70000&chunked=1").length,
         "a chunked body spans several blocks")

    # --- delay --------------------------------------------------------
    start = time.time()
    t.http(url + "/data?size=4096&block=1024&delay=100")
    elapsed = time.time() - start
    if elapsed >= 0.3:
        t.ok("delay slows the transfer")
    else:
        t.fail("delay slows the transfer", ">=0.3s", f"{elapsed:.2f}s")

    # --- unmatched ----------------------------------------------------
    t.eq(404, t.http(url + "/nosuchthing").status, "an unmatched URL gives 404")
