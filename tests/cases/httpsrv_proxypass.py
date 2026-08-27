"""A service which is both a site and a proxy.

The rules answer what they have; anything else is handed to the proxy code,
which authenticates as a proxy and fetches it. The same connection carries
both kinds of request.
"""

import os


def run(t):
    root = os.path.join(t.tmpdir, "pp")
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "a.html"), "w") as fp:
        fp.write("<h1>local</h1>")

    # two origins, so a change of destination is visible
    one = t.free_port()
    two = t.free_port()
    t.start("httpsrv_proxypass_origins", f"""
        auth iponly
        allow *
        http echo * /**
        httpsrv -p{one}

        flush
        auth iponly
        allow *
        http echo * /**
        httpsrv -p{two}
    """, ports=[one, two])

    # --- the rule which hands a request on ---------------------------------
    srv = t.free_port()
    t.start("httpsrv_proxypass", f"""
        log
        auth iponly
        allow *
        http file * /local/*.html "{root}/$1.html"
        http reply * /health** 200
        http proxypass * /**
        httpsrv -p{srv}
    """, ports=[srv])

    url = f"http://127.0.0.1:{srv}"
    t.contains(t.http(url + "/local/a.html"), "<h1>local</h1>",
               "a rule of its own is still answered here")
    t.eq(200, t.http(url + "/health").status, "and so is another")

    r = t.http(f"http://127.0.0.1:{one}/echo", proxy=f"127.0.0.1:{srv}")
    t.eq(200, r.status, "a request the rules do not answer is proxied")
    t.contains(r, "path=/echo", "and the origin sees it")

    # a client which sends an origin-form request with a Host header reaches
    # the same place: what decides is which rule matches, not the form
    r = t.http(url + "/echo", headers={"Host": f"127.0.0.1:{one}"})
    t.contains(r, "path=/echo", "an origin-form request is proxied the same way")

    # --- an access rule which sends the rest to the proxy -------------------
    # allow, with a chain to the local proxy, then a second rule for the pass
    # the proxy itself makes
    rsrv = t.free_port()
    t.start("httpsrv_proxypass_acl", f"""
        log
        auth iponly
        allow *
        parent 1000 http 0.0.0.0 0
        allow *
        http file * /local/*.html "{root}/$1.html"
        httpsrv -p{rsrv}
    """, ports=[rsrv])

    rurl = f"http://127.0.0.1:{rsrv}"
    t.contains(t.http(rurl + "/local/a.html"), "<h1>local</h1>",
               "a rule still wins over the redirect")
    r = t.http(f"http://127.0.0.1:{one}/echo", proxy=f"127.0.0.1:{rsrv}")
    t.eq(200, r.status, "and what no rule matches goes to the proxy the rule named")

    # --- rules after the chain decide what the proxy may fetch -------------
    # The service answers for itself on the first pass, so an address or a
    # port there is the one the client connected to; on the pass the proxy
    # makes, it is the one the request names.
    gsrv = t.free_port()
    t.start("httpsrv_proxypass_gate", f"""
        log
        auth iponly
        allow *
        parent 1000 http 0.0.0.0 0
        allow * * 127.0.0.1/32 {one}
        deny *
        httpsrv -p{gsrv}
    """, ports=[gsrv])

    t.eq(200, t.http(f"http://127.0.0.1:{one}/echo", proxy=f"127.0.0.1:{gsrv}").status,
         "a destination a later rule allows is fetched")
    t.eq(403, t.http(f"http://127.0.0.1:{two}/echo", proxy=f"127.0.0.1:{gsrv}").status,
         "and one no rule allows is refused")

    # a deny written before the rule carrying the chain applies as well
    bsrv = t.free_port()
    t.start("httpsrv_proxypass_deny", f"""
        log
        auth iponly
        deny * * 127.0.0.1/32 {two}
        allow *
        parent 1000 http 0.0.0.0 0
        allow *
        httpsrv -p{bsrv}
    """, ports=[bsrv])

    t.eq(200, t.http(f"http://127.0.0.1:{one}/echo", proxy=f"127.0.0.1:{bsrv}").status,
         "what the deny does not name is still fetched")
    t.eq(403, t.http(f"http://127.0.0.1:{two}/echo", proxy=f"127.0.0.1:{bsrv}").status,
         "a deny before the chain stops the request too")

    # --- one connection, both kinds of request -----------------------------
    text, closed = t.raw_session(srv,
        f"GET /local/a.html HTTP/1.1\r\nHost: t\r\n\r\n"
        f"GET http://127.0.0.1:{one}/echo HTTP/1.1\r\nHost: 127.0.0.1:{one}\r\n\r\n"
        f"GET http://127.0.0.1:{two}/echo HTTP/1.1\r\nHost: 127.0.0.1:{two}\r\n\r\n"
        f"GET /local/a.html HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
        quiet=2)
    t.eq(4, text.count("HTTP/1."), "four requests are answered on one connection")
    t.eq(2, text.count("<h1>local</h1>"), "two of them here")
    t.eq(2, text.count("peer.addr="), "and two by the origins")
    t.eq(True, closed, "the last one ends it")

    # --- every kind of rule on the same connection --------------------------
    with open(os.path.join(root, "f.html"), "w") as fp:
        fp.write("FILEBODY")
    with open(os.path.join(root, "c.html"), "w") as fp:
        fp.write("CACHEBODY")

    msrv = t.free_port()
    t.start("httpsrv_proxypass_mix", f"""
        log
        auth iponly
        allow *
        http file  * /f/*.html "{root}/$1.html"
        http cache * /c/*.html "{root}/$1.html"
        http proxypass * /**
        httpsrv -p{msrv}
    """, ports=[msrv])

    proxied = f"GET http://127.0.0.1:{one}/echo HTTP/1.1\r\nHost: 127.0.0.1:{one}\r\n\r\n"
    text, closed = t.raw_session(msrv,
        "GET /f/f.html HTTP/1.1\r\nHost: t\r\n\r\n"
        "GET /c/c.html HTTP/1.1\r\nHost: t\r\n\r\n"
        + proxied +
        "GET /c/c.html HTTP/1.1\r\nHost: t\r\n\r\n"
        + proxied +
        "GET /f/f.html HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
        quiet=2)
    t.eq(6, text.count("HTTP/1."), "file, cache and proxypass share one connection")
    t.eq(2, text.count("FILEBODY"), "both files arrive")
    t.eq(2, text.count("CACHEBODY"), "both cached files arrive")
    t.eq(2, text.count("peer.addr="), "and both proxied requests arrive")
    t.eq(True, closed, "the request asking to close ends it")

    # --- a proxied answer of unstated length ends the connection ------------
    # Its body is delimited by the close, so nothing can follow it here
    # either: the client has to ask again on a new connection.
    closer = t.free_port()
    stop = t.raw_server(closer,
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nCLOSEDELIMITED",
                        close_after=True)
    try:
        text, closed = t.raw_session(msrv,
            f"GET http://127.0.0.1:{closer}/x HTTP/1.1\r\nHost: 127.0.0.1:{closer}\r\n\r\n"
            "GET /f/f.html HTTP/1.1\r\nHost: t\r\n\r\n", quiet=2)
        t.eq(1, text.count("HTTP/1."), "the answer of unstated length is the last one")
        t.contains(text, "CLOSEDELIMITED", "and its body still arrives whole")
        t.eq(True, closed, "the connection ends with it")
    finally:
        stop()

    # --- credentials go where a proxy expects them --------------------------
    asrv = t.free_port()
    t.start("httpsrv_proxypass_auth", f"""
        log
        users u:CL:p
        auth strong
        allow u
        http file * /local/*.html "{root}/$1.html"
        http proxypass * /**
        httpsrv -p{asrv}
    """, ports=[asrv])

    aurl = f"http://127.0.0.1:{asrv}"
    r = t.http(f"http://127.0.0.1:{one}/echo", proxy=f"127.0.0.1:{asrv}")
    t.eq(407, r.status, "a proxy-style request with no credentials is asked for them")
    t.contains(r.header("Proxy-Authenticate") or "", "Basic",
               "with the header a proxy client reads")

    r = t.http(f"http://127.0.0.1:{one}/echo", proxy=f"127.0.0.1:{asrv}",
               proxy_auth=("u", "p"))
    t.eq(200, r.status, "and is served once they are given")

    r = t.http(aurl + "/local/a.html")
    t.eq(401, r.status, "a request to the site itself is asked the site's way")
    t.contains(r.header("WWW-Authenticate") or "", "Basic", "with its own header")
    t.contains(t.http(aurl + "/local/a.html", auth=("u", "p")), "<h1>local</h1>",
               "and answered once they are given")
