"""Request parsing: decoding, path safety, malformed and oversized input.

These go over a raw socket, because a well-behaved client would normalise
most of them away before they ever reached the server.
"""


def run(t):
    srv = t.free_port()
    t.start("httpsrv_parsing", f"""
        log
        auth iponly
        allow *
        http echo * /echo**
        http echo * /safe/**
        httpsrv -p{srv}
    """, ports=[srv])

    def request(path, host="t", extra=""):
        return t.raw(srv, f"GET {path} HTTP/1.0\r\nHost: {host}\r\n{extra}\r\n")

    # --- percent-decoding ---------------------------------------------
    reply = request("/%65cho")
    t.contains(reply, "200 OK", "a percent-encoded path is decoded before matching")
    t.contains(reply, "path=/echo", "the decoded path is what gets reported")
    t.contains(request("/echo%20space"), "glob= space",
               "an encoded space decodes into the glob")

    # --- traversal -----------------------------------------------------
    for path in ("/safe/../etc/passwd", "/safe/%2e%2e/etc", "/safe/..%2fetc",
                 "/echo/../../x"):
        t.not_contains(request(path), "200 OK", f"traversal is refused: {path}")

    t.contains(request("/safe/./ok"), "200 OK",
               "a harmless dot segment is still served")

    # --- injection ------------------------------------------------------
    t.not_contains(request("/echo%0d%0aInjected:%20yes"), "Injected: yes",
                   "an encoded CRLF cannot inject a header")
    t.not_contains(request("/echo%00cut"), "200 OK", "an encoded NUL is refused")

    # a header value cannot smuggle a newline into the echoed output
    reply = request("/echo", host="evil", extra="X-Injected: yes\r\n")
    t.not_contains(reply, "host=evil\nX-Injected",
                   "header values stay in their own fields")

    # --- malformed ------------------------------------------------------
    t.not_contains(t.raw(srv, "GARBAGE\r\n\r\n"), "200 OK",
                   "a malformed request line is not served")
    t.not_contains(t.raw(srv, "GET\r\n\r\n"), "200 OK",
                   "a request line with no URL is not served")

    # an over-long path has to be refused rather than quietly truncated to
    # something shorter that might match another rule
    t.not_contains(request("/echo" + "a" * 9000), "200 OK",
                   "an over-long path is refused, not truncated")

    # --- methods --------------------------------------------------------
    url = f"http://127.0.0.1:{srv}"
    t.eq(200, t.http(url + "/echo", method="HEAD").status, "HEAD is accepted")
    r = t.http(url + "/echo", method="POST", body="payload=1",
               headers={"Content-Type": "application/x-www-form-urlencoded"})
    t.contains(r, "method=POST", "POST reaches the handler")
    t.contains(r, "content.length=9", "the POST content length is parsed")

    # --- dollars in the configuration ------------------------------------
    # Outside quotes a dollar begins the name of a file to include, so an
    # argument holding one is quoted. Two dollars stand for one, which is how
    # a dollar reaches a rule as text.
    dsrv = t.free_port()
    t.start("httpsrv_dollar", f"""
        log
        auth iponly
        allow *
        http redir * /old** 301 "http://example.org/x$$y/$1"
        http redir * "pcre:^/re/([a-z]+)$" 302 "http://example.org/re/$1"
        http echo * /**
        httpsrv -p{dsrv}
    """, ports=[dsrv])

    durl = f"http://127.0.0.1:{dsrv}"
    r = t.http(durl + "/old/a")
    t.eq(301, r.status, "a rule holding a doubled dollar loads")
    t.eq("http://example.org/x$y//a", r.header("Location"),
         "and two dollars reach the location as one")
    t.eq(302, t.http(durl + "/re/abc").status,
         "a quoted regular expression keeps its anchor")
    t.eq(200, t.http(durl + "/re/ab9").status,
         "and the anchor is real: what it excludes falls through")
