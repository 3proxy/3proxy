"""Keep-alive: which answers may be followed by another request.

The next request begins where the last answer ended, so a connection is only
kept when the length of what was sent is known exactly and the body of the
request was read to its end. Everything else closes, which is the safe way to
be wrong.
"""

import os


def run(t):
    root = os.path.join(t.tmpdir, "ka")
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "a.html"), "w") as fp:
        fp.write("<h1>hello</h1>")

    port = t.free_port()
    t.start("httpsrv_keepalive", f"""
        log
        auth iponly
        allow *
        http file  * /w/*.html "{root}/$1.html"
        http reply * /ok**  200
        http echo  * /echo**
        http data  * /chunked** size=100&chunked=1
        httpsrv -p{port}
    """, ports=[port])

    def req(path, version="1.1", extra="", body=""):
        head = (f"GET {path} HTTP/{version}\r\nHost: t\r\n{extra}\r\n")
        if body:
            head = head.replace("GET", "POST", 1)
        return head + body

    def session(*requests, quiet=0.5):
        text, closed = t.raw_session(port, "".join(requests), quiet=quiet)
        return text, closed, text.count("HTTP/1.")

    # --- what keeps the connection ---------------------------------------
    text, closed, n = session(req("/w/a.html"), req("/ok"),
                              req("/w/a.html", extra="Connection: close\r\n"))
    t.eq(3, n, "three 1.1 requests are answered on one connection")
    t.eq(True, closed, "and the one asking to close ends it")
    t.contains(text, "Connection: keep-alive", "the answers say the connection is kept")
    t.eq(2, text.count("<h1>hello</h1>"), "each file arrives whole")

    text, closed, n = session(req("/w/a.html", version="1.0"), req("/ok", version="1.0"))
    t.eq(1, n, "a 1.0 request without the header is answered once")
    t.eq(True, closed, "and the connection ends")
    t.contains(text, "Connection: close", "which the answer says")

    text, closed, n = session(req("/w/a.html", version="1.0",
                                  extra="Connection: keep-alive\r\n"),
                              req("/ok", version="1.0",
                                  extra="Connection: close\r\n"))
    t.eq(2, n, "a 1.0 client asking for keep-alive gets it")

    # a request carrying a body: the next one begins after it
    text, closed, n = session(req("/echo", extra="Content-Length: 5\r\n", body="hello"),
                              req("/ok", extra="Connection: close\r\n"))
    t.eq(2, n, "a body which was read to its end leaves the stream in place")
    t.contains(text, "content.length=5", "and the body was seen")

    # --- what ends it -----------------------------------------------------
    text, closed, n = session(req("/echo", extra="Transfer-Encoding: chunked\r\n"),
                              req("/ok"))
    t.eq(1, n, "a request body this server cannot frame ends the connection")
    t.eq(True, closed, "the connection is closed rather than left mid-body")

    # A body longer than the server is willing to read leaves the rest of it
    # in the stream, so the connection cannot carry another request. The send
    # may not even finish - the server answers and closes part way through -
    # which is the same answer from the other side.
    big = "x" * 1500000
    text, closed, n = session(req("/echo", extra="Content-Length: 1500000\r\n", body=big),
                              quiet=2)
    t.eq(1, n, "a body past what the server will read is answered once")
    t.contains(text, "Connection: close",
               "and the answer ends the connection rather than leaving the rest to be read")

    # --- answers of other shapes -----------------------------------------
    text, closed, n = session(req("/chunked"), req("/ok", extra="Connection: close\r\n"))
    t.eq(2, n, "a chunked answer may be followed by another request")

    text, closed, n = session(req("/chunked", version="1.0"), req("/ok", version="1.0"))
    t.eq(1, n, "but not for a client which has no chunked encoding to read")

    stamp = t.http(f"http://127.0.0.1:{port}/w/a.html").header("Last-Modified")
    text, closed, n = session(req("/w/a.html", extra=f"If-Modified-Since: {stamp}\r\n"),
                              req("/ok", extra="Connection: close\r\n"))
    t.eq(2, n, "a 304 carries no body and the next request follows it")
    t.contains(text, "304", "and it is a 304")

    # --- the administration pages always close ---------------------------
    aport = t.free_port()
    t.start("httpsrv_keepalive_admin", f"""
        log
        auth iponly
        allow *
        http file * /w/*.html "{root}/$1.html"
        admin -p{aport}
    """, ports=[aport])

    text, closed = t.raw_session(aport,
        f"GET /w/a.html HTTP/1.1\r\nHost: t\r\n\r\nGET /C HTTP/1.1\r\nHost: t\r\n\r\n"
        f"GET /w/a.html HTTP/1.1\r\nHost: t\r\n\r\n")
    t.eq(2, text.count("HTTP/1."), "an administration page is the last thing on a connection")
    t.eq(True, closed, "which the server closes, since the page states no length")
