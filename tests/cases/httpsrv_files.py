"""The operations that serve a filesystem: file, cache, redir and rewrite.

A rule maps a request onto a path with a template, where $1 upwards stand for
what the stars or the groups of a regular expression matched.
"""

import os


def run(t):
    root = os.path.join(t.tmpdir, "web")
    os.makedirs(os.path.join(root, "picts", "set"), exist_ok=True)
    with open(os.path.join(root, "a.html"), "w") as fp:
        fp.write("<h1>hello</h1>")
    with open(os.path.join(root, "big.bin"), "wb") as fp:
        fp.write(b"x" * 300000)          # past a single send, and past the cache limit
    with open(os.path.join(root, "picts", "set", "dog.gif"), "wb") as fp:
        fp.write(b"GIF89a-pretend")

    with open(os.path.join(root, "b.webp"), "wb") as fp:
        fp.write(b"RIFF-pretend")

    port = t.free_port()
    t.start("httpsrv_files", f"""
        log
        auth iponly
        allow *
        http rewrite * /alias/** "/w/$1"
        http file  * /w/*.html "{root}/$1.html"
        http file  * /big       {root}/big.bin
        http cache * /c/*.html  "{root}/$1.html"
        http cache * "pcre:^/(.*)/pic/(.*)\\.(gif|jpeg)$" "{root}/picts/$1/$2.$3"
        http redir * /old/**    301 "https://example.org/$1"
        http redir * /moved     /w/a.html
        http file  * /rel/*.html "web/$1.html"
        http echo  * /echo

        http_content_type .webp image/webp
        http_content_type dat   application/x-mydata
        http file * /ct/*.webp  "{root}/$1.webp"
        http file * /named/*.html "{root}/$1.html" text/x-named
        http file * /star/*.html  "{root}/$1.html" *
        http cache * /ctc/*.webp  "{root}/$1.webp"

        http file  * /aged/*.html  "{root}/$1.html" * 3600
        http cache * /aged2/*.html "{root}/$1.html" * 60
        http file  * /extra/*.html "{root}/$1.html" * * "X-One: 1\\nX-Two: two words"
        http file  * /err/*.html   "{root}/$1.html" * * "X-Served: static" 404
        http reply * /ok**
        http reply * /nobody**  204
        http reply * /down**    503 "Retry-After: 30"
        http cache * /held/*.html "{root}/$1.html" * 30
        httpsrv -p{port}
    """, ports=[port])

    url = f"http://127.0.0.1:{port}"

    # --- file -------------------------------------------------------------
    r = t.http(url + "/w/a.html")
    t.eq(200, r.status, "a file is served")
    t.contains(r, "<h1>hello</h1>", "with its content")
    t.eq("text/html", r.header("Content-Type"), "and a type taken from the name")
    t.eq(str(len("<h1>hello</h1>")), r.header("Content-Length"), "and its length")

    t.eq(404, t.http(url + "/w/nosuch.html").status, "a missing file is not found")
    big = t.http(url + "/big")
    t.eq(300000, big.length, "a large file arrives whole")
    t.eq("300000", big.header("Content-Length"), "and is announced by its length")
    t.eq(None, big.header("Transfer-Encoding"),
         "a file is never sent chunked")
    t.eq("300000", t.http(url + "/big", method="HEAD").header("Content-Length"),
         "HEAD gives the length without the body")
    t.eq(200, t.http(url + "/w/a.html", method="HEAD").status, "HEAD is answered")
    t.eq(0, t.http(url + "/w/a.html", method="HEAD").length, "HEAD carries no body")

    # --- cache ------------------------------------------------------------
    first = t.http(url + "/c/a.html")
    second = t.http(url + "/c/a.html")
    t.eq(200, first.status, "a cached file is served")
    t.eq(first.text, second.text, "and the same on the next request")
    t.contains(second, "<h1>hello</h1>", "from memory this time")

    # a file changed on disk is noticed rather than served from before
    with open(os.path.join(root, "a.html"), "w") as fp:
        fp.write("<h1>changed</h1>")
    t.contains(t.http(url + "/c/a.html"), "changed",
               "a file replaced on disk is read again")

    # --- what the stars stand for -----------------------------------------
    r = t.http(url + "/set/pic/dog.gif")
    t.eq(200, r.status, "a regular expression maps a request onto a path")
    t.contains(r, "GIF89a", "and the file is served")
    t.eq("image/gif", r.header("Content-Type"), "with the type of that name")

    # --- redir ------------------------------------------------------------
    r = t.http(url + "/old/thing")
    t.eq(301, r.status, "a redirect uses the status it was given")
    t.eq("https://example.org/thing", r.header("Location"),
         "and a location built from the request")
    t.eq(302, t.http(url + "/moved").status, "without a status it is 302")

    # --- rewrite ----------------------------------------------------------
    r = t.http(url + "/alias/a.html")
    t.eq(200, r.status, "a rewritten request reaches the rule after it")
    t.contains(r, "changed", "and is served from the path it was rewritten to")

    # --- the type a reply carries -------------------------------------------
    # Worked out from the name, using what the configuration has registered
    # on top of what is built in, unless the rule says otherwise.
    t.eq("image/webp", t.http(url + "/ct/b.webp").header("Content-Type"),
         "a registered extension names the type")
    t.eq("image/webp", t.http(url + "/ctc/b.webp").header("Content-Type"),
         "and a cached file is answered the same way")
    t.eq("text/x-named", t.http(url + "/named/a.html").header("Content-Type"),
         "a rule may name the type itself")
    t.eq("text/html", t.http(url + "/star/a.html").header("Content-Type"),
         "and a star there leaves it to the name of the file")

    # --- what a rule adds to the answer ------------------------------------
    r = t.http(url + "/aged/a.html")
    t.eq("max-age=3600", r.header("Cache-Control"), "a rule may describe caching")
    t.eq("max-age=60", t.http(url + "/aged2/a.html").header("Cache-Control"),
         "a cached file is answered the same way")
    t.eq(None, t.http(url + "/w/a.html").header("Cache-Control"),
         "and a rule which says nothing sends nothing")

    r = t.http(url + "/extra/a.html")
    t.eq("1", r.header("X-One"), "a rule may add headers")
    t.eq("two words", r.header("X-Two"),
         "the second of them arrives whole, spaces and all")

    r = t.http(url + "/err/a.html")
    t.eq(404, r.status, "a rule may answer with the status it names")
    t.contains(r, "<h1>", "and the file is still the body")
    t.eq("static", r.header("X-Served"),
         "what the rule adds goes with the status the rule asked for")

    # a refusal the server decided on is its own answer
    r = t.http(url + "/err/nosuch.html")
    t.eq(404, r.status, "a missing file is still not found")
    t.eq(None, r.header("X-Served"), "and carries none of the rule's headers")
    t.eq(None, t.http(url + "/aged/nosuch.html").header("Cache-Control"),
         "nor what it said about caching")

    # --- reply --------------------------------------------------------------
    r = t.http(url + "/ok")
    t.eq(200, r.status, "reply answers with 200 by default")
    t.eq("0", r.header("Content-Length"), "with a length of zero")
    t.eq(0, r.length, "and no body")

    r = t.http(url + "/nobody")
    t.eq(204, r.status, "reply answers with the status it was given")
    t.eq(None, r.header("Content-Length"),
         "and a status carrying no body is sent without a length")

    r = t.http(url + "/down")
    t.eq(503, r.status, "reply serves a refusal the configuration decided on")
    t.eq("30", r.header("Retry-After"), "with the headers that go with it")

    # --- a client which has the file already --------------------------------
    r = t.http(url + "/w/a.html")
    stamp = r.header("Last-Modified")
    t.ne(None, stamp, "a file is answered with the time it was last changed")

    r = t.http(url + "/w/a.html", headers={"If-Modified-Since": stamp})
    t.eq(304, r.status, "and an unchanged file is answered 304")
    t.eq(0, r.length, "which carries no body")
    t.eq(None, r.header("Content-Length"), "and no length")
    t.eq(stamp, r.header("Last-Modified"), "but still says when the file changed")

    t.eq(200, t.http(url + "/w/a.html",
                     headers={"If-Modified-Since": "Sun, 06 Nov 1994 08:49:37 GMT"}).status,
         "an older date is answered with the file")
    t.eq(200, t.http(url + "/w/a.html",
                     headers={"If-Modified-Since": "not a date at all"}).status,
         "and a date which cannot be read is treated as none")
    t.eq(304, t.http(url + "/c/a.html", headers={"If-Modified-Since": stamp}).status,
         "a file answered from memory is conditional in the same way")
    t.eq(404, t.http(url + "/err/a.html", headers={"If-Modified-Since": stamp}).status,
         "a rule with a status of its own is not turned into a 304")

    # --- a rule which says how long its copy may be held --------------------
    t.contains(t.http(url + "/held/a.html"), "changed", "a held file is served")
    with open(os.path.join(root, "a.html"), "w") as fp:
        fp.write("<h1>replaced</h1>")
    t.not_contains(t.http(url + "/held/a.html"), "replaced",
                   "and within its max-age the disk is not looked at again")
    t.contains(t.http(url + "/c/a.html"), "replaced",
               "while a rule without one notices the change at once")

    # --- the paths a rule may not build ------------------------------------
    t.eq(403, t.http(url + "/rel/a.html").status,
         "a relative target is refused")
    t.ne(200, t.http(url + "/w/../etc/passwd").status,
         "a request climbing out of the tree is refused")
