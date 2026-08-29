"""PCRE filtering: matching, rewriting, options and rule scope.

A request rewrite is applied to the buffer the server is sent, so it works
on a direct connection as well as through a parent. The destination was
chosen, and the access rules applied to it, before the filter ran, so a
rewrite that moves the request to another host or changes the method is
ignored rather than acted on.
"""


def _has_pcre(t):
    """Whether this build accepts the pcre commands at all.

    The last line is nonsense on purpose: it makes 3proxy report and exit
    instead of waiting, and what it says about the line above is the answer.
    """
    out = t.run_config("pcre_probe",
                       'log\npcre request deny "x"\nnot_a_command\n')
    return "'pcre'" not in out


def run(t):
    if not _has_pcre(t):
        t.skip("PCRE (this build has no PCRE support)")
        return

    origin = t.free_port()
    t.start("pcre_origin", f"""
        log
        auth iponly
        allow *
        http echo * /echo**
        http echo * /secret**
        http data * /data
        httpsrv -p{origin}
    """, ports=[origin])

    url = f"http://127.0.0.1:{origin}"

    def proxy_with(name, *rules):
        port = t.free_port()
        t.start(name, "\n".join([
            "log", "flush", "auth iponly", "allow *", *rules, f"proxy -p{port}"]),
            ports=[port])
        return f"127.0.0.1:{port}"

    # --- matching and denial ---------------------------------------------
    p = proxy_with("deny", 'pcre request deny "/secret"')
    t.eq(200, t.http(url + "/echo", proxy=p).status, "an unmatched request passes")
    t.ne(200, t.http(url + "/secret/page", proxy=p).status, "a matched request is denied")

    # the rules are ordered, and the first decision wins
    p = proxy_with("allow_first", 'pcre request allow "/echo"', 'pcre request deny "/"')
    t.eq(200, t.http(url + "/echo", proxy=p).status, "allow short-circuits a later deny")
    p = proxy_with("deny_first", 'pcre request deny "/"', 'pcre request allow "/echo"')
    t.ne(200, t.http(url + "/echo", proxy=p).status, "deny short-circuits a later allow")

    # --- what the pattern is matched against ------------------------------
    p = proxy_with("cliheader", 'pcre cliheader deny "BadBot"')
    t.eq(200, t.http(url + "/echo", proxy=p).status, "a header rule ignores other requests")
    t.ne(200, t.http(url + "/echo", proxy=p, headers={"User-Agent": "BadBot/1.0"}).status,
         "a client header can be matched")

    # --- options ------------------------------------------------------------
    p = proxy_with("caseless", "pcre_options PCRE2_CASELESS",
                   'pcre request deny "/SECRET"')
    t.ne(200, t.http(url + "/secret/page", proxy=p).status,
         "PCRE2_CASELESS makes the match case-insensitive")
    p = proxy_with("cased", 'pcre request deny "/SECRET"')
    t.eq(200, t.http(url + "/secret/page", proxy=p).status,
         "without it the match is case-sensitive")

    # --- the access rule a pcre rule carries --------------------------------
    p = proxy_with("ace_here", f'pcre request deny "/echo" * * * {origin}')
    t.ne(200, t.http(url + "/echo", proxy=p).status,
         "a rule applies where its access rule matches")
    p = proxy_with("ace_elsewhere", 'pcre request deny "/echo" * * * 1')
    t.eq(200, t.http(url + "/echo", proxy=p).status,
         "and not where it does not")

    # pcre_extend appends another access rule to the one just defined
    p = proxy_with("extend", 'pcre request deny "/echo" * * * 1',
                   f"pcre_extend * * * {origin}")
    t.ne(200, t.http(url + "/echo", proxy=p).status,
         "pcre_extend widens the rule to another destination")
    p = proxy_with("extend_other", 'pcre request deny "/echo" * * * 1',
                   "pcre_extend * * * 2")
    t.eq(200, t.http(url + "/echo", proxy=p).status,
         "an extension that matches nothing changes nothing")

    # --- a regular expression where a host name is expected -----------------
    # The same prefix works in an access rule and in an http rule, so one
    # kind of expression is understood wherever a name can be written.
    named = t.free_port()
    t.start("pcre_named", f"""
        log
        flush
        nserver 127.0.0.1
        nscache 1024
        nsrecord host1.test 127.0.0.1
        nsrecord other.test 127.0.0.1
        auth iponly
        allow * * "pcre:^host[0-9]+\\.test$"
        proxy -p{named}
    """, ports=[named])

    t.eq(200, t.http(f"http://host1.test:{origin}/echo", proxy=f"127.0.0.1:{named}").status,
         "a destination matching the expression is allowed")
    t.ne(200, t.http(f"http://other.test:{origin}/echo", proxy=f"127.0.0.1:{named}").status,
         "one that does not match is refused")

    # --- rewriting the reply ------------------------------------------------
    p = proxy_with("rewrite_srv",
                   'pcre_rewrite srvheader dunno "text/plain" "text/rewritten"',
                   'pcre_rewrite srvdata dunno "peer.addr" "PEER.ADDR"')
    r = t.http(url + "/echo", proxy=p)
    t.eq(200, r.status, "a rewritten reply still arrives")
    t.eq("text/rewritten", r.header("Content-Type"), "a reply header can be rewritten")
    t.contains(r, "PEER.ADDR", "reply data can be rewritten")
    t.not_contains(r, "peer.addr", "the original text is gone")

    # --- rewriting the request ------------------------------------------------
    p = proxy_with("rewrite_req", 'pcre_rewrite request dunno "/echo/old" "/echo/new"')
    r = t.http(url + "/echo/old", proxy=p)
    t.eq(200, r.status, "a rewritten request still arrives")
    t.contains(r, "path=/echo/new", "the origin sees the rewritten path")

    # the replacement may be longer or shorter than what it replaces
    p = proxy_with("rewrite_long", 'pcre_rewrite request dunno "/echo/x" "/echo/deeper/still"')
    t.contains(t.http(url + "/echo/x", proxy=p), "path=/echo/deeper/still",
               "a longer replacement is spliced in")
    p = proxy_with("rewrite_short", 'pcre_rewrite request dunno "/echo/aaaaaaaaaa" "/echo/b"')
    t.contains(t.http(url + "/echo/aaaaaaaaaa", proxy=p), "path=/echo/b",
               "a shorter replacement is spliced in")

    p = proxy_with("rewrite_query", 'pcre_rewrite request dunno "token=old" "token=new"')
    t.contains(t.http(url + "/echo?token=old", proxy=p), "query=token=new",
               "the query can be rewritten")

    p = proxy_with("rewrite_none", 'pcre_rewrite request dunno "/nothing" "/else"')
    t.contains(t.http(url + "/echo/keep", proxy=p), "path=/echo/keep",
               "a request that does not match is left alone")

    # what follows the request line has to survive the splice
    p = proxy_with("rewrite_post", 'pcre_rewrite request dunno "/echo/old" "/echo/new"')
    r = t.http(url + "/echo/old", proxy=p, method="POST", body="hello",
               headers={"Content-Type": "text/plain"})
    t.contains(r, "path=/echo/new", "a POST is rewritten too")
    t.contains(r, "content.length=5", "its body is still described correctly")

    conn = t.connection("127.0.0.1", origin, proxy=p)
    try:
        first = t.http(url + "/echo/old", proxy=p, conn=conn)
        second = t.http(url + "/echo/old", proxy=p, conn=conn)
        t.contains(first, "path=/echo/new", "the first of two on a connection is rewritten")
        t.contains(second, "path=/echo/new", "and so is the second")
    finally:
        conn.close()

    # --- rewrites that would change where the request goes --------------------
    elsewhere = t.free_port()
    t.start("pcre_elsewhere", f"""
        log
        flush
        auth iponly
        allow *
        http echo * /echo**
        httpsrv -p{elsewhere}
    """, ports=[elsewhere])

    p = proxy_with("rewrite_host",
                   f'pcre_rewrite request dunno "127.0.0.1:{origin}" "127.0.0.1:{elsewhere}"')
    r = t.http(url + "/echo", proxy=p)
    t.eq(200, r.status, "a rewrite naming another host still answers")
    t.contains(r, f"host=127.0.0.1:{origin}",
               "but the request goes where the access rules allowed")

    p = proxy_with("rewrite_method", 'pcre_rewrite request dunno "^GET" "HEAD"')
    t.contains(t.http(url + "/echo", proxy=p), "method=GET",
               "a rewrite of the method is ignored")

    # --- and the same rewrite through an HTTP parent --------------------------
    parent = t.free_port()
    t.start("pcre_parent", f"""
        log
        flush
        auth iponly
        allow *
        proxy -p{parent}
    """, ports=[parent])
    p = proxy_with("rewrite_parent", 'pcre_rewrite request dunno "/echo/old" "/echo/new"',
                   f"parent 1000 http 127.0.0.1 {parent}")
    r = t.http(url + "/echo/old", proxy=p)
    t.eq(200, r.status, "a rewritten request through a parent arrives")
    t.contains(r, "path=/echo/new", "the origin sees the rewritten path through a parent")

    # --- a rewrite which grows the headers ----------------------------------
    # GHSA-h845-prxq-ww3q: a rewrite that doubles the client headers used to
    # leave a buffer holding exactly what it produced, and the Content-Length
    # the data filter regenerates was then written past the end of it.
    p = proxy_with("rewrite_grow",
                   'pcre_rewrite cliheader dunno "(?s).*" "$0$0"',
                   'pcre clidata dunno *')
    big = "".join("X-%d: %s\r\n" % (i, chr(65 + i) * 20000) for i in range(5))
    reply = t.raw_proxy_request(p, url + "/echo", extra=big, body="z")
    t.contains(reply, "200", "a doubled header block with a body is answered")
    t.contains(t.http(url + "/echo", proxy=p), "path=/echo",
               "and the proxy is still there afterwards")

    # A reference to a group the pattern does not have is dropped, and dropped
    # by both the pass which measures the result and the pass which writes it.
    p = proxy_with("rewrite_nogroup",
                   'pcre_rewrite cliheader dunno "(?s)Host:" "$9$9$9$9$9$9$9$9"')
    r = t.http(url + "/echo", proxy=p, headers={"X-Pad": "P" * 2000})
    t.eq(200, r.status, "a reference to a group which did not match is left out")
    t.contains(t.http(url + "/echo", proxy=p), "path=/echo",
               "and that proxy is still there too")

    # an optional group which took part on one request and not on the next
    p = proxy_with("rewrite_optgroup",
                   'pcre_rewrite cliheader dunno "X-Mark: (a)?(b)" "[$1][$2]"')
    t.eq(200, t.http(url + "/echo", proxy=p, headers={"X-Mark": "ab"}).status,
         "a group which matched is put in")
    t.eq(200, t.http(url + "/echo", proxy=p, headers={"X-Mark": "b"}).status,
         "and one which did not is left out")
