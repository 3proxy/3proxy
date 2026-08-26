"""PCRE filtering: matching, rewriting, options and rule scope.

Request rewriting only reaches the wire through an HTTP parent. On a direct
connection the request has already been parsed and converted to origin form
by the time the filter runs, so the rewrite shows up in the log and nowhere
else; that path is left alone here rather than pinned down as correct.
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
        http * /echo* echo
        http * /secret* echo
        http * /data data
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

    # --- rewriting the reply ------------------------------------------------
    p = proxy_with("rewrite_srv",
                   'pcre_rewrite srvheader dunno "text/plain" "text/rewritten"',
                   'pcre_rewrite srvdata dunno "peer.addr" "PEER.ADDR"')
    r = t.http(url + "/echo", proxy=p)
    t.eq(200, r.status, "a rewritten reply still arrives")
    t.eq("text/rewritten", r.header("Content-Type"), "a reply header can be rewritten")
    t.contains(r, "PEER.ADDR", "reply data can be rewritten")
    t.not_contains(r, "peer.addr", "the original text is gone")

    # --- rewriting the request, which needs an HTTP parent -------------------
    parent = t.free_port()
    t.start("pcre_parent", f"""
        log
        flush
        auth iponly
        allow *
        proxy -p{parent}
    """, ports=[parent])
    p = proxy_with("rewrite_req", 'pcre_rewrite request dunno "/echo/old" "/echo/new"',
                   f"parent 1000 http 127.0.0.1 {parent}")
    r = t.http(url + "/echo/old", proxy=p)
    t.eq(200, r.status, "a rewritten request still arrives")
    t.contains(r, "path=/echo/new", "the origin sees the rewritten request")
