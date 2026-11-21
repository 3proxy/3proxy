"""A pcre action with ,log: what the pattern matched is written to the log.

dunno,log decides nothing, so a request it matches goes on as if the rule
was not there, and every match is a record of its own, carrying what the
pattern matched of what the client sent. The options apply to it as to
any other pattern, so a header can be watched whatever its case, and by
the line, wherever in the headers it comes.
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
    if not t.skip_unless("httpsrv", "pcre"):
        return
    if not _has_pcre(t):
        t.skip("PCRE (this build has no PCRE support)")
        return

    origin = t.free_port()
    t.start("pcre_origin", f"""
        log
        auth iponly
        allow *
        http echo * /echo**
        httpsrv -p{origin}
    """, ports=[origin])

    url = f"http://127.0.0.1:{origin}"

    def proxy_with(name, *rules):
        port = t.free_port()
        server = t.start(name, "\n".join([
            'logformat "%H:%M:%S %T"',
            "log", "flush", "auth iponly", "allow *",
            *rules, f"proxy -p{port}"]),
            ports=[port])
        return f"127.0.0.1:{port}", server

    # --- dunno,log: decided nothing, watched something ---------------------
    p, s = proxy_with("dunno_log", 'pcre cliheader dunno,log "X-Log-Marker:.*"')
    t.eq(200, t.http(url + "/echo", proxy=p).status,
         "a request without the header is served")
    out = s.output()
    t.not_contains(out, "watchme-123",
                   "and nothing about it is logged but the connection")
    t.eq(200, t.http(url + "/echo", proxy=p,
                     headers={"X-Log-Marker": "watchme-123"}).status,
         "a request a dunno,log rule matches is served all the same")
    out = t.wait_output(s, "watchme-123")
    t.contains(out, "X-Log-Marker: watchme-123",
              "what the pattern matched is written to the log")

    # --- deny,log: refused, and the refusal leaves its trace ----------------
    p, s = proxy_with("deny_log", 'pcre cliheader deny,log "Forbidden-Marker:.*"')
    t.eq(200, t.http(url + "/echo", proxy=p).status,
         "a request without the header is served")
    t.ne(200, t.http(url + "/echo", proxy=p,
                     headers={"Forbidden-Marker": "closed"}).status,
         "a request a deny,log rule matches is denied")
    out = t.wait_output(s, "Forbidden-Marker: closed")
    t.contains(out, "Forbidden-Marker: closed",
               "what the pattern matched is written to the log")

    # --- the options apply: any case, any line of the headers ----------------
    p, s = proxy_with("options_log",
                      "pcre_options PCRE2_CASELESS PCRE2_MULTILINE",
                      'pcre cliheader dunno,log "^x-log-marker:.*$"')
    t.eq(200, t.http(url + "/echo", proxy=p,
                     headers={"X-Log-Marker": "cased-456"}).status,
         "a header matches in lower case, on whatever line it comes")
    out = t.wait_output(s, "cased-456")
    t.contains(out, "X-Log-Marker: cased-456",
               "and what it matched is written to the log")
