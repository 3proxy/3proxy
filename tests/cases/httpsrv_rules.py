"""Rule dispatch: host and URL patterns, and per-service rule sets."""


def run(t):
    srv = t.free_port()
    srv2 = t.free_port()
    t.start("httpsrv_rules", f"""
        log
        auth iponly
        allow *
        http echo * /exact
        http echo * /pre*
        http echo * /deep/**
        http echo * **.suffix
        http echo * **mid**
        http echo host.example.com /byhost
        http echo *.wild.example.com /bywild
        http echo * /only-first

        http rewrite_host *.old.example ** "$1.new.example"
        http rewrite_host "pcre:^legacy-(.*)$" ** "$1.new.example"
        http rewrite_host * /badhost** "not a host name"
        http echo one.new.example /**
        httpsrv -p{srv}

        flush
        auth iponly
        allow *
        http echo * /only-second
        httpsrv -p{srv2}
    """, ports=[srv, srv2])

    url = f"http://127.0.0.1:{srv}"

    # --- URL patterns -------------------------------------------------
    t.eq(200, t.http(url + "/exact").status, "an exact URL matches")
    t.eq(404, t.http(url + "/exactly").status,
         "an exact URL does not match a longer path")
    t.eq(200, t.http(url + "/pre").status, "a prefix matches the bare prefix")
    t.eq(200, t.http(url + "/pretty").status,
         "a prefix matches a longer name in the same path element")

    # a single star stays inside one element of the path, which is what keeps
    # a rule from reaching into directories it did not name
    t.eq(404, t.http(url + "/pretty/deep").status,
         "a prefix does not cross a slash")
    t.eq(200, t.http(url + "/deep/a/b/c").status,
         "a double star does cross one")
    t.eq(200, t.http(url + "/any.suffix").status, "a suffix matches")
    t.eq(404, t.http(url + "/any.suffixx").status,
         "a suffix is anchored at the end")
    t.eq(200, t.http(url + "/xxmidxx").status, "a substring matches")
    t.eq(404, t.http(url + "/nomatch").status, "an unmatched URL gives 404")

    # --- host patterns ------------------------------------------------
    def with_host(path, host):
        return t.http(url + path, headers={"Host": host})

    t.eq(200, with_host("/byhost", "host.example.com").status,
         "an exact host matches")
    t.eq(404, with_host("/byhost", "other.example.com").status,
         "another host does not match")
    t.eq(200, with_host("/bywild", "a.wild.example.com").status,
         "a wildcard host matches")
    t.eq(404, with_host("/bywild", "a.other.example.com").status,
         "a wildcard host rejects another domain")

    # the rules are ordered, and the first match wins
    t.contains(t.http(url + "/exact"), "path=/exact",
               "the first matching rule handles the request")

    # --- per-service rule sets ----------------------------------------
    # Rules accumulate until a service starts, which takes them; later rules
    # belong to the next service only.
    t.eq(200, t.http(f"http://127.0.0.1:{srv}/only-first").status,
         "the first service has its own rules")
    t.eq(404, t.http(f"http://127.0.0.1:{srv}/only-second").status,
         "the first service does not have the later rules")
    t.eq(200, t.http(f"http://127.0.0.1:{srv2}/only-second").status,
         "the second service has its own rules")
    t.eq(404, t.http(f"http://127.0.0.1:{srv2}/only-first").status,
         "the second service does not have the earlier rules")

    # --- a rule which changes the host --------------------------------
    # The stars of the host pattern are what $1 upwards stand for here, the
    # way the stars of the URL stand for themselves in a rewrite.
    r = t.http(url + "/anything", headers={"Host": "one.old.example"})
    t.eq(200, r.status, "a rewritten host reaches the rules after it")
    t.contains(r, "host=one.new.example", "and the request carries the new name")

    t.eq(200, t.http(url + "/anything", headers={"Host": "legacy-one"}).status,
         "a regular expression names the part to keep")

    t.eq(404, t.http(url + "/anything", headers={"Host": "other.example"}).status,
         "a host no rule rewrites is left as it was")

    t.eq(403, t.http(url + "/badhost", headers={"Host": "x"}).status,
         "a rule may not build something which is not a host name")
