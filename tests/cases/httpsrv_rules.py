"""Rule dispatch: host and URL patterns, and per-service rule sets."""


def run(t):
    srv = t.free_port()
    srv2 = t.free_port()
    t.start("httpsrv_rules", f"""
        log
        auth iponly
        allow *
        http * /exact echo
        http * /pre* echo
        http * *.suffix echo
        http * *mid* echo
        http host.example.com /byhost echo
        http *.wild.example.com /bywild echo
        http * /only-first echo
        httpsrv -p{srv}

        flush
        auth iponly
        allow *
        http * /only-second echo
        httpsrv -p{srv2}
    """, ports=[srv, srv2])

    url = f"http://127.0.0.1:{srv}"

    # --- URL patterns -------------------------------------------------
    t.eq(200, t.http(url + "/exact").status, "an exact URL matches")
    t.eq(404, t.http(url + "/exactly").status,
         "an exact URL does not match a longer path")
    t.eq(200, t.http(url + "/pre").status, "a prefix matches the bare prefix")
    t.eq(200, t.http(url + "/pretty/deep").status,
         "a prefix matches a longer path")
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
