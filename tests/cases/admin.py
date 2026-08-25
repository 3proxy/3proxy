"""The admin interface, now a set of handlers on the HTTP server."""


def run(t):
    adm = t.free_port()
    lim = t.free_port()
    t.start("admin", f"""
        log
        auth iponly
        allow *
        countin 1 D 100 * * *
        countin 2 D 200 * * *
        admin -p{adm}

        flush
        auth iponly
        allow *
        admin -p{lim} -s1
    """, ports=[adm, lim])

    url = f"http://127.0.0.1:{adm}"

    # --- the predefined pages -----------------------------------------
    t.eq(200, t.http(url + "/").status, "the main page")
    t.eq(200, t.http(url + "/C").status, "the counters page")
    t.eq(200, t.http(url + "/R").status, "the reload page")
    t.eq(200, t.http(url + "/S").status, "the services page")

    counters = t.http(url + "/C")
    t.contains(counters, "countin", "the counters page names the counter type")
    t.contains(counters, "<tr>", "the counters page renders a table")
    t.contains(t.http(url + "/R"), "Reload", "the reload page confirms the request")
    t.contains(t.http(url + "/S"), "<", "the services page returns markup")

    # --- the menu no longer offers the removed config editor -----------
    main = t.http(url + "/")
    t.contains(main, "HREF='/C'", "the menu links to the counters")
    t.contains(main, "HREF='/R'", "the menu links to reload")
    t.contains(main, "HREF='/S'", "the menu links to the services")
    t.not_contains(main, "HREF='/F'",
                   "the menu no longer links to the config editor")

    # /F and /U are gone, so they fall through to the catch-all rule
    t.eq(200, t.http(url + "/F").status, "the removed /F falls through")
    t.eq(200, t.http(url + "/U").status, "the removed /U falls through")
    t.contains(t.http(url + "/F"), "configuration", "/F yields the main page")

    # --- counter control through the glob ------------------------------
    # /C<action><number> is routed by the /C* rule, the action arriving as
    # the glob
    t.http(url + "/CD0")
    t.contains(t.http(url + "/C"), ">NO<", "a counter can be disabled")
    t.http(url + "/CS0")
    t.contains(t.http(url + "/C"), ">YES<", "a counter can be enabled again")

    # --- limited mode ---------------------------------------------------
    limited = f"http://127.0.0.1:{lim}"
    t.eq(200, t.http(limited + "/").status, "limited mode serves the main page")
    t.eq(200, t.http(limited + "/C").status, "limited mode serves the counters")
    t.not_contains(t.http(limited + "/R"), "Reload scheduled",
                   "limited mode refuses a reload")

    # --- the writable command is gone ------------------------------------
    output = t.run_config("writable", f"""
        log
        writable
        admin -p{t.free_port()}
    """)
    t.contains(output, "Unknown command", "the writable command is rejected")
