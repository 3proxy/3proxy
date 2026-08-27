"""Authentication and access rules in front of the HTTP server."""


def run(t):
    srv = t.free_port()
    openport = t.free_port()
    t.start("httpsrv_auth", f"""
        log
        http echo * /echo
        auth strong
        users alice:CL:secret bob:CL:hunter2
        allow alice
        httpsrv -p{srv}

        flush
        http echo * /echo
        auth iponly
        allow *
        httpsrv -p{openport}
    """, ports=[srv, openport])

    url = f"http://127.0.0.1:{srv}"

    r = t.http(url + "/echo")
    t.eq(401, r.status, "no credentials gives 401")
    t.ne(None, r.header("WWW-Authenticate"),
         "the 401 carries a WWW-Authenticate header")

    t.eq(200, t.http(url + "/echo", auth=("alice", "secret")).status,
         "valid credentials pass")
    t.eq(401, t.http(url + "/echo", auth=("alice", "wrong")).status,
         "a wrong password gives 401")
    t.eq(401, t.http(url + "/echo", auth=("nobody", "secret")).status,
         "an unknown user gives 401")

    # bob authenticates, but no rule admits him
    t.eq(403, t.http(url + "/echo", auth=("bob", "hunter2")).status,
         "authenticated but not allowed gives 403")

    # authentication comes before dispatch, so an unmatched URL still needs it
    t.eq(401, t.http(url + "/nosuchpath").status,
         "authentication precedes the rule lookup")

    # the second service kept its own iponly authentication
    t.eq(200, t.http(f"http://127.0.0.1:{openport}/echo").status,
         "the open service needs no credentials")

    t.contains(t.http(url + "/echo", auth=("alice", "secret")), "path=/echo",
               "an authenticated request is dispatched")
