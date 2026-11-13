"""Authentication and access rules in front of the HTTP server."""

import base64


def run(t):
    if not t.skip_unless("httpsrv"):
        return
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

    # --- credentials do not outlive the request that carried them ------
    # A kept connection answers a second request without credentials as
    # unauthenticated: a reverse proxy reuses its upstreams between
    # clients, so one client's login must not open another's way in.
    creds = base64.b64encode(b"alice:secret").decode()
    text, closed = t.raw_session(srv,
        f"GET /echo HTTP/1.1\r\nHost: t\r\n"
        f"Authorization: Basic {creds}\r\n\r\n"
        f"GET /echo HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
    parts = text.split("HTTP/1.")
    t.eq(3, len(parts), "the kept connection answers both requests")
    t.eq(True, parts[1].startswith("1 200"),
         "the request with credentials is allowed")
    t.eq(True, parts[2].startswith("0 401"),
         "the request after it, without credentials, is refused")
