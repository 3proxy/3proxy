"""The HTTP proxy, with the built-in server as the origin.

Access rules accumulate until "flush", so each service section here starts
from a clean list.
"""


def run(t):
    srv = t.free_port()
    other = t.free_port()
    prx = t.free_port()
    deny = t.free_port()
    auth = t.free_port()

    t.start("proxy_http", f"""
        log
        auth iponly
        allow *
        http * /echo* echo
        http * /data data
        httpsrv -p{srv}

        # a second origin, used as a destination the rules must keep out
        flush
        auth iponly
        allow *
        http * /echo* echo
        httpsrv -p{other}

        # an open proxy
        flush
        auth iponly
        allow *
        proxy -p{prx}

        # only the first origin is reachable
        flush
        auth iponly
        allow * * * {srv}
        proxy -p{deny}

        # credentials required
        flush
        auth strong
        users alice:CL:secret
        allow alice
        proxy -p{auth}
    """, ports=[srv, other, prx, deny, auth])

    origin = f"http://127.0.0.1:{srv}"
    second = f"http://127.0.0.1:{other}"
    open_proxy = f"127.0.0.1:{prx}"

    # --- plain proxying -------------------------------------------------
    r = t.http(origin + "/echo", proxy=open_proxy)
    t.eq(200, r.status, "a GET through the proxy")
    t.contains(r, "path=/echo", "the origin sees the proxied path")
    t.contains(r, "peer.addr=127.0.0.1", "the origin sees the proxy as the peer")

    t.eq(10000, t.http(origin + "/data?size=10000", proxy=open_proxy).length,
         "a sized body survives proxying")
    t.eq(10000,
         t.http(origin + "/data?size=10000&chunked=1", proxy=open_proxy).length,
         "a chunked body survives proxying")
    t.eq(503, t.http(origin + "/data?size=5&status=503", proxy=open_proxy).status,
         "the origin status is relayed")

    # --- POST and keep-alive ---------------------------------------------
    r = t.http(origin + "/echo", proxy=open_proxy, method="POST", body="x=1")
    t.contains(r, "method=POST", "POST is proxied")

    # two requests on one connection, which may carry different methods
    conn = t.connection("127.0.0.1", srv, proxy=open_proxy)
    try:
        first = t.http(origin + "/echo", proxy=open_proxy, method="POST",
                       body="x=1", conn=conn)
        second_reply = t.http(origin + "/echo", proxy=open_proxy, conn=conn)
        t.eq((200, 200), (first.status, second_reply.status),
             "two requests on one proxied connection")
    finally:
        conn.close()

    # --- CONNECT ----------------------------------------------------------
    t.eq(200, t.http(origin + "/echo", proxy=open_proxy, tunnel=True).status,
         "CONNECT tunnels to the origin")

    # --- access control ----------------------------------------------------
    denying = f"127.0.0.1:{deny}"
    t.eq(200, t.http(origin + "/echo", proxy=denying).status,
         "the permitted destination is reachable")
    t.ne(200, t.http(second + "/echo", proxy=denying).status,
         "a destination outside the rules is refused")
    t.ne(200, t.http(second + "/echo", proxy=denying, tunnel=True).status,
         "CONNECT to a destination outside the rules is refused")
    # the open proxy still reaches it, so the refusal came from the rules
    t.eq(200, t.http(second + "/echo", proxy=open_proxy).status,
         "the same destination is reachable through the open proxy")

    # --- proxy authentication -----------------------------------------------
    needs_auth = f"127.0.0.1:{auth}"
    t.eq(407, t.http(origin + "/echo", proxy=needs_auth).status,
         "the proxy demands credentials")
    t.eq(200, t.http(origin + "/echo", proxy=needs_auth,
                     proxy_auth=("alice", "secret")).status,
         "valid proxy credentials pass")
    t.eq(407, t.http(origin + "/echo", proxy=needs_auth,
                     proxy_auth=("alice", "wrong")).status,
         "wrong proxy credentials are refused")
