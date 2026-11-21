"""A port in a rule may carry a service port after a slash.

The rules of the limiters are shared by all the services, so there has
been no way to limit the connections of one service alone. X/S — or
*/S for any destination — matches only requests that came through
the service listening on the port S: a deny so written closes one
service, a connlim so written caps one service, and neither touches
another service of the same configuration.
"""

import time


def run(t):
    if not t.skip_unless("httpsrv"):
        return

    origin = t.free_port()
    t.start("viaport_origin", f"""
        auth iponly
        allow *
        http data * /data**
        httpsrv -p{origin}
    """, ports=[origin])
    url = f"http://127.0.0.1:{origin}/data"

    # a deny written with a service port closes that service alone
    first, second = t.free_port(), t.free_port()
    t.start("viaport_deny", f"""
        log
        auth iponly
        deny * * * */{second}
        allow *
        proxy -p{first}
        proxy -p{second}
    """, ports=[first, second])

    t.eq(200, t.http(url, proxy=f"127.0.0.1:{first}").status,
         "the service the rule does not name is served")
    t.ne(200, t.http(url, proxy=f"127.0.0.1:{second}").status,
         "the service the rule names by its port is refused")

    # a connlim written with a service port caps that service alone
    third, fourth = t.free_port(), t.free_port()
    t.start("viaport_connlim", f"""
        log
        auth iponly
        connlim 1 0 * * * */{third}
        allow *
        proxy -p{third}
        proxy -p{fourth}
    """, ports=[third, fourth])

    def slow(result):
        # about two seconds: 400 KB in 8 KB blocks, 40 ms apart
        r = t.http(f"http://127.0.0.1:{origin}"
                   f"/data?size=400000&block=8192&delay=40",
                   proxy=f"127.0.0.1:{third}")
        result["status"] = r.status

    result = {}
    held = __import__("threading").Thread(target=slow, args=(result,))
    held.start()
    time.sleep(0.5)

    t.ne(200, t.http(url, proxy=f"127.0.0.1:{third}").status,
         "a second request of the service the rule names, while its first "
         "is still going, is refused")

    t.eq(200, t.http(url, proxy=f"127.0.0.1:{fourth}").status,
         "another service is not counted in that limit")
    held.join(60)
    t.eq(200, result.get("status", 0),
         "and the request the limit waited for finishes whole")

    # a slash with nothing after it, or a bare * in a list, is refused
    out = t.run_config("viaport_bad",
                       "log\nallow * * * 443/\nnot_a_command\n")
    t.contains(out, "Invalid port or port range",
               "a service port with no destination port is refused")
