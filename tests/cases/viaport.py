"""A port in a rule may name the service the request came through.

The rules of the limiters are shared by all the services, so there has
been no way to limit the connections of one service alone. After an @ a
port in a rule names that service — by its port, by the address it
listens on, or by both: @1080, @10.0.0.1, @[::1]:1080 — and, with no
destination written, any destination. A deny so written closes one
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

    # a deny naming a service by its port closes that service alone
    first, second = t.free_port(), t.free_port()
    t.start("viaport_deny", f"""
        log
        auth iponly
        deny * * * @{second}
        allow *
        proxy -p{first}
        proxy -p{second}
    """, ports=[first, second])

    t.eq(200, t.http(url, proxy=f"127.0.0.1:{first}").status,
         "the service the rule does not name is served")
    t.ne(200, t.http(url, proxy=f"127.0.0.1:{second}").status,
         "the service the rule names by its port is refused")

    # a connlim naming a service by its port caps that service alone
    third, fourth = t.free_port(), t.free_port()
    t.start("viaport_connlim", f"""
        log
        auth iponly
        connlim 1 0 * * * @{third}
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

    # a service named by its address, and by its address and port
    if t.has_ipv6():
        fifth, sixth = t.free_port(), t.free_port()
        t.start("viaport_ip", f"""
            log
            auth iponly
            deny * * * @[::1]
            allow *
            proxy -p{fifth} -i127.0.0.1
            proxy -p{sixth} -i::1
        """, ports=[fifth, ("::1", sixth)])

        t.eq(200, t.http(url, proxy=f"127.0.0.1:{fifth}").status,
             "the service on another address is served")
        r = t.http(url, proxy=f"[::1]:{sixth}")
        t.ne(200, r.status if r else 0,
             "the service the rule names by its address is refused")

    # an @ with nothing after it is refused
    out = t.run_config("viaport_bad",
                       "log\nallow * * * 443@\nnot_a_command\n")
    t.contains(out, "Invalid port or port range",
               "a service with nothing after the @ is refused")
