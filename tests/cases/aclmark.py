"""The mark command: a rule's connections carry a mark.

mark <number> extends the rule above it like nolog and weight; the
connection it lets through sends with the mark on its sockets towards
the destination. Where the system has no mark (Linux SO_MARK, FreeBSD
SO_USER_COOKIE) the command changes nothing, and what is checked here
is the flow: a rule with a mark serves as one without.
"""


def run(t):
    if not t.skip_unless("httpsrv"):
        return

    origin = t.free_port()
    t.start("mark_origin", f"""
        log
        auth iponly
        allow *
        http data * /data**
        httpsrv -p{origin}
    """, ports=[origin])

    # a rule with a mark serves the connections it lets through
    prox = t.free_port()
    t.start("mark_rule", f"""
        log
        auth iponly
        allow * * 192.168.0.0/16
        allow * * 127.0.0.0/8
        mark 20
        proxy -p{prox}
    """, ports=[prox])

    t.eq(200, t.http(f"http://127.0.0.1:{origin}/data",
                     proxy=f"127.0.0.1:{prox}").status,
         "a request matched by a rule with a mark is served")

    # a mark of the rule above only: a rule of its own is refused
    out = t.run_config("mark_alone", "log\nmark 20\nnot_a_command\n")
    t.contains(out, "'mark' failed",
               "a mark with no rule above it is refused")
    t.not_contains(out, "'not_a_command'",
                   "and the file stops at the refused line")

    # and so is a mark that is not a number
    out = t.run_config("mark_word", "log\nallow *\nmark twenty\nnot_a_command\n")
    t.contains(out, "Wrong mark",
               "a mark that is not a number is refused")
