"""The radius command: a server may be a name, an address, and carry a
port, with an IPv6 address in brackets.

The port was in the man page but not in the code before: a server with a
port was simply refused. A name is resolved when the configuration is
read, with the name servers in force or the system's.
"""


def run(t):
    def accepted(config):
        out = t.run_config("radius_cmd", config + "\nnot_a_command\n")
        return "'radius' failed" not in out, out

    ok, out = accepted("log\nradius s3cret 127.0.0.1:18120")
    if ok:
        t.ok("a server address with a port is accepted")
    else:
        t.fail("a server address with a port is accepted",
               "'radius' not refused", out)

    ok, out = accepted("log\nradius s3cret localhost")
    if ok:
        t.ok("a server name is accepted, resolved when the file is read")
    else:
        t.fail("a server name is accepted, resolved when the file is read",
               "'radius' not refused", out)

    if t.has_ipv6():
        ok, out = accepted("log\nradius s3cret [::1]:18120")
        if ok:
            t.ok("an IPv6 server address in brackets, with a port, is accepted")
        else:
            t.fail("an IPv6 server address in brackets, with a port, is accepted",
                   "'radius' not refused", out)

    out = t.run_config("radius_bad",
                       "log\nradius s3cret 999.999.999.999\nnot_a_command\n")
    t.contains(out, "'radius' failed",
               "an address that is none is refused")
    t.not_contains(out, "'not_a_command'",
                   "and the file stops at the refused line")
