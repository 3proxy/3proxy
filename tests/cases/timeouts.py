"""timeouts: a service keeps the timeouts given before it, so services can
have timeouts of their own."""

import socket
import time


def run(t):
    short = t.free_port()
    long = t.free_port()
    t.start("timeouts", f"""
        auth none
        timeouts 1 5 30 2
        proxy -p{short}
        timeouts 1 5 30 60
        proxy -p{long}
    """, ports=[short, long])

    def idle(port, wait):
        """Connects and sends nothing: how long until the proxy gives up on
        the request (STRING_LONG), or None if it still waits after wait."""
        sock = socket.create_connection(("127.0.0.1", port), 5)
        sock.settimeout(wait)
        start = time.time()
        try:
            sock.recv(100)
            return time.time() - start
        except socket.timeout:
            return None
        except OSError:
            return time.time() - start
        finally:
            sock.close()

    took = idle(short, 10)
    t.in_range(round(took) if took is not None else None, 1, 5,
               "a service started after timeouts with STRING_LONG 2 closes an "
               "idle connection in about 2 seconds")
    t.eq(None, idle(long, 4),
         "a service started after timeouts with STRING_LONG 60 still waits")
