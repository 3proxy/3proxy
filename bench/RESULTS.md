# Benchmark results

3proxy against nginx, haproxy, envoy, squid, tinyproxy, dante and stunnel on two
machines, as an HTTP proxy, through CONNECT and SOCKSv5 tunnels, as a TCP
relay, ending or beginning TLS, and with 20000 connections open at once; and
the version ladder 0.9.9.2 / 1.0.2 / devel / experimental against them all.
The current figures are from 29-30 October 2026: the four 3proxy versions,
every proxy, the plain suite and the mix over a shaped link (the section
[The four 3proxy versions](#the-four-3proxy-versions-and-every-proxy-30-october-2026)
below); the sessions before them are at the end. How the benchmark works is
in [README.md](README.md); the measurements are in [data/](data/), and
`bench/report.py` turns them into the older tables.

## In short

Ranges are over the two machines, ARM and Intel; the tables give each.

* **The version ladder:** 0.9.9.2 collapses on small kept-alive requests as
  an HTTP proxy (1.5k req/s against 17.7k for 1.0.2 on Intel; fixed in
  1.0.2) and is otherwise level with 1.0.2. devel adds splice(): streams go
  from 18-25 to 30-63 Gbit/s. experimental (the current head) adds the
  buffer pool and loop relay work: +50-100% over devel on every request
  scenario, close-1k and all mixes, with half the memory (28-35 MB
  idle-scale against 130+ MB).
* **experimental against everyone:** best of all proxies as an HTTP proxy
  from 2000 clients (14.2k against nginx 8.7k on Intel), best through
  CONNECT and SOCKS on both machines, best 3proxy everywhere in the mix -
  9.2k against nginx 7.4k req/s on Intel plain, 5.4-6.0k shaped - and the
  only proxy with no failed exchange anywhere. nginx and haproxy still lead
  the small-request scenarios (44-50k against 34.9k on ka-1k, 15.4k against
  7.0k on close-1k, Intel).
* **dante** manages 40-65% of experimental through SOCKS with the only
  nonzero errors of the set, and cannot stand 20000 connections at all: on
  8 GB machines its per-connection processes exhaust memory, and it is only
  measurable with a smaller pool (2.5k req/s at 2000, 2.13k at 10000, ARM
  shaped, against 2.58k/2.43k for experimental).
* **Memory with few connections:** experimental needs 4-35 MB, envoy 16-31,
  nginx and haproxy 28-44.

## Setup

| | M4 | Skylake |
|---|---|---|
| host | Apple M4 Pro laptop, UTM (Apple Virtualization) | OpenStack virtual machine, KVM |
| virtual machine | 8 CPUs, 8 GB | 8 CPUs (Intel Xeon, Skylake, 2.0 GHz), 8 GB |
| system | Ubuntu 24.04, Linux 6.8, aarch64 | AlmaLinux 10, Linux 6.12, x86_64 |
| nginx | 1.28.3 | 1.26.3 |
| haproxy | 3.2.25 | 3.0.5 |
| squid | 7.7 | 6.10 |
| tinyproxy | 1.11.2 (built from source) | 1.11.2 |
| dante | 1.4.4 | 1.4.4 |
| wrk, iperf3 | 4.2.0, 3.20 | 4.2.0, 3.17.1 |
| proxychains-ng | 4.17 | 4.17 |
| envoy | 1.34.1 (BoringSSL) | 1.34.1 (BoringSSL) |
| stunnel, OpenSSL | 5.72, 3.0.13 | 5.72, 3.5.8 |

### How the client, the proxy and the origin were kept apart

* **Network:** each runs in a network namespace of its own, linked by veth
  pairs (client 10.0.1.2 - 10.0.1.1 proxy 10.0.2.1 - 10.0.2.2 origin), so they
  share no loopback and every proxy is crossed by the same path. MTU 1500.
* **CPU:** each runs in a cgroup pinned to CPUs of its own: the client
  (wrk, iperf3) on CPUs 0-3, the proxy on CPU 4, the origin (nginx serving
  files from tmpfs, iperf3 -s) on CPUs 5-7. RPS steers what each veth receives
  to the receiving side's CPUs, so the kernel's network work for a role is
  done on its own CPUs too. The proxy has the fewest CPUs on purpose: it has to
  be what runs out first.
* **Every proxy gets the same CPU:** one nginx worker, one haproxy thread, and
  3proxy's thread per connection, squid's, tinyproxy's and dante's processes
  all confined to the same CPU.
* **CPU time** is the busy time of the role's CPUs from `/proc/stat`, its own
  processes plus the interrupts and softirqs handled there (a quarter of a
  proxy's time here), so a proxy is also charged for the kernel's work on its
  connections - which is where splice() moves the copying.
* **Which side set the pace** is recorded for every run: the role whose CPUs,
  or one thread of it, were busy at least 90% of the time.
* **Repetitions:** three runs of 10 seconds per proxy and scenario, the order
  of the proxies rotated between repetitions; the tables give medians.
* **Tunnels:** wrk and iperf3 run under proxychains-ng, which opens a CONNECT
  or SOCKSv5 tunnel for each connection they make, blocking in `connect()`
  until the proxy has answered. This costs the client CPU time per connection,
  so wrk gets more threads there (16 against 4).

### Proxies

| column | configuration |
|---|---|
| 0.9.9.2 | the 0.9 LTS line's last release, no splice(), 64 KB buffers, a thread per connection |
| 1.0.2 | release 1.0.2, no splice(), 64 KB buffers |
| devel | devel as of 30 October (c3702866): 16 KB buffers, the thread pool, splice() in its automatic mode |
| experimental (bp) | the experimental head (5de7ae2): devel plus the event loops relaying by default (loopmode cb) and the pool of 16 KB buffers |
| nginx | `proxy_pass` to an upstream with `keepalive 1024`, `stream` for the TCP relay, `reuseport` |
| nginx-halfclose | the same with `proxy_half_close on` on the relays (not nginx's default) |
| haproxy | `mode http` with `http-reuse always`, `mode tcp` for the TCP relay |
| haproxy splice-auto | `option splice-auto`: splices a direction once reads fill the buffer three times in a row |
| envoy | one worker (`--concurrency 1`), `http_connection_manager` with the router filter as an HTTP proxy for the origin, `tcp_proxy` for the TCP relay |
| squid | no cache, no logs, `via off` |
| tinyproxy | `DisableViaHeader Yes`, critical messages only |
| dante | no authentication, one `sockd` process tree (`-N 1`) |
| stunnel | TLS scenarios only |

nginx and envoy have no splice() support. None of nginx, haproxy and envoy has
CONNECT or SOCKS, so they are measured as HTTP proxies and TCP relays only; squid and tinyproxy
only as HTTP proxies and through CONNECT, dante only through SOCKS. 3proxy
versions are built with the Makefile they shipped with (`-O3 -flto`). Logging
is off everywhere.

### Scenarios

| scenario | load |
|---|---|
| stream1, stream1-down | one iperf3 stream, upload and download |
| stream16 | 16 iperf3 streams, upload |
| ka-1k, http-ka-1k | 1 KB answers over 64 kept-alive connections |
| http-ka-1m | 1 MB answers over 16 kept-alive connections |
| ka-50k-2000, http-ka-50k-2000 | 2000 kept-alive connections, 50 KB answers |
| http-ka-2k-50k-2000 | the same, each request a POST with a 2 KB body |
| close-1k, http-close-1k | 64 connections, a new one for every request |

`http-*` go through the HTTP proxy (absolute URIs). The CONNECT, SOCKS and
relay tables run the same loads through a CONNECT tunnel, a SOCKSv5 tunnel or
a TCP relay to the origin (3proxy `tcppm`, nginx `stream`, haproxy
`mode tcp`): the HTTP requests are then plain HTTP inside the tunnel.

## How to read the tables

* A table for each machine, ARM (the M4) and Intel (the Skylake host): the
  two are different machines in different conditions, and an average of them
  would mean nothing. Each cell is the median of three runs; TCP streams and
  1 MB answers in Gbit/s, the other HTTP scenarios in thousands of requests
  per second. "–" marks a proxy that does not serve the scenario.
* wrk runs a closed loop, each connection sending its next request once the
  answer is in, so a proxy answering fewer requests shows a longer median
  by that alone; what compares is the 99th percentile against the median,
  how evenly a proxy serves its connections, which matters most with 2000
  clients and in the mix. wrk leaves requests over 2 seconds out (they are
  counted as timeouts).
* CPU time per gigabyte or request and peak memory are in the tables of the
  section below. Every proxy ran at its CPU limit in the plain runs, so its
  CPU per unit of work is close to the inverse of its throughput; the shaped
  link runs, where the pace is set by netem, are where it separates proxies.

## The four 3proxy versions and every proxy (30 October 2026)

3proxy 0.9.9.2, 1.0.2, devel (c3702866) and experimental (5de7ae2, the
head) against nginx, nginx with `proxy_half_close on`, haproxy, haproxy
`splice-auto`, envoy, squid and tinyproxy: the whole plain suite (streams,
1 KB / 1 MB / 50 KB and 2 KB+50 KB requests, a new connection per request,
the 20000-connection mix) and the same mix over a shaped link of 20 Mbit/s,
5 ms delay and 0.5% loss. Three runs of 10 s per cell plain, 20 s shaped;
medians. The proxy's cgroup is capped at 6 GB (`--prx-mem-mb`). The data is
in [data/results-full7/](data/results-full7/).

Notes on the tables:

* **dante\*** numbers are from the rerun of 30 October, same conditions as
  the rest of the tables. dante cannot take part in a
  20000-connection mix on these 8 GB machines - its process per connection
  exhausts memory and the kernel kills the benchmark's origin - so the
  common tables have no dante mix cells; its mix behaviour, measured with
  smaller pools where it survives, is in
  [its own table](#dante-in-the-shaped-mix-by-pool-size-arm-earlier-runs).
* **nginx errors:** the plain `nginx` column runs its relays without
  `proxy_half_close`, nginx's default, and that is what its 518 (Intel) and
  213 (ARM) errors in mix-relay shaped are: exchanges cut short on a
  half-closed connection. nginx-halfclose, with it on, has none. nginx's
  own default configuration, in other words, is what fails - it is marked
  in the tables as nginx, and the fix is one directive.
* **Logging is off for every proxy**: 3proxy runs with no log or dlog
  directive at all, nginx with `access_log off`, envoy at `--log-level
  error`, squid with `access_log none`, tinyproxy at critical level; dante
  and stunnel write their error files. No proxy was doing per-request
  logging during any run.
* The Intel figures are from a clean rerun after a dante run had killed the
  host's sshd; the ARM shaped mix is client-bound (2.4-2.5k req/s for every
  proxy alike), so compare Intel for differences there.
* tinyproxy's 22-24k errors in the shaped mix are its connection-per-request
  behaviour under loss; they are real, not a measurement artifact.


### Intel — throughput (Gbit/s for streams, k req/s else) — bold = row winner

| scenario | 0.9.9.2 | 1.0.2 | devel | exp | nginx | nginx-hc | haproxy | hap-sa | envoy | squid | tiny | dante* |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stream1 | 18.1 | 18.4 | **32.1** | 30.4 | 9.3 | 9.4 | 9.3 | 31.2 | 17.7 | – | – | – |
| stream1-down | 19.5 | 19.6 | **31.1** | **31.3** | 9.7 | 9.7 | 9.5 | 29.1 | 17.9 | – | – | – |
| stream16 | 18.6 | 18.6 | **30.4** | 29.9 | 9.6 | 9.1 | 8.8 | 28.3 | 14.7 | – | – | – |
| http-ka-1k | 1.5 | 17.7 | 22.2 | **34.9** | **34.8** | 32.9 | **34.9** | 34.7 | 10.5 | 9.1 | 3.7 | – |
| http-ka-1m | 1.7 | 2.1 | **3.3** | **3.3** | 0.7 | 0.7 | 0.9 | 2.9 | 1.5 | 0.2 | 0.1 | – |
| http-ka-50k-2000 | 10.0 | 10.2 | 11.4 | **14.2** | 8.7 | 8.8 | 7.1 | 7.2 | 6.3 | 2.2 | 1.6 | – |
| http-ka-2k-50k-2000 | 9.2 | 9.2 | 10.2 | **12.4** | 8.3 | 8.4 | 7.2 | 7.3 | 5.9 | 1.8 | 1.5 | – |
| http-close-1k | 4.7 | 4.7 | 5.9 | 7.0 | 12.7 | 12.9 | 15.4 | **15.4** | 6.2 | 4.1 | 3.7 | – |
| relay-stream1-down | 18.4 | 19.7 | **32.1** | 31.2 | 9.3 | 9.7 | 9.4 | 31.5 | 18.6 | – | – | – |
| relay-stream16 | 18.7 | 18.1 | 30.2 | **31.0** | 9.4 | 9.6 | 9.1 | 29.6 | 14.5 | – | – | – |
| relay-ka-1k | 30.3 | 30.4 | 30.7 | 41.4 | 46.9 | **49.1** | 45.4 | 46.5 | 35.7 | – | – | – |
| relay-ka-50k-2000 | 14.7 | 14.6 | 18.0 | **21.3** | 12.4 | 12.0 | 9.6 | 19.5 | 12.5 | – | – | – |
| relay-ka-2k-50k-2000 | 13.5 | 13.5 | 15.7 | **20.0** | 11.9 | 12.2 | 9.1 | 18.0 | 11.9 | – | – | – |
| relay-close-1k | 5.3 | 5.0 | 6.1 | 7.0 | 7.9 | 8.2 | **8.4** | 8.1 | 5.0 | – | – | – |
| connect-stream1-down | 19.1 | 19.7 | **32.4** | 32.0 | – | – | – | – | – | 13.4 | 1.2 | – |
| connect-stream16 | 19.0 | 18.7 | 30.8 | **32.1** | – | – | – | – | – | 13.1 | 1.2 | – |
| connect-ka-1k | 30.8 | 30.0 | 30.1 | **39.9** | – | – | – | – | – | 37.7 | 29.3 | – |
| connect-ka-50k-2000 | 13.6 | 13.0 | 15.0 | **20.2** | – | – | – | – | – | 10.7 | 2.3 | – |
| connect-ka-2k-50k-2000 | 12.2 | 12.4 | 13.8 | **19.7** | – | – | – | – | – | 10.7 | 2.4 | – |
| connect-close-1k | 4.6 | 4.3 | 5.3 | **5.5** | – | – | – | – | – | 3.6 | 4.8 | – |
| socks-stream1-down | 19.2 | 20.3 | **32.4** | 31.4 | – | – | – | – | – | – | – | 8.3* |
| socks-stream16 | 19.2 | 18.8 | **30.5** | 29.8 | – | – | – | – | – | – | – | 16.1* |
| socks-ka-1k | 31.0 | 29.1 | 30.1 | **42.0** | – | – | – | – | – | – | – | 25.3* |
| socks-ka-50k-2000 | 13.7 | 13.1 | 14.7 | **21.5** | – | – | – | – | – | – | – | 11.7* |
| socks-ka-2k-50k-2000 | 12.1 | 12.0 | 14.3 | **19.4** | – | – | – | – | – | – | – | 11.3* |
| socks-close-1k | 4.5 | 4.4 | **5.0** | **5.1** | – | – | – | – | – | – | – | 1.6* |
| mix-http | 6.0 | 6.1 | 7.8 | **9.2** | 7.4 | 7.4 | 7.2 | 8.3 | 5.4 | 2.4 | 1.6 | – |
| mix-connect | 5.6 | 8.6 | 8.3 | **11.2** | – | – | – | – | – | 7.0 | 2.7 | – |
| mix-socks | 8.1 | 8.3 | 8.3 | **11.0** | – | – | – | – | – | – | – | – |
| mix-relay | 8.7 | 8.5 | 9.5 | **11.4** | 9.4 | 9.8 | 7.7 | 9.3 | 8.9 | – | – | – |
| mix-http [shaped] | 4.0 | 3.8 | 4.2 | 5.4 | 4.3 | 4.4 | 5.0 | **5.5** | 3.3 | 1.8 | 1.5 | – |
| mix-connect [shaped] | 4.6 | 4.6 | 4.8 | **5.8** | – | – | – | – | – | 4.4 | 2.5 | – |
| mix-socks [shaped] | 4.8 | 4.6 | 4.9 | **5.8** | – | – | – | – | – | – | – | – |
| mix-relay [shaped] | 4.7 | 4.7 | 4.9 | **6.0** | 5.5 | 5.8 | 5.4 | 5.8 | 5.1 | – | – | – |

### Intel — peak memory MB / errors (medians)

| scenario | 0.9.9.2 | 1.0.2 | devel | exp | nginx | nginx-hc | haproxy | hap-sa | envoy | squid | tiny | dante* |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stream1 | 7 / 0 | 9 / 0 | 12 / 0 | 13 / 0 | 32 / 0 | 33 / 0 | 31 / 0 | 44 / 0 | 32 / 0 | – | – | – |
| stream1-down | 8 / 0 | 7 / 0 | 13 / 0 | 10 / 0 | 33 / 0 | 33 / 0 | 31 / 0 | 43 / 0 | 32 / 0 | – | – | – |
| stream16 | 93 / 0 | 89 / 0 | 97 / 0 | 103 / 0 | 108 / 0 | 107 / 0 | 53 / 0 | 105 / 0 | 152 / 0 | – | – | – |
| http-ka-1k | 10 / 0 | 10 / 0 | 8 / 0 | 5 / 0 | 32 / 0 | 32 / 0 | 30 / 0 | 36 / 0 | 26 / 0 | 22 / 0 | 8 / 37007 | – |
| http-ka-1m | 13 / 0 | 16 / 0 | 17 / 0 | 17 / 0 | 45 / 0 | 44 / 0 | 45 / 0 | 51 / 0 | 45 / 0 | 43 / 0 | 9 / 1332 | – |
| http-ka-50k-2000 | 159 / 0 | 173 / 0 | 83 / 0 | 162 / 0 | 113 / 0 | 114 / 0 | 179 / 0 | 184 / 0 | 364 / 0 | 184 / 0 | 30 / 16222 | – |
| http-ka-2k-50k-2000 | 156 / 0 | 179 / 0 | 80 / 0 | 162 / 0 | 119 / 0 | 117 / 0 | 179 / 0 | 184 / 0 | 367 / 0 | 190 / 0 | 30 / 15445 | – |
| http-close-1k | 174 / 0 | 49 / 0 | 9 / 0 | 7 / 0 | 32 / 0 | 32 / 0 | 31 / 0 | 36 / 0 | 29 / 0 | 19 / 0 | 8 / 37575 | – |
| relay-stream1-down | 9 / 0 | 7 / 0 | 13 / 0 | 12 / 0 | 32 / 0 | 33 / 0 | 31 / 0 | 44 / 0 | 33 / 0 | – | – | – |
| relay-stream16 | 90 / 0 | 92 / 0 | 95 / 0 | 105 / 0 | 111 / 0 | 106 / 0 | 54 / 0 | 101 / 0 | 151 / 0 | – | – | – |
| relay-ka-1k | 6 / 0 | 6 / 0 | 7 / 0 | 5 / 0 | 31 / 0 | 32 / 0 | 29 / 0 | 35 / 0 | 23 / 0 | – | – | – |
| relay-ka-50k-2000 | 104 / 0 | 78 / 0 | 55 / 0 | 120 / 0 | 107 / 0 | 115 / 0 | 151 / 0 | 126 / 0 | 300 / 0 | – | – | – |
| relay-ka-2k-50k-2000 | 105 / 0 | 88 / 0 | 59 / 0 | 116 / 0 | 109 / 0 | 104 / 0 | 150 / 0 | 130 / 0 | 297 / 0 | – | – | – |
| relay-close-1k | 13 / 0 | 13 / 0 | 11 / 0 | 6 / 0 | 32 / 0 | 32 / 0 | 29 / 0 | 36 / 0 | 24 / 0 | – | – | – |
| connect-stream1-down | 8 / 0 | 10 / 0 | 12 / 0 | 13 / 0 | – | – | – | – | – | 21 / 0 | 2 / 0 | – |
| connect-stream16 | 78 / 0 | 74 / 0 | 96 / 0 | 101 / 0 | – | – | – | – | – | 65 / 0 | 71 / 0 | – |
| connect-ka-1k | 10 / 0 | 9 / 0 | 7 / 0 | 5 / 0 | – | – | – | – | – | 20 / 0 | 6 / 0 | – |
| connect-ka-50k-2000 | 388 / 2 | 255 / 0 | 220 / 2 | 120 / 1 | – | – | – | – | – | 244 / 0 | 130 / 0 | – |
| connect-ka-2k-50k-2000 | 391 / 1 | 261 / 1 | 224 / 0 | 115 / 1 | – | – | – | – | – | 251 / 0 | 136 / 0 | – |
| connect-close-1k | 11 / 26 | 12 / 14 | 8 / 22 | 5 / 27 | – | – | – | – | – | 21 / 2 | 7 / 18 | – |
| socks-stream1-down | 7 / 0 | 7 / 0 | 10 / 0 | 11 / 0 | – | – | – | – | – | – | – | 31 / 0* |
| socks-stream16 | 81 / 0 | 81 / 0 | 98 / 0 | 101 / 0 | – | – | – | – | – | – | – | 84 / 0* |
| socks-ka-1k | 6 / 0 | 6 / 0 | 7 / 0 | 5 / 0 | – | – | – | – | – | – | – | 98 / 0* |
| socks-ka-50k-2000 | 258 / 2 | 258 / 1 | 217 / 0 | 122 / 2 | – | – | – | – | – | – | – | 1453 / 2* |
| socks-ka-2k-50k-2000 | 263 / 2 | 266 / 2 | 220 / 1 | 121 / 1 | – | – | – | – | – | – | – | 1423 / 2* |
| socks-close-1k | 7 / 18 | 7 / 25 | 7 / 17 | 5 / 22 | – | – | – | – | – | – | – | 131 / 9* |
| mix-http | 2950 / 0 | 2366 / 0 | 1414 / 0 | 674 / 0 | 222 / 0 | 226 / 0 | 497 / 0 | 423 / 0 | 606 / 0 | 656 / 0 | 789 / 9749 | – |
| mix-connect | 3217 / 20497 | 2080 / 0 | 1501 / 0 | 452 / 0 | – | – | – | – | – | 1805 / 329 | 1075 / 124 | – |
| mix-socks | 2139 / 0 | 1979 / 0 | 1514 / 0 | 472 / 0 | – | – | – | – | – | – | – | – |
| mix-relay | 1785 / 0 | 1788 / 0 | 1324 / 0 | 429 / 0 | 645 / 455 | 662 / 0 | 480 / 0 | 342 / 0 | 713 / 0 | – | – | – |
| mix-http [shaped] | 2995 / 0 | 2288 / 0 | 1507 / 0 | 724 / 0 | 261 / 0 | 258 / 0 | 446 / 0 | 414 / 0 | 625 / 0 | 830 / 0 | 792 / 22353 | – |
| mix-connect [shaped] | 3320 / 2 | 2028 / 0 | 1488 / 0 | 473 / 0 | – | – | – | – | – | 1860 / 408 | 1090 / 312 | – |
| mix-socks [shaped] | 1958 / 0 | 1957 / 0 | 1505 / 0 | 493 / 0 | – | – | – | – | – | – | – | – |
| mix-relay [shaped] | 1917 / 0 | 1895 / 0 | 1411 / 0 | 472 / 0 | 688 / 518 | 706 / 0 | 458 / 0 | 418 / 0 | 719 / 0 | – | – | – |

### Intel — p75 / p90 / p99, ms (medians; streams have none)

| scenario | 0.9.9.2 | 1.0.2 | devel | exp | nginx | nginx-hc | haproxy | hap-sa | envoy | squid | tiny | dante* |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stream1 | – | – | – | – | – | – | – | – | – | – | – | – |
| stream1-down | – | – | – | – | – | – | – | – | – | – | – | – |
| stream16 | – | – | – | – | – | – | – | – | – | – | – | – |
| http-ka-1k | 41 / 41 / 42 | 4 / 5 / 7 | 3 / 4 / 5 | 17 / 28 / 36 | 2 / 2 / 3 | 2 / 2 / 3 | 2 / 2 / 3 | 2 / 2 / 3 | 6 / 7 / 10 | 7 / 9 / 11 | 19 / 22 / 27 | – |
| http-ka-1m | 25 / 41 / 45 | 9 / 12 / 17 | 6 / 7 / 10 | 6 / 8 / 11 | 24 / 27 / 32 | 24 / 26 / 31 | 21 / 23 / 27 | 6 / 7 / 8 | 12 / 13 / 15 | 69 / 74 / 84 | 126 / 136 / 160 | – |
| http-ka-50k-2000 | 59 / 67 / 115 | 63 / 70 / 116 | 52 / 62 / 120 | 157 / 163 / 1010 | 144 / 158 / 187 | 136 / 147 / 166 | 287 / 307 / 686 | 282 / 294 / 637 | 321 / 349 / 512 | 516 / 579 / 642 | 681 / 869 / 1710 | – |
| http-ka-2k-50k-2000 | 67 / 79 / 139 | 77 / 88 / 126 | 58 / 66 / 113 | 163 / 196 / 893 | 147 / 153 / 167 | 138 / 145 / 164 | 279 / 297 / 697 | 283 / 295 / 641 | 347 / 384 / 539 | 539 / 586 / 596 | 730 / 811 / 1690 | – |
| http-close-1k | 16 / 19 / 23 | 15 / 19 / 24 | 12 / 14 / 20 | 11 / 14 / 21 | 5 / 6 / 7 | 5 / 6 / 7 | 4 / 5 / 6 | 4 / 5 / 6 | 11 / 12 / 16 | 16 / 18 / 23 | 19 / 21 / 27 | – |
| relay-stream1-down | – | – | – | – | – | – | – | – | – | – | – | – |
| relay-stream16 | – | – | – | – | – | – | – | – | – | – | – | – |
| relay-ka-1k | 2 / 3 / 4 | 2 / 3 / 4 | 2 / 3 / 4 | 16 / 28 / 36 | 1 / 2 / 2 | 1 / 2 / 2 | 1 / 2 / 2 | 1 / 2 / 2 | 2 / 2 / 3 | – | – | – |
| relay-ka-50k-2000 | 37 / 45 / 68 | 33 / 38 / 56 | 25 / 30 / 50 | 97 / 126 / 826 | 77 / 78 / 93 | 84 / 89 / 95 | 220 / 233 / 1040 | 95 / 106 / 769 | 167 / 192 / 368 | – | – | – |
| relay-ka-2k-50k-2000 | 41 / 47 / 75 | 33 / 39 / 62 | 30 / 35 / 51 | 98 / 138 / 865 | 83 / 92 / 106 | 79 / 85 / 95 | 226 / 260 / 1140 | 106 / 115 / 715 | 174 / 192 / 383 | – | – | – |
| relay-close-1k | 13 / 16 / 20 | 15 / 17 / 21 | 11 / 13 / 19 | 11 / 14 / 20 | 8 / 9 / 11 | 8 / 9 / 11 | 8 / 9 / 11 | 8 / 9 / 11 | 13 / 14 / 17 | – | – | – |
| connect-stream1-down | – | – | – | – | – | – | – | – | – | – | – | – |
| connect-stream16 | – | – | – | – | – | – | – | – | – | – | – | – |
| connect-ka-1k | 2 / 3 / 4 | 2 / 3 / 4 | 2 / 3 / 4 | 16 / 28 / 36 | – | – | – | – | – | 2 / 2 / 2 | 2 / 3 / 4 | – |
| connect-ka-50k-2000 | 138 / 154 / 228 | 140 / 159 / 231 | 111 / 130 / 205 | 96 / 104 / 141 | – | – | – | – | – | 179 / 191 / 218 | 618 / 715 / 1090 | – |
| connect-ka-2k-50k-2000 | 148 / 169 / 228 | 142 / 159 / 225 | 121 / 149 / 190 | 97 / 102 / 142 | – | – | – | – | – | 177 / 183 / 195 | 614 / 718 / 1340 | – |
| connect-close-1k | 7 / 10 / 13 | 8 / 11 / 14 | 6 / 9 / 12 | 5 / 8 / 11 | – | – | – | – | – | 12 / 13 / 17 | 7 / 10 / 12 | – |
| socks-stream1-down | – | – | – | – | – | – | – | – | – | – | – |– |
| socks-stream16 | – | – | – | – | – | – | – | – | – | – | – |– |
| socks-ka-1k | 2 / 3 / 3 | 2 / 3 / 4 | 2 / 3 / 4 | 16 / 28 / 36 | – | – | – | – | – | – | – | 3 / 5 / 6* |
| socks-ka-50k-2000 | 132 / 149 / 230 | 140 / 160 / 236 | 114 / 141 / 210 | 94 / 98 / 136 | – | – | – | – | – | – | – | 308 / 316 / 331* |
| socks-ka-2k-50k-2000 | 147 / 174 / 283 | 143 / 162 / 211 | 122 / 137 / 188 | 97 / 105 / 143 | – | – | – | – | – | – | – | 311 / 317 / 328* |
| socks-close-1k | 7 / 10 / 14 | 8 / 11 / 14 | 7 / 9 / 12 | 6 / 9 / 13 | – | – | – | – | – | – | – | 23 / 29 / 39* |
| mix-http | 11 / 49 / 5505 | 12 / 90 / 5505 | 7 / 14 / 4194 | 229 / 344 / 1769 | 164 / 254 / 4194 | 139 / 229 / 3932 | 229 / 557 / 2753 | 311 / 557 / 1442 | 377 / 426 / 508 | 86 / 1376 / 7340 | 1901 / 3670 / 5767 | – |
| mix-connect | 90 / 213 / 3408 | 18 / 221 / 3277 | 11 / 238 / 3539 | 139 / 254 / 1901 | – | – | – | – | – | 131 / 188 / 4063 | 188 / 1901 / 5505 | – |
| mix-socks | 47 / 238 / 3408 | 33 / 238 / 3408 | 16 / 262 / 3539 | 147 / 262 / 1966 | – | – | – | – | – | – | – | – |
| mix-relay | 9 / 27 / 3408 | 8 / 18 / 3539 | 4 / 11 / 3277 | 22 / 205 / 2228 | 6 / 12 / 3146 | 5 / 12 / 3015 | 188 / 590 / 2621 | 111 / 246 / 2490 | 229 / 254 / 344 | – | – | – |
| mix-http [shaped] | 98 / 819 / 6554 | 115 / 852 / 7340 | 188 / 885 / 6291 | 377 / 623 / 3539 | 262 / 442 / 6291 | 262 / 393 / 6291 | 344 / 819 / 3801 | 459 / 852 / 2032 | 623 / 721 / 950 | 754 / 1704 / 8389 | 1769 / 3277 / 6291 | – |
| mix-connect [shaped] | 123 / 459 / 5767 | 102 / 524 / 5767 | 90 / 475 / 5243 | 279 / 557 / 3408 | – | – | – | – | – | 188 / 295 / 5767 | 123 / 1507 / 11534 | – |
| mix-socks [shaped] | 119 / 410 / 5243 | 123 / 393 / 5767 | 127 / 524 / 5243 | 279 / 524 / 3408 | – | – | – | – | – | – | – | – |
| mix-relay [shaped] | 102 / 492 / 5505 | 115 / 492 / 5767 | 86 / 508 / 5243 | 262 / 524 / 3277 | 156 / 311 / 4456 | 139 / 262 / 4194 | 328 / 623 / 2621 | 393 / 590 / 1245 | 410 / 492 / 721 | – | – | – |

### ARM (M4) — throughput (Gbit/s for streams, k req/s else) — bold = row winner

| scenario | 0.9.9.2 | 1.0.2 | devel | exp | nginx | nginx-hc | haproxy | hap-sa | envoy | squid | tiny | dante* |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stream1 | 24.2 | 25.2 | **62.7** | 62.0 | 18.7 | 19.3 | 9.0 | 27.0 | 34.8 | – | – | – |
| stream1-down | 24.5 | 25.0 | **61.1** | 59.9 | 19.7 | 20.0 | 8.9 | 26.3 | 33.7 | – | – | – |
| stream16 | 23.8 | 24.3 | **55.6** | 48.2 | 18.8 | 18.7 | 9.6 | 27.4 | 20.0 | – | – | – |
| http-ka-1k | 1.5 | 15.5 | 16.6 | 35.6 | 44.2 | 44.9 | **50.0** | **50.0** | 25.0 | 22.2 | 4.5 | – |
| http-ka-1m | 2.3 | 3.1 | 5.5 | **5.5** | 1.7 | 1.6 | 0.7 | 2.2 | 3.0 | 0.4 | 0.1 | – |
| http-ka-50k-2000 | 10.1 | 10.1 | 10.3 | **16.5** | 14.4 | 14.4 | 10.3 | 10.2 | 11.0 | 4.3 | 1.9 | – |
| http-ka-2k-50k-2000 | 8.9 | 9.3 | 9.3 | **14.1** | 13.3 | 13.1 | 9.7 | 9.7 | 11.2 | 3.2 | 1.9 | – |
| http-close-1k | 4.6 | 4.8 | 5.7 | 9.4 | 14.1 | 14.0 | **16.6** | **16.5** | 15.5 | 7.4 | 4.6 | – |
| relay-stream1-down | 24.2 | 24.3 | **64.3** | 61.3 | 19.5 | 19.5 | 9.2 | 27.4 | 33.8 | – | – | – |
| relay-stream16 | 24.2 | 23.8 | **55.7** | 48.5 | 18.8 | 18.6 | 8.8 | 28.0 | 19.9 | – | – | – |
| relay-ka-1k | 21.0 | 20.7 | 20.8 | 37.5 | **52.4** | **52.2** | 51.8 | 50.1 | 38.0 | – | – | – |
| relay-ka-50k-2000 | 12.6 | 12.4 | 12.7 | 23.0 | 18.1 | 18.0 | 14.2 | **25.2** | 14.7 | – | – | – |
| relay-ka-2k-50k-2000 | 11.5 | 11.5 | 11.7 | 21.4 | 16.3 | 16.4 | 13.2 | **23.5** | 14.2 | – | – | – |
| relay-close-1k | 5.3 | 5.3 | 6.2 | **10.2** | 8.8 | 8.8 | **10.2** | **10.2** | 9.3 | – | – | – |
| connect-stream1-down | 24.4 | 25.5 | **63.6** | 59.6 | – | – | – | – | – | 15.3 | 1.5 | – |
| connect-stream16 | 24.1 | 24.1 | **55.0** | 48.1 | – | – | – | – | – | 20.0 | 1.5 | – |
| connect-ka-1k | 20.5 | 20.2 | 20.2 | 35.1 | – | – | – | – | – | **42.2** | 17.4 | – |
| connect-ka-50k-2000 | 11.7 | 11.7 | 11.8 | **22.9** | – | – | – | – | – | 16.1 | 2.6 | – |
| connect-ka-2k-50k-2000 | 10.8 | 10.7 | 10.9 | **21.4** | – | – | – | – | – | 15.2 | 2.5 | – |
| connect-close-1k | 4.1 | 4.1 | 4.7 | **6.0** | – | – | – | – | – | 5.4 | 4.3 | – |
| socks-stream1-down | 24.6 | 25.0 | 61.0 | **69.3** | – | – | – | – | – | – | – | 11.3* |
| socks-stream16 | 24.1 | 24.2 | **55.8** | 47.2 | – | – | – | – | – | – | – | 15.5* |
| socks-ka-1k | 20.6 | 20.5 | 20.2 | **35.4** | – | – | – | – | – | – | – | 28.2* |
| socks-ka-50k-2000 | 11.8 | 11.8 | 12.0 | **23.0** | – | – | – | – | – | – | – | 14.3* |
| socks-ka-2k-50k-2000 | 10.9 | 10.8 | 11.0 | **21.6** | – | – | – | – | – | – | – | 14.2* |
| socks-close-1k | 3.9 | 3.9 | 4.4 | **5.7** | – | – | – | – | – | – | – | 3.6* |
| mix-http | 4.9 | 4.7 | 5.6 | 8.6 | 9.2 | 9.2 | 7.5 | **9.3** | 7.2 | 3.0 | 1.8 | – |
| mix-connect | 5.7 | 6.2 | 6.0 | **9.8** | – | – | – | – | – | 7.9 | 2.4 | – |
| mix-socks | 6.2 | 6.3 | 6.1 | **9.8** | – | – | – | – | – | – | – | – |
| mix-relay | 6.6 | 6.5 | 6.3 | **9.8** | 8.8 | 8.9 | 7.5 | 8.9 | 7.9 | – | – | – |
| mix-http [shaped] | 2.3 | 2.3 | 2.3 | 2.4 | 2.5 | **2.5** | 2.5 | 2.5 | **2.5** | 2.5 | 1.6 | – |
| mix-connect [shaped] | 2.4 | 2.4 | 2.4 | **2.5** | – | – | – | – | – | 2.5 | 2.1 | – |
| mix-socks [shaped] | 2.4 | 2.4 | 2.4 | **2.5** | – | – | – | – | – | – | – | – |
| mix-relay [shaped] | 2.4 | 2.4 | 2.4 | 2.5 | **2.5** | **2.5** | 2.5 | **2.5** | 2.5 | – | – | – |

### ARM (M4) — peak memory MB / errors (medians)

| scenario | 0.9.9.2 | 1.0.2 | devel | exp | nginx | nginx-hc | haproxy | hap-sa | envoy | squid | tiny | dante* |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stream1 | 18 / 0 | 18 / 0 | 23 / 0 | 35 / 0 | 33 / 0 | 33 / 0 | 34 / 0 | 41 / 0 | 22 / 0 | – | – | – |
| stream1-down | 20 / 0 | 20 / 0 | 22 / 0 | 34 / 0 | 37 / 0 | 36 / 0 | 34 / 0 | 43 / 0 | 24 / 0 | – | – | – |
| stream16 | 107 / 0 | 126 / 0 | 126 / 0 | 111 / 0 | 60 / 0 | 58 / 0 | 46 / 0 | 134 / 0 | 184 / 0 | – | – | – |
| http-ka-1k | 131 / 0 | 131 / 0 | 134 / 0 | 28 / 0 | 34 / 0 | 34 / 0 | 35 / 0 | 41 / 0 | 19 / 0 | 26 / 0 | 135 / 44575 | – |
| http-ka-1m | 55 / 0 | 58 / 0 | 58 / 0 | 43 / 0 | 47 / 0 | 45 / 0 | 38 / 0 | 47 / 0 | 39 / 0 | 36 / 0 | 41 / 1475 | – |
| http-ka-50k-2000 | 241 / 0 | 231 / 0 | 229 / 0 | 185 / 0 | 77 / 0 | 73 / 0 | 159 / 0 | 165 / 0 | 255 / 0 | 158 / 0 | 158 / 19051 | – |
| http-ka-2k-50k-2000 | 254 / 0 | 240 / 0 | 232 / 0 | 184 / 0 | 72 / 0 | 76 / 0 | 156 / 0 | 166 / 0 | 325 / 0 | 175 / 0 | 175 / 18947 | – |
| http-close-1k | 197 / 0 | 161 / 0 | 136 / 0 | 31 / 0 | 33 / 0 | 34 / 0 | 35 / 0 | 41 / 0 | 20 / 0 | 25 / 0 | 133 / 45992 | – |
| relay-stream1-down | 20 / 0 | 19 / 0 | 23 / 0 | 35 / 0 | 35 / 0 | 34 / 0 | 34 / 0 | 43 / 0 | 24 / 0 | – | – | – |
| relay-stream16 | 95 / 0 | 101 / 0 | 103 / 0 | 125 / 0 | 63 / 0 | 57 / 0 | 39 / 0 | 100 / 0 | 127 / 0 | – | – | – |
| relay-ka-1k | 130 / 0 | 130 / 0 | 16 / 0 | 28 / 0 | 33 / 0 | 35 / 0 | 34 / 0 | 40 / 0 | 17 / 0 | – | – | – |
| relay-ka-50k-2000 | 197 / 0 | 197 / 0 | 101 / 0 | 143 / 0 | 114 / 0 | 114 / 0 | 165 / 0 | 142 / 0 | 242 / 0 | – | – | – |
| relay-ka-2k-50k-2000 | 199 / 0 | 198 / 0 | 112 / 0 | 143 / 0 | 110 / 0 | 107 / 0 | 165 / 0 | 140 / 0 | 225 / 0 | – | – | – |
| relay-close-1k | 146 / 0 | 149 / 0 | 18 / 0 | 30 / 0 | 35 / 0 | 35 / 0 | 34 / 0 | 40 / 0 | 19 / 0 | – | – | – |
| connect-stream1-down | 19 / 0 | 20 / 0 | 25 / 0 | 34 / 0 | – | – | – | – | – | 23 / 0 | 23 / 0 | – |
| connect-stream16 | 133 / 0 | 116 / 0 | 132 / 0 | 108 / 0 | – | – | – | – | – | 122 / 0 | 122 / 0 | – |
| connect-ka-1k | 131 / 0 | 133 / 0 | 132 / 0 | 29 / 0 | – | – | – | – | – | 32 / 0 | 133 / 0 | – |
| connect-ka-50k-2000 | 434 / 0 | 341 / 1 | 340 / 0 | 147 / 0 | – | – | – | – | – | 368 / 0 | 368 / 0 | – |
| connect-ka-2k-50k-2000 | 436 / 0 | 344 / 0 | 343 / 0 | 140 / 0 | – | – | – | – | – | 375 / 0 | 375 / 0 | – |
| connect-close-1k | 132 / 5 | 132 / 1 | 134 / 6 | 30 / 4 | – | – | – | – | – | 32 / 0 | 129 / 1 | – |
| socks-stream1-down | 20 / 0 | 19 / 0 | 21 / 0 | 35 / 0 | – | – | – | – | – | – | – | 13 / 0* |
| socks-stream16 | 109 / 0 | 123 / 0 | 94 / 0 | 81 / 0 | – | – | – | – | – | – | – | 116 / 0* |
| socks-ka-1k | 131 / 0 | 131 / 0 | 18 / 0 | 28 / 0 | – | – | – | – | – | – | – | 40 / 0* |
| socks-ka-50k-2000 | 333 / 0 | 333 / 1 | 225 / 0 | 143 / 1 | – | – | – | – | – | – | – | 785 / 0* |
| socks-ka-2k-50k-2000 | 335 / 2 | 336 / 0 | 228 / 0 | 145 / 1 | – | – | – | – | – | – | – | 787 / 0* |
| socks-close-1k | 132 / 5 | 134 / 4 | 18 / 5 | 29 / 5 | – | – | – | – | – | – | – | 59 / 2* |
| mix-http | 3031 / 0 | 2457 / 0 | 1676 / 0 | 721 / 0 | 192 / 0 | 188 / 0 | 311 / 0 | 306 / 0 | 635 / 0 | 873 / 0 | 976 / 11770 | – |
| mix-connect | 3323 / 0 | 2603 / 0 | 1626 / 0 | 494 / 0 | – | – | – | – | – | 2850 / 382 | 1135 / 108 | – |
| mix-socks | 2137 / 0 | 2167 / 0 | 1523 / 0 | 526 / 0 | – | – | – | – | – | – | – | – |
| mix-relay | 1932 / 0 | 1952 / 0 | 1333 / 0 | 480 / 0 | 794 / 422 | 794 / 0 | 474 / 0 | 358 / 0 | 644 / 0 | – | – | – |
| mix-http [shaped] | 3348 / 0 | 2602 / 0 | 1871 / 0 | 1079 / 0 | 657 / 0 | 660 / 0 | 504 / 0 | 479 / 0 | 775 / 144 | 846 / 0 | 968 / 24582 | – |
| mix-connect [shaped] | 3423 / 1 | 2613 / 0 | 1872 / 0 | 696 / 0 | – | – | – | – | – | 3007 / 224 | 1137 / 471 | – |
| mix-socks [shaped] | 2156 / 0 | 2154 / 0 | 1777 / 0 | 716 / 0 | – | – | – | – | – | – | – | – |
| mix-relay [shaped] | 2054 / 1 | 2052 / 0 | 1678 / 0 | 688 / 0 | 1090 / 213 | 1093 / 0 | 530 / 0 | 529 / 0 | 831 / 0 | – | – | – |

### ARM (M4) — p75 / p90 / p99, ms (medians; streams have none)

| scenario | 0.9.9.2 | 1.0.2 | devel | exp | nginx | nginx-hc | haproxy | hap-sa | envoy | squid | tiny | dante* |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stream1 | – | – | – | – | – | – | – | – | – | – | – | – |
| stream1-down | – | – | – | – | – | – | – | – | – | – | – | – |
| stream16 | – | – | – | – | – | – | – | – | – | – | – | – |
| http-ka-1k | 44 / 46 / 53 | 5 / 6 / 10 | 5 / 6 / 10 | 3 / 4 / 8 | 2 / 2 / 2 | 1 / 2 / 2 | 1 / 2 / 2 | 1 / 2 / 2 | 3 / 3 / 4 | 3 / 3 / 4 | 16 / 19 / 23 | – |
| http-ka-1m | 27 / 36 / 43 | 6 / 8 / 12 | 4 / 5 / 8 | 4 / 5 / 8 | 11 / 14 / 19 | 11 / 14 / 20 | 25 / 26 / 28 | 8 / 8 / 9 | 6 / 6 / 7 | 47 / 48 / 52 | 118 / 123 / 136 | – |
| http-ka-50k-2000 | 77 / 101 / 474 | 78 / 101 / 256 | 75 / 99 / 257 | 120 / 124 / 561 | 58 / 64 / 70 | 55 / 61 / 69 | 191 / 197 / 705 | 196 / 200 / 682 | 184 / 193 / 324 | 280 / 295 / 507 | 572 / 617 / 1430 | – |
| http-ka-2k-50k-2000 | 96 / 124 / 299 | 90 / 114 / 243 | 85 / 110 / 591 | 144 / 146 / 538 | 53 / 58 / 66 | 57 / 63 / 68 | 207 / 214 / 761 | 205 / 214 / 760 | 182 / 201 / 305 | 312 / 340 / 359 | 568 / 603 / 1400 | – |
| http-close-1k | 15 / 18 / 22 | 15 / 17 / 21 | 12 / 15 / 19 | 8 / 10 / 14 | 5 / 5 / 5 | 5 / 5 / 5 | 4 / 4 / 5 | 4 / 4 / 5 | 4 / 5 / 6 | 9 / 9 / 10 | 16 / 18 / 22 | – |
| relay-stream1-down | – | – | – | – | – | – | – | – | – | – | – | – |
| relay-stream16 | – | – | – | – | – | – | – | – | – | – | – | – |
| relay-ka-1k | 4 / 5 / 8 | 4 / 5 / 8 | 4 / 5 / 8 | 2 / 4 / 6 | 1 / 1 / 2 | 1 / 1 / 2 | 1 / 1 / 2 | 1 / 2 / 2 | 2 / 2 / 3 | – | – | – |
| relay-ka-50k-2000 | 64 / 86 / 531 | 67 / 88 / 400 | 63 / 85 / 274 | 95 / 95 / 353 | 58 / 66 / 73 | 56 / 64 / 147 | 140 / 145 / 948 | 81 / 85 / 1290 | 139 / 148 / 268 | – | – | – |
| relay-ka-2k-50k-2000 | 74 / 97 / 404 | 71 / 91 / 224 | 70 / 91 / 432 | 96 / 99 / 366 | 54 / 60 / 66 | 54 / 61 / 66 | 151 / 154 / 905 | 88 / 92 / 1280 | 143 / 150 / 261 | – | – | – |
| relay-close-1k | 14 / 16 / 19 | 14 / 16 / 20 | 11 / 13 / 18 | 8 / 10 / 14 | 7 / 8 / 9 | 7 / 8 / 8 | 6 / 7 / 7 | 6 / 7 / 7 | 7 / 8 / 9 | – | – | – |
| connect-stream1-down | – | – | – | – | – | – | – | – | – | – | – | – |
| connect-stream16 | – | – | – | – | – | – | – | – | – | – | – | – |
| connect-ka-1k | 4 / 5 / 7 | 4 / 5 / 7 | 4 / 5 / 8 | 3 / 4 / 7 | – | – | – | – | – | 2 / 2 / 2 | 4 / 5 / 8 | – |
| connect-ka-50k-2000 | 186 / 234 / 358 | 184 / 232 / 347 | 186 / 234 / 352 | 95 / 95 / 98 | – | – | – | – | – | 123 / 127 / 130 | 761 / 879 / 1600 | – |
| connect-ka-2k-50k-2000 | 196 / 244 / 367 | 202 / 248 / 368 | 194 / 239 / 358 | 96 / 97 / 109 | – | – | – | – | – | 129 / 134 / 139 | 795 / 918 / 1670 | – |
| connect-close-1k | 9 / 12 / 14 | 10 / 12 / 14 | 8 / 11 / 13 | 6 / 8 / 11 | – | – | – | – | – | 8 / 9 / 10 | 10 / 12 / 15 | – |
| socks-stream1-down | – | – | – | – | – | – | – | – | – | – | – |– |
| socks-stream16 | – | – | – | – | – | – | – | – | – | – | – |– |
| socks-ka-1k | 4 / 5 / 7 | 4 / 5 / 7 | 4 / 5 / 8 | 3 / 4 / 7 | – | – | – | – | – | – | – | 4 / 4 / 4* |
| socks-ka-50k-2000 | 187 / 234 / 351 | 188 / 233 / 347 | 184 / 231 / 351 | 95 / 95 / 98 | – | – | – | – | – | – | – | 188 / 191 / 203* |
| socks-ka-2k-50k-2000 | 196 / 242 / 355 | 201 / 246 / 360 | 195 / 239 / 350 | 95 / 96 / 102 | – | – | – | – | – | – | – | 188 / 191 / 200* |
| socks-close-1k | 10 / 12 / 15 | 10 / 12 / 15 | 9 / 11 / 14 | 7 / 9 / 12 | – | – | – | – | – | – | – | 11 / 15 / 19* |
| mix-http | 19 / 51 / 6554 | 16 / 35 / 7078 | 16 / 30 / 5767 | 188 / 295 / 2097 | 6 / 11 / 3277 | 6 / 11 / 3277 | 262 / 295 / 2228 | 213 / 221 / 1835 | 279 / 311 / 377 | 459 / 1049 / 4981 | 1016 / 3146 / 5243 | – |
| mix-connect | 180 / 344 / 5243 | 164 / 344 / 4719 | 172 / 344 / 4719 | 197 / 262 / 1245 | – | – | – | – | – | 90 / 156 / 3408 | 655 / 819 / 4456 | – |
| mix-socks | 147 / 311 / 4456 | 147 / 311 / 4719 | 188 / 344 / 4719 | 197 / 262 / 1114 | – | – | – | – | – | – | – | – |
| mix-relay | 14 / 29 / 4719 | 15 / 27 / 4719 | 16 / 32 / 4719 | 139 / 221 / 1966 | 6 / 13 / 3408 | 6 / 12 / 3277 | 94 / 655 / 3539 | 66 / 254 / 2884 | 254 / 279 / 377 | – | – | – |
| mix-http [shaped] | 852 / 1966 / 6291 | 819 / 1966 / 6554 | 819 / 1835 / 6291 | 786 / 1835 / 6291 | 786 / 1769 / 6029 | 754 / 1769 / 6029 | 754 / 1769 / 6029 | 754 / 1769 / 6029 | 754 / 1704 / 6029 | 524 / 1376 / 8389 | 1638 / 3015 / 6029 | – |
| mix-connect [shaped] | 786 / 1835 / 6554 | 754 / 1835 / 6554 | 786 / 1835 / 6291 | 754 / 1769 / 6291 | – | – | – | – | – | 754 / 1769 / 6291 | 442 / 786 / 9437 | – |
| mix-socks [shaped] | 786 / 1835 / 6291 | 754 / 1835 / 6291 | 754 / 1769 / 6291 | 754 / 1769 / 6291 | – | – | – | – | – | – | – | – |
| mix-relay [shaped] | 786 / 1835 / 6291 | 786 / 1835 / 6291 | 754 / 1835 / 6291 | 786 / 1769 / 6029 | 786 / 1769 / 6029 | 786 / 1769 / 6029 | 786 / 1769 / 6029 | 786 / 1769 / 6029 | 754 / 1769 / 6291 | – | – | – |

### dante in the shaped mix, by pool size (ARM, earlier runs)

Dante keeps a process per connection, so its memory grows with the pool;
20000 connections cannot be measured on an 8 GB machine at all.

| pool | dante: rate, p99, cpu s/GB, peak | experimental: the same |
|---|---|---|
| 2000 | 2.50k, 0.48 s, 8.8, 796 MB | 2.58k, 0.72 s, 6.1, 110 MB |
| 10000 | 2.13k, 6.29 s, 10.1, 3710 MB | 2.43k, 3.80 s, 7.8, 403 MB |
| 20000 | OOM: the origin is killed (ARM), or 0 req/s with 5 GB (Intel) | 6.0k req/s on Intel plain |

## Caveats

* Every scenario but the mix ones is synthetic: the links between the
  client, the proxy and the origin have no bandwidth limit and no delay, and
  one or a few kinds of request are repeated, so each connection goes as fast
  as the CPUs allow. The mix scenarios, many connections with web-like
  exchanges, and above all over the shaped link, are the closest to a proxy
  giving clients access to the Internet.
* Both machines are virtual: their CPUs cannot be pinned to physical cores, so
  absolute figures move between sessions; compare within a table.
* The roles have CPUs of their own but share the memory, and memory bandwidth,
  which copying proxies use most, cannot be split. On the Skylake host it may
  well be the limit; a CPU waiting for memory counts as busy, so this shows as
  less work per busy second rather than as idle time.
* wrk measures in a closed loop: a slower proxy is offered less load, so
  latencies compare only between runs of similar throughput, and requests over
  2 seconds are left out of its latency figures.
* The tool versions differ between the machines (haproxy 3.2 against 3.0,
  nginx 1.28 against 1.26, squid 7.7 against 6.10); both envoy builds are
  the same 1.34.1 binary.
* In the tunnel scenarios proxychains-ng's work is done in the client: with a
  new tunnel for every request it sets the pace on the M4.
* The shaped ARM mix is client-bound: every proxy lands at 2.4-2.5k req/s,
  so the shaped tables' differences are meaningful on Intel only; ARM still
  separates the proxies by errors and CPU.
