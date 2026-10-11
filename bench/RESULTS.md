# Benchmark results

3proxy 0.9.4, 1.0.1 and devel against nginx and haproxy, measured on two
machines, 11 October 2026; then devel's splice() by direction and with grace
delay. How the benchmark works is in
[README.md](README.md); the measurements are in [data/](data/), and
`bench/report.py` turns them into the tables below.

## In short

* **Bulk TCP, no splice:** devel and 1.0.1 move 19-22 Gbit/s per CPU core,
  1.5 to 2.2 times nginx and haproxy and 2.4 to 3.6 times 0.9.4, at 0.36-0.43
  CPU seconds per gigabyte against 0.59-0.87 for nginx and haproxy.
* **Bulk TCP and large HTTP answers with splice():** 3proxy with splice moves
  1.3 to 2.1 times what it does without, at 40-55% less CPU per gigabyte. On
  the Skylake host it is level with haproxy splicing every connection with TCP
  streams and 11% behind it with 1 MB HTTP answers; on the M4 it is ahead (37.8
  against 22.1 Gbit/s with 16 streams, 35.3 against 28.0 with 1 MB HTTP
  answers). haproxy's own heuristic (`splice-auto`) does not engage for 1 MB
  HTTP answers on the M4 (haproxy 2.8) and stays at its copying speed.
* **Small requests:** nginx and haproxy answer 2 to 3 times more 1 KB requests
  per core over kept-alive connections, and 3 times more when every request
  opens a new connection: 3proxy runs a thread per connection. splice() makes
  small requests slower (13.4-14.9k against 15.8-18.1k requests per second),
  which is why it stays off unless asked for.
* **2000 clients, 50 KB answers:** devel leads the copying proxies on the
  Skylake host (10.5k requests per second against nginx's 9.2k and haproxy's
  7.3k), nginx leads on the M4 (11.0k against devel's 10.4k); haproxy splicing
  every connection is fastest there (11.9k). splice() does not help 3proxy with
  answers this small.
* **1.0.1 against devel:** 1.0.1 manages 6k requests per second over kept-alive
  connections whatever the CPU, held by a 10 ms sleep each time a request is
  answered; devel has it removed and also sets TCP_NODELAY by default.
* **Memory:** with few connections 3proxy needs the least (devel 8-17 MB
  against 30-54 MB for nginx and haproxy; 57 MB when every request opens a new
  connection on the Skylake host); with 2000 connections at once, a thread for
  each costs it 150-200 MB against nginx's 90-113 MB.

## Setup

| | M4 | Skylake |
|---|---|---|
| host | Apple M4 Pro laptop, UTM (Apple Virtualization) | OpenStack virtual machine, KVM |
| virtual machine | 8 CPUs, 8 GB | 8 CPUs (Intel Xeon, Skylake, 2.0 GHz), 8 GB |
| system | Ubuntu 24.04, Linux 6.8, aarch64 | AlmaLinux 10, Linux 6.12, x86_64 |
| nginx | 1.24.0 | 1.26.3 |
| haproxy | 2.8.16 | 3.0.5 |
| wrk, iperf3 | 4.1.0, 3.16 | 4.2.0, 3.17.1 |

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
  3proxy's thread per connection confined to the same CPU.
* **CPU time** is the busy time of the role's CPUs from `/proc/stat`, its own
  processes plus the interrupts and softirqs handled there (a quarter of a
  proxy's time here), so a proxy is also charged for the kernel's work on its
  connections - which is where splice() moves the copying.
* **Which side set the pace** is recorded for every run: the role whose CPUs,
  or one thread of it, were busy at least 90% of the time.
* **Repetitions:** three runs of 10 seconds per proxy and scenario, the order
  of the proxies rotated between repetitions; the tables give medians. The
  haproxy splice columns come from a second session an hour later, with plain
  haproxy run again to see how far the conditions moved: by 2.5% or less on
  the M4 and 7.5% or less on the Skylake host, except for one origin-bound
  case (-9.7%).

### Proxies

| column | configuration |
|---|---|
| 0.9.4 | 0.9.4, `-s0` (no splice) `-ocTCP_NODELAY -osTCP_NODELAY` |
| 1.0.1 | 1.0.1, `-ocTCP_NODELAY -osTCP_NODELAY` (built without splice) |
| devel | devel as of these tests, defaults (TCP_NODELAY is on by default) |
| nginx | `proxy_pass` to an upstream with `keepalive 1024`, `stream` for TCP, `reuseport` |
| haproxy | `mode http` with `http-reuse always`, `mode tcp` for TCP |
| 0.9.4 splice | 0.9.4, which splices by default, `-ocTCP_NODELAY -osTCP_NODELAY` |
| devel splice | devel with `-s`, which in this build spliced both directions always (`-s3` since the automatic mode came) |
| haproxy splice-auto | `option splice-auto`: splices a direction once reads fill the buffer three times in a row |
| haproxy splice | `option splice-request` and `option splice-response`: splices always |

nginx has no splice() support. 3proxy versions are built with the Makefile
they shipped with (`-O3 -flto` for 1.0.1 and devel, `-O2` for 0.9.4, which on
gcc 14 also needs `-fpermissive`). Logging is off everywhere.

### Scenarios

| scenario | load |
|---|---|
| stream1, stream1-down | one iperf3 stream through a TCP relay (3proxy `tcppm`), upload and download |
| stream16 | 16 iperf3 streams |
| http-ka-1k, http-ka-1m | 64 (1 KB) or 16 (1 MB) kept-alive connections through the HTTP proxy |
| http-ka-50k-2000 | 2000 kept-alive connections, 50 KB answers |
| http-close-1k | 64 connections, a new one for every request |

## How to read the table

* Each cell: the median on the M4 / on the Skylake host / their average. TCP
  streams and 1 MB HTTP answers in Gbit/s, the other HTTP scenarios in
  thousands of requests per second.
* Columns: the client talking to the origin with no proxy (only the kernel
  forwarding, for reference), then the proxies copying through user space,
  then after the second ‖ the proxies using splice().
* **Bold**: the best average of its group (copying, splice) in the row, and
  any other of the group whose runs cannot be told apart from it: the range of
  its average (from the average of each machine's slowest run to that of the
  fastest) reaches the best one's.
* \*: the best of the row, copying and splice together, by the same rule -
  whether copying or splice() wins the scenario.
* A few results were limited by the client or the origin rather than by the
  proxy, which can then do more than shown: on the M4, devel splice with single
  and 16 streams (the receiving iperf3 thread at a full core), haproxy with 16
  streams, and several of the 1 MB HTTP runs. The per-run `bound` column in
  [data/](data/) has the detail; `bench/report.py` on one machine's files marks
  them.
* CPU time per gigabyte or request is in the data, but adds little: every
  proxy ran at its CPU limit, so its CPU per unit of work is the inverse of its
  throughput. Peak memory is in the data as well, summed up above.
* http-ka-50k-2000: every proxy but haproxy leaves some requests waiting longer
  than wrk's 2 second limit (counted as timeouts in the data, 140-540 a run);
  haproxy serves the 2000 connections more evenly, with none over 2 seconds but
  a median wait 2 to 3 times longer.

## Throughput

| scenario (M4 / Intel / average) | no proxy | ‖ | 0.9.4 | 1.0.1 | devel | nginx | haproxy | ‖ | 0.9.4 splice | devel splice | haproxy splice-auto | haproxy splice |
|---|---:|:-:|---:|---:|---:|---:|---:|:-:|---:|---:|---:|---:|
| stream1, Gbit/s | 62.0 / 44.4 / 53.2 | ‖ | 8.3 / 5.5 / 6.9 | 22.1 / 19.1 / 20.6 | **22.0 / 19.9 / 21.0** | 13.5 / 9.8 / 11.6 | 13.6 / 9.7 / 11.7 | ‖ | 25.1 / 29.2 / 27.1 | **45.7 / 31.4 / 38.6** * | 29.5 / 30.6 / 30.1 | **44.7 / 32.3 / 38.5** * |
| stream16, Gbit/s | 141.2 / 150.5 / 145.9 | ‖ | 8.7 / 5.6 / 7.2 | **20.9 / 18.9 / 19.9** | **20.9 / 18.8 / 19.8** | 13.5 / 9.9 / 11.7 | 9.5 / 9.2 / 9.3 | ‖ | 24.5 / 28.3 / 26.4 | **37.8 / 31.2 / 34.5** * | 15.9 / 30.3 / 23.1 | 22.1 / 31.5 / 26.8 |
| stream1-down, Gbit/s | 61.8 / 43.1 / 52.5 | ‖ | 8.8 / 5.6 / 7.2 | **22.4 / 18.8 / 20.6** | **22.1 / 19.4 / 20.8** | 13.6 / 9.7 / 11.7 | 13.6 / 9.3 / 11.5 | ‖ | **47.9 / 34.4 / 41.1** * | 47.4 / 32.0 / 39.7 | 30.4 / 31.0 / 30.7 | **47.6 / 33.7 / 40.6** * |
| http-ka-1k, k req/s | 120.3 / 127.1 / 123.7 | ‖ | 14.1 / 19.2 / 16.7 | 6.0 / 6.1 / 6.1 | 15.8 / 18.1 / 17.0 | 37.0 / 36.5 / 36.8 | **44.3 / 37.3 / 40.8** * | ‖ | 13.4 / 14.6 / 14.0 | 14.9 / 13.8 / 14.4 | **44.1 / 37.2 / 40.7** * | **44.1 / 38.0 / 41.1** * |
| http-ka-1m, Gbit/s | 71.6 / 67.5 / 69.5 | ‖ | 8.3 / 5.8 / 7.1 | 12.5 / 12.4 / 12.4 | **21.9 / 18.3 / 20.1** | 12.6 / 5.8 / 9.2 | 6.0 / 7.6 / 6.8 | ‖ | **33.0 / 26.6 / 29.8** * | **35.3 / 23.9 / 29.6** * | 5.9 / 24.2 / 15.1 | 28.0 / 26.7 / 27.4 |
| http-ka-50k-2000, k req/s | 84.5 / 85.7 / 85.1 | ‖ | 7.6 / 7.0 / 7.3 | 9.0 / 10.3 / 9.6 | **10.4 / 10.5 / 10.5** * | 11.0 / 9.2 / 10.1 | 9.6 / 7.3 / 8.4 | ‖ | 9.1 / 9.4 / 9.3 | 9.9 / 9.0 / 9.4 | 9.6 / 7.7 / 8.6 | **11.9 / 9.0 / 10.4** * |
| http-close-1k, k req/s | 48.7 / 52.1 / 50.4 | ‖ | 5.0 / 4.8 / 4.9 | 4.4 / 4.0 / 4.2 | 5.2 / 4.8 / 5.0 | 13.3 / 12.9 / 13.1 | **16.6 / 15.1 / 15.9** * | ‖ | 4.8 / 4.4 / 4.6 | 5.0 / 4.4 / 4.7 | **16.7 / 15.1 / 15.9** * | **16.8 / 15.5 / 16.1** * |


## Splice by direction

devel splices what the server sends with `-s1` (downloads), what the client
sends with `-s2` (uploads), both with `-s3`; haproxy's matching settings are
`option splice-response`, `option splice-request` and both. The 2000 client
scenario here sends a 2 KB POST body with each request and gets 50 KB back
(`http-ka-2k-50k-2000`). Same setup and markings as above; measured in a
session of their own ([data/](data/) `*-splice-direction.csv`).

| scenario (M4 / Intel / average) | no proxy | ‖ | devel -s0 | haproxy | ‖ | devel -s1 | devel -s3 | haproxy splice-response | haproxy splice |
|---|---:|:-:|---:|---:|:-:|---:|---:|---:|---:|
| stream1, Gbit/s | 61.6 / 45.5 / 53.6 | ‖ | **22.4 / 19.0 / 20.7** | 13.1 / 9.5 / 11.3 | ‖ | 22.4 / 19.5 / 21.0 | **44.1 / 31.9 / 38.0** * | 13.6 / 9.7 / 11.7 | **46.3 / 30.7 / 38.5** * |
| stream16, Gbit/s | 140.6 / 147.1 / 143.8 | ‖ | **21.1 / 19.2 / 20.2** | 9.0 / 8.9 / 8.9 | ‖ | 20.9 / 18.7 / 19.8 | **38.2 / 32.3 / 35.2** * | 9.2 / 9.1 / 9.2 | 23.2 / 33.3 / 28.3 |
| stream1-down, Gbit/s | 63.7 / 47.0 / 55.3 | ‖ | **22.3 / 19.5 / 20.9** | 13.8 / 9.5 / 11.7 | ‖ | **47.9 / 33.0 / 40.5** * | **46.3 / 30.7 / 38.5** * | **46.9 / 32.3 / 39.6** * | **47.4 / 32.6 / 40.0** * |
| http-ka-1k, k req/s | 120.0 / 127.6 / 123.8 | ‖ | 15.9 / 19.5 / 17.7 | **44.2 / 37.1 / 40.7** * | ‖ | 15.3 / 17.0 / 16.1 | 15.0 / 14.9 / 14.9 | **44.0 / 37.0 / 40.5** * | **44.1 / 35.0 / 39.5** * |
| http-ka-1m, Gbit/s | 71.0 / 67.2 / 69.1 | ‖ | **22.3 / 17.5 / 19.9** | 5.8 / 7.7 / 6.8 | ‖ | **35.6 / 24.7 / 30.2** * | **34.6 / 24.5 / 29.5** * | 26.4 / 27.7 / 27.1 | 26.5 / 25.9 / 26.2 |
| http-ka-2k-50k-2000, k req/s | 73.7 / 64.7 / 69.2 | ‖ | **9.5 / 9.7 / 9.6** | 8.8 / 7.2 / 8.0 | ‖ | 9.0 / 8.4 / 8.7 | 8.7 / 7.6 / 8.1 | **11.2 / 8.7 / 10.0** * | **11.2 / 9.0 / 10.1** * |
| http-close-1k, k req/s | 49.0 / 43.4 / 46.2 | ‖ | 5.1 / 4.9 / 5.0 | **16.5 / 15.9 / 16.2** * | ‖ | 5.0 / 4.7 / 4.9 | 5.0 / 4.2 / 4.6 | **16.7 / 15.0 / 15.8** * | **16.8 / 15.5 / 16.2** * |


* Each option splices the direction it names: with `-s1` an upload stream
  goes at the copying speed and a download stream at the splicing one, as with
  haproxy's `splice-response`.
* For bulk downloads `-s1` gets all of splice()'s gain; `-s3` is needed only
  for bulk uploads (stream1, stream16).
* Small requests and 50 KB answers gain nothing from splicing in 3proxy, in
  either direction: devel `-s0` stays ahead of `-s1` and `-s3`. haproxy gains
  25% with 2000 clients from splicing the answers; there it is ahead of devel by
  4-5%.

## Grace delay with splice

`-s1` without grace delay, with the setting suggested in the documentation
(`-g8000,3,10`: wait 10 ms before reading once 3 reads in a row averaged 8 KB or
less), and with one meant to wait on answers only (`-g65536,2,10`: any 2 reads
in a row; an HTTP request body is read at once, an answer of 50 KB or more is
not). Measured in a session of their own ([data/](data/) `*-grace.csv`).

| scenario (M4 / Intel / average) | -s1, no grace delay | -s1 -g8000,3,10 | -s1 -g65536,2,10 |
|---|---:|---:|---:|
| stream1, Gbit/s | **22.0 / 20.0 / 21.0** * | **22.1 / 19.7 / 20.9** * | **22.4 / 20.1 / 21.3** * |
| stream16, Gbit/s | **20.8 / 19.5 / 20.2** * | **20.9 / 18.4 / 19.7** * | **20.7 / 19.1 / 19.9** * |
| stream1-down, Gbit/s | **48.1 / 32.7 / 40.4** * | 28.6 / 33.0 / 30.8 | 18.3 / 32.5 / 25.4 |
| http-ka-1k, k req/s | 15.4 / 15.4 / 15.4 | **15.5 / 16.4 / 16.0** * | **15.5 / 16.6 / 16.0** * |
| http-ka-1m, Gbit/s | **35.6 / 25.5 / 30.5** * | **35.5 / 25.2 / 30.3** * | **36.1 / 25.4 / 30.8** * |
| http-ka-2k-50k-2000, k req/s | **9.0 / 8.3 / 8.6** * | **9.0 / 8.3 / 8.7** * | **9.1 / 8.5 / 8.8** * |
| http-close-1k, k req/s | **5.1 / 4.5 / 4.8** * | **5.1 / 4.6 / 4.8** * | **5.1 / 4.7 / 4.9** * |


* Grace delay makes little difference here: 4% more 1 KB requests over
  kept-alive connections, nothing elsewhere - except on the M4 with a single
  download stream, where it costs 40% (`-g8000,3,10`) to 60% (`-g65536,2,10`)
  of the throughput. These links are fast and local: reads are rarely small,
  so the delay seldom applies, and when it does it mostly adds waiting. It is
  meant for slow links carrying small packets, which this benchmark does not
  have.

## Caveats

* Both machines are virtual: their CPUs cannot be pinned to physical cores, so
  absolute figures move between sessions; compare within a table.
* The roles have CPUs of their own but share the memory, and memory bandwidth,
  which copying proxies use most, cannot be split. On the Skylake host it may
  well be the limit; a CPU waiting for memory counts as busy, so this shows as
  less work per busy second rather than as idle time.
* wrk measures in a closed loop: a slower proxy is offered less load, so
  latencies compare only between runs of similar throughput, and requests over
  2 seconds are left out of its latency figures.
* The haproxy versions differ between the machines (2.8 and 3.0).

