# Benchmarks

Compares the speed and the cost of 3proxy versions, and of other proxies doing
the same job, on Linux.

Results of the latest comparison, with the setup they were measured on, are
in [RESULTS.md](RESULTS.md); the measurements are in [data/](data/).

## How the measurement is isolated

The client, the proxy and the origin each run in a network namespace of
their own, linked by veth pairs:

```
[bcli] 10.0.1.2 --veth-- 10.0.1.1 [bprx] 10.0.2.1 --veth-- 10.0.2.2 [bsrv]
 wrk, iperf3              the proxy              nginx (files), iperf3 -s
```

so they share no loopback, and a packet crosses the same path whichever proxy
is measured. Each role also runs in a cgroup of its own pinned to separate
CPUs (`--cpus`, default `cli=0-3,prx=4,srv=5-7` for 8 CPUs), so one does not
take CPU from another, and RPS steers what each veth receives to the
receiver's CPUs, so the kernel's network work for a role is done on its own
CPUs too. The proxy's cgroup is created anew for every run, which is what
makes its peak memory readable on its own.

The proxy gets the fewest CPUs on purpose: the measurement is about the proxy,
so it has to be what runs out first. Every proxy is given the same CPUs: nginx
gets as many workers and haproxy as many threads as the proxy has CPUs;
3proxy runs a thread per connection inside the same cpuset. Logging is off
everywhere.

CPU time is the busy time of a role's CPUs read from `/proc/stat`: its
processes and the interrupts and softirqs handled there. The cgroup's own CPU
time is not enough: a kernel with `CONFIG_IRQ_TIME_ACCOUNTING` leaves the
softirqs out of it, and that is where much of the network work is done (a
quarter of a proxy's CPU in these tests).

Every run records which side set its pace (`bound`): the role whose CPUs were
busy at least 90% of the time, or which had a thread doing so (an iperf3
stream is one thread, so one busy core is its limit however many CPUs the
role has). A run bound by the client or the origin says only that the proxy
can do at least that much.

`none` is no proxy at all: the client reaches the origin through the proxy
namespace with the kernel forwarding, the upper bound for every scenario.

## What is reported

For every run, in a CSV under `bench/results/`:

| column | meaning |
|---|---|
| `gbit`, `rate` | throughput, requests per second for HTTP |
| `p50_ms`, `p99_ms` | latency from wrk (closed loop: compare at equal load only) |
| `prx_cpu_s`, `prx_task_s` | busy CPU seconds of the proxy's CPUs, network work included; the CPU time of its processes alone |
| `cpu_s_per_gb`, `cpu_us_per_req` | the proxy's cost per unit of work: the fairest figure, least affected by which side was the limit |
| `peak_mb` | the proxy's peak memory |
| `cli_util`, `prx_util`, `srv_util` | how busy each role's CPUs were |
| `cli_thread`, `srv_thread` | the busiest client and origin thread, as a share of one CPU |
| `bound` | `proxy`, `client`, `origin`, or `none` when nothing was busy all the time |
| `errors`, `timeouts`, `retrans` | socket errors and non-2xx answers; requests slower than wrk's 2 seconds; TCP retransmissions in the stream scenarios |

Repetitions rotate the order of the proxies, so drift over time (heat, the
host) falls on all of them alike; the summary gives medians.

## Scenarios

| name | load |
|---|---|
| `stream1`, `stream1-down` | one iperf3 stream through a TCP relay (3proxy `tcppm`, nginx `stream`, haproxy `mode tcp`), upload and download |
| `stream16` | sixteen streams |
| `http-ka-1k`, `http-ka-1m` | HTTP over kept-alive connections through an HTTP proxy (absolute URIs), 1 KB and 1 MB answers |
| `http-ka-50k-2000` | 2000 clients at once, GET answered with 50 KB |
| `http-ka-2k-50k-2000` | the same, each request a POST with a 2 KB body |
| `http-close-1k` | a new connection for every request |
| `connect-*` | the same loads through CONNECT tunnels: wrk and iperf3 run under proxychains-ng, so every connection they make asks the proxy for a tunnel to the origin (`connect-close-1k`: a tunnel for every request) |
| `socks-*` | the same through SOCKSv5 |
| `relay-*` | the same through a TCP relay to a fixed destination: 3proxy `tcppm`, nginx `stream`, haproxy `mode tcp` |

nginx is not a forward proxy: it answers absolute URIs by passing them to its
upstream, which is the origin here. Neither nginx nor haproxy has CONNECT or
SOCKS, so they take part in the HTTP and `relay-*` scenarios but not in the
`connect-*` and `socks-*` ones. tinyproxy
and squid are HTTP proxies, measured in the HTTP and `connect-*` scenarios;
dante is a SOCKS server, measured in the `socks-*` ones.

## Running

Root, `iproute2`, `iperf3`, `wrk`, `proxychains4` (proxychains-ng, for the `connect-*` and `socks-*` scenarios), `nginx` (with the stream module:
`libnginx-mod-stream` on Debian and Ubuntu, `nginx-mod-stream` on
RHEL-like systems) and, to compare with it,
`haproxy`.

```sh
bench/build.sh 0.9.9.1 1.0.1                      # tags into bench/bin/
NAME=devel bench/build.sh .                       # the working tree
CC="gcc -fcommon" bench/build.sh 0.8.13           # before 0.9, newer gcc
CC="gcc -fpermissive" bench/build.sh 0.9.4        # 0.9.x with gcc 14 and later

sudo bench/bench.py \
    --proxy none \
    --proxy 3proxy:bench/bin/3proxy-1.0.1 \
    --proxy 3proxy:bench/bin/3proxy-devel \
    --proxy "3proxy:bench/bin/3proxy-0.9.4:-s0" \
    --proxy nginx --proxy haproxy
```

`bench/report.py <csv>` turns a run into Markdown tables: throughput, the
proxy's CPU per gigabyte or per request, and its peak memory. With
`--machine NAME=a.csv,b.csv` once per machine it makes a single throughput
table of all of them, each cell their medians and their average.

After the binary, a 3proxy entry can carry options for both its services:
`-s1`, `-s2` and `-s3` splice downloads, uploads or both (`-s0` keeps 0.9.0 to
0.9.8, which use splice() both ways by default, from using it), and
`-ocTCP_NODELAY -osTCP_NODELAY` turns Nagle's algorithm off on the client and
server sockets.

haproxy can be measured with splice() too: `haproxy::splice-auto` lets its
heuristic splice a direction once reads fill the buffer three times in a row;
`haproxy::splice-response`, `haproxy::splice-request` and `haproxy::splice`
always splice the server's data, the client's, or both (`option
splice-response`, `option splice-request`), as 3proxy's `-s1`, `-s2` and `-s3`
do. nginx has no splice() support, so it has no such
variant.

`--scenario` picks scenarios, `--reps` and `--duration` set the repetitions
and their length, `--netem "delay 1ms rate 10gbit"` puts a slower, longer link
between the client and the proxy, `--mtu` changes the links' MTU.

## Caveats

* A virtual machine cannot pin its virtual CPUs to physical ones, so its
  absolute numbers move between sessions: compare within one session, and
  keep absolute figures for real hardware.
* wrk measures latency in a closed loop, so a slower proxy is also offered
  less load; compare latencies only between runs of similar throughput.
* The roles have CPUs of their own but share the memory: memory bandwidth,
  which copying proxies use most, cannot be split, and on some hosts it,
  rather than the CPU, sets the limit. A CPU waiting for memory counts as
  busy, so such a limit shows as less work per busy second.
* Versions are built with the Makefile they shipped with, so compiler flags
  differ between them (0.8 builds with `-O2`, 0.9.9 and later with
  `-O3 -flto`) as they did for their users.
