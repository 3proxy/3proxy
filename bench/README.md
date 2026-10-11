# Benchmarks

Compares the speed and the cost of 3proxy versions, and of other proxies doing
the same job, on Linux.

## How the measurement is isolated

The client, the proxy and the origin each run in a network namespace of
their own, linked by veth pairs:

```
[bcli] 10.0.1.2 --veth-- 10.0.1.1 [bprx] 10.0.2.1 --veth-- 10.0.2.2 [bsrv]
 wrk, iperf3              the proxy              nginx (files), iperf3 -s
```

so they share no loopback, and a packet crosses the same path whichever proxy
is measured. Each role also runs in a cgroup of its own pinned to separate
CPUs (`--cpus`, default `cli=0-3,prx=4-5,srv=6-7`), so one does not take CPU
from another, and RPS steers what each veth receives to the receiver's CPUs.
The proxy's cgroup is created anew for every run, which is what makes its
CPU time and peak memory readable on their own.

Every proxy is given the same CPUs: nginx gets as many workers and haproxy as
many threads as the proxy cgroup has CPUs; 3proxy runs a thread per
connection inside the same cpuset. Logging is off everywhere.

`none` is no proxy at all: the client reaches the origin through the proxy
namespace with the kernel forwarding, the upper bound for every scenario.

## What is reported

For every run, in a CSV under `bench/results/`:

| column | meaning |
|---|---|
| `gbit`, `rate` | throughput, requests per second for HTTP |
| `p50_ms`, `p99_ms` | latency from wrk (closed loop: compare at equal load only) |
| `prx_cpu_s` | CPU seconds the proxy used, all its threads and processes |
| `cpu_s_per_gb`, `cpu_us_per_req` | the proxy's cost per unit of work: the fairest figure, least affected by which side was the limit |
| `peak_mb` | the proxy's peak memory |
| `cli_util`, `prx_util`, `srv_util` | how busy each role's CPUs were: a client or origin near 100% means the result says nothing about the proxy |
| `errors`, `retrans` | socket errors and non-2xx answers; TCP retransmissions in the stream scenarios |

Repetitions rotate the order of the proxies, so drift over time (heat, the
host) falls on all of them alike; the summary gives medians.

## Scenarios

| name | load |
|---|---|
| `stream1`, `stream1-down` | one iperf3 stream through a TCP relay (3proxy `tcppm`, nginx `stream`, haproxy `mode tcp`), upload and download |
| `stream16` | sixteen streams |
| `http-ka-1k`, `http-ka-1m` | HTTP over kept-alive connections through an HTTP proxy (absolute URIs), 1 KB and 1 MB answers |
| `http-close-1k` | a new connection for every request |

nginx is not a forward proxy: it answers absolute URIs by passing them to its
upstream, which is the origin here, and it has no CONNECT or SOCKS, so only
these scenarios compare like with like.

## Running

Root, `iproute2`, `iperf3`, `wrk`, `nginx` (with the stream module:
`libnginx-mod-stream` on Debian and Ubuntu) and, to compare with it,
`haproxy`.

```sh
bench/build.sh 0.9.9.1 1.0.1                      # tags into bench/bin/
NAME=devel bench/build.sh .                       # the working tree
CC="gcc -fcommon" bench/build.sh 0.8.13           # before 0.9, newer gcc

sudo bench/bench.py \
    --proxy none \
    --proxy 3proxy:bench/bin/3proxy-1.0.1 \
    --proxy 3proxy:bench/bin/3proxy-devel \
    --proxy "3proxy:bench/bin/3proxy-0.9.4:-s0" \
    --proxy nginx --proxy haproxy
```

After the binary, a 3proxy entry can carry options for both its services:
`-s0` keeps 0.9.0 to 0.9.8, which use splice() by default, from using it, and
`-ocTCP_NODELAY -osTCP_NODELAY` turns Nagle's algorithm off on the client and
server sockets.

`--scenario` picks scenarios, `--reps` and `--duration` set the repetitions
and their length, `--netem "delay 1ms rate 10gbit"` puts a slower, longer link
between the client and the proxy, `--mtu` changes the links' MTU.

## Caveats

* A virtual machine cannot pin its virtual CPUs to physical ones, so its
  absolute numbers move between sessions: compare within one session, and
  keep absolute figures for real hardware.
* wrk measures latency in a closed loop, so a slower proxy is also offered
  less load; compare latencies only between runs of similar throughput.
* Versions are built with the Makefile they shipped with, so compiler flags
  differ between them (0.8 builds with `-O2`, 0.9.9 and later with
  `-O3 -flto`) as they did for their users.
