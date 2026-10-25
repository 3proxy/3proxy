#!/usr/bin/env python3
"""Markdown tables from a bench.py CSV: throughput, the proxy's CPU per unit
of work, and its peak memory, a scenario per row and a proxy per column, each
cell the median of the repetitions.

Proxies given with --splice (those using splice()) form a group of their own
after the others, the two separated by a ‖ column. The best proxy of each
group in each row is in bold, and so is any other of the group whose
repetitions overlap the best one's (the range of the repetitions stands for
the error): the measurement cannot tell them apart. "direct", no proxy, comes
first and is not ranked.
A value marked ‡ was limited by the client or the origin rather than by the
proxy (most of its repetitions were), so the proxy can do at least that much.

    bench/report.py bench/results/20261011-155353.csv > tables.md

Several CSVs make one set of tables: a proxy is taken from the first file it
appears in, so a later run can add proxies, and a proxy it repeats (run again
to see how much the conditions moved between the runs) is left out.

--label old=new renames a column, e.g. --label 3proxy-devel-s="devel, splice".

--machine NAME=a.csv,b.csv, given once per machine, makes a single table of
throughput instead: each cell the machines' medians and their average. The
best average of each group (no splice, splice) is in bold, and so is any other
of the group whose range (the average of its slowest runs to that of its
fastest) reaches the best one's; * marks the best of the row, both groups
together, in the same way. --split puts the splice group in a table of its own
(* still compares across both), --prefix connect- takes only the scenarios so
named. --latency makes one table of the runs' 50th, 90th and 99th
percentile latency for a single CSV instead, ranked by the 99th. --overall
marks the best of the row only, in bold and with *: for tables where one
group has a single proxy, its group's best says nothing.
"""

import argparse
import csv
import statistics

STREAM = ("stream1", "stream1-down", "stream16", "connect-stream1-down", "connect-stream16",
          "socks-stream1-down", "socks-stream16", "relay-stream1-down", "relay-stream16",
          "tls-term-stream1-down", "tls-term-stream16", "tls-init-stream1-down", "tls-init-stream16")
# connect-ka-1m etc. are bulk too when present


def values(rows, key):
    xs = []
    for r in rows:
        try:
            x = float(r[key])
        except (KeyError, ValueError):
            continue
        if x == x:
            xs.append(x)
    return xs


def median(rows, key):
    xs = values(rows, key)
    return statistics.median(xs) if xs else None


def winners(by, scenario, proxies, key, higher):
    """Proxies tied for best: the best median, and those whose range of
    repetitions overlaps the best one's."""
    ranges = {}
    for p in proxies:
        if p == "direct":
            continue
        xs = values(by.get((scenario, p), []), key)
        if xs:
            ranges[p] = (min(xs), statistics.median(xs), max(xs))
    if not ranges:
        return set()
    if higher:
        best = max(ranges, key=lambda p: ranges[p][1])
        return {p for p, r in ranges.items() if r[2] >= ranges[best][0]}
    best = min(ranges, key=lambda p: ranges[p][1])
    return {p for p, r in ranges.items() if r[0] <= ranges[best][2]}


def fmt(x, digits):
    if x is None:
        return "–"
    return f"{x:,.{digits}f}"


def table(title, scenarios, groups, labels, cell, best):
    """groups: lists of proxies, each ranked on its own, shown in order with
    a separator column between them."""
    head, rule = [], []
    for i, g in enumerate(groups):
        if i:
            head.append("‖")
            rule.append(":-:")
        head += [labels.get(p, p) for p in g]
        rule += ["---:"] * len(g)
    out = [f"**{title}**", "", "| scenario | " + " | ".join(head) + " |",
           "|---|" + "|".join(rule) + "|"]
    for s in scenarios:
        cells = []
        for i, g in enumerate(groups):
            if i:
                cells.append("‖")
            win = best(s, g)
            cells += [f"**{cell(s, p)}**" if p in win else cell(s, p) for p in g]
        out.append(f"| {s} | " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def load(paths):
    """Rows of several CSVs, a proxy taken from the first file it is in."""
    rows, seen = [], set()
    for path in paths:
        new = list(csv.DictReader(open(path)))
        rows += [r for r in new if r["proxy"] not in seen]
        seen |= {r["proxy"] for r in new}
    return rows


# In the combined table, the bulk scenarios in Gbit/s, the others in
# thousands of requests per second.
BULK = STREAM + ("http-ka-1m", "tls-term-ka-1m", "tls-init-ka-1m")


def combined(machines, labels, splice, prefix=None, split=False, overall_only=False):
    """One throughput table for several machines: each cell their medians
    and their average. Bold: the best of its group; *: the best of the row.
    split puts the proxies using splice() in a table of their own, * still
    comparing across both."""
    data, proxies, scenarios = {}, [], []
    for name, paths in machines:
        by = {}
        for r in load(paths):
            if prefix and not r["scenario"].startswith(prefix):
                continue
            by.setdefault((r["scenario"], r["proxy"]), []).append(r)
            if r["proxy"] not in proxies:
                proxies.append(r["proxy"])
            if r["scenario"] not in scenarios:
                scenarios.append(r["scenario"])
        data[name] = by

    def runs(name, s, p):
        sel = data[name].get((s, p), [])
        if s in BULK:
            return values(sel, "gbit")
        return [x / 1000 for x in values(sel, "rate")]

    def value(name, s, p):
        xs = runs(name, s, p)
        return statistics.median(xs) if xs else None

    def average(s, p):
        xs = [value(n, s, p) for n, _ in machines]
        return sum(xs) / len(xs) if xs and None not in xs else None

    def spread(s, p):
        """The range of the average: of the slowest runs to of the fastest."""
        lows, highs = [], []
        for n, _ in machines:
            xs = runs(n, s, p)
            if not xs:
                return None
            lows.append(min(xs))
            highs.append(max(xs))
        return sum(lows) / len(lows), sum(highs) / len(highs)

    def leaders(s, ps):
        """The best average, and those whose range reaches the best one's:
        the runs cannot tell them apart."""
        known = {p: average(s, p) for p in ps if p != "direct"}
        known = {p: a for p, a in known.items() if a is not None}
        if not known:
            return set()
        floor = spread(s, max(known, key=known.get))[0]
        return {p for p in known if spread(s, p)[1] >= floor}

    plain = [p for p in proxies if p != "direct" and p not in splice]
    spliced = [p for p in proxies if p in splice]
    direct = [p for p in proxies if p == "direct"]
    # one machine: its medians alone, with ‡ where most runs were limited by
    # the client or the origin; several: their medians and their average
    single = len(machines) == 1
    names = machines[0][0] if single else " / ".join(n for n, _ in machines) + " / average"

    def limited(s, p):
        if not single:
            return ""
        bounds = [r.get("bound", "") for r in data[machines[0][0]].get((s, p), [])]
        other = sum(b in ("client", "origin") for b in bounds)
        return " ‡" if bounds and other * 2 > len(bounds) else ""

    def render(tables):
        """tables: lists of groups, each table printed on its own; bold for
        the best of a group, * for the best of the row over all of them."""
        everyone = [p for t in tables for g in t for p in g]
        for t in tables:
            head, rule = [], []
            for i, g in enumerate(t):
                if i:
                    head.append("‖")
                    rule.append(":-:")
                head += [labels.get(p, p) for p in g]
                rule += ["---:"] * len(g)
            out = [f"| scenario ({names}) | " + " | ".join(head) + " |",
                   "|---|" + "|".join(rule) + "|"]
            for s in scenarios:
                unit = "Gbit/s" if s in BULK else "k req/s"
                overall = leaders(s, everyone)
                cells = []
                for i, g in enumerate(t):
                    if i:
                        cells.append("‖")
                    best = overall if overall_only else leaders(s, g)
                    for p in g:
                        vals = [value(n, s, p) for n, _ in machines]
                        if not single:
                            vals.append(average(s, p))
                        if all(v is None for v in vals):
                            cells.append("–")
                            continue
                        text = " / ".join(fmt(v, 1) for v in vals) + limited(s, p)
                        if p in best:
                            text = f"**{text}**"
                        if p in overall:
                            text += " *"
                        cells.append(text)
                name = s[len(prefix):] if prefix else s
                out.append(f"| {name}, {unit} | " + " | ".join(cells) + " |")
            print("\n".join(out))
            print()

    if split and spliced:
        render([[g for g in (direct, plain) if g], [spliced]])
    else:
        render([[g for g in (direct, plain, spliced) if g]])


def latency(path, labels, splice, prefix=None):
    """Latency of one machine's runs: each cell the medians of the runs' 50th,
    90th (when recorded) and 99th percentiles, in milliseconds. Bold: the lowest 99th percentile
    of its group and any other whose runs overlap it; *: the same over the
    row. Scenarios without a latency (iperf3 streams) are left out."""
    by, proxies, scenarios = {}, [], []
    for r in load([path]):
        if prefix and not r["scenario"].startswith(prefix):
            continue
        if not values([r], "p99_ms"):
            continue
        by.setdefault((r["scenario"], r["proxy"]), []).append(r)
        if r["proxy"] not in proxies:
            proxies.append(r["proxy"])
        if r["scenario"] not in scenarios:
            scenarios.append(r["scenario"])

    def ms(x):
        if x is None:
            return "–"
        return fmt(x, 2 if x < 10 else 1 if x < 100 else 0)

    plain = [p for p in proxies if p != "direct" and p not in splice]
    spliced = [p for p in proxies if p in splice]
    groups = [g for g in ([p for p in proxies if p == "direct"], plain, spliced) if g]
    everyone = [p for g in groups for p in g]
    head, rule = [], []
    for i, g in enumerate(groups):
        if i:
            head.append("‖")
            rule.append(":-:")
        head += [labels.get(p, p) for p in g]
        rule += ["---:"] * len(g)
    # the percentiles the results have: older ones only p50 and p99
    pcts = [c for c in ("p50_ms", "p75_ms", "p90_ms", "p99_ms")
            if c in ("p50_ms", "p99_ms") or any(values(rs, c) for rs in by.values())]
    out = [f"| scenario, {' / '.join(c[:3] for c in pcts)} ms | " + " | ".join(head) + " |",
           "|---|" + "|".join(rule) + "|"]
    for s in scenarios:
        overall = winners(by, s, everyone, "p99_ms", False)
        cells = []
        for i, g in enumerate(groups):
            if i:
                cells.append("‖")
            best = winners(by, s, g, "p99_ms", False)
            for p in g:
                sel = by.get((s, p), [])
                if not sel:
                    cells.append("–")
                    continue
                text = " / ".join(ms(median(sel, c)) for c in pcts)
                if p in best:
                    text = f"**{text}**"
                if p in overall:
                    text += " *"
                cells.append(text)
        name = s[len(prefix):] if prefix else s
        out.append(f"| {name} | " + " | ".join(cells) + " |")
    print("\n".join(out))
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="*")
    ap.add_argument("--split", action="store_true",
                    help="the proxies using splice() in a table of their own")
    ap.add_argument("--prefix", help="only the scenarios named so, e.g. connect- "
                    "(the prefix is left out of the rows)")
    ap.add_argument("--machine", action="append", default=[],
                    help="NAME=a.csv[,b.csv]: one throughput table for all the "
                         "machines given, instead of the tables for one")
    ap.add_argument("--overall", action="store_true",
                    help="with --machine: only the best of the row, bold and *")
    ap.add_argument("--label", action="append", default=[], help="old=new")
    ap.add_argument("--title", default="")
    ap.add_argument("--splice", action="append", default=[],
                    help="a proxy (as named in the CSV) using splice(); repeat")
    ap.add_argument("--latency", action="store_true",
                    help="one table of latency, 50th / 90th / 99th percentile, for the "
                         "one CSV given")
    args = ap.parse_args()
    labels = dict(l.split("=", 1) for l in args.label)

    if args.latency:
        latency(args.csv[0], labels, args.splice, args.prefix)
        return

    if args.machine:
        combined([(m.split("=", 1)[0], m.split("=", 1)[1].split(","))
                  for m in args.machine], labels, args.splice, args.prefix, args.split,
                 args.overall)
        return
    rows = load(args.csv)
    proxies, scenarios = [], []
    for r in rows:
        if r["proxy"] not in proxies:
            proxies.append(r["proxy"])
        if r["scenario"] not in scenarios:
            scenarios.append(r["scenario"])
    by = {}
    for r in rows:
        by.setdefault((r["scenario"], r["proxy"]), []).append(r)

    def limited(s, p):
        if p == "direct":
            return ""
        bounds = [r.get("bound", "") for r in by.get((s, p), [])]
        other = sum(b in ("client", "origin") for b in bounds)
        return " ‡" if bounds and other * 2 > len(bounds) else ""

    def throughput(s, p):
        sel = by.get((s, p), [])
        g = median(sel, "gbit")
        if s in STREAM:
            return fmt(g, 1) + limited(s, p)
        rate = median(sel, "rate")
        return f"{fmt(g, 2)} ({fmt(rate / 1000 if rate else None, 1)}k/s)" + limited(s, p)

    def cpu(s, p):
        sel = by.get((s, p), [])
        if p == "direct":
            return "–"
        if s in BULK or s in ("http-ka-50k-2000", "http-ka-2k-50k-2000"):
            return fmt(median(sel, "cpu_s_per_gb"), 2) + " s/GB"
        return fmt(median(sel, "cpu_us_per_req"), 0) + " µs/req"

    def peak(s, p):
        if p == "direct":
            return "–"
        return fmt(median(by.get((s, p), []), "peak_mb"), 0)

    def cpukey(s):
        return "cpu_s_per_gb" if s in STREAM or s in ("http-ka-1m", "http-ka-50k-2000", "http-ka-2k-50k-2000") \
            else "cpu_us_per_req"

    plain = [p for p in proxies if p != "direct" and p not in args.splice]
    spliced = [p for p in proxies if p in args.splice]
    groups = [g for g in ([p for p in proxies if p == "direct"], plain, spliced) if g]

    prefix = f"{args.title}: " if args.title else ""
    print(table(prefix + "throughput, Gbit/s (thousands of requests per second for HTTP)",
                scenarios, groups, labels, throughput,
                lambda s, g: winners(by, s, g, "gbit", True)))
    print(table(prefix + "proxy CPU time per gigabyte or per request",
                scenarios, groups, labels, cpu,
                lambda s, g: winners(by, s, g, cpukey(s), False)))
    print(table(prefix + "proxy peak memory, MB", scenarios, groups, labels, peak,
                lambda s, g: winners(by, s, g, "peak_mb", False)))


if __name__ == "__main__":
    main()
