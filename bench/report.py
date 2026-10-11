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
"""

import argparse
import csv
import statistics

STREAM = ("stream1", "stream1-down", "stream16")


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="+")
    ap.add_argument("--label", action="append", default=[], help="old=new")
    ap.add_argument("--title", default="")
    ap.add_argument("--splice", action="append", default=[],
                    help="a proxy (as named in the CSV) using splice(); repeat")
    args = ap.parse_args()
    labels = dict(l.split("=", 1) for l in args.label)

    rows, seen = [], set()
    for path in args.csv:
        new = list(csv.DictReader(open(path)))
        rows += [r for r in new if r["proxy"] not in seen]
        seen |= {r["proxy"] for r in new}
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
        if s in STREAM or s in ("http-ka-1m", "http-ka-50k-2000"):
            return fmt(median(sel, "cpu_s_per_gb"), 2) + " s/GB"
        return fmt(median(sel, "cpu_us_per_req"), 0) + " µs/req"

    def peak(s, p):
        if p == "direct":
            return "–"
        return fmt(median(by.get((s, p), []), "peak_mb"), 0)

    def cpukey(s):
        return "cpu_s_per_gb" if s in STREAM or s in ("http-ka-1m", "http-ka-50k-2000") \
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
