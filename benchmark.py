"""benchmark.py - Unified 4-suite, 2,000-row developer privacy benchmark."""
from __future__ import annotations
import argparse, json, os, subprocess, sys, time, warnings
from collections import defaultdict
import numpy as np
from engine import CascadeEngine
from sanitizer import StreamRehydrator, VaultSession

warnings.filterwarnings("ignore")
BASE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(BASE, "benchmarks")
SUITES = ["dev_prompts", "git_leaks", "mcp_configs", "adversarial_sse"]
LABELS = ["API_KEY", "AUTH_TOKEN", "CREDIT_CARD", "EMAIL", "PHONE", "IP_ADDRESS",
          "GOVT_ID", "IBAN_CRYPTO", "PERSON", "ORGANIZATION", "LOCATION"]

def load(suite):
    with open(os.path.join(BENCH, f"{suite}.jsonl"), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)

def blank():
    return defaultdict(lambda: {"stp": 0, "sfp": 0, "sfn": 0, "ptp": 0, "pfp": 0, "pfn": 0, "n": 0})

def score_row(preds, gts, per):
    for lbl in LABELS:
        pl = [p for p in preds if p.label == lbl]
        gl = [(s, e) for (g, s, e) in gts if g == lbl]
        for key, overlap in (("s", False), ("p", True)):
            used_g, used_p = set(), set()
            tp = 0
            for pi, p in enumerate(pl):
                for gi, (s, e) in enumerate(gl):
                    hit = max(p.start, s) < min(p.end, e) if overlap else (p.start == s and p.end == e)
                    if gi not in used_g and hit:
                        used_g.add(gi); used_p.add(pi); tp += 1; break
            per[lbl][key + "tp"] += tp
            per[lbl][key + "fp"] += len(pl) - tp
            per[lbl][key + "fn"] += len(gl) - tp
        per[lbl]["n"] += len(gl)

def rehydrate(text, vault, size):
    r = StreamRehydrator(vault)
    out = "".join(r.process_chunk(text[i:i + size]) for i in range(0, len(text), size))
    return out + r.flush()

def evaluate(rows, engine):
    per = blank()
    s1, s2, tot = [], [], []
    hard_total = hard_pass = clean_total = clean_pass = 0
    json_total = json_parse = json_rt = 0
    sse_pass = 0
    for r in rows:
        text = r["text"]
        gts = [(s["label"], s["start"], s["end"]) for s in r["spans"]]
        t0 = time.perf_counter(); engine.detect_stage1(text)
        t1 = time.perf_counter(); engine.detect_stage2(text)
        t2 = time.perf_counter(); preds = engine.detect(text)
        t3 = time.perf_counter()
        s1.append((t1 - t0) * 1e3); s2.append((t2 - t1) * 1e3); tot.append((t3 - t2) * 1e3)
        score_row(preds, gts, per)
        if r["category"] == "hard_negative":
            hard_total += 1; hard_pass += int(not preds)
        if r["category"] == "clean":
            clean_total += 1; clean_pass += int(not preds)
        if r.get("meta", {}).get("format") == "json":
            json_total += 1
            d, vault = VaultSession().dehydrate(text, preds)
            try:
                json.loads(d); json_parse += 1
                ok = rehydrate(d, vault, 7) == text
                json.loads(rehydrate(d, vault, 7))
                json_rt += int(ok)
            except json.JSONDecodeError:
                pass
        d, vault = VaultSession().dehydrate(text, preds)
        sse_pass += int(all(rehydrate(d, vault, size) == text for size in (1, 2, 7)))
    return {"rows": rows, "per": per, "s1": s1, "s2": s2, "tot": tot,
            "hard": (hard_pass, hard_total), "clean": (clean_pass, clean_total),
            "json": (json_parse, json_rt, json_total), "sse": (sse_pass, len(rows))}

def combine(results):
    per = blank()
    for res in results:
        for lbl in LABELS:
            for k, v in res["per"][lbl].items():
                per[lbl][k] += v
    return {"per": per, "s1": sum((r["s1"] for r in results), []),
            "s2": sum((r["s2"] for r in results), []), "tot": sum((r["tot"] for r in results), []),
            "hard": tuple(sum(r["hard"][i] for r in results) for i in range(2)),
            "clean": tuple(sum(r["clean"][i] for r in results) for i in range(2)),
            "json": tuple(sum(r["json"][i] for r in results) for i in range(3)),
            "sse": tuple(sum(r["sse"][i] for r in results) for i in range(2)),
            "rows": sum((r["rows"] for r in results), [])}

def metrics(per):
    t = {k: sum(st[k] for st in per.values()) for k in ("stp", "sfp", "sfn", "ptp", "pfp", "pfn")}
    return prf(t["stp"], t["sfp"], t["sfn"]), prf(t["ptp"], t["pfp"], t["pfn"])

def line(name, a, b="", c="", d=""):
    return f"| {name:<30} | {a:>13} | {b:>13} | {c:>13} | {d:>9} |"

def report(results, total):
    out = []
    out.append("# Code-Airlock Unified Benchmark Results\n")
    out.append("Metrics only. No raw credentials or PII values are included.\n")
    out.append("## Suite Scorecard\n")
    out.append("| Suite | Rows | Strict P / R / F1 | Partial P / R / F1 | Hard-Neg | Clean 0-FP | SSE |")
    out.append("| :--- | ---: | :---: | :---: | :---: | :---: | :---: |")
    for suite, res in results.items():
        st, pt = metrics(res["per"])
        out.append(f"| {suite} | {len(res['rows'])} | {st[0]:.1%} / {st[1]:.1%} / {st[2]:.1%} | "
                   f"{pt[0]:.1%} / {pt[1]:.1%} / {pt[2]:.1%} | {res['hard'][0]}/{res['hard'][1]} | "
                   f"{res['clean'][0]}/{res['clean'][1]} | {res['sse'][0]}/{res['sse'][1]} |")
    st, pt = metrics(total["per"])
    out.append(f"| **all** | **{len(total['rows'])}** | **{st[0]:.1%} / {st[1]:.1%} / {st[2]:.1%}** | "
               f"**{pt[0]:.1%} / {pt[1]:.1%} / {pt[2]:.1%}** | **{total['hard'][0]}/{total['hard'][1]}** | "
               f"**{total['clean'][0]}/{total['clean'][1]}** | **{total['sse'][0]}/{total['sse'][1]}** |")
    out.append("\n## Latency\n")
    out.append("| Stage | p50 | p95 |")
    out.append("| :--- | ---: | ---: |")
    for name, arr in (("Stage 1 (deterministic)", total["s1"]), ("Stage 2 (GLiNER)", total["s2"]), ("Total cascade", total["tot"])):
        out.append(f"| {name} | {np.percentile(arr, 50):.3f} ms | {np.percentile(arr, 95):.3f} ms |")
    out.append("\n## Per-Entity Support & Metrics\n")
    out.append("| Entity | GT | Strict P / R / F1 | Partial P / R / F1 |")
    out.append("| :--- | ---: | :---: | :---: |")
    for lbl in LABELS:
        s = total["per"][lbl]
        s1, p1 = prf(s["stp"], s["sfp"], s["sfn"]), prf(s["ptp"], s["pfp"], s["pfn"])
        out.append(f"| {lbl} | {s['n']} | {s1[0]:.1%} / {s1[1]:.1%} / {s1[2]:.1%} | "
                   f"{p1[0]:.1%} / {p1[1]:.1%} / {p1[2]:.1%} |")
    out.append("\n## Invariants\n")
    out.append(f"- MCP JSON parse: {total['json'][0]}/{total['json'][2]} valid; "
               f"round-trip: {total['json'][1]}/{total['json'][2]}")
    out.append(f"- SSE 1/2/7-byte round-trip: {total['sse'][0]}/{total['sse'][1]} rows")
    out.append(f"- Hard negatives: {total['hard'][0]}/{total['hard'][1]} clean")
    out.append(f"- Clean-row 0-FP rate: {total['clean'][0]}/{total['clean'][1]} "
               f"({total['clean'][0] / total['clean'][1]:.1%})" if total["clean"][1] else "- Clean-row 0-FP rate: n/a")
    text = "\n".join(out) + "\n"
    with open(os.path.join(BASE, "BENCHMARK_RESULTS.md"), "w", encoding="utf-8") as f:
        f.write(text)
    return text

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=SUITES + ["all"], default="all")
    args = parser.parse_args()
    if not all(os.path.exists(os.path.join(BENCH, f"{s}.jsonl")) for s in SUITES):
        subprocess.run([sys.executable, os.path.join(BASE, "build_benchmarks.py")], check=True)
    chosen = SUITES if args.suite == "all" else [args.suite]
    engine = CascadeEngine()
    results = {s: evaluate(load(s), engine) for s in chosen}
    total = combine(list(results.values()))
    text = report(results, total)
    print(text)

if __name__ == "__main__":
    main()
