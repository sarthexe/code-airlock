"""benchmark.py - Gold-set benchmark for the pii-airlock 11-entity taxonomy."""
from __future__ import annotations
import json, os, time, warnings
from collections import defaultdict
import numpy as np
from engine import TECH_ALLOWLIST, CascadeEngine
from sanitizer import StreamRehydrator, VaultSession

warnings.filterwarnings("ignore")
os.environ["TOKENIZERS_PARALLELISM"] = "false"
GOLD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gold_set.jsonl")
LABELS = ["API_KEY", "AUTH_TOKEN", "CREDIT_CARD", "EMAIL", "PHONE", "IP_ADDRESS",
          "GOVT_ID", "IBAN_CRYPTO", "PERSON", "ORGANIZATION", "LOCATION"]

def load(path: str = GOLD) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)

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

def neg_ok(text: str, neg: dict, preds) -> bool:
    spans, start = [], 0
    while (i := text.find(neg["value"], start)) >= 0:
        spans.append((i, i + len(neg["value"]))); start = i + 1
    return not any(p.label == neg["label"] and max(p.start, a) < min(p.end, b)
                   for p in preds for a, b in spans)

def roundtrip(dehydrated: str, vault: dict[str, str], original: str) -> bool:
    r = StreamRehydrator(vault)
    if "".join(r.process_chunk(c) for c in dehydrated) + r.flush() != original:
        return False
    r = StreamRehydrator(vault)
    return "".join(r.process_chunk(dehydrated[i:i + 7]) for i in range(0, len(dehydrated), 7)) + r.flush() == original

def row(name: str, a: str, b: str, c: str = "") -> None:
    print(f"| {name:<34} | {a:>15} | {b:>15} | {c:>5} |")

def main(path: str | None = None) -> None:
    rows = load(path) if path else load()
    engine = CascadeEngine()
    for w in ("Warmup text.", "Rahul at Microsoft in Bengaluru, India.", "test@test.com +1-555-123-4567"):
        for _ in range(2):
            engine.detect(w)

    per = defaultdict(lambda: {"stp": 0, "sfp": 0, "sfn": 0, "ptp": 0, "pfp": 0, "pfn": 0, "n": 0})
    s1_lat, s2_lat, tot_lat = [], [], []
    clean_spans, clean_rows_hit, clean_rows = 0, 0, 0
    neg_pass = neg_total = tech_pass = tech_total = empty_fail = rt_pass = 0

    for r in rows:
        text = r["text"]
        gts = [(e["label"], e["start"], e["end"]) for e in r["entities"]]
        t0 = time.perf_counter(); engine.detect_stage1(text)
        t1 = time.perf_counter(); engine.detect_stage2(text)
        t2 = time.perf_counter(); preds = engine.detect(text)
        t3 = time.perf_counter()
        s1_lat.append((t1 - t0) * 1e3); s2_lat.append((t2 - t1) * 1e3); tot_lat.append((t3 - t2) * 1e3)

        if gts:
            score_row(preds, gts, per)
        else:
            clean_rows += 1
            clean_spans += len(preds)
            clean_rows_hit += bool(preds)
            if r.get("expect_empty") and preds:
                empty_fail += 1
        if "tech_allowlist" in r["tags"]:
            tech_total += 1
            tech_pass += int(not any(p.text.strip().lower() in TECH_ALLOWLIST for p in preds))
        for neg in r.get("negatives", []):
            neg_total += 1
            neg_pass += int(neg_ok(text, neg, preds))
        session = VaultSession()
        dehydrated, vault = session.dehydrate(text, preds)
        rt_pass += int(roundtrip(dehydrated, vault, text))

    tot = {k: sum(st[k] for st in per.values()) for k in ("stp", "sfp", "sfn", "ptp", "pfp", "pfn")}
    sp, sr, sf = prf(tot["stp"], tot["sfp"], tot["sfn"])
    pp, pr, pf = prf(tot["ptp"], tot["pfp"], tot["pfn"])
    pii_rows = sum(1 for r in rows if r["entities"])
    spans = sum(per[l]["n"] for l in LABELS)

    sep = "+" + "-" * 36 + "+" + "-" * 17 + "+" + "-" * 17 + "+" + "-" * 7 + "+"
    print("\n" + sep)
    print(f"| {'GOLD-SET BENCHMARK (developer prompts + injected PII)':<78} |")
    print(sep)
    print(f"| {'Rows / PII rows / GT spans / sources':<34} | {len(rows):>15} | {pii_rows:>15} | {spans:>5} |")
    print(sep)
    row("1. Stage 1 latency (deterministic)", f"{np.percentile(s1_lat,50):.3f} ms", f"{np.percentile(s1_lat,95):.3f} ms")
    row("2. Stage 2 latency (GLiNER)", f"{np.percentile(s2_lat,50):.3f} ms", f"{np.percentile(s2_lat,95):.3f} ms")
    row("3. Total cascade latency", f"{np.percentile(tot_lat,50):.3f} ms", f"{np.percentile(tot_lat,95):.3f} ms")
    print(sep)
    row("4a. Overall STRICT P / R / F1", f"{sp:.1%} / {sr:.1%}", f"F1 {sf:.1%}")
    row("4b. Overall PARTIAL P / R / F1", f"{pp:.1%} / {pr:.1%}", f"F1 {pf:.1%}")
    print(sep)
    row("5a. Hard-negative checks", f"{neg_pass}/{neg_total} pass", "")
    row("5b. TECH_ALLOWLIST checks", f"{tech_pass}/{tech_total} pass", f"{empty_fail} empty-fail")
    row("5c. Clean-row detections (review)", f"{clean_rows_hit}/{clean_rows} rows", f"{clean_spans} spans")
    row("6. Round-trip stream invariant", f"{rt_pass}/{len(rows)} pass", "")
    print(sep)
    print(f"| {'Entity':<34} | {'Strict P / R / F1':>15} | {'Partial P / R / F1':>15} | {'GT':>5} |")
    print(sep)
    for lbl in LABELS:
        st = per[lbl]
        p1, r1, f1 = prf(st["stp"], st["sfp"], st["sfn"])
        p2, r2, f2 = prf(st["ptp"], st["pfp"], st["pfn"])
        print(f"| {lbl:<34} | {p1*100:>4.0f}/{r1*100:>4.0f}/{f1*100:>4.0f} | "
              f"{p2*100:>4.0f}/{r2*100:>4.0f}/{f2*100:>4.0f} | {st['n']:>5} |")
    print(sep + "\n")

if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else None)
