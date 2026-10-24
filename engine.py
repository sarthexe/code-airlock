"""engine.py - 2-Stage Cascade PII Detector with 11-Entity Core Taxonomy."""
from __future__ import annotations
import re
from dataclasses import dataclass
import torch
from gliner import GLiNER

@dataclass(frozen=True)
class Span:
    start: int
    end: int
    label: str
    text: str
    score: float = 1.0
    source: str = "stage1"

# Mathematical validators
V_D = (
    (0,1,2,3,4,5,6,7,8,9),(1,2,3,4,0,6,7,8,9,5),(2,3,4,0,1,7,8,9,5,6),(3,4,0,1,2,8,9,5,6,7),
    (4,0,1,2,3,9,5,6,7,8),(5,9,8,7,6,0,4,3,2,1),(6,5,9,8,7,1,0,4,3,2),(7,6,5,9,8,2,1,0,4,3),
    (8,7,6,5,9,3,2,1,0,4),(9,8,7,6,5,4,3,2,1,0),
)
V_P = (
    (0,1,2,3,4,5,6,7,8,9),(1,5,7,6,2,8,3,0,9,4),(5,8,0,3,7,9,6,1,4,2),(8,9,1,6,0,4,3,5,2,7),
    (9,4,5,3,1,2,6,8,7,0),(4,2,8,6,5,7,3,9,0,1),(2,7,9,3,8,0,6,4,1,5),(7,0,4,6,9,1,3,2,5,8),
)
def verhoeff_check(num: str) -> bool:
    clean = [int(c) for c in num if c.isdigit()]
    if not clean: return False
    c = 0
    for i, n in enumerate(reversed(clean)):
        c = V_D[c][V_P[i % 8][n]]
    return c == 0

def luhn_checksum(candidate: str) -> bool:
    d = [int(c) for c in candidate if c.isdigit()]
    return 13 <= len(d) <= 19 and sum(x if i % 2 == 0 else (x * 2 - 9 if x * 2 > 9 else x * 2) for i, x in enumerate(reversed(d))) % 10 == 0

def mod97_check(iban: str) -> bool:
    clean = iban.replace(" ", "").upper()
    return 15 <= len(clean) <= 34 and int("".join(str(ord(c) - 55) if c.isalpha() else c for c in clean[4:] + clean[:4])) % 97 == 1

def is_valid_ipv4(ip: str) -> bool:
    p = ip.split(".")
    return len(p) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in p)

def is_valid_phone(phone: str) -> bool:
    n = sum(c.isdigit() for c in phone)
    return 10 <= n <= 15

# Pre-compiled Stage 1 Regexes (8 Structured Entity Types)
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
API_KEY_RE = re.compile(
    r"\b(?:sk-(?:proj-|ant-|svcacct-|admin-)?[a-zA-Z0-9\-_]{20,}|AKIA[0-9A-Z]{16}|"
    r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}|AIza[0-9A-Za-z\-_]{35}|"
    r"xox[baprs]-[0-9a-zA-Z\-]{10,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}|SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}|"
    r"glpat-[A-Za-z0-9_\-]{20,}|npm_[A-Za-z0-9]{36}|shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}|sq0(?:atp|csp)-[A-Za-z0-9_\-]{22,43}|"
    r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,1000}|SK[0-9a-f]{32}|key-[0-9a-z]{32}|access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}|"
    r"dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}|A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}|"
    r"PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}|nfp_[A-Za-z0-9]{40}|vercel_[A-Za-z0-9]{24,}|"
    r"[0-9]{9,10}:[A-Za-z0-9_-]{35}|https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24,})\b"
)
AUTH_TOKEN_RE = re.compile(
    r"\b(?:eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}|"
    r"Bearer\s+[a-zA-Z0-9_\-\.=]{8,})\b|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"
)
PHONE_RE = re.compile(
    r"(?i)(?<!order)(?<!invoice)(?<!id)(?<!ticket)(?<!order\s)(?<!invoice\s)(?<!id\s)(?<!ticket\s)"
    r"(?<!order:\s)(?<!invoice:\s)(?<!id:\s)(?<!ticket:\s)(?<!order\s#\s)(?<!invoice\s#\s)"
    r"(?<!\d)(?:(?:\+?1[-.\s]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[-.\s]?[2-9]\d{2}[-.\s]?\d{4}|"
    r"(?:\+91[-.\s]?)?[6-9]\d{9}|\+\d{1,3}(?:[-.\s]?\d{1,4}){2,5})(?!\d)"
)
IPV4_CAND_RE = re.compile(r"(?<!\d)(?:\d{1,4}\.){3}\d{1,4}(?!\d)")
CC_CAND_RE = re.compile(r"(?<!\d)(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,7}|\d{4}[ -]\d{6}[ -]\d{5}|\d{13,19})(?!\d)")
SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
AADHAAR_RE = re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

TECH_ALLOWLIST = frozenset({
    "docker", "redis", "fastapi", "pytorch", "react", "aws", "postgres", "postgresql",
    "github", "kubernetes", "python", "javascript", "typescript", "linux", "ubuntu",
    "nginx", "openai", "langchain", "vllm", "ollama", "cuda", "onnx", "nextjs",
    "tailwind", "graphql", "kafka", "mongodb", "sqlite", "java", "go", "golang",
    "rust", "kotlin", "swift", "ruby", "php", "scala", "django", "flask", "spring",
    "express", "rails", "heroku", "vercel", "netlify", "cloudflare", "digitalocean",
    "supabase", "firebase", "stripe", "twilio", "datadog", "sentry", "grafana",
    "prometheus", "terraform", "ansible", "jenkins", "gitlab", "bitbucket", "npm",
    "yarn", "pnpm", "pip", "cargo", "maven", "gradle", "webpack", "vite", "babel",
    "eslint", "jest", "pytest", "numpy", "pandas", "scipy", "sklearn", "tensorflow",
    "keras", "huggingface", "transformers", "spacy",
})

PERSON_STOPWORDS = frozenset({
    "user", "users", "employee", "employees", "author", "authors", "name", "names",
    "username", "admin", "client", "customer", "owner", "sender", "recipient",
    "person", "self", "caller", "callee", "manager", "developer", "engineer",
    "alice_id", "bob_id", "you", "your", "we", "our", "they", "them", "their",
    "he", "she", "it", "this", "that", "these", "those",
})

CODE_CHARS = frozenset("_()[]{}:;/\\=$@")
SCHEMA_WORDS = frozenset({
    "production", "development", "staging", "prod", "dev", "test", "localhost",
    "api", "backend", "frontend", "database", "server", "client", "service", "origin",
})

def stage2_ok(text: str, label: str) -> bool:
    """Reject Stage 2 drift on code identifiers, tech names, and role words."""
    t = text.strip()
    if len(t) <= 2: return False
    low = t.lower()
    if low in TECH_ALLOWLIST or low in {"location", "organization", "person", "address", "user"}: return False
    if label in ("LOCATION", "ORGANIZATION") and low in SCHEMA_WORDS: return False
    if label == "LOCATION" and re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", low): return False
    if label == "ORGANIZATION" and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", t): return False
    if label == "PERSON" and low in PERSON_STOPWORDS: return False
    if label == "PERSON" and " " not in t and (len(t) > 25 or any(c.isdigit() for c in t) or sum(c.isupper() for c in t) / len(t) > 0.5): return False
    if any(ch in CODE_CHARS for ch in t) or (any(c.isdigit() for c in t) and "." in t): return False
    return True

def spans_overlap(s1: Span, s2: Span) -> bool:
    return max(s1.start, s2.start) < min(s1.end, s2.end)

LABEL_PRIORITY = {"API_KEY": 0, "AUTH_TOKEN": 0, "CREDIT_CARD": 0, "GOVT_ID": 0,
                  "IBAN_CRYPTO": 0, "EMAIL": 1, "PHONE": 1, "IP_ADDRESS": 1}

def _resolve_same_stage(spans: list[Span]) -> list[Span]:
    sorted_spans = sorted(spans, key=lambda s: (LABEL_PRIORITY.get(s.label, 2), -(s.end - s.start), -s.score, s.start))
    accepted: list[Span] = []
    for cand in sorted_spans:
        if not any(spans_overlap(cand, ex) for ex in accepted):
            accepted.append(cand)
    return accepted

def merge_adjacent_locations(spans: list[Span], text: str) -> list[Span]:
    if not spans: return []
    res: list[Span] = []
    i = 0
    while i < len(spans):
        curr = spans[i]
        while i + 1 < len(spans) and curr.label == "LOCATION" and spans[i+1].label == "LOCATION":
            nxt = spans[i+1]
            if text[curr.end:nxt.start] == ", ":
                curr = Span(curr.start, nxt.end, "LOCATION", text[curr.start:nxt.end], min(curr.score, nxt.score), curr.source)
                i += 1
            else:
                break
        res.append(curr)
        i += 1
    return res

def merge_spans(stage1_spans: list[Span], stage2_spans: list[Span]) -> list[Span]:
    s1 = _resolve_same_stage(stage1_spans)
    s2 = _resolve_same_stage([s for s in stage2_spans if not any(spans_overlap(s, ex) for ex in s1)])
    return sorted(s1 + s2, key=lambda s: s.start)

class CascadeEngine:
    def __init__(self, device: str | None = None, model_name: str = "urchade/gliner_small-v2.1", threshold: float = 0.5):
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.threshold = threshold
        self.gliner = GLiNER.from_pretrained(model_name)
        if hasattr(self.gliner, "to"): self.gliner.to(self.device)
        self.label_map = {"person": "PERSON", "organization": "ORGANIZATION", "location": "LOCATION"}

    def detect_stage1(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for m in EMAIL_RE.finditer(text): spans.append(Span(m.start(), m.end(), "EMAIL", m.group(), 1.0, "stage1"))
        for m in API_KEY_RE.finditer(text): spans.append(Span(m.start(), m.end(), "API_KEY", m.group(), 1.0, "stage1"))
        for m in AUTH_TOKEN_RE.finditer(text): spans.append(Span(m.start(), m.end(), "AUTH_TOKEN", m.group(), 1.0, "stage1"))
        for m in PHONE_RE.finditer(text):
            if is_valid_phone(m.group()): spans.append(Span(m.start(), m.end(), "PHONE", m.group(), 1.0, "stage1"))
        for m in IPV4_CAND_RE.finditer(text):
            if is_valid_ipv4(m.group()): spans.append(Span(m.start(), m.end(), "IP_ADDRESS", m.group(), 1.0, "stage1"))
        for m in CC_CAND_RE.finditer(text):
            if luhn_checksum(m.group()): spans.append(Span(m.start(), m.end(), "CREDIT_CARD", m.group(), 1.0, "stage1"))
        for m in SSN_RE.finditer(text): spans.append(Span(m.start(), m.end(), "GOVT_ID", m.group(), 1.0, "stage1"))
        for m in PAN_RE.finditer(text): spans.append(Span(m.start(), m.end(), "GOVT_ID", m.group(), 1.0, "stage1"))
        for m in AADHAAR_RE.finditer(text):
            if verhoeff_check(m.group()): spans.append(Span(m.start(), m.end(), "GOVT_ID", m.group(), 1.0, "stage1"))
        for m in ETH_RE.finditer(text): spans.append(Span(m.start(), m.end(), "IBAN_CRYPTO", m.group(), 1.0, "stage1"))
        for m in IBAN_RE.finditer(text):
            if mod97_check(m.group()): spans.append(Span(m.start(), m.end(), "IBAN_CRYPTO", m.group(), 1.0, "stage1"))
        return _resolve_same_stage(spans)

    def detect_stage2(self, text: str) -> list[Span]:
        preds = self.gliner.predict_entities(text, ["person", "organization", "location"], threshold=self.threshold)
        raw_spans: list[Span] = []
        for p in preds:
            lbl = self.label_map.get(p["label"], p["label"].upper())
            if not stage2_ok(p["text"], lbl): continue
            raw_spans.append(Span(p["start"], p["end"], lbl, p["text"], float(p.get("score", 0.0)), "stage2"))
        resolved = _resolve_same_stage(raw_spans)
        resolved_sorted = sorted(resolved, key=lambda s: s.start)
        return merge_adjacent_locations(resolved_sorted, text)

    def detect(self, text: str) -> list[Span]:
        return merge_spans(self.detect_stage1(text), self.detect_stage2(text))
