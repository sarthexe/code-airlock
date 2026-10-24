"""build_benchmarks.py - Deterministic 4-suite, 2,000-row developer privacy benchmark (seed=42)."""
from __future__ import annotations
import json, os, random, string
from engine import verhoeff_check

R = random.Random(42)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmarks")
LABELS = ["API_KEY", "AUTH_TOKEN", "CREDIT_CARD", "EMAIL", "PHONE", "IP_ADDRESS",
          "GOVT_ID", "IBAN_CRYPTO", "PERSON", "ORGANIZATION", "LOCATION"]
AL = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
UP = string.ascii_uppercase + string.digits
FIRST = ["Aarav", "Sofia", "Liam", "Mei", "Omar", "Elena", "Kwame", "Priya", "Mateo", "Yuki",
         "Chloe", "Dmitri", "Amara", "Noah", "Leila", "Hiroshi", "Fatima", "Lucas", "Anika", "Diego"]
LAST = ["Sharma", "Garcia", "Okafor", "Chen", "Haddad", "Petrova", "Mensah", "Iyer", "Rossi", "Tanaka",
        "Dubois", "Volkov", "Diallo", "Bennett", "Nasser", "Sato", "Rahman", "Silva", "Kapoor", "Torres"]
ORGS = ["Acme Cloud", "Northwind Labs", "Umbrella Health", "Vanguard Security", "Quantum Dynamics",
        "Apex Financial", "Meridian Bank", "Galactic Transport", "Cyberdyne Systems", "Initech"]
CITIES = [("Austin", "US"), ("Bangalore", "IN"), ("Berlin", "DE"),
          ("Paris", "FR"), ("Tokyo", "JP"), ("Lagos", "NG"),
          ("Sao Paulo", "BR"), ("Toronto", "CA"), ("Dubai", "AE"),
          ("London", "GB")]
DOMAINS = ["acme.io", "northwind.dev", "quantum-soft.io", "apex-fin.com", "initech.dev"]

def a(n, cs=AL): return "".join(R.choice(cs) for _ in range(n))
def luhn(s):
    t = 0
    for i, ch in enumerate(reversed(s)):
        d = int(ch)
        if i % 2: d = d * 2 - 9 if d * 2 > 9 else d * 2
        t += d
    return t % 10 == 0
def card():
    base = "4" + "".join(R.choice(string.digits) for _ in range(14))
    return next(base + c for c in string.digits if luhn(base + c))
def bad_card():
    while True:
        s = "5" + "".join(R.choice(string.digits) for _ in range(15))
        if not luhn(s): return s
def govt():
    base = str(R.randint(2, 9)) + "".join(R.choice(string.digits) for _ in range(10))
    d = next(base + c for c in string.digits if verhoeff_check(base + c))
    return f"{d[:4]} {d[4:8]} {d[8:]}"
def bad_govt():
    return next("0000 0000 000" + c for c in string.digits if not verhoeff_check("0000 0000 000" + c))
def iban():
    bban = "".join(R.choice(string.digits) for _ in range(18))
    return f"DE{98 - int(bban + '131400') % 97:02d}{bban}"
def bad_iban():
    s = iban()
    return s[:-1] + str((int(s[-1]) + 1) % 10)
def ip(): return f"{R.randint(1,223)}.{R.randint(0,255)}.{R.randint(0,255)}.{R.randint(1,254)}"
def phone(): return R.choice([f"+1-{R.randint(200,999)}-{R.randint(200,999)}-{R.randint(1000,9999)}",
                              f"+44 20 {R.randint(1000,9999)} {R.randint(1000,9999)}",
                              f"+91 {R.randint(6,9)}{R.randint(100000000,999999999)}"])
def email():
    return f"{R.choice(FIRST).lower()}.{R.choice(LAST).lower()}{R.randint(1,99)}@{R.choice(DOMAINS)}"
def person(): return f"{R.choice(FIRST)} {R.choice(LAST)}"
def org(): return R.choice(ORGS)
def loc(): return R.choice(CITIES)[0]
def jwt(): return f"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.{a(24)}"
def pem(): return f"-----BEGIN RSA PRIVATE KEY-----\n{a(48)}\n-----END RSA PRIVATE KEY-----"

def api():
    return R.choice([
        lambda: "sk-proj-" + a(32), lambda: "sk-ant-api03-" + a(80) + "AA",
        lambda: "AKIA" + a(16, UP), lambda: "ghp_" + a(36),
        lambda: "github_pat_" + a(60), lambda: "AIza" + a(35),
        lambda: "xoxb-test-" + a(20), lambda: "sk_live_" + a(32),
        lambda: "SG." + a(22) + "." + a(43), lambda: "glpat-" + a(24),
        lambda: "npm_" + a(36), lambda: "shpat_" + a(32, HEX),
        lambda: "sq0atp-" + a(22), lambda: "pypi-AgEIcHlwaS5vcmc" + a(50),
        lambda: "SK" + a(32, HEX), lambda: "key-" + a(32, HEX),
        lambda: "access_token$production$" + a(16, HEX) + "$" + a(32, HEX),
        lambda: "dt0c01." + a(24, UP) + "." + a(64, UP),
        lambda: "A3-" + a(6, UP) + "-" + a(11, UP) + "-" + a(5, UP) + "-" + a(5, UP) + "-" + a(5, UP),
        lambda: "PMAK-" + a(24) + "-" + a(34), lambda: "nfp_" + a(40), lambda: "vercel_" + a(24),
        lambda: "123456789:" + a(35), lambda: "https://hooks.slack.com/services/T" + a(8) + "/B" + a(8) + "/" + a(24)
    ])()
def auth(): return R.choice([jwt, lambda: "Bearer " + a(32)])()
def val(label):
    return {"API_KEY": api, "AUTH_TOKEN": auth, "CREDIT_CARD": card, "EMAIL": email,
            "PHONE": phone, "IP_ADDRESS": ip, "GOVT_ID": govt, "IBAN_CRYPTO": iban,
            "PERSON": person, "ORGANIZATION": org, "LOCATION": loc}[label]()

SENT = {
 "API_KEY": ["Rotate the leaked key {V} before the next deploy.", "The staging job rejected {V} with a 401.", "A secret scanner flagged {V} in the build log."],
 "AUTH_TOKEN": ["The bearer token {V} expired mid-request.", "Refresh the session token {V} before retrying.", "The auth header still contains {V}."],
 "CREDIT_CARD": ["Billing failed for card {V} during checkout.", "The refund to card {V} was declined.", "Charge {V} and email the receipt."],
 "EMAIL": ["Escalate to {V} if the retry also fails.", "Send the stack trace to {V}.", "The on-call rota lists {V} for tonight."],
 "PHONE": ["Call the on-call number {V} immediately.", "The pager {V} is not responding.", "Update {V} in the incident channel."],
 "IP_ADDRESS": ["The health check from {V} timed out.", "Block {V} at the edge proxy.", "The replica at {V} is unreachable."],
 "GOVT_ID": ["KYC rejected national ID {V}.", "The audit log contains ID {V}.", "Verify applicant ID {V} before payout."],
 "IBAN_CRYPTO": ["The payout to IBAN {V} was reversed.", "Reconcile the transfer to {V}.", "The treasury wallet {V} needs review."],
 "PERSON": ["The incident was opened by {V}.", "Ask {V} to approve the migration.", "The PR was authored by {V}."],
 "ORGANIZATION": ["The production cluster belongs to {V}.", "The invoice belongs to {V}.", "Migrate the bucket owned by {V}."],
 "LOCATION": ["The primary region is {V}.", "Replicate the database to {V}.", "The edge node in {V} is degraded."]
}
INTRO = ["Debug this production issue:", "Review this incident report:", "Triage this support escalation:",
         "Investigate this failed deployment:", "Summarize this monitoring alert:"]
OUTRO = ["Return a concise root-cause analysis.", "Suggest the safest remediation.",
         "Explain the failure and the next step.", "List the commands needed to fix it."]
TECH = ["FastAPI", "Docker", "Kubernetes", "Redis", "Postgres", "PyTorch", "AWS", "Heroku",
        "React", "Terraform", "Kafka", "MongoDB", "Nginx", "Grafana", "Prometheus", "Next.js"]
VARS = ["user", "employee", "author", "request", "payload", "session", "order", "config"]

def fill(tmpl, items):
    text, spans = tmpl, []
    for i, (label, value) in enumerate(items):
        ph = f"[[{i}]]"; j = text.index(ph)
        text = text[:j] + value + text[j + len(ph):]
        spans.append({"start": j, "end": j + len(value), "label": label, "text": value})
    return text, sorted(spans, key=lambda s: s["start"])

def row(suite, category, text, spans, meta=None):
    return {"id": f"{suite}-{len(ROWS[suite]):04d}", "suite": suite, "category": category,
            "text": text, "spans": spans, "meta": meta or {}}

ROWS = {s: [] for s in ("dev_prompts", "git_leaks", "mcp_configs", "adversarial_sse")}

def dev_pos(i):
    labels = [LABELS[(i * 4 + j) % 11] for j in range(4)]
    body = " ".join(R.choice(SENT[l]).replace("{V}", f"[[{j}]]") for j, l in enumerate(labels))
    text, spans = fill(f"{R.choice(INTRO)} {body} {R.choice(OUTRO)}",
                       [(labels[j], val(labels[j])) for j in range(4)])
    return row("dev_prompts", "positive", text, spans, {"labels": labels})

def dev_clean(i):
    return row("dev_prompts", "clean",
               f"You are a helpful coding assistant. Build a {R.choice(TECH)} service with "
               f"{R.choice(TECH)} and {R.choice(TECH)}. The {R.choice(VARS)} object is internal; "
               f"add tests and document the {R.choice(VARS)} schema.", [], {"project": i})

def dev_neg(i):
    items = [bad_card(), bad_govt(), bad_iban(), "192.168.1.300", "v1.2.3.4",
             "550e8400-e29b-41d4-a716-446655440000", "Authorization: Bearer token"]
    picked = R.sample(items, 3)
    text = f"Validate these values during migration: {picked[0]}, {picked[1]}, and {picked[2]}."
    return row("dev_prompts", "hard_negative", text, [], {"checks": picked})

KEY = {"API_KEY": "api_key", "AUTH_TOKEN": "auth_token", "CREDIT_CARD": "billing_card",
       "GOVT_ID": "national_id", "IBAN_CRYPTO": "payout_iban", "EMAIL": "owner_email",
       "PHONE": "oncall_phone", "IP_ADDRESS": "upstream_ip", "PERSON": "owner",
       "ORGANIZATION": "organization", "LOCATION": "region"}

def git_pos(i):
    labels = [LABELS[(i * 4 + j + 3) % 11] for j in range(4)]
    lines = "\n".join(f"+{KEY[l]}: \"[[{j}]]\"" for j, l in enumerate(labels))
    text, spans = fill(
        f"commit {a(40, HEX)}\nDate:   Sat Oct 24 14:55:00 2026 +0000\n\n"
        f"    chore: update production configuration\n\ndiff --git a/config/production.yaml b/config/production.yaml\n"
        f"new file mode 100644\n--- /dev/null\n+++ b/config/production.yaml\n@@ -0,0 +1,8 @@\n"
        f"+service: payments\n{lines}\n+retries: 3\n", [(labels[j], val(labels[j])) for j in range(4)])
    return row("git_leaks", "positive", text, spans, {"artifact": "diff"})

def git_neg(i):
    items = [a(40, HEX), "sha256:" + a(64, HEX), "550e8400-e29b-41d4-a716-446655440000",
             R.choice(["us-east-1", "eu-west-1", "ap-south-1"]), "ssh-rsa " + a(80),
             "v1.2.3.4", bad_card(), bad_govt(), bad_iban()]
    picked = R.sample(items, 4)
    text = (f"diff --git a/CHANGELOG.md b/CHANGELOG.md\n--- a/CHANGELOG.md\n+++ b/CHANGELOG.md\n"
            f"@@ -1,3 +1,6 @@\n # Release Notes\n" + "\n".join(f"+ {p}" for p in picked) + "\n")
    return row("git_leaks", "hard_negative", text, [], {"checks": picked})

def mcp_json(i, positive):
    labels = [LABELS[(i * 4 + j + 5) % 11] for j in range(4)] if positive else []
    obj = {"service": "payments", "environment": "production", "retries": 3}
    if positive:
        obj.update({KEY[l]: f"[[{j}]]" for j, l in enumerate(labels)})
    text, spans = fill(json.dumps(obj, indent=2), [(labels[j], val(labels[j])) for j in range(len(labels))])
    return row("mcp_configs", "positive" if positive else "clean", text, spans, {"format": "json"})

def mcp_env(i, positive):
    labels = [LABELS[(i * 4 + j + 7) % 11] for j in range(4)] if positive else []
    lines = ["SERVICE=payments", "ENVIRONMENT=production"]
    lines += [f"{KEY[l].upper()}=[[{j}]]" for j, l in enumerate(labels)]
    text, spans = fill("\n".join(lines), [(labels[j], val(labels[j])) for j in range(len(labels))])
    return row("mcp_configs", "positive" if positive else "clean", text, spans, {"format": "env"})

def mcp_yaml(i, positive):
    labels = [LABELS[(i * 4 + j + 9) % 11] for j in range(4)] if positive else []
    lines = ["service: payments", "environment: production"]
    lines += [f"{KEY[l]}: \"[[{j}]]\"" for j, l in enumerate(labels)]
    text, spans = fill("\n".join(lines), [(labels[j], val(labels[j])) for j in range(len(labels))])
    return row("mcp_configs", "positive" if positive else "clean", text, spans, {"format": "yaml"})

ADV_LABELS = ["API_KEY", "AUTH_TOKEN", "CREDIT_CARD", "EMAIL", "PHONE", "IP_ADDRESS", "GOVT_ID", "IBAN_CRYPTO", "PERSON"]

def adv_collision(i):
    labels = [ADV_LABELS[(i * 2 + j) % len(ADV_LABELS)] for j in range(2)]
    text, spans = fill(
        f"template <typename T> void audit(T value) {{ if (x < 10 && y > 20) {{ log(\"[[0]]\"); }} "
        f"auto p = std::vector<std::pair<int,int>>{{}}; cat << 'EOF' < input.txt; // [[1]]",
        [(labels[j], val(labels[j])) for j in range(2)])
    return row("adversarial_sse", "positive", text, spans, {"kind": "code_collision"})

def adv_malformed(i):
    labels = [ADV_LABELS[(i * 3 + j) % len(ADV_LABELS)] for j in range(2)]
    text, spans = fill(
        f"<PERSON_999> and <UNKNOWN_TAG_1> appear before <PERSON_777 with real values "
        f"[[0]] and [[1]] inside <outer <PERSON_999>>.", [(labels[j], val(labels[j])) for j in range(2)])
    return row("adversarial_sse", "positive", text, spans, {"kind": "malformed_tag"})

def adv_dense(i):
    p, e, k = person(), email(), api()
    turns = R.randint(3, 5)
    body = " ".join(f"Turn {n}: [[{n*3}]] ([[{n*3+1}]]) retried key [[{n*3+2}]]." for n in range(turns))
    items = [(lbl, v) for _ in range(turns) for lbl, v in (("PERSON", p), ("EMAIL", e), ("API_KEY", k))]
    text, spans = fill(body, items)
    return row("adversarial_sse", "positive", text, spans, {"kind": "dense", "turns": turns})

for i in range(1000):
    if i < 600: ROWS["dev_prompts"].append(dev_pos(i))
    elif i < 900: ROWS["dev_prompts"].append(dev_clean(i))
    else: ROWS["dev_prompts"].append(dev_neg(i))
for i in range(500):
    if i < 350: ROWS["git_leaks"].append(git_pos(i))
    else: ROWS["git_leaks"].append(git_neg(i))
for i in range(250):
    if i < 80: ROWS["mcp_configs"].append(mcp_json(i, True))
    elif i < 100: ROWS["mcp_configs"].append(mcp_json(i, False))
    elif i < 160: ROWS["mcp_configs"].append(mcp_env(i, True))
    elif i < 175: ROWS["mcp_configs"].append(mcp_env(i, False))
    elif i < 235: ROWS["mcp_configs"].append(mcp_yaml(i, True))
    else: ROWS["mcp_configs"].append(mcp_yaml(i, False))
for i in range(250):
    if i < 100: ROWS["adversarial_sse"].append(adv_collision(i))
    elif i < 175: ROWS["adversarial_sse"].append(adv_malformed(i))
    else: ROWS["adversarial_sse"].append(adv_dense(i))

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for suite, rows in ROWS.items():
        with open(os.path.join(OUT, f"{suite}.jsonl"), "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        print(f"{suite}: {len(rows)} rows")
    print("total:", sum(len(r) for r in ROWS.values()))
