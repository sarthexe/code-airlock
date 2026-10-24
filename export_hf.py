"""export_hf.py - Publish the 4-split Code-Airlock benchmark to Hugging Face."""
import argparse, json, os, subprocess, sys
from datasets import Dataset, DatasetDict, Features, Sequence, Value
from huggingface_hub import CommitOperationAdd, HfApi, whoami

BASE = os.path.dirname(os.path.abspath(__file__))
SUITES = ["dev_prompts", "git_leaks", "mcp_configs", "adversarial_sse"]
DISCLAIMER = (
    "> **Disclaimer:** All credentials, secrets, and PII spans in this dataset are "
    "synthetic test fixtures generated for DLP / privacy-gateway evaluation. "
    "They are not live credentials and do not identify real people.\n"
)
META = Features({
    "artifact": Value("string"), "checks": Sequence(Value("string")),
    "format": Value("string"), "kind": Value("string"),
    "labels": Sequence(Value("string")), "project": Value("int64"),
    "turns": Value("int64"),
})

def load(split):
    with open(os.path.join(BASE, "benchmarks", f"{split}.jsonl"), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

def normalize(row):
    meta = row.get("meta") or {}
    out = dict(row)
    out["meta"] = {
        "artifact": meta.get("artifact", ""), "checks": meta.get("checks", []),
        "format": meta.get("format", ""), "kind": meta.get("kind", ""),
        "labels": meta.get("labels", []), "project": meta.get("project", -1),
        "turns": meta.get("turns", -1),
    }
    return out

def build_split(split):
    ds = Dataset.from_list([normalize(r) for r in load(split)])
    features = ds.features.copy()
    features["meta"] = META
    return ds.cast(features)

def build_data():
    return DatasetDict({s: build_split(s) for s in SUITES})

def make_card(data):
    rows = {s: len(ds) for s, ds in data.items()}
    spans = {s: sum(len(r["spans"]) for r in ds) for s, ds in data.items()}
    lines = [
        "---", "pretty_name: Code-Airlock PII & Secret Benchmark", "language:", "  - en",
        "license: mit", "task_categories:", "  - token-classification", "tags:",
        "  - privacy", "  - pii", "  - secrets", "  - mcp", "  - code", "size_categories:",
        "  - n<10K", "---", "", "# Code-Airlock PII & Secret Benchmark", "", DISCLAIMER, "",
        f"A unified {sum(rows.values()):,}-row developer privacy benchmark with four stratified splits.", "",
        "## Splits", "", "| Split | Rows | Ground-truth spans |", "| :--- | ---: | ---: |",
    ]
    lines += [f"| `{s}` | {rows[s]} | {spans[s]} |" for s in SUITES]
    lines += [
        "", "## Schema", "", "`id`, `suite`, `category` (`positive` / `clean` / `hard_negative`), "
        "`text`, `spans` (`start`, `end`, `label`, `text`), `meta`.", "",
        "## Usage", "", "```python", "from datasets import load_dataset",
        'ds = load_dataset("sarthax/pii-airlock-bench")', "print(ds)", "```", "",
        "## Links", "", "- Code: https://github.com/sarthexe/code-airlock",
        "- Results: https://github.com/sarthexe/code-airlock/blob/main/BENCHMARK_RESULTS.md", "",
    ]
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-id", default="sarthexe/pii-airlock-bench")
    parser.add_argument("--token", default=None)
    args = parser.parse_args()
    token = args.token or os.environ.get("HF_TOKEN")
    missing = [s for s in SUITES if not os.path.exists(os.path.join(BASE, "benchmarks", f"{s}.jsonl"))]
    if missing:
        subprocess.run([sys.executable, os.path.join(BASE, "build_benchmarks.py")], check=True)
    me = whoami(token=token)["name"]
    namespace, _, name = args.repo_id.rpartition("/")
    repo_id = f"{me}/{name}" if namespace != me else args.repo_id
    data = build_data()
    data.push_to_hub(repo_id, token=token)
    HfApi(token=token).create_commit(
        repo_id=repo_id, repo_type="dataset", commit_message="Add dataset card",
        operations=[CommitOperationAdd(path_in_repo="README.md", path_or_fileobj=make_card(data).encode())],
    )
    print(f"Published 4 splits to https://huggingface.co/datasets/{repo_id}")

if __name__ == "__main__":
    main()
