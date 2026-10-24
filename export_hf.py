"""export_hf.py - Export a benchmark JSONL to Hugging Face Datasets Hub."""
import argparse, json, os
from datasets import Dataset
from huggingface_hub import whoami


def export_hub(repo_id: str, filename: str = "dev_benchmark.jsonl", token: str | None = None) -> None:
    token = token or os.environ.get("HF_TOKEN")
    me = whoami(token=token)["name"]
    namespace, _, name = repo_id.rpartition("/")
    if namespace and namespace != me:
        print(f"Token belongs to {me!r}, not {namespace!r}; redirecting to {me}/{name}")
        repo_id = f"{me}/{name}"
    elif not namespace:
        repo_id = f"{me}/{repo_id}"
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    with open(path, encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle]
    ds = Dataset.from_list(rows)
    print(f"Loaded {len(ds)} rows from {filename}")
    ds.push_to_hub(repo_id, token=token)
    print(f"Successfully published dataset to https://huggingface.co/datasets/{repo_id}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export benchmark to Hugging Face Hub")
    parser.add_argument("--repo-id", required=True, help="Hugging Face dataset name or user/name")
    parser.add_argument("--file", default="dev_benchmark.jsonl", help="Benchmark JSONL to export")
    parser.add_argument("--token", default=None, help="Hugging Face write token (or set HF_TOKEN env var)")
    args = parser.parse_args()
    export_hub(args.repo_id, args.file, args.token)
