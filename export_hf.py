"""export_hf.py - Export dev_benchmark.jsonl to Hugging Face Datasets Hub."""
import argparse, json, os
from datasets import Dataset


def export_hub(repo_id: str, token: str | None = None) -> None:
    path = os.path.join(os.path.dirname(__file__), "dev_benchmark.jsonl")
    with open(path, encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle]
    ds = Dataset.from_list(rows)
    print(f"Loaded {len(ds)} rows from dev_benchmark.jsonl")
    ds.push_to_hub(repo_id, token=token)
    print(f"Successfully published dataset to https://huggingface.co/datasets/{repo_id}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export benchmark to Hugging Face Hub")
    parser.add_argument("--repo-id", required=True, help="Hugging Face repo id (e.g. sarthexe/code-airlock-dev-eval)")
    parser.add_argument("--token", default=None, help="Hugging Face write token (or set HF_TOKEN env var)")
    args = parser.parse_args()
    export_hub(args.repo_id, args.token or os.environ.get("HF_TOKEN"))
