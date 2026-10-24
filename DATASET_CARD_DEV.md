---
pretty_name: Code-Airlock Developer Privacy Benchmark
language:
  - en
license: mit
task_categories:
  - token-classification
tags:
  - privacy
  - pii
  - secrets
  - code
  - mcp
  - benchmark
  - developer-tools
size_categories:
  - n<1K
---

# Code-Airlock Developer Privacy Benchmark

A developer-native benchmark for evaluating PII and secret redaction in coding
agents, MCP servers, and LLM gateways. Unlike conversational PII datasets, these
rows are real developer artifacts: `.env` files, Docker/Kubernetes/Terraform
configs, cURL pipelines, production tracebacks, SDK initializers, and hard
negative code.

## Composition

| Metric | Value |
| :--- | ---: |
| Rows | 56 |
| Ground-truth spans | 112 |
| PII rows | 23 |
| Clean / hard-negative rows | 33 |
| Entity types | 11 |

Coverage includes `API_KEY`, `AUTH_TOKEN`, `CREDIT_CARD`, `EMAIL`, `PHONE`,
`IP_ADDRESS`, `GOVT_ID`, `IBAN_CRYPTO`, `PERSON`, `ORGANIZATION`, `LOCATION`.

Hard negatives include C++ templates, bitwise operators, shell redirection,
Git SHAs, Docker digests, UUIDs, SemVer, invalid IPv4 octets, non-Luhn cards,
non-Verhoeff national IDs, and non-MOD-97 IBANs.

## Fields

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | string | Row identifier |
| `source` | string | Source family (`config`, `cli`, `logs`, `code`, `hard_neg`, …) |
| `tags` | list[string] | Row tags |
| `text` | string | Developer prompt / code / log content |
| `entities` | list[object] | Ground-truth spans: `label`, `start`, `end`, `text` |
| `negatives` | list[object] | Values that must **not** be detected as the given label |
| `expect_empty` | bool | True when the row should produce zero detections |

## Evaluation

```bash
python benchmark.py dev_benchmark.jsonl
```

Reference result for `code-airlock` v0.1.0:

```text
Strict P / R / F1 : 97.2% / 94.6% / 95.9%
Clean-code false positives : 0 / 33 rows
Hard negatives : 22 / 22
Round-trip invariant : 56 / 56
```

## Usage

```python
from datasets import load_dataset

ds = load_dataset("sarthax/code-airlock-dev-benchmark", split="train")
print(ds[0])
```

## License

MIT. All credentials are synthetic test values; no live secrets are included.

## Links

- Code: https://github.com/sarthexe/code-airlock
- Real Git-leak suite: https://huggingface.co/datasets/sarthax/code-airlock-git-leaks
