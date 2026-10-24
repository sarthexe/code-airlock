---
pretty_name: Code-Airlock Git-Leak Benchmark
language:
  - en
license: mit
task_categories:
  - token-classification
tags:
  - privacy
  - pii
  - secrets
  - git
  - gitleaks
  - mcp
  - benchmark
size_categories:
  - n<1K
---

# Code-Airlock Git-Leak Benchmark

A real-Git-artifact benchmark for secret and PII redaction in coding agents.
Rows are actual `git show`, `git diff`, `git stash show`, and `.git/config`
outputs, including fixtures from the [Gitleaks](https://github.com/gitleaks/gitleaks)
test corpus.

## Composition

| Metric | Value |
| :--- | ---: |
| Rows | 36 |
| Ground-truth spans | 61 |
| Real Gitleaks fixtures | 2 |
| Git diff / log / stash / config | 9 |
| Gitleaks long-tail formats | 22 |
| Git hard negatives | 3 |

Long-tail formats include Stripe, SendGrid, Square, Shopify, PyPI, Twilio,
Mailgun, PayPal, Dynatrace, npm, GitLab, Slack webhooks, 1Password, Facebook,
Twitter, Heroku, Mailchimp, Picatic, Sidekiq, AWS secret keys, Discord,
Telegram, Postman, Netlify, and Vercel.

Hard negatives cover commit SHAs, Docker digests, UUIDs, SemVer, invalid IPv4,
non-Luhn cards, non-Verhoeff IDs, non-MOD-97 IBANs, C++ templates, and bitwise
operators.

## Fields

Identical to the developer suite: `id`, `source`, `tags`, `text`, `entities`,
`negatives`, `expect_empty`.

## Evaluation

```bash
python benchmark.py git_leak_benchmark.jsonl
```

Reference result for `code-airlock` v0.1.0:

```text
Strict P / R / F1 : 100.0% / 88.5% / 93.9%
API_KEY           : 100% / 81% / 90%
Hard negatives : 8 / 8
Round-trip invariant : 36 / 36
```

Remaining false negatives are contextual long-tail tokens (Facebook, Twitter,
Heroku, Mailchimp, Sidekiq, AWS secret keys, Discord) that need keyword-aware
rules rather than token-shape regexes.

## Usage

```python
from datasets import load_dataset

ds = load_dataset("sarthax/code-airlock-git-leaks", split="train")
print(ds[0])
```

## Safety

All values are **format-valid dummy credentials** generated for testing. No live
secrets or real people are included; the Gitleaks fixture values are already
public test fixtures.

## Links

- Code: https://github.com/sarthexe/code-airlock
- Developer suite: https://huggingface.co/datasets/sarthax/code-airlock-dev-benchmark
