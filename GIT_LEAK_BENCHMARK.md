# Git-Leak Benchmark (`git_leak_benchmark.jsonl`)

This suite measures `code-airlock` against **real Git artifacts** and the
secret formats tracked by [Gitleaks](https://github.com/gitleaks/gitleaks).

**Published dataset:** https://huggingface.co/datasets/sarthax/code-airlock-git-leaks

## Composition

| Group | Rows | What it contains |
| :--- | ---: | :--- |
| Real Gitleaks fixtures | 2 | Actual `git show` / `git diff --cached` output from Gitleaks' own fixture repositories, including a committed AWS key and author PII. |
| Git diff / log / stash / config | 9 | `.env` additions, `.git/config` remote URLs with embedded PATs, commit trailers, Terraform diffs, Kubernetes secrets, Docker Compose stashes. |
| Gitleaks long-tail formats | 22 | Stripe, SendGrid, Square, Shopify, PyPI, Twilio, Mailgun, PayPal, Dynatrace, npm, GitLab, Slack webhooks, 1Password, Facebook, Twitter, Heroku, Mailchimp, Picatic, Sidekiq, AWS secret keys, Discord, Telegram, Postman, Netlify, Vercel. |
| Git-specific hard negatives | 3 | Diffs with commit SHAs, Docker digests, UUIDs, SemVer, invalid IPs, non-Luhn cards, non-Verhoeff IDs, non-MOD-97 IBANs, C++ templates and bitwise operators. |
| **Total** | **36** | **61 ground-truth spans**, 3 hard-negative rows. |

## Results (strict exact-span matching)

```
Rows / PII rows / spans :   36 / 33 / 61
Overall P / R / F1      : 100.0% / 88.5% / 93.9%
Hard negatives          :   8 / 8
Round-trip invariant     :  36 / 36
```

| Entity | P / R / F1 | GT |
| :--- | :---: | ---: |
| `API_KEY` | 100 / **81** / 90 | 37 |
| `AUTH_TOKEN` | 100 / 100 / 100 | 1 |
| `EMAIL` | 100 / 100 / 100 | 8 |
| `PHONE` | 100 / 100 / 100 | 1 |
| `IP_ADDRESS` | 100 / 100 / 100 | 4 |
| `PERSON` | 100 / 100 / 100 | 9 |
| `ORGANIZATION` | 100 / 100 / 100 | 1 |
| `CREDIT_CARD`, `GOVT_ID`, `IBAN_CRYPTO`, `LOCATION` | no positive GT (hard-negative checks only) | 0 |

## Remaining false negatives (honest known gaps)

These require **keyword context** around the value, not just a token shape:

- `facebook...` 32-hex secrets
- `twitter...` 35–44 char secrets
- `heroku...<uuid>`
- Mailchimp `...-us12`
- Sidekiq `BUNDLE_GEMS__CONTRIBSYS__COM = "<8>:<8>"`
- AWS `aws_secret_access_key = "<40>"` (the value alone has no prefix)
- Discord 64-hex bot tokens

Adding these safely needs a context-aware rule (keyword + captured value span),
which would exceed the current 200-line engine budget.

## Reproduce

```bash
# 1. Fetch the Gitleaks fixture corpus (small, depth-1 clone)
git clone --depth 1 https://github.com/gitleaks/gitleaks.git .git_leaks/gitleaks

# 2. Generate (the generator ships with the Hugging Face dataset because it
#    embeds format-valid dummy credentials that GitHub Push Protection blocks)
python build_git_leak_benchmark.py

# 3. Evaluate
python benchmark.py git_leak_benchmark.jsonl
```

The generated file is deliberately **not committed**: it contains format-valid
credentials that GitHub Push Protection (correctly) treats as secrets. Publish
it to Hugging Face with `export_hf.py` instead:

```bash
python export_hf.py --repo-id sarthax/code-airlock-git-leaks --file git_leak_benchmark.jsonl --card DATASET_CARD_GIT.md
```
