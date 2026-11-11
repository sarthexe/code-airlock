# Security Policy

`code-airlock` is a local privacy layer for developer prompts, files, and LLM
traffic. Detection is best-effort: it reduces exposure, but it is not a
guarantee that every secret or PII span is found. Do not treat it as a
replacement for secret managers, scoped credentials, or provider-side DLP.

## Supported versions

| Version | Supported |
| :--- | :---: |
| `0.1.x` | Yes |
| `< 0.1` | No |

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability that could expose
secrets or weaken redaction.

Use GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Select **Advisories** → **Report a vulnerability**.
3. Include reproduction steps, affected version/commit, and the expected vs.
   actual behavior.

You should receive an acknowledgement within 72 hours. Please allow time for a
fix and coordinated disclosure before publishing details.

## Threat model (summary)

- Stage 1 regex/checksum rules and Stage 2 GLiNER run locally; detection does
  not make network calls.
- The OpenAI-compatible proxy forwards only the scrubbed payload upstream and
  rehydrates locally.
- The session vault is in-memory and process-scoped; restarting the MCP server
  invalidates old tokens by design.
- The MCP tools never return raw vault values from `airlock_vault_status`.
- Known gaps include contextual SaaS tokens (e.g. some Heroku/Mailchimp
  formats), PEM bodies beyond the header line, and statistical NER misses.

## Hardening checklist

- Bind the proxy to `127.0.0.1`; never expose it to an untrusted network.
- Keep `.env`, vault exports, and `secrets.out.json` out of version control.
- Rotate any credential that may have transited an unredacted path.
- Pin dependencies in production and review upstream security advisories.
