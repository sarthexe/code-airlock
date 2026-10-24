# Code-Airlock: Supported Identity Taxonomy

`code-airlock` uses a **2-Stage Hybrid Cascade** to redact and rehydrate 11 core categories of sensitive data. 

**Design Principle:** Deterministic patterns and mathematical checksums (Stage 1) never touch a neural network, and unstructured human context (Stage 2) is filtered through a technical allowlist to prevent false positives on developer prompts.

---

## Stage 1: Deterministic Fast-Pass (`< 0.05 ms`)

Stage 1 executes pre-compiled regular expressions paired with zero-allocation algorithmic validators. Stage 1 matches **always override** Stage 2 on overlapping character spans.

| Token Tag | Target Identities | Validation / Checksum Mechanism |
| :--- | :--- | :--- |
| `<API_KEY_n>` | OpenAI (`sk-`), Anthropic (`sk-ant-`), AWS (`AKIA`), GitHub (`ghp_`, `github_pat_`), Google (`AIza`), Slack (`xoxb-`) | Prefix signature + strict character-class & length bounds |
| `<AUTH_TOKEN_n>` | JSON Web Tokens (JWT), Bearer headers, SSH/RSA/EC Private Keys | 3-part Base64URL header/payload/signature check (`eyJ...`); PEM block matching |
| `<CREDIT_CARD_n>` | Visa, Mastercard, Amex, RuPay, Discover (13–19 digits) | Separator normalization + **Luhn Checksum Algorithm** (blocks false positives on 16-digit order/invoice numbers) |
| `<GOVT_ID_n>` | US SSN, Indian PAN, 12-Digit National IDs (Aadhaar format) | Strict structural mask (PAN/SSN) + **Verhoeff Dihedral Group $D_5$ Checksum** for 12-digit IDs |
| `<IBAN_CRYPTO_n>` | International Bank Account Numbers (IBAN), Ethereum (`0x...`) addresses | **ISO 7064 MOD-97-10 Checksum** for IBANs; 40-char hex boundary check for ETH |
| `<EMAIL_n>` | Personal and corporate email addresses | RFC-5322 practical pattern (prevents partial `<PERSON>` extraction inside email handles) |
| `<PHONE_n>` | E.164 international (`+91...`, `+1...`) and local 10–15 digit phone numbers | Digit-count bounds + negative lookbehind for reference prefixes (`order`, `invoice`, `id`, `ticket`) |
| `<IP_ADDRESS_n>` | IPv4 network addresses | Word-bounded pattern + **Octet Range Check (`0–255`)** to ignore software version strings (e.g., `1.2.3.400`) |

---

## Stage 2: Contextual Neural NER (`~15.0 ms`)

Stage 2 runs `urchade/gliner_small-v2.1` to capture unstructured entities that lack a fixed mathematical format.

| Token Tag | GLiNER Label | Target Identities | Post-Processing & Guardrails |
| :--- | :--- | :--- | :--- |
| `<PERSON_n>` | `person` | Individual names across diverse linguistic origins | Deferred on overlap with `<EMAIL_n>`; honorifics normalized |
| `<ORGANIZATION_n>` | `organization` | Companies, enterprise clients, financial institutions | Filtered against **`TECH_ALLOWLIST`** (`Docker`, `Redis`, `FastAPI`, `AWS`, `PyTorch`, etc.) to prevent redacting code/stack terms |
| `<LOCATION_n>` | `location` | Street addresses, cities, countries, office branches | Filtered against **`TECH_ALLOWLIST`**; adjacent comma-separated spans (e.g., `"Bengaluru, India"`) merged into a single token |

---

## Conflict Resolution & Session Guarantees

1. **Deterministic Priority:** If Stage 1 and Stage 2 flag overlapping spans, Stage 1 wins unconditionally.
2. **Longest-Span Tiebreaker:** Within the same stage, longer character spans take precedence over shorter substrings.
3. **Session Idempotency:** Identical plaintext values within a single request lifecycle always map to the same token (e.g., `"Sarah Connor"` $\rightarrow$ `<PERSON_1>` everywhere in the prompt).
4. **Streaming Rehydration Safety:** The inbound SSE sliding-window parser only buffers on `<` and flushes immediately on non-tag characters, ensuring zero delay on code comparison operators (`if a < b:`).