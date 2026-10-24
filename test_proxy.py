"""test_proxy.py - End-to-end tests for the pii-airlock streaming gateway."""
import json
from fastapi.testclient import TestClient
import proxy

client = TestClient(proxy.app)

def chat(messages, stream=False, headers=None):
    return client.post("/v1/chat/completions",
                       json={"model": "test-model", "messages": messages, "stream": stream},
                       headers=headers or {})

def sse_frames(resp):
    out = []
    for line in resp.text.splitlines():
        if line.startswith("data:") and line[5:].strip() != "[DONE]":
            out.append(json.loads(line[5:].strip()))
    return out


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "engine": "pii-airlock"}


ALL_PII = [
    "Rahul Verma", "rahul.verma@tcs.com", "Tata Consultancy Services", "Bengaluru, India",
    "+1-555-234-5678", "4532-0151-1283-0366", "192.168.1.100",
    "sk-abcdefghijklmnopqrstuvwxyz123456", "Bearer abcdefgh12345678",
    "ABCDE1234F", "DE89370400440532013000", "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
]

def test_zero_outbound_pii_leak_all_11_entities():
    text = ("Rahul Verma (rahul.verma@tcs.com) works at Tata Consultancy Services in Bengaluru, India. "
            "Call +1-555-234-5678. Card 4532-0151-1283-0366. Node 192.168.1.100. "
            "Key sk-abcdefghijklmnopqrstuvwxyz123456. Auth Bearer abcdefgh12345678. "
            "PAN ABCDE1234F. IBAN DE89370400440532013000. "
            "Wallet 0x71C7656EC7ab88b098defB751B7401B5f6d8976F.")
    r = chat([{"role": "system", "content": "You are a helpful assistant."},
              {"role": "user", "content": text},
              {"role": "user", "content": "Rahul Verma pinged again."}])
    assert r.status_code == 200, r.text
    assert int(r.headers["X-Airlock-Redacted-Count"]) >= 12
    outbound = json.dumps(proxy.LAST_OUTBOUND)
    for value in ALL_PII:
        assert value not in outbound, f"leaked: {value}"
    assert "<PERSON_1>" in outbound and "<PERSON_2>" not in outbound


def test_non_streaming_roundtrip_and_headers():
    text = "Hi, I'm Priya Patel and my email is priya@example.com."
    r = chat([{"role": "user", "content": text}])
    assert r.status_code == 200
    assert r.headers["X-Airlock-Redacted-Count"] == "2"
    assert float(r.headers["X-Airlock-Latency-Ms"]) >= 0
    content = r.json()["choices"][0]["message"]["content"]
    assert "Priya Patel" in content and "priya@example.com" in content
    assert "<PERSON_1>" not in content and "<EMAIL_1>" not in content


def test_streaming_split_token_rehydration_with_cpp_code():
    key = "sk-abcdefghijklmnopqrstuvwxyz123456"
    text = f"Contact Rahul Verma with key {key} about template <typename T> and a < b."
    r = chat([{"role": "user", "content": text}], stream=True)
    assert r.status_code == 200
    assert r.headers["X-Airlock-Redacted-Count"] == "2"
    assert float(r.headers["X-Airlock-Latency-Ms"]) >= 0
    assert "text/event-stream" in r.headers["content-type"]
    frames = sse_frames(r)
    assert len(frames) > 20
    content = "".join(f["choices"][0]["delta"].get("content", "") for f in frames)
    assert "Rahul Verma" in content and key in content
    assert "<typename T>" in content and "a < b" in content
    assert "<PERSON_1>" not in r.text and "<API_KEY_1>" not in r.text


def test_clean_developer_prompt_passes_through():
    text = "FastAPI + Redis + Heroku + Docker with Postgres"
    r = chat([{"role": "user", "content": text}])
    assert r.status_code == 200
    assert r.headers["X-Airlock-Redacted-Count"] == "0"
    content = r.json()["choices"][0]["message"]["content"]
    assert text in content and "<" not in content
