"""proxy.py - OpenAI-compatible PII redaction & rehydration gateway."""
from __future__ import annotations
import json, os, time
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from engine import CascadeEngine
from sanitizer import StreamRehydrator, VaultSession

app = FastAPI(title="pii-airlock", version="0.1.0")
engine = CascadeEngine()
UPSTREAM = os.getenv("AIRLOCK_UPSTREAM_URL", "").rstrip("/")
LAST_OUTBOUND: dict = {}


def _prepare(messages: list[dict], session: VaultSession) -> tuple[list[dict], int]:
    """Redact every message through one shared session so tokens stay stable."""
    out, count = [], 0
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str) and content:
            spans = engine.detect(content)
            text, _ = session.dehydrate(content, spans)
            count += len(spans)
            msg = {**msg, "content": text}
        out.append(msg)
    return out, count


def _headers(latency_ms: float, count: int) -> dict:
    return {"X-Airlock-Latency-Ms": f"{latency_ms:.2f}", "X-Airlock-Redacted-Count": str(count)}


def _leaks(payload: dict, session: VaultSession) -> list[str]:
    blob = json.dumps(payload)
    return [v for v in set(session.vault.values()) if v in blob]


def _mock_reply(messages: list[dict]) -> str:
    for msg in reversed(messages):
        if msg.get("role") == "user" and isinstance(msg.get("content"), str):
            return "Echo: " + msg["content"]
    return "Echo."


def _chunk(text: str) -> dict:
    return {"id": "chatcmpl-airlock", "object": "chat.completion.chunk", "model": "airlock-mock",
            "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}]}


async def _mock_sse(text: str):
    """Adversarial 2-char frames so every <ENTITY_n> token is split mid-tag."""
    for i in range(0, len(text), 2):
        yield "data: " + json.dumps(_chunk(text[i:i + 2])) + "\n\n"
    yield "data: [DONE]\n\n"


async def _upstream_frames(url: str, payload: dict, headers: dict):
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream("POST", url, json=payload, headers=headers) as resp:
            async for line in resp.aiter_lines():
                if line:
                    yield line + "\n"


async def _rehydrate_sse(frames, vault: dict[str, str]):
    """Rewrite SSE delta.content through a stateful StreamRehydrator."""
    rehydrator = StreamRehydrator(vault)
    async for frame in frames:
        if not frame.startswith("data:"):
            yield frame
            continue
        data = frame[5:].strip()
        if data == "[DONE]":
            tail = rehydrator.flush()
            if tail:
                yield "data: " + json.dumps(_chunk(tail)) + "\n\n"
            yield "data: [DONE]\n\n"
            continue
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            yield frame
            continue
        for choice in obj.get("choices", []):
            delta = choice.get("delta") or {}
            if isinstance(delta.get("content"), str) and delta["content"]:
                delta["content"] = rehydrator.process_chunk(delta["content"])
        yield "data: " + json.dumps(obj) + "\n\n"


async def _live_json(url: str, payload: dict, headers: dict, session: VaultSession) -> dict:
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(url, json=payload, headers=headers)
    data = resp.json()
    for choice in data.get("choices", []):
        message = choice.get("message") or {}
        if isinstance(message.get("content"), str):
            message["content"] = session.rehydrate(message["content"])
    return data


@app.get("/health")
async def health():
    return {"status": "ok", "engine": "pii-airlock"}


@app.post("/v1/chat/completions")
async def chat(request: Request):
    started = time.perf_counter()
    body = await request.json()
    stream = bool(body.get("stream"))
    session = VaultSession()
    messages, count = _prepare(body.get("messages", []), session)
    headers = _headers((time.perf_counter() - started) * 1000, count)
    model = body.get("model", "airlock-mock")
    payload = {"model": model, "messages": messages, "stream": stream}

    if not UPSTREAM or request.headers.get("x-airlock-upstream", "").lower() == "mock":
        LAST_OUTBOUND.clear()
        LAST_OUTBOUND.update(payload)
        if _leaks(payload, session):
            return JSONResponse({"error": "outbound PII leak detected"}, status_code=500, headers=headers)
        reply = _mock_reply(messages)
        if stream:
            return StreamingResponse(_rehydrate_sse(_mock_sse(reply), session.vault),
                                     media_type="text/event-stream", headers=headers)
        return JSONResponse({
            "id": "chatcmpl-airlock", "object": "chat.completion", "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": session.rehydrate(reply)},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }, headers=headers)

    url = UPSTREAM if UPSTREAM.endswith("/v1/chat/completions") else UPSTREAM + "/v1/chat/completions"
    upstream_headers = {"Content-Type": "application/json"}
    if auth := request.headers.get("authorization"):
        upstream_headers["Authorization"] = auth
    if stream:
        return StreamingResponse(_rehydrate_sse(_upstream_frames(url, payload, upstream_headers), session.vault),
                                 media_type="text/event-stream", headers=headers)
    return JSONResponse(await _live_json(url, payload, upstream_headers, session), headers=headers)
