"""Minimal Ollama client using only the Python standard library (no extra installs).
Talks to the local Ollama server's /api/chat endpoint.

Default host: http://localhost:11434  (Ollama for Windows and Linux both use this)
"""
import json
import urllib.error
import urllib.request

DEFAULT_HOST = "http://localhost:11434"


class OllamaError(RuntimeError):
    pass


def _post(host, path, payload, timeout):
    req = urllib.request.Request(host.rstrip("/") + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.URLError as e:
        raise OllamaError(f"cannot reach Ollama at {host} - is it running? ({e})") from e


def list_models(host=DEFAULT_HOST):
    req = urllib.request.Request(host.rstrip("/") + "/api/tags")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return [m["name"] for m in json.loads(r.read().decode()).get("models", [])]
    except urllib.error.URLError as e:
        raise OllamaError(f"cannot reach Ollama at {host} - is it running? ({e})") from e


def chat(model, system, user, *, temperature=0.7, seed=0, num_ctx=4096, num_predict=1024,
         host=DEFAULT_HOST, timeout=1800):
    """One non-streaming generation. Returns dict with text and timing.

    num_ctx=4096: prompt style (c) can exceed Ollama's older 2048-token default,
    which would silently cut the prompt. Ollama's format="json" option is NOT used,
    because malformed JSON is one of the measured metrics (Invalid output).
    """
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "stream": False,
        "options": {"temperature": temperature, "seed": seed, "num_ctx": num_ctx, "num_predict": num_predict},
    }
    r = _post(host, "/api/chat", payload, timeout)
    ns = 1e9
    return {
        "text": r.get("message", {}).get("content", ""),
        "total_s": round(r.get("total_duration", 0) / ns, 2),
        "load_s": round(r.get("load_duration", 0) / ns, 2),
        "prompt_tokens": r.get("prompt_eval_count", 0),
        "output_tokens": r.get("eval_count", 0),
        "gen_s": round(r.get("eval_duration", 0) / ns, 2),
    }
