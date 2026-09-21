from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

RAW_CAPTURE_PROTOCOL = "scc-provider-gateway-raw-capture/0.2"
LOG_PROTOCOL = "scc-provider-execution-custody-log/0.1"
ISO_PROTOCOL = "scc-provider-semantic-isolation-assertion/0.1"
ROUTING_PROTOCOL = "scc-provider-routing-surface-assertion/0.1"
CAPTURE_POINT = "POST_GATEWAY_PRE_PROVIDER_APPLICATION_ROUTING"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ROUTING_BODY_KEYS = (
    "model", "service_tier", "prompt_cache_key", "prompt_cache_retention",
    "safety_identifier", "store", "seed",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def parse_json_object(data: bytes, *, what: str) -> dict[str, Any]:
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"{what} is not one UTF-8 JSON object: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError(f"{what} must be a JSON object")
    return obj


def parse_adapter_benchmark_packet(request_body: bytes) -> dict[str, Any]:
    body = parse_json_object(request_body, what="provider request body")
    messages = body.get("messages")
    if not isinstance(messages, list) or len(messages) < 2 or not isinstance(messages[1], dict):
        raise ValueError("provider request body lacks adapter user message")
    content = messages[1].get("content")
    if not isinstance(content, str):
        raise ValueError("adapter user message content is not text")
    try:
        wrapper = json.loads(content)
    except Exception as exc:
        raise ValueError(f"adapter user message is not canonical JSON: {exc}") from exc
    packet = wrapper.get("benchmark_packet") if isinstance(wrapper, dict) else None
    if not isinstance(packet, dict):
        raise ValueError("adapter user message lacks benchmark_packet")
    return packet


def diagnostic_identity_from_request(request_body: bytes) -> dict[str, Any]:
    """Extract only diagnostics derivable from the frozen adapter request.

    Seed and Stage-II round index are intentionally not guessed here. They are
    bound later from frozen SCC trusted receipts by bind_provider_log.py.
    """
    packet = parse_adapter_benchmark_packet(request_body)
    if "instance_id" in packet and "channel_ids" in packet and "rows" in packet:
        return {
            "phase": "STAGE_R_ROOT_DISCOVERY",
            "task_id": packet.get("instance_id"),
            "arm_id": "STAGE_R_ROOT_DISCOVERY",
            "round_index": None,
        }
    stage = packet.get("stage")
    if stage == "STAGE_I_SELECTION":
        phase = "STAGE_I_SELECTION"
    elif stage == "STAGE_II_DISCOVERY":
        phase = "STAGE_II_DISCOVERY"
    else:
        raise ValueError(f"unsupported benchmark stage in provider request: {stage!r}")
    return {
        "phase": phase,
        "task_id": packet.get("task_id"),
        "arm_id": packet.get("arm_id"),
        "round_index": None,
    }


def _normalized_nonsecret_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Project the exact provider-bound wire headers onto semantic routing data.

    The v0.2 gateway emits the provider request with http.client.putrequest(...,
    skip_host=True, skip_accept_encoding=True) and an explicit header set.  Thus
    this function is no longer applied to a pre-wire approximation.  Only the
    credential value and body-length framing metadata are omitted.  Host and
    Content-Type are retained because they can affect provider routing/parsing.
    """
    out: dict[str, str] = {}
    for raw_k, raw_v in headers.items():
        k = str(raw_k).strip().lower()
        if not k:
            continue
        if k in {"authorization", "proxy-authorization", "cookie", "set-cookie"}:
            continue
        if k == "content-length":
            continue
        out[k] = str(raw_v).strip()
    return dict(sorted(out.items()))


def routing_surface(
    *,
    upstream_url: str,
    outgoing_headers: Mapping[str, str],
    request_body: bytes,
    provider_scope_id_hash: str,
) -> dict[str, Any]:
    if not _HEX64.fullmatch(provider_scope_id_hash):
        raise ValueError("provider_scope_id_hash must be 64 lowercase hex")
    parts = urlsplit(upstream_url)
    if parts.scheme != "https" or not parts.netloc:
        raise ValueError("production routing surface requires an https upstream URL")
    body = parse_json_object(request_body, what="provider request body")
    auth = None
    for k, v in outgoing_headers.items():
        if str(k).lower() == "authorization":
            auth = str(v)
            break
    auth_mode = "bearer" if isinstance(auth, str) and auth.startswith("Bearer ") else ("present_other" if auth else "absent")
    body_routing = {k: body[k] for k in _ROUTING_BODY_KEYS if k in body}
    return {
        "capture_point": CAPTURE_POINT,
        "http_method": "POST",
        "upstream_origin": f"{parts.scheme}://{parts.netloc}",
        "upstream_path": parts.path or "/",
        "authorization_present": bool(auth),
        "auth_mode": auth_mode,
        "nonsecret_provider_bound_headers": _normalized_nonsecret_headers(outgoing_headers),
        "provider_scope_id_hash": provider_scope_id_hash,
        "routing_body_projection": body_routing,
    }


def routing_surface_sha256(**kwargs: Any) -> str:
    return sha256_bytes(canonical_json_bytes(routing_surface(**kwargs)))


def make_raw_capture_event(
    *,
    sequence_index: int,
    gateway_event_id: str,
    adapter_url: str,
    upstream_url: str,
    outgoing_headers: Mapping[str, str],
    request_body: bytes,
    response_body: bytes,
    response_headers: Mapping[str, str],
    provider_scope_id_hash: str,
) -> dict[str, Any]:
    if not isinstance(sequence_index, int) or sequence_index < 0:
        raise ValueError("sequence_index must be a nonnegative integer")
    if not isinstance(gateway_event_id, str) or not gateway_event_id:
        raise ValueError("gateway_event_id must be nonempty")
    req_obj = parse_json_object(request_body, what="provider request body")
    provider_parse_error = None
    try:
        provider = parse_json_object(response_body, what="provider response body")
    except Exception as exc:
        provider = {}
        provider_parse_error = str(exc)
    provider_id = provider.get("id")
    if provider_id is not None and not isinstance(provider_id, str):
        provider_parse_error = provider_parse_error or "provider response id is not a string"
        provider_id = None
    model = provider.get("model")
    if model is not None and (not isinstance(model, str) or not model):
        provider_parse_error = provider_parse_error or "provider response model is invalid"
        model = None
    http_req_id = None
    for k, v in response_headers.items():
        if str(k).lower() == "x-request-id":
            http_req_id = str(v)
            break
    identity = diagnostic_identity_from_request(request_body)
    surface = routing_surface(
        upstream_url=upstream_url,
        outgoing_headers=outgoing_headers,
        request_body=request_body,
        provider_scope_id_hash=provider_scope_id_hash,
    )
    return {
        "protocol": RAW_CAPTURE_PROTOCOL,
        "sequence_index": sequence_index,
        "gateway_event_id": gateway_event_id,
        "url": adapter_url,
        "upstream_url": upstream_url,
        "request_body_b64": b64(request_body),
        "request_body_sha256": sha256_bytes(request_body),
        "response_body_b64": b64(response_body),
        "response_body_sha256": sha256_bytes(response_body),
        "provider_request_id": provider_id,
        "provider_http_request_id": http_req_id,
        "provider_reported_model": model,
        "provider_system_fingerprint": provider.get("system_fingerprint"),
        "provider_response_parse_error": provider_parse_error,
        "diagnostic_identity_from_request": identity,
        "provider_scope_id_hash": provider_scope_id_hash,
        "semantic_routing_surface": surface,
        "semantic_routing_surface_sha256": sha256_bytes(canonical_json_bytes(surface)),
        "authorization_secret_exported": False,
        "cookie_forwarded": any(str(k).lower() == "cookie" for k in outgoing_headers),
        "request_model": req_obj.get("model"),
    }


def bind_raw_events_to_expected(
    raw_events: list[Mapping[str, Any]],
    expected: list[Mapping[str, Any]],
    *,
    adapter: Any,
    cfg: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Deterministically add SCC-only diagnostics after the run.

    This function never invents seed/round information from provider traffic.
    It requires the frozen trusted-side expected call sequence and verifies the
    provider-bound bytes before binding those diagnostics.
    """
    if len(raw_events) != len(expected):
        raise ValueError(f"raw/expected call count mismatch: {len(raw_events)} != {len(expected)}")
    out: list[dict[str, Any]] = []
    seen_gateway: set[str] = set()
    seen_provider: set[str] = set()
    for idx, (raw, item) in enumerate(zip(raw_events, expected)):
        if raw.get("sequence_index") != idx:
            raise ValueError(f"raw sequence mismatch at {idx}")
        gid = raw.get("gateway_event_id")
        if not isinstance(gid, str) or not gid or gid in seen_gateway:
            raise ValueError(f"raw gateway_event_id missing/duplicate at {idx}")
        seen_gateway.add(gid)
        packet = item["packet"]
        url, _headers, expected_body = adapter.build_request(cfg, packet, item["kind"])
        try:
            logged_body = base64.b64decode(str(raw["request_body_b64"]), validate=True)
        except Exception as exc:
            raise ValueError(f"invalid request_body_b64 at {idx}: {exc}") from exc
        if logged_body != expected_body:
            raise ValueError(f"raw request body differs from frozen adapter reconstruction at {idx}")
        if raw.get("url") != url:
            raise ValueError(f"raw provider URL differs from frozen adapter reconstruction at {idx}")
        if raw.get("request_body_sha256") != sha256_bytes(logged_body):
            raise ValueError(f"raw request hash mismatch at {idx}")
        try:
            response_body = base64.b64decode(str(raw["response_body_b64"]), validate=True)
        except Exception as exc:
            raise ValueError(f"invalid response_body_b64 at {idx}: {exc}") from exc
        if raw.get("response_body_sha256") != sha256_bytes(response_body):
            raise ValueError(f"raw response hash mismatch at {idx}")
        provider = parse_json_object(response_body, what=f"provider response {idx}")
        if raw.get("provider_reported_model") != provider.get("model"):
            raise ValueError(f"raw provider model mismatch at {idx}")
        pid = raw.get("provider_request_id")
        if provider.get("id") is not None and pid != provider.get("id"):
            raise ValueError(f"raw provider_request_id mismatch at {idx}")
        if isinstance(pid, str) and pid:
            if pid in seen_provider:
                raise ValueError(f"duplicate provider_request_id at {idx}")
            seen_provider.add(pid)
        out.append({
            "sequence_index": idx,
            "gateway_event_id": gid,
            "provider_request_id": pid,
            "phase": item["phase"],
            "seed": int(item["seed"]),
            "task_id": item["task_id"],
            "arm_id": item["arm_id"],
            "round_index": item["round_index"],
            "url": raw["url"],
            "request_body_b64": raw["request_body_b64"],
            "request_body_sha256": raw["request_body_sha256"],
            "response_body_b64": raw["response_body_b64"],
            "response_body_sha256": raw["response_body_sha256"],
            "provider_reported_model": raw["provider_reported_model"],
        })
    return out
