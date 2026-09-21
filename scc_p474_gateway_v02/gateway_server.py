#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import secrets
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from gateway_core import canonical_json_bytes, make_raw_capture_event, routing_surface, sha256_bytes


def emit_external_record(prefix: str, obj: dict) -> None:
    raw = canonical_json_bytes(obj)
    encoded = base64.b64encode(raw).decode("ascii")
    print(f"{prefix} {encoded}", flush=True)


def append_jsonl(path: Path, obj: dict) -> None:
    data = canonical_json_bytes(obj) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OSError("append write made no progress")
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _host_header(parts) -> str:
    host = parts.hostname or ""
    if not host:
        raise ValueError("upstream host is empty")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parts.port is not None and parts.port != 443:
        host = f"{host}:{parts.port}"
    return host


def exact_provider_wire_headers(*, upstream_url: str, content_type: str, authorization: str, body: bytes) -> dict[str, str]:
    parts = urlsplit(upstream_url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("upstream_url must be https")
    if not authorization:
        raise ValueError("authorization is required")
    return {
        "Host": _host_header(parts),
        "Content-Type": content_type,
        "Authorization": authorization,
        "Content-Length": str(len(body)),
    }


def provider_post_exact(*, upstream_url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes, dict[str, str]]:
    parts = urlsplit(upstream_url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("upstream_url must be https")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout, context=ctx)
    try:
        conn.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
        for k, v in headers.items():
            conn.putheader(k, v)
        conn.endheaders(body)
        resp = conn.getresponse()
        raw = resp.read()
        return int(resp.status), raw, {k: v for k, v in resp.getheaders()}
    finally:
        conn.close()


class GatewayState:
    def __init__(self, *, public_base: str, upstream_base: str, capture_path: Path, provider_scope_id_hash: str):
        parts = urlsplit(upstream_base)
        if parts.scheme != "https" or not parts.netloc or parts.username is not None or parts.password is not None:
            raise ValueError("upstream_base must be an https origin/base without userinfo")
        if parts.query or parts.fragment:
            raise ValueError("upstream_base must not contain query or fragment")
        public = urlsplit(public_base)
        if public.scheme != "https" or not public.netloc:
            raise ValueError("public_base must be an https origin/base")
        self.public_base = public_base.rstrip("/")
        self.upstream_base = upstream_base.rstrip("/")
        self.capture_path = capture_path
        self.provider_scope_id_hash = provider_scope_id_hash
        self._next = 0

    def reserve_sequence(self) -> int:
        i = self._next
        self._next += 1
        return i


class Handler(BaseHTTPRequestHandler):
    server_version = "SCCEvidenceGateway/0.3"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _send_bytes(self, status: int, raw: bytes, response_headers: dict[str, str]) -> None:
        self.send_response(status)
        self.send_header("Content-Type", response_headers.get("Content-Type", response_headers.get("content-type", "application/json")))
        for k, v in response_headers.items():
            if k.lower() == "x-request-id":
                self.send_header("x-request-id", v)
                break
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def do_POST(self):
        state: GatewayState = self.server.state  # type: ignore[attr-defined]
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        try:
            n = int(self.headers.get("Content-Length", ""))
        except Exception:
            self.send_error(411)
            return
        if n < 0:
            self.send_error(400)
            return
        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            self.send_error(415, "frozen adapter requires application/json")
            return
        auth = self.headers.get("Authorization")
        if not auth:
            self.send_error(401)
            return
        for forbidden in ("Cookie", "X-Conversation-Id", "X-Session-Id", "X-Thread-Id", "X-Previous-Response-Id"):
            if self.headers.get(forbidden) is not None:
                self.send_error(400, f"forbidden state header: {forbidden}")
                return

        body = self.rfile.read(n)
        sequence_index = state.reserve_sequence()
        gateway_event_id = "gw_" + secrets.token_hex(16)
        upstream_url = state.upstream_base + "/v1/chat/completions"
        wire_headers = exact_provider_wire_headers(
            upstream_url=upstream_url,
            content_type="application/json",
            authorization=auth,
            body=body,
        )
        request_started_ns = time.time_ns()
        request_record = {
            "protocol": "scc-provider-external-request-record/0.1",
            "sequence_index": sequence_index,
            "gateway_event_id": gateway_event_id,
            "gateway_request_started_ns": request_started_ns,
            "adapter_url": state.public_base + "/v1/chat/completions",
            "upstream_url": upstream_url,
            "request_body_b64": base64.b64encode(body).decode("ascii"),
            "request_body_sha256": sha256_bytes(body),
            "provider_scope_id_hash": state.provider_scope_id_hash,
            "semantic_routing_surface": routing_surface(
                upstream_url=upstream_url,
                outgoing_headers=wire_headers,
                request_body=body,
                provider_scope_id_hash=state.provider_scope_id_hash,
            ),
            "provider_wire_headers_redacted": {
                k.lower(): ("<REDACTED>" if k.lower() == "authorization" else v)
                for k, v in wire_headers.items()
            },
            "authorization_secret_exported": False,
        }
        emit_external_record("SCC_PROVIDER_REQUEST_V1", request_record)

        timeout = float(os.environ.get("SCC_GATEWAY_UPSTREAM_TIMEOUT_S", "120"))
        try:
            status, raw, response_headers = provider_post_exact(
                upstream_url=upstream_url,
                headers=wire_headers,
                body=body,
                timeout=timeout,
            )
            network_error = None
        except Exception as exc:
            status = 502
            raw = json.dumps({"error": {"type": "gateway_upstream_transport_error", "message": str(exc)}}, sort_keys=True, separators=(",", ":")).encode()
            response_headers = {"Content-Type": "application/json"}
            network_error = f"{type(exc).__name__}: {exc}"
        response_received_ns = time.time_ns()

        try:
            event = make_raw_capture_event(
                sequence_index=sequence_index,
                gateway_event_id=gateway_event_id,
                adapter_url=state.public_base + "/v1/chat/completions",
                upstream_url=upstream_url,
                outgoing_headers=wire_headers,
                request_body=body,
                response_body=raw,
                response_headers=response_headers,
                provider_scope_id_hash=state.provider_scope_id_hash,
            )
            event["provider_http_status"] = status
            event["provider_transport_error"] = network_error
            event["provider_wire_header_names"] = [k.lower() for k in wire_headers]
            event["provider_wire_headers_redacted"] = {
                k.lower(): ("<REDACTED>" if k.lower() == "authorization" else v)
                for k, v in wire_headers.items()
            }
            event["provider_wire_headers_sha256"] = sha256_bytes(canonical_json_bytes(event["provider_wire_headers_redacted"]))
            event["gateway_request_started_ns"] = request_started_ns
            event["gateway_response_received_ns"] = response_received_ns
            response_record = {
                "protocol": "scc-provider-external-response-record/0.1",
                "sequence_index": sequence_index,
                "gateway_event_id": gateway_event_id,
                "gateway_request_started_ns": request_started_ns,
                "gateway_response_received_ns": response_received_ns,
                "response_body_b64": event["response_body_b64"],
                "response_body_sha256": event["response_body_sha256"],
                "provider_request_id": event["provider_request_id"],
                "provider_http_request_id": event["provider_http_request_id"],
                "provider_reported_model": event["provider_reported_model"],
                "provider_http_status": status,
                "provider_transport_error": network_error,
            }
            emit_external_record("SCC_PROVIDER_RESPONSE_V1", response_record)
            append_jsonl(state.capture_path, event)
        except Exception as exc:
            self.send_error(502, f"evidence capture failed closed: {exc}")
            return

        self._send_bytes(status, raw, response_headers)


def main() -> None:
    ap = argparse.ArgumentParser(description="SCC provider evidence gateway v0.3 proposed")
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--public-base", required=True)
    ap.add_argument("--upstream-base", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--provider-scope-id-hash", required=True)
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    ap.add_argument("--external-tls-terminated", action="store_true")
    a = ap.parse_args()
    if a.external_tls_terminated:
        if a.tls_cert or a.tls_key:
            raise SystemExit("do not combine --external-tls-terminated with local TLS key/cert")
    elif not (a.tls_cert and a.tls_key):
        raise SystemExit("local TLS mode requires --tls-cert and --tls-key")

    state = GatewayState(public_base=a.public_base, upstream_base=a.upstream_base, capture_path=Path(a.capture), provider_scope_id_hash=a.provider_scope_id_hash)
    server = HTTPServer((a.listen, a.port), Handler)
    server.state = state  # type: ignore[attr-defined]
    if not a.external_tls_terminated:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.tls_cert, a.tls_key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
