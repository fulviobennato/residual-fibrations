#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

class H(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def log_message(self,*a): return
    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_error(404); return
        n=int(self.headers.get("Content-Length","0"))
        body=self.rfile.read(n)
        i=self.server.counter  # type: ignore[attr-defined]
        self.server.counter += 1  # type: ignore[attr-defined]
        out=Path(self.server.out_dir)  # type: ignore[attr-defined]
        out.joinpath(f"provider_body_{i:03d}.bin").write_bytes(body)
        out.joinpath(f"provider_headers_{i:03d}.json").write_text(json.dumps(dict(self.headers.items()),sort_keys=True,indent=2)+"\n")
        obj=json.loads(body)
        model=obj.get("model")
        resp={
          "id":f"chatcmpl-p476-smoke-{i:04d}",
          "object":"chat.completion",
          "created":0,
          "model":model,
          "system_fingerprint":"fp_p476_stdout_smoke",
          "choices":[{"index":0,"message":{"role":"assistant","content":"{}","refusal":None},"finish_reason":"stop"}],
          "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
        }
        raw=json.dumps(resp,sort_keys=True,separators=(",",":")).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("x-request-id",f"req-p476-smoke-{i:04d}")
        self.send_header("Content-Length",str(len(raw)))
        self.send_header("Connection","close")
        self.end_headers(); self.wfile.write(raw); self.close_connection=True

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--port",type=int,default=9443)
    ap.add_argument("--cert",required=True); ap.add_argument("--key",required=True); ap.add_argument("--out-dir",required=True)
    a=ap.parse_args(); Path(a.out_dir).mkdir(parents=True,exist_ok=True)
    srv=HTTPServer(("127.0.0.1",a.port),H); srv.out_dir=a.out_dir; srv.counter=0  # type: ignore[attr-defined]
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(a.cert,a.key);srv.socket=ctx.wrap_socket(srv.socket,server_side=True)
    srv.serve_forever()
if __name__=="__main__": main()
