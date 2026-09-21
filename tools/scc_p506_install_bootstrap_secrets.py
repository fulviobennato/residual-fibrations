#!/usr/bin/env python3
"""Install the SCC one-time bootstrap secrets into GitHub Actions without printing values.

Prerequisites:
  - gh CLI installed and authenticated for fulviobennato/residual-fibrations
  - exact private adapter v0.3 ZIP
  - exact private benchmark v0.6.13 ZIP
  - GHCR PAT classic with read:packages + write:packages
  - dedicated OpenAI API project/service-account key

Secrets installed:
  SCC_ADAPTER_V03_ZIP_B64
  SCC_BENCHMARK_V0613_B64_00
  SCC_BENCHMARK_V0613_B64_01
  SCC_BENCHMARK_V0613_B64_02
  SCC_BENCHMARK_V0613_B64_03
  SCC_GHCR_PAT
  SCC_OPENAI_API_KEY

Secret values are piped to gh over stdin and are never printed.
"""

from __future__ import annotations
import argparse, base64, getpass, hashlib, io, json, lzma, pathlib, shutil, stat, struct, subprocess, sys, zipfile

REPO = "fulviobennato/residual-fibrations"
ADAPTER_SHA = "70a6e3fcbce57b96491b3530401f1f81505b05989c255377c8828785f4ac6bae"
BENCHMARK_SHA = "35e257503ff1c4d36f30634b19c5da570288dd264ec710331a69dcfed776659c"
BENCHMARK_MEMBER_COUNT = 243
PACK_SHA = "54f95722384566b202808fff036e8c6bd38b412c836e361a8c0aaa13014b88d5"
CHUNK_SHAS = [
    "9ab45e2e3963cda1c78ad8191afc816342e09ef317ebd1a64d85dd72d285b6a3",
    "7184f58e54b9b873bf5c8d8b0c57a3d30103384d912432f1a24467086de5950a",
    "3ac024203c4d3c0f73fe3584f60b87c22570ec1939c30849024d1e0bf81e84ef",
    "b2bea46722b9acf70b657bf333c4dc7bd7799d1bc32ba184cbb3e30063d1cdf4",
]
CHUNK_CHARS = 48620
MAGIC = b"SCCBT1\0"

def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def require_file(path: str, expected_sha: str) -> bytes:
    p = pathlib.Path(path)
    data = p.read_bytes()
    got = sha(data)
    if got != expected_sha:
        raise SystemExit(f"{p.name}: SHA-256 mismatch {got}; expected {expected_sha}")
    return data

def make_benchmark_chunks(zbytes: bytes) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
        infos = z.infolist()
        if len(infos) != BENCHMARK_MEMBER_COUNT:
            raise SystemExit(f"benchmark member count {len(infos)} != {BENCHMARK_MEMBER_COUNT}")
        names = [i.filename for i in infos]
        if names != sorted(names) or len(set(names)) != len(names):
            raise SystemExit("benchmark ZIP member order/uniqueness mismatch")
        payload = bytearray(MAGIC)
        payload += struct.pack(">I", len(infos))
        for i in infos:
            p = pathlib.PurePosixPath(i.filename)
            if p.is_absolute() or ".." in p.parts:
                raise SystemExit(f"unsafe benchmark path {i.filename!r}")
            mode = (i.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise SystemExit(f"benchmark symlink member {i.filename!r}")
            data = z.read(i.filename)
            nb = i.filename.encode("utf-8")
            payload += struct.pack(">H", len(nb)) + nb + struct.pack(">Q", len(data)) + data
    packed = lzma.compress(bytes(payload), format=lzma.FORMAT_XZ, preset=9 | lzma.PRESET_EXTREME)
    if sha(packed) != PACK_SHA:
        raise SystemExit(f"P502 transport pack SHA mismatch {sha(packed)}")
    b64 = base64.b64encode(packed).decode("ascii")
    chunks = [b64[i:i+CHUNK_CHARS] for i in range(0, len(b64), CHUNK_CHARS)]
    if len(chunks) != 4 or any(len(c) != CHUNK_CHARS for c in chunks):
        raise SystemExit("P502 secret chunk shape mismatch")
    for i, (c, expected) in enumerate(zip(chunks, CHUNK_SHAS)):
        got = sha(c.encode("ascii"))
        if got != expected:
            raise SystemExit(f"P502 chunk {i:02d} SHA mismatch {got}")
    return chunks

def gh(*args: str, input_bytes: bytes | None = None, capture: bool = False) -> subprocess.CompletedProcess:
    cmd = ["gh", *args]
    return subprocess.run(
        cmd,
        input=input_bytes,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=None,
        check=True,
    )

def set_secret(name: str, value: str) -> None:
    if not value:
        raise SystemExit(f"refuse empty secret {name}")
    gh("secret", "set", name, "--repo", REPO, input_bytes=value.encode("utf-8"))

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter-zip", required=True)
    ap.add_argument("--benchmark-zip", required=True)
    ap.add_argument("--repo", default=REPO)
    args = ap.parse_args()

    global REPO
    REPO = args.repo

    if shutil.which("gh") is None:
        raise SystemExit("GitHub CLI 'gh' is not installed")

    gh("auth", "status", "--hostname", "github.com")

    adapter = require_file(args.adapter_zip, ADAPTER_SHA)
    benchmark = require_file(args.benchmark_zip, BENCHMARK_SHA)
    chunks = make_benchmark_chunks(benchmark)

    ghcr_pat = getpass.getpass("SCC_GHCR_PAT (classic PAT read:packages + write:packages): ").strip()
    openai_key = getpass.getpass("SCC_OPENAI_API_KEY (dedicated OpenAI project/service-account key): ").strip()
    if not ghcr_pat or not openai_key:
        raise SystemExit("refuse empty credential")

    values = {
        "SCC_ADAPTER_V03_ZIP_B64": base64.b64encode(adapter).decode("ascii"),
        "SCC_BENCHMARK_V0613_B64_00": chunks[0],
        "SCC_BENCHMARK_V0613_B64_01": chunks[1],
        "SCC_BENCHMARK_V0613_B64_02": chunks[2],
        "SCC_BENCHMARK_V0613_B64_03": chunks[3],
        "SCC_GHCR_PAT": ghcr_pat,
        "SCC_OPENAI_API_KEY": openai_key,
    }

    for name, value in values.items():
        set_secret(name, value)
        print(f"installed {name}", file=sys.stderr)

    result = gh("secret", "list", "--repo", REPO, "--json", "name,updatedAt", capture=True)
    listing = json.loads(result.stdout.decode("utf-8"))
    present = {x.get("name") for x in listing if isinstance(x, dict)}
    missing = sorted(set(values) - present)
    if missing:
        raise SystemExit("secret metadata list missing: " + ",".join(missing))

    receipt = {
        "schema": "scc-bootstrap-secret-installation-local/1",
        "repo": REPO,
        "secret_names": sorted(values),
        "all_secret_names_visible_in_metadata": True,
        "adapter_sha256": ADAPTER_SHA,
        "benchmark_sha256": BENCHMARK_SHA,
        "benchmark_transport_pack_sha256": PACK_SHA,
        "benchmark_chunk_sha256": CHUNK_SHAS,
        "secret_values_printed": False,
        "note": "This local receipt contains no secret values and is not external scientific custody.",
    }
    print(json.dumps(receipt, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
