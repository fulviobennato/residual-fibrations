#!/usr/bin/env python3
"""Create four GitHub Actions secret chunks for the frozen SCC v0.6.13 benchmark.

Input is the exact SCC_benchmark_core_v0_6_13.zip. The helper:
1. verifies the frozen ZIP SHA-256,
2. extracts the 243 regular files,
3. serializes a private deterministic SCCBT1 payload,
4. compresses it with XZ preset 9|EXTREME,
5. base64-encodes and splits into four chunks, each < 48 KiB,
6. prints only non-secret metadata/hashes unless --write-dir is supplied.

The resulting chunks are PRIVATE benchmark bytes and must be installed only as
GitHub Actions secrets SCC_BENCHMARK_V0613_B64_00..03.
"""
import argparse, base64, hashlib, io, json, lzma, os, pathlib, stat, struct, tempfile, zipfile

EXPECTED_ZIP_SHA = "35e257503ff1c4d36f30634b19c5da570288dd264ec710331a69dcfed776659c"
EXPECTED_MEMBER_COUNT = 243
MAGIC = b"SCCBT1\0"
MAX_SECRET_BYTES = 48 * 1024
SECRET_COUNT = 4

def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("zip_path")
    ap.add_argument("--write-dir")
    args=ap.parse_args()
    zp=pathlib.Path(args.zip_path)
    zbytes=zp.read_bytes()
    if sha(zbytes)!=EXPECTED_ZIP_SHA:
        raise SystemExit("frozen benchmark ZIP SHA mismatch")
    with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
        infos=z.infolist()
        if len(infos)!=EXPECTED_MEMBER_COUNT:
            raise SystemExit("wrong ZIP member count")
        names=[i.filename for i in infos]
        if names!=sorted(names):
            raise SystemExit("ZIP member order is not canonical sorted order")
        if len(set(names))!=len(names):
            raise SystemExit("duplicate ZIP member")
        payload=bytearray(MAGIC)
        payload += struct.pack(">I", len(infos))
        for i in infos:
            p=pathlib.PurePosixPath(i.filename)
            if p.is_absolute() or ".." in p.parts:
                raise SystemExit(f"unsafe path: {i.filename}")
            if ((i.external_attr >> 16) & 0o170000) == stat.S_IFLNK:
                raise SystemExit(f"symlink: {i.filename}")
            data=z.read(i.filename)
            nb=i.filename.encode("utf-8")
            payload += struct.pack(">H",len(nb)) + nb + struct.pack(">Q",len(data)) + data
    packed=lzma.compress(bytes(payload),format=lzma.FORMAT_XZ,preset=9|lzma.PRESET_EXTREME)
    b64=base64.b64encode(packed).decode("ascii")
    chunk_len=((len(b64)+SECRET_COUNT-1)//SECRET_COUNT + 3)//4*4
    chunks=[b64[i:i+chunk_len] for i in range(0,len(b64),chunk_len)]
    if len(chunks)!=SECRET_COUNT or any(len(c)>=MAX_SECRET_BYTES for c in chunks):
        raise SystemExit("payload does not fit four 48KiB GitHub secrets")
    meta={
      "schema":"scc-private-benchmark-secret-payload/1",
      "benchmark_zip_sha256":EXPECTED_ZIP_SHA,
      "benchmark_zip_bytes":len(zbytes),
      "member_count":EXPECTED_MEMBER_COUNT,
      "transport_pack_xz_sha256":sha(packed),
      "transport_pack_xz_bytes":len(packed),
      "base64_chars":len(b64),
      "chunks":[
        {"secret_name":f"SCC_BENCHMARK_V0613_B64_{i:02d}","chars":len(c),"sha256":sha(c.encode())}
        for i,c in enumerate(chunks)
      ],
    }
    if args.write_dir:
        out=pathlib.Path(args.write_dir); out.mkdir(parents=True,exist_ok=True)
        for i,c in enumerate(chunks):
            (out/f"SCC_BENCHMARK_V0613_B64_{i:02d}.txt").write_text(c,encoding="ascii")
        (out/"P502_SECRET_METADATA.json").write_text(json.dumps(meta,sort_keys=True,indent=2)+"\n")
    print(json.dumps(meta,sort_keys=True,indent=2))

if __name__=="__main__":
    main()
