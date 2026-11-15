"""Restore only the checksum-locked public Kustomize tool to a private cache."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE = Path(
    os.environ.get("CONFIG_TOOL_CACHE", ROOT.parent / ".runtime/config-tools")
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_cache(path):
    path = Path(path).resolve()
    for parent in (path, *path.parents):
        if (parent / ".git").exists() or (
            (parent / "HEAD").is_file() and (parent / "objects").is_dir()
        ):
            raise ValueError("Tool cache must remain outside every Git checkout")
    return path


def selected(root=ROOT):
    data = json.loads((root / "locks/toolchain.json").read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or set(data.get("tools", {})) != {"kustomize"}:
        raise ValueError("Unsupported tool lock")
    tool = data["tools"]["kustomize"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", tool.get("version", "")):
        raise ValueError("Exact tool version required")
    system = platform.system().lower()
    if system not in {"windows", "linux"} or platform.machine().lower() not in {
        "amd64",
        "x86_64",
    }:
        raise ValueError("Only locked Windows/Linux amd64 tools are supported")
    row = tool["platforms"][system + "_amd64"]
    suffix = "zip" if system == "windows" else "tar.gz"
    filename = f"kustomize_v{tool['version']}_{system}_amd64.{suffix}"
    expected = f"https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv{tool['version']}/{filename}"
    member = "kustomize.exe" if system == "windows" else "kustomize"
    if row["url"] != expected or row["member"] != member:
        raise ValueError("Tool URL/member is outside the reviewed release")
    if any(
        not re.fullmatch("[0-9a-f]{64}", row.get(key, ""))
        for key in ["archive_sha256", "binary_sha256"]
    ):
        raise ValueError("Tool archive/binary checksum required")
    return tool, row, system


def executable(cache=DEFAULT_CACHE, root=ROOT):
    tool, row, system = selected(root)
    target = (
        private_cache(cache)
        / "kustomize"
        / tool["version"]
        / (system + "_amd64")
        / row["member"]
    )
    target = private_cache(target)
    if not target.is_file() or digest(target.read_bytes()) != row["binary_sha256"]:
        raise ValueError("Locked tool missing/corrupt; explicitly restore tools first")
    return target


def unpack(data, member, archive_hash, binary_hash, zip_archive):
    if digest(data) != archive_hash:
        raise ValueError("Tool archive checksum mismatch")
    if zip_archive:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            binary = archive.read(member)
    else:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            info = archive.getmember(member)
            if not info.isfile():
                raise ValueError("Tool archive member must be a regular file")
            binary = archive.extractfile(info).read()
    if digest(binary) != binary_hash:
        raise ValueError("Tool binary checksum mismatch")
    return binary


def restore(cache=DEFAULT_CACHE, root=ROOT):
    tool, row, system = selected(root)
    target = (
        private_cache(cache)
        / "kustomize"
        / tool["version"]
        / (system + "_amd64")
        / row["member"]
    )
    target = private_cache(target)
    if target.exists():
        return executable(cache, root)
    with urllib.request.urlopen(row["url"], timeout=60) as response:
        data = response.read(100 * 1024 * 1024 + 1)
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("Tool download exceeded size bound")
    binary = unpack(
        data,
        row["member"],
        row["archive_sha256"],
        row["binary_sha256"],
        system == "windows",
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_bytes(binary)
    temporary.chmod(0o700)
    temporary.replace(target)
    return executable(cache, root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    args = parser.parse_args()
    print(
        json.dumps(
            {
                "tool": "kustomize",
                "verified_executable": str(restore(args.cache)),
                "cluster_operations": False,
            }
        )
    )


if __name__ == "__main__":
    main()
