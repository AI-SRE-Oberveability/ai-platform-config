"""Temporary synthetic fixtures outside Git, with native POSIX temp storage."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tools import private_cache


def temporary_directory():
    if os.name == "posix":
        return tempfile.TemporaryDirectory()
    root = private_cache(Path(__file__).resolve().parents[2] / ".runtime/config-tests")
    root.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=root)
