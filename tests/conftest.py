"""Tests suite for `auth`."""

import sys
from pathlib import Path

path = Path(__file__)

while path.name != "tests" and path.is_dir():
    path = path.parent

source_path = path.parent / "src"

if source_path not in sys.path:
    sys.path.insert(0, source_path)
