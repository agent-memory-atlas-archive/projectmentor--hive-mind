"""The file-backed signer, for tests that sign with a seed they hold (3.1 signer seam: the signing functions take a
`Signer`, never a raw seed)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hivemind.crypto.signer import FileSigner  # noqa: E402,F401
