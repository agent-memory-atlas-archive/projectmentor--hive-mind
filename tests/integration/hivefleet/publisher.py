"""A throwaway module publisher for the integration tests (slice B).

The publisher's Ed25519 seed is made from `os.urandom` when the object is built and lives only in this process: it is
never written to a file, an environment variable, a log or a command line (`sign()` is the only thing that uses it). The
public key is what a test pins with `module add --publisher`, so it ends up in the *test node's* `.modules.json` and in the
signed manifest, and nowhere else. The real publisher seed is never used and never read. A fixture module is a signed git
repo built under a directory the caller names (the run's temp dir), then installed through the public command.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from . import CORE

if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))
import ed25519  # noqa: E402  (the core's own, so a fixture is signed exactly as the core verifies)

_STATUS = '#!/bin/sh\nprintf \'{"schema":1,"state":"ok","version":"%s","problems":[]}\\n\'\n'
_DOCTOR = '#!/bin/sh\nprintf \'{"schema":1,"results":[{"level":"ok","check":"fixture","message":"fixture is healthy"}]}\\n\'\n'
_GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@invalid", "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@invalid"}


def _b64(b):
    return base64.b64encode(b).decode()


class ThrowawayPublisher:
    def __init__(self, workdir):
        self._seed = os.urandom(32)
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.pub = _b64(ed25519.pub_from_seed(self._seed))

    def __repr__(self):
        return f"ThrowawayPublisher(pub={self.pub})"                # never the seed

    def __getstate__(self):
        raise TypeError("a throwaway publisher is not serialised")

    def seed_forms(self):
        """The seed as raw bytes, base64 and hex: what a test searches the disk for. Test use only."""
        return [self._seed, _b64(self._seed).encode(), self._seed.hex().encode()]

    def sign(self, raw):
        return _b64(ed25519.sign(raw, self._seed))

    def build(self, name="fixture", version="1.0.0", min_core=None, files=None, sign_with=None, tamper=None, unlisted=None,
              **manifest_extra):
        """Write a signed contract-1 module into `workdir/<name>-<version>` as a one-commit git repo; returns the path.
        `min_core` defaults to the oldest core a contract-1 manifest may name. `sign_with` is another publisher whose key
        signs the manifest instead (a wrong signer); `tamper` rewrites a listed file after signing; `unlisted` adds a
        tracked file the manifest does not name."""
        import hive_modules
        if min_core is None:
            min_core = ".".join(map(str, hive_modules.CONTRACT_MIN_CORE[1]))
        repo = self.workdir / f"{name}-{version}"
        body = files or {"status.sh": _STATUS % version, "doctor.sh": _DOCTOR}
        for rel, text in body.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text)
            (repo / rel).chmod(0o755)
        m = {"name": name, "version": version, "min_core": min_core, "contract": 1, "publisher": self.pub,
             "files": {rel: hashlib.sha256(text.encode()).hexdigest() for rel, text in body.items()},
             "status": ["status.sh"], "doctor": ["doctor.sh"], **manifest_extra}
        raw = json.dumps({k: v for k, v in m.items() if v is not None}, indent=1).encode()
        (repo / "module.json").write_bytes(raw)
        (repo / "module.json.sig").write_text((sign_with or self).sign(raw))
        if tamper:
            (repo / tamper).write_text("#!/bin/sh\necho owned\n")
        if unlisted:
            (repo / unlisted).write_text("stray")
        env = {**os.environ, **_GIT_ENV}
        for argv in (["init", "-q"], ["add", "-A", "-f"], ["commit", "-q", "-m", "fixture"]):
            subprocess.run(["git", "-C", str(repo), *argv], check=True, env=env, capture_output=True)
        return repo
