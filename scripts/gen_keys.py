"""Generate the sender's Ed25519 keypair at the paths named in rail.yaml.

    python scripts/gen_keys.py [--config config/rail.yaml]

The PRIVATE key stays on Network A (the sender).  Copy ONLY the .pub file to
Network B (the receiver).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from railcds.cli import cmd_keys  # noqa: E402


class _Args:
    config = None


if __name__ == "__main__":
    if "--config" in sys.argv:
        _Args.config = sys.argv[sys.argv.index("--config") + 1]
    raise SystemExit(cmd_keys(_Args))
