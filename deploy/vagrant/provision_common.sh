#!/usr/bin/env bash
# Common provisioning: Python and a writable working copy. Kept light -
# the ML stack is installed ONLY on the sender, because the receiver performs no
# inspection (see docs/TESTING_GUIDE.md).
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-pip python3-venv rsync arptables iptables-persistent

# Work from a writable copy so each VM keeps its own data/ and keys.
mkdir -p /opt/rail-run
rsync -a --exclude 'dist' --exclude '__pycache__' --exclude '.pytest_cache'       /opt/rail/ /opt/rail-run/
cd /opt/rail-run

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip >/dev/null

# Core only - both sides need these.
pip install cryptography PyYAML numpy

echo "[common] base provisioning complete on $(hostname)"
