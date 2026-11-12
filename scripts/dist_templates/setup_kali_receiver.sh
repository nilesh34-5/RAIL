#!/usr/bin/env bash
# =============================================================================
# RAIL RECEIVER (Network B) - one-shot setup for Kali Linux
#
#   bash setup_kali_receiver.sh
#
# The receiver performs NO inspection, so it needs no ML stack: no lightgbm,
# no torch, no yara, no lief, and no models directory. Three packages plus
# RaptorQ is the entire dependency set, which keeps the trusted computing base
# small on the side being protected.
#
# Run BEFORE applying network hardening, while this machine still has internet.
# =============================================================================
set -euo pipefail

echo "=============================================================="
echo "RAIL RECEIVER setup (Kali)"
echo "=============================================================="

echo "[1/4] system packages..."
sudo apt-get update -y
sudo apt-get install -y python3 python3-pip python3-venv iptables arptables

echo "[2/4] virtualenv..."
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip >/dev/null

echo "[3/4] dependencies (minimal by design)..."
pip install cryptography PyYAML numpy

# The receiver must be able to decode whatever FEC the sender chose. If the
# sender has RaptorQ and this side does not, every object is undecodable and
# the one-way link gives no way to signal the mismatch. Keep the two in step.
pip install raptorq || echo "  [warn] raptorq unavailable - pin fec.backend: reedsolo on BOTH sides"

echo "[4/4] checking the public key..."
if [ -f data/keys/sender_ed25519.pub ]; then
  echo "      sender public key present"
else
  echo "      [!] MISSING data/keys/sender_ed25519.pub"
  echo "          Copy it from the sender. Never copy the .key file."
fi
mkdir -p data/received

echo
echo "=============================================================="
echo "RECEIVER ready."
echo
echo "  Activate the venv in every new shell:"
echo "     source .venv/bin/activate"
echo
echo "  Listen (start this BEFORE the sender):"
echo "     python3 -m railcds.cli receive --out data/received"
echo "=============================================================="
