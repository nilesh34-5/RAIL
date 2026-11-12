#!/usr/bin/env bash
# =============================================================================
# RAIL SENDER (Network A) - one-shot setup for Kali Linux
#
#   bash setup_kali_sender.sh
#
# Run this from inside the SENDER folder, BEFORE applying any network
# hardening: the lockdown rules can restrict this machine's traffic, and every
# package must already be installed by then.
#
# Kali marks its system Python "externally managed" (PEP 668), so pip refuses
# to install into it. We therefore build a virtualenv - the supported route.
# =============================================================================
set -euo pipefail

echo "=============================================================="
echo "RAIL SENDER setup (Kali)"
echo "=============================================================="

# ---- system packages -------------------------------------------------------
echo "[1/5] system packages..."
sudo apt-get update -y
sudo apt-get install -y python3 python3-pip python3-venv python3-dev \
                        build-essential libmagic1 git curl iptables arptables

# ---- virtualenv ------------------------------------------------------------
echo "[2/5] virtualenv..."
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip >/dev/null

# ---- core + inspection stack ----------------------------------------------
echo "[3/5] core and inspection dependencies (this is the big one)..."
pip install cryptography PyYAML numpy scikit-learn joblib reedsolo \
            lightgbm yara-python python-magic
pip install lief || echo "  [warn] lief unavailable - only the optional EMBER2018 detector needs it"

# RaptorQ: the RFC 6330 fountain code. A manylinux wheel exists, so unlike
# Windows this installs cleanly.
pip install raptorq || echo "  [warn] raptorq unavailable - falling back to Reed-Solomon"

# EMBER2024 pretrained classifier. thrember declares signify>=0.7.1 but its code
# imports SignedPEFile, which only exists up to 0.5.2 - an upstream metadata bug.
# Install thrember first, then pin signify back; pip warns and it works.
pip install "git+https://github.com/FutureComputing4AI/EMBER2024.git" \
  || echo "  [warn] thrember unavailable - EMBER2024 detector will be skipped"
pip install "signify==0.5.2" 2>/dev/null || true

# Deep byte-CNN detectors (MalConv / MalConvGCT). ~250 MB; skip with SKIP_TORCH=1
if [ "${SKIP_TORCH:-0}" != "1" ]; then
  echo "      installing PyTorch (CPU build, ~250 MB) - set SKIP_TORCH=1 to skip"
  pip install torch --index-url https://download.pytorch.org/whl/cpu \
    || echo "  [warn] torch unavailable - MalConv detectors will be skipped"
fi

# ---- models, keys, sample objects -----------------------------------------
echo "[4/5] models, keys and sample objects..."
python3 scripts/download_models.py --deep || true
python3 scripts/train_anomaly.py --max-files 400 || true
[ -f data/keys/sender_ed25519.key ] || python3 scripts/gen_keys.py

# ---- report ----------------------------------------------------------------
echo "[5/5] detector status:"
python3 -m railcds.cli detectors 2>/dev/null || true

echo
echo "=============================================================="
echo "SENDER ready."
echo
echo "  Copy the PUBLIC key to the receiver (never the .key):"
echo "     data/keys/sender_ed25519.pub"
echo
echo "  Activate the venv in every new shell:"
echo "     source .venv/bin/activate"
echo
echo "  Send:"
echo "     python3 -m railcds.cli send --spool data/spool"
echo "=============================================================="
