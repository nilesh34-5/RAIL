#!/usr/bin/env bash
# =============================================================================
# RAIL - one-shot VM setup. Run this INSIDE the RAIL1 folder on each Kali VM.
#
#     bash setup_vm.sh sender      # on 10.0.2.11
#     bash setup_vm.sh receiver    # on 10.0.2.8
#
# Installs dependencies, writes the correct IPs into config/rail.yaml, and on
# the receiver deletes the private key (it must never exist on Network B).
#
# Run this BEFORE any network hardening, while the VM still has internet.
# Safe to re-run.
# =============================================================================
set -euo pipefail

ROLE="${1:-}"
SENDER_IP="${SENDER_IP:-10.0.2.11}"
RECEIVER_IP="${RECEIVER_IP:-10.0.2.8}"
PORT="${PORT:-52080}"

if [ "$ROLE" != "sender" ] && [ "$ROLE" != "receiver" ]; then
    echo "usage: bash setup_vm.sh <sender|receiver>"
    exit 2
fi

echo "=============================================================="
echo "RAIL setup - role=$ROLE   sender=$SENDER_IP  receiver=$RECEIVER_IP"
echo "=============================================================="

# ---- 1. system packages ----------------------------------------------------
echo
echo "[1/5] system packages ..."
sudo apt-get update -y >/dev/null
if [ "$ROLE" = "sender" ]; then
    sudo apt-get install -y python3 python3-pip python3-venv python3-dev \
                            build-essential libmagic1 git curl iptables >/dev/null
else
    sudo apt-get install -y python3 python3-pip python3-venv iptables >/dev/null
fi

# ---- 2. virtualenv ---------------------------------------------------------
# Kali marks system Python "externally managed" (PEP 668) so pip refuses to
# install into it. A venv is the supported route.
echo "[2/5] virtualenv ..."
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip >/dev/null

# ---- 3. python dependencies ------------------------------------------------
echo "[3/5] python dependencies ..."
pip install --quiet cryptography PyYAML numpy

# Both sides must decode the same FEC. RaptorQ has a Linux wheel, so normally
# both get it; if either side fails, we pin reedsolo on BOTH in step 4.
RQ_OK=1
pip install --quiet raptorq || RQ_OK=0
pip install --quiet reedsolo || true

if [ "$ROLE" = "sender" ]; then
    echo "      inspection stack (this is the long part) ..."
    pip install --quiet scikit-learn joblib lightgbm yara-python python-magic
    pip install --quiet lief || echo "      [warn] lief unavailable (optional)"
    pip install --quiet "git+https://github.com/FutureComputing4AI/EMBER2024.git" \
        || echo "      [warn] thrember unavailable - EMBER2024 detector skipped"
    # thrember declares signify>=0.7.1 but its code imports SignedPEFile, which
    # only exists up to 0.5.2. Upstream metadata bug; pin back and it works.
    pip install --quiet "signify==0.5.2" 2>/dev/null || true
    if [ "${SKIP_TORCH:-0}" != "1" ]; then
        echo "      PyTorch CPU (~250 MB; set SKIP_TORCH=1 to skip) ..."
        pip install --quiet torch --index-url https://download.pytorch.org/whl/cpu \
            || echo "      [warn] torch unavailable - MalConv detectors skipped"
    fi
fi

# ---- 4. configuration ------------------------------------------------------
echo "[4/5] configuration ..."
python3 - "$ROLE" "$SENDER_IP" "$RECEIVER_IP" "$PORT" "$RQ_OK" <<'PYEOF'
import sys, re, pathlib
role, sender_ip, receiver_ip, port, rq_ok = sys.argv[1:6]
p = pathlib.Path("config/rail.yaml")
text = p.read_text(encoding="utf-8")
# edit in place so every comment in the file is preserved
text = re.sub(r'(\n\s*send_host:\s*)"[^"]*"', rf'\g<1>"{receiver_ip}"', text, count=1)
text = re.sub(r'(\n\s*bind_host:\s*)"[^"]*"', r'\g<1>"0.0.0.0"', text, count=1)
text = re.sub(r'(\n\s*send_port:\s*)\d+', rf'\g<1>{port}', text, count=1)
text = re.sub(r'(\n\s*bind_port:\s*)\d+', rf'\g<1>{port}', text, count=1)
if rq_ok != "1":
    # RaptorQ missing here, so force BOTH sides onto the block code
    text = re.sub(r'(\n\s*backend:\s*)"auto"', r'\g<1>"reedsolo"', text, count=1)
p.write_text(text, encoding="utf-8")
print(f"      send_host -> {receiver_ip}   bind_port -> {port}")
PYEOF

if [ "$ROLE" = "receiver" ]; then
    # The private key must never exist on Network B. Only the .pub is needed.
    if [ -f data/keys/sender_ed25519.key ]; then
        shred -u data/keys/sender_ed25519.key 2>/dev/null \
            || rm -f data/keys/sender_ed25519.key
        echo "      removed the private key (receiver keeps only the .pub)"
    fi
    mkdir -p data/received
else
    python3 scripts/make_test_object.py >/dev/null 2>&1 || true
    echo "      sample objects ready in data/spool/"
fi

# ---- 5. status -------------------------------------------------------------
echo "[5/5] status:"
echo -n "      FEC backend: "
python3 -c "from railcds.fec import FEC; print(FEC(backend='auto').effective_backend)" 2>/dev/null || echo "?"
if [ "$ROLE" = "sender" ]; then
    python3 -m railcds.cli detectors 2>/dev/null | sed 's/^/      /' || true
fi

echo
echo "=============================================================="
echo "$ROLE ready."
echo
echo "  In EVERY new terminal first run:   source .venv/bin/activate"
echo
if [ "$ROLE" = "receiver" ]; then
echo "  Start listening (do this BEFORE sending):"
echo "     python3 -m railcds.cli receive --out data/received"
else
echo "  Send (only after the receiver is listening):"
echo "     python3 -m railcds.cli send --spool data/spool"
fi
echo "=============================================================="
