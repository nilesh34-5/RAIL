#!/usr/bin/env bash
# =============================================================================
# RAIL bootstrap - set a Kali VM up completely, in one command.
#
#     bash bootstrap.sh sender      # on 10.0.2.8
#     bash bootstrap.sh receiver    # on 10.0.2.9
#
# Override the addresses if yours differ:
#     SENDER_IP=1.2.3.4 RECEIVER_IP=1.2.3.5 bash bootstrap.sh sender
#     SKIP_TORCH=1 bash bootstrap.sh sender      # skip the 250 MB download
#
# Creates (or repairs) the virtualenv, installs every dependency for the role,
# fetches the offline models, writes the peer addresses into config/rail.yaml,
# removes the private key on the receiver, and finishes with a health check.
#
# Safe to re-run. Run it BEFORE any network lockdown, while the VM still has
# internet.
# =============================================================================
set -uo pipefail

ROLE="${1:-}"
SENDER_IP="${SENDER_IP:-10.0.2.8}"
RECEIVER_IP="${RECEIVER_IP:-10.0.2.9}"
PORT="${PORT:-52080}"

if [ "$ROLE" != "sender" ] && [ "$ROLE" != "receiver" ]; then
    echo "usage: bash bootstrap.sh <sender|receiver>"
    exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE" || exit 1
VENV="$HERE/.venv"
PY="$VENV/bin/python3"

echo "=============================================================="
echo "RAIL bootstrap - role=$ROLE"
echo "  sender   = $SENDER_IP"
echo "  receiver = $RECEIVER_IP"
echo "  project  = $HERE"
echo "=============================================================="

# ---- 1. system packages ----------------------------------------------------
echo
echo "[1/7] system packages ..."
sudo apt-get update -y >/dev/null 2>&1
sudo apt-get install -y python3 python3-venv python3-full python3-pip >/dev/null 2>&1
if [ "$ROLE" = "sender" ]; then
    sudo apt-get install -y python3-dev build-essential libmagic1 git curl >/dev/null 2>&1
fi
sudo apt-get install -y iptables arptables >/dev/null 2>&1
echo "      done"

# ---- 2. virtualenv (repair if broken) --------------------------------------
# Kali marks the system Python "externally managed" (PEP 668), so pip refuses to
# install into it. A venv is the supported route. A venv built by an older
# Python also breaks after a distro upgrade, so verify it actually runs.
echo "[2/7] virtualenv ..."
NEED_VENV=0
if [ ! -x "$PY" ]; then
    NEED_VENV=1
elif ! "$PY" -c "import sys" >/dev/null 2>&1; then
    echo "      existing venv is broken - rebuilding"
    NEED_VENV=1
fi
if [ "$NEED_VENV" = "1" ]; then
    rm -rf "$VENV"
    python3 -m venv "$VENV" || { echo "[!] venv creation failed"; exit 1; }
    echo "      created $VENV"
else
    echo "      reusing $VENV"
fi
"$PY" -m pip install --upgrade pip >/dev/null 2>&1

# ---- 3. python dependencies ------------------------------------------------
echo "[3/7] python dependencies ..."
"$PY" -m pip install --quiet cryptography PyYAML numpy reedsolo \
    || { echo "[!] core install failed - check internet"; exit 1; }

# RaptorQ: both gateways must agree, so install it on both or neither.
RQ=1
"$PY" -m pip install --quiet raptorq || RQ=0
[ "$RQ" = "1" ] && echo "      raptorq installed" \
                || echo "      [warn] raptorq unavailable - will pin reedsolo"

if [ "$ROLE" = "sender" ]; then
    echo "      inspection stack (this is the long part) ..."
    "$PY" -m pip install --quiet scikit-learn joblib lightgbm yara-python python-magic \
        || echo "      [warn] part of the inspection stack failed"
    "$PY" -m pip install --quiet lief || echo "      [warn] lief unavailable (optional)"
    "$PY" -m pip install --quiet pytest || echo "      [warn] pytest unavailable"

    if [ "${SKIP_TORCH:-0}" != "1" ]; then
        echo "      PyTorch CPU (~250 MB; SKIP_TORCH=1 to skip) ..."
        # --extra-index-url ADDS the PyTorch index. Using --index-url would
        # REPLACE PyPI and can disturb already-installed packages.
        "$PY" -m pip install --quiet torch --extra-index-url https://download.pytorch.org/whl/cpu \
            || echo "      [warn] torch unavailable - MalConv detectors skipped"
    fi

    echo "      EMBER2024 classifier ..."
    "$PY" -m pip install --quiet "git+https://github.com/FutureComputing4AI/EMBER2024.git" \
        || echo "      [warn] thrember unavailable - EMBER2024 skipped"
    # thrember declares signify>=0.7.1 but its code imports SignedPEFile, which
    # only exists up to 0.5.2. Upstream metadata bug: pin back, pip warns, works.
    "$PY" -m pip install --quiet "signify==0.5.2" >/dev/null 2>&1 || true
fi

# ---- 4. verify the imports before going further ----------------------------
echo "[4/7] verifying imports ..."
if [ "$ROLE" = "sender" ]; then
    "$PY" -c "import cryptography, yaml, numpy; print('      core OK')" || exit 1
else
    "$PY" -c "import cryptography, yaml, numpy; print('      core OK')" || exit 1
fi

# ---- 5. models + sample objects -------------------------------------------
echo "[5/7] models and sample objects ..."
if [ "$ROLE" = "sender" ]; then
    "$PY" scripts/download_models.py --deep >/dev/null 2>&1 \
        && echo "      models provisioned" || echo "      [warn] model download issues"
    "$PY" scripts/train_anomaly.py --max-files 400 >/dev/null 2>&1 \
        && echo "      anomaly model trained" || echo "      [warn] anomaly training skipped"
    if [ -f data/keys/sender_ed25519.key ]; then
        echo "      keypair already present"
    else
        "$PY" scripts/gen_keys.py >/dev/null 2>&1             && echo "      keypair generated - copy data/keys/sender_ed25519.pub to the receiver"             || echo "      [warn] key generation FAILED - run: ./rail keys"
    fi
    "$PY" scripts/make_test_object.py >/dev/null 2>&1
    echo "      sample objects in data/spool/"
else
    mkdir -p data/received
    # The private key must never exist on Network B.
    if [ -f data/keys/sender_ed25519.key ]; then
        shred -u data/keys/sender_ed25519.key 2>/dev/null || rm -f data/keys/sender_ed25519.key
        echo "      removed the private key (receiver keeps only the .pub)"
    fi
fi

# ---- 6. configuration ------------------------------------------------------
echo "[6/7] configuration ..."
"$PY" - "$ROLE" "$SENDER_IP" "$RECEIVER_IP" "$PORT" "$RQ" <<'PYEOF'
import sys, re, pathlib
role, sender_ip, receiver_ip, port, rq = sys.argv[1:6]
p = pathlib.Path("config/rail.yaml")
t = p.read_text(encoding="utf-8")
# edit in place so the file's comments survive
t = re.sub(r'(\n\s*send_host:\s*)"[^"]*"', f'\\g<1>"{receiver_ip}"', t, count=1)
t = re.sub(r'(\n\s*bind_host:\s*)"[^"]*"', '\\g<1>"0.0.0.0"', t, count=1)
t = re.sub(r'(\n\s*send_port:\s*)\d+', f'\\g<1>{port}', t, count=1)
t = re.sub(r'(\n\s*bind_port:\s*)\d+', f'\\g<1>{port}', t, count=1)
if rq != "1":
    # no RaptorQ here, so force BOTH sides onto the block code
    t = re.sub(r'(\n\s*backend:\s*)"auto"', '\\g<1>"reedsolo"', t, count=1)
p.write_text(t, encoding="utf-8")
print(f"      send_host={receiver_ip}  ports={port}")
PYEOF

chmod +x "$HERE/rail" 2>/dev/null || true
[ -f "$HERE/unlock.sh" ] && chmod +x "$HERE/unlock.sh" 2>/dev/null || true

# ---- 7. health check -------------------------------------------------------
echo "[7/7] health check ..."
PEER="$RECEIVER_IP"
[ "$ROLE" = "receiver" ] && PEER="$SENDER_IP"
echo
"$PY" -m railcds.cli doctor --role "$ROLE" --peer "$PEER" 2>/dev/null

echo
echo "=============================================================="
echo "$ROLE bootstrap complete."
echo
echo "  Use ./rail for everything - it runs inside the venv for you,"
echo "  so you never need 'source .venv/bin/activate':"
echo
if [ "$ROLE" = "receiver" ]; then
echo "     ./rail doctor --role receiver --peer $SENDER_IP"
echo "     ./rail receive --out data/received"
echo "     ./rail report"
else
echo "     ./rail doctor --role sender --peer $RECEIVER_IP"
echo "     ./rail send --spool data/spool"
echo "     ./rail report"
fi
echo "=============================================================="
