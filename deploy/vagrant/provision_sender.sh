#!/usr/bin/env bash
# Network A (sender) provisioning: one-way firewall, models, keys, spool.
set -euo pipefail
cd /opt/rail-run
source .venv/bin/activate

RECEIVER_IP=10.20.0.20
PORT=52080

# ---- Inspection stack: sender only -------------------------------------
apt-get install -y libmagic1 build-essential >/dev/null
pip install scikit-learn lightgbm yara-python python-magic reedsolo joblib
pip install lief || true

# ---- Point the sender at Network B -------------------------------------
python3 - <<PY
import yaml, pathlib
p = pathlib.Path("config/rail.yaml"); c = yaml.safe_load(p.read_text())
c["transport"]["send_host"] = "$RECEIVER_IP"
c["transport"]["send_port"] = $PORT
p.write_text(yaml.safe_dump(c, sort_keys=False))
print("configured send_host ->", "$RECEIVER_IP")
PY

# ---- Provision offline inspection models + keys + samples --------------
python3 scripts/download_models.py || true
python3 scripts/gen_keys.py
python3 scripts/make_test_object.py
# publish ONLY the public key to the shared exchange dir for Network B
mkdir -p /opt/exchange
cp data/keys/sender_ed25519.pub /opt/exchange/sender_ed25519.pub
echo "[sender] public key published to /opt/exchange/"

# ---- One-way network hardening (see deploy/diode-emulator/harden_diode.sh) --
# Learn B's MAC BEFORE B stops answering ARP, then pin it statically.
ping -c 2 -W 2 $RECEIVER_IP >/dev/null 2>&1 || true
bash /opt/rail/deploy/diode-emulator/harden_diode.sh sender eth1 $RECEIVER_IP $PORT eth0

echo "[sender] ready.  Send with:"
echo "  sudo -i; cd /opt/rail-run; source .venv/bin/activate"
echo "  python3 -m railcds.cli send --spool data/spool"
