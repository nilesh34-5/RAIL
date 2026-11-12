#!/usr/bin/env bash
# Network B (receiver) provisioning: one-way firewall, public key, output dir.
set -euo pipefail
cd /opt/rail-run
source .venv/bin/activate

SENDER_IP=10.20.0.10
PORT=52080

# ---- Bind on all interfaces for the private net ------------------------
python3 - <<PY
import yaml, pathlib
p = pathlib.Path("config/rail.yaml"); c = yaml.safe_load(p.read_text())
c["transport"]["bind_host"] = "0.0.0.0"
c["transport"]["bind_port"] = $PORT
p.write_text(yaml.safe_dump(c, sort_keys=False))
print("configured bind_port ->", $PORT)
PY

# ---- Install the sender's PUBLIC key (from the shared exchange dir) -----
mkdir -p data/keys
if [ -f /opt/exchange/sender_ed25519.pub ]; then
  cp /opt/exchange/sender_ed25519.pub data/keys/sender_ed25519.pub
  echo "[receiver] installed sender public key"
else
  echo "[receiver] WARNING: public key not found; run 'vagrant provision netA' first"
fi

# The receiver runs NO inspection: it needs no ML models at all.
mkdir -p data/received

# ---- One-way network hardening (see deploy/diode-emulator/harden_diode.sh) --
# Applied last: after this the receiver cannot emit ANY frame toward Network A,
# including ARP replies and ICMP errors.
bash /opt/rail/deploy/diode-emulator/harden_diode.sh receiver eth1 $SENDER_IP $PORT eth0

echo "[receiver] ready.  Start listening with:"
echo "  sudo -i; cd /opt/rail-run; source .venv/bin/activate"
echo "  python3 -m railcds.cli receive --out data/received"
