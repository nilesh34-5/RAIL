#!/bin/bash
# Records the machine and link details for the paper.
# Usage (from your RAIL1 folder):
#     bash wired_test/env_info.sh sender       on A
#     bash wired_test/env_info.sh receiver     on B
# It asks for your sudo password once (for ethtool).
ROLE="${1:?usage: bash wired_test/env_info.sh sender|receiver [nic]}"
IF="${2:-eno1}"
cd "$(dirname "$0")/.." || exit 1
mkdir -p results_wired
sudo -v
{
  echo "=== role: $ROLE   date: $(date)"
  lsb_release -a 2>/dev/null
  uname -a
  python3 --version
  [ -x .venv/bin/python ] && echo "venv: $(.venv/bin/python --version)"
  openssl version
  lscpu | grep -E 'Model name|^CPU\(s\)'
  free -h | head -2
  ip -br addr
  ip -br link
  sudo ethtool "$IF" | grep -iE 'speed|duplex|link detected'
  sudo ethtool -i "$IF" | grep -E 'driver|version|bus-info'
  lspci 2>/dev/null | grep -i ethernet
} 2>&1 | tee "results_wired/env_${ROLE}.txt"
echo
echo "saved: results_wired/env_${ROLE}.txt"
