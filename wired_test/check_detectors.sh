#!/bin/bash
# Checks that all 7 inspection detectors load - run on the SENDER (A):
#     bash wired_test/check_detectors.sh
# Writes results_wired/detectors_A.txt. Do not go on with the test unless it
# prints PASS: 7 of 7.
cd "$(dirname "$0")/.." || exit 1
[ -f .venv/bin/activate ] && source .venv/bin/activate
mkdir -p results_wired
python3 -m railcds.cli detectors 2>&1 | tee results_wired/detectors_A.txt
n_all=$(grep -cE '^ +- [a-z0-9_]+ +weight=' results_wired/detectors_A.txt)
n_ok=$(grep -cE '^ +- [a-z0-9_]+ +weight=[^ ]+ +available$' results_wired/detectors_A.txt)
echo
if [ "$n_all" -eq 7 ] && [ "$n_ok" -eq 7 ]; then
  echo "PASS: 7 of 7 detectors available" | tee -a results_wired/detectors_A.txt
else
  echo "FAIL: $n_ok of $n_all detectors available" | tee -a results_wired/detectors_A.txt
  echo "      Run: bash wired_test/fix_ember.sh   (needs internet)"
  exit 1
fi
