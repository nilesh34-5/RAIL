#!/bin/bash
# =============================================================================
# Makes the EMBER2024 detector load on Ubuntu - run on the SENDER (A) while it
# still has internet (Phase 0):
#     bash wired_test/fix_ember.sh
#
# Without the fix, EMBER2024 can fail with:
#     LibraryNotFoundError: Error detecting the version of libcrypto
# This is a known bug in the oscrypto 1.3.0 package with newer OpenSSL
# versions. The fix is the oscrypto code from its GitHub master branch.
# Only a package in .venv changes.
# =============================================================================
set -u
cd "$(dirname "$0")/.." || exit 1
source .venv/bin/activate || { echo "[!] no .venv here - run the RAIL setup first"; exit 1; }

echo "[1/4] thrember package (EMBER2024 feature extractor)"
if python3 -c "import thrember" 2>/dev/null; then
  echo "      present"
else
  pip install "git+https://github.com/FutureComputing4AI/EMBER2024.git" && pip install "signify==0.5.2"
fi

echo "[2/4] oscrypto from GitHub master (fixes the libcrypto error)"
pip install --force-reinstall --no-deps "git+https://github.com/wbond/oscrypto.git@master" \
  || pip install --force-reinstall --no-deps "https://github.com/wbond/oscrypto/archive/refs/heads/master.zip"
if python3 -c "import oscrypto.asymmetric; from oscrypto import backend; print('      oscrypto OK, backend =', backend())"; then
  :
else
  echo "      [!] oscrypto still fails - take a photo of the lines above"
fi

echo "[3/4] EMBER2024 model file"
if [ -f models/ember2024/EMBER2024_all.model ]; then
  echo "      present ($(du -h models/ember2024/EMBER2024_all.model | cut -f1))"
else
  python3 scripts/download_models.py --ember2024
fi

echo "[4/4] detector check"
bash wired_test/check_detectors.sh
