# RAIL gateway image (sender, receiver and diode all run from this image).
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 git build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/rail
COPY requirements.txt ./
RUN pip install --no-cache-dir \
        cryptography PyYAML numpy scikit-learn lightgbm lief yara-python \
        python-magic reedsolo joblib && \
    pip install --no-cache-dir \
        "git+https://github.com/FutureComputing4AI/EMBER2024.git" && \
    pip install --no-cache-dir "signify==0.5.2"

COPY . .

# Provision offline models at build time so inspection works with no network.
RUN python scripts/download_models.py || true

ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "railcds.cli", "detectors"]
