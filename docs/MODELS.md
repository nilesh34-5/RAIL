# Offline ML & signature models for Stage S2 (Deep Packet / Object Inspection)

RAIL's inspection stage runs a bank of **independent detectors**; each returns a
confidence `s_i(O) ∈ [0,1]` and they are combined with Noisy-OR (Eq. 1). All
models below run **fully offline** - nothing contacts the network at inspection
time. You download/provision them once with:

```bash
python scripts/download_models.py            # YARA rules + EMBER2024 classifier
python scripts/train_anomaly.py              # trains the anomaly model locally
```

Then check what loaded:

```bash
python -m railcds.cli detectors
```

Detectors are configured (weight, on/off, model path) under
`inspection.detectors` in `config/rail.yaml`. A missing optional model simply
marks its detector *unavailable* and the others carry the decision.

---

## The models

| # | Detector (`config` key) | Type | Model / source | Offline size | Download |
|---|---|---|---|---|---|
| 1 | `ember2024_ml` | **Supervised ML** - LightGBM gradient boosting | **EMBER2024** `EMBER2024_all` (Joyce et al.), HuggingFace `joyce8/EMBER2024-benchmark-models` via the `thrember` package | ~3.8 MB | `download_models.py --ember2024` |
| 2 | `yara_signature` | Signature rules | Bundled RAIL rules + optional community **Yara-Rules** corpus | KB-MB | `download_models.py` (`--yara-full` for the corpus) |
| 3 | `entropy_anomaly` | **Unsupervised ML** - IsolationForest (scikit-learn) | Trained locally on benign files (byte-distribution) | ~1-5 MB | `train_anomaly.py` |
| 4 | `ember_ml` | Supervised ML - LightGBM | Classic **EMBER2018** 2381-feature model (trained from the official dataset) | ~25 MB | `download_models.py --ember2018-dataset` (heavy) |
| 5 | `malconv_ml` | **Deep learning** - raw-byte CNN (PyTorch) | **MalConv** (Raff et al. 2018); pretrained checkpoint from PRALab `secml_malware` | 4.2 MB | `download_models.py --malconv` |
| 5b | `malconvgct_ml` | **Deep learning** - byte CNN + global channel gating | **MalConvGCT** (Raff et al. 2021), `FutureComputing4AI/MalConv2` | 33 MB | `download_models.py --malconvgct` |
| 6 | `file_type` | Heuristic + libmagic | polyglot / magic-byte analysis | - | built in |
| 7 | `protocol_validator` | Heuristic | structural/container checks | - | built in |

Default enabled set: **1, 2, 3, 5, 5b, 6, 7** - i.e. everything except the
EMBER2018 model (4), which requires training from a 1.6 GB dataset.
Both deep models need PyTorch: `pip install torch --index-url https://download.pytorch.org/whl/cpu`.

Get all downloadable models in one go:

```bash
python scripts/download_models.py --deep
```

---

### 1. EMBER2024 (recommended) - `ember2024_ml`

A pretrained **LightGBM** classifier from the EMBER2024 benchmark. `predict`
returns a maliciousness probability from a 2568-dimension static analysis
(byte/entropy histograms, strings, PE/ELF/PDF/APK/.NET structure, imports,
Authenticode, rich header). The `EMBER2024_all` variant is **multi-format**, so
unlike EMBER2018 it scores *any* transferred object, not just PE files.

Install + download:

```bash
pip install "git+https://github.com/FutureComputing4AI/EMBER2024.git"
pip install "signify==0.5.2"          # required so thrember imports on Python 3.13
python scripts/download_models.py --ember2024
```

Sanity check on the development machine: `notepad.exe -> 0.008`, `calc.exe -> 0.25`,
EICAR marker -> `0.87`. Feature extraction uses pure-Python `pefile` (no native
LIEF build needed for this detector).

> **Dependency note.** `thrember` imports `SignedPEFile` from
> `signify.authenticode`, which the newer signify releases moved - pin
> `signify==0.5.2`. `huggingface_hub` (pulled in by thrember) fetches the model;
> after that, inference is fully offline.

### 2. YARA signatures - `yara_signature`

Offline pattern rules compiled by `yara-python`. `download_models.py` always
writes a compact, self-contained RAIL rule set (`models/yara/rail_bundled.yar`:
EICAR marker, PE markers, encoded-PowerShell, script-in-document, embedded
executable). `--yara-full` additionally `git clone`s the community
[Yara-Rules](https://github.com/Yara-Rules/rules) corpus; rules with unresolved
`include`s are skipped at load time. Rule severity (`meta: severity`) scales the
detector's confidence.

### 3. Entropy / byte-distribution anomaly - `entropy_anomaly`

A scikit-learn **IsolationForest** trained *only on benign objects*
(`train_anomaly.py`) - no malware required. It learns the byte distribution of
ordinary traffic and flags out-of-distribution payloads (packed, encrypted,
random). Point `--dirs` at a representative corpus of your real cross-domain
traffic for a production baseline; the default samples system files so the demo
is self-contained. If the trained model is absent the detector degrades to a
pure Shannon-entropy heuristic so the pipeline still runs.

### 4. EMBER2018 (classic) - `ember_ml`

The original 2381-feature LightGBM PE model. RAIL ships a LIEF-1.0 feature
extractor (`railcds/inspection/ember_features.py`) reproducing the EMBER v2
vector. The **pretrained model is not a standalone download**; it is produced
from the official dataset:

```bash
pip install "git+https://github.com/elastic/ember.git"
curl -O https://ember.elastic.co/ember_dataset_2018_2.tar.bz2      # ~1.6 GB
tar xjf ember_dataset_2018_2.tar.bz2 -C models/ember
python -c "import ember; ember.create_vectorized_features('models/ember'); ember.train_model('models/ember')"
# -> models/ember/ember_model_2018.txt, then set ember_ml.enabled: true
```

Because LIEF 1.0's API differs from the version EMBER was authored against, a
few enum-derived hashed features may not be bit-identical to training; the
dominant features (byte/entropy/string histograms and, above all, the 1280
import/library features) are exact. Prefer EMBER2024 unless you specifically
need the 2018 model.

### 5. MalConv - `malconv_ml` (deep learning)

A raw-byte CNN: byte embedding -> gated strided convolution (ReLU value branch ×
sigmoid gate) -> global max-pool -> dense head. It reads the object's bytes
directly with **no feature engineering**, so it fails differently from the
gradient-boosted EMBER models that score a hand-designed feature vector - which
is exactly the independence Noisy-OR (Eq. 1) assumes.

Weights are the **pretrained checkpoint published with `secml_malware`**
(PRALab, University of Cagliari), widely used in the adversarial-ML literature.

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
python scripts/download_models.py --malconv
```

> **Byte convention matters.** These weights were trained with **raw byte values
> (0-255) padded with 256** - *not* the "shift bytes by +1, pad with 0"
> convention used by some MalConv ports. Getting this wrong does not error; it
> silently produces meaningless scores (benign Windows binaries scored ~1.0 in
> our first run). `railcds/inspection/malconv_net.py` documents and implements
> the correct convention.

Measured on the development machine: 15 signed Windows binaries score between `1.6e-14`
and `8.1e-4` - correctly confident that known-good system files are benign.

### 5b. MalConvGCT - `malconvgct_ml` (deep learning)

MalConvGCT (Raff et al., 2021, *Classifying Sequences of Extreme Length with
Constant Memory Applied to Malware Detection*) adds **global channel gating**
and a low-memory convolution scheme, letting it attend across sequences far
longer than MalConv's fixed 1 MiB window at constant memory cost. It is the
stronger of the two byte-level models.

The network definition is **vendored** (Apache-2.0 licence; only the imports
were made package-relative) under `railcds/inspection/vendor/malconv2/`; only
the checkpoint is downloaded.

```bash
python scripts/download_models.py --malconvgct
```

Verified: all benign PEs in the benchmark score `0.000`.

### 6-7. `file_type` and `protocol_validator`

No download. `file_type` combines libmagic with a multi-signature scan to catch
**polyglots** (the Koch et al. threat the paper cites) and executable-as-image
masquerades. `protocol_validator` flags structural anomalies (truncated
containers, NUL-in-text, oversize).

### Optional: ClamAV

For an additional offline AV engine, install ClamAV and update its signature DB
(`freshclam`), then add a detector that shells out to `clamscan`/`clamd`. Not
wired by default (native engine + ~300 MB DB).

---

## Provenance: pretrained vs trained on this system

A model trained locally carries different validity claims than one trained by
its authors on a large labelled corpus.

| Detector | Provenance | Trained by whom, on what |
|---|---|---|
| `ember2024_ml` | **Pretrained - downloaded** | Authors of EMBER2024, on the EMBER2024 corpus (millions of labelled files). We only run inference. |
| `malconv_ml` | **Pretrained - downloaded** | PRALab, on an EMBER-style labelled PE corpus. We only run inference. |
| `malconvgct_ml` | **Pretrained - downloaded** | Raff et al. (FutureComputing4AI), on their labelled corpus. We only run inference. |
| `entropy_anomaly` | **Trained locally on this system** | `scripts/train_anomaly.py`, IsolationForest fitted on ~900 benign local files. Unsupervised - no malware and no labels used. |
| `yara_signature` | Not trained - authored rules | Hand-written pattern rules (RAIL-bundled; optional community corpus). |
| `file_type`, `protocol_validator` | Not trained - deterministic | Hand-written heuristics. |

**Three of the four ML/DL models are pretrained and downloaded; exactly one is
trained on this machine.** No model in RAIL was trained on real malware by us -
we neither collected nor needed a malware corpus.

In short:

> Three pretrained models (EMBER2024, MalConv, MalConvGCT) are obtained from
> published research artefacts and used for inference only; the anomaly detector
> is an IsolationForest fitted locally on benign traffic, requiring no labelled
> malware.

---

## Tuning notes and limitations

* **Weights and thresholds are policy.** Benign-but-unusual objects (e.g.
  low-entropy repeated text, tiny malformed PDFs) can score mid-range because
  Noisy-OR lets *any* detector raise the alarm. Tune per-detector `weight` and
  `block_threshold` in `config/rail.yaml` to your traffic; retrain the anomaly
  model on representative benign data.
* **Anomaly ≠ malicious.** The IsolationForest measures distributional novelty,
  which is a useful but non-specific signal - hence a modest default weight.
* **EMBER models are static analysis.** They do not execute content; pair them
  with `file_type`/CDR-style sanitisation for defence in depth.
* Every model here runs offline after provisioning, which is a requirement for a
  cross-domain gateway that must not make outbound connections.
