# RAIL - Risk-Adaptive Integrity Layering

A working software implementation of the **RAIL** cross-domain gateway from the
paper *"Software-Based Data Diodes for Trusted Network Integration: A Survey and
a Risk-Adaptive Multilayer Architecture"* (Mane & Vidyarthi).

RAIL moves objects one-way between two isolated trusted networks and lets **deep
inspection drive cryptographic integrity**: a Noisy-OR risk score from a bank of
offline ML/signature detectors continuously sets the chunk granularity, the
Merkle/hash-chain detail, and how often the Merkle root is anchored to a ledger.
Suspicious objects are processed finely and audited often; routine objects move
cheaply; dangerous objects are quarantined and never cross.

```
 Network A --> S1 protocol break > S2 inspect (risk r) > S3 adapt+sign > S4 FEC ==> one-way ==> S4' > S5 verify > S6 deliver --> Network B
                                        |                                              audit log, anchored every T(r)
```

## What's implemented

* **All six stages S1-S6** and **all seven equations** - see
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the paper-to-code map.
* **Layered offline inspection** (Stage S2), 7 independent detectors combined
  with Noisy-OR (Eq. 1): EMBER2024 LightGBM classifier, **MalConv** and
  **MalConvGCT** deep raw-byte CNNs, IsolationForest byte-anomaly, YARA
  signatures, polyglot/file-type, protocol validation. Three pretrained models
  are downloaded; one is trained locally. See [`docs/MODELS.md`](docs/MODELS.md).
* **Risk-adaptive integrity** (Stage S3): geometric chunk sizing (Eq. 2), linked
  SHA-256 hash chain (Eq. 3), Merkle tree, nonce+policy session binding.
* **Risk-adaptive anchoring** (Eq. 4) to an append-only, self-chained dual audit
  log; covert-channel quantisation (Eq. 5) with an explicit capacity bound (Eq. 6).
* **OS-level boundary enforcement** (`railcds.cli lockdown`): programs the host
  firewall so the RAIL flow is the *only* traffic between the two hosts - the
  second independent enforcement point the paper argues for. The gateways warn
  at start-up when it is not active.
* **Driver-layer enforcement** (`railcds.cli driverfilter`): XDP/eBPF at the NIC
  driver plus tc-bpf egress on Linux - the Table I "Driver Layer" rung - with
  fallback to WFP (Windows) or pf (macOS/BSD) and a reported tier.
* **One-way reliable transport**: FEC (built-in Reed-Solomon erasure code, or
  RaptorQ if installed) over send-only/recv-only UDP - no acknowledgements.
* **Deployment**: single machine, two-VM one-way virtual network (Vagrant),
  and Docker (one-way by topology). See [`deploy/README_NETWORK.md`](deploy/README_NETWORK.md).
* **Tests**: 26 passing unit/integration tests (`py -m pytest`), plus a
  security demonstration that mounts a concrete attack for every threat in the
  paper's threat model (`py scripts/demo_attacks.py`, 10/10 checks).

## Quick start

```bash
py -m pip install cryptography PyYAML numpy scikit-learn lightgbm lief yara-python python-magic-bin reedsolo joblib
py -m pip install "git+https://github.com/FutureComputing4AI/EMBER2024.git" "signify==0.5.2"

py scripts/download_models.py --deep   # offline models (YARA, EMBER2024, MalConv, MalConvGCT)
py scripts/train_anomaly.py       # local anomaly model
py scripts/gen_keys.py            # Ed25519 keypair
py scripts/make_test_object.py    # harmless sample objects

py scripts/demo_local.py --loss 0.2   # end-to-end demo (benign path)
py scripts/demo_attacks.py            # security demo (threat model T1-T5)
py scripts/benchmark_models.py        # compare the ML/DL detectors
py -m pytest -q                       # test suite
```

Quantitative evaluation of the four parameters the paper defers (goodput,
integrity overhead, inspection accuracy, measured channel capacity):

```bash
py scripts/evaluate.py                # results -> docs/RESULTS.md
```

Full instructions: [`docs/RUNBOOK.md`](docs/RUNBOOK.md).
Test it yourself / per-side config: [`docs/TESTING_GUIDE.md`](docs/TESTING_GUIDE.md).
Locking the network down to one flow: [`docs/NETWORK_HARDENING.md`](docs/NETWORK_HARDENING.md).
Measured results: [`docs/RESULTS.md`](docs/RESULTS.md).

## Example demo output

```
object             risk band  chunk_sz  chunks  symbols   sent     status  anchor(s)
benign.txt        0.455    1    370728       1        5      4  DELIVERED      170.9
polyglot.pdf      0.869    3     46341       1        2      1  DELIVERED       23.4
random.bin        0.938    3         -       -        -      - QUARANTINE          -
report.pdf        0.732    2    131072       1        2      1  DELIVERED       78.8
signature_hit.txt  0.901    3         -       -        -      - QUARANTINE          -
suspicious.ps1    0.972    3         -       -        -      - QUARANTINE          -
```

Risk rises -> chunks get smaller and anchoring gets more frequent; objects at or
above `θ_blk = 0.90` are quarantined and never transmitted; delivered objects
are reconstructed from FEC despite 20 % simulated packet loss and verified
against the signed Merkle root.

## Layout

```
railcds/                 the RAIL package (one module per stage)
  inspection/            Stage S2 detectors + engine
config/rail.yaml         every tunable from the paper
scripts/                 provisioning, training, demos, key-gen
tests/                   pytest suite
deploy/                  Vagrant (2-VM one-way net), Docker, diode emulator
docs/                    ARCHITECTURE, MODELS, RUNBOOK, RESULTS,
                         TESTING_GUIDE, NETWORK_HARDENING
wired_test/              two-machine wired field-trial kit
evaluation_testbed_2026-10/  two-node testbed harness, configs and raw results
models/  data/           populated at provisioning/run time
```

## Scope and limitations

This is a research prototype for the paper. It demonstrates the architecture and
its security properties end-to-end; it is **not** an accredited cross-domain
solution. Detector weights/thresholds are policy and should be tuned to real
traffic; the ML models are static analysis; and as the paper states, software
enforcement rests on the correctness of the OS/kernel/inspection stack - an
attacker who holds the sending gateway defeats the model. See the limitations in
`docs/MODELS.md` and the paper's Conclusion.

## License

Released under the MIT License (see [`LICENSE`](LICENSE)). The MalConv2 model
definitions in `railcds/inspection/vendor/malconv2/` come from
FutureComputing4AI/MalConv2 and stay under the Apache License 2.0 (see the
`LICENSE` file in that folder). The pretrained models fetched by
`scripts/download_models.py` are not part of this repository and keep their own
licences.
