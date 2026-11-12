# RAIL evaluation results

Measured on the reference implementation with `python scripts/evaluate.py`.
Raw numbers are in `results_evaluation.json`; the console transcript is
`eval_full.txt`.

The paper's Conclusion defers evaluation of **goodput, integrity overhead,
inspection accuracy and measured channel capacity**. This document reports all
four, plus validation of the paper's worked examples and one-way reliability.

**Test bed.** 8 logical CPUs, Windows 10, Python 3.13.7, CPU-only inference.
Seven detectors active: `protocol_validator`, `file_type`, `entropy_anomaly`,
`yara_signature`, `ember2024_ml`, `malconv_ml`, `malconvgct_ml`.
Policy `rail-policy-2026.08`, θ_blk = 0.90, B = 4 bands.

---

## E1 - Goodput (MB/s)

| Object | S2 inspect | S3 integrity | S4 FEC | End-to-end |
|---|---|---|---|---|
| 1 MB | 0.27 | 99.3 | 0.29 | 0.14 |
| 4 MB | 0.28 | 336.6 | 0.25 | 0.13 |
| 16 MB | 0.27 | **327.6** | 0.21 | **0.12** |

Per-MB cost at 16 MB: inspection **3.70 s**, FEC **4.76 s**, integrity **0.003 s**.

**Stage S3, the mechanism this paper contributes, costs 0.08 % of pipeline
time.** Risk-adaptive integrity layering is essentially free relative to the
inspection and coding stages that surround it, so adaptive auditability comes
at negligible throughput cost.

The two bottlenecks are both implementation artefacts, not architectural:

* **S4 FEC (4.76 s/MB)** - our portable Cauchy Reed-Solomon coder is pure-Python
  NumPy. A native RaptorQ or ISA-L implementation is 2-3 orders of magnitude
  faster.
* **S2 inspection (3.70 s/MB)** - dominated by the three ML models running
  sequentially on CPU. Detectors are independent by construction (Noisy-OR
  assumes it), so they parallelise trivially; GPU inference would help further.

End-to-end goodput is **≈0.12 MB/s on this prototype**; it reflects unoptimised
Python, not a limit of the architecture.

---

## E2 - Integrity overhead (Stage S3), 16 MB object

| Band | r̃ | Chunk size | Chunks | S3 time | Goodput | Metadata | Metadata % |
|---|---|---|---|---|---|---|---|
| 0 | 0.00 | 1,048,576 | 16 | 28.0 ms | 572 MB/s | 539 B | 0.0032 % |
| 1 | 0.25 | 370,728 | 46 | 33.7 ms | 474 MB/s | 762 B | 0.0045 % |
| 2 | 0.50 | 131,072 | 128 | 52.1 ms | 307 MB/s | 1,420 B | 0.0085 % |
| 3 | 0.75 | 46,341 | 363 | 30.7 ms | 521 MB/s | 2,936 B | 0.0175 % |

Breakdown at the top band: hash chain 18.5 ms, chunking 10.1 ms, Merkle 1.9 ms,
signature 0.3 ms.

**Findings.**

1. **Maximum scrutiny costs 1.10× the time of minimum scrutiny** while giving
   23× finer chunk granularity. The adaptation is nearly free in CPU terms -
   SHA-256 throughput depends on total bytes hashed, not on how they are split.
2. **Metadata stays under 0.02 % of object size** even at the finest
   granularity, so adaptive integrity does not meaningfully inflate what
   crosses the wire.
3. Timing is not monotone in band (band 2 measured slowest) because the cost is
   dominated by memory traffic and allocator behaviour rather than chunk count.
   With only two repetitions this is measurement noise - **increase `reps` before
   quoting per-band timings as a trend.**

### Merkle proof scaling

| Chunks | Proof hashes | Proof bytes |
|---|---|---|
| 16 | 4 | 128 |
| 64 | 6 | 192 |
| 256 | 8 | 256 |
| 1,024 | 10 | 320 |
| 4,096 | 12 | 384 |

Exactly log₂(n), confirming the paper's claim that doubling the chunk count adds
a single hash - 1,024 chunks need 10 hashes, as the paper states.

---

## E3 - Inspection accuracy

**Benign corpus: 60 signed Windows system binaries.**

* Risk: mean **0.280**, median 0.258, range 0.232-0.467
* **False positive rate at θ_blk = 0.90: 0/60 = 0.0 %**

**Synthetic threat set: 4 objects, detection rate 100 %.**

| Object | Risk | Blocked | Caught by |
|---|---|---|---|
| `suspicious.ps1` | 0.982 | yes | YARA (encoded PowerShell) |
| `polyglot.pdf` | 0.939 | yes | `file_type` 0.85 + YARA 0.70 |
| `random.bin` | 0.927 | yes | anomaly + EMBER2024 |
| `signature_hit.txt` | 0.903 | yes | YARA signature |

### Per-detector false-alarm profile (benign corpus)

| Detector | Mean | Max |
|---|---|---|
| `entropy_anomaly` | 0.280 | 0.518 |
| `yara_signature` | 0.150 | 0.150 |
| `ember2024_ml` | 0.030 | 0.204 |
| `malconvgct_ml` | 0.003 | 0.091 |
| `malconv_ml` | 0.000 | 0.001 |
| `protocol_validator`, `file_type` | 0.000 | 0.000 |

The three pretrained ML models are the *quietest* detectors on benign traffic -
they contribute almost nothing to false alarms while carrying most of the
detection weight. The unsupervised anomaly detector is the noisiest, which is
expected: it measures distributional novelty, not maliciousness, and is why it
carries a modest weight (0.5).

### A false-positive bug this experiment found

The first run showed benign mean risk of **0.690** with `yara_signature` scoring
**0.700 on 100 % of benign binaries**. The bundled rule
`Embedded_Executable_Marker` used the condition:

```
$mz and not ($mz at 0)      // $mz = "This program cannot be run in DOS mode"
```

In a legitimate PE that string sits at roughly offset 78 - never at 0 - so the
rule matched **every valid Windows executable**. Fixed by requiring that the
*carrier* is not itself an executable:

```
($mz and uint16(0) != 0x5A4D) or ($elf in (64..filesize) and uint32(0) != 0x464C457F)
```

`Windows_PE_Executable` was also demoted to a new `info` severity (0.15),
because file typing is the `file_type` detector's job and scoring it twice
violates the independence Noisy-OR assumes.

**Effect: benign mean risk 0.690 -> 0.280; detection rate 75 % -> 100 %.**

This shows why per-detector false-alarm profiling is a necessary deployment
step - the gateway never errored, it simply treated every executable as
half-suspicious, and only measurement against a benign corpus exposed it.

### Limitation

**This is not a malware-detection accuracy benchmark.** The false-positive rate
is measured against real benign binaries and is meaningful. The 100 % detection
rate is against four *synthetic* threat objects and is **not** a TPR against
real malware. Establishing that requires a labelled corpus (EMBER2024 test set,
VirusShare) inside an isolated VM with host AV disabled - see
`deploy/README_NETWORK.md` §5. Published EMBER2024/MalConv figures should be
cited for model accuracy rather than re-derived here.

---

## E4 - Covert-channel capacity vs the Eq. (6) bound

Attacker model: the adversary cannot hide data *in* the file - that is what
inspection is for - but can choose benign artefacts that steer the risk score,
encoding data in the band, which is observable from Network B.

| Quantity | Value |
|---|---|
| Bands B | 4 |
| Eq. (6) bound at λ = 1 obj/s | **2.000 bit/s** |
| Trials | 120 |
| Attacker symbol->band accuracy | 20.0 % |
| Distinct bands actually reachable | {1, 3} |
| **Measured mutual information** | **0.837 bit/object** |
| **Measured capacity at λ = 1 obj/s** | **0.837 bit/s** |
| Within derived bound? | **YES** (0.837 ≤ 2.000) |

The paper leaves open "whether observed leakage stays within the derived
bound." It does, at **42 % of the bound**.

Two reasons the measured channel is well under the theoretical maximum:

1. The attacker could only reliably reach **2 of 4 bands** with benign-looking
   artefacts, so the practical alphabet is smaller than B.
2. Steering accuracy was 20 %, near chance - the Noisy-OR combination of seven
   detectors makes the resulting band hard to control precisely.

The bound is therefore **conservative but not vacuous**: 2 bit/s is a usable
ceiling. Note this measures one
specific attacker strategy; a better-informed adversary who knows the detector
weights would score higher, still capped at log₂B.

---

## E5 - Validation of the paper's worked examples

| Claim in paper | Paper states | Measured | Match |
|---|---|---|---|
| Eq. 2, 10 MB at r = 0.1 | ~15 chunks | 691,802 B -> **16 chunks** | yes |
| Eq. 2, 10 MB at r = 0.9 | ~420 chunks | 24,834 B -> **423 chunks** | yes |
| Eq. 4, T(0) | = T_max | **300.0 s** (T_max = 300) | yes |
| Eq. 4, T(1) | = T_min | **5.0 s** (T_min = 5) | yes |
| Eq. 1, five 0.02 + one 0.9 | ~0.91 vs mean ~0.16 | **0.910** vs **0.167** | yes |
| Merkle proof, 1,024 chunks | ~10 hashes | **10 hashes** | yes |

Every numeric claim printed in the paper reproduces on the implementation.

---

## E6 - One-way reliability (FEC, no acknowledgements)

256 KiB payload, 50 % FEC overhead, Cauchy Reed-Solomon backend.

| Loss rate | Recovery |
|---|---|
| 0 % | 100 % |
| 5 % | 100 % |
| 10 % | 100 % |
| 20 % | 100 % |
| 30 % | 60 % |
| 40 % | 0 % |

Recovery is total while loss stays comfortably below the configured overhead,
degrades in the transition region, and fails completely beyond it. There is no
retransmission path on a one-way link, so **`fec.overhead` must be provisioned
above worst-case expected link loss**, not average loss.

The degradation at 30 % (below the nominal 50 % overhead) is a real and
important effect: a large object spans many independent coding *generations*,
and the object is lost if *any single generation* falls below its recovery
threshold. Whole-object delivery probability therefore falls off faster than
per-generation probability. This argues for provisioning overhead well above the
loss rate, and it is the quantitative version of the paper's observation that
redundancy "has to be decided in advance from the expected loss on the link."

---

## Summary

| Parameter (as named in the paper) | Result |
|---|---|
| **Goodput** | 0.12 MB/s end-to-end; S3 is 0.08 % of cost; bottlenecks are pure-Python FEC and CPU ML inference |
| **Integrity overhead** | 1.10× time for 23× finer granularity; metadata < 0.02 % of object; Merkle proofs exactly log₂(n) |
| **Inspection accuracy** | 0 % FPR on 60 benign binaries; 100 % detection on the synthetic threat set; real-malware TPR not established |
| **Measured channel capacity** | 0.837 bit/s vs 2.000 bit/s bound - **leakage stays within the derived bound** |

Reproduce with:

```bash
python scripts/evaluate.py            # full run
python scripts/evaluate.py --quick    # faster, smaller samples
```
