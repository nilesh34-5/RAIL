# Documentation index

Read these while testing. Nothing here needs to be copied to a gateway.

| File | What it covers |
|---|---|
| `FINAL_TEST_REPORT.md` | **Results.** All three test scenarios and the paper's four parameters |
| `TESTING_GUIDE.md` | **Start here.** Four test levels, sender vs receiver config, checklist, troubleshooting |
| `NETWORK_HARDENING.md` | Blocking every non-RAIL path; two-terminal and two-VM cases; driver-layer enforcement per OS |
| `MODELS.md` | The offline ML/DL detectors, how to download them, pretrained vs locally trained |
| `RESULTS.md` | Measured goodput, integrity overhead, inspection accuracy, covert-channel capacity |
| `ARCHITECTURE.md` | Paper-to-code map: stages S1-S6 and equations 1-6 |
| `RUNBOOK.md` | Install and run reference |
| `OVERVIEW_README.md` | Project overview |
| `deploy/` | Vagrant two-VM lab, Docker, diode hardening and verification scripts |
| `results_evaluation.json` | Raw evaluation numbers |

## Quick reference - the numbers

| Parameter (as named in the paper) | Measured |
|---|---|
| Goodput | 0.12 MB/s end-to-end; Stage S3 is 0.08 % of pipeline cost |
| Integrity overhead | 1.10× time for 23× finer granularity; metadata < 0.02 % of object |
| Inspection accuracy | 0 % false positives on 60 benign binaries; 100 % on the synthetic threat set |
| Covert-channel capacity | 0.837 bit/s measured vs the 2.000 bit/s Eq. (6) bound - within bound |

## Limitations

* **Goodput** on this prototype is ~0.12 MB/s, dominated by pure-Python FEC and
  CPU ML inference. That is an implementation limit, not an architectural one.
* **On Windows, FEC is Reed-Solomon, not RaptorQ.** No RaptorQ wheel exists for
  Windows / Python 3.13 and building it needs a Rust toolchain; on Linux RaptorQ
  is used. The E6 loss curve in `RESULTS.md` shows the block-code redundancy
  cliff the paper attributes to Reed-Solomon in Sec. III-C.
* **The 100 % detection figure is against synthetic threat objects.** A real
  malware TPR needs a labelled corpus inside an isolated VM with host AV off.
* **A true driver-layer filter is reachable out of the box only on Linux.**
  Windows needs Microsoft's XDP-for-Windows driver; macOS has no packet-level
  DriverKit hook, so `pf` is the floor.
* **Check the eBPF filter on the target host.** Run
  `railcds/driver/load_xdp.sh verify` on Linux before relying on it, and note
  whether it attaches as `xdpdrv` (driver rung) or `xdpgeneric` (kernel rung).
* **Everything is enforced by the two gateways' kernels.** An attacker with
  kernel control of a gateway defeats it - which the paper's threat model
  already places out of scope.
* **Detector weights and `block_threshold` are policy, not constants.** Profile
  against your own benign traffic before quoting accuracy; `evaluate.py` prints
  a per-detector false-alarm table for exactly this.
