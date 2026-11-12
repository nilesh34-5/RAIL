# RAIL - final test report

Executed against the packaged build in `dist/` (SENDER 43.3 MB / RECEIVER 0.1 MB).

**Test bed.** 8 logical CPUs, Windows 10, Python 3.13.7, CPU-only inference.
Seven detectors active: `protocol_validator`, `file_type`, `entropy_anomaly`,
`yara_signature`, `ember2024_ml`, `malconv_ml`, `malconvgct_ml`.
Policy `rail-policy-2026.08`, θ_blk = 0.90, B = 4 bands, FEC overhead 50 %.

| Scenario | Status |
|---|---|
| A - Standalone (single process) | **executed, passed** |
| B - Two terminals, real UDP sockets | **executed, passed** |
| C - Two VMs on an isolated virtual network | **executed, passed** |

---

## A. Standalone

Run from `dist/SENDER` in one process, FEC symbols passed through a simulated
lossy channel.

| Check | Result |
|---|---|
| A1 Detectors load | **7/7 available** |
| A2 Unit tests | **26 passed** |
| A3 Threat model (T1-T5) | **10/10 checks passed** |
| A4 Pipeline S1-S6 @ 20 % loss | 2 delivered, 4 quarantined |
| A5 Audit chains | sender intact (6), receiver intact (2) |
| A6 Delivered objects | `benign.txt`, `report.pdf` **byte-identical** |

```
object             risk band  chunk_sz  chunks  symbols  sent   status  anchor(s)
benign.txt        0.457    1    370728       1        5     4 DELIVERED    170.9
polyglot.pdf      0.939    3         -       -        -     - QUARANTINE       -
random.bin        0.927    3         -       -        -     - QUARANTINE       -
report.pdf        0.831    3     46341       1        2     1 DELIVERED     23.4
signature_hit.txt 0.903    3         -       -        -     - QUARANTINE       -
suspicious.ps1    0.982    3         -       -        -     - QUARANTINE       -
```

Chunk size falls 370 728 -> 46 341 B and the anchoring interval falls
170.9 s -> 23.4 s as the band rises: Eq. (2) and Eq. (4) operating in the
inverted directions the paper specifies.

---

## B. Two terminals - real UDP between the two packaged folders

`dist/SENDER` -> `dist/RECEIVER` over UDP 127.0.0.1:52080. The receiver folder
contains **no `railcds/inspection/`, no models and no private key**.

**Sender (Network A)**

```
benign.txt         r=0.457 band=1 chunk=370728  symbols=5  SENT
polyglot.pdf       r=0.939 band=3 QUARANTINED
random.bin         r=0.927 band=3 QUARANTINED
report.pdf         r=0.831 band=3 chunk=46341   symbols=2  SENT
signature_hit.txt  r=0.903 band=3 QUARANTINED
suspicious.ps1     r=0.982 band=3 QUARANTINED
```

**Receiver (Network B)**

```
benign.txt   DELIVERED verified=True band=1
report.pdf   DELIVERED verified=True band=3
```

| Check | Result |
|---|---|
| B3 Delivered file integrity | both **byte-identical** to source |
| B4 Independent audit logs | A intact (6 entries), B intact (2 entries) |
| B5 Dual ledger anchoring | **same epoch and root from both sides** |

```
A(sender)   epoch=uEBAOCRhB5tk band=1 root=119d3e4538e8b68f
B(receiver) epoch=uEBAOCRhB5tk band=1 root=119d3e4538e8b68f
```

B5 is the cross-check the paper describes: two logs written and anchored
independently, agreeing on the commitment. It is the evidence that would survive
compromise of one gateway.

**This also validates the split package.** A receiver with the entire inspection
subsystem removed reconstructed, verified and delivered correctly - confirming
that inspection belongs wholly on the source side.

---

## C. Two VMs on an isolated virtual network

Vagrant 2.4.9 installed; two Ubuntu 22.04 VMs on a VirtualBox **internal
network** `rail-diode`, promiscuous mode denied, management out-of-band on the
NAT adapter.

| VM | Role | Diode IP | Packages installed |
|---|---|---|---|
| `netA` | sender | 10.20.0.10 | full ML stack, 7/7 detectors |
| `netB` | receiver | 10.20.0.20 | **cryptography, PyYAML, numpy only** |

The provisioning split is real: netB installed no ML libraries at all, matching
the architecture.

### C1-C2 One-way enforcement (kernel, iptables + arptables)

From **netB**, every route back to Network A is closed:

| Attempt | Result |
|---|---|
| `ping 10.20.0.10` | **blocked** |
| TCP/22 to 10.20.0.10 | **blocked** |
| arbitrary UDP to A | **dropped** (counter incremented) |
| `arptables` OUTPUT on eth1 | **policy DROP** |
| IPv6 on eth1 | **disabled** (`disable_ipv6 = 1`) |
| `ip_forward` | **0** on both |

### C3 Transfer across the diode

```
netA  benign.txt         r=0.409 band=1 chunk=370728 sym=5  SENT
netA  report.pdf         r=0.805 band=3 chunk=46341  sym=2  SENT
netA  polyglot.pdf / random.bin / signature_hit.txt / suspicious.ps1  QUARANTINED
netB  benign.txt, report.pdf  DELIVERED
```

**Byte-perfect delivery**, confirmed by SHA-256 on both machines:

```
netA  data/spool/benign.txt     71f7de26ee64cdad...
netB  data/received/benign.txt  71f7de26ee64cdad...   MATCH
netA  data/spool/report.pdf     f1d37b2e5ea6fcfc...
netB  data/received/report.pdf  f1d37b2e5ea6fcfc...   MATCH
```

Audit chains intact on both sides, written independently.

### C6 Diode evidence - firewall counters after the transfer

```
netA OUTPUT  7 pkts  7539 B  ACCEPT udp eth1 -> 10.20.0.20:52080
netA INPUT   0 pkts     0 B  DROP   all  eth1        (nothing came back)
netB INPUT   7 pkts  7539 B  ACCEPT udp eth1 <- 10.20.0.10:52080
netB OUTPUT  0 pkts     0 B  DROP   all  eth1        (nothing left toward A)
```

**7 packets out = 7 packets in, and zero reverse traffic in either direction.**
This is the evidence that the loopback scenarios cannot produce.

### Three defects this scenario exposed

None appeared in scenarios A or B.

**1. ARP hardening was too broad and cut management access.** The receiver
applied `arptables -P OUTPUT DROP` globally, silencing ARP on the *management*
NIC as well. netB became unreachable over SSH as soon as its ARP cache expired,
and the first transfer attempt failed with the sender's packets leaving but
nothing arriving. Fixed by scoping the block to the diode interface:

```
arptables -P OUTPUT ACCEPT
arptables -A OUTPUT -o eth1 -j DROP
```

This is the practical form of the paper's own warning that enforcement must be
placed carefully: a rule correct in intent silently removed the operator's
ability to administer the gateway.

**2. Shell scripts edited on Windows acquired CRLF endings** and failed on
Linux with `set: pipefail: invalid option name`. The packager now forces LF on
every shipped `.sh`.

**3. ARP ordering matters.** netA could not resolve netB's MAC once netB stopped
answering ARP (`10.20.0.20 FAILED`). The sender's MAC entry must be pinned
*before* the receiver is hardened - `PEER_MAC=...` does this, and the run above
used it.

---

## D. RaptorQ and the driver layer (executed on the VMs)

Two gaps that Windows could not close were closed on the Linux VMs.

### D1 RaptorQ (RFC 6330)

`raptorq 2.0.0` installs from a manylinux wheel, so both VMs run the fountain
code. `fec.py` implements the RaptorQ encoder/decoder path (`k = 0` in the RAIL
header marks a fountain symbol; the block code always uses k >= 1).

**Recovery vs packet loss** - 256 KiB object, 50 % overhead, 20 trials/point:

| Loss | RaptorQ | Reed-Solomon |
|---|---|---|
| 0 % | 100 % | 100 % |
| 10 % | 100 % | 100 % |
| 20 % | 100 % | 100 % |
| **30 %** | **85 %** | **75 %** |
| 40 % | 0 % | 0 % |
| 50 % | 0 % | 0 % |

RaptorQ is **10 points better in the transition region**, because it has no
generation boundaries: the block code loses the whole object if *any single*
generation falls short, whereas the fountain code needs only enough symbols in
aggregate. Both fail beyond ~35 % loss for an information-theoretic reason -
with 50 % overhead you cannot recover from fewer symbols than the object has
source symbols.

This is the paper's Sec. III-C argument, measured.

### D2 Driver layer - compiled, verified, attached

On netB the eBPF source compiled and the kernel verifier accepted both
programs, which were JIT-compiled:

```
82: xdp        name xdp_rail_ingres  tag eb4cdd89dfcb7d47  gpl  jited
86: sched_cls  name tc_rail_egress   tag 1c85150bf663ab60  gpl  jited
```

Both halves demonstrated in operation:

```
map 2 (XDP ingress): pass_in  = 14    RAIL datagrams admitted
map 3 (tc egress):   drop_out = 8     frames netB tried to send to A, shot
```

A full RaptorQ transfer ran **through** the attached filter and delivered
byte-identical objects, `verified: true` on both.

**Attach mode: `xdpgeneric`, not `xdpdrv`.** VirtualBox's emulated NIC has no
native XDP support, so the program runs post-`skb` rather than at the driver.
The enforcement tier actually achieved here is therefore **KERNEL**, not
DRIVER. The driver rung needs a receiver on hardware with a native-XDP NIC
(or a virtio-net interface), with the loader reporting `xdpdrv`.

### D3 Three further defects found

**1. `fec.backend: "auto"` can diverge across hosts.** netA gained RaptorQ and
auto-selected it; netB had not, and could not decode. On a one-way link the
receiver cannot signal a mismatch. **Pin `backend` explicitly on both sides**,
or ensure identical FEC support.

**2. The receiver crashed on an unexpected symbol.** A RaptorQ symbol reaching a
Reed-Solomon decoder was parsed with `k = 0` and killed the process with
`ValueError: need at least one array to concatenate`. A gateway that cannot
request a retransmission must never terminate on what arrives. Fixed: the
decoder now rejects structurally impossible headers, and the receive loop
converts any reconstruction or parse failure into a `REJECTED` result and keeps
serving. Two regression tests added (26 tests total).

**3. Loading the same eBPF object twice creates two copies of its map**, so the
XDP and tc programs do not share `rail_counters`. The status command now reads
every instance; otherwise egress counts silently read as zero.

---

# Final results - the four parameters named in the paper

## 1. Goodput

| Object | S2 inspect | S3 integrity | S4 FEC | End-to-end |
|---|---|---|---|---|
| 1 MB | 0.32 | 286.8 | 0.33 | 0.16 |
| 4 MB | 0.37 | 541.7 | 0.34 | 0.18 |
| 16 MB | 0.38 | **478.6** | 0.36 | **0.18** |

Per-MB cost at 16 MB: inspection 2.625 s, **FEC 2.791 s**, integrity **0.002 s**.

> **Stage S3 - the mechanism this paper contributes - is 0.04 % of pipeline
> time.** Risk-adaptive integrity layering is effectively free relative to the
> stages around it.

The bottleneck is **S4 FEC at 52 % of pipeline time**, followed by S2
inspection. Both are implementation artefacts: a pure-Python Cauchy
Reed-Solomon coder and three ML models run sequentially on CPU. Neither is an
architectural limit.

## 2. Integrity overhead (16 MB object)

| Band | r̃ | Chunk size | Chunks | S3 time | Metadata % |
|---|---|---|---|---|---|
| 0 | 0.00 | 1 048 576 | 16 | 22.1 ms | 0.0032 % |
| 1 | 0.25 | 370 728 | 46 | 26.8 ms | 0.0045 % |
| 2 | 0.50 | 131 072 | 128 | 21.9 ms | 0.0085 % |
| 3 | 0.75 | 46 341 | 363 | 21.9 ms | 0.0175 % |

**Maximum scrutiny costs 0.99× the time of minimum scrutiny for 23× finer
granularity**, with metadata below 0.02 % of object size. SHA-256 cost tracks
total bytes hashed, not how they are split, so the adaptation is essentially
free. Merkle proofs measured exactly log₂(n) - 1 024 chunks -> 10 hashes.

## 3. Inspection accuracy

* Benign corpus: 60 signed Windows binaries - risk mean **0.280**, max 0.467
* **False positive rate at θ_blk = 0.90: 0/60 = 0.0 %**
* **Detection rate on the synthetic threat set: 4/4 = 100 %** (0.903-0.982)

| Detector | Mean on benign | Max |
|---|---|---|
| `entropy_anomaly` | 0.280 | 0.518 |
| `yara_signature` | 0.150 | 0.150 |
| `ember2024_ml` | 0.030 | 0.204 |
| `malconvgct_ml` | 0.003 | 0.091 |
| `malconv_ml` | 0.000 | 0.001 |
| `protocol_validator`, `file_type` | 0.000 | 0.000 |

The three pretrained ML/DL models are the **quietest** detectors on benign
traffic while carrying most of the detection weight.

## 4. Measured covert-channel capacity

| Quantity | Value |
|---|---|
| Eq. (6) bound at λ = 1 obj/s | **2.000 bit/s** |
| Measured mutual information (120 trials) | **0.837 bit/object** |
| Attacker symbol->band accuracy | 20.0 % |
| Bands reachable with benign artefacts | 2 of 4 |
| **Within the derived bound?** | **YES - 42 % of bound** |

This answers the question the paper's Conclusion leaves open: observed leakage
does stay within the derived bound.

---

## Validation of the paper's worked examples

| Claim | Paper states | Measured |
|---|---|---|
| Eq. 2, 10 MB at r = 0.1 | ~15 chunks | **16** |
| Eq. 2, 10 MB at r = 0.9 | ~420 chunks | **423** |
| Eq. 4, T(0) / T(1) | T_max / T_min | **300.0 s / 5.0 s** |
| Eq. 1, five 0.02 + one 0.9 | ~0.91 vs mean ~0.16 | **0.910 vs 0.167** |
| Merkle proof, 1 024 chunks | ~10 hashes | **10** |

Every numeric claim printed in the paper reproduces on the implementation.

## One-way reliability (no acknowledgements)

| Loss | 0 % | 5 % | 10 % | 20 % | 30 % | 40 % |
|---|---|---|---|---|---|---|
| Recovery | 100 % | 100 % | 100 % | 100 % | **60 %** | **0 %** |

Recovery is total below the configured overhead and collapses beyond it. The
degradation at 30 % - below the nominal 50 % overhead - is real: a large object
spans many independent coding generations and is lost if *any one* falls short,
so whole-object delivery decays faster than per-generation recovery.

This is the empirical form of the block-code limitation the paper attributes to
Reed-Solomon in Sec. III-C, and it is the argument for fountain codes.

---

## Statement of limitations

1. **On Windows, FEC is Reed-Solomon, not RaptorQ.** No RaptorQ wheel exists
   for Windows / Python 3.13 and building it needs a Rust toolchain. On Linux
   RaptorQ is used (Sec. D1).
2. **The 100 % detection figure is against four synthetic objects.** It is not a
   true-positive rate against real malware, which needs a labelled corpus in an
   isolated VM with host AV disabled. The 0 % false-positive rate, measured on
   60 real signed binaries, *is* meaningful.
3. **Scenario C used 7 detectors on netA** after the ML stack was installed
   post-provisioning; the risk scores differ slightly from scenarios A and B
   because the anomaly model was retrained on the VM's own file corpus.
4. **Goodput is prototype-limited** (~0.18 MB/s), dominated by pure-Python FEC
   and CPU inference.
5. **The covert-channel figure measures one attacker strategy.** A better-
   informed adversary who knows the detector weights would score higher, still
   capped at log₂B.
6. **Enforcement is host-kernel-level, not hardware.** An attacker with kernel
   control of a gateway defeats it - which the paper's threat model already
   places out of scope.
