# RAIL two-machine field test - runbook

Two real Linux machines (A = **sender**, Network A; B = **receiver**, Network B)
connected through a router. This covers: pre-flight, what to copy and how to
start, how to run every test, a full numbered test-case series, and a speed
test against a normal (non-RAIL) connection.

Everything here uses the **existing RAIL1 code** and the helper scripts in
`evaluation_testbed_2026-10/rail_eval` and `.../testbed`. Nothing in `railcds/`
needs editing. Only downloaded models are used.

---

## 0. Before you start - read this first

**Management access is the one thing that bites people.** The hardening step
cuts the diode link down to a single one-way UDP flow: after it runs, you
**cannot SSH over that link** (the receiver is not allowed to send anything
back). Plan for one of these:

- **Best:** two NICs per machine - one for the RAIL link (through the router)
  and one separate "management" NIC/network for SSH. The hardening keeps the
  management NIC open (`MGMT_IF`).
- **Simplest:** a keyboard + monitor (or the VM console) physically at each
  machine, so you can type commands locally after hardening.

Do **all unhardened tests first**, while you can still reach both boxes, then
harden.

**Network plan (fill this in before you touch anything):**

| Item | Machine A (sender) | Machine B (receiver) |
|---|---|---|
| RAIL-link interface (e.g. `eth1`, `enp3s0`) | `________` | `________` |
| RAIL-link IP (same subnet) | e.g. `192.168.50.10` | e.g. `192.168.50.20` |
| RAIL-link MAC (`ip -br link`) | `________` | **`________`** (sender needs this) |
| Management interface (if separate) | `________` | `________` |
| UDP port | `52080` | `52080` |

Put both machines on the **same subnet** on the router's LAN ports (so they are
layer-2 neighbours). Use a dedicated subnet with no other hosts if you can.

---

## 1. Pre-flight steps (both machines, BEFORE hardening)

1. **Cable + power.** Both machines into the router's LAN ports; router on.
2. **Find the interface names:** `ip -br link` and `ip -br addr`.
3. **Set static IPs** on the RAIL-link NIC (same subnet), e.g. on A:
   ```bash
   sudo ip addr add 192.168.50.10/24 dev <A_IF>
   sudo ip link set <A_IF> up
   ```
   and on B: `192.168.50.20/24` on `<B_IF>`.
4. **Confirm two-way connectivity NOW** (you lose it after hardening):
   ```bash
   # on A:  ping -c3 192.168.50.20      # on B:  ping -c3 192.168.50.10
   ```
5. **Record B's MAC** (sender needs it to pin a static ARP entry after B stops
   answering ARP):  on B run `ip -br link show <B_IF>` -> copy the MAC.
6. **Confirm time/date** are roughly right on both (timestamps go in the logs).
7. **Install prerequisites** (while you still have internet):
   - A: `sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip python3-dev build-essential libmagic1 git curl iptables arptables clang llvm libbpf-dev linux-headers-$(uname -r) iperf3 tcpdump`
   - B: `sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip iptables arptables iperf3 tcpdump`

---

## 2. Which folders to copy, and how to start

You can copy the **whole `RAIL1` folder to both machines** - it is the least
error-prone. (For a smaller trusted base on B you may instead use
`dist/RECEIVER`, regenerated with `scripts/package_dist.py --sender-ip <A> --receiver-ip <B>`; optional.)

Also copy the **`evaluation_testbed_2026-10` folder** (the harnesses and configs)
to **machine A** - the sender runs the analysis scripts.

### 2.1 Sender (machine A)
```bash
cd RAIL1
bash dist/SENDER/setup_kali_sender.sh      # venv + deps + models + keys
#   if you did not use dist/SENDER:  python3 -m venv .venv && source .venv/bin/activate
#   pip install cryptography PyYAML numpy scikit-learn joblib reedsolo lightgbm \
#       yara-python python-magic lief raptorq
#   pip install "git+https://github.com/FutureComputing4AI/EMBER2024.git"
#   pip install "signify==0.5.2"
#   pip install torch --index-url https://download.pytorch.org/whl/cpu
#   python3 scripts/download_models.py --deep         # downloads EMBER2024, MalConv(GCT), YARA
#   python3 scripts/gen_keys.py                        # Ed25519 keypair
source .venv/bin/activate
python3 -m railcds.cli detectors                       # all 3 ML models should say "available"
```
> Do **not** run `train_anomaly.py` - leave the IsolationForest out so only
> downloaded models are used (its detector falls back to the entropy heuristic).

### 2.2 Receiver (machine B)
```bash
cd RAIL1
bash dist/RECEIVER/setup_kali_receiver.sh  # venv + minimal deps (no ML, no models)
source .venv/bin/activate
```

### 2.3 Copy ONLY the public key A -> B
```bash
# from A, over the management network (NOT the diode link if it is already hardened):
scp data/keys/sender_ed25519.pub  <user>@192.168.50.20:RAIL1/data/keys/
# NEVER copy sender_ed25519.key.  B must only ever hold the .pub.
```

### 2.4 Point the two sides at each other (edit `config/rail.yaml` on both)
- On **A**: `transport.send_host: "192.168.50.20"` , `send_port: 52080`
- On **B**: `transport.bind_host: "0.0.0.0"` , `bind_port: 52080`
- On **both**: set `fec.backend: "reedsolo"` to start (identical on both sides),
  and make sure `policy.id` is **the same string** on both.
- (Or override per-run without editing the file:
  `RAIL_SEND_HOST=192.168.50.20 python3 -m railcds.cli send ...`)

### 2.5 First transfer (do this before any hardening)
```bash
# B first:
python3 -m railcds.cli receive --out data/received --no-preflight
# A:
python3 scripts/make_test_object.py --out data/spool
python3 -m railcds.cli send --spool data/spool --no-preflight
# On B, every object should print "DELIVERED ... verified: true".
# Compare a delivered file to the source to prove end-to-end integrity:
sha256sum data/received/benign.txt     # compare with the same file on A
```

---

## 3. How to conduct the tests

There are two kinds:

- **Networked tests** (need both machines + the router): clean transfer,
  one-way enforcement, forward-path-after-hardening, reliability under loss,
  tamper/replay over the wire, and the speed test. Use the **CLI**
  (`railcds.cli send/receive`) and the **harden/verify** scripts.
- **Sender-only analysis** (run on A, in-process, no link needed): detection
  accuracy, covert-channel capacity, integrity cost per band, stage timing.
  Use `scripts/evaluate.py` and the `rail_eval/*.py` helpers.

### 3.1 Hardening (the one-way enforcement) - machine-local commands
```bash
# RECEIVER (B) first, then SENDER (A).  Replace IFs/IPs/MAC with yours.
# on B:
cd RAIL1/deploy/diode-emulator
sudo ./harden_diode.sh receiver <B_IF> 192.168.50.10 52080 <B_MGMT_IF>
# on A (pin B's MAC because B will stop answering ARP):
cd RAIL1/deploy/diode-emulator
sudo PEER_MAC=<B_MAC> ./harden_diode.sh sender <A_IF> 192.168.50.20 52080 <A_MGMT_IF>
# optional driver layer (eBPF) on both:
cd RAIL1/railcds/driver
sudo ./load_xdp.sh attach receiver <B_IF> 192.168.50.10 52080     # on B
sudo ./load_xdp.sh attach sender   <A_IF> 192.168.50.20 52080     # on A
# verify:
sudo ./verify_diode.sh receiver <B_IF> 192.168.50.10    # on B
sudo ./verify_diode.sh sender   <A_IF> 192.168.50.20    # on A (run a transfer when it asks)
# release when done:
sudo python3 -m railcds.cli lockdown --role sender   --peer 192.168.50.20 --release   # on A
sudo python3 -m railcds.cli lockdown --role receiver --peer 192.168.50.10 --release   # on B
sudo ./load_xdp.sh detach <IF>
```

### 3.2 Loss emulation for reliability (on the SENDER's link NIC)
A standard kernel has `netem` (the namespace testbed did not, which is why it
used an eBPF emulator; that is **not** needed here):
```bash
sudo tc qdisc add dev <A_IF> root netem loss 10%            # random 10%
sudo tc qdisc change dev <A_IF> root netem loss 10% 25%     # bursty (correlated)
sudo tc qdisc del dev <A_IF> root                            # remove
```

### 3.3 Automated analysis on the sender
**Primary (self-contained):** `scripts/evaluate.py` already
measures goodput, integrity overhead, inspection accuracy, covert-channel
capacity and reliability in-process - no extra files needed.
```bash
cd RAIL1 && source .venv/bin/activate
python3 scripts/evaluate.py --out results_evaluation.json
```
**Richer, optional (the field harnesses):** these give per-tier
detection metrics, Wilson CIs and the B=2/4/8/16 covert-channel sweep. They need
a folder of **your own benign files** (the included `build_corpus.py` scans
paths from the build box and will not reproduce on your machine, so point the
analysis at a folder you choose, e.g. a copy of `/usr/bin`, some PDFs/Office
files, etc.):
```bash
# make a benign manifest from any folder of benign files (edit ROOT):
python3 - <<'PY'
import os, hashlib, csv, glob, shutil
ROOT = "/usr/bin"          # <-- any folder of benign files (binaries, PDFs, docs...)
out  = "/tmp/benign"
os.makedirs(out + "/x", exist_ok=True)
rows = []
for i, p in enumerate(f for f in glob.glob(ROOT + "/**/*", recursive=True) if os.path.isfile(f)):
    sz = os.path.getsize(p)
    if not (512 <= sz <= 20 * 1024 * 1024):
        continue
    dst = f"x/f_{i}{os.path.splitext(p)[1]}"
    shutil.copy(p, out + "/" + dst)
    rows.append({"file": dst, "class": "misc", "size": sz,
                 "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest(),
                 "origin": "local", "source_name": os.path.basename(p)})
w = csv.DictWriter(open(out + "/manifest.csv", "w", newline=""), fieldnames=list(rows[0]))
w.writeheader(); w.writerows(rows)
print("benign files:", len(rows))
PY
python3 ../evaluation_testbed_2026-10/rail_eval/e5_inspect.py  --node $PWD --config config/rail.yaml \
        --benign /tmp/benign --positives data/spool --out /tmp/e5.jsonl
python3 ../evaluation_testbed_2026-10/rail_eval/e5_analyze.py  --e5 /tmp/e5.jsonl --out /tmp/e5_metrics.json
python3 ../evaluation_testbed_2026-10/rail_eval/e7_covert.py   --e5 /tmp/e5.jsonl --out /tmp/e7.json
python3 ../evaluation_testbed_2026-10/rail_eval/e34_perf.py    --node $PWD --config config/rail.yaml --out /tmp/e34.json
```

---

## 4. Test-case series

Record, for each: date/time, who ran it, exact command, observed result,
PASS/FAIL. "A:" = run on sender, "B:" = run on receiver.

| ID | Objective | Pre-cond. | Steps (A / B) | Expected result | Pass criteria |
|---|---|---|---|---|---|
| **TC-00** | Link & reachability | IPs set, **unhardened** | A: `ping -c3 <B_IP>`; B: `ping -c3 <A_IP>` | Both ping succeed | 0% loss both ways |
| **TC-01** | Key exchange | setup done | B: `ls data/keys/` | Only `sender_ed25519.pub` on B (no `.key`) | `.pub` present, `.key` absent on B |
| **TC-02** | Detector pre-flight | sender setup | A: `python3 -m railcds.cli detectors` | ember2024, malconv, malconvgct = **available** | all 3 ML "available" |
| **TC-03** | Clean transfer | unhardened | B: `cli receive --out data/received`; A: `make_test_object.py` then `cli send --spool data/spool` | B prints DELIVERED/verified:true for benign objects | delivered SHA-256 == source; `verified:true` |
| **TC-04** | Inspection / quarantine | sender setup | A: `cli inspect data/spool/polyglot.pdf` and `.../suspicious.ps1` | risk high; polyglot/EICAR flagged; high-risk object QUARANTINED on send | malicious objects not sent; benign sent |
| **TC-05** | One-way: IP channels | **hardened** | B: `ping -c3 <A_IP>`; `curl`/`nc` to A; A: `sudo tcpdump -ni <A_IF> -Q in` | all B->A attempts fail; tcpdump on A sees **0** frames from B | 0 frames from B reach A |
| **TC-06** | One-way: ARP / L2 | hardened | B: `sudo ./verify_diode.sh receiver <B_IF> <A_IP>` | ARP egress DROP on B; A has static ARP for B | verify_diode "one-way properties hold" |
| **TC-07** | One-way: raw frame / driver layer | hardened + XDP | A: `tcpdump -ni <A_IF> -Q in -e`; B: send a raw AF_PACKET frame (script below) | with tc/XDP on, 0 raw frames reach A; detach tc on B and it reaches the wire | driver layer stops raw frame |
| **TC-08** | Forward path after hardening | hardened | repeat TC-03 | objects still DELIVERED A->B | delivery still works one-way |
| **TC-09** | Tamper detection | both up | A: `python3 scripts/demo_attacks.py` (or `e6_tamper.py --attack bitflip/chunk_swap/truncation/forged_sig`) | every tampered object REJECTED at S5 | 100% rejected, 0 delivered |
| **TC-10** | Replay detection | receiver running | A: `e6_tamper.py --attack replay` | 1st copy delivered, replay REJECTED ("replayed epoch") | replay rejected in-session |
| **TC-11** | Audit-log integrity | after transfers | A: `cli verify-log data/audit_sender.jsonl`; then edit a line and re-run | intact -> OK; edited -> "chain BROKEN at index"; **tail truncation not caught** without anchor | edit detected; note truncation caveat |
| **TC-12** | Reliability vs loss | unhardened; netem | A: set `netem loss X%`; run batch of N objects; B: count DELIVERED. X = 0,5,10,20,30,40; random & bursty; `fec.repeat` 1 & 2 | full delivery to ~overhead margin, then falls; rep 2 survives higher random loss; bursts harder | delivery curve recorded with CIs |
| **TC-13** | FEC overhead η | from TC-12 | A: read `symbols_sent` vs object size | η≈0.5 (rep 1), ≈2.0 (rep 2) | overhead recorded |
| **TC-14** | Detection accuracy | sender-only | A: `scripts/evaluate.py` (primary); or `e5_inspect.py`->`e5_analyze.py` on your own benign folder | TPR on threat set; FPR on benign (PE/ELF low, diverse higher); AUC; noisy-OR vs mean/max | metrics produced |
| **TC-15** | Covert channel | sender-only | A: `scripts/evaluate.py` (E4 block); or `e7_covert.py` for the B=2/4/8/16 sweep | measured leakage < bound λ·log₂B | within bound |
| **TC-16** | Integrity cost per band | sender-only | A: `scripts/evaluate.py` (E2 block); or `e34_perf.py --node $PWD --config config/rail.yaml` | S3 ≈ few ms (≈0.04% of pipeline); chunks/metadata per band | per-band table produced |
| **TC-17** | Anchor-write reduction | from logs | A: count lines in `data/ledger.jsonl` vs objects | RAIL ≪ per-object anchoring | reduction recorded |
| **TC-SPEED** | **Speed vs normal network** | unhardened | see §5 | RAIL goodput vs raw iperf3 baseline -> overhead ratio | numbers recorded |

**TC-07 raw-frame sender (run on B):**
```bash
sudo python3 - <<'PY'
import socket
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); raw.bind(("<B_IF>",0))
dst=bytes.fromhex("<A_MAC_no_colons>"); src=bytes.fromhex("<B_MAC_no_colons>")
frame=dst+src+b"\x08\x00"+b"RAWBYPASS"*8
for _ in range(5): raw.send(frame)
print("sent 5 raw frames")
PY
```

---

## 5. TC-SPEED - RAIL speed vs a normal connection

This is the comparison the automated suite does **not** do by itself. Run it
**unhardened** (you need a normal two-way link for the iperf3 baseline).

**Step 1 - raw link capacity (plain network, no RAIL):**
```bash
# B:  iperf3 -s
# A:  iperf3 -c 192.168.50.20 -u -b 0 -t 20      # UDP, push as fast as possible
#     iperf3 -c 192.168.50.20 -t 20              # TCP throughput too
```
Record the Mbit/s. This is your link's normal speed.

**Step 2 - RAIL end-to-end goodput (same object, through the full pipeline):**
```bash
# make a benign ~50 MB object (low entropy so it is not quarantined):
A: yes "RAIL throughput test payload line." | head -c 52428800 > data/spool/big.txt
# B:
python3 -m railcds.cli receive --out data/received --no-preflight
# A (time it):
time python3 -m railcds.cli send data/spool/big.txt --no-preflight
```
RAIL goodput ≈ `50 MB ÷ (seconds printed)`. For a per-stage picture
(`inspection vs FEC vs integrity`), run `e34_perf.py` (TC-16).

**Step 3 - the ratio:** `overhead = raw_capacity ÷ RAIL_goodput`.
Expect RAIL to be **much slower than the raw link** - the cost is almost all in
S2 inspection (the three ML models) and the pure-Python FEC, *not* in the RAIL
integrity layer (S3 ≈ 0.04% of the time). To separate "RAIL design cost" from
"prototype cost":

- Run the big transfer with **inspection effectively off** (in `config/rail.yaml`
  set `enabled: false` for `ember2024_ml`, `malconv_ml`, `malconvgct_ml`) to see
  goodput without the ML bottleneck. That isolates the transport + integrity cost.
- Compare rail goodput **with** vs **without** those detectors to show inspection
  is the dominant cost, and that the adaptive-integrity mechanism itself is nearly
  free.

> Note: RAIL runs over **UDP with forward error correction and no ACKs**, so the
> fair baseline is iperf3 **UDP** at a comparable send rate, plus the FEC
> overhead (η). A plain TCP number will look faster partly because it is a
> different transport, not only because of RAIL.

---

## 6. Suggested order

1. TC-00 ... TC-04 and TC-03 (unhardened) - prove it works and inspects.
2. **TC-SPEED** and TC-12/TC-13 (unhardened - you need the two-way link + netem).
3. TC-14, TC-15, TC-16, TC-17 (sender-only analysis - can run any time).
4. Harden (receiver first, then sender; then XDP). Keep local console access.
5. TC-05, TC-06, TC-07, TC-08 (enforcement + forward path after hardening).
6. TC-09, TC-10, TC-11 (tamper/replay/log).
7. Release hardening (`lockdown --release`, `load_xdp detach`) and restore SSH.

Save every result (the JSON files and the PASS/FAIL notes).
