# Two-VM test on Kali (VirtualBox) - step by step

Setup used:

| Role | VM | IP |
|---|---|---|
| Sender - Network A | Kali | **10.0.2.11** |
| Receiver - Network B | Kali | **10.0.2.8** |

`10.0.2.x` is VirtualBox's **NAT Network** range, so the VMs can reach each
other and still have internet. Packages are pre-configured for these addresses.

Work through Phase 0 -> 3 in order. Phase 3 (security enforcement) is optional.

---

## Phase 0 - Pre-flight (5 min)

Run on **both** VMs:

```bash
ip -brief addr show
```

Confirm one shows `10.0.2.11` and the other `10.0.2.8`, and note the interface
name (usually `eth0`).

From the **sender**, check the receiver is reachable:

```bash
ping -c 3 10.0.2.8
```

**If this fails**, your adapters are on plain *NAT*, not *NAT Network*. Plain
NAT isolates each VM and they can never talk. Fix in VirtualBox:
`VM -> Settings -> Network -> Adapter 1 -> Attached to: NAT Network`, on both VMs,
same network name. Then re-check.

Also confirm internet works (you need it for Phase 1):

```bash
ping -c 2 8.8.8.8
```

> **How many NICs do you have?** If `ip -brief addr` shows only `eth0`, you have
> a single NIC. Everything below still works - but see the note in Phase 3
> about what a single NIC cannot enforce.

---

## Phase 1 - Install (20-40 min, mostly downloads)

### 1.1 Get the folders onto the VMs

On **Windows**, serve the package folder over HTTP:

```powershell
cd RAIL1\dist
python -m http.server 8000
```

Find the host's address from a VM (the NAT Network gateway):

```bash
ip route | grep default
```

Then on the **sender** (substitute the gateway IP you just saw, often `10.0.2.1`):

```bash
mkdir -p ~/rail && cd ~/rail
wget -r -np -nH --cut-dirs=1 -R "index.html*" http://10.0.2.1:8000/SENDER/
```

and on the **receiver**:

```bash
mkdir -p ~/rail && cd ~/rail
wget -r -np -nH --cut-dirs=1 -R "index.html*" http://10.0.2.1:8000/RECEIVER/
```

*Alternatives if HTTP is awkward:* a VirtualBox shared folder (needs Guest
Additions), or a USB drive. The SENDER folder is ~43 MB, RECEIVER ~0.1 MB.

### 1.2 Install on the sender

```bash
cd ~/rail/SENDER && bash setup_kali_sender.sh
```

This installs the full inspection stack. Kali marks its system Python
"externally managed" (PEP 668), so the script builds a **virtualenv**.

Skip PyTorch if you want a faster install (you lose the two MalConv detectors):

```bash
SKIP_TORCH=1 bash setup_kali_sender.sh
```

At the end you should see 7 detectors. Any marked `UNAVAILABLE` are optional and
the others carry the decision.

### 1.3 Install on the receiver

```bash
cd ~/rail/RECEIVER && bash setup_kali_receiver.sh
```

Three packages plus RaptorQ. **No ML libraries, no models** - the receiver
performs no inspection.

### 1.4 Copy the public key

The packages ship a matching keypair so you can test immediately. To generate
fresh keys, on the **sender**:

```bash
cd ~/rail/SENDER && source .venv/bin/activate && python3 scripts/gen_keys.py
```

Then copy **only** `data/keys/sender_ed25519.pub` to the receiver's
`data/keys/`. Never copy the `.key`.

### 1.5 Keep the FEC backends in step

Check on **both** VMs:

```bash
source .venv/bin/activate && python3 -c "from railcds.fec import FEC; print(FEC(backend='auto').effective_backend)"
```

**Both must print the same thing.** If one says `raptorq` and the other
`reedsolo`, every object will be undecodable - and a one-way link gives the
receiver no way to tell you. If they differ, pin it in `config/rail.yaml` on
both sides:

```yaml
fec:
  backend: "reedsolo"
```

---

## Phase 2 - Functional test (10 min)

### 2.1 Start the receiver first

On the **receiver** (10.0.2.8):

```bash
cd ~/rail/RECEIVER && source .venv/bin/activate
python3 -m railcds.cli receive --out data/received
```

It prints `listening on 0.0.0.0:52080` and a warning that OS-level enforcement
is not active - correct at this stage; Phase 3 fixes it.

### 2.2 Send

On the **sender** (10.0.2.11), in a second terminal:

```bash
cd ~/rail/SENDER && source .venv/bin/activate
python3 -m railcds.cli send --spool data/spool
```

Wait a few seconds after starting the receiver - the sender loads several
hundred MB of ML models before its first datagram.

### 2.3 What you should see

**Sender:** 6 objects processed. `benign.txt` and `report.pdf` -> `SENT`;
`random.bin`, `signature_hit.txt`, `suspicious.ps1`, `polyglot.pdf` ->
`QUARANTINED`. The quarantined ones **never leave Network A** - that is Stage S2
blocking at `θ_blk = 0.90`.

**Receiver:** `DELIVERED` with `verified: true` for the objects that were sent.

### 2.4 Verify integrity

On the **sender**:

```bash
sha256sum data/spool/benign.txt data/spool/report.pdf
```

On the **receiver**:

```bash
sha256sum data/received/benign.txt data/received/report.pdf
```

The hashes must match exactly.

### 2.5 Verify the audit trail

On **both** VMs:

```bash
python3 -m railcds.cli verify-log data/audit_sender.jsonl      # sender
python3 -m railcds.cli verify-log data/audit_receiver.jsonl    # receiver
```

Both must report `chain intact`. Then compare the ledger anchors - the same
Merkle root should appear from both sides, which is the independent
cross-check the paper describes:

```bash
cat data/ledger.jsonl
```

### 2.6 Adaptive behaviour (the paper's core claim)

On the **sender**:

```bash
python3 scripts/demo_local.py --loss 0.2
```

Read the table: as `risk` rises, `chunk_sz` **falls** (Eq. 2) and `anchor(s)`
**falls** (Eq. 4, the inverse direction).

Then the threat model and the measurements:

```bash
python3 scripts/demo_attacks.py     # expect 10/10
python3 scripts/evaluate.py         # the paper's four parameters
python3 -m pytest -q                # expect 26 passed
```

---

## Phase 3 - Security enforcement (15 min)

Until now the two VMs can still reach each other over SSH, ICMP and everything
else. The Python controls only its own sockets.

### 3.1 See the rules before applying them

On the **sender**:

```bash
python3 -m railcds.cli lockdown --role sender --peer 10.0.2.8
```

Read the output, then apply:

```bash
sudo -E env "PATH=$PATH" python3 -m railcds.cli lockdown --role sender --peer 10.0.2.8 --apply
```

On the **receiver**:

```bash
sudo -E env "PATH=$PATH" python3 -m railcds.cli lockdown --role receiver --peer 10.0.2.11 --apply
```

This is **peer-scoped**: it blocks traffic between these two VMs only, leaving
each machine's internet intact. You cannot lock yourself out.

### 3.2 Prove the boundary is one-way

From the **receiver**, every one of these must FAIL:

```bash
ping -c 2 -W 2 10.0.2.11
```

```bash
timeout 4 bash -c 'cat < /dev/tcp/10.0.2.11/22'
```

Check the drop counters:

```bash
sudo iptables -L OUTPUT -v -n | grep 10.0.2.11
```

From the **sender**, capture while a transfer runs - you should see traffic
leaving and **nothing coming back**:

```bash
sudo tcpdump -ni any host 10.0.2.8
```

### 3.3 Confirm RAIL still works through the rules

Re-run Phase 2.1-2.2. Objects must still be delivered and verified. That is the
point: everything is blocked *except* the one permitted flow.

### 3.4 What a single NIC cannot enforce

With one NIC, two things from the paper's model are **not** enforced:

* **ARP is still answered.** `arptables` policy is global, so blocking ARP would
  also cut the VM's default gateway. The receiver therefore still replies to the
  sender's ARP requests - a residual layer-2 reverse channel. The tool warns
  about this rather than silently skipping it.
* **The segment is shared with NAT traffic**, so it is not an isolated diode
  segment.

**To close both**, add a second adapter to each VM:

`VM -> Settings -> Network -> Adapter 2 -> Attached to: Internal Network`, name it
`rail-diode`, on both VMs. Inside each VM give it a static address
(10.20.0.10 on the sender, 10.20.0.20 on the receiver), point the configs at
those addresses, and then use strict scope:

```bash
sudo bash deploy/diode-emulator/harden_diode.sh receiver eth1 10.20.0.10 52080 eth0
```

Now `eth0` is out-of-band management and `eth1` carries only RAIL - which is the
topology the paper assumes, and the only one where ARP blocking is safe.

### 3.5 Undo

```bash
sudo -E env "PATH=$PATH" python3 -m railcds.cli lockdown --role sender --peer 10.0.2.8 --release
```

---

## Optional - driver-layer enforcement (Linux only)

On the **receiver**:

```bash
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) linux-tools-common
sudo bash railcds/driver/load_xdp.sh verify receiver 10.0.2.11 52080
```

That compiles the eBPF only. To attach (use the diode NIC if you added one):

```bash
sudo bash railcds/driver/load_xdp.sh attach receiver eth0 10.0.2.11 52080
sudo bash railcds/driver/load_xdp.sh status eth0
```

**Read the attach mode it prints.** `xdpdrv` is the true driver rung;
`xdpgeneric` is a kernel-level fallback, not the driver layer. VirtualBox's
emulated NIC gives `xdpgeneric`.

Detach with:

```bash
sudo bash railcds/driver/load_xdp.sh detach eth0
```

---

## Troubleshooting

**Nothing arrives.** Check the ports match (52080 both sides), that the receiver
started first, and that both report the same FEC backend (§1.5).

**Every object REJECTED.** Almost always a `policy.id` mismatch or a stale
public key. Compare `config/rail.yaml` on both sides and re-copy the `.pub`.

**`externally-managed-environment` from pip.** You are outside the venv. Run
`source .venv/bin/activate` first.

**`set: pipefail: invalid option name`.** The `.sh` file has Windows line
endings. Fix: `sed -i 's/\r$//' <file>`.

**Detector `UNAVAILABLE`.** Optional models are missing; the rest still work.
Re-run `python3 scripts/download_models.py --deep`.

**Sender seems to hang.** Expected on first run - it is loading ML models.
Throughput is ~0.12 MB/s on this prototype (see `RESULTS.md` §E1).
