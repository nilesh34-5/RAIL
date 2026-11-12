# SENDER (Network A) - start here

This folder is the **source-side gateway**. It inspects every object and is the
only side that holds the private key. Copy this whole folder to Network A.

## 1. Install (full stack - inspection runs here)

```bash
py -m pip install -r requirements.txt
```

```bash
py -m pip install "git+https://github.com/FutureComputing4AI/EMBER2024.git" "signify==0.5.2"
```

```bash
py -m pip install torch --index-url https://download.pytorch.org/whl/cpu
```

## 2. Point it at the receiver

In `config/rail.yaml`:

```yaml
transport:
  send_host: "__RECEIVER_IP__"   # the RECEIVER's IP address
  send_port: 52080
```

## 3. Check the inspection stack loaded

```bash
py -m railcds.cli detectors
```

Expect 7 detectors marked `available`. Anything `UNAVAILABLE` means a model is
missing - run `py scripts/download_models.py --deep` and then
`py scripts/train_anomaly.py`.

## 4. Keys

A working keypair is already included so you can test immediately. To generate
a fresh one:

```bash
py scripts/gen_keys.py
```

Then copy **only** `data/keys/sender_ed25519.pub` into the RECEIVER folder.
The `.key` file must never leave this machine.

## 5. Lock the network down (recommended)

```bash
py -m railcds.cli lockdown --role sender --peer __RECEIVER_IP__ --apply
```

Run it without `--apply` first to review the rules. Needs Administrator/root.
Without this, the two hosts can still reach each other over SSH, SMB, HTTP and
ICMP - RAIL's Python controls only its own sockets.

## 6. Send

```bash
py -m railcds.cli send --spool data/spool
```

## Other things you can run here

| Command | What it does |
|---|---|
| `py scripts/demo_local.py --loss 0.2` | whole pipeline in one process |
| `py scripts/demo_attacks.py` | threat model T1-T5, expect 10/10 |
| `py scripts/evaluate.py` | goodput / overhead / accuracy / channel capacity |
| `py scripts/benchmark_models.py` | compare the ML detectors |
| `py -m pytest -q` | 26 tests |

Full detail is in the **DOCS** folder.
