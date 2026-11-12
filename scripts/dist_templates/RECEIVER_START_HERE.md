# RECEIVER (Network B) - start here

This folder is the **destination-side gateway**. It is small: it
performs no inspection, holds no private key, and needs no ML libraries. Copy
this whole folder to Network B.

There is no `railcds/inspection/` here and no `models/` directory:
inspection happens on the sender, so shipping it here would only enlarge the
trusted computing base on the side the architecture is protecting.

## 1. Install (three packages)

```bash
py -m pip install -r requirements.txt
```

No lightgbm, no torch, no yara, no lief.

## 2. Check the port

In `config/rail.yaml`:

```yaml
transport:
  bind_host: "0.0.0.0"
  bind_port: 52080      # must equal the sender's send_port
```

## 3. Public key

`data/keys/sender_ed25519.pub` is already here and matches the SENDER folder.
If you regenerate keys on the sender, copy the new `.pub` across. Never copy
the `.key`.

## 4. Lock the network down (recommended)

```bash
py -m railcds.cli lockdown --role receiver --peer __SENDER_IP__ --apply
```

On Linux you can go one layer lower, to the NIC driver. Compile-check first:

```bash
sudo bash railcds/driver/load_xdp.sh verify receiver __SENDER_IP__ 52080
```

```bash
py -m railcds.cli driverfilter --role receiver --peer __SENDER_IP__ --iface eth1 --apply
```

## 5. Listen

```bash
py -m railcds.cli receive --out data/received
```

Start this **before** the sender, and allow a few seconds - the sender loads
several hundred MB of ML models before its first datagram leaves.

## 6. Check what arrived

```bash
py -m railcds.cli verify-log data/audit_receiver.jsonl
```

Delivered objects land in `data/received/`. Each audit-log line records the
Merkle root, the signature, the quantised risk band and the epoch.

## Four settings that MUST match the sender

| Setting | Symptom if wrong |
|---|---|
| `policy.id` | every object `REJECTED - policy mismatch` |
| `integrity.risk_bands` | `REJECTED - band out of range` |
| `bind_port` = sender's `send_port` | nothing arrives at all |
| public key matches sender's private key | `REJECTED - sig_ok=False` |

Chunk sizes and FEC settings do **not** need to match - chunk lengths travel in
the manifest and FEC parameters travel in each symbol header, so this side
adapts automatically.

Full detail is in the **DOCS** folder.
