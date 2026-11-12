# RAIL test over WiFi - start to finish

Two Linux laptops/PCs on the **same WiFi**. One is the **SENDER** (Network A),
the other is the **RECEIVER** (Network B). You will install RAIL, send files one
way from A to B, and run a set of tests in order.

Read the three short warnings first.

---

## Read this first (WiFi warnings)

1. **Turn off "AP isolation" on your router.** Many WiFi routers have a setting
   called *AP isolation* or *client isolation* that stops two WiFi devices from
   talking to each other. If it is on, nothing will work. Turn it off.

2. **You will lose SSH after you "harden" the link.** The whole point of RAIL is
   that the receiver is not allowed to send anything back. Once you turn on the
   one-way lockdown, you **cannot SSH into the machines over WiFi** anymore. So:
   - Do all the early tests first, while you can still use both machines normally.
   - When you get to the lockdown tests, **sit at each machine's own keyboard and
     screen** (or use its own terminal). Do not rely on SSH after lockdown.
   - When you are done, run the "release" command to get normal networking back.

3. **The eBPF / XDP "driver layer" usually does NOT work on WiFi.** That is
   normal. WiFi network cards do not support it. You will still get the real
   one-way enforcement from the firewall rules (iptables + arptables), which is
   what you demonstrate on WiFi. Also know that WiFi radios always send tiny
   "ACK" signals back in hardware that no software can switch off - so WiFi can
   never be a *perfect* physical diode. For a functional/lab test that is fine;
   for the strict diode claim, a wired link is better.

---

## Part 1 - Find the basic facts about each machine

Do this on **both** machines and write the answers down.

1. Find the WiFi network name of the card (looks like `wlan0`, `wlp2s0`, etc.):
   ```
   ip -br link
   ```
   The WiFi one is the entry that is "UP" and is not `lo`. Call it **WIFI_IF**.

2. Find the machine's WiFi IP address:
   ```
   ip -br addr
   ```
   Note the address next to your WiFi card, e.g. `192.168.1.25`. 

3. Find the WiFi card's hardware (MAC) address - you need the **receiver's** one
   later:
   ```
   ip -br link show <WIFI_IF>
   ```
   It looks like `aa:bb:cc:dd:ee:ff`.

Fill this in:

| | SENDER (A) | RECEIVER (B) |
|---|---|---|
| WiFi card name (WIFI_IF) | __________ | __________ |
| WiFi IP | e.g. 192.168.1.20 | e.g. 192.168.1.30 |
| WiFi MAC | (not needed) | __________ (needed by A) |
| Port | 52080 | 52080 |

4. Check they can talk to each other (do this now, before anything else):
   - On A: `ping -c 3 <B_IP>`
   - On B: `ping -c 3 <A_IP>`
   Both must succeed. If not, fix AP isolation / same-network first.

---

## Part 2 - Install RAIL (needs internet; do it before any lockdown)

Copy the **whole `RAIL1` folder** to both machines (USB stick or `scp` while you
still have normal networking). The ML models are already inside `RAIL1/models/`,
so nothing is downloaded again except Python packages.

**On the SENDER (A):**
```
cd RAIL1
bash dist/SENDER/setup_kali_sender.sh
source .venv/bin/activate
python3 -m railcds.cli detectors
```
The last command should list `ember2024_ml`, `malconv_ml`, `malconvgct_ml` as
**available**. (This step needs internet once, to install Python packages.)

**On the RECEIVER (B):**
```
cd RAIL1
bash dist/RECEIVER/setup_kali_receiver.sh
source .venv/bin/activate
```
The receiver installs almost nothing (no ML) - that is by design.

---

## Part 3 - Give the receiver the sender's public key

RAIL signs each file on A and checks the signature on B. B needs only the
**public** key. Never copy the private key.

On A, copy just the `.pub` file to B (over WiFi, before lockdown):
```
scp data/keys/sender_ed25519.pub  <you>@<B_IP>:RAIL1/data/keys/
```
On B, check it arrived:
```
ls data/keys/
```
You should see `sender_ed25519.pub`. You should **not** see `...key` on B.

---

## Part 4 - Point the two machines at each other

Open `config/rail.yaml` on each machine and set these.

**On the SENDER (A):**
```
transport:
  send_host: "<B_IP>"      # the receiver's WiFi IP
  send_port: 52080
fec:
  backend: "reedsolo"       # use the same on both sides
```
**On the RECEIVER (B):**
```
transport:
  bind_host: "0.0.0.0"
  bind_port: 52080
fec:
  backend: "reedsolo"
```
On **both**, make sure the `policy:` `id:` line is the **exact same text**.

---

## Part 5 - First real transfer (the main "it works" demo)

Do this **before** any lockdown, with both machines reachable.

1. On the **receiver (B)**, start listening:
   ```
   python3 -m railcds.cli receive --out data/received --no-preflight
   ```
   Leave it running. It waits for files.

2. On the **sender (A)**, make the sample test files and send them:
   ```
   python3 scripts/make_test_object.py --out data/spool
   python3 -m railcds.cli send --spool data/spool --no-preflight
   ```

3. Watch the receiver screen. For each safe file you should see a line saying
   **DELIVERED** and **verified: true**. The dangerous ones get **QUARANTINED**
   on the sender and never leave.

4. Prove the file arrived unchanged. On B:
   ```
   sha256sum data/received/benign.txt
   ```
   Compare that long code to the same file on A (`sha256sum data/spool/benign.txt`).
   They must match exactly.

If this works, the project runs. Everything below is testing it properly.

---

## Part 6 - The test files you will send, and what each one proves

`make_test_object.py` already created these in `data/spool` (none are real
malware):

| File | What it is | What should happen |
|---|---|---|
| `benign.txt` | ordinary text | DELIVERED, verified |
| `report.pdf` | a normal small PDF | DELIVERED, verified |
| `random.bin` | random/high-entropy bytes | high risk; may be QUARANTINED |
| `signature_hit.txt` | has the EICAR test marker | flagged by signature rules |
| `suspicious.ps1` | fake "encoded PowerShell" | flagged |
| `polyglot.pdf` | a file that is a PDF *and* carries an EXE header | high risk; QUARANTINED |

So "sending the test files" = steps in Part 5. The quarantine/flag behaviour is
test case **T2** below.

---

## Part 7 - The network test cases, in the order to run them

Run them top to bottom. Tests **T1-T6 do not need lockdown** (keep both machines
reachable). Tests **T7-T9 need lockdown** (sit at each machine's own keyboard).
For each test: do the action, check the "expected", mark PASS or FAIL.

### Before lockdown

**T1 - Clean one-way transfer**
- Do: Part 5 (receiver listening, sender sends the spool).
- Expected: safe files show DELIVERED + verified:true; the delivered file's
  sha256 equals the source. PASS if yes.

**T2 - Inspection and quarantine**
- Do, on A: `python3 -m railcds.cli inspect data/spool/polyglot.pdf` and
  `python3 -m railcds.cli inspect data/spool/signature_hit.txt`.
- Expected: high risk score; polyglot/EICAR are flagged. When you `send`, the
  high-risk ones say QUARANTINED and are not delivered. PASS if dangerous files
  are stopped and safe ones pass.

**T3 - Integrity / tamper detection**
- Do, on A: `python3 scripts/demo_attacks.py`
- Expected: every tampered case (bit flip, chunk swap, cut/joined chunks,
  truncation, wrong signature) is **REJECTED**; a clean one is accepted.
  PASS if all tampered ones are rejected.

**T4 - Replay protection**
- Do: with the receiver running, send the same file twice in a row:
  `python3 -m railcds.cli send data/spool/benign.txt --no-preflight` (twice).
- Expected: first copy DELIVERED; the second is **REJECTED** as a replay (same
  session). PASS if the second is refused.

**T5 - Reliability when the WiFi drops packets**
- Do, on A, add fake packet loss on the WiFi card, then send a batch:
  ```
  sudo tc qdisc add dev <A_WIFI_IF> root netem loss 10%
  python3 -m railcds.cli send --spool data/spool --no-preflight
  sudo tc qdisc del dev <A_WIFI_IF> root
  ```
  Repeat with `loss 20%`, then `loss 30%`. (For bursty loss use
  `netem loss 20% 25%`.)
- Expected: files still arrive up to moderate loss, then start failing at high
  loss. To survive more loss, set `fec: repeat: 2` in `config/rail.yaml` on both
  sides and try again. PASS if you can show the delivery rate falling as loss
  rises, and `repeat: 2` doing better.

**T6 - Speed vs a normal transfer**
- Do, raw WiFi speed first (needs `iperf3` on both; install before lockdown):
  - On B: `iperf3 -s`
  - On A: `iperf3 -c <B_IP> -u -b 0 -t 15` (note the Mbit/s)
- Then RAIL speed on a bigger file:
  ```
  yes "speed test line" | head -c 10485760 > data/spool/big.txt   # 10 MB
  # B:  python3 -m railcds.cli receive --out data/received --no-preflight
  # A:  time python3 -m railcds.cli send data/spool/big.txt --no-preflight
  ```
  RAIL speed ≈ 10 MB ÷ the seconds it printed.
- Expected: RAIL is much slower than raw WiFi (most of the time is the malware
  inspection, not the WiFi). To show that, temporarily set the three ML
  detectors to `enabled: false` in `config/rail.yaml` and repeat - it speeds up
  a lot. PASS if you record raw speed, RAIL-full speed, and RAIL-without-ML speed.

### Turn on the one-way lockdown

Now sit at **each machine's own keyboard** (SSH will stop working).

**On the RECEIVER (B):**
```
cd RAIL1/deploy/diode-emulator
sudo ./harden_diode.sh receiver <B_WIFI_IF> <A_IP> 52080 lo
```
**On the SENDER (A)** (use the receiver's MAC you noted in Part 1):
```
cd RAIL1/deploy/diode-emulator
sudo PEER_MAC=<B_MAC> ./harden_diode.sh sender <A_WIFI_IF> <B_IP> 52080 lo
```
(The last word `lo` is a harmless "management interface" placeholder since you
have no separate management card. Skip `load_xdp.sh` - it needs a wired card.)

### After lockdown

**T7 - Prove the receiver cannot talk back**
- Do, on B: try to reach A every way:
  ```
  ping -c 3 <A_IP>
  ssh <A_IP>
  ```
- At the same time, on A, watch what arrives:
  ```
  sudo tcpdump -ni <A_WIFI_IF> -Q in
  ```
- Expected: every attempt from B fails, and A sees **no packets coming from B**.
  PASS if B cannot reach A at all.

**T8 - Prove the forward path still works one-way**
- Do: with the lockdown on, repeat the send from A and receive on B (Part 5).
- Expected: files still go A -> B and are DELIVERED + verified. PASS if one-way
  delivery still works.

**T9 - Check the enforcement report**
- Do, on B: `sudo ./verify_diode.sh receiver <B_WIFI_IF> <A_IP>`
- Expected: it prints checks and ends with "one-way properties hold" (the ARP
  line may warn on WiFi - that is expected; the IP-level checks are the key ones).
  PASS if the IP-level one-way checks hold.

### Undo the lockdown (get normal networking back)
Run from the **RAIL1 folder** (not the diode-emulator folder), on each machine:
```
# on B (receiver):
cd RAIL1 && sudo .venv/bin/python -m railcds.cli lockdown --role receiver --peer <A_IP> --release
# on A (sender):
cd RAIL1 && sudo .venv/bin/python -m railcds.cli lockdown --role sender   --peer <B_IP> --release
```
If networking is still blocked, just **reboot** the machine - the rules are not
permanent unless you deliberately saved them.

---

## Part 8 - Simple order to run everything

1. Part 1-4: set up both machines (internet on).
2. Part 5: first transfer - prove it works.
3. T1, T2, T3, T4 - core function (transfer, inspect, tamper, replay).
4. T5 - reliability with packet loss.
5. T6 - speed test (raw vs RAIL vs RAIL-no-ML).
6. Lock down (at the keyboards). T7, T8, T9 - one-way enforcement.
7. Release the lockdown (or reboot).

## What to save
For each test write: what you ran, what you saw, PASS or FAIL. Also keep the
files `data/audit_sender.jsonl`, `data/audit_receiver.jsonl`,
`data/ledger.jsonl`, and the numbers from T5 and T6.

## If something goes wrong (quick fixes)
- *They can't ping each other:* AP isolation is on, or they are on different WiFi
  bands/networks. Put both on the same 2.4/5 GHz SSID; turn off client isolation.
- *Receiver shows nothing:* start the receiver **before** the sender; check both
  use the same port (52080) and the same `policy id`; check `fec.backend` is
  `reedsolo` on both.
- *"detector unavailable" on A:* the Python packages did not all install - re-run
  the sender setup with internet on.
- *SSH dead after lockdown:* expected. Use the local keyboard, or reboot to
  clear the rules.
- *`load_xdp.sh` fails:* expected on WiFi. Ignore it; the firewall rules are what
  enforce one-way here.
