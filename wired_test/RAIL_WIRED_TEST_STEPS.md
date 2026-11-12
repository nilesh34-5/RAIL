# RAIL wired test, run 2: complete steps (two Ubuntu machines, Ethernet cable)

This is the full test, from start to end, in one run. All numbers for the paper's field trial come from this run.

| | Sender (A) | Receiver (B) |
|---|---|---|
| IP | 192.168.66.27 | 192.168.66.89 |
| Network card | eno1 | eno1 |
| RAIL port | UDP 52080 | UDP 52080 |

## Rules for this run

1. `A$` means type on the sender. `B$` means type on the receiver.
2. Open every terminal in your RAIL1 folder (for example `~/Desktop/RAIL1`). Then run `source .venv/bin/activate` in it.
3. Use two terminals on each machine:
   - **A-T1** for captures, **A-T2** for everything else.
   - **B-T1** for the receiver, **B-T2** for everything else.
4. **Never start the receiver with `railcds.cli receive` directly.** Always use `bash wired_test/rx_loop.sh ...` in B-T1. It restarts the receiver after each sender run. A receiver left running ignores every later sender run.
5. **On A, wait 20 seconds after one send before the next.** The test scripts wait by themselves.
6. Type the commands exactly as written. Keep `python3 -u` and `tee -i`, so the receiver's output is not lost when Ctrl-C stops `tee`.
7. Press **Ctrl-C** to stop a program. Never press Ctrl-Z.
8. If an output does not match the **Expected** line, stop and take a photo.
9. Allow about 3 hours.

## What is in this kit (folder `RAIL1/wired_test`)

| File | Runs on | Purpose |
|---|---|---|
| `RAIL_WIRED_TEST_STEPS.md` | | This guide |
| `fix_ember.sh` | A | Makes EMBER2024 load, then checks all 7 detectors |
| `check_detectors.sh` | A | Checks all 7 detectors (PASS or FAIL) |
| `env_info.sh` | both | Records machine and link details |
| `rx_loop.sh` | B | Receiver that restarts after every sender run |
| `arp_probe.py` | A | ARP requests to B, counts B's replies |
| `e1_raw.py` | B | Sends 50 raw frames for the driver-layer test |
| `pcap_count.py` | A | Counts packets in a capture file |
| `loss_run.sh` | A | Whole loss test (34 runs) |
| `count_loss.sh` | B | Counts delivered objects per loss setting |
| `make_noml_config.py` | A | "Inspection off" config for the speed test |
| `speed_run.sh` | A | Whole speed test (6 runs) |
| `anchors_count.py` | A | Counts anchors and signed objects |
| `rx_summary.py` | B | Summarises the receiver's audit log |
| `check_results.sh` | both | Lists missing or wrong result files |

None of these change RAIL's own code.

---

## Phase 0: prepare (needs internet, so keep Wi-Fi on for now)

**0.1 Put in the kit.** On both machines, copy the `wired_test` folder into RAIL1 (replace any older copy). Keep everything else in RAIL1 (`.venv`, `models`, `data/keys`, `config`). Then, on both:

```
sed -i 's/\r$//' wired_test/*.sh wired_test/*.py
ls wired_test
```

The `sed` line removes Windows line endings. `ls` must show the files in the table above.

**0.2 Move earlier results aside, then clean.** On both:

```
mkdir -p ~/rail_run1 && mv results_wired rail_wired_*.tgz data/audit_*.jsonl data/ledger.jsonl ~/rail_run1/ 2>/dev/null; ls ~/rail_run1
rm -rf data/received data/recv_loss data/recv_speed spool_loss spool_speed && mkdir -p results_wired
```

**0.3 RAIL setup (only if `.venv` is missing).** Check on both: `ls .venv/bin/python`. If it is there, skip to 0.4. If not:

```
A$ bash dist/SENDER/setup_kali_sender.sh
B$ bash dist/RECEIVER/setup_kali_receiver.sh
```

**0.4 Fix EMBER2024 (A only).**

```
A$ bash wired_test/fix_ember.sh
```

**Expected:** the last line says **`PASS: 7 of 7 detectors available`**. The result is saved in `results_wired/detectors_A.txt`.

**Do not go on if it says FAIL.** Take a photo of the whole output. The inspection results depend on this step.

**0.5 Receiver check (B only).**

```
B$ source .venv/bin/activate && python3 -c "import raptorq, yaml, numpy, cryptography; print('B OK')"
```

**0.6 Keys.** The receiver must hold only the public key.

```
B$ rm -f data/keys/sender_ed25519.key && ls data/keys      # only sender_ed25519.pub
A$ ls data/keys                                            # .key and .pub
A$ sha256sum data/keys/sender_ed25519.pub
B$ sha256sum data/keys/sender_ed25519.pub                  # must match A
```

**0.7 Test tools.** On both:

```
sudo apt update && sudo apt install -y arptables iperf tcpdump ethtool clang llvm libbpf-dev gcc-multilib
```

**0.8 Config.** Open `config/rail.yaml` on both and check these values.

| Setting | Sender (A) | Receiver (B) |
|---|---|---|
| `policy: id:` | same on both | same on both |
| `anchoring: backend:` | `"file"` | `"file"` |
| `fec: backend:` | `"auto"` | `"auto"` |
| `fec: repeat:` | `1` | `1` |
| `transport: send_host:` | `"192.168.66.89"` | (not used) |
| `transport: send_port:` | `52080` | (not used) |
| `transport: bind_host:` | (not used) | `"0.0.0.0"` |
| `transport: bind_port:` | (not used) | `52080` |
| `transport: pace_ms:` | `0.5` | `0.5` |

**0.9 Make the cable the only link.** On both:

```
sudo ufw disable
nmcli radio wifi off
```

Check the routes:

```
A$ ip route get 192.168.66.89        # must say "dev eno1"
B$ ip route get 192.168.66.27        # must say "dev eno1"
```

---

## Phase 1: check the link

```
A$ ip -br addr show eno1             # 192.168.66.27/24
B$ ip -br addr show eno1             # 192.168.66.89/24
A$ ping -c5 192.168.66.89 | tee results_wired/ping_A_to_B.txt
B$ ping -c5 192.168.66.27 | tee results_wired/ping_B_to_A.txt
```

Both pings must reply. If an address disappears later, make it permanent:

```
A$ sudo nmcli con add type ethernet ifname eno1 con-name railwire ipv4.method manual ipv4.addresses 192.168.66.27/24 ipv6.method disabled connection.autoconnect-priority 100 && sudo nmcli con up railwire
B$ sudo nmcli con add type ethernet ifname eno1 con-name railwire ipv4.method manual ipv4.addresses 192.168.66.89/24 ipv6.method disabled connection.autoconnect-priority 100 && sudo nmcli con up railwire
```

---

## Phase 2: baselines before lockdown (these need two-way traffic)

**2.1 Record the environment.** Both machines.

```
A$ bash wired_test/env_info.sh sender
B$ bash wired_test/env_info.sh receiver
```

**Expected:** each ends with `saved: results_wired/env_sender.txt` or `env_receiver.txt`.

**2.2 Link speed, TCP.** Start B first. B stops by itself after 90 seconds, so start A within a minute.

```
B-T1$ timeout 90 stdbuf -oL iperf -s 2>&1 | tee -i results_wired/baseline_tcp_B.txt
A$    iperf -c 192.168.66.89 -t 15 2>&1 | tee results_wired/baseline_tcp.txt
```

**2.3 Link speed, UDP.** Same way. Read the result on B.

```
B-T1$ timeout 90 stdbuf -oL iperf -s -u 2>&1 | tee -i results_wired/baseline_udp_B.txt
A$    iperf -c 192.168.66.89 -u -b 1000M -t 15 2>&1 | tee results_wired/baseline_udp_A.txt
```

**Expected:** B's file ends with a line showing Mbits/sec and the lost datagrams.

**2.4 MAC addresses and the pin.** Write down both MACs. You need them in Phase 4.

```
B$ ip -br link show eno1 | tee results_wired/mac_B.txt               # note B_MAC
A$ ip -br link show eno1 | tee results_wired/mac_A.txt               # note A_MAC
A$ ping -c2 192.168.66.89 && ip neigh show 192.168.66.89             # learned MAC must equal B_MAC
A$ sudo ip neigh replace 192.168.66.89 lladdr <B_MAC> dev eno1 nud permanent
A$ ip neigh show 192.168.66.89 | tee results_wired/neigh_pin_A.txt   # must say PERMANENT
```

The lockdown stops B from answering ARP. The pin lets A still address B.

**2.5 Start the receiver loop and check a transfer, still unlocked.** B-T1 now runs the receiver loop until the end of Phase 5. Leave it open.

```
B-T1$ bash wired_test/rx_loop.sh data/received results_wired/rx_main.txt
```

Wait until it says `waiting for the sender`. Then:

```
A$ python3 scripts/make_test_object.py --out data/spool
A$ python3 -u -m railcds.cli send data/spool/benign.txt --no-preflight 2>&1 | tee results_wired/t0_unlocked_send.txt
```

**Expected on B-T1, within about 10 seconds:** `[rx ...] run 1: DELIVERED 1  REJECTED 0`.

**Stop here if this fails.** Take a photo of both screens.

---

## Phase 3: lockdown

This cuts every network on each machine until you release it. Use the machines' own keyboards and screens. Leave B-T1 running.

**3.1 Apply.** Receiver first, then sender. Use B-T2.

```
B-T2$ sudo .venv/bin/python -m railcds.cli lockdown --role receiver --peer 192.168.66.27 --port 52080 --scope total --iface eno1 --apply | tee results_wired/lockdown_apply_B.txt
A$    sudo .venv/bin/python -m railcds.cli lockdown --role sender   --peer 192.168.66.89 --port 52080 --scope total --iface eno1 --apply | tee results_wired/lockdown_apply_A.txt
```

**Expected:** both end with **`0 failed`**.

**3.2 Confirm.**

```
B-T2$ sudo .venv/bin/python -m railcds.cli lockdown --role receiver --peer 192.168.66.27 --status | tee results_wired/lockdown_status_B.txt
A$    sudo .venv/bin/python -m railcds.cli lockdown --role sender   --peer 192.168.66.89 --status | tee results_wired/lockdown_status_A.txt
A$    sudo iptables -S | grep RAIL-diode | tee results_wired/rules_A.txt     # needs ACCEPT ... udp --dport 52080
B-T2$ sudo iptables -S | grep RAIL-diode | tee results_wired/rules_B.txt
B-T2$ sudo arptables -L | tee results_wired/arp_rules_B.txt                 # OUTPUT policy DROP
```

**Expected:** both status outputs say `ACTIVE`.

**3.3 Locked transfer check.** Wait 20 seconds after the last send.

```
A$ python3 -u -m railcds.cli send data/spool/benign.txt --no-preflight 2>&1 | tee results_wired/t0_locked_send.txt
```

**Expected on B-T1:** `run 2: DELIVERED 1`.

---

## Phase 4: one-way enforcement (E1)

### 4.1 Driver layer off: 16 reverse attempts (ICMP, TCP, UDP, ARP)

In A-T1, capture every frame that comes from B. Leave it running until the end of 4.1.

```
A-T1$ sudo tcpdump -ni eno1 -e -w results_wired/e1_from_B.pcap ether src <B_MAC>
```

Make the attempts. The first three are from B. The ARP test runs on A and asks B for its address.

```
B-T2$ ping -c4 -W1 192.168.66.27 | tee results_wired/e1_icmp.txt
B-T2$ for p in 22 80 443 52080; do timeout 2 bash -c "echo hi > /dev/tcp/192.168.66.27/$p"; echo "tcp $p exit=$?"; done 2>&1 | tee results_wired/e1_tcp.txt
B-T2$ python3 -c "
import socket; s=socket.socket(2,2)
for p in (52080,53,123,9999):
    try: s.sendto(b'reverse',('192.168.66.27',p)); print('udp',p,'sent')
    except Exception as e: print('udp',p,'blocked:',e)" | tee results_wired/e1_udp.txt
A-T2$ sudo python3 wired_test/arp_probe.py eno1 192.168.66.89 | tee results_wired/e1_arp.txt
```

**Expected:** ping 100% packet loss. TCP exit is not 0. UDP says blocked. ARP ends with **`replies from B: 0`**.

Stop A-T1 with Ctrl-C, then count:

```
A-T2$ sudo python3 wired_test/pcap_count.py results_wired/e1_from_B.pcap | tee results_wired/e1_from_B_count.txt
```

**Expected: 0.**

### 4.2 Driver layer off: raw frames

Raw frames bypass the firewall, so they are expected to get through here. Run `e1_raw.py` only once per capture.

```
A-T1$ sudo tcpdump -ni eno1 -e -w results_wired/e1_raw_off.pcap ether proto 0x88b5
B-T2$ sudo python3 wired_test/e1_raw.py eno1 <A_MAC> | tee results_wired/e1_raw_sent_off.txt
```

When B prints `raw frames sent: 50 of 50`, stop A-T1 with Ctrl-C, then:

```
A-T2$ sudo python3 wired_test/pcap_count.py results_wired/e1_raw_off.pcap | tee results_wired/e1_raw_off_count.txt
```

**Expected: 50.**

### 4.3 Driver layer on (B only): raw frames

```
B-T2$ sudo .venv/bin/python -m railcds.cli driverfilter --role receiver --peer 192.168.66.27 --port 52080 --iface eno1 --apply | tee results_wired/driverfilter_B.txt
B-T2$ sudo .venv/bin/python -m railcds.cli driverfilter --status --iface eno1 | tee -a results_wired/driverfilter_B.txt
A-T1$ sudo tcpdump -ni eno1 -e -w results_wired/e1_raw_on.pcap ether proto 0x88b5
B-T2$ sudo python3 wired_test/e1_raw.py eno1 <A_MAC> | tee results_wired/e1_raw_sent_on.txt
```

When B prints its last line, stop A-T1 with Ctrl-C, then:

```
A-T2$ sudo python3 wired_test/pcap_count.py results_wired/e1_raw_on.pcap | tee results_wired/e1_raw_on_count.txt
```

**Expected: 0.** B may still print `sent: 50 of 50`. The frames leave the program but the filter drops them before the cable.

- The filter may attach in generic mode. That is fine. Note what it says.
- If the filter will not compile or attach, keep the message. The firewall results still stand.

### 4.4 Delivery with the driver layer on

Wait 20 seconds after the last send.

```
A$ python3 -u -m railcds.cli send data/spool/benign.txt --no-preflight 2>&1 | tee results_wired/t0_driver_on_send.txt
```

**Expected on B-T1:** `DELIVERED 1`. **Keep the driver layer on for Phases 5 to 8**, so every result is under full enforcement.

If nothing is delivered, detach the filter, note it, and carry on without it:

```
B-T2$ sudo .venv/bin/python -m railcds.cli driverfilter --detach --iface eno1 --apply
```

---

## Phase 5: functional tests, locked

B-T1 still runs the receiver loop from step 2.5.

**5.1 Transfer and integrity (all 7 detectors on).** Wait 20 seconds after the last send. This can take a minute or two.

```
A$ python3 -u -m railcds.cli send --spool data/spool --no-preflight 2>&1 | tee results_wired/t1_sender.txt
A$ sha256sum data/spool/benign.txt | tee -a results_wired/t1_sender.txt
A$ grep -E '"object"|"status"' results_wired/t1_sender.txt
```

**Expected:**
- benign.txt and report.pdf say `SENT`.
- polyglot.pdf, random.bin, signature_hit.txt and suspicious.ps1 say `QUARANTINED`.
- B-T1 shows a line with `DELIVERED 2` (it may come as two lines).

Then compare the hashes:

```
B-T2$ sha256sum data/received/benign.txt | tee results_wired/t1_receiver_sha.txt     # must match A's
```

**5.2 Inspection scores.**

```
A$ for f in benign.txt report.pdf random.bin signature_hit.txt suspicious.ps1 polyglot.pdf; do echo "=== $f"; python3 -m railcds.cli inspect data/spool/$f; done 2>&1 | tee results_wired/t2_inspect.txt
```

**5.3 Tampering and replay.**

```
A$ python3 scripts/demo_attacks.py 2>&1 | tee results_wired/t3_attacks.txt
```

**Expected: `10/10 checks passed`.** 9/10 means EMBER2024 is missing.

**5.4 Sender audit log.**

```
A$ python3 -m railcds.cli verify-log data/audit_sender.jsonl | tee results_wired/t4_log.txt
A$ cp data/audit_sender.jsonl /tmp/log.bak && sed -i '2s/.*/{"x":1}/' data/audit_sender.jsonl
A$ python3 -m railcds.cli verify-log data/audit_sender.jsonl | tee -a results_wired/t4_log.txt
A$ cp /tmp/log.bak data/audit_sender.jsonl
A$ python3 -m railcds.cli verify-log data/audit_sender.jsonl
```

**Expected:** `chain intact`, then `chain BROKEN` after the edit, then `chain intact` again after the restore.

**5.5 Stop the receiver loop.** Press Ctrl-C in B-T1. It prints the number of runs and the log file name.

---

## Phase 6: loss test (E2)

**6.1 Start a new receiver loop for the loss test.**

```
B-T1$ bash wired_test/rx_loop.sh data/recv_loss results_wired/e2_rx_log.txt
```

**6.2 Run the loss script on A.**

```
A$ bash wired_test/loss_run.sh
```

- It asks you to confirm that B-T1 is running. Press Enter. Then it asks for your sudo password.
- It runs 34 settings with 20 text objects each: Reed-Solomon and RaptorQ, repeat 1 and 2, random and burst loss at 0, 10, 25, 35 and 45%.
- It takes about 17 minutes. Let it finish.
- The malware models are off for this test only, because it measures error correction, not detection.
- B-T1 prints one line per run. At high loss a run may deliver nothing, and then no line appears for it. That is a result, not a fault.
- If it says "Unknown qdisc netem", run `sudo modprobe sch_netem` and start it again.

**6.3 Count.** When A prints `ALL LOSS RUNS DONE`, wait 20 seconds. Stop B-T1 with Ctrl-C, then:

```
B-T2$ bash wired_test/count_loss.sh | tee results_wired/e2_loss_counts.txt
```

**Expected:** 34 lines like `reedsolo repeat=1 rand_25 delivered=19/20`. **Both `none_0` lines must say `20/20`.** If they do not, the receiver loop was not running. Fix that and run 6.1 to 6.3 again.

---

## Phase 7: speed (E8)

**7.1 Plain one-way UDP through the same lockdown.** B-T1 must have no receiver running (stopped in 6.3). B stops by itself after 90 seconds.

```
B-T1$ timeout 90 stdbuf -oL iperf -s -u -p 52080 2>&1 | tee -i results_wired/e8_plain_udp_B.txt
A$    iperf -c 192.168.66.89 -u -p 52080 -b 1000M -t 15 2>&1 | tee results_wired/e8_plain_udp_A.txt
```

A may say it got no reply from the server. That is expected under the lockdown. Use the Mbit/s that **B** received.

**7.2 RAIL with inspection on, then off.** Three runs each, all in one script.

```
B-T1$ bash wired_test/rx_loop.sh data/recv_speed results_wired/e8_rx_log.txt
A$    bash wired_test/speed_run.sh
```

- Press Enter when it asks about B-T1.
- It makes three 10 MiB text files and the "inspection off" config by itself.
- Each run prints `real=` (the time) and `status=SENT`. With inspection on, a run can take a few minutes.
- B-T1 shows one `DELIVERED 1` line per run, six in total.

When A prints `ALL SPEED RUNS DONE`, wait 20 seconds and stop B-T1 with Ctrl-C.

---

## Phase 8: local measurements (CPU-heavy, so run with nothing else going)

**8.1 Stage costs, covert channel and coder test.** This can take 30 minutes or more with all 7 detectors.

```
A$ python3 scripts/evaluate.py --out results_wired/evaluation.json 2>&1 | tee results_wired/t6_evaluate.txt
```

**8.2 False-positive rate on 100 real Ubuntu programs.** These are known-good files, so any "blocked" result is a false positive.

```
A$ find /usr/bin -maxdepth 1 -type f -size +8k -size -4096k | sort | awk 'NR%15==1' | head -100 > results_wired/benign_list.txt
A$ python3 -m railcds.cli inspect $(cat results_wired/benign_list.txt) > results_wired/e5_benign_elf.json 2>&1
A$ echo "blocked=$(grep -c '"blocked": true' results_wired/e5_benign_elf.json) passed=$(grep -c '"blocked": false' results_wired/e5_benign_elf.json)" | tee results_wired/e5_benign_fpr.txt
```

**Expected:** `blocked` plus `passed` equals 100.

**8.3 Anchors and the evidence report.**

```
A$ python3 wired_test/anchors_count.py | tee results_wired/t7_anchors.txt
A$ python3 -m railcds.cli report --spool data/spool --out data/received --full 2>&1 | tee results_wired/t9_report.txt
```

**Expected:** `anchors=` and `signed=` are both above 0.

**8.4 Receiver audit log, checked at the end.**

```
B$ python3 -m railcds.cli verify-log data/audit_receiver.jsonl | tee results_wired/t4_log_B.txt
B$ python3 wired_test/rx_summary.py | tee results_wired/rx_summary.txt
```

**Expected:** `chain intact`, and `delivered and verified: N of N` with both numbers the same.

---

## Phase 9: check, release and collect

**9.1 Check the results while still locked.** On both:

```
A$ bash wired_test/check_results.sh sender
B$ bash wired_test/check_results.sh receiver
```

**Expected:** `ALL PRESENT AND AS EXPECTED`. If a line says `MISSING`, `EMPTY` or `CHECK`, redo that step now. If you cannot, write down why.

**9.2 Release the lockdown.**

```
B$ sudo .venv/bin/python -m railcds.cli driverfilter --detach --iface eno1 --apply
B$ sudo .venv/bin/python -m railcds.cli lockdown --role receiver --peer 192.168.66.27 --release --apply
A$ sudo .venv/bin/python -m railcds.cli lockdown --role sender   --peer 192.168.66.89 --release --apply
A$ sudo ip neigh del 192.168.66.89 dev eno1
```

**9.3 Bundle the results.** The names end in `2` so they do not mix with earlier runs.

```
A$ tar czf rail_wired2_sender.tgz results_wired data/audit_sender.jsonl data/ledger.jsonl config/rail.yaml config/loss_*.yaml config/speed_noml.yaml wired_test
B$ tar czf rail_wired2_receiver.tgz results_wired data/audit_receiver.jsonl config/rail.yaml wired_test
```

Never include `data/keys`.

**9.4 Restore normal networking.** On both:

```
nmcli radio wifi on
sudo ufw enable          # only if it was on before
```

If anything seems stuck, reboot. Nothing in the lockdown is permanent. Copy both `.tgz` files out by USB.

---

## Checklist (fill in as you go)

| # | Step | Check | Expected | Result |
|---|---|---|---|---|
| 1 | 0.4 | Detectors on A | PASS: 7 of 7 | |
| 2 | 0.9 | Routes to the other machine | dev eno1 | |
| 3 | 1 | Ping both ways (unlocked) | replies | |
| 4 | 2.1 | env_sender.txt and env_receiver.txt | both saved | |
| 5 | 2.2, 2.3 | TCP / UDP baseline (UDP read on B) | about 940 Mbit/s | |
| 6 | 2.5 | Transfer, unlocked | DELIVERED 1 | |
| 7 | 3.1, 3.2 | Lockdown apply and status, both | 0 failed, ACTIVE | |
| 8 | 3.3 | Transfer, locked | DELIVERED 1 | |
| 9 | 4.1 | Frames from B, 12 IP attempts plus ARP | 0 | |
| 10 | 4.1 | ARP replies from B | 0 | |
| 11 | 4.2 | Raw frames, driver layer off | 50 | |
| 12 | 4.3 | Raw frames, driver layer on | 0 | |
| 13 | 4.3 | Driver layer mode | native or generic | |
| 14 | 4.4 | Transfer, driver layer on | DELIVERED 1 | |
| 15 | 5.1 | Sent / quarantined | 2 SENT, 4 QUARANTINED | |
| 16 | 5.1 | Hashes match | yes | |
| 17 | 5.3 | demo_attacks | 10/10 | |
| 18 | 5.4 | Sender log edit detected | BROKEN | |
| 19 | 6.3 | Loss counts | 34 lines, both none_0 at 20/20 | |
| 20 | 7.1 | Plain UDP at B | Mbit/s | |
| 21 | 7.2 | RAIL, inspection on, 3 runs | seconds | |
| 22 | 7.2 | RAIL, inspection off, 3 runs | seconds | |
| 23 | 8.2 | Ubuntu programs blocked | out of 100 | |
| 24 | 8.3 | Anchors / signed objects | both above 0 | |
| 25 | 8.4 | Receiver log and deliveries | intact, N of N | |
| 26 | 9.1 | check_results.sh, both | ALL PRESENT AND AS EXPECTED | |

---

## If something goes wrong

| Problem | What to do |
|---|---|
| fix_ember.sh says FAIL | Take a photo of the whole output. Do not run the test without EMBER2024. |
| Ping fails before lockdown | Check both IPs with `ip -br addr show eno1`, the cable, and `ip route get` (must say dev eno1). Turn Wi-Fi off. |
| Lockdown says some commands failed | A tool is missing (usually arptables). Install it, release, and apply again. |
| rx_loop.sh says "port 52080 is busy" | Another receiver or iperf is still running. Stop it with Ctrl-C in its terminal, then start the loop again. |
| A sends but B-T1 shows no line | Wait 10 seconds. Then check that B-T1 runs `rx_loop.sh`. Check `iptables -S` on A shows the ACCEPT for udp 52080. Check `ip neigh show 192.168.66.89` on A says PERMANENT with B's real MAC. |
| Two sends close together, the second not delivered | Wait 20 seconds and send it again. |
| Sender prints an error | Take a photo of the sender's output. |
| "Unknown qdisc netem" | `sudo modprobe sch_netem`, then run `bash wired_test/loss_run.sh` again. |
| Driver filter will not compile | Check that `clang` and `gcc-multilib` are installed. Otherwise skip 4.3 and 4.4 and note it. |
| pcap_count.py says "not a classic pcap file" | Count with `sudo tcpdump -r FILE 2>/dev/null \| grep -c ethertype` and note it. |
| IP address disappears | Use the `nmcli` commands in Phase 1. |
| Machine seems stuck after lockdown | Release (Phase 9.2) or reboot. |
| `$'\r': command not found` when running a script | Run `sed -i 's/\r$//' wired_test/*.sh wired_test/*.py` and try again. |
