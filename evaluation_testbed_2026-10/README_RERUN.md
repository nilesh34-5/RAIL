# Re-running the RAIL evaluation on your own two VMs

This folder holds the evaluation harness that drives `RAIL1`. It was developed
and run on a two-node testbed that emulates the two VMs with Linux network
namespaces; to reproduce on real Vagrant/Kali VMs, use the `deploy/vagrant`
setup plus the harnesses in `rail_eval/`.

## What is in this folder

```
testbed/
  net_up.sh        build the 3-namespace testbed (netA, netB, wire)   [emulation only]
  loss_wire.c      eBPF packet-loss emulator (netem-equivalent)        [emulation only]
  loss_ctl.sh      set/clear loss on the wire; read drop counters      [emulation only]
rail_eval/
  build_corpus.py  assemble the benign-by-construction corpus + manifest.csv
  e5_inspect.py    run RAIL's InspectionEngine over the corpus -> per-object scores
  e5_analyze.py    -> TPR/FPR/F1/AUC per tier and fusion rule (Table 7)
  rx_harness.py    receiver harness (drives railcds.receiver, writes rx.jsonl)
  tx_harness.py    sender harness   (drives railcds.sender,   writes tx.jsonl)
  transfer.sh      one transfer across the link, with warm/go handshake
  e1_enforcement.sh  E1 one-way enforcement + raw-frame control
  e2_reliability.sh  E2 delivery ratio vs loss (RS and RaptorQ)
  e6_tamper.py / e6_run.sh  E6 tamper and replay
  e34_perf.py      E3/E4 per-band integrity cost + stage timing
  e7_covert.py     E7 covert-channel mutual information vs bound
  consolidate.py   gather everything -> summary.json (with Wilson CIs)
configs/            experiment YAMLs (copies of your rail.yaml with only
                    transport.send_host / fec.backend / detector-enable changed)
results/            all raw outputs + summary.json
```

## On real VMs (recommended, gives a true malware TPR)

1. Provision both VMs as usual (`deploy/vagrant`), and on the **sender** run
   `dist/SENDER/setup_kali_sender.sh` so the downloaded models and keys are in place.
   Copy only `data/keys/sender_ed25519.pub` to the receiver.
2. For **E1/E6** apply your own `harden_diode.sh` and `driver/load_xdp.sh` on the two
   VMs, then run the probe steps in `e1_enforcement.sh` / `e6_run.sh` with the VM IPs.
3. For **E2 reliability**, use `tc netem` on the link NIC (a standard kernel has
   `sch_netem`; the testbed used the eBPF emulator only because its kernel did not):
   `tc qdisc add dev eth1 root netem loss 20%` or
   `tc qdisc add dev eth1 root netem loss gemodel <p> <r> 100% 0%`, then
   `tx_harness.py --spool <dir>` on the sender and `rx_harness.py` on the receiver.
4. For a **true detection TPR**, download the EMBER2024 **test** split on the sender
   (`python -c "import thrember; thrember.download_models(...)"` plus the test set),
   add the malware feature vectors as label-1 items in `e5_inspect.py`, and rerun
   `e5_analyze.py`. This is the one number this environment could not produce,
   because the labelled test set was not reachable here.

## Notes

- The `RAIL1` source is used as-is; results go in a separate subfolder.
- Only **downloaded** models were used (EMBER2024, MalConv, MalConvGCT, bundled YARA);
  the locally-trained IsolationForest was left disabled.
- The sender private key never left the sender node.
