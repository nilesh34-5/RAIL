#!/bin/bash
# =============================================================================
# Checks that every result file the paper needs is present and looks right.
# Run on each machine from your RAIL1 folder BEFORE you release the lockdown
# and bundle (Phase 9):
#     bash wired_test/check_results.sh sender      on A
#     bash wired_test/check_results.sh receiver    on B
# Redo any step marked MISSING or CHECK.
# =============================================================================
ROLE="${1:?usage: bash wired_test/check_results.sh sender|receiver}"
cd "$(dirname "$0")/.." || exit 1
R=results_wired
bad=0

have() {            # have <file>  - present and not empty
  if [ ! -e "$R/$1" ]; then echo "MISSING  $1"; bad=$((bad + 1)); return 1; fi
  if [ ! -s "$R/$1" ]; then echo "EMPTY    $1"; bad=$((bad + 1)); return 1; fi
  echo "ok       $1"
}
want() {            # want <file> <grep -E pattern> <what it should show>
  [ -s "$R/$1" ] || return
  if ! grep -qE "$2" "$R/$1"; then echo "CHECK    $1: expected $3"; bad=$((bad + 1)); fi
}
equals() {          # equals <file> <number>
  [ -s "$R/$1" ] || return
  v=$(tr -dc '0-9' < "$R/$1")
  if [ "$v" != "$2" ]; then echo "CHECK    $1: expected $2, found ${v:-nothing}"; bad=$((bad + 1)); fi
}

if [ "$ROLE" = sender ]; then
  for f in detectors_A.txt env_sender.txt ping_A_to_B.txt baseline_tcp.txt baseline_udp_A.txt \
           mac_A.txt neigh_pin_A.txt t0_unlocked_send.txt \
           lockdown_apply_A.txt lockdown_status_A.txt rules_A.txt t0_locked_send.txt \
           e1_from_B.pcap e1_from_B_count.txt e1_arp.txt \
           e1_raw_off.pcap e1_raw_off_count.txt e1_raw_on.pcap e1_raw_on_count.txt \
           t0_driver_on_send.txt \
           t1_sender.txt t2_inspect.txt t3_attacks.txt t4_log.txt e2_loss_log.txt \
           e8_plain_udp_A.txt e8_rail_full_1.txt e8_rail_full_2.txt e8_rail_full_3.txt \
           e8_rail_noml_1.txt e8_rail_noml_2.txt e8_rail_noml_3.txt e8_summary.txt \
           evaluation.json t6_evaluate.txt benign_list.txt e5_benign_elf.json e5_benign_fpr.txt \
           t7_anchors.txt t9_report.txt; do
    have "$f"
  done
  [ -s data/audit_sender.jsonl ] && echo "ok       data/audit_sender.jsonl" || { echo "MISSING  data/audit_sender.jsonl"; bad=$((bad + 1)); }
  [ -s data/ledger.jsonl ] && echo "ok       data/ledger.jsonl" || { echo "MISSING  data/ledger.jsonl"; bad=$((bad + 1)); }
  echo "--- content checks"
  want detectors_A.txt "PASS: 7 of 7" "PASS: 7 of 7 detectors"
  want lockdown_apply_A.txt " 0 failed" "0 failed"
  want rules_A.txt "udp.*52080.*ACCEPT|ACCEPT.*52080|52080.*-j ACCEPT" "an ACCEPT rule for udp 52080"
  equals e1_from_B_count.txt 0
  want e1_arp.txt "replies from B: 0" "replies from B: 0"
  equals e1_raw_on_count.txt 0
  [ -s "$R/e1_raw_off_count.txt" ] && [ "$(tr -dc '0-9' < "$R/e1_raw_off_count.txt")" = "0" ] \
    && { echo "CHECK    e1_raw_off_count.txt: 0 frames with the driver layer off - expected the frames sent"; bad=$((bad + 1)); }
  if [ -s "$R/t1_sender.txt" ]; then
    q=$(grep -c '"status": "QUARANTINED"' "$R/t1_sender.txt")
    [ "$q" -eq 4 ] || { echo "CHECK    t1_sender.txt: expected 4 QUARANTINED, found $q - are all 7 detectors on?"; bad=$((bad + 1)); }
  fi
  want t3_attacks.txt "10/10 checks passed" "10/10 checks passed"
  want t4_log.txt "chain intact" "chain intact"
  want t4_log.txt "BROKEN" "chain BROKEN after the edit"
  want e2_loss_log.txt "ALL LOSS RUNS DONE" "ALL LOSS RUNS DONE"
  want e8_summary.txt "ALL SPEED RUNS DONE" "ALL SPEED RUNS DONE"
  if [ -s "$R/evaluation.json" ]; then
    python3 - "$R/evaluation.json" <<'PY' || bad=$((bad + 1))
import json, sys
d = json.load(open(sys.argv[1]))
det = d.get("environment", {}).get("detectors", [])
if len(det) != 7 or "ember2024_ml" not in det:
    print("CHECK    evaluation.json: expected 7 detectors incl. ember2024_ml, found %d %s" % (len(det), det))
    sys.exit(1)
PY
  fi
elif [ "$ROLE" = receiver ]; then
  for f in env_receiver.txt ping_B_to_A.txt baseline_tcp_B.txt baseline_udp_B.txt mac_B.txt \
           rx_main.txt lockdown_apply_B.txt lockdown_status_B.txt rules_B.txt arp_rules_B.txt \
           e1_icmp.txt e1_tcp.txt e1_udp.txt e1_raw_sent_off.txt driverfilter_B.txt e1_raw_sent_on.txt \
           t1_receiver_sha.txt e2_rx_log.txt e2_loss_counts.txt e8_plain_udp_B.txt e8_rx_log.txt \
           t4_log_B.txt rx_summary.txt; do
    have "$f"
  done
  [ -s data/audit_receiver.jsonl ] && echo "ok       data/audit_receiver.jsonl" || { echo "MISSING  data/audit_receiver.jsonl"; bad=$((bad + 1)); }
  echo "--- content checks"
  want lockdown_apply_B.txt " 0 failed" "0 failed"
  want arp_rules_B.txt "OUTPUT.*DROP|policy DROP" "arptables OUTPUT policy DROP"
  want baseline_udp_B.txt "Mbits/sec" "a server report with Mbits/sec"
  want e8_plain_udp_B.txt "Mbits/sec" "a server report with Mbits/sec"
  want driverfilter_B.txt "0 failed" "1 command(s) succeeded, 0 failed"
  want rx_main.txt "DELIVERED|delivered=" "deliveries"
  want t4_log_B.txt "chain intact" "chain intact"
  if [ -s "$R/e2_loss_counts.txt" ]; then
    n=$(grep -c "delivered=" "$R/e2_loss_counts.txt")
    [ "$n" -eq 34 ] || { echo "CHECK    e2_loss_counts.txt: expected 34 lines, found $n"; bad=$((bad + 1)); }
    z=$(grep "none_0" "$R/e2_loss_counts.txt" | grep -vc "delivered=20/20")
    [ "$z" -eq 0 ] || { echo "CHECK    e2_loss_counts.txt: a 0% loss run did not deliver 20/20 - was rx_loop.sh running?"; bad=$((bad + 1)); }
  fi
  if [ -s "$R/rx_summary.txt" ]; then
    line=$(grep "delivered and verified" "$R/rx_summary.txt")
    a=$(echo "$line" | awk '{print $4}'); b=$(echo "$line" | awk '{print $6}')
    [ -n "$a" ] && [ "$a" = "$b" ] || { echo "CHECK    rx_summary.txt: not every delivery verified ($line)"; bad=$((bad + 1)); }
  fi
else
  echo "usage: bash wired_test/check_results.sh sender|receiver"; exit 2
fi

echo
if [ "$bad" -eq 0 ]; then
  echo "ALL PRESENT AND AS EXPECTED ($ROLE)"
else
  echo "$bad item(s) to look at ($ROLE). Redo those steps if you can, or note why not."
fi
