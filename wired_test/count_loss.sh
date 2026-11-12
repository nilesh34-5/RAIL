#!/bin/bash
# Counts delivered objects per loss setting - run on the RECEIVER (B) from your
# RAIL1 folder after loss_run.sh has finished on the sender:
#     bash wired_test/count_loss.sh | tee results_wired/e2_loss_counts.txt
cd "$(dirname "$0")/.." || exit 1
DIR="${1:-data/recv_loss}"
total=0; lines=0
for be in reedsolo raptorq; do
  for rep in 1 2; do
    for tag in none_0 rand_10 rand_25 rand_35 rand_45 burst_10 burst_25 burst_35 burst_45; do
      [ "$tag" = none_0 ] && [ "$rep" = 2 ] && continue
      n=$(ls "$DIR"/L_${be}_r${rep}_${tag}_*.txt 2>/dev/null | wc -l)
      echo "$be repeat=$rep $tag delivered=$n/20"
      total=$((total + n)); lines=$((lines + 1))
    done
  done
done
echo "# $lines settings, $total of $((lines * 20)) objects delivered"
