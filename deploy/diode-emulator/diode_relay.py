"""Software data-diode emulator: a strictly one-way UDP pump.

Emulates the enforcement a hardware diode provides, for use in VM / container
test networks.  It binds an *input* socket on the Network-A-facing side and
forwards every datagram to the Network-B-facing *output* address.  It never
transmits anything back toward Network A and never reads from the output socket,
so no reverse channel can form through the relay.  Placing this process (and
only this process) on the boundary between two isolated subnets gives a tangible
one-way link without special hardware.

    python diode_relay.py --in 0.0.0.0:52080 --out 10.20.0.10:52080
                          [--loss 0.0] [--rate-bps 0] [--log]

--loss injects datagram loss (to exercise FEC); --rate-bps throttles throughput;
--log prints a one-line counter periodically.  The relay is tiny
and stateless so its one-way behaviour is easy to audit.
"""
from __future__ import annotations

import argparse
import random
import socket
import time


def parse_hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host or "0.0.0.0", int(port)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="bind addr, host:port")
    ap.add_argument("--out", dest="out", required=True, help="forward to host:port")
    ap.add_argument("--loss", type=float, default=0.0, help="drop probability [0,1]")
    ap.add_argument("--rate-bps", type=float, default=0.0, help="throttle bytes/sec")
    ap.add_argument("--log", action="store_true")
    args = ap.parse_args()

    in_host, in_port = parse_hostport(args.inp)
    out_host, out_port = parse_hostport(args.out)

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
    rx.bind((in_host, in_port))
    # separate send-only socket toward Network B; the relay never recvs on it
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[diode] one-way {in_host}:{in_port}  ==>  {out_host}:{out_port}"
          f"  loss={args.loss}  rate_bps={args.rate_bps or 'unlimited'}")

    fwd = dropped = total_bytes = 0
    t0 = time.time()
    while True:
        data, _src = rx.recvfrom(65535)          # source address is discarded
        if args.loss and random.random() < args.loss:
            dropped += 1
            continue
        tx.sendto(data, (out_host, out_port))
        fwd += 1
        total_bytes += len(data)
        if args.rate_bps:
            time.sleep(len(data) / args.rate_bps)
        if args.log and fwd % 500 == 0:
            dt = time.time() - t0
            print(f"[diode] fwd={fwd} dropped={dropped} "
                  f"{total_bytes/1e6:.1f} MB in {dt:.1f}s")


if __name__ == "__main__":
    raise SystemExit(main())
