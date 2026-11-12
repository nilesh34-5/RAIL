"""Unidirectional UDP transport (the software-enforced one-way link).

The sender holds a send-only socket; the receiver holds a recv-only socket.
There is no application-level acknowledgement, retransmit request
or return datagram - reliability is provided entirely by FEC (Stage S4/S4').
UDP is used because it is connectionless: no handshake or ACK travels back to
the source, which matches the diode model.  In a real deployment the one-way
property is additionally enforced below this layer (firewall egress-only rules,
a physical diode, or the diode-emulator relay in deploy/).
"""
from __future__ import annotations

import socket
import time
from typing import Callable


class UdpSender:
    """Send-only UDP endpoint."""

    def __init__(self, host: str, port: int, pace_ms: float = 0.0) -> None:
        self.addr = (host, port)
        self.pace = pace_ms / 1000.0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # large send buffer to smooth bursts
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)

    def send(self, datagram: bytes) -> None:
        self.sock.sendto(datagram, self.addr)
        if self.pace:
            time.sleep(self.pace)

    def send_many(self, datagrams) -> int:
        count = 0
        for d in datagrams:
            self.send(d)
            count += 1
        return count

    def close(self) -> None:
        self.sock.close()


class UdpReceiver:
    """Recv-only UDP endpoint."""

    def __init__(self, host: str, port: int, mtu: int = 1500) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
        self.sock.bind((host, port))
        self.bufsize = max(mtu + 64, 2048)

    def recv_loop(self, on_datagram: Callable[[bytes], None],
                  idle_timeout: float | None = None) -> None:
        """Call ``on_datagram`` for every datagram until idle for the timeout."""
        if idle_timeout is not None:
            self.sock.settimeout(idle_timeout)
        while True:
            try:
                data, _ = self.sock.recvfrom(self.bufsize)
            except socket.timeout:
                return
            on_datagram(data)

    def close(self) -> None:
        self.sock.close()
