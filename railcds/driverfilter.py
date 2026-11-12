"""Driver-layer enforcement across receiver operating systems.

Table I of the paper places enforcement on a ladder - Application, Socket Layer,
Kernel Filter, Driver Layer, NIC/Media - and Sec. III-A argues that the earlier a
frame is discarded the less it costs and the less room it has to slip through.
:mod:`railcds.netenforce` reaches the *Kernel Filter* rung. This module reaches
the *Driver Layer* rung where the operating system allows it, and reports
which rung was actually achieved when it does not.

Available mechanisms per OS:

===========  =====================================  ==========================
OS           Mechanism                              Tier reached
===========  =====================================  ==========================
Linux        XDP native (xdpdrv) + tc-bpf egress    DRIVER (pre-skb)
Linux        XDP generic (xdpgeneric) fallback      KERNEL (post-skb)
Windows      XDP-for-Windows, if the driver is      DRIVER
             installed
Windows      WFP via netsh (netenforce.py)          KERNEL
macOS        pf packet filter                       KERNEL
FreeBSD      pf / ipfw (netmap for driver level)    KERNEL
===========  =====================================  ==========================

In practice, a *true* driver-layer filter is reachable
out of the box only on Linux. On Windows it needs Microsoft's XDP-for-Windows
driver, and anything lower would mean writing and signing a WFP callout or NDIS
lightweight filter - which is a driver-development project, not a configuration
step. On macOS the in-kernel packet-filter hooks (NKE) are deprecated with no
packet-level DriverKit replacement, so pf is the floor.

Because the receiver is the side that must never transmit, this module is most
important there - and a receiver can always be *chosen* to be Linux, which is
the recommendation.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

TIER_DRIVER = "DRIVER"      # discarded at/near the NIC driver, before skb
TIER_KERNEL = "KERNEL"      # discarded in the kernel network stack
TIER_APP = "APPLICATION"    # only the gateway process declines to read

DRIVER_DIR = Path(__file__).resolve().parent / "driver"


@dataclass
class DriverPlan:
    """What can be attached on this host, and the tier it achieves."""

    platform: str
    role: str
    peer_ip: str
    port: int
    iface: Optional[str]
    mechanism: str
    tier: str
    commands: List[Tuple[str, List[str]]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def add(self, why: str, argv: List[str]) -> None:
        self.commands.append((why, argv))

    def render(self) -> str:
        out = [f"# platform={self.platform} role={self.role} iface={self.iface}",
               f"# mechanism={self.mechanism}",
               f"# enforcement tier achievable here: {self.tier}"]
        for why, argv in self.commands:
            out.append(f"\n# {why}")
            out.append(" ".join(argv))
        return "\n".join(out)


# ---------------------------------------------------------------------------
def _linux(role, peer, port, iface) -> DriverPlan:
    have_clang = shutil.which("clang") is not None
    mech = "XDP (eBPF) ingress + tc-bpf egress"
    tier = TIER_DRIVER if have_clang else TIER_KERNEL
    p = DriverPlan("Linux", role, peer, port, iface, mech, tier)
    loader = DRIVER_DIR / "load_xdp.sh"
    p.add("compile rail_xdp.c and attach XDP at the driver plus tc egress",
          ["sudo", "bash", str(loader), "attach", role, iface or "eth1",
           peer, str(port)])
    if not have_clang:
        p.notes.append(
            "clang/libbpf not installed, so the eBPF object cannot be built. "
            "Install with: apt-get install -y clang llvm libbpf-dev "
            "linux-headers-$(uname -r)  - without it you stay at the kernel "
            "(netfilter) tier.")
    p.notes.append(
        "XDP attaches in native (xdpdrv) mode only if the NIC driver supports "
        "it; virtio-net and most physical NICs do, but some fall back to "
        "xdpgeneric, which is still kernel-level rather than driver-level. The "
        "loader reports which mode was achieved.")
    p.notes.append(
        "XDP is receive-side only, which is why egress is enforced with a "
        "tc-bpf program on the clsact qdisc.")
    return p


def _windows(role, peer, port, iface) -> DriverPlan:
    xdp_present = _windows_xdp_installed()
    if xdp_present:
        mech = "XDP-for-Windows"
        tier = TIER_DRIVER
    else:
        mech = "Windows Filtering Platform (netsh/WFP)"
        tier = TIER_KERNEL
    p = DriverPlan("Windows", role, peer, port, iface, mech, tier)
    if xdp_present:
        p.notes.append(
            "XDP-for-Windows is installed. RAIL does not yet ship a compiled "
            "Windows XDP program; attach one with the XDP-for-Windows SDK, or "
            "use the WFP rules below, which are already kernel-enforced.")
    else:
        p.notes.append(
            "XDP-for-Windows is NOT installed, so the driver rung is not "
            "reachable here. Enforcement falls back to WFP, which is still "
            "kernel-mode (BFE programs tcpip.sys/wfplwfs.sys callouts) - just "
            "one rung higher than XDP.")
        p.notes.append(
            "To reach the driver rung on Windows either install "
            "microsoft/xdp-for-windows, or run the RECEIVER on Linux, which is "
            "the recommended arrangement: the receiver is the side that must "
            "never transmit.")
    p.add("apply the kernel-tier (WFP) rules instead",
          ["python", "-m", "railcds.cli", "lockdown", "--role", role,
           "--peer", peer, "--apply"])
    return p


def _bsd_like(system, role, peer, port, iface) -> DriverPlan:
    mech = "pf packet filter (kernel)"
    tier = TIER_KERNEL
    p = DriverPlan(system, role, peer, port, iface, mech, tier)
    anchor = "/etc/pf.anchors/rail"
    # NB: the rule text is embedded in a shell command, so newlines are written
    # as literal \n escapes for printf rather than real line breaks.
    nl = r"\n"
    if role == "receiver":
        rules = (f"block in all{nl}"
                 f"block out all{nl}"
                 f"pass in quick on {iface or 'em1'} proto udp "
                 f"from {peer} to any port {port} keep state (no-sync){nl}")
    else:
        rules = (f"block in all{nl}"
                 f"block out all{nl}"
                 f"pass out quick on {iface or 'em1'} proto udp "
                 f"to {peer} port {port} keep state (no-sync){nl}")
    p.add(f"write the pf anchor ({anchor})",
          ["sh", "-c", f"printf '{rules}' | sudo tee {anchor}"])
    p.add("load the anchor", ["sudo", "pfctl", "-a", "rail", "-f", anchor])
    p.add("enable pf", ["sudo", "pfctl", "-e"])
    if system == "Darwin":
        p.notes.append(
            "macOS: Network Kernel Extensions are deprecated and DriverKit "
            "exposes no packet-filter hook, so pf is the lowest layer "
            "available without a kernel extension. The driver rung is not "
            "reachable; run the receiver on Linux if you need it.")
    else:
        p.notes.append(
            "FreeBSD: netmap can reach the driver layer but needs a custom "
            "forwarding program; pf is the practical kernel-tier option.")
    p.notes.append("pf keeps state; on the receiver the blanket 'block out all' "
                   "is what prevents any reverse traffic.")
    return p


def _windows_xdp_installed() -> bool:
    try:
        res = subprocess.run(["sc", "query", "xdp"],
                             capture_output=True, text=True)
        return "RUNNING" in res.stdout or "STOPPED" in res.stdout
    except Exception:      # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
def plan(role: str, peer_ip: str, port: int,
         iface: Optional[str] = None) -> DriverPlan:
    """Build the driver-layer plan for whatever OS this host runs."""
    if role not in ("sender", "receiver"):
        raise ValueError("role must be 'sender' or 'receiver'")
    system = platform.system()
    if system == "Linux":
        return _linux(role, peer_ip, int(port), iface)
    if system == "Windows":
        return _windows(role, peer_ip, int(port), iface)
    if system in ("Darwin", "FreeBSD", "OpenBSD", "NetBSD"):
        return _bsd_like(system, role, peer_ip, int(port), iface)
    p = DriverPlan(system, role, peer_ip, int(port), iface,
                   "unknown", TIER_APP)
    p.notes.append(f"no packet-filter integration for {system}; only the "
                   f"application-tier behaviour of the gateway applies.")
    return p


def detach_plan(iface: str) -> DriverPlan:
    system = platform.system()
    p = DriverPlan(system, "-", "-", 0, iface, "detach", TIER_APP)
    if system == "Linux":
        p.add("detach XDP and tc programs",
              ["sudo", "bash", str(DRIVER_DIR / "load_xdp.sh"), "detach", iface])
    elif system == "Windows":
        p.add("remove the WFP rules",
              ["python", "-m", "railcds.cli", "lockdown", "--role", "sender",
               "--peer", "0.0.0.0", "--release"])
    else:
        p.add("flush the pf anchor", ["sudo", "pfctl", "-a", "rail", "-F", "all"])
    return p


def status(iface: Optional[str] = None) -> Tuple[str, str]:
    """Return ``(tier, human_description)`` for what is enforced right now."""
    system = platform.system()
    try:
        if system == "Linux":
            if iface:
                res = subprocess.run(["ip", "-details", "link", "show", "dev", iface],
                                     capture_output=True, text=True)
                out = res.stdout.lower()
                if "xdpdrv" in out or ("xdp" in out and "generic" not in out):
                    return TIER_DRIVER, f"XDP native attached on {iface}"
                if "xdpgeneric" in out:
                    return TIER_KERNEL, f"XDP generic (post-skb) on {iface}"
            res = subprocess.run(["iptables", "-w", "-S"],
                                 capture_output=True, text=True)
            if "RAIL-diode" in res.stdout:
                return TIER_KERNEL, "netfilter rules present"
            return TIER_APP, "no packet filter attached"
        if system == "Windows":
            from . import netenforce
            active, msg = netenforce.status("")
            if active:
                return TIER_KERNEL, f"WFP rules present ({msg})"
            return TIER_APP, "no WFP rules present"
        res = subprocess.run(["pfctl", "-a", "rail", "-s", "rules"],
                             capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            return TIER_KERNEL, "pf anchor 'rail' loaded"
        return TIER_APP, "pf anchor not loaded"
    except FileNotFoundError:
        return TIER_APP, "packet-filter tooling unavailable"
    except Exception as exc:      # noqa: BLE001
        return TIER_APP, f"status check failed: {exc}"


def apply(p: DriverPlan, verbose: bool = True) -> Tuple[int, int]:
    ok = bad = 0
    for why, argv in p.commands:
        exe = shutil.which(argv[0])
        if exe is None:
            if verbose:
                print(f"  [skip] {argv[0]} not available - {why}")
            bad += 1
            continue
        res = subprocess.run(argv, capture_output=True, text=True)
        if res.returncode == 0:
            ok += 1
            if verbose:
                print(f"  [ ok ] {why}")
                if res.stdout.strip():
                    for line in res.stdout.strip().splitlines()[:6]:
                        print(f"         {line}")
        else:
            bad += 1
            if verbose:
                err = (res.stderr or res.stdout or "").strip().splitlines()
                print(f"  [FAIL] {why}\n         {err[0] if err else '?'}")
    return ok, bad
