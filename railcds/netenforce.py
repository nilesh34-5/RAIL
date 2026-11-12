"""OS-level enforcement of the one-way boundary (Stage S0).

The RAIL gateway processes only control their own sockets.  While they run, the
two hosts remain free to talk over SSH, SMB, HTTP, ICMP, ARP or anything else -
none of which the Python code can restrain.  Software enforcement at the
application layer is therefore necessary but not sufficient; the paper makes
this point directly, recommending "multiple independent enforcement mechanisms"
(Sec. III-A, citing the Raise the Bar guidance).

This module supplies the second, independent mechanism: it programs the host
firewall so that the ONLY traffic permitted between Network A and Network B is
the single unidirectional RAIL flow.  It is kept out of the data
path - it configures the kernel and then gets out of the way, so a fault in the
transfer application cannot reopen the boundary.

Two scopes:

``peer``   (default, safe)  Block every protocol between this host and the peer
                            except the RAIL flow.  The host keeps its other
                            network connectivity, so you cannot lock yourself
                            out of a machine you are working on.
``strict`` (VM / appliance) Additionally default-deny the whole diode interface,
                            allowing only loopback, the management NIC and the
                            RAIL flow.  Use on dedicated gateway VMs.

Directionality enforced:

  sender    may send UDP to PEER:PORT and receive NOTHING from the peer
  receiver  may receive UDP from PEER:PORT and send NOTHING to the peer

Nothing here is applied unless the caller explicitly asks: :func:`plan` returns
the commands, :func:`apply` runs them, and both are surfaced through
``python -m railcds.cli lockdown``, which dry-runs by default.
"""
from __future__ import annotations

import ipaddress
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

RULE_TAG = "RAIL-diode"          # every rule we create carries this name/comment


# ---------------------------------------------------------------------------
@dataclass
class Plan:
    """A set of firewall commands plus what they are for."""

    platform: str
    role: str
    peer_ip: str
    port: int
    scope: str
    commands: List[Tuple[str, List[str]]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add(self, why: str, argv: List[str]) -> None:
        self.commands.append((why, argv))

    def render(self) -> str:
        out = [f"# platform={self.platform} role={self.role} "
               f"peer={self.peer_ip} port={self.port} scope={self.scope}"]
        for why, argv in self.commands:
            out.append(f"\n# {why}")
            out.append(" ".join(argv))
        return "\n".join(out)


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Windows  (netsh advfirewall)
# ---------------------------------------------------------------------------
def _plan_windows(plan: Plan, diode_if: Optional[str]) -> Plan:
    peer, port, role = plan.peer_ip, plan.port, plan.role
    lo_range = f"1-{port - 1}" if port > 1 else None
    hi_range = f"{port + 1}-65535" if port < 65535 else None

    def rule(name, direction, action, extra):
        return ["netsh", "advfirewall", "firewall", "add", "rule",
                f"name={RULE_TAG}-{name}", f"dir={direction}",
                f"action={action}", f"remoteip={peer}"] + extra

    # Windows Firewall gives block rules precedence over allow rules, so the
    # permitted flow must never be covered by a block: we carve the UDP port
    # space around it with explicit ranges instead of a blanket block.
    if role == "sender":
        plan.add("permit the RAIL flow: outbound UDP to the receiver's port",
                 rule("allow-out", "out", "allow",
                      ["protocol=UDP", f"remoteport={port}"]))
        for i, rng in enumerate(filter(None, (lo_range, hi_range))):
            plan.add(f"block every other outbound UDP port to the peer ({rng})",
                     rule(f"block-out-udp{i}", "out", "block",
                          ["protocol=UDP", f"remoteport={rng}"]))
        plan.add("block all outbound TCP to the peer (SSH, SMB, HTTP, ...)",
                 rule("block-out-tcp", "out", "block", ["protocol=TCP"]))
        plan.add("block outbound ICMP to the peer (ping, error messages)",
                 rule("block-out-icmp", "out", "block", ["protocol=ICMPv4"]))
        plan.add("block ALL inbound traffic from the peer (no reverse channel)",
                 rule("block-in-any", "in", "block", ["protocol=ANY"]))
    else:  # receiver
        plan.add("permit the RAIL flow: inbound UDP on the listening port",
                 rule("allow-in", "in", "allow",
                      ["protocol=UDP", f"localport={port}"]))
        for i, rng in enumerate(filter(None, (lo_range, hi_range))):
            plan.add(f"block every other inbound UDP port from the peer ({rng})",
                     rule(f"block-in-udp{i}", "in", "block",
                          ["protocol=UDP", f"localport={rng}"]))
        plan.add("block all inbound TCP from the peer",
                 rule("block-in-tcp", "in", "block", ["protocol=TCP"]))
        # The receiver must never emit anything toward A.
        plan.add("block ALL outbound traffic to the peer (no ACK, no ICMP, "
                 "no application traffic)",
                 rule("block-out-any", "out", "block", ["protocol=ANY"]))

    if _is_loopback(peer):
        plan.warnings.append(
            "peer is a loopback address: Windows Firewall does NOT filter "
            "loopback traffic, so these rules will have no effect. Use two "
            "machines or two VMs for an enforced boundary.")
    plan.warnings.append(
        "run from an Administrator prompt; netsh silently refuses otherwise.")
    return plan


# ---------------------------------------------------------------------------
# Linux  (iptables / arptables)
# ---------------------------------------------------------------------------
def _plan_linux(plan: Plan, diode_if: Optional[str], mgmt_if: str) -> Plan:
    peer, port, role, scope = plan.peer_ip, plan.port, plan.role, plan.scope
    ipt = ["iptables", "-w"]

    if scope in ("strict", "total"):
        plan.add(f"{scope} scope: flush any previous ruleset",
                 ipt + ["-F"])
        plan.add(f"{scope} scope: default-deny inbound",
                 ipt + ["-P", "INPUT", "DROP"])
        plan.add(f"{scope} scope: default-deny outbound",
                 ipt + ["-P", "OUTPUT", "DROP"])
        plan.add(f"{scope} scope: never route for anyone",
                 ipt + ["-P", "FORWARD", "DROP"])
        # Loopback stays up in every scope: it is local IPC, not a cross-domain
        # path, and the gateway's own processes need it.
        for chain, flag in (("INPUT", "-i"), ("OUTPUT", "-o")):
            plan.add(f"keep loopback usable ({chain})",
                     ipt + ["-A", chain, flag, "lo", "-j", "ACCEPT"])
        if scope == "strict" and diode_if:
            # strict keeps an out-of-band management NIC reachable
            for chain, flag in (("INPUT", "-i"), ("OUTPUT", "-o")):
                plan.add(f"keep the out-of-band management NIC usable ({chain})",
                         ipt + ["-A", chain, flag, mgmt_if, "-j", "ACCEPT"])

    # iptables is first-match, so the permit precedes the blocks.
    if role == "sender":
        plan.add("permit the RAIL flow: outbound UDP to the receiver's port",
                 ipt + ["-A", "OUTPUT", "-d", peer, "-p", "udp",
                        "--dport", str(port), "-m", "comment",
                        "--comment", RULE_TAG, "-j", "ACCEPT"])
        plan.add("block every other outbound protocol/port to the peer",
                 ipt + ["-A", "OUTPUT", "-d", peer, "-m", "comment",
                        "--comment", RULE_TAG, "-j", "DROP"])
        plan.add("block ALL inbound traffic from the peer (no reverse channel)",
                 ipt + ["-A", "INPUT", "-s", peer, "-m", "comment",
                        "--comment", RULE_TAG, "-j", "DROP"])
    else:
        plan.add("permit the RAIL flow: inbound UDP from the sender",
                 ipt + ["-A", "INPUT", "-s", peer, "-p", "udp",
                        "--dport", str(port), "-m", "comment",
                        "--comment", RULE_TAG, "-j", "ACCEPT"])
        plan.add("block every other inbound protocol/port from the peer",
                 ipt + ["-A", "INPUT", "-s", peer, "-m", "comment",
                        "--comment", RULE_TAG, "-j", "DROP"])
        plan.add("block ALL outbound traffic to the peer - the decisive rule; "
                 "stops ACKs, ICMP errors and application traffic alike",
                 ipt + ["-A", "OUTPUT", "-d", peer, "-m", "comment",
                        "--comment", RULE_TAG, "-j", "DROP"])

    # ICMP port-unreachable is a genuine reverse channel; suppress echo too.
    plan.add("stop the kernel answering pings",
             ["sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=1"])
    plan.add("never forward packets between interfaces",
             ["sysctl", "-w", "net.ipv4.ip_forward=0"])

    if scope == "total":
        # IPv6 cannot be made unidirectional at all: neighbour discovery and
        # router advertisement are two-way by design. Disable it everywhere.
        plan.add("disable IPv6 on every interface (NDP/RA are inherently "
                 "two-way and cannot exist on a one-way segment)",
                 ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
        plan.add("disable IPv6 on the default interface template",
                 ["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"])
    elif diode_if:
        plan.add("disable IPv6 on the diode NIC - neighbour discovery and "
                 "router advertisement are inherently two-way",
                 ["sysctl", "-w", f"net.ipv6.conf.{diode_if}.disable_ipv6=1"])

    # ARP lives below iptables entirely, so it needs arptables. But the policy
    # is global: `arptables -P OUTPUT DROP` stops ARP on EVERY interface, which
    # on a single-NIC host also severs the default gateway. Only apply it when a
    # dedicated diode NIC exists (strict scope); otherwise say why we did not.
    if role == "receiver":
        if scope in ("strict", "total") and (diode_if or scope == "total"):
            plan.add("never emit ARP: a reply to the sender's 'who has' request "
                     "is a real frame travelling B -> A, beneath every IP rule",
                     ["arptables", "-P", "OUTPUT", "DROP"])
            plan.add("still accept inbound ARP (the sender must be able to "
                     "address us; we simply never answer)",
                     ["arptables", "-P", "INPUT", "ACCEPT"])
        else:
            plan.warnings.append(
                "ARP is NOT blocked in peer scope. arptables policy is global, "
                "so dropping ARP on a single-NIC host would also cut its default "
                "gateway. The receiver therefore still answers ARP to the sender "
                "- a residual L2 reverse channel. Use --scope total to close it.")
    elif scope in ("strict", "total"):
        plan.warnings.append(
            "The receiver will stop answering ARP, so the sender can no longer "
            f"resolve it. Pin the MAC BEFORE locking the receiver:  "
            f"sudo ip neigh replace {peer} lladdr <RECEIVER_MAC> dev "
            f"{diode_if or '<nic>'} nud permanent")

    if scope == "total":
        plan.warnings.append(
            "TOTAL scope severs ALL networking except the single RAIL flow: no "
            "internet, no DNS, no SSH, no package installs. Use the VM console, "
            "not SSH. Undo with:  lockdown --role <role> --peer <ip> --release")

    if _is_loopback(peer):
        plan.warnings.append(
            "peer is a loopback address; a single host cannot enforce a real "
            "boundary (shared kernel and filesystem). Use VMs or netns.")
    plan.warnings.append("run as root; iptables refuses otherwise.")
    return plan


# ---------------------------------------------------------------------------
def plan(role: str, peer_ip: str, port: int, scope: str = "peer",
         diode_if: Optional[str] = None, mgmt_if: str = "eth0") -> Plan:
    """Build the firewall plan for this host without executing anything."""
    if role not in ("sender", "receiver"):
        raise ValueError("role must be 'sender' or 'receiver'")
    if scope not in ("peer", "strict", "total"):
        raise ValueError("scope must be 'peer', 'strict' or 'total'")
    system = platform.system()
    p = Plan(platform=system, role=role, peer_ip=peer_ip, port=int(port),
             scope=scope)
    if system == "Windows":
        return _plan_windows(p, diode_if)
    if system in ("Linux", "Darwin"):
        if system == "Darwin":
            p.warnings.append("macOS uses pf, not iptables; these commands are "
                              "for Linux. Translate to pf or use a Linux VM.")
        return _plan_linux(p, diode_if, mgmt_if)
    p.warnings.append(f"unsupported platform {system}; no rules generated")
    return p


def release_plan(role: str, peer_ip: str, port: int) -> Plan:
    """Build the plan that removes rules previously applied by RAIL."""
    system = platform.system()
    p = Plan(platform=system, role=role, peer_ip=peer_ip, port=int(port),
             scope="release")
    if system == "Windows":
        # a single delete removes every rule sharing the name prefix
        for suffix in ("allow-out", "block-out-udp0", "block-out-udp1",
                       "block-out-tcp", "block-out-icmp", "block-in-any",
                       "allow-in", "block-in-udp0", "block-in-udp1",
                       "block-in-tcp", "block-out-any"):
            p.add(f"remove rule {RULE_TAG}-{suffix}",
                  ["netsh", "advfirewall", "firewall", "delete", "rule",
                   f"name={RULE_TAG}-{suffix}"])
    else:
        # A total lock sets default-DROP policies, so simply deleting the
        # tagged rules would leave the host with no networking at all. Restore
        # the policies first, then flush, so release always fully recovers.
        p.add("restore default-ACCEPT policies (a total lock set them to DROP)",
              ["bash", "-c",
               "iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT; "
               "iptables -P FORWARD ACCEPT"])
        p.add("flush all iptables rules", ["bash", "-c", "iptables -F"])
        p.add("restore ARP", ["bash", "-c",
              "arptables -P OUTPUT ACCEPT 2>/dev/null; "
              "arptables -P INPUT ACCEPT 2>/dev/null; "
              "arptables -F 2>/dev/null; true"])
        p.add("re-enable IPv6",
              ["bash", "-c",
               "sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null; "
               "sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null; true"])
        p.add("restore ping responses",
              ["sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=0"])
        p.add("drop any pinned static ARP entries",
              ["bash", "-c", "ip -s neigh flush all 2>/dev/null; true"])
        p.add("bring interfaces back up via the network manager",
              ["bash", "-c",
               "systemctl restart NetworkManager 2>/dev/null || "
               "systemctl restart networking 2>/dev/null || true"])
    return p


# ---------------------------------------------------------------------------
def apply(p: Plan, verbose: bool = True) -> Tuple[int, int]:
    """Execute a plan. Returns ``(succeeded, failed)`` command counts."""
    ok = bad = 0
    for why, argv in p.commands:
        exe = shutil.which(argv[0])
        if exe is None:
            if verbose:
                print(f"  [skip] {argv[0]} not installed - {why}")
            bad += 1
            continue
        res = subprocess.run(argv, capture_output=True, text=True)
        if res.returncode == 0:
            ok += 1
            if verbose:
                print(f"  [ ok ] {why}")
        else:
            bad += 1
            if verbose:
                msg = (res.stderr or res.stdout or "").strip().splitlines()
                print(f"  [FAIL] {why}\n         {msg[0] if msg else '?'}")
    return ok, bad


def status(peer_ip: str) -> Tuple[bool, str]:
    """Best-effort check that RAIL firewall rules are currently installed."""
    system = platform.system()
    try:
        if system == "Windows":
            res = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 f"name={RULE_TAG}-block-out-any"],
                capture_output=True, text=True)
            if RULE_TAG in res.stdout:
                return True, "RAIL firewall rules present (netsh)"
            res2 = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 f"name={RULE_TAG}-block-in-any"],
                capture_output=True, text=True)
            if RULE_TAG in res2.stdout:
                return True, "RAIL firewall rules present (netsh)"
            return False, "no RAIL firewall rules found"
        res = subprocess.run(["iptables", "-w", "-S"],
                             capture_output=True, text=True)
        if RULE_TAG in res.stdout:
            return True, "RAIL firewall rules present (iptables)"
        return False, "no RAIL firewall rules found"
    except FileNotFoundError:
        return False, "firewall tooling unavailable"
    except Exception as exc:      # noqa: BLE001
        return False, f"status check failed: {exc}"
