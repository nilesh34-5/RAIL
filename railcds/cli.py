"""RAIL command-line interface.

    python -m railcds.cli keys                 generate the Ed25519 keypair
    python -m railcds.cli detectors            list inspection detectors + status
    python -m railcds.cli inspect FILE...       Stage S2 only: score object risk
    python -m railcds.cli send FILE...          run the sender gateway (S1-S4)
    python -m railcds.cli send --spool DIR      send every file in a spool dir
    python -m railcds.cli receive [--timeout S] run the receiver gateway (S4'-S6)
    python -m railcds.cli lockdown --role R      firewall off every non-RAIL path
    python -m railcds.cli driverfilter --role R  attach the driver-layer filter
    python -m railcds.cli doctor --role R        pre-flight health check
    python -m railcds.cli report                 full evidence report
    python -m railcds.cli verify-log FILE        check an audit log's hash chain
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_config
from .crypto import generate_keypair, save_keypair


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_keys(args) -> int:
    cfg = load_config(args.config)
    priv, pub = generate_keypair()
    ppath = cfg.resolve(cfg.crypto["sender_private_key"])
    upath = cfg.resolve(cfg.crypto["sender_public_key"])
    save_keypair(priv, pub, ppath, upath)
    print(f"[+] wrote private key -> {ppath}")
    print(f"[+] wrote public key  -> {upath}")
    print("    (copy ONLY the .pub to Network B; the private key stays on A)")
    return 0


def cmd_detectors(args) -> int:
    from .inspection.engine import InspectionEngine
    cfg = load_config(args.config)
    engine = InspectionEngine(cfg)
    print(f"policy: {cfg.policy_id}")
    print(f"block threshold theta_blk = {engine.block_threshold}")
    print(f"risk bands B = {engine.bands}")
    print("detectors:")
    for d in engine.detectors:
        status = "available" if d.available else f"UNAVAILABLE ({d._load_error})"
        print(f"  - {d.name:<20} weight={d.weight:<4} {status}")
    return 0


def cmd_inspect(args) -> int:
    from .inspection.engine import InspectionEngine
    from .models import TransferObject
    cfg = load_config(args.config)
    engine = InspectionEngine(cfg)
    for f in args.files:
        p = Path(f)
        obj = TransferObject(name=p.name, data=p.read_bytes())
        report = engine.inspect(obj)
        _print({
            "object": p.name, "size": obj.size,
            "risk": round(report.risk, 4), "band": report.band,
            "band_value": report.band_value, "blocked": report.blocked,
            "detectors": [
                {"name": r.name, "score": round(r.score, 4), "weight": r.weight,
                 "available": r.available, "detail": r.detail}
                for r in report.results
            ],
        })
    return 0



def _preflight(cfg, role: str, peer: str) -> None:
    """Warn loudly if the OS-level boundary is not enforced.

    The gateway processes only control their own sockets; every other path
    between the two hosts (SSH, SMB, HTTP, ICMP, ARP) stays open unless the
    host firewall is programmed. Running without that second, independent
    enforcement mechanism is a valid lab configuration but must never be
    mistaken for an enforced boundary.
    """
    from . import netenforce
    active, msg = netenforce.status(peer)
    if active:
        print(f"[i] OS-level enforcement ACTIVE ({msg})")
        return
    print("[!] " + "=" * 68)
    print("[!] OS-level enforcement is NOT active.")
    print("[!] RAIL controls only its own sockets - every other channel between")
    print("[!] these hosts (SSH, SMB, HTTP, ICMP, ARP) is still open.")
    print(f"[!] Enforce it with:  python -m railcds.cli lockdown --role {role} "
          f"--peer {peer} --apply")
    print("[!] " + "=" * 68)


def cmd_send(args) -> int:
    from .sender import SenderGateway
    from .protocol_break import ProtocolBreak
    from .models import TransferObject
    cfg = load_config(args.config)
    gw = SenderGateway(cfg)
    print(f"[i] FEC backend: {gw.fec.effective_backend}; "
          f"target {cfg.transport['send_host']}:{cfg.transport['send_port']}")
    if not args.no_preflight:
        _preflight(cfg, "sender", cfg.transport["send_host"])
    objs = []
    if args.spool:
        objs = list(ProtocolBreak(spool_dir=Path(args.spool)).iter_spool())
    for f in args.files:
        p = Path(f)
        objs.append(TransferObject(name=p.name, data=p.read_bytes()))
    if not objs:
        print("[!] nothing to send (give FILE... or --spool DIR)", file=sys.stderr)
        return 2
    for obj in objs:
        summary = gw.process(obj)
        _print(summary)
    gw.close()
    return 0


def cmd_receive(args) -> int:
    from .receiver import ReceiverGateway
    cfg = load_config(args.config)
    out = Path(args.out) if args.out else None
    gw = ReceiverGateway(cfg, out_dir=out, on_result=_print)
    if not args.no_preflight:
        _preflight(cfg, "receiver", args.peer or cfg.transport["send_host"])
    print(f"[i] listening on {cfg.transport['bind_host']}:{cfg.transport['bind_port']} "
          f"(Ctrl-C to stop)")
    try:
        gw.serve(idle_timeout=args.timeout)
    except KeyboardInterrupt:
        pass
    finally:
        gw.close()
    print("[i] receiver stopped")
    return 0


def cmd_verify_log(args) -> int:
    from .auditlog import AuditLog
    log = AuditLog(Path(args.file), side="?")
    broken = log.verify_chain()
    if broken is None:
        print(f"[+] audit log chain intact ({len(log.entries())} entries)")
        return 0
    print(f"[!] audit log chain BROKEN at entry index {broken}")
    return 1



def cmd_lockdown(args) -> int:
    """Program the host firewall so ONLY the RAIL flow crosses the boundary."""
    from . import netenforce
    cfg = load_config(args.config)
    t = cfg.transport
    role = args.role
    peer = args.peer or (t["send_host"] if role == "sender" else None)
    port = args.port or (t["send_port"] if role == "sender" else t["bind_port"])
    if peer is None:
        print("[!] receiver needs --peer <sender ip> (the config has no send_host "
              "for the far side)", file=sys.stderr)
        return 2

    if args.release:
        plan = netenforce.release_plan(role, peer, port)
    else:
        plan = netenforce.plan(role, peer, int(port), scope=args.scope,
                               diode_if=args.iface, mgmt_if=args.mgmt_iface)

    if args.status:
        active, msg = netenforce.status(peer)
        print(f"enforcement: {'ACTIVE' if active else 'NOT ACTIVE'} - {msg}")
        return 0 if active else 1

    print(plan.render())
    for w in plan.warnings:
        print(f"\n# WARNING: {w}")

    if not args.apply:
        print("\n# DRY RUN - nothing was changed. Re-run with --apply "
              "(as Administrator/root) to install these rules.")
        return 0

    print("\napplying...")
    ok, bad = netenforce.apply(plan)
    print(f"\n{ok} command(s) succeeded, {bad} failed")
    if bad:
        print("[!] some rules did not apply - the boundary is NOT fully enforced")
    return 1 if bad else 0



def cmd_driverfilter(args) -> int:
    """Attach the lowest-level packet filter this OS supports (Table I)."""
    from . import driverfilter
    cfg = load_config(args.config)
    t = cfg.transport
    role = args.role
    peer = args.peer or (t["send_host"] if role == "sender" else None)
    port = args.port or (t["send_port"] if role == "sender" else t["bind_port"])

    if args.status:
        tier, msg = driverfilter.status(args.iface)
        print(f"enforcement tier: {tier} - {msg}")
        return 0 if tier in (driverfilter.TIER_DRIVER,
                             driverfilter.TIER_KERNEL) else 1

    if args.detach:
        plan = driverfilter.detach_plan(args.iface or "eth1")
    else:
        if peer is None:
            print("[!] receiver needs --peer <sender ip>", file=sys.stderr)
            return 2
        plan = driverfilter.plan(role, peer, int(port), iface=args.iface)

    print(plan.render())
    for n in plan.notes:
        print(f"\n# NOTE: {n}")

    if not args.apply:
        print("\n# DRY RUN - nothing was changed. Re-run with --apply "
              "(as root/Administrator).")
        return 0

    print("\napplying...")
    ok, bad = driverfilter.apply(plan)
    print(f"\n{ok} command(s) succeeded, {bad} failed")
    tier, msg = driverfilter.status(args.iface)
    print(f"enforcement tier now: {tier} - {msg}")
    return 1 if bad else 0



def cmd_report(args) -> int:
    """Print the full evidence report for a completed transfer."""
    from .report import build_report
    cfg = load_config(args.config)
    return build_report(cfg,
                        out_dir=Path(args.out) if args.out else None,
                        spool_dir=Path(args.spool) if args.spool else None,
                        full=args.full)



def cmd_doctor(args) -> int:
    """Pre-flight: verify environment, packages, models, keys, config, network."""
    from .doctor import run
    cfg = load_config(args.config)
    return run(cfg, args.role, args.peer)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="railcds", description="RAIL cross-domain gateway")
    p.add_argument("--config", default=None, help="path to rail.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keys", help="generate Ed25519 keypair").set_defaults(fn=cmd_keys)
    sub.add_parser("detectors", help="list inspection detectors").set_defaults(fn=cmd_detectors)

    s = sub.add_parser("inspect", help="score object risk (S2 only)")
    s.add_argument("files", nargs="+")
    s.set_defaults(fn=cmd_inspect)

    s = sub.add_parser("send", help="run sender gateway (S1-S4)")
    s.add_argument("files", nargs="*")
    s.add_argument("--spool", help="directory of files to send")
    s.add_argument("--no-preflight", action="store_true",
                   help="skip the OS-enforcement check")
    s.set_defaults(fn=cmd_send)

    s = sub.add_parser("receive", help="run receiver gateway (S4'-S6)")
    s.add_argument("--timeout", type=float, default=None, help="idle seconds before exit")
    s.add_argument("--out", help="output directory for delivered objects")
    s.add_argument("--peer", help="sender IP, for the enforcement check")
    s.add_argument("--no-preflight", action="store_true",
                   help="skip the OS-enforcement check")
    s.set_defaults(fn=cmd_receive)

    s = sub.add_parser("lockdown",
                       help="firewall the host so only the RAIL flow crosses")
    s.add_argument("--role", choices=["sender", "receiver"], required=True)
    s.add_argument("--peer", help="the other gateway's IP")
    s.add_argument("--port", type=int, help="RAIL UDP port")
    s.add_argument("--scope", choices=["peer", "strict", "total"], default="peer",
                   help="peer: block only peer<->host traffic (safe default); "
                        "strict: default-deny the diode NIC, keep a management "
                        "NIC; total: block ALL networking except the RAIL flow "
                        "(no internet, no SSH - use the VM console)")
    s.add_argument("--iface", help="diode interface, e.g. eth1 (Linux)")
    s.add_argument("--mgmt-iface", default="eth0",
                   help="out-of-band management interface (Linux, strict scope)")
    s.add_argument("--apply", action="store_true",
                   help="actually install the rules (default is a dry run)")
    s.add_argument("--release", action="store_true",
                   help="remove rules previously installed by RAIL")
    s.add_argument("--status", action="store_true",
                   help="report whether enforcement is currently active")
    s.set_defaults(fn=cmd_lockdown)

    s = sub.add_parser("driverfilter",
                       help="attach the lowest-level packet filter this OS allows")
    s.add_argument("--role", choices=["sender", "receiver"], default="receiver")
    s.add_argument("--peer", help="the other gateway's IP")
    s.add_argument("--port", type=int, help="RAIL UDP port")
    s.add_argument("--iface", help="diode interface (eth1, Ethernet 2, em1 ...)")
    s.add_argument("--apply", action="store_true",
                   help="actually attach (default is a dry run)")
    s.add_argument("--detach", action="store_true", help="remove the filter")
    s.add_argument("--status", action="store_true",
                   help="report the enforcement tier currently achieved")
    s.set_defaults(fn=cmd_driverfilter)

    s = sub.add_parser("doctor",
                       help="pre-flight check of everything before a transfer")
    s.add_argument("--role", choices=["sender", "receiver"], required=True)
    s.add_argument("--peer", help="the other gateway's IP")
    s.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("report",
                       help="full evidence report: logs, roots, hashes, anchors")
    s.add_argument("--out", help="directory of delivered objects")
    s.add_argument("--spool", help="source spool directory, for integrity compare")
    s.add_argument("--full", action="store_true", help="show every field")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("verify-log", help="verify an audit log hash chain")
    s.add_argument("file")
    s.set_defaults(fn=cmd_verify_log)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
