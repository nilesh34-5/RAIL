# Blocking everything except the RAIL flow

> **Is the running Python enough?** No. `sender.py` and `receiver.py` control
> only their own sockets. While they run, the two hosts can still reach each
> other over SSH, SMB, HTTP, ICMP and ARP, and any other process may open a
> socket freely. The gateway cannot restrain the operating system it runs on.
>
> RAIL therefore ships a second, independent enforcement mechanism that
> programs the host firewall:
>
> ```
> python -m railcds.cli lockdown --role sender   --peer <B_IP> --apply
> python -m railcds.cli lockdown --role receiver --peer <A_IP> --apply
> ```
>
> It dry-runs by default (printing exactly what it would do), needs
> Administrator/root to `--apply`, and is undone with `--release`. Both
> gateways check it at start-up and print a loud warning when it is not active.
> Works on Windows (`netsh advfirewall`) and Linux (`iptables`/`arptables`).


RAIL enforces one-way transfer *in software*. That is only half a diode: the
paper itself says enforcement "is best placed at several independent points, so
that a single defective rule or a compromised proxy is not sufficient to defeat
the boundary." This document supplies the other points - the network settings
that stop any communication from Network A to Network B other than the single
permitted UDP flow, and stop **all** traffic from B back to A.

Two deployments are covered: two terminals on one machine, and two VMs.

---

## Case 1 - Two terminals on one machine

**What this can and cannot be.** On a single host you cannot build a real
diode:

* Both processes share one kernel, one loopback interface, one filesystem and
  one memory space. A compromised sender can reach the receiver through
  dozens of paths that have nothing to do with the network.
* **Windows Firewall does not filter loopback traffic at all.** Rules you add
  for `127.0.0.1` are simply not applied. There is no configuration that fixes
  this.
* On Linux, `iptables -A OUTPUT -o lo` can filter loopback, but the shared
  kernel and filesystem remain.

So: **the single-machine setup is a functional test of the pipeline, not a
security boundary.** Use it to demonstrate S1-S6, adaptive integrity and FEC
recovery. Use VMs for any claim about isolation.

### What is still worth doing on one machine

These reduce accidental coupling.

**Separate OS accounts and directories** so the receiver cannot read the
sender's private key or write to its spool:

```bash
# Linux
sudo useradd -m rail-a && sudo useradd -m rail-b
sudo chmod 700 /opt/rail-a/data/keys        # private key readable only by A
```

```powershell
# Windows: deny Network B's account any access to the sender's key material
icacls "data\keys" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"
```

**Bind the receiver to loopback only**, so nothing off-box can reach it:

```yaml
transport:
  bind_host: "127.0.0.1"     # not 0.0.0.0
```

**Confirm nothing else is listening** on the RAIL port:

```bash
netstat -ano | findstr 52080
```

### An isolated single-machine option (Linux)

Network namespaces give each side its own network stack, so firewall rules
between them are real. This is the only single-host arrangement worth calling
isolated:

```bash
sudo ip netns add netB
sudo ip link add veth-a type veth peer name veth-b
sudo ip link set veth-b netns netB
sudo ip addr add 10.20.0.10/24 dev veth-a && sudo ip link set veth-a up
sudo ip netns exec netB ip addr add 10.20.0.20/24 dev veth-b
sudo ip netns exec netB ip link set veth-b up
sudo ip netns exec netB ip link set lo up

# apply the same one-way rules used for the VM case
sudo ip netns exec netB bash deploy/diode-emulator/harden_diode.sh receiver veth-b 10.20.0.10 52080 lo
sudo bash deploy/diode-emulator/harden_diode.sh sender veth-a 10.20.0.20 52080 lo
```

Run the receiver with `sudo ip netns exec netB python3 -m railcds.cli receive`.
Windows users can do this inside WSL2.

---

## Case 2 - Two VMs (the real configuration)

Everything below is applied automatically by `deploy/vagrant/`; the manual
steps are given so they can be checked.

### Layer 0 - Virtual network topology

Use a VirtualBox **internal network** (`intnet`), not NAT, bridged or host-only.
An internal network is not reachable from the host or the outside world, so the
diode segment carries nothing but RAIL traffic.

```ruby
a.vm.network "private_network", ip: "10.20.0.10", virtualbox__intnet: "rail-diode"
b.vm.network "private_network", ip: "10.20.0.20", virtualbox__intnet: "rail-diode"
vb.customize ["modifyvm", :id, "--nicpromisc2", "deny"]   # no sniffing
```

**Keep management out-of-band.** Each VM keeps its Vagrant NAT adapter (`eth0`)
for `vagrant ssh` and package installs. `eth1` is the diode segment and carries
only the RAIL flow. In a real deployment those are separate physical networks.
Never administer a gateway over the diode segment.

### Layer 1 - Apply the hardening

```bash
sudo bash deploy/diode-emulator/harden_diode.sh sender   eth1 10.20.0.20 52080 eth0
```

```bash
sudo bash deploy/diode-emulator/harden_diode.sh receiver eth1 10.20.0.10 52080 eth0
```

Order matters: harden the **sender first**. Once B stops answering ARP, A can no
longer learn B's MAC address, so A must pin it first (the script does this
automatically, and accepts `PEER_MAC=aa:bb:...` if you already know it).

### What the rules actually do

**Default deny, then one exception.** Both gateways set
`INPUT/OUTPUT/FORWARD` policy to `DROP`. Loopback and the management NIC are
re-allowed; the diode NIC gets exactly one rule.

Sender:
```
iptables -A OUTPUT -o eth1 -p udp -d 10.20.0.20 --dport 52080 -j ACCEPT
iptables -A INPUT  -i eth1 -j DROP          # nothing may arrive from B
```

Receiver:
```
iptables -A INPUT  -i eth1 -p udp -s 10.20.0.10 --dport 52080 -j ACCEPT
iptables -A OUTPUT -o eth1 -j DROP          # nothing may leave toward A
```

The receiver's blanket egress DROP is the important rule. It stops not only
application traffic but every kernel-generated response as well.

### Three reverse channels that are easy to miss

**1. ICMP is a reverse channel.** When a UDP datagram reaches a closed port,
the kernel replies with ICMP port-unreachable - a packet travelling B -> A that
carries timing and liveness information. The blanket egress DROP catches it;
`icmp_echo_ignore_all=1` is applied as well.

**2. ARP is a reverse channel.** `iptables` does not see ARP at all. On a
shared L2 segment, A asks "who has 10.20.0.20?" and B *answers* - a frame from
B to A, below every IP rule you wrote. Fix both ends:

```bash
# on B: never emit ARP
sudo arptables -P OUTPUT DROP

# on A: pin B's MAC so no ARP request is needed
sudo ip neigh replace 10.20.0.20 lladdr <B_MAC> dev eth1 nud permanent
```

**3. IPv6 cannot be made unidirectional.** Neighbour Discovery and Router
Advertisement are inherently two-way, and IPv6 is often enabled with no
`ip6tables` rules at all. Disable it on the diode NIC:

```bash
sudo sysctl -w net.ipv6.conf.eth1.disable_ipv6=1
```

Also applied: `ip_forward=0` (neither gateway relays), `rp_filter=1`, redirects
off, and rules persisted with `netfilter-persistent` so a reboot does not
silently reopen the path.

### Layer 2 - Shut down services on the diode segment

A firewall that is later relaxed should not expose a listening service.

```bash
sudo systemctl disable --now ssh          # or bind sshd to the mgmt NIC only
sudo systemctl disable --now systemd-resolved avahi-daemon cups
sudo ss -lntup                            # expect only the RAIL UDP socket
```

Give `eth1` a static address so no DHCP client runs on it - DHCP is a two-way
exchange:

```bash
sudo dhclient -r eth1 2>/dev/null || true
```

### Layer 3 - Optional: a relay so A and B are never on one segment

The strongest software arrangement puts the two gateways on **two different
internal networks** joined by a small relay that only ever forwards one way.
`deploy/diode-emulator/diode_relay.py` does this, and `deploy/docker/` wires the
same shape with Compose (`net_a`, `net_b`, and a `diode` service attached to
both). A and B then have no L2 adjacency at all, so ARP never arises.

---

## Verifying it

Run:

```bash
sudo bash deploy/diode-emulator/verify_diode.sh receiver eth1 10.20.0.10
```

```bash
sudo bash deploy/diode-emulator/verify_diode.sh sender eth1 10.20.0.20
```

On **B** these must all fail: `ping 10.20.0.10`, `ssh 10.20.0.10`, any TCP
connect. On **A**, capture the diode NIC during a full transfer and confirm not
one frame arrives:

```bash
sudo tcpdump -ni eth1 -Q in
```

**Zero captured inbound packets while a transfer is running**, together with the
`iptables -L -v -n` counters showing dropped packets, demonstrates the property
the architecture claims.

Finally, confirm the diode still passes traffic the right way: run a transfer
and check objects land in `data/received` on B with `verified: true`.

---

## Limits

Everything here is enforced by the Linux kernel on the two gateways. It is
strictly stronger than application-level enforcement alone, and it is what the
paper means by multiple independent enforcement points. It is **not** equivalent
to a hardware diode:

* An attacker with **kernel-level control of the receiver** can remove these
  rules. The paper states this directly - persistent OS compromise is outside
  the security model.
* The **hypervisor** remains a shared component. A VM-escape defeats the
  separation. Physically separate machines with a real diode or a
  transmit-only fibre remove that assumption.
* These rules stop *network* channels. They say nothing about the covert channel
  RAIL creates in its own adaptive behaviour - that is bounded separately by
  risk quantisation (Eq. 5/6) and measured in `docs/RESULTS.md` §E4.

---

# Driver-layer enforcement (Table I, "Driver Layer" rung)

`lockdown` reaches the **Kernel Filter** rung. `driverfilter` goes one lower
where the OS permits it:

```bash
py -m railcds.cli driverfilter --role receiver --peer 10.20.0.10 --iface eth1
```

Dry-runs by default; `--apply` attaches, `--detach` removes, `--status` reports
the tier actually achieved.

## What each receiver OS can reach

| Receiver OS | Mechanism | Tier | Ships in RAIL |
|---|---|---|---|
| **Linux** | XDP native (`xdpdrv`) + tc-bpf egress | **DRIVER** (pre-`skb`) | yes - `railcds/driver/rail_xdp.c` |
| Linux (no native XDP driver) | XDP generic (`xdpgeneric`) | KERNEL (post-`skb`) | yes - automatic fallback |
| **Windows** | XDP-for-Windows | DRIVER | detected; program not shipped |
| Windows (default) | WFP via `netsh` | KERNEL | yes - `lockdown` |
| **macOS** | `pf` | KERNEL | yes - anchor generated |
| **FreeBSD** | `pf` / `ipfw` (netmap for driver) | KERNEL | yes - anchor generated |

**A true driver-layer filter is reachable out of the box only on Linux.** On
Windows it needs Microsoft's XDP-for-Windows driver; anything lower would mean
writing and signing a WFP callout or NDIS lightweight filter, which is a driver
development project rather than a configuration step. On macOS, Network Kernel
Extensions are deprecated with no packet-level DriverKit replacement, so `pf`
is the floor.

**Recommendation: run the receiver on Linux.** The receiver is the side that
must never transmit, so that is where the lowest-level enforcement matters most.

## Why two eBPF programs

XDP is **receive-side only** - it has no transmit hook. So:

* `xdp_rail_ingress` (XDP, at the driver) passes only IPv4/UDP from the peer on
  the RAIL port. Everything else is dropped before an `sk_buff` is allocated,
  including **all ARP and all IPv6**.
* `tc_rail_egress` (tc `clsact`) enforces the outbound half. On the receiver it
  returns `TC_ACT_SHOT` unconditionally: nothing leaves that interface - no
  ACKs, no ICMP errors, no ARP replies.

A per-CPU counter map records passed/dropped frames, so the enforcement can be
checked:

```bash
sudo bash railcds/driver/load_xdp.sh status eth1
```

## Verify it compiles before attaching

```bash
sudo bash railcds/driver/load_xdp.sh verify receiver 10.20.0.10 52080
```

Needs `clang llvm libbpf-dev linux-headers-$(uname -r)`.

> The eBPF source includes the usual verifier bounds checks (explicit
> `data_end` checks, bounded `ihl`). Run `load_xdp.sh verify` on the Linux host
> before relying on it, and note the attach mode the loader prints: `xdpdrv` is
> the driver rung, `xdpgeneric` is not.

## Enforcement tier reached

With this layer attached on a Linux receiver in `xdpdrv` mode, enforcement
reaches the driver layer (Table I). If the receiver runs Windows or macOS, or
XDP falls back to `xdpgeneric`, it reaches the kernel-filter layer; the loader
reports which.
