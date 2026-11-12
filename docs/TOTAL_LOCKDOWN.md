# Total lockdown - block ALL traffic except the RAIL flow

| Role | IP |
|---|---|
| **SENDER** - Network A | **10.0.2.8** |
| **RECEIVER** - Network B | **10.0.2.9** |

`--scope total` severs **everything** except one unidirectional UDP flow:

* default `DROP` on INPUT, OUTPUT and FORWARD
* only loopback plus the single RAIL rule survives
* **no internet, no DNS, no SSH, no apt, no pip**
* IPv6 disabled on every interface (NDP and RA are two-way by design)
* the receiver never emits ARP, so not even a layer-2 frame returns
* ICMP echo suppressed; IP forwarding off

## Read this before you start

**Use the VirtualBox console window, not SSH.** After the lock, SSH into the VM
is impossible by design.

**Finish all installing first.** No package can be downloaded once locked.

**Know how to get out.** Either command restores the machine:

```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role sender --peer 10.0.2.9 --release
```

```bash
sudo bash unlock.sh
```

`unlock.sh` needs no Python and no arguments - use it if anything goes wrong.

---

## Order matters: pin the MAC before locking the receiver

Under total scope the receiver stops answering ARP. If the sender has not
already learnt the receiver's MAC address, it can never resolve it and no
datagram will ever leave. Pin it **first**.

### On the RECEIVER - read its MAC and interface
```bash
ip -brief link show
```
Note the interface (e.g. `eth0`) and the MAC (e.g. `08:00:27:aa:bb:cc`).

### On the SENDER - pin it permanently
```bash
sudo ip neigh replace 10.0.2.9 lladdr <RECEIVER_MAC> dev eth0 nud permanent
```
```bash
ip neigh show 10.0.2.9
```
Must show `PERMANENT`.

---

## Apply the lock

### 1. SENDER (10.0.2.8)
```bash
cd ~/RAIL1 && source .venv/bin/activate
```
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role sender --peer 10.0.2.9 --scope total --apply
```

### 2. RECEIVER (10.0.2.9)
```bash
cd ~/RAIL1 && source .venv/bin/activate
```
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role receiver --peer 10.0.2.8 --scope total --apply
```

---

## Prove the lock is real

Run these on **both** machines. Every one must FAIL.

```bash
ping -c 2 -W 2 8.8.8.8
```
```bash
curl -m 5 https://www.google.com
```
```bash
ping -c 2 -W 2 <the other VM>
```

Then confirm the policies are `DROP`:
```bash
sudo iptables -S | grep '^-P'
```
Expect `-P INPUT DROP`, `-P OUTPUT DROP`, `-P FORWARD DROP`.

If `curl` still reaches Google, the rules did not apply - check that you used
`sudo` and that the command reported no failures.

---

## Transfer through the locked boundary

### RECEIVER - start first, leave running
```bash
python3 -m railcds.cli receive --out data/received
```

### SENDER
```bash
python3 -m railcds.cli send --spool data/spool
```

Both should print `OS-level enforcement ACTIVE`.

### Verify (RECEIVER, second console)
```bash
cd ~/RAIL1 && source .venv/bin/activate && python3 -m railcds.cli report
```

---

## NIC / driver-level filtering (optional, deeper than iptables)

iptables filters in the kernel's network stack. eBPF goes lower - XDP on the
receive path and tc on the transmit path.

### RECEIVER - install the toolchain BEFORE locking
```bash
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) linux-tools-common
```

### Compile only (no attach)
```bash
sudo bash railcds/driver/load_xdp.sh verify receiver 10.0.2.8 52080
```

### Attach
```bash
sudo bash railcds/driver/load_xdp.sh attach receiver eth0 10.0.2.8 52080
```

### Check, including the drop counters
```bash
sudo bash railcds/driver/load_xdp.sh status eth0
```

**Read the attach mode.** `xdpdrv` is true driver-level; `xdpgeneric` is a
kernel-level fallback, not the driver rung. VirtualBox's emulated NIC gives
`xdpgeneric`.

### Detach
```bash
sudo bash railcds/driver/load_xdp.sh detach eth0
```

---

## Unlock

### SENDER
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role sender --peer 10.0.2.9 --release
```

### RECEIVER
```bash
sudo .venv/bin/python3 -m railcds.cli lockdown --role receiver --peer 10.0.2.8 --release
```

### Confirm on both
```bash
ping -c 2 8.8.8.8
```

If either machine is still cut off:
```bash
sudo bash unlock.sh
```

---

## What total lockdown does and does not prove

**Does prove.** With default-DROP policies and a single permitted rule, the only
packet that can cross is UDP from the sender to the receiver's RAIL port. The
receiver emits nothing at all - no ACK, no ICMP error, no ARP reply. This is
kernel-enforced and independent of the RAIL application: it holds even if the
Python process is killed or compromised.

**Does not prove.** The rules live in the kernel of each gateway. An attacker
with root on a gateway can remove them - which the paper's threat model already
places out of scope. And the hypervisor remains a shared component; a VM escape
defeats the separation regardless of any firewall.
