# RAIL deployment & network setup

RAIL enforces one-way transfer in software. This guide shows three ways to run
it, from a single laptop to isolated virtual networks, plus how the one-way
property is enforced in each.

Everything below assumes you have already installed the Python dependencies and
provisioned the offline models (see `../docs/RUNBOOK.md`).

---

## 0. What "one-way" means here

The sender process only ever calls `sendto`; the receiver only ever calls
`recvfrom`. There is **no** application acknowledgement, retransmit request or
reverse datagram - reliability comes entirely from forward error correction
(RaptorQ / Reed-Solomon, Stage S4/S4'). On top of that application-level
guarantee you add **one** of the enforcement mechanisms below so a compromised
gateway cannot open a reverse path:

| Layer | Enforcement | Where |
|-------|-------------|-------|
| Application | send-only / recv-only sockets | `railcds/transport.py` |
| Host firewall | egress-only / ingress-only rules | Vagrant provisioners |
| Network topology | sender has no route to receiver | Docker compose |
| Physical | a real hardware diode or the relay | `diode-emulator/` |

Production cross-domain guidance (NCDSMO "Raise the Bar") requires *multiple
independent* mechanisms; the Vagrant lab combines send-only sockets **and** an
egress-only firewall, which is the pattern to follow.

---

## 1. Single machine (loopback) - quickest

No network setup at all. Run the in-process demo:

```bash
python scripts/demo_local.py --loss 0.2
```

or the real UDP path in two terminals:

```bash
# terminal 1 (receiver / Network B)
python -m railcds.cli receive --out data/received
# terminal 2 (sender / Network A)
python -m railcds.cli send --spool data/spool
```

Both use `127.0.0.1:52080` from `config/rail.yaml`. Good for development; it does
**not** enforce one-way at the OS level (loopback is bidirectional).

---

## 2. Two virtual machines + a one-way virtual network (recommended)

`vagrant/` builds two Ubuntu VMs on a host-only private network `10.20.0.0/24`
and installs egress-/ingress-only `iptables` rules so traffic flows **only**
`netA (10.20.0.10) -> netB (10.20.0.20):52080`.

```bash
cd deploy/vagrant
vagrant up                     # builds both VMs, installs deps + models + keys

# terminal 1 - receiver
vagrant ssh netB
sudo -i && cd /opt/rail-run && source .venv/bin/activate
python3 -m railcds.cli receive --out data/received

# terminal 2 - sender
vagrant ssh netA
sudo -i && cd /opt/rail-run && source .venv/bin/activate
python3 -m railcds.cli send --spool data/spool
```

**Key distribution.** `provision_sender.sh` generates the Ed25519 keypair on
netA and publishes **only** the public key to the shared `exchange/` folder;
`provision_receiver.sh` installs it on netB. The private key never leaves netA.

**Verify the diode.** From netB, confirm you cannot reach back to netA:

```bash
ping -c1 10.20.0.10        # succeeds at IP layer only if you relax rules
nc -u 10.20.0.10 52080     # datagrams are dropped by netA's INPUT rule
```

To test FEC under loss, add loss on netB's ingress:
`sudo tc qdisc add dev eth1 root netem loss 20%`.

---

## 3. Docker Compose - one-way by topology

`docker/docker-compose.yml` runs three containers:

```
net_a:  sender  -- diode --  net_b:  receiver
```

The **diode** container is the only member of both `internal` networks and runs
`diode_relay.py`, which forwards datagrams strictly A->B and never sends back.
The sender has no route to the receiver, so no reverse channel can exist.

```bash
cd deploy/docker
docker compose build
docker compose up -d receiver diode
docker compose run --rm sender python -m railcds.cli send --spool data/spool
docker compose logs -f receiver
```

---

## 4. Real (physical) networks

Map the roles onto two physical hosts / VLANs:

1. Put the sender and receiver on separate subnets with no route between them
   except through the boundary device.
2. Boundary device options, strongest first:
   - a **hardware data diode** (the sender's optical TX only);
   - a dedicated relay host running `diode_relay.py` with two NICs, one facing
     each subnet, and egress-only firewalling;
   - stateful firewall rules permitting only `UDP A->B:52080`.
3. Set `transport.send_host` (Network A) to the receiver/relay address and
   `transport.bind_host: 0.0.0.0` (Network B). MTU and `pace_ms` can be tuned
   for the link in `config/rail.yaml`.

---

## 5. Testing against real malware

The bundled samples are harmless (see `scripts/make_test_object.py`). To
evaluate detection on real malware, do it **only inside an isolated VM with host
antivirus disabled and no internet route** - otherwise the host AV (e.g. Windows
Defender) will quarantine samples before RAIL sees them, and live samples must
never touch a production network. The Vagrant `netA` VM (no NAT egress if you
remove the default route) is a suitable sandbox.
