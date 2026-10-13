<div align="center">

# 🎭 MASQ

**Transparent MITM positioning at kernel speed — the target never notices.**

<br>

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20NetHunter-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/tests-4%2F4%20pass-brightgreen.svg)]()

<br>

*ARP-spoof between a target and its gateway. Forward at kernel speed.
Zero packet drop. Self-healing. The target's internet never blinks.*

</div>

---

## 🎯 What It Does

MASQ slips between a target host and its gateway, then forwards traffic
so fast the target's connection never drops. It's built for **authorized
lab networks** and security research — the goal is a *silent* takeover:
the target keeps working, unaware its traffic is passing through you.

```
   TARGET                    YOU (MASQ)                GATEWAY
   ──────                    ───────────                ───────
     │                           │                         │
     │  1. ARP poisoned ────────▶│  "I'm the gateway"      │
     │                           │                         │
     │  2. sends traffic ───────▶│                         │
     │                           │  3. kernel forwards ───▶│
     │                           │◀──── replies ───────────│
     │  4. replies forwarded ────│                         │
     │                           │                         │
     ▼                           ▼                         ▼
  never                   data plane live            real internet
  notices                BEFORE first ARP            untouched
```

## 🔥 Why It's Silent

Most MITM tools poison ARP first and *hope* forwarding is ready. MASQ
does the opposite — **arm the data plane first, then touch ARP**:

| Step | What MASQ does | Why it matters |
|---|---|---|
| 1 | Arm `ip_forward`, sysctls, policy routing | forwarding is live **before** any ARP |
| 2 | Verify the data plane | abort safely if it can't forward (ARP untouched) |
| 3 | *Then* send the first ARP spoof | target's traffic never drops a single packet |

On top of that:

- **`send_redirects` off** — the kernel never tells the target "find the
  real gateway directly", so the attack doesn't self-defeat.
- **Unicast ARP only** — only the target and gateway see the change,
  not the whole network.
- **Always-on ARP responder** — answers before the real owner, refreshed
  ~every 15s with natural jitter.
- **Near-zero latency** — target traffic never enters Python. The kernel
  forwards it; MASQ is just the control plane. Added delay is <0.1ms,
  invisible under real internet jitter (2–50ms).

## ✨ Features

- **Kernel-speed forwarding** — `ip_forward` + policy routing; the target's
  traffic flows through without Python touching it.
- **Fail-safe takeover** — data plane verified before the first ARP; if it
  can't forward, the tool aborts without touching ARP at all.
- **Self-healing** — responds to every ARP request; keeps the position
  against the real gateway with jittered re-asserts.
- **Clean restore** — on Ctrl+C, SIGTERM, or crash (via state file +
  `restore`), both sides' real MACs are restored.
- **Passive taps** — `dns`, `conn`, `pcap`, `live` — read copies only,
  never in the forwarding path.
- **Optional GUI** — PyQt6 console with live packets, sparkline, and
  Wireshark-style dissection.

## 🛡️ Safety First

- **Positioning only.** MASQ does not block, inject, or alter traffic —
  it positions and forwards. (IPS/enforcement features were deliberately
  removed to keep it a pure, silent MITM.)
- Use only on networks you **own** or are **explicitly authorized** to test.
- The `selftest` command arms and disarms the data plane **without ever
  touching ARP** — safe to run anywhere to check your environment.

## 📦 Requirements

- **Python 3.11+**
- **scapy** — `pip3 install scapy` (or `apt install python3-scapy`)
- **PyQt6** *(optional)* — only for the `--gui` console
- Linux (Kali/Ubuntu, Samsung A51 NetHunter); root required (raw sockets
  + ARP)

## ⚡ Quick Start

```bash
# Survey the network (interfaces, gateway, MACs)
sudo python3 mitm.py recon

# Safe check: arm + verify the data plane, ARP untouched
sudo python3 mitm.py selftest --iface wlan0

# Before a WiFi attack: does the target answer ARP? (client-isolation test)
sudo python3 mitm.py recon --iface wlan0 --target 192.168.1.50

# Take position — no taps, minimal footprint
sudo python3 mitm.py start --iface wlan0 --target 192.168.1.50

# Position + passive sniffing
sudo python3 mitm.py start --iface wlan0 --target 192.168.1.50 \
    --tap dns --tap conn --tap pcap

# Monitor / stop / recover
sudo python3 mitm.py status
sudo python3 mitm.py stop
sudo python3 mitm.py restore     # if the process crashed
```

## 🎮 CLI Reference

| Command | Description |
|---|---|
| `recon` | survey interfaces, gateway, MACs; `--target` probes for client isolation |
| `selftest` | arm + verify + disarm the data plane — **never touches ARP** |
| `start` | take position between target and gateway |
| `status` | show the running session + live counters |
| `stop` | stop the session and restore everything |
| `restore` | force-restore from the last session's saved state |
| `interfaces` | list detected network interfaces |

### Key flags for `start`

| flag | meaning |
|---|---|
| `--target IP` | the victim host (required) |
| `--iface` | network interface (auto-detected if omitted) |
| `--tap` | passive tap: `dns` \| `conn` \| `pcap[=path]` \| `live` (repeatable) |
| `--refresh-interval` | ARP re-assert interval in seconds (default 10, jittered) |
| `--stats-interval` | how often to print counters (seconds) |
| `--plain` | plain text output (disable rich tables) |
| `--show-packets` | live tshark-style packet stream |
| `--gui` | launch the PyQt6 console |

## 🎮 GUI Console

A PyQt6 shell over the same engine (`-g` / `--gui`):

```bash
sudo apt install -y python3-pyqt6
sudo xhost +si:localuser:root          # one-time: root display access
sudo python3 mitm.py start --iface wlan0 --target 192.168.1.50 --gui
```

- **SUMMARY tab** — live metrics (duration, up/down traffic, DNS), a
  traffic sparkline, and bar charts of services / domains / destinations
  (IPs translated to domains via DNS answers).
- **PACKETS tab** — live filterable table with FOLLOW, plus layer-by-layer
  tree dissection + hex (Wireshark-style).
- **Stop** (button or window close) = full restore; the target is never
  left poisoned.

## 📊 What Gets Recorded

Each run writes to `logs/`:

| File | Contents |
|---|---|
| `dns_*.log` | the target's DNS queries + answers |
| `conn_*.log` | new TCP connections + UDP flows |
| `capture_*.pcap` | full capture for Wireshark |
| `summary_*.txt` / `.json` | end-of-session totals |
| `live_*.json` | machine-readable live state |

## 🏗️ Project Layout

```
mitm.py          CLI entry (recon / selftest / start / status / stop / restore)
core/
  dataplane.py   ip_forward, sysctls, policy routing, counters, verify/disarm
  position.py    ARP spoofing engine + self-healing responder
  session.py     one MITM session: lifecycle, always-restore guarantee
  recon.py       network survey + client-isolation probe
  restore.py     crash-safe ARP + data-plane restore
taps/
  dnssniff.py    passive DNS observer
  connlog.py     TCP/UDP connection logger
  pcap_tap.py    full pcap capture
  livetap.py     bounded live packet buffer (GUI feed)
gui/
  app.py         PyQt6 console (SUMMARY + PACKETS)
  model.py       packet table model
  theme.py       visual tokens
tests/           surface smoke tests (no root, no network)
```

## 📱 Verified on NetHunter

Developed and tested on a **Samsung Galaxy A51** running Kali NetHunter
(aarch64, kernel without nftables). Real run, target = laptop:

```
forwarded  target->gw 49 pkts (2.6 KB)   gw->target 71 pkts (17.6 KB)
heals fixed: 0          ← the target never detected the takeover
```

Positioning held, the target's connection stayed up, and ARP restored
cleanly on exit.

## ⚠️ Honest Limitations

- **TLS is not decrypted** — this is passive positioning, not interception
  of content (no CA installed on the target).
- **IPv6 traffic** may bypass the IPv4 MITM path (RA/DNSv6 takeover is a
  future phase).
- **WiFi throughput** is capped by the air (traffic crosses twice); it adds
  no errors, just the physical WiFi limit.
- ARP-monitoring tools (e.g. ARPwatch) can see the gateway MAC change —
  per the lab assumption, none are present.
- **Kernel without nftables** (e.g. NetHunter): counters fall back to
  interface totals; forwarding and positioning are unaffected.

## 📜 License

MIT — for authorized lab and research use only.

---

<div align="center">

**Built for the quiet ones who finish the handshake.**

*MASQ — arm the data plane, then wear the mask.*

</div>
