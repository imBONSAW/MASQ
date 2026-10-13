"""Tap orchestration: optional passive observers that only READ copies.

Taps never sit in the forwarding path, so they can never add latency or
drop target packets — if a tap dies, the MITM keeps forwarding.
"""
import os
import time


class TapManager:
    def __init__(self, specs, iface, target_ip, target_mac, base_dir, log=None):
        self.specs = specs or []
        self.iface = iface
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.base_dir = base_dir
        self.log = log or print
        self.active = []

    def start(self):
        if not self.specs:
            return
        logs = os.path.join(self.base_dir, "logs")
        os.makedirs(logs, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        for s in self.specs:
            name, _, arg = s.partition("=")
            try:
                if name == "dns":
                    from taps import dnssniff
                    t = dnssniff.DnsTap(self.iface, self.target_ip, self.target_mac,
                                        os.path.join(logs, f"dns_{ts}.log"))
                elif name == "conn":
                    from taps import connlog
                    t = connlog.ConnTap(self.iface, self.target_mac,
                                        os.path.join(logs, f"conn_{ts}.log"),
                                        target_ip=self.target_ip)
                elif name == "pcap":
                    from taps import pcap_tap
                    t = pcap_tap.PcapTap(self.iface, self.target_mac,
                                         arg or os.path.join(logs, f"capture_{ts}.pcap"))
                elif name == "live":
                    from taps import livetap
                    t = livetap.LiveTap(self.iface, self.target_mac)
                else:
                    self.log(f"[!] unknown tap '{s}' (available: dns, conn, pcap[=file], live)")
                    continue
                t.start()
                self.active.append(t)
                self.log(f"[*] tap '{name}' running -> {t.describe()}")
            except Exception as e:
                self.log(f"[!] tap '{name}' failed to start (MITM continues without it): {e}")

    def stop(self):
        # do NOT clear self.active: the end-of-session summary reads the
        # in-memory stats of these taps after they are stopped
        for t in self.active:
            try:
                t.stop()
            except Exception:
                pass

    def get(self, kind):
        """Return the active tap of a given kind, or None."""
        for t in self.active:
            if getattr(t, "kind", None) == kind:
                return t
        return None
