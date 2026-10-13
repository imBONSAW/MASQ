"""Full packet capture to pcap via tcpdump — zero parse overhead, Wireshark-ready."""
import shutil
import subprocess


class PcapTap:
    kind = "pcap"

    def __init__(self, iface, target_mac, path):
        self.iface = iface
        self.bpf = f"ether host {target_mac}"
        self.path = path
        self.proc = None

    def describe(self):
        return self.path

    def summary(self):
        try:
            import os
            return {"path": self.path, "size": os.path.getsize(self.path)}
        except OSError:
            return {"path": self.path, "size": None}

    def start(self):
        if shutil.which("tcpdump") is None:
            raise RuntimeError("pcap tap needs tcpdump (apt install tcpdump)")
        self.proc = subprocess.Popen(
            ["tcpdump", "-i", self.iface, "-s", "0", "-w", self.path, self.bpf],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
