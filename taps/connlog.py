"""New TCP connections and new UDP flows opened by the target.

TCP: SYN without ACK (a genuinely new connection).
UDP: first packet per (dst, dport) pair counts as a new flow (no SYN in UDP);
     port 53/5353 are excluded here — the dns tap owns DNS and mDNS is noise.

Keeps in-memory session stats used for the end-of-session summary.
"""
import collections
import time

from scapy.all import IP, TCP, UDP

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns-tcp",
    80: "http", 110: "pop3", 123: "ntp", 143: "imap", 443: "https",
    465: "smtps", 515: "ipp", 554: "rtsp", 587: "submission",
    853: "dns-over-tls", 993: "imaps", 995: "pop3s", 1883: "mqtt",
    1935: "rtmp", 3306: "mysql", 3389: "rdp", 3478: "stun",
    5060: "sip", 5222: "xmpp", 5228: "fcm", 5349: "stuns",
    8080: "http-alt", 8443: "https-alt", 8883: "mqtt-tls",
    19302: "webrtc-stun", 19305: "webrtc-stun",
}


def _service_label(proto, port):
    name = SERVICES.get(port)
    if name is None:
        return f"other ({proto} {port})"
    if proto == "udp" and port == 443:
        name = "quic/http3"
    return f"{name} ({proto} {port})"


class ConnTap:
    kind = "conn"

    def __init__(self, iface, target_mac, logfile, target_ip=None):
        self.iface = iface
        self.target_mac = target_mac
        self.logfile = logfile
        self.target_ip = target_ip
        self._fh = None
        self._sniffer = None
        self._udp_seen = set()
        self.services = collections.Counter()
        self.dsts = collections.Counter()
        self.proto_flows = {"TCP": 0, "UDP": 0}

    def describe(self):
        return self.logfile

    def start(self):
        from scapy.all import AsyncSniffer
        self._fh = open(self.logfile, "a", buffering=1)
        bpf = ("(tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0) "
               "or (udp and not (port 53 or port 5353))")
        self._sniffer = AsyncSniffer(iface=self.iface, filter=bpf,
                                     prn=self._prn, store=False, promisc=False)
        self._sniffer.start()

    def stop(self):
        try:
            if self._sniffer:
                self._sniffer.stop()
        finally:
            if self._fh:
                self._fh.close()
                self._fh = None

    def summary(self):
        return {
            "tcp": self.proto_flows["TCP"],
            "udp": self.proto_flows["UDP"],
            "services": self.services.most_common(8),
            "top_dsts": self.dsts.most_common(10),
        }

    def _prn(self, pkt):
        try:
            ts = time.strftime("%H:%M:%S")
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                ip, tcp = pkt[IP], pkt[TCP]
                if self.target_ip and ip.src != self.target_ip and ip.dst != self.target_ip:
                    return
                self.proto_flows["TCP"] += 1
                lbl = _service_label("tcp", int(tcp.dport))
                self.services[lbl] += 1
                self.dsts[ip.dst] += 1
                self._fh.write(f"{ts} NEW {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}\n")
            elif pkt.haslayer(UDP) and pkt.haslayer(IP):
                ip, udp = pkt[IP], pkt[UDP]
                if self.target_ip and ip.src != self.target_ip and ip.dst != self.target_ip:
                    return
                key = (ip.dst, int(udp.dport))
                if len(self._udp_seen) >= 100000 or key in self._udp_seen:
                    return
                self._udp_seen.add(key)
                self.proto_flows["UDP"] += 1
                lbl = _service_label("udp", int(udp.dport))
                self.services[lbl] += 1
                self.dsts[ip.dst] += 1
                self._fh.write(f"{ts} FLOW {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}\n")
        except Exception:
            pass
