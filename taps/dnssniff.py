"""Passive DNS query log for the target (queries and answers, content-free).

Also keeps in-memory session stats (domain counts, qtype counts, and an
address->domain map from answers) used for the end-of-session summary.
"""
import collections
import socket
import time

QTYPES = {1: "A", 12: "PTR", 28: "AAAA", 33: "SRV", 5: "CNAME",
          15: "MX", 16: "TXT", 65: "HTTPS", 255: "ANY"}


def _s(x):
    if isinstance(x, (bytes, bytearray)):
        return x.decode(errors="replace").rstrip(".")
    return str(x).rstrip(".")


def _norm(name):
    """Normalize a query name: lowercase, no trailing dot, no router '.lan' suffix."""
    name = name.lower().strip()
    if name.endswith(".lan"):
        name = name[:-4]
    return name


def _rdata_addr(rtype, rdata):
    """Return a printable address from an A/AAAA record, else None."""
    try:
        if rtype == 1:
            return rdata if isinstance(rdata, str) else socket.inet_ntop(socket.AF_INET, rdata)
        if rtype == 28:
            return rdata if isinstance(rdata, str) else socket.inet_ntop(socket.AF_INET6, rdata)
    except (OSError, ValueError):
        return None
    return None


class DnsTap:
    kind = "dns"

    def __init__(self, iface, target_ip, target_mac, logfile):
        self.iface = iface
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.logfile = logfile
        self._fh = None
        self._sniffer = None
        self.domains = collections.Counter()
        self.qtypes = collections.Counter()
        self.addr_map = {}

    def describe(self):
        return self.logfile

    def start(self):
        from scapy.all import AsyncSniffer
        self._fh = open(self.logfile, "a", buffering=1)
        bpf = f"udp port 53 and ether host {self.target_mac}"
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
            "total": sum(self.domains.values()),
            "unique": len(self.domains),
            "qtypes": dict(self.qtypes),
            "top_domains": self.domains.most_common(12),
        }

    def _prn(self, pkt):
        try:
            from scapy.all import DNS, DNSQR, DNSRR
            if not pkt.haslayer(DNS):
                return
            d = pkt[DNS]
            ts = time.strftime("%H:%M:%S")
            if int(d.qr) == 0 and pkt.haslayer(DNSQR):
                q = pkt[DNSQR]
                name = _norm(_s(q.qname))
                if name:
                    self.domains[name] += 1
                qt = int(q.qtype)
                self.qtypes[QTYPES.get(qt, f"type{qt}")] += 1
                self._w(f"{ts} Q {_s(q.qname)} type={qt}")
            elif int(d.qr) == 1 and int(d.ancount) > 0 and d.an is not None:
                for i in range(int(d.ancount)):
                    try:
                        rr = d.an[i]
                        addr = _rdata_addr(int(rr.type), rr.rdata)
                        if addr:
                            self.addr_map.setdefault(addr, _norm(_s(rr.rrname)))
                        self._w(f"{ts} A {_s(rr.rrname)} -> {_s(rr.rdata)}")
                    except Exception:
                        break
        except Exception:
            pass

    def _w(self, line):
        if self._fh:
            self._fh.write(line + "\n")
