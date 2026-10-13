"""GUI live packet feed: a bounded buffer of raw target packets.

The GUI polls take_new() from its own thread; the sniffer only appends.
Nothing here parses packets — rows are rendered lazily by the GUI so the
capture path stays as light as possible.
"""
import threading


class LiveTap:
    kind = "live"

    def __init__(self, iface, target_mac, maxlen=8000):
        self.iface = iface
        self.target_mac = target_mac
        self.maxlen = maxlen
        self._buf = []
        self._seq = 0
        self._lock = threading.Lock()
        self._sniffer = None

    def describe(self):
        return f"live feed ({self.maxlen} packet window)"

    def start(self):
        from scapy.all import AsyncSniffer
        self._sniffer = AsyncSniffer(
            iface=self.iface, filter=f"ether host {self.target_mac}",
            prn=self._prn, store=False, promisc=False)
        self._sniffer.start()

    def stop(self):
        try:
            if self._sniffer:
                self._sniffer.stop()
        except Exception:
            pass

    def _prn(self, pkt):
        with self._lock:
            self._seq += 1
            self._buf.append((self._seq, pkt))
            if len(self._buf) > self.maxlen:
                self._buf.pop(0)

    def take_new(self, max_n=None):
        """Hand over captured packets (up to max_n), newest last."""
        with self._lock:
            if max_n is None or len(self._buf) <= max_n:
                out, self._buf = self._buf, []
            else:
                out = self._buf[:max_n]
                self._buf = self._buf[max_n:]
        return out
