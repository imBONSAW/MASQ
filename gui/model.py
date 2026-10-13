"""Packet data model and Scapy presentation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import time
from typing import Any, Iterable

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtGui import QColor, QFont

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from .theme import COLORS, mono_font, protocol_color


@dataclass(slots=True)
class PacketRecord:
    seq: int
    wall_time: float
    proto: str
    source: str
    destination: str
    info: str
    length: int
    packet: Any
    arrived: float

    @property
    def cells(self) -> tuple[str, ...]:
        stamp = datetime.fromtimestamp(self.wall_time).strftime("%H:%M:%S.%f")[:-3]
        return (str(self.seq), stamp, self.proto, self.source, self.destination, self.info, str(self.length))

    @property
    def search_text(self) -> str:
        return " ".join(self.cells).casefold()


def _clean_dns_name(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value).rstrip(".")


def _endpoints(pkt: Any) -> tuple[str, str]:
    if pkt.haslayer(IP):
        return str(pkt[IP].src), str(pkt[IP].dst)
    if pkt.haslayer(ARP):
        return str(pkt[ARP].psrc), str(pkt[ARP].pdst)
    if pkt.haslayer(Ether):
        return str(pkt[Ether].src), str(pkt[Ether].dst)
    return "?", "?"


def _protocol(pkt: Any) -> str:
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    try:
        return str(pkt.lastlayer().name).upper()
    except Exception:
        return "OTHER"


def _packet_info(pkt: Any, proto: str) -> str:
    try:
        if proto == "DNS":
            dns = pkt[DNS]
            direction = "response" if int(dns.qr) else "query"
            if dns.qd and isinstance(dns.qd, DNSQR):
                return f"{direction} {_clean_dns_name(dns.qd.qname)}"
            return direction
        if proto == "TCP":
            tcp = pkt[TCP]
            flags = str(tcp.flags)
            return f"{tcp.sport} → {tcp.dport}  [{flags}] seq={tcp.seq} ack={tcp.ack}"
        if proto == "UDP":
            udp = pkt[UDP]
            return f"{udp.sport} → {udp.dport}"
        if proto == "ICMP":
            icmp = pkt[ICMP]
            return f"type={icmp.type} code={icmp.code}"
        if proto == "ARP":
            arp = pkt[ARP]
            operation = "request" if int(arp.op) == 1 else "reply" if int(arp.op) == 2 else f"op={arp.op}"
            return f"{operation} {arp.psrc} ({arp.hwsrc}) → {arp.pdst}"
        return str(pkt.summary())
    except Exception:
        try:
            return str(pkt.summary())
        except Exception:
            return "undissected packet"


def packet_to_record(seq: int, pkt: Any) -> PacketRecord:
    wall_time = float(getattr(pkt, "time", time.time()))
    proto = _protocol(pkt)
    src, dst = _endpoints(pkt)
    try:
        length = len(bytes(pkt))
    except Exception:
        length = int(getattr(pkt, "wirelen", 0) or 0)
    return PacketRecord(seq, wall_time, proto, src, dst, _packet_info(pkt, proto), length, pkt, time.monotonic())


class PacketTableModel(QAbstractTableModel):
    HEADERS = ("#", "TIME", "PROTO", "SOURCE", "DESTINATION", "INFO", "LEN")

    def __init__(self, parent=None, max_rows: int = 20_000) -> None:
        super().__init__(parent)
        self.max_rows = max_rows
        self._records: list[PacketRecord] = []
        self._visible: list[PacketRecord] = []
        self._filter = ""
        self._mono: QFont = mono_font(9)

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._visible)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._visible)):
            return None
        record = self._visible[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return record.cells[index.column()]
        if role == Qt.ItemDataRole.FontRole:
            return self._mono
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if index.column() in (0, 6):
                return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.ForegroundRole:
            if index.column() == 2:
                return protocol_color(record.proto)
            if index.column() in (0, 1, 6):
                return QColor(COLORS["muted"])
        if role == Qt.ItemDataRole.BackgroundRole:
            age = time.monotonic() - record.arrived
            if age < 0.8:
                strength = max(0.0, 1.0 - age / 0.8)
                accent = QColor(COLORS["accent"])
                accent.setAlpha(int(12 + 48 * strength))
                return accent
        if role == Qt.ItemDataRole.ToolTipRole:
            return record.info
        return None

    def set_filter(self, text: str) -> None:
        needle = text.strip().casefold()
        if needle == self._filter:
            return
        self.beginResetModel()
        self._filter = needle
        self._visible = [r for r in self._records if not needle or needle in r.search_text]
        self.endResetModel()

    def append_records(self, records: Iterable[PacketRecord]) -> int:
        incoming = list(records)
        if not incoming:
            return 0
        overflow = len(self._records) + len(incoming) - self.max_rows
        if overflow > 0:
            trim = min(len(self._records), max(overflow, min(1000, self.max_rows // 10)))
            self.beginResetModel()
            del self._records[:trim]
            self._records.extend(incoming)
            if len(self._records) > self.max_rows:
                del self._records[: len(self._records) - self.max_rows]
            self._visible = [r for r in self._records if not self._filter or self._filter in r.search_text]
            self.endResetModel()
            return len(incoming)
        matches = [r for r in incoming if not self._filter or self._filter in r.search_text]
        self._records.extend(incoming)
        if matches:
            first = len(self._visible)
            self.beginInsertRows(QModelIndex(), first, first + len(matches) - 1)
            self._visible.extend(matches)
            self.endInsertRows()
        return len(incoming)

    def packet_at(self, index: QModelIndex):
        if index.isValid() and 0 <= index.row() < len(self._visible):
            return self._visible[index.row()].packet
        return None

    def refresh_fades(self) -> None:
        if self._visible:
            bottom = min(len(self._visible) - 1, 256)
            first = max(0, len(self._visible) - 1 - bottom)
            self.dataChanged.emit(self.index(first, 0), self.index(len(self._visible) - 1, len(self.HEADERS) - 1), [Qt.ItemDataRole.BackgroundRole])

    def clear(self) -> None:
        self.beginResetModel()
        self._records.clear()
        self._visible.clear()
        self.endResetModel()

    @property
    def total_count(self) -> int:
        return len(self._records)
