"""masq PyQt6 desktop console."""

from __future__ import annotations

import html
import math
import os
import sys
import threading
import time
from typing import Any, Callable

from PyQt6.QtCore import (
    QEasingCurve,
    QEvent,
    QObject,
    QPointF,
    QTimer,
    Qt,
    QVariantAnimation,
    pyqtSignal,
)
from PyQt6.QtGui import QBrush, QColor, QCloseEvent, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTableView,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from scapy.utils import hexdump

from core.session import MitmSession, SessionError
from .model import PacketTableModel, packet_to_record
from .theme import COLORS, color, mono_font, stylesheet, ui_font

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def format_bytes(value: int | float | None) -> str:
    if value is None:
        return "—"
    number = float(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    index = 0
    while abs(number) >= 1024.0 and index < len(units) - 1:
        number /= 1024.0
        index += 1
    return f"{number:,.0f} {units[index]}" if index == 0 else f"{number:,.1f} {units[index]}"


def format_duration(seconds: float | int) -> str:
    total = max(0, int(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


class Bridge(QObject):
    log = pyqtSignal(str)
    status = pyqtSignal(dict)
    ended = pyqtSignal(object)


class StatusDot(QWidget):
    def __init__(self, error_sink: Callable[[str], None], parent=None) -> None:
        super().__init__(parent)
        self.setFixedSize(24, 24)
        self._running = False
        self._phase = 0.0
        self._error_sink = error_sink
        self._timer = QTimer(self)
        self._timer.setInterval(40)
        self._timer.timeout.connect(self._safe_tick)

    def set_running(self, running: bool) -> None:
        self._running = running
        if running:
            self._timer.start()
        else:
            self._timer.stop()
            self._phase = 0.0
        self.update()

    def _safe_tick(self) -> None:
        try:
            self._phase = (self._phase + 0.08) % (math.tau)
            self.update()
        except Exception as exc:
            self._timer.stop()
            self._error_sink(f"[!] status animation: {exc}")

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        center = QPointF(self.width() / 2, self.height() / 2)
        if self._running:
            pulse = (math.sin(self._phase) + 1.0) / 2.0
            halo = QColor(COLORS["accent"])
            halo.setAlpha(int(25 + pulse * 55))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(halo)
            painter.drawEllipse(center, 7.0 + pulse * 3.0, 7.0 + pulse * 3.0)
            painter.setBrush(color("success"))
        else:
            painter.setBrush(color("faint"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(center, 4.0, 4.0)


class Sparkline(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumSize(140, 40)
        self.setMaximumHeight(48)
        self.samples: list[float] = []

    def add_sample(self, value: float) -> None:
        self.samples.append(max(0.0, float(value)))
        del self.samples[:-60]
        self.update()

    def clear(self) -> None:
        self.samples.clear()
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), color("base"))
        if len(self.samples) < 2:
            painter.setPen(color("faint"))
            painter.setFont(mono_font(8))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "PPS  waiting")
            return
        maximum = max(max(self.samples), 1.0)
        left, top, right, bottom = 7.0, 7.0, self.width() - 7.0, self.height() - 7.0
        step = (right - left) / max(1, len(self.samples) - 1)
        path = QPainterPath()
        for index, value in enumerate(self.samples):
            x = left + index * step
            y = bottom - (value / maximum) * (bottom - top)
            if index == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        painter.setPen(QPen(color("accent"), 1.7))
        painter.drawPath(path)
        painter.setPen(color("muted"))
        painter.setFont(mono_font(7))
        painter.drawText(7, 12, f"{self.samples[-1]:,.0f} PPS")


class BarList(QWidget):
    def __init__(self, empty_text: str, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[tuple[str, int]] = []
        self._empty = empty_text
        self.setMinimumHeight(170)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_rows(self, rows: list[tuple[Any, Any]]) -> None:
        self._rows = [(str(label), int(count)) for label, count in rows if int(count) >= 0]
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(mono_font(8))
        rect = self.rect().adjusted(0, 4, 0, -4)
        if not self._rows:
            painter.setPen(color("faint"))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self._empty)
            return
        visible = self._rows[:10]
        row_h = max(24, min(31, rect.height() // max(1, len(visible))))
        maximum = max((count for _, count in visible), default=1) or 1
        for index, (label, count) in enumerate(visible):
            y = rect.top() + index * row_h
            bar_y = y + row_h - 8
            width = max(2.0, (self.width() - 10) * count / maximum)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color("accent_dim"))
            painter.drawRoundedRect(0, bar_y, int(width), 4, 2, 2)
            painter.setPen(color("text"))
            clipped = painter.fontMetrics().elidedText(label, Qt.TextElideMode.ElideMiddle, max(60, self.width() - 62))
            painter.drawText(0, y, self.width() - 48, row_h - 7, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, clipped)
            painter.setPen(color("muted"))
            painter.drawText(self.width() - 48, y, 48, row_h - 7, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, f"{count:,}")


class Section(QWidget):
    def __init__(self, title: str, meta: str, content: QWidget, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        head = QHBoxLayout()
        heading = QLabel(title)
        heading.setObjectName("SectionTitle")
        detail = QLabel(meta)
        detail.setObjectName("SectionMeta")
        head.addWidget(heading)
        head.addStretch()
        head.addWidget(detail)
        layout.addLayout(head)
        layout.addWidget(content, 1)


class Metric(QWidget):
    def __init__(self, label: str, value: str = "0", parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        self.value = QLabel(value)
        self.value.setObjectName("MetricValue")
        self.value.setFont(mono_font(14))
        caption = QLabel(label.upper())
        caption.setObjectName("MetricLabel")
        layout.addWidget(self.value)
        layout.addWidget(caption)


class ManualScrollFilter(QObject):
    manual = pyqtSignal()

    def eventFilter(self, watched, event) -> bool:
        if event.type() in (QEvent.Type.Wheel, QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress):
            self.manual.emit()
        return False


class MainWindow(QMainWindow):
    def __init__(self, args: Any) -> None:
        super().__init__()
        self.args = args
        self.bridge = Bridge(self)
        self.session: MitmSession | None = None
        self.worker: threading.Thread | None = None
        self.running = False
        self.latest_status: dict[str, Any] = {}
        self._last_rate: tuple[float, int] | None = None
        self._scroll_animation: QVariantAnimation | None = None
        self._closing = False
        self.setWindowTitle("MASQ  |  network positioning console")
        self.resize(1460, 900)
        self.setMinimumSize(1060, 680)
        self._build_ui()
        self._connect_signals()
        self._create_timers()
        self._set_running(False, "IDLE")
        self._log("[i] Console ready. Traffic stays in the kernel; this view observes copies only.")

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(12, 0, 12, 12)
        outer.setSpacing(10)

        accent = QFrame()
        accent.setFixedHeight(2)
        accent.setStyleSheet(f"background: {COLORS['accent']}; border: none;")
        outer.addWidget(accent)

        control = QFrame()
        control.setObjectName("ControlBar")
        control_layout = QHBoxLayout(control)
        control_layout.setContentsMargins(16, 10, 12, 10)
        control_layout.setSpacing(10)
        brand_box = QVBoxLayout()
        brand_box.setSpacing(0)
        product = QLabel("masq")
        product.setObjectName("Product")
        eyebrow = QLabel("TRANSPARENT POSITIONING CONSOLE")
        eyebrow.setObjectName("Eyebrow")
        brand_box.addWidget(product)
        brand_box.addWidget(eyebrow)
        control_layout.addLayout(brand_box)
        control_layout.addSpacing(18)
        self.iface_input = QLineEdit(str(getattr(self.args, "iface", None) or ""))
        self.iface_input.setPlaceholderText("interface (auto)")
        self.iface_input.setFixedWidth(145)
        self.target_input = QLineEdit(str(getattr(self.args, "target", "") or ""))
        self.target_input.setPlaceholderText("target IPv4 / host")
        self.target_input.setMinimumWidth(190)
        self.target_input.setMaximumWidth(250)
        control_layout.addWidget(self.iface_input)
        control_layout.addWidget(self.target_input)
        self.start_button = QPushButton("START")
        self.start_button.setObjectName("Primary")
        self.stop_button = QPushButton("STOP")
        self.stop_button.setObjectName("Stop")
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addStretch(1)
        self.sparkline = Sparkline()
        control_layout.addWidget(self.sparkline)
        control_layout.addSpacing(8)
        self.traffic_label = QLabel("0 pkts  ·  0 B")
        self.traffic_label.setFont(mono_font(9))
        self.traffic_label.setMinimumWidth(165)
        self.traffic_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        control_layout.addWidget(self.traffic_label)
        self.status_dot = StatusDot(self._log)
        control_layout.addWidget(self.status_dot)
        self.state_label = QLabel("IDLE")
        self.state_label.setFont(mono_font(9))
        self.state_label.setMinimumWidth(92)
        control_layout.addWidget(self.state_label)
        outer.addWidget(control)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_summary_tab(), "SUMMARY")
        self.tabs.addTab(self._build_packets_tab(), "PACKETS")
        outer.addWidget(self.tabs, 1)

        log_frame = QFrame()
        log_frame.setObjectName("LogPanel")
        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(10, 6, 10, 7)
        log_layout.setSpacing(3)
        log_head = QHBoxLayout()
        log_title = QLabel("ENGINE LOG")
        log_title.setObjectName("Eyebrow")
        clear_log = QPushButton("CLEAR")
        clear_log.setFixedHeight(25)
        clear_log.setMaximumWidth(64)
        clear_log.clicked.connect(lambda: self.log_view.clear())
        log_head.addWidget(log_title)
        log_head.addStretch()
        log_head.addWidget(clear_log)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.document().setMaximumBlockCount(2000)
        self.log_view.setFixedHeight(88)
        log_layout.addLayout(log_head)
        log_layout.addWidget(self.log_view)
        outer.addWidget(log_frame)

    def _build_summary_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 18)
        layout.setSpacing(18)
        rail = QFrame()
        rail.setObjectName("MetricRail")
        metrics = QHBoxLayout(rail)
        metrics.setContentsMargins(18, 12, 18, 12)
        metrics.setSpacing(30)
        self.duration_metric = Metric("Duration", "00:00:00")
        self.up_metric = Metric("Upstream", "0 pkts  /  0 B")
        self.down_metric = Metric("Downstream", "0 pkts  /  0 B")
        self.dns_metric = Metric("DNS Queries", "0")
        for metric in (self.duration_metric, self.up_metric, self.down_metric, self.dns_metric):
            metrics.addWidget(metric, 1)
        layout.addWidget(rail)

        grid = QGridLayout()
        grid.setHorizontalSpacing(26)
        grid.setVerticalSpacing(18)
        self.services = BarList("No transport services observed")
        self.domains = BarList("No DNS queries observed")
        self.destinations = BarList("No destinations observed")
        grid.addWidget(Section("Services", "TCP / UDP", self.services), 0, 0)
        grid.addWidget(Section("DNS domains", "TOP QUERIES", self.domains), 0, 1)
        grid.addWidget(Section("Destinations", "DOMAIN HINTS", self.destinations), 0, 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)
        layout.addLayout(grid, 1)
        return page

    def _build_packets_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        tools = QWidget()
        tool_layout = QHBoxLayout(tools)
        tool_layout.setContentsMargins(10, 8, 10, 8)
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter packets across every column…")
        self.filter_input.setClearButtonEnabled(True)
        self.packet_count = QLabel("0 buffered")
        self.packet_count.setFont(mono_font(8))
        self.packet_count.setStyleSheet(f"color: {COLORS['muted']};")
        self.follow_button = QPushButton("FOLLOW")
        self.follow_button.setObjectName("Follow")
        self.follow_button.setCheckable(True)
        self.follow_button.setChecked(True)
        self.follow_button.setToolTip("Keep the newest packet in view")
        tool_layout.addWidget(self.filter_input, 1)
        tool_layout.addWidget(self.packet_count)
        tool_layout.addWidget(self.follow_button)
        layout.addWidget(tools)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.packet_model = PacketTableModel(self)
        self.packet_table = QTableView()
        self.packet_table.setModel(self.packet_model)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.packet_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.packet_table.setShowGrid(False)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.verticalHeader().setDefaultSectionSize(29)
        header = self.packet_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        widths = (74, 112, 72, 170, 170, 560, 72)
        for column, width in enumerate(widths):
            header.resizeSection(column, width)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        splitter.addWidget(self.packet_table)

        detail_tabs = QTabWidget()
        self.layer_tree = QTreeWidget()
        self.layer_tree.setHeaderLabels(("FIELD", "VALUE"))
        self.layer_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.layer_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.layer_tree.setUniformRowHeights(True)
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.hex_view.setPlaceholderText("Select a packet to inspect its bytes")
        detail_tabs.addTab(self.layer_tree, "DISSECTION")
        detail_tabs.addTab(self.hex_view, "HEX")
        splitter.addWidget(detail_tabs)
        splitter.setSizes((520, 250))
        splitter.setCollapsible(0, False)
        layout.addWidget(splitter, 1)
        return page

    def _connect_signals(self) -> None:
        self.bridge.log.connect(self._log)
        self.bridge.status.connect(self._on_status)
        self.bridge.ended.connect(self._on_ended)
        self.start_button.clicked.connect(self._start_session)
        self.stop_button.clicked.connect(self._stop_session)
        self.target_input.returnPressed.connect(self._start_session)
        self.filter_input.textChanged.connect(self.packet_model.set_filter)
        self.packet_table.selectionModel().currentRowChanged.connect(self._show_packet)
        self.follow_button.toggled.connect(self._follow_toggled)
        scroll_filter = ManualScrollFilter(self.packet_table)
        scroll_filter.manual.connect(self._manual_scroll)
        self.packet_table.viewport().installEventFilter(scroll_filter)
        self.packet_table.verticalScrollBar().installEventFilter(scroll_filter)
        self._scroll_filter = scroll_filter
        # one persistent scroll animation — never deleted, just reconfigured
        self._scroll_animation = QVariantAnimation(self)
        self._scroll_animation.setDuration(180)
        self._scroll_animation.setEasingCurve(QEasingCurve.Type.OutQuart)
        self._scroll_animation.valueChanged.connect(
            lambda value: self.packet_table.verticalScrollBar().setValue(int(value)))

    def _create_timers(self) -> None:
        self.packet_timer = QTimer(self)
        self.packet_timer.setInterval(250)
        self.packet_timer.timeout.connect(lambda: self._safe_timer("packet poll", self._poll_packets))
        self.packet_timer.start()
        self.summary_timer = QTimer(self)
        self.summary_timer.setInterval(1000)
        self.summary_timer.timeout.connect(lambda: self._safe_timer("summary refresh", self._refresh_summary))
        self.summary_timer.start()
        self.fade_timer = QTimer(self)
        self.fade_timer.setInterval(120)
        self.fade_timer.timeout.connect(lambda: self._safe_timer("row fade", self.packet_model.refresh_fades))
        self.fade_timer.start()

    def _safe_timer(self, name: str, callback: Callable[[], None]) -> None:
        try:
            callback()
        except Exception as exc:
            self._log(f"[!] UI {name} failed: {exc}")

    def _tap_names(self) -> list[str]:
        requested = list(getattr(self.args, "tap", None) or [])
        for required in ("dns", "conn", "live"):
            if required not in requested:
                requested.append(required)
        return requested

    def _start_session(self) -> None:
        if self.running:
            return
        target = self.target_input.text().strip()
        iface = self.iface_input.text().strip() or None
        if not target:
            self._log("[!] Target is required.")
            self.state_label.setText("TARGET REQUIRED")
            self.target_input.setFocus()
            return
        self.packet_model.clear()
        self.layer_tree.clear()
        self.hex_view.clear()
        self.latest_status.clear()
        self._last_rate = None
        self.sparkline.clear()
        self._reset_summary()
        self._set_running(True, "STARTING")
        self._log(f"[*] Starting session for {target}" + (f" on {iface}" if iface else " with automatic interface selection"))
        try:
            self.session = MitmSession(on_log=self.bridge.log.emit,
                                       on_status=self.bridge.status.emit)
        except Exception as exc:
            self._set_running(False, "FAILED")
            self._log(f"[!] Could not initialize engine: {exc}")
            return

        def worker_main() -> None:
            failure: str | None = None
            try:
                assert self.session is not None
                self.session.start(target, iface, self._tap_names(),
                                   refresh_interval=10.0, stats_interval=5.0)
            except SessionError as exc:
                failure = str(exc)
            except Exception as exc:
                failure = f"Unexpected engine error: {exc}"
            finally:
                self.bridge.ended.emit(failure)

        self.worker = threading.Thread(target=worker_main, name="masq-engine", daemon=False)
        self.worker.start()

    def _stop_session(self) -> None:
        if not self.running or self.session is None:
            return
        self.state_label.setText("RESTORING ARP")
        self.stop_button.setEnabled(False)
        self._log("[i] Stop requested. Restoring the target ARP state…")
        try:
            self.session.stop()
        except Exception as exc:
            self._log(f"[!] Stop request failed: {exc}")

    def _on_ended(self, failure: object) -> None:
        self._safe_timer("final packet poll", self._poll_packets)
        self._safe_timer("final summary refresh", self._refresh_summary)
        if self.worker and self.worker is not threading.current_thread():
            self.worker.join(timeout=0.05)
        if failure:
            message = str(failure)
            self._log(f"[!] {message}")
            self._set_running(False, "FAILED")
        else:
            self._log("[i] Session ended. Final capture view is frozen and ARP state is restored.")
            self._set_running(False, "STOPPED")

    def _set_running(self, running: bool, state: str) -> None:
        self.running = running
        self.status_dot.set_running(running)
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.target_input.setEnabled(not running)
        self.iface_input.setEnabled(not running)
        self.state_label.setText(state)
        self.state_label.setStyleSheet(f"color: {COLORS['success'] if running else COLORS['muted']};")

    def _on_status(self, status: dict) -> None:
        try:
            self.latest_status = dict(status)
            self.state_label.setText("POSITIONED")
            up = int(status.get("up", 0) or 0)
            down = int(status.get("down", 0) or 0)
            total = up + down
            total_bytes = int(status.get("up_b", 0) or 0) + int(status.get("down_b", 0) or 0)
            self.traffic_label.setText(f"{total:,} pkts  ·  {format_bytes(total_bytes)}")
            now = time.monotonic()
            if self._last_rate is not None:
                then, previous = self._last_rate
                elapsed = max(0.001, now - then)
                self.sparkline.add_sample(max(0, total - previous) / elapsed)
            self._last_rate = (now, total)
        except Exception as exc:
            self._log(f"[!] Status update failed: {exc}")

    def _poll_packets(self) -> None:
        if self.session is None or getattr(self.session, "taps", None) is None:
            return
        tap = self.session.taps.get("live")
        if tap is None:
            return
        items = tap.take_new(512)
        if not items:
            return
        records = []
        for seq, packet in items:
            try:
                records.append(packet_to_record(int(seq), packet))
            except Exception as exc:
                self._log(f"[!] Packet {seq} could not be rendered: {exc}")
        if records:
            self.packet_model.append_records(records)
            self.packet_count.setText(f"{self.packet_model.total_count:,} buffered")
            if self.follow_button.isChecked():
                self._animate_scroll_to_bottom()

    def _refresh_summary(self) -> None:
        if self.session is None:
            return
        status = dict(self.latest_status)
        up = int(status.get("up", 0) or 0)
        up_b = int(status.get("up_b", 0) or 0)
        down = int(status.get("down", 0) or 0)
        down_b = int(status.get("down_b", 0) or 0)
        try:
            if self.session.dp is not None:
                counters = self.session.dp.counters()
                if len(counters) == 4 and all(value is not None for value in counters):
                    up, up_b, down, down_b = map(int, counters)
        except Exception as exc:
            self._log(f"[!] Kernel counter read failed: {exc}")
        started = float((getattr(self.session, "st", None) or {}).get("started", time.time()))
        elapsed = status.get("elapsed")
        if elapsed is None:
            elapsed = max(0.0, time.time() - started)
        self.duration_metric.value.setText(format_duration(elapsed))
        self.up_metric.value.setText(f"{up:,} pkts  /  {format_bytes(up_b)}")
        self.down_metric.value.setText(f"{down:,} pkts  /  {format_bytes(down_b)}")
        self.traffic_label.setText(f"{up + down:,} pkts  ·  {format_bytes(up_b + down_b)}")
        if getattr(self.session, "taps", None) is None:
            return
        dns_tap = self.session.taps.get("dns")
        conn_tap = self.session.taps.get("conn")
        dns_summary: dict[str, Any] = dns_tap.summary() if dns_tap else {}
        conn_summary: dict[str, Any] = conn_tap.summary() if conn_tap else {}
        self.dns_metric.value.setText(f"{int(dns_summary.get('total', 0) or 0):,}")
        self.services.set_rows(list(conn_summary.get("services", []) or []))
        self.domains.set_rows(list(dns_summary.get("top_domains", []) or []))
        hints = dict(getattr(dns_tap, "addr_map", {}) or {}) if dns_tap else {}
        destinations = []
        for ip, count in list(conn_summary.get("top_dsts", []) or []):
            hint = hints.get(ip)
            destinations.append((f"{ip}  {hint}" if hint else str(ip), count))
        self.destinations.set_rows(destinations)

    def _reset_summary(self) -> None:
        self.duration_metric.value.setText("00:00:00")
        self.up_metric.value.setText("0 pkts  /  0 B")
        self.down_metric.value.setText("0 pkts  /  0 B")
        self.dns_metric.value.setText("0")
        self.services.set_rows([])
        self.domains.set_rows([])
        self.destinations.set_rows([])
        self.traffic_label.setText("0 pkts  ·  0 B")
        self.packet_count.setText("0 buffered")

    def _show_packet(self, current, previous) -> None:
        packet = self.packet_model.packet_at(current)
        self.layer_tree.clear()
        self.hex_view.clear()
        if packet is None:
            return
        try:
            layer = packet
            depth = 0
            while layer is not None and depth < 64:
                name = str(getattr(layer, "name", layer.__class__.__name__))
                top = QTreeWidgetItem((name, str(layer.summary())))
                top.setForeground(0, QBrush(color("accent")))
                top.setFont(0, ui_font(9))
                self.layer_tree.addTopLevelItem(top)
                fields_desc = getattr(layer, "fields_desc", [])
                shown = set()
                for descriptor in fields_desc:
                    field_name = str(getattr(descriptor, "name", "field"))
                    try:
                        value = layer.getfieldval(field_name)
                        rendered = descriptor.i2repr(layer, value)
                    except Exception:
                        rendered = repr(getattr(layer, field_name, None))
                    shown.add(field_name)
                    child = QTreeWidgetItem((field_name, str(rendered)))
                    child.setForeground(0, QBrush(color("muted")))
                    top.addChild(child)
                for field_name, value in getattr(layer, "fields", {}).items():
                    if field_name not in shown:
                        child = QTreeWidgetItem((str(field_name), repr(value)))
                        child.setForeground(0, QBrush(color("muted")))
                        top.addChild(child)
                top.setExpanded(True)
                payload = getattr(layer, "payload", None)
                if payload is None or payload is layer or payload.__class__.__name__ == "NoPayload":
                    break
                layer = payload
                depth += 1
            self.hex_view.setPlainText(hexdump(packet, dump=True) or "")
        except Exception as exc:
            self._log(f"[!] Packet dissection failed: {exc}")
            try:
                self.hex_view.setPlainText(packet.show(dump=True))
            except Exception:
                self.hex_view.setPlainText(str(exc))

    def _animate_scroll_to_bottom(self) -> None:
        bar = self.packet_table.verticalScrollBar()
        animation = self._scroll_animation
        if animation.state() == QVariantAnimation.State.Running:
            animation.stop()
        animation.setStartValue(float(bar.value()))
        animation.setEndValue(float(bar.maximum()))
        animation.start()

    def _manual_scroll(self) -> None:
        if self._scroll_animation.state() == QVariantAnimation.State.Running:
            self._scroll_animation.stop()
        if self.follow_button.isChecked():
            self.follow_button.setChecked(False)

    def _follow_toggled(self, checked: bool) -> None:
        if checked:
            self._animate_scroll_to_bottom()

    def _log(self, message: str) -> None:
        try:
            stamp = time.strftime("%H:%M:%S")
            text = str(message).replace("\r", " ").replace("\n", " ↳ ")
            if text.startswith("[!]"):
                tint = COLORS["danger"]
            elif text.startswith("[i]"):
                tint = COLORS["muted"]
            else:
                tint = COLORS["accent"]
            escaped = html.escape(f"{stamp}  {text}")
            self.log_view.append(f'<span style="color:{tint};">{escaped}</span>')
            self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())
        except Exception:
            pass

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._closing:
            event.accept()
            return
        self._closing = True
        self.packet_timer.stop()
        self.summary_timer.stop()
        self.fade_timer.stop()
        if self.session is not None and self.worker is not None and self.worker.is_alive():
            try:
                self.session.stop()
            except Exception as exc:
                self._log(f"[!] Stop during close failed: {exc}")
            self.state_label.setText("RESTORING ARP")
            QApplication.processEvents()
            self.worker.join()
        event.accept()


def run_gui(args: Any) -> int:
    """Launch the masq console using argparse-compatible *args*."""
    app = QApplication.instance()
    owns_app = app is None
    if app is None:
        app = QApplication(sys.argv)
    app.setApplicationName("masq")
    app.setOrganizationName("masq")
    app.setStyle("Fusion")
    app.setStyleSheet(stylesheet())
    app.setFont(ui_font(10))
    window = MainWindow(args)
    window.show()
    if owns_app:
        return app.exec()
    return 0
