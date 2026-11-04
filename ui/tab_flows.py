# -*- coding: utf-8 -*-
"""
流量画像页
==========

不存报文，只维护五元组流表，所以可以长时间挂着看「谁在占带宽、在访问什么」。

三块结果：

* Top Talkers：按主机汇总收发字节
* Top 会话：按流排序，带应用识别（HTTP Host / TLS SNI / DNS 域名 / 端口特征）
* 应用分布：按应用聚合的字节数

支持实时抓包和离线 pcap 分析；离线分析不需要管理员权限。
工作线程只写 `core.flows.FlowTable`，界面用 QTimer 每秒拉一次快照。
"""

from __future__ import annotations

from PyQt5.QtCore import QThread, QTimer, pyqtSignal
from PyQt5.QtWidgets import (QComboBox, QFileDialog, QFrame, QHBoxLayout,
                             QLabel, QLineEdit, QMessageBox, QPushButton,
                             QTabWidget, QVBoxLayout, QWidget)

from core import flows as F
from core import hostinfo as HI
from core.logging_bus import log
from theme import (C_BLUE, C_MINT, C_PURPLE_DEEP, C_RED,
                   C_TEXT_DIM, C_YELLOW)
from ui.widgets import BarChart, Card, label, make_table, safe_slot, set_row

TALKER_HEADERS = ["主机", "流数", "包数", "发送", "接收", "合计"]
FLOW_HEADERS = ["应用", "协议", "源", "目标", "包数", "字节", "速率", "时长", "标志"]
APP_HEADERS = ["应用", "流数", "包数", "字节"]
DEST_HEADERS = ["目标", "字节"]


class PcapTask(QThread):
    """离线分析 pcap：可能要跑几秒到几十秒，不能占着界面线程。"""

    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, path: str, limit: int, parent=None):
        super().__init__(parent)
        self.path = path
        self.limit = limit

    def run(self):
        try:
            self.done.emit(F.analyze_pcap(self.path, limit=self.limit))
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class FlowsTab(QWidget):
    """流量画像页。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.monitor: F.FlowMonitor | None = None
        self.offline_table: F.FlowTable | None = None
        self._task: PcapTask | None = None
        self._ifaces: list = []
        self._signature = None
        self._build()

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh_view)
        self.timer.start()

    # ==================== 界面 ====================

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)
        outer.addWidget(self._build_banner())
        outer.addWidget(self._build_control())
        outer.addWidget(self._build_results(), 1)
        self.reload_ifaces()

    def _build_banner(self) -> QWidget:
        w = QFrame()
        w.setObjectName("Card")
        w.setStyleSheet("QFrame#Card { background-color:#E8F3FF;"
                        f" border:1px solid {C_BLUE}; border-radius:14px; }}")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(3)
        title = QLabel("🏆 流量画像：只看五元组统计，不保存原始报文")
        title.setStyleSheet(f"color:{C_PURPLE_DEEP}; font-weight:800; font-size:10.5pt;")
        lay.addWidget(title)
        desc = QLabel(
            "实时模式需要管理员 + Npcap；离线模式直接选一个 pcap/pcapng 文件，"
            "普通权限就能跑。应用识别靠端口表 + 载荷特征（TLS ClientHello 的 SNI、"
            "HTTP Host、DNS 应答），加密流量只能看到域名/IP，看不到具体内容。")
        desc.setWordWrap(True)
        desc.setObjectName("Dim")
        lay.addWidget(desc)
        return w

    def _build_control(self) -> QWidget:
        card = Card("🎛 采集与分析")

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("网卡", "Dim"))
        self.cmb_iface = QComboBox()
        self.cmb_iface.setMinimumWidth(300)
        r1.addWidget(self.cmb_iface)
        btn_reload = QPushButton("刷新网卡")
        btn_reload.setObjectName("Ghost")
        btn_reload.clicked.connect(self.reload_ifaces)
        r1.addWidget(btn_reload)
        r1.addWidget(label("BPF", "Dim"))
        self.ed_bpf = QLineEdit("ip")
        self.ed_bpf.setMaximumWidth(220)
        self.ed_bpf.setToolTip("默认抓所有 IPv4；可改成 \"tcp port 443\" 之类")
        r1.addWidget(self.ed_bpf)
        self.btn_start = QPushButton("▶ 开始")
        self.btn_start.setObjectName("Primary")
        self.btn_start.clicked.connect(self.start_capture)
        r1.addWidget(self.btn_start)
        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_capture)
        r1.addWidget(self.btn_stop)
        r1.addStretch(1)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(8)
        self.btn_pcap = QPushButton("📂 打开 pcap 分析")
        self.btn_pcap.setObjectName("Ghost")
        self.btn_pcap.clicked.connect(self.open_pcap)
        r2.addWidget(self.btn_pcap)
        self.btn_export = QPushButton("导出流表 CSV")
        self.btn_export.setObjectName("Ghost")
        self.btn_export.clicked.connect(self.export_csv)
        r2.addWidget(self.btn_export)
        self.btn_clear = QPushButton("清空统计")
        self.btn_clear.setObjectName("Ghost")
        self.btn_clear.clicked.connect(self.clear_stats)
        r2.addWidget(self.btn_clear)
        r2.addSpacing(12)
        self.lbl_state = label("未开始", "Dim")
        self.lbl_state.setStyleSheet(f"color:{C_TEXT_DIM}; font-weight:700;")
        r2.addWidget(self.lbl_state)
        self.lbl_stats = label("包 0 · 流 0 · 0 pps · 0 bps", "Dim")
        r2.addWidget(self.lbl_stats)
        r2.addStretch(1)
        card.add(r2)
        return card

    def _build_results(self) -> QWidget:
        self.tabs = QTabWidget()

        self.table_talkers = make_table(TALKER_HEADERS, stretch_col=0)
        for col, width in ((1, 70), (2, 80), (3, 100), (4, 100), (5, 100)):
            self.table_talkers.setColumnWidth(col, width)
        self.tabs.addTab(self.table_talkers, "🏆 Top Talkers")

        self.table_flows = make_table(FLOW_HEADERS, stretch_col=2)
        for col, width in ((0, 200), (1, 60), (3, 190), (4, 70), (5, 90),
                           (6, 90), (7, 90), (8, 140)):
            self.table_flows.setColumnWidth(col, width)
        self.tabs.addTab(self.table_flows, "🔀 Top 会话")

        page_apps = QWidget()
        al = QVBoxLayout(page_apps)
        al.setContentsMargins(0, 6, 0, 0)
        al.setSpacing(6)
        al.addWidget(label("按应用聚合的字节数（Top 8）", "CardT"))
        self.chart_apps = BarChart()
        al.addWidget(self.chart_apps, 1)
        self.table_apps = make_table(APP_HEADERS, stretch_col=0)
        for col, width in ((1, 70), (2, 80), (3, 100)):
            self.table_apps.setColumnWidth(col, width)
        al.addWidget(self.table_apps, 1)
        self.tabs.addTab(page_apps, "📊 应用分布")

        self.table_dests = make_table(DEST_HEADERS, stretch_col=0)
        self.table_dests.setColumnWidth(1, 130)
        self.tabs.addTab(self.table_dests, "🌐 Top 目标")
        return self.tabs

    # ==================== 网卡 ====================

    @safe_slot
    def reload_ifaces(self) -> None:
        self.cmb_iface.clear()
        self._ifaces = HI.list_ifaces()
        for iface in self._ifaces:
            self.cmb_iface.addItem(iface.label, iface)
        prim = HI.primary_iface()
        if prim is not None:
            for idx, iface in enumerate(self._ifaces):
                if iface.ip == prim.ip:
                    self.cmb_iface.setCurrentIndex(idx)
                    break

    def current_iface(self):
        return self.cmb_iface.currentData()

    # ==================== 起停 ====================

    @safe_slot
    def start_capture(self) -> None:
        if self.monitor is not None and self.monitor.running:
            return
        if not HI.is_admin():
            QMessageBox.warning(self, "需要管理员",
                                "实时抓包要用 Npcap 原始套接字，请以管理员身份重启后再试。\n"
                                "如果只是想分析已有的包，用「打开 pcap 分析」即可。")
            return
        iface = self.current_iface()
        if iface is None:
            QMessageBox.warning(self, "没有网卡", "本机没有可用网卡")
            return
        nets = [iface.cidr] if getattr(iface, "cidr", "") else []
        self.monitor = F.FlowMonitor(iface, self.ed_bpf.text().strip() or "ip",
                                     local_nets=nets)
        try:
            self.monitor.start()
        except Exception as exc:
            self.monitor = None
            QMessageBox.warning(self, "启动失败", str(exc))
            return
        self.offline_table = None
        self._signature = None
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.lbl_state.setText(f"实时：{iface.alias}")
        self.lbl_state.setStyleSheet(f"color:{C_MINT}; font-weight:700;")

    @safe_slot
    def stop_capture(self) -> None:
        if self.monitor is not None:
            self.monitor.stop()
            self.monitor = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.lbl_state.setText("已停止（统计保留）")
        self.lbl_state.setStyleSheet(f"color:{C_YELLOW}; font-weight:700;")
        self.refresh_view(force=True)

    def is_running(self) -> bool:
        return bool(self.monitor is not None and self.monitor.running)

    # ==================== 数据 ====================

    def _table(self):
        if self.monitor is not None:
            return self.monitor.table
        return self.offline_table

    @safe_slot
    def refresh_view(self, force: bool = False) -> None:
        table = self._table()
        if table is None:
            if force:
                self.lbl_stats.setText("包 0 · 流 0 · 0 pps · 0 bps")
            return
        snap = table.snapshot(top=120)
        signature = (snap["packets"], snap["flows_total"], len(snap["flows"]))
        self.lbl_stats.setText(
            f"包 {snap['packets']:,} · 流 {snap['flows_total']:,} · "
            f"{snap['pps']:g} pps · {F.format_rate(snap['bps'])}")
        if not force and signature == self._signature:
            return
        self._signature = signature

        self._fill(self.table_talkers,
                   [[t["host"], t["flows"], t["packets"],
                     F.format_bytes(t["sent"]), F.format_bytes(t["recv"]),
                     F.format_bytes(t["total"])] for t in snap["talkers"]])

        flows = snap["flows"]
        rows = []
        for flow in flows:
            span = max(0.0, flow["last"] - flow["first"])
            rate = flow["bytes"] / span if span > 0.5 else 0.0
            detail = flow["sni"] or flow["host"] or flow["dns"]
            app = flow["app"] or "未知"
            rows.append([f"{app} · {detail}" if detail else app,
                         flow["proto"],
                         f"{flow['src']}:{flow['sport']}",
                         f"{flow['dst']}:{flow['dport']}",
                         flow["packets"], F.format_bytes(flow["bytes"]),
                         F.format_rate(rate), F.format_duration(span),
                         ",".join(flow.get("flags", [])) or "-"])
        self._fill(self.table_flows, rows)

        apps = snap["apps"]
        self._fill(self.table_apps,
                   [[a["app"], a["flows"], a["packets"],
                     F.format_bytes(a["bytes"])] for a in apps])
        self.chart_apps.set_data(
            [(a["app"], a["bytes"] / 1024 / 1024) for a in apps[:8]], unit=" MB")

        self._fill(self.table_dests,
                   [[host, F.format_bytes(size)]
                    for host, size in table.top_destinations(20)])

    @safe_slot
    def clear_stats(self) -> None:
        table = self._table()
        if table is not None:
            table.reset()
        self._signature = None
        for widget in (self.table_talkers, self.table_flows,
                       self.table_apps, self.table_dests):
            widget.setRowCount(0)
        self.chart_apps.set_data([])
        self.lbl_stats.setText("包 0 · 流 0 · 0 pps · 0 bps")

    # ==================== 离线 ====================

    @safe_slot
    def open_pcap(self) -> None:
        if self._task is not None and self._task.isRunning():
            QMessageBox.information(self, "正在分析", "上一个 pcap 还没分析完")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 pcap", "", "抓包文件 (*.pcap *.pcapng *.cap);;所有文件 (*)")
        if not path:
            return
        self.btn_pcap.setEnabled(False)
        self.lbl_state.setText("分析中…")
        self.lbl_state.setStyleSheet(f"color:{C_YELLOW}; font-weight:700;")
        self._task = PcapTask(path, 300000, self)
        self._task.done.connect(self._on_pcap_done)
        self._task.failed.connect(self._on_pcap_failed)
        self._task.finished.connect(lambda: self.btn_pcap.setEnabled(True))
        self._task.start()

    @safe_slot
    def _on_pcap_done(self, table) -> None:
        self.offline_table = table
        self._signature = None
        self.lbl_state.setText("离线分析完成")
        self.lbl_state.setStyleSheet(f"color:{C_MINT}; font-weight:700;")
        self.tabs.setCurrentWidget(self.table_talkers)
        self.refresh_view(force=True)
        QMessageBox.information(
            self, "分析完成",
            f"共 {table.packets:,} 个包，{len(table.flows):,} 条流。\n"
            f"结果已显示在 Top Talkers / Top 会话 / 应用分布里。")

    @safe_slot
    def _on_pcap_failed(self, msg: str) -> None:
        self.lbl_state.setText("分析失败")
        self.lbl_state.setStyleSheet(f"color:{C_RED}; font-weight:700;")
        QMessageBox.warning(self, "分析失败", msg)

    # ==================== 导出 ====================

    @safe_slot
    def export_csv(self) -> None:
        table = self._table()
        if table is None or table.packets == 0:
            QMessageBox.information(self, "没有数据", "先抓包或分析一个 pcap")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出流表", "flows.csv",
                                              "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            rows = table.flow_rows(top=5000)
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                import csv
                writer = csv.writer(fh)
                writer.writerow(FLOW_HEADERS)
                writer.writerows(rows)
            QMessageBox.information(self, "导出成功",
                                    f"已导出 {len(rows)} 条流到：\n{path}")
            log(f"已导出 {len(rows)} 条流到 {path}", "success", "flows")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))

    # ==================== 工具 ====================

    @staticmethod
    def _fill(table, rows: list) -> None:
        table.setSortingEnabled(False)
        table.setRowCount(0)
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            set_row(table, index, row)
        table.setSortingEnabled(True)

    def shutdown(self) -> None:
        """主窗口关闭时调用。"""
        try:
            self.timer.stop()
        except Exception:
            pass
        if self.monitor is not None:
            self.monitor.stop()
            self.monitor = None
        task = self._task
        if task is not None and task.isRunning():
            try:
                task.wait(5000)
            except Exception:
                pass
        self._task = None
