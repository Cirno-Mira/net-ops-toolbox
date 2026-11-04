# -*- coding: utf-8 -*-
"""
资产变更监控页
==============

把「定期采样 → 存快照 → 和上一份对比」做成一个可长期挂着的页面。
数据源有三种，分别复用已有的核心模块：

* 主动扫描  → `core.assets.discover`
* 被动发现  → `core.passive.PassiveCollector`
* SNMP      → `core.snmp.interfaces`

快照存在 `netops_history.db`（SQLite），随时可以翻历史、设基线、导出 JSON。
采样在普通后台线程里跑，界面用 QTimer 只读状态和差异 —— 工作线程不碰 Qt。
"""

from __future__ import annotations

from PyQt5.QtCore import QThread, QTimer, pyqtSignal
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFrame,
                             QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                             QPushButton, QSpinBox, QStackedWidget, QTabWidget,
                             QVBoxLayout, QWidget)

from core import hostinfo as HI
from core import monitor as M
from core import store as ST
from core.logging_bus import log
from theme import (C_BLUE, C_MINT, C_PINK, C_PURPLE_DEEP, C_RED,
                   C_TEXT_DIM, C_YELLOW)
from ui.widgets import Card, label, make_table, safe_slot, set_row

DIFF_HEADERS = ["类型", "主键", "字段", "旧值", "新值"]
HISTORY_HEADERS = ["ID", "类型", "标签", "时间", "行数", "校验"]
SAMPLE_HEADERS = ["时间", "快照 #", "行数", "变化数"]

SOURCE_ITEMS = [("主动扫描（ARP / Ping）", "assets"),
                ("被动发现（旁路监听）", "passive"),
                ("SNMP 接口表", "snmp")]


class SampleTask(QThread):
    """在后台跑一次 `MonitorSession.tick()`，避免卡住界面。"""

    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn())
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class MonitorTab(QWidget):
    """资产变更监控页。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.session: M.MonitorSession | None = None
        self.store = ST.SnapshotStore()
        self.passive_provider = None
        self._baseline: ST.Snapshot | None = None
        self._shown_diff = None
        self._task: SampleTask | None = None
        self._last_history_at = 0.0
        self._ifaces: list = []
        self._build()

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh_status)
        self.timer.start()

    # ==================== 界面 ====================

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)
        outer.addWidget(self._build_banner())
        outer.addWidget(self._build_control())
        outer.addWidget(self._build_status())
        outer.addWidget(self._build_results(), 1)
        self.refresh_history()

    def _build_banner(self) -> QWidget:
        w = QFrame()
        w.setObjectName("Card")
        w.setStyleSheet("QFrame#Card { background-color:#E8F3FF;"
                        f" border:1px solid {C_BLUE}; border-radius:14px; }}")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(3)
        title = QLabel("🛰 定期采样，只记录「变了什么」：新设备、消失的设备、改过的 MAC / 端口")
        title.setStyleSheet(f"color:{C_PURPLE_DEEP}; font-weight:800; font-size:10.5pt;")
        lay.addWidget(title)
        desc = QLabel(
            "快照存在本机 netops_history.db，不上传。主动扫描模式会按间隔真实发包；"
            "被动模式直接读取「被动资产发现」页正在采集的数据（请先在那里开始监听）；"
            "SNMP 模式读取设备接口表。默认忽略 last_seen / 包数这类每轮都会变的值。")
        desc.setWordWrap(True)
        desc.setObjectName("Dim")
        lay.addWidget(desc)
        return w

    def _build_control(self) -> QWidget:
        card = Card("🎛 监控设置")

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("数据源", "Dim"))
        self.cmb_source = QComboBox()
        for text, data in SOURCE_ITEMS:
            self.cmb_source.addItem(text, data)
        self.cmb_source.currentIndexChanged.connect(self._on_source_changed)
        r1.addWidget(self.cmb_source)
        r1.addSpacing(10)
        r1.addWidget(label("采样间隔", "Dim"))
        self.sp_interval = QSpinBox()
        self.sp_interval.setRange(5, 3600)
        self.sp_interval.setValue(60)
        self.sp_interval.setSingleStep(10)
        self.sp_interval.setSuffix(" 秒")
        r1.addWidget(self.sp_interval)
        r1.addStretch(1)
        self.lbl_baseline = label("基线：未设置", "Dim")
        r1.addWidget(self.lbl_baseline)
        card.add(r1)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_assets_page())
        self.stack.addWidget(self._build_passive_page())
        self.stack.addWidget(self._build_snmp_page())
        card.add(self.stack)

        r2 = QHBoxLayout()
        r2.setSpacing(8)
        self.btn_start = QPushButton("▶ 开始监控")
        self.btn_start.setObjectName("Primary")
        self.btn_start.clicked.connect(self.start_monitor)
        r2.addWidget(self.btn_start)
        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_monitor)
        r2.addWidget(self.btn_stop)
        self.btn_sample = QPushButton("⏱ 立即采样一次")
        self.btn_sample.setObjectName("Ghost")
        self.btn_sample.clicked.connect(self.sample_now)
        r2.addWidget(self.btn_sample)
        r2.addStretch(1)
        card.add(r2)
        return card

    def _build_assets_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 4, 0, 0)
        lay.setSpacing(6)

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
        r1.addWidget(label("目标", "Dim"))
        self.ed_target = QLineEdit()
        self.ed_target.setPlaceholderText("留空 = 当前网段；支持 192.168.1.0/24、区间、多段")
        r1.addWidget(self.ed_target, 1)
        lay.addLayout(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(12)
        self.chk_arp = QCheckBox("ARP 扫描")
        self.chk_arp.setChecked(True)
        self.chk_ping = QCheckBox("Ping 扫描")
        self.chk_ping.setChecked(True)
        self.chk_cache = QCheckBox("合并本机 ARP 缓存")
        self.chk_cache.setChecked(True)
        self.chk_names = QCheckBox("解析主机名")
        self.chk_names.setChecked(True)
        self.chk_vendor = QCheckBox("识别厂商")
        self.chk_vendor.setChecked(True)
        for chk in (self.chk_arp, self.chk_ping, self.chk_cache,
                    self.chk_names, self.chk_vendor):
            r2.addWidget(chk)
        r2.addStretch(1)
        lay.addLayout(r2)
        self.reload_ifaces()
        return page

    def _build_passive_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 4, 0, 0)
        lay.setSpacing(4)
        tip = QLabel(
            "直接读取「🛰 被动发现」页当前采集到的资产。请先到那一页选网卡并点开始监听；"
            "这里不会额外发任何包。如果那一页还没开始，采样会得到 0 行。")
        tip.setWordWrap(True)
        tip.setObjectName("Dim")
        lay.addWidget(tip)
        return page

    def _build_snmp_page(self) -> QWidget:
        page = QWidget()
        lay = QHBoxLayout(page)
        lay.setContentsMargins(0, 4, 0, 0)
        lay.setSpacing(6)
        lay.addWidget(label("设备", "Dim"))
        self.ed_host = QLineEdit()
        self.ed_host.setPlaceholderText("交换机 / 路由器 IP")
        self.ed_host.setMinimumWidth(190)
        lay.addWidget(self.ed_host)
        lay.addWidget(label("团体名", "Dim"))
        self.ed_community = QLineEdit("public")
        self.ed_community.setMaximumWidth(130)
        lay.addWidget(self.ed_community)
        lay.addWidget(label("版本", "Dim"))
        self.cmb_version = QComboBox()
        self.cmb_version.addItem("v2c", 2)
        self.cmb_version.addItem("v1", 1)
        lay.addWidget(self.cmb_version)
        lay.addWidget(label("端口", "Dim"))
        self.sp_port = QSpinBox()
        self.sp_port.setRange(1, 65535)
        self.sp_port.setValue(161)
        lay.addWidget(self.sp_port)
        lay.addStretch(1)
        return page

    def _build_status(self) -> QWidget:
        card = Card("📈 运行状态")
        row = QHBoxLayout()
        row.setSpacing(16)
        self.lbl_state = label("未开始", "Dim")
        self.lbl_state.setStyleSheet(f"color:{C_TEXT_DIM}; font-weight:700;")
        row.addWidget(self.lbl_state)
        self.lbl_samples = label("采样 0 次", "Dim")
        row.addWidget(self.lbl_samples)
        self.lbl_last = label("上次：-", "Dim")
        row.addWidget(self.lbl_last)
        self.lbl_next = label("下次：-", "Dim")
        row.addWidget(self.lbl_next)
        self.lbl_changes = label("变化：-", "Dim")
        row.addWidget(self.lbl_changes)
        row.addStretch(1)
        card.add(row)
        return card

    def _build_results(self) -> QWidget:
        self.tabs = QTabWidget()

        self.table_diff = make_table(DIFF_HEADERS, stretch_col=4)
        for col, width in ((0, 60), (1, 130), (2, 120), (3, 190)):
            self.table_diff.setColumnWidth(col, width)
        self.tabs.addTab(self.table_diff, "🔀 本次变化")

        page_history = QWidget()
        hl = QVBoxLayout(page_history)
        hl.setContentsMargins(0, 6, 0, 0)
        hl.setSpacing(6)
        bar = QHBoxLayout()
        bar.setSpacing(6)
        bar.addWidget(label("类型", "Dim"))
        self.cmb_kind = QComboBox()
        self.cmb_kind.addItem("全部", "")
        for kind, spec in ST.KINDS.items():
            self.cmb_kind.addItem(spec["label"], kind)
        self.cmb_kind.currentIndexChanged.connect(self.refresh_history)
        bar.addWidget(self.cmb_kind)
        bar.addStretch(1)
        btn_load = QPushButton("设为基线")
        btn_load.setObjectName("Ghost")
        btn_load.clicked.connect(self.set_baseline)
        bar.addWidget(btn_load)
        btn_compare = QPushButton("与最新快照对比")
        btn_compare.setObjectName("Ghost")
        btn_compare.clicked.connect(self.compare_history)
        bar.addWidget(btn_compare)
        btn_export = QPushButton("导出 JSON")
        btn_export.setObjectName("Ghost")
        btn_export.clicked.connect(self.export_history)
        bar.addWidget(btn_export)
        btn_delete = QPushButton("删除选中")
        btn_delete.setObjectName("Danger")
        btn_delete.clicked.connect(self.delete_history)
        bar.addWidget(btn_delete)
        hl.addLayout(bar)

        self.table_history = make_table(HISTORY_HEADERS, stretch_col=2)
        for col, width in ((0, 60), (1, 130), (3, 150), (4, 70), (5, 90)):
            self.table_history.setColumnWidth(col, width)
        hl.addWidget(self.table_history, 1)
        self.tabs.addTab(page_history, "🗂 历史快照")

        self.table_samples = make_table(SAMPLE_HEADERS, stretch_col=None)
        for col, width in ((0, 150), (1, 80), (2, 80), (3, 80)):
            self.table_samples.setColumnWidth(col, width)
        self.tabs.addTab(self.table_samples, "⏱ 采样记录")
        return self.tabs

    # ==================== 数据源 ====================

    @safe_slot
    def _on_source_changed(self, index: int) -> None:
        self.stack.setCurrentIndex(max(0, min(index, self.stack.count() - 1)))

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

    def _build_source(self):
        """按当前选中的数据源返回 (kind, source, label)，失败返回 None。"""
        kind = self.cmb_source.currentData()
        if kind == "assets":
            iface = self.current_iface()
            if iface is None:
                QMessageBox.warning(self, "没有网卡", "本机没有可用网卡")
                return None
            text = self.ed_target.text().strip() or iface.cidr
            hosts = HI.expand_targets(text)
            if not hosts:
                QMessageBox.warning(self, "目标无效", f"无法解析目标：{text}")
                return None
            if len(hosts) > HI.MAX_HOSTS:
                hosts = hosts[:HI.MAX_HOSTS]
            if not (self.chk_arp.isChecked() or self.chk_ping.isChecked()
                    or self.chk_cache.isChecked()):
                QMessageBox.warning(self, "没有探测方式",
                                    "至少勾选 ARP、Ping 或 ARP 缓存之一")
                return None
            if self.chk_arp.isChecked() and not HI.is_admin():
                QMessageBox.warning(self, "需要管理员",
                                    "ARP 扫描需要管理员权限；可改用 Ping + 缓存，"
                                    "或以管理员身份重启。")
                return None
            source = M.make_assets_source(
                hosts, iface, use_arp=self.chk_arp.isChecked(),
                use_ping=self.chk_ping.isChecked(),
                use_cache=self.chk_cache.isChecked(),
                resolve_names=self.chk_names.isChecked(),
                lookup_vendor=self.chk_vendor.isChecked())
            return kind, source, f"主动扫描 {len(hosts)} 个目标"

        if kind == "passive":
            provider = self.passive_provider
            collector = provider() if callable(provider) else provider
            if collector is None:
                QMessageBox.warning(self, "被动发现未启动",
                                    "请先到「🛰 被动发现」页选好网卡并点「开始监听」。")
                return None
            return kind, M.make_passive_source(collector), "被动发现资产"

        host = self.ed_host.text().strip()
        if not host:
            QMessageBox.warning(self, "缺少设备", "请填写 SNMP 设备 IP")
            return None
        community = self.ed_community.text().strip()
        if not community:
            QMessageBox.warning(self, "缺少团体名", "SNMP v1/v2c 需要团体名")
            return None
        source = M.make_snmp_source(host, community,
                                    int(self.cmb_version.currentData() or 2),
                                    int(self.sp_port.value()))
        return kind, source, f"SNMP 接口表 {host}"

    # ==================== 起停 ====================

    @safe_slot
    def start_monitor(self) -> None:
        if self.session is not None and self.session.is_running():
            return
        built = self._build_source()
        if built is None:
            return
        kind, source, label = built
        self._stop_session()
        self.session = M.MonitorSession(
            self.store, kind, source, label=label,
            interval=float(self.sp_interval.value()),
            baseline_id=(self._baseline.id if self._baseline else 0))
        self._shown_diff = None
        if not self.session.start(immediate=True):
            QMessageBox.warning(self, "启动失败", "监控没有启动，请检查快照库与参数")
            self.session = None
            return
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_sample.setEnabled(False)
        self.lbl_state.setText(f"运行中：{label}")
        self.lbl_state.setStyleSheet(f"color:{C_MINT}; font-weight:700;")
        log(f"开始变更监控：{label}，每 {M.human_interval(self.sp_interval.value())}",
            "info", "monitor")

    @safe_slot
    def stop_monitor(self) -> None:
        self._stop_session()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_sample.setEnabled(True)
        self.lbl_state.setText("已停止")
        self.lbl_state.setStyleSheet(f"color:{C_YELLOW}; font-weight:700;")
        self.lbl_next.setText("下次：-")
        self.refresh_status(force=True)

    def _stop_session(self) -> None:
        if self.session is not None and self.session.is_running():
            self.session.stop()
        self.session = None

    def is_running(self) -> bool:
        return bool(self.session is not None and self.session.is_running())

    # ==================== 采样 ====================

    @safe_slot
    def sample_now(self) -> None:
        if self.is_running():
            QMessageBox.information(self, "正在监控", "监控运行中会按间隔自动采样，无需手动触发")
            return
        if self._task is not None and self._task.isRunning():
            return
        built = self._build_source()
        if built is None:
            return
        kind, source, label = built
        session = M.MonitorSession(
            self.store, kind, source, label=label,
            interval=float(self.sp_interval.value()),
            baseline_id=(self._baseline.id if self._baseline else 0))
        self.session = session
        self.btn_sample.setEnabled(False)
        self.lbl_state.setText(f"采样中：{label}")
        self.lbl_state.setStyleSheet(f"color:{C_YELLOW}; font-weight:700;")
        self._task = SampleTask(session.tick, self)
        self._task.done.connect(self._on_sample_done)
        self._task.failed.connect(self._on_sample_failed)
        self._task.finished.connect(lambda: self.btn_sample.setEnabled(True))
        self._task.start()

    @safe_slot
    def _on_sample_done(self, diff) -> None:
        self.lbl_state.setText("采样完成")
        self.lbl_state.setStyleSheet(f"color:{C_MINT}; font-weight:700;")
        self.refresh_status(force=True)
        self.refresh_history()
        if diff is None:
            QMessageBox.warning(self, "采样失败", "没有拿到数据，详见日志")

    @safe_slot
    def _on_sample_failed(self, msg: str) -> None:
        self.lbl_state.setText("采样失败")
        self.lbl_state.setStyleSheet(f"color:{C_RED}; font-weight:700;")
        QMessageBox.warning(self, "采样失败", msg)

    # ==================== 刷新 ====================

    @safe_slot
    def refresh_status(self, force: bool = False) -> None:
        session = self.session
        if session is None:
            if force:
                self.lbl_samples.setText("采样 0 次")
                self.lbl_last.setText("上次：-")
                self.table_samples.setRowCount(0)
            return
        status = session.status()
        self.lbl_state.setText(("运行中：" if status.running else "已停止：")
                               + status.label)
        self.lbl_state.setStyleSheet(
            f"color:{C_MINT if status.running else C_YELLOW}; font-weight:700;")
        self.lbl_samples.setText(f"采样 {status.samples} 次"
                                 + (f" · 失败 {status.errors}" if status.errors else ""))
        self.lbl_last.setText(f"上次：{status.last_at or '-'}"
                              f"（{status.last_rows} 行）")
        self.lbl_next.setText(f"下次：{status.next_at or '-'}")
        if status.last_error:
            self.lbl_last.setToolTip(status.last_error)

        rows = [[s.at, s.snapshot_id, s.rows,
                 s.changes if s.changes else "-"] for s in reversed(status.history)]
        self._fill(self.table_samples, rows)

        diff = session.last_diff
        if diff is not None and diff is not self._shown_diff:
            self._shown_diff = diff
            self._show_diff(diff)
            self.refresh_history()

    @safe_slot
    def refresh_history(self, *_args) -> None:
        kind = self.cmb_kind.currentData() or ""
        items = self.store.list(kind or None, limit=300)
        rows = [[item["id"], ST.KINDS.get(item["kind"], {}).get("label", item["kind"]),
                 item["label"], item["created_at"], item["row_count"],
                 item["checksum"][:8]] for item in items]
        self._fill(self.table_history, rows)

    def _show_diff(self, diff: ST.DiffResult) -> None:
        self._fill(self.table_diff, diff.rows())
        counts = diff.counts()
        self.lbl_changes.setText(
            f"变化：新增 {counts['added']} / 消失 {counts['removed']} / "
            f"修改 {counts['changed']} / 未变 {counts['unchanged']}")
        if diff.total_changes:
            self.lbl_changes.setStyleSheet(f"color:{C_PINK}; font-weight:700;")
            self.tabs.setCurrentWidget(self.table_diff)
        else:
            self.lbl_changes.setStyleSheet(f"color:{C_MINT}; font-weight:700;")

    @staticmethod
    def _fill(table, rows: list) -> None:
        table.setSortingEnabled(False)
        table.setRowCount(0)
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            colors = {}
            if row and row[0] in ("新增",):
                colors[0] = C_MINT
            elif row and row[0] in ("消失",):
                colors[0] = C_RED
            elif row and row[0] in ("变化",):
                colors[0] = C_YELLOW
            set_row(table, index, row, colors)
        table.setSortingEnabled(True)

    # ==================== 历史操作 ====================

    def _selected_snapshot(self) -> ST.Snapshot | None:
        rows = sorted({i.row() for i in self.table_history.selectionModel().selectedRows()})
        if not rows:
            QMessageBox.information(self, "没有选中", "先在历史列表里选一份快照")
            return None
        item = self.table_history.item(rows[0], 0)
        if item is None:
            return None
        try:
            return self.store.load(int(item.text()))
        except (TypeError, ValueError):
            return None

    @safe_slot
    def set_baseline(self) -> None:
        snap = self._selected_snapshot()
        if snap is None:
            return
        self._baseline = snap
        self.lbl_baseline.setText(f"基线：#{snap.id} {snap.created_at}")
        if self.session is not None:
            self.session.set_baseline(snap.id)
        log(f"已把快照 #{snap.id} 设为对比基线", "info", "monitor")

    @safe_slot
    def compare_history(self) -> None:
        snap = self._selected_snapshot()
        if snap is None:
            return
        latest = self.store.latest(snap.kind)
        if latest is None:
            QMessageBox.information(self, "没有数据", "这个类型还没有其它快照")
            return
        if latest.id == snap.id:
            QMessageBox.information(self, "只有一份快照", "选中项已经是最新快照，无法对比")
            return
        spec = ST.KINDS.get(snap.kind, {})
        diff = ST.diff_rows(snap.rows, latest.rows,
                            key_field=spec.get("key", "ip"),
                            ignore_fields=spec.get("ignore", ()))
        diff.old_label = f"#{snap.id} {snap.created_at}"
        diff.new_label = f"#{latest.id} {latest.created_at}"
        self._shown_diff = diff
        self._show_diff(diff)
        log(f"历史对比：{diff.summary()}", "info", "monitor")

    @safe_slot
    def export_history(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "导出快照",
                                              "netops_snapshots.json",
                                              "JSON 文件 (*.json)")
        if not path:
            return
        snap = None
        rows = sorted({i.row() for i in self.table_history.selectionModel().selectedRows()})
        if rows:
            item = self.table_history.item(rows[0], 0)
            if item is not None:
                try:
                    snap = int(item.text())
                except ValueError:
                    snap = None
        try:
            count = self.store.export_json(path, snap)
            QMessageBox.information(self, "导出成功",
                                    f"已导出 {count} 份快照到：\n{path}")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))

    @safe_slot
    def delete_history(self) -> None:
        snap = self._selected_snapshot()
        if snap is None:
            return
        if QMessageBox.question(self, "删除快照",
                                f"确定删除快照 #{snap.id}（{snap.created_at}）？") \
                != QMessageBox.Yes:
            return
        self.store.delete(snap.id)
        if self._baseline is not None and self._baseline.id == snap.id:
            self._baseline = None
            self.lbl_baseline.setText("基线：未设置")
        self.refresh_history()

    # ==================== 收尾 ====================

    def shutdown(self) -> None:
        """主窗口关闭时调用：停采样、等任务、关数据库。"""
        try:
            self.timer.stop()
        except Exception:
            pass
        self._stop_session()
        task = self._task
        if task is not None and task.isRunning():
            try:
                task.wait(5000)
            except Exception:
                pass
        self._task = None
        self.store.close()
