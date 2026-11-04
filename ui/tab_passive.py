# -*- coding: utf-8 -*-
"""
被动资产发现页
==============

只看不发：把网卡上的 ARP / DHCP / mDNS / NBNS / LLDP / CDP 流量收集起来，
还原「这个广播域里到底有什么」。适合不方便主动扫描、或者想抓 ARP 欺骗的场合。

界面约定与其它页一致：

* 顶部先讲清楚「需要管理员 + Npcap，且不会主动发包」；
* 工作线程（AsyncSniffer）只更新核心层的 `PassiveCollector`，
  界面用 QTimer 每秒拉一次快照 —— 工作线程绝不碰 Qt 控件；
* `shutdown()` 会在关窗口时停掉嗅探器。
"""

from __future__ import annotations

import ipaddress

from PyQt5.QtCore import QTimer, pyqtSignal
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFrame,
                             QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                             QPlainTextEdit, QPushButton, QTabWidget,
                             QVBoxLayout, QWidget)

from core import hostinfo as HI
from core import passive as P
from core.logging_bus import log
from theme import C_BLUE, C_MINT, C_PURPLE_DEEP, C_TEXT_DIM, C_YELLOW
from ui.widgets import Card, label, make_table, safe_slot, set_row

HOST_HEADERS = ["IP", "MAC", "厂商", "主机名", "系统", "DHCP 厂商类",
                "来源", "包数", "首次发现", "最后发现"]
LINK_HEADERS = ["本机网卡", "邻居设备", "邻居端口", "管理地址",
                "平台 / 描述", "协议", "最后发现"]
ALERT_HEADERS = ["级别", "类型", "IP", "MAC", "说明", "时间"]
EVENT_HEADERS = ["时间", "类型", "源", "目标", "MAC", "摘要"]

KIND_LABEL = {"arp": "ARP", "dhcp": "DHCP", "mdns": "mDNS",
              "nbns": "NBNS", "lldp": "LLDP", "cdp": "CDP", "ip": "IP"}


class PassiveTab(QWidget):
    """被动资产发现页。"""

    send_to_ports = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.sniffer: P.PassiveSniffer | None = None
        self.collector = P.PassiveCollector()
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
        title = QLabel("🛰 被动发现：只旁路监听，不向网络发任何探测包")
        title.setStyleSheet(f"color:{C_PURPLE_DEEP}; font-weight:800; font-size:10.5pt;")
        lay.addWidget(title)
        desc = QLabel(
            "需要管理员权限 + Npcap（原始收包）。适合观察 ARP 欺骗、IP 冲突、"
            "流氓 DHCP 和交换机邻居；看不到东西通常是因为网卡选错、目标在别的广播域，"
            "或者交换机做了端口隔离。左侧网卡列表来自本机，选接到目标网段的那块。")
        desc.setWordWrap(True)
        desc.setObjectName("Dim")
        lay.addWidget(desc)
        return w

    def _build_control(self) -> QWidget:
        card = Card("🎛 采集设置")

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("网卡", "Dim"))
        self.cmb_iface = QComboBox()
        self.cmb_iface.setMinimumWidth(320)
        self.cmb_iface.currentIndexChanged.connect(self._on_iface_changed)
        r1.addWidget(self.cmb_iface)
        btn_reload = QPushButton("刷新网卡")
        btn_reload.setObjectName("Ghost")
        btn_reload.clicked.connect(self.reload_ifaces)
        r1.addWidget(btn_reload)
        r1.addSpacing(8)
        self.btn_start = QPushButton("▶ 开始监听")
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
        r2.setSpacing(12)
        self.chk_arp = QCheckBox("ARP")
        self.chk_dhcp = QCheckBox("DHCP")
        self.chk_mdns = QCheckBox("mDNS")
        self.chk_nbns = QCheckBox("NBNS")
        self.chk_lldp = QCheckBox("LLDP")
        self.chk_cdp = QCheckBox("CDP")
        for chk in (self.chk_arp, self.chk_dhcp, self.chk_mdns,
                    self.chk_nbns):
            chk.setChecked(True)
        for chk in (self.chk_lldp, self.chk_cdp):
            chk.setChecked(True)
            chk.setToolTip("只有网卡能收到交换机/路由器发出的二层通告时才有数据")
        for chk in (self.chk_arp, self.chk_dhcp, self.chk_mdns,
                    self.chk_nbns, self.chk_lldp, self.chk_cdp):
            r2.addWidget(chk)
        r2.addStretch(1)
        card.add(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(6)
        r3.addWidget(label("受信任 DHCP", "Dim"))
        self.ed_trusted = QLineEdit()
        self.ed_trusted.setPlaceholderText(
            "留空 = 不判断流氓 DHCP；填服务器 IP，多个用逗号分隔")
        self.ed_trusted.setMinimumWidth(260)
        r3.addWidget(self.ed_trusted, 1)
        r3.addSpacing(8)
        r3.addWidget(label("期望网关 MAC", "Dim"))
        self.ed_gw_mac = QLineEdit()
        self.ed_gw_mac.setPlaceholderText("可选，例如 e0:9d:1e:3b:7d:e9")
        self.ed_gw_mac.setMaximumWidth(210)
        r3.addWidget(self.ed_gw_mac)
        card.add(r3)

        r4 = QHBoxLayout()
        r4.setSpacing(8)
        self.lbl_state = label("未开始", "Dim")
        r4.addWidget(self.lbl_state)
        r4.addSpacing(10)
        self.lbl_count = label("资产 0 · 邻居 0 · 告警 0 · 事件 0", "Dim")
        r4.addWidget(self.lbl_count)
        r4.addStretch(1)
        btn_audit = QPushButton("📋 生成审计结论")
        btn_audit.setObjectName("Ghost")
        btn_audit.clicked.connect(self.render_audit)
        r4.addWidget(btn_audit)
        btn_export = QPushButton("导出资产 CSV")
        btn_export.setObjectName("Ghost")
        btn_export.clicked.connect(self.export_csv)
        r4.addWidget(btn_export)
        btn_ports = QPushButton("→ 选中项送入端口扫描")
        btn_ports.setObjectName("Ghost")
        btn_ports.clicked.connect(self._send_ports)
        r4.addWidget(btn_ports)
        btn_clear = QPushButton("清空")
        btn_clear.setObjectName("Ghost")
        btn_clear.clicked.connect(self.clear_all)
        r4.addWidget(btn_clear)
        card.add(r4)
        return card

    def _build_results(self) -> QWidget:
        self.tabs = QTabWidget()

        self.table_hosts = make_table(HOST_HEADERS, stretch_col=None)
        for col, width in ((0, 120), (1, 140), (2, 170), (3, 150),
                           (4, 110), (5, 150), (6, 150), (7, 60),
                           (8, 80), (9, 80)):
            self.table_hosts.setColumnWidth(col, width)
        self.tabs.addTab(self.table_hosts, "🖥 资产表")

        self.table_events = make_table(EVENT_HEADERS, stretch_col=5)
        self.table_events.setColumnWidth(0, 80)
        self.table_events.setColumnWidth(1, 70)
        self.table_events.setColumnWidth(2, 140)
        self.table_events.setColumnWidth(3, 140)
        self.table_events.setColumnWidth(4, 140)
        self.tabs.addTab(self.table_events, "📡 事件流")

        self.table_links = make_table(LINK_HEADERS, stretch_col=4)
        for col, width in ((0, 110), (1, 170), (2, 130), (3, 130), (5, 70)):
            self.table_links.setColumnWidth(col, width)
        self.tabs.addTab(self.table_links, "🔗 拓扑邻居")

        self.table_alerts = make_table(ALERT_HEADERS, stretch_col=4)
        for col, width in ((0, 60), (1, 130), (2, 120), (3, 140), (5, 80)):
            self.table_alerts.setColumnWidth(col, width)
        self.tabs.addTab(self.table_alerts, "⚠ 告警")

        self.txt_audit = QPlainTextEdit()
        self.txt_audit.setReadOnly(True)
        self.txt_audit.setPlaceholderText(
            "点「生成审计结论」后，这里会按严重程度列出发现的问题。")
        self.tabs.addTab(self.txt_audit, "📋 审计结论")
        return self.tabs

    # ==================== 网卡 ====================

    @safe_slot
    def reload_ifaces(self) -> None:
        self.cmb_iface.blockSignals(True)
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
        self.cmb_iface.blockSignals(False)
        self._on_iface_changed()

    def current_iface(self):
        return self.cmb_iface.currentData()

    @safe_slot
    def _on_iface_changed(self, *_args) -> None:
        iface = self.current_iface()
        if iface is not None and iface.gateway:
            self.ed_trusted.setPlaceholderText(
                f"留空 = 不判断；本机网关是 {iface.gateway}，可填入作为受信任服务器")

    # ==================== 起停 ====================

    def _modes(self) -> dict:
        return {"arp": self.chk_arp.isChecked(),
                "dhcp": self.chk_dhcp.isChecked(),
                "mdns": self.chk_mdns.isChecked(),
                "nbns": self.chk_nbns.isChecked(),
                "lldp": self.chk_lldp.isChecked(),
                "cdp": self.chk_cdp.isChecked()}

    @safe_slot
    def start_capture(self) -> None:
        if self.sniffer is not None and self.sniffer.running:
            return
        if not HI.is_admin():
            QMessageBox.warning(
                self, "需要管理员",
                "被动收包要用 Npcap 原始套接字，请用「以管理员身份重启」后再试。")
            return
        iface = self.current_iface()
        if iface is None:
            QMessageBox.warning(self, "没有网卡", "本机没有可用网卡")
            return
        modes = self._modes()
        if not any(modes.values()):
            QMessageBox.warning(self, "没有选协议", "至少勾选一种要监听的协议")
            return

        trusted = self._parse_ips(self.ed_trusted.text())
        self.collector = P.PassiveCollector(
            local_iface=iface.alias,
            trusted_dhcp=trusted,
            gateway_ip=iface.gateway,
            gateway_mac=self.ed_gw_mac.text().strip())
        self.sniffer = P.PassiveSniffer(iface, self.collector,
                                        bpf=P.bpf_for(modes))
        try:
            self.sniffer.start()
        except Exception as exc:
            self.sniffer = None
            QMessageBox.warning(self, "启动失败", str(exc))
            return

        self._signature = None
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.lbl_state.setText(f"监听中：{iface.alias}")
        self.lbl_state.setStyleSheet(f"color:{C_MINT};")
        self.tabs.setCurrentIndex(0)
        log(f"开始被动发现：{iface.alias}（{P.bpf_for(modes)}）", "info", "passive")

    @safe_slot
    def stop_capture(self) -> None:
        if self.sniffer is not None:
            self.sniffer.stop()
            self.sniffer = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.lbl_state.setText("已停止（结果保留）")
        self.lbl_state.setStyleSheet(f"color:{C_YELLOW};")
        self.refresh_view(force=True)

    def is_running(self) -> bool:
        return bool(self.sniffer is not None and self.sniffer.running)

    # ==================== 刷新 ====================

    @safe_slot
    def refresh_view(self, force: bool = False) -> None:
        snap = self.collector.snapshot()
        signature = (snap["host_count"], snap["link_count"],
                     snap["alert_count"], len(snap.get("events", [])),
                     snap["counters"].get("packets", 0))
        self.lbl_count.setText(
            f"资产 {snap['host_count']} · 邻居 {snap['link_count']} · "
            f"告警 {snap['alert_count']} · 事件 {snap['counters']['packets']}")
        if not force and signature == self._signature:
            return
        self._signature = signature

        self._fill(self.table_hosts, [self._host_row(h) for h in snap["hosts"]])
        self._fill(self.table_events,
                   [[e["time"], KIND_LABEL.get(e["kind"], e["kind"]),
                     e["src"] or "-", e["dst"] or "-", e["mac"] or "-",
                     e["info"]] for e in reversed(snap.get("events", []))])
        self._fill(self.table_links,
                   [[ln["local"], ln["remote"], ln["remote_port"],
                     ln["mgmt_ip"], ln["platform"], ln["source"],
                     ln["last_seen"]] for ln in snap["links"]])
        alert_rows = []
        for alert in snap["alerts"]:
            alert_rows.append([P.SEVERITY_LABEL.get(alert["severity"],
                                                     alert["severity"]),
                               alert["kind"], alert["ip"] or "-",
                               alert["mac"] or "-", alert["detail"],
                               alert["at"]])
        self._fill(self.table_alerts, alert_rows)

    @staticmethod
    def _host_row(host: dict) -> list:
        return [host["ip"], host["mac"] or "-", host["vendor"] or "-",
                host["hostname"] or "-", host["os_guess"] or "-",
                host["dhcp_vendor"] or "-",
                " / ".join(host.get("sources", [])) or "-",
                host["packets"], host["first_seen"], host["last_seen"]]

    @staticmethod
    def _fill(table, rows: list) -> None:
        table.setSortingEnabled(False)
        table.setRowCount(0)
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            set_row(table, index, row)
        table.setSortingEnabled(True)

    # ==================== 审计 / 导出 ====================

    @safe_slot
    def render_audit(self) -> None:
        snap = self.collector.snapshot()
        findings = self.collector.audit()
        lines = [
            "被动资产发现 · 审计结论",
            "=" * 30,
            f"资产 {snap['host_count']} 台 / 拓扑邻居 {snap['link_count']} 条 / "
            f"告警 {snap['alert_count']} 条 / 观察 {snap['uptime']:.0f} 秒",
            "",
        ]
        if not snap["host_count"] and not snap["alert_count"]:
            lines.append("还没有采集到数据。先确认网卡是否正确、目标是否在同一广播域，"
                         "以及是否有设备在发包。")
        elif not findings:
            lines.append("未发现明显问题。")
        for finding in findings:
            lines.append(f"[{P.SEVERITY_LABEL.get(finding['severity'], finding['severity'])}] "
                         f"{finding['title']}")
            lines.append(f"    {finding['detail']}")
            if finding.get("items"):
                lines.append(f"    {'、'.join(finding['items'][:12])}")
            lines.append("")
        if snap["alerts"]:
            lines.append("-" * 30)
            lines.append("最近告警：")
            for alert in snap["alerts"][:30]:
                lines.append(f"  {alert['at']}  {alert['detail']}")
        self.txt_audit.setPlainText("\n".join(lines))
        self.tabs.setCurrentWidget(self.txt_audit)
        log(f"审计完成：{len(findings)} 条结论", "success", "passive")

    @safe_slot
    def export_csv(self) -> None:
        snap = self.collector.snapshot()
        if not snap["hosts"]:
            QMessageBox.information(self, "没有数据", "先采集到资产再导出")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出被动资产",
                                              "passive_assets.csv",
                                              "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            count = P.export_csv(path, snap["hosts"])
            log(f"已导出 {count} 条被动资产到 {path}", "success", "passive")
            QMessageBox.information(self, "导出成功", f"已导出 {count} 条到：\n{path}")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))

    @safe_slot
    def _send_ports(self) -> None:
        rows = sorted({i.row() for i in self.table_hosts.selectionModel().selectedRows()})
        if not rows:
            rows = list(range(self.table_hosts.rowCount()))
        ips = []
        for row in rows:
            item = self.table_hosts.item(row, 0)
            if item is not None and item.text():
                ips.append(item.text())
        if ips:
            self.send_to_ports.emit(ips)

    @safe_slot
    def clear_all(self) -> None:
        if self.is_running():
            self.stop_capture()
        self.collector.reset()
        self._signature = None
        for table in (self.table_hosts, self.table_events,
                      self.table_links, self.table_alerts):
            table.setRowCount(0)
        self.txt_audit.clear()
        self.lbl_count.setText("资产 0 · 邻居 0 · 告警 0 · 事件 0")
        self.lbl_state.setText("已清空")
        self.lbl_state.setStyleSheet(f"color:{C_TEXT_DIM};")

    # ==================== 收尾 ====================

    @staticmethod
    def _parse_ips(text: str) -> list[str]:
        out = []
        for token in text.replace("，", ",").replace(";", ",").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                ipaddress.ip_address(token)
                out.append(token)
            except ValueError:
                continue
        return out

    def shutdown(self) -> None:
        """主窗口关闭时调用。"""
        try:
            self.timer.stop()
        except Exception:
            pass
        if self.sniffer is not None:
            self.sniffer.stop()
            self.sniffer = None
