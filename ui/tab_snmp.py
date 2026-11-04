# -*- coding: utf-8 -*-
"""
SNMP 设备信息页
===============

手写 BER 的 SNMP v1 / v2c 客户端（见 `core/snmp.py`），不依赖 pysnmp。

四类读取：

* 系统概况：型号、固件、名称、位置、运行时长
* 接口表：up/down、速率、MAC
* ARP 表：设备眼里的 IP↔MAC（很好用，能直接看出谁在网关后面）
* LLDP 邻居：交换机之间的连线关系

另外留了一个「原始 OID」子页，方便查任意标量；以及一个需要显式授权
才能用的「写入 sysName / sysLocation」，用来验证设备是否存在弱配置。
"""

from __future__ import annotations

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (QCheckBox, QComboBox, QDoubleSpinBox, QFrame,
                             QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                             QPlainTextEdit, QPushButton, QSpinBox, QTabWidget,
                             QVBoxLayout, QWidget)

from core import snmp as SN
from core.logging_bus import log
from theme import C_BLUE, C_MINT, C_PURPLE_DEEP, C_RED, C_TEXT_DIM, C_YELLOW
from ui.widgets import Card, label, make_table, safe_slot, set_row

IF_HEADERS = ["索引", "接口名", "类型", "速率", "MAC", "管理状态", "运行状态"]
ARP_HEADERS = ["IP", "MAC", "接口索引", "类型"]
LLDP_HEADERS = ["索引", "系统名", "端口", "端口描述", "平台 / 描述"]
OID_HEADERS = ["OID", "名称", "类型", "值"]


class SnmpTask(QThread):
    """把一次可能阻塞的 SNMP 查询放到后台线程。"""

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


class SnmpTab(QWidget):
    """SNMP 设备信息页。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: SnmpTask | None = None
        self._last_info: dict = {}
        self._last_ifaces: list = []
        self._build()

    # ==================== 界面 ====================

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)
        outer.addWidget(self._build_banner())
        outer.addWidget(self._build_control())
        outer.addWidget(self._build_results(), 1)

    def _build_banner(self) -> QWidget:
        w = QFrame()
        w.setObjectName("Card")
        w.setStyleSheet("QFrame#Card { background-color:#E8F3FF;"
                        f" border:1px solid {C_BLUE}; border-radius:14px; }}")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(3)
        title = QLabel("🛰 只做客户端查询：不监听 161，也不改设备配置（写入需单独授权）")
        title.setStyleSheet(f"color:{C_PURPLE_DEEP}; font-weight:800; font-size:10.5pt;")
        lay.addWidget(title)
        desc = QLabel(
            "SNMP v1/v2c 明文传输、默认团体名（public/private）仍然很常见。"
            "本页默认只读；要判断设备是否存在弱配置，用「安全结论」即可，"
            "不需要真的去改。v3 的 USM 认证加密本工具不支持。")
        desc.setWordWrap(True)
        desc.setObjectName("Dim")
        lay.addWidget(desc)
        return w

    def _build_control(self) -> QWidget:
        card = Card("🎯 设备与凭据")

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("目标", "Dim"))
        self.ed_host = QLineEdit()
        self.ed_host.setPlaceholderText("交换机 / 路由器 / 打印机的 IP，例如 192.168.1.1")
        self.ed_host.setMinimumWidth(210)
        r1.addWidget(self.ed_host)
        r1.addWidget(label("团体名", "Dim"))
        self.ed_community = QLineEdit("public")
        self.ed_community.setMaximumWidth(130)
        r1.addWidget(self.ed_community)
        r1.addWidget(label("版本", "Dim"))
        self.cmb_version = QComboBox()
        self.cmb_version.addItem("v2c", 2)
        self.cmb_version.addItem("v1", 1)
        r1.addWidget(self.cmb_version)
        r1.addWidget(label("端口", "Dim"))
        self.sp_port = QSpinBox()
        self.sp_port.setRange(1, 65535)
        self.sp_port.setValue(161)
        r1.addWidget(self.sp_port)
        r1.addWidget(label("超时", "Dim"))
        self.sp_timeout = QDoubleSpinBox()
        self.sp_timeout.setRange(0.3, 10.0)
        self.sp_timeout.setSingleStep(0.5)
        self.sp_timeout.setValue(1.5)
        self.sp_timeout.setSuffix(" 秒")
        r1.addWidget(self.sp_timeout)
        r1.addWidget(label("重试", "Dim"))
        self.sp_retries = QSpinBox()
        self.sp_retries.setRange(0, 3)
        self.sp_retries.setValue(1)
        r1.addWidget(self.sp_retries)
        r1.addStretch(1)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(8)
        self.btn_info = QPushButton("📋 读取系统信息")
        self.btn_info.setObjectName("Primary")
        self.btn_info.clicked.connect(self.read_info)
        r2.addWidget(self.btn_info)
        self.btn_ifaces = QPushButton("🔌 读取接口表")
        self.btn_ifaces.setObjectName("Ghost")
        self.btn_ifaces.clicked.connect(self.read_ifaces)
        r2.addWidget(self.btn_ifaces)
        self.btn_arp = QPushButton("📇 读取 ARP 表")
        self.btn_arp.setObjectName("Ghost")
        self.btn_arp.clicked.connect(self.read_arp)
        r2.addWidget(self.btn_arp)
        self.btn_lldp = QPushButton("🔗 读取 LLDP 邻居")
        self.btn_lldp.setObjectName("Ghost")
        self.btn_lldp.clicked.connect(self.read_lldp)
        r2.addWidget(self.btn_lldp)
        self.btn_probe = QPushButton("🔑 探测常见团体名")
        self.btn_probe.setObjectName("Ghost")
        self.btn_probe.clicked.connect(self.probe_communities)
        r2.addWidget(self.btn_probe)
        r2.addStretch(1)
        self.lbl_state = label("就绪", "Dim")
        r2.addWidget(self.lbl_state)
        card.add(r2)
        return card

    def _build_results(self) -> QWidget:
        self.tabs = QTabWidget()

        self.txt_info = QPlainTextEdit()
        self.txt_info.setReadOnly(True)
        self.txt_info.setPlaceholderText(
            "填目标与团体名，点「读取系统信息」。\n"
            "读完后这里会显示型号、固件、运行时长，以及一段安全结论。")
        self.tabs.addTab(self.txt_info, "📋 系统概况")

        self.table_ifaces = make_table(IF_HEADERS, stretch_col=1)
        for col, width in ((0, 60), (2, 130), (3, 100), (4, 150), (5, 90), (6, 90)):
            self.table_ifaces.setColumnWidth(col, width)
        self.tabs.addTab(self.table_ifaces, "🔌 接口表")

        self.table_arp = make_table(ARP_HEADERS, stretch_col=1)
        for col, width in ((0, 140), (2, 90), (3, 90)):
            self.table_arp.setColumnWidth(col, width)
        self.tabs.addTab(self.table_arp, "📇 ARP 表")

        self.table_lldp = make_table(LLDP_HEADERS, stretch_col=4)
        for col, width in ((0, 90), (1, 170), (2, 130), (3, 160)):
            self.table_lldp.setColumnWidth(col, width)
        self.tabs.addTab(self.table_lldp, "🔗 LLDP 邻居")

        self.tabs.addTab(self._build_oid_page(), "🔧 原始 OID")
        self.tabs.addTab(self._build_write_page(), "✏ 写入（需授权）")
        return self.tabs

    def _build_oid_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 8, 0, 0)
        lay.setSpacing(6)

        row = QHBoxLayout()
        row.setSpacing(6)
        row.addWidget(label("OID", "Dim"))
        self.ed_oid = QLineEdit("1.3.6.1.2.1.1.1.0,1.3.6.1.2.1.1.3.0,1.3.6.1.2.1.1.5.0")
        self.ed_oid.setPlaceholderText("多个 OID 用逗号分隔，最多 32 个")
        row.addWidget(self.ed_oid, 1)
        self.btn_oid = QPushButton("GET")
        self.btn_oid.setObjectName("Primary")
        self.btn_oid.clicked.connect(self.read_oid)
        row.addWidget(self.btn_oid)
        lay.addLayout(row)

        self.table_oid = make_table(OID_HEADERS, stretch_col=1)
        self.table_oid.setColumnWidth(0, 240)
        self.table_oid.setColumnWidth(2, 90)
        lay.addWidget(self.table_oid, 1)
        return page

    def _build_write_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 8, 0, 0)
        lay.setSpacing(8)

        warn = QLabel(
            "写入会真的改设备配置。只建议在实验设备上验证 sysName / sysLocation "
            "是否可写；生产设备改错可能导致监控系统认不出资产。")
        warn.setWordWrap(True)
        warn.setStyleSheet(f"color:{C_RED}; font-weight:700;")
        lay.addWidget(warn)

        self.chk_write_auth = QCheckBox("我确认这是实验设备或已获授权，并知道怎么改回来")
        lay.addWidget(self.chk_write_auth)

        row1 = QHBoxLayout()
        row1.setSpacing(6)
        row1.addWidget(label("sysName", "Dim"))
        self.ed_sysname = QLineEdit()
        self.ed_sysname.setPlaceholderText("留空 = 不修改")
        row1.addWidget(self.ed_sysname, 1)
        lay.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(6)
        row2.addWidget(label("sysLocation", "Dim"))
        self.ed_syslocation = QLineEdit()
        self.ed_syslocation.setPlaceholderText("留空 = 不修改")
        row2.addWidget(self.ed_syslocation, 1)
        self.btn_write = QPushButton("写入")
        self.btn_write.setObjectName("Danger")
        self.btn_write.clicked.connect(self.write_values)
        row2.addWidget(self.btn_write)
        lay.addLayout(row2)

        lay.addStretch(1)
        return page

    # ==================== 参数 ====================

    def _params(self) -> dict | None:
        host = self.ed_host.text().strip()
        if not host:
            QMessageBox.warning(self, "缺少目标", "请先填写设备 IP")
            return None
        community = self.ed_community.text().strip()
        if not community:
            QMessageBox.warning(self, "缺少团体名", "SNMP v1/v2c 必须填团体名")
            return None
        return {"host": host, "community": community,
                "version": int(self.cmb_version.currentData() or 2),
                "port": int(self.sp_port.value()),
                "timeout": float(self.sp_timeout.value()),
                "retries": int(self.sp_retries.value())}

    def _start(self, what: str, fn, on_done) -> None:
        if self.worker is not None and self.worker.isRunning():
            QMessageBox.information(self, "正在查询", "上一个 SNMP 查询还没结束，请稍等")
            return
        self._set_busy(True)
        self.lbl_state.setText(f"{what}…")
        self.lbl_state.setStyleSheet(f"color:{C_YELLOW};")
        self.worker = SnmpTask(fn, self)
        self.worker.done.connect(on_done)
        self.worker.failed.connect(lambda msg: self._failed(what, msg))
        self.worker.finished.connect(self._finished)
        self.worker.start()

    def _set_busy(self, busy: bool) -> None:
        for btn in (self.btn_info, self.btn_ifaces, self.btn_arp, self.btn_lldp,
                    self.btn_probe, self.btn_oid, self.btn_write):
            btn.setEnabled(not busy)

    @safe_slot
    def _finished(self) -> None:
        self._set_busy(False)

    def _failed(self, what: str, msg: str) -> None:
        self._set_busy(False)
        self.lbl_state.setText(f"{what}失败")
        self.lbl_state.setStyleSheet(f"color:{C_RED};")
        log(f"SNMP {what}失败：{msg}", "error", "snmp")
        QMessageBox.warning(self, "SNMP 查询失败",
                            f"{msg}\n\n常见原因：团体名不对、目标没开 SNMP、"
                            f"ACL 只允许特定管理机、UDP 161 被防火墙拦住。")

    # ==================== 读取 ====================

    @safe_slot
    def read_info(self) -> None:
        params = self._params()
        if params is None:
            return
        self._start("读取系统信息",
                    lambda: SN.sys_info(params["host"], params["community"],
                                        params["version"], params["port"],
                                        params["timeout"]),
                    self._show_info)

    @safe_slot
    def _show_info(self, info: dict) -> None:
        self._last_info = info or {}
        if not self._last_info:
            self._failed("读取系统信息", "设备没有返回 sysDescr")
            return
        version_text = "v2c" if self._last_info.get("version") == 2 else "v1"
        lines = ["SNMP 系统信息", "=" * 30,
                 f"目标        : {self._last_info.get('host', '')}",
                 f"团体名      : {self._last_info.get('community', '')}",
                 f"版本        : {version_text}",
                 f"厂商（推断）: {self._last_info.get('vendor') or '未识别'}",
                 ""]
        labels = [("sysDescr", "系统描述"), ("sysName", "设备名"),
                  ("sysObjectID", "设备 OID"), ("sysUpTime", "运行时长"),
                  ("sysContact", "联系人"), ("sysLocation", "位置"),
                  ("sysServices", "服务层级")]
        for key, name in labels:
            value = self._last_info.get(key)
            if value not in (None, ""):
                lines.append(f"{name:<10}: {value}")
        lines.append("")
        lines.append("-" * 30)
        lines.append("安全结论：")
        findings = SN.security_report(self._last_info,
                                      self._last_info.get("community", ""),
                                      self._last_ifaces)
        if not findings:
            lines.append("  暂无需要特别说明的项。")
        for finding in findings:
            lines.append(f"  [{finding['severity']}] {finding['title']}")
            lines.append(f"      {finding['detail']}")
        self.txt_info.setPlainText("\n".join(lines))
        self.tabs.setCurrentWidget(self.txt_info)
        self.lbl_state.setText("已读取系统信息")
        self.lbl_state.setStyleSheet(f"color:{C_MINT};")
        log(f"SNMP 系统信息读取成功：{self._last_info.get('sysName', '')}",
            "success", "snmp")

    @safe_slot
    def read_ifaces(self) -> None:
        params = self._params()
        if params is None:
            return
        self._start("读取接口表",
                    lambda: SN.interfaces(params["host"], params["community"],
                                          params["version"], params["port"],
                                          params["timeout"]),
                    self._show_ifaces)

    @safe_slot
    def _show_ifaces(self, rows: list) -> None:
        self._last_ifaces = list(rows or [])
        data = []
        for item in self._last_ifaces:
            data.append([item.get("index", ""), item.get("descr") or "-",
                         item.get("type_name", ""), item.get("speed_text", ""),
                         item.get("mac_text", "-"), item.get("admin", ""),
                         item.get("oper", "")])
        self._fill(self.table_ifaces, data)
        self.tabs.setCurrentWidget(self.table_ifaces)
        self.lbl_state.setText(f"接口 {len(data)} 个")
        self.lbl_state.setStyleSheet(f"color:{C_MINT};")
        log(f"SNMP 接口表读取完成：{len(data)} 个接口", "success", "snmp")
        if self._last_info:
            self._show_info(self._last_info)      # 结论里补上 down 接口信息
            self.tabs.setCurrentWidget(self.table_ifaces)

    @safe_slot
    def read_arp(self) -> None:
        params = self._params()
        if params is None:
            return
        self._start("读取 ARP 表",
                    lambda: SN.arp_table(params["host"], params["community"],
                                         params["version"], params["port"],
                                         params["timeout"]),
                    self._show_arp)

    @safe_slot
    def _show_arp(self, rows: list) -> None:
        data = [[r.get("ip", ""), r.get("mac", ""), r.get("ifindex", ""),
                 r.get("type", "")] for r in rows or []]
        self._fill(self.table_arp, data)
        self.tabs.setCurrentWidget(self.table_arp)
        self.lbl_state.setText(f"ARP {len(data)} 条")
        self.lbl_state.setStyleSheet(f"color:{C_MINT};")
        log(f"SNMP ARP 表读取完成：{len(data)} 条", "success", "snmp")

    @safe_slot
    def read_lldp(self) -> None:
        params = self._params()
        if params is None:
            return
        self._start("读取 LLDP 邻居",
                    lambda: SN.lldp_neighbors(params["host"], params["community"],
                                              params["version"], params["port"],
                                              params["timeout"]),
                    self._show_lldp)

    @safe_slot
    def _show_lldp(self, rows: list) -> None:
        data = [[r.get("index", ""), r.get("sys_name") or "-",
                 r.get("port_id") or "-", r.get("port_desc") or "-",
                 r.get("sys_desc") or "-"] for r in rows or []]
        self._fill(self.table_lldp, data)
        self.tabs.setCurrentWidget(self.table_lldp)
        self.lbl_state.setText(f"LLDP 邻居 {len(data)} 条")
        self.lbl_state.setStyleSheet(f"color:{C_MINT};")
        log(f"SNMP LLDP 邻居读取完成：{len(data)} 条", "success", "snmp")

    @safe_slot
    def probe_communities(self) -> None:
        params = self._params()
        if params is None:
            return

        def task():
            return SN.probe_communities(params["host"], params["port"],
                                        params["version"],
                                        min(1.0, params["timeout"]))

        self._start("探测团体名", task, self._show_probe)

    @safe_slot
    def _show_probe(self, result) -> None:
        community, info = result if isinstance(result, tuple) else ("", {})
        if not community:
            self.lbl_state.setText("没有探测到可用团体名")
            self.lbl_state.setStyleSheet(f"color:{C_TEXT_DIM};")
            QMessageBox.information(
                self, "未发现", "常见团体名都试过了，均无应答。\n"
                                "可能是设备没开 SNMP、ACL 限制、或团体名是自定义的。")
            return
        self.ed_community.setText(community)
        self._show_info(info)
        QMessageBox.information(self, "探测成功",
                                f"可用团体名：{community}\n已填回输入框并读取系统信息。")

    @safe_slot
    def read_oid(self) -> None:
        params = self._params()
        if params is None:
            return
        oids = [o.strip() for o in self.ed_oid.text().replace("；", ",")
                .replace(";", ",").split(",") if o.strip()]
        if not oids:
            QMessageBox.warning(self, "缺少 OID", "至少填一个 OID")
            return
        if len(oids) > 32:
            QMessageBox.warning(self, "OID 太多", "一次最多 32 个 OID")
            return
        self._start("原始 OID 查询",
                    lambda: SN.get(params["host"], oids, params["community"],
                                   params["version"], params["port"],
                                   params["timeout"], params["retries"]),
                    self._show_oid)

    @safe_slot
    def _show_oid(self, resp) -> None:
        if not resp.ok:
            self._failed("原始 OID 查询", resp.error_text)
            return
        data = [[vb.oid, vb.to_dict().get("name") or "-",
                 f"0x{vb.tag:02X}", vb.display()] for vb in resp.varbinds]
        self._fill(self.table_oid, data)
        self.lbl_state.setText(f"返回 {len(data)} 个 varbind")
        self.lbl_state.setStyleSheet(f"color:{C_MINT};")

    # ==================== 写入 ====================

    @safe_slot
    def write_values(self) -> None:
        if not self.chk_write_auth.isChecked():
            QMessageBox.warning(self, "未授权", "请先勾选「我确认这是实验设备或已获授权」")
            return
        params = self._params()
        if params is None:
            return
        name = self.ed_sysname.text().strip()
        location = self.ed_syslocation.text().strip()
        values = []
        if name:
            values.append((SN.OID_SYS_NAME, "string", name))
        if location:
            values.append((SN.OID_SYS_LOCATION, "string", location))
        if not values:
            QMessageBox.information(self, "没有内容", "sysName 与 sysLocation 都为空")
            return
        if QMessageBox.question(
                self, "确认写入",
                f"将向 {params['host']} 写入：\n"
                + "\n".join(f"  {oid} = {value}" for oid, _k, value in values)
                + "\n\n确定吗？") != QMessageBox.Yes:
            return
        self._start("写入配置",
                    lambda: SN.set_values(params["host"], values,
                                          params["community"], params["version"],
                                          params["port"], params["timeout"],
                                          params["retries"]),
                    self._show_write)

    @safe_slot
    def _show_write(self, resp) -> None:
        if not resp.ok:
            self._failed("写入配置", resp.error_text)
            return
        self.lbl_state.setText("写入成功")
        self.lbl_state.setStyleSheet(f"color:{C_MINT};")
        log("SNMP 写入成功", "success", "snmp")
        QMessageBox.information(self, "写入成功",
                                "设备已接受写入。可再点「读取系统信息」核对。")

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
        """主窗口关闭时调用：等后台查询收尾（不强制 terminate）。"""
        worker = self.worker
        if worker is not None and worker.isRunning():
            try:
                worker.wait(3000)
            except Exception:
                pass
        self.worker = None
