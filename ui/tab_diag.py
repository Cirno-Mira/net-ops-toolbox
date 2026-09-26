# -*- coding: utf-8 -*-
"""
环境自检页
==========

把「这条链路到底哪一环有问题」集中到一页：

* 权限 / Npcap / 网卡 / 监听端口 / 防火墙 一键体检
* 一键放行防火墙入站端口
* 发包自检（无害：只问网关的 MAC，不做任何欺骗）
* 一键导出诊断报告，方便贴给别人看
"""

from __future__ import annotations

from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QMessageBox,
                             QPlainTextEdit, QPushButton, QVBoxLayout, QWidget)

from core import netdiag as ND
from ui.widgets import Card, label, safe_slot
from theme import C_MINT, C_RED


class DiagTab(QWidget):
    """环境自检。由主窗口通过 bind() 注入 ARP / 透明代理页的引用。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.arp_tab = None
        self.mitm_tab = None
        self._build()

    def bind(self, arp_tab, mitm_tab):
        self.arp_tab = arp_tab
        self.mitm_tab = mitm_tab
        self.run()

    # ---------------- 界面 ----------------

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        card = Card("🩺 环境自检")
        r1 = QHBoxLayout()
        r1.setSpacing(8)
        self.btn_run = QPushButton("🔄 重新体检")
        self.btn_run.setObjectName("Primary")
        self.btn_run.clicked.connect(self.run)
        self.btn_fw = QPushButton("放行防火墙端口")
        self.btn_fw.setObjectName("Ghost")
        self.btn_fw.setToolTip("给透明代理的监听端口加入站放行规则（需要管理员）\n"
                               "Windows 防火墙 Public 配置开着时，外部连接会被丢弃")
        self.btn_fw.clicked.connect(self.allow_firewall)
        self.btn_send = QPushButton("🔧 发包自检（无害）")
        self.btn_send.setObjectName("Ghost")
        self.btn_send.setToolTip("只发正常的 ARP 请求，验证能不能发包、能不能到达对方")
        self.btn_send.clicked.connect(self.run_send_selftest)
        self.btn_save = QPushButton("导出报告")
        self.btn_save.setObjectName("Ghost")
        self.btn_save.clicked.connect(self.export)
        for b in (self.btn_run, self.btn_fw, self.btn_send, self.btn_save):
            r1.addWidget(b)
        r1.addStretch(1)
        self.lbl_state = label("点「重新体检」开始", "Dim")
        r1.addWidget(self.lbl_state)
        card.add(r1)

        tip = QLabel(
            "这一页按「一条链路」的顺序检查。被牵引设备的流量看不到时，"
            "从上往下看第一个 ❌ 就是卡住的地方。")
        tip.setObjectName("Dim")
        tip.setWordWrap(True)
        card.add(tip)

        self.txt = QPlainTextEdit()
        self.txt.setReadOnly(True)
        self.txt.setFont(QFont("Microsoft YaHei UI", 10))
        self.txt.setMinimumHeight(300)
        card.add(self.txt)
        lay.addWidget(card, 1)

    # ---------------- 检查 ----------------

    @safe_slot
    def run(self):
        if self.arp_tab is None or self.mitm_tab is None:
            self.txt.setPlainText("还没绑定页面引用（内部错误）")
            return
        iface = self.arp_tab.current_iface()
        http_port = self.mitm_tab.sp_http.value()
        https_port = self.mitm_tab.sp_https.value()
        proxy = self.mitm_tab.proxy
        dns = self.arp_tab.dns
        items = ND.diagnose(
            iface=iface,
            http_port=http_port,
            https_port=https_port,
            forward_port=self.mitm_tab.sp_forward_port.value(),
            forward_to_tool=self.mitm_tab.chk_forward_tool.isChecked(),
            proxy_running=bool(proxy and proxy.running),
            proxy_connections=int(proxy.stats.get("connections", 0)) if proxy else 0,
            dns_running=dns is not None,
            dns_spoofed=dns.stats["spoofed"] if dns else 0,
        )
        self.txt.setPlainText(ND.format_report(items))
        bad = [i for i in items if i["ok"] is False]
        if bad:
            self.lbl_state.setText(f"发现 {len(bad)} 个问题")
            self.lbl_state.setStyleSheet(f"color:{C_RED}; font-weight:700;")
        else:
            self.lbl_state.setText("链路全部就绪 ✅")
            self.lbl_state.setStyleSheet(f"color:{C_MINT}; font-weight:700;")

    @safe_slot
    def allow_firewall(self):
        if self.mitm_tab is None:
            return
        ports = [self.mitm_tab.sp_http.value(), self.mitm_tab.sp_https.value()]
        ok, msg = ND.allow_firewall([p for p in ports if p])
        if ok:
            QMessageBox.information(self, "已放行", msg)
        else:
            QMessageBox.warning(self, "放行失败", msg)
        self.run()

    @safe_slot
    def run_send_selftest(self):
        if self.arp_tab is None:
            return
        self.arp_tab.run_selftest()

    @safe_slot
    def export(self):
        path, _ = QFileDialog.getSaveFileName(self, "导出诊断报告",
                                              "netops_diag.txt", "文本文件 (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.txt.toPlainText())
            QMessageBox.information(self, "导出成功", f"已保存到：\n{path}")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))
