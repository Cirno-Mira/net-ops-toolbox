# -*- coding: utf-8 -*-
"""
报告导出页
==========

把各页面扫到的东西汇总成一份可交付的 Markdown / HTML 报告。
点「采集数据」会自动去读资产、端口、体检、流量劫持、目录爆破各页的现有结果。
"""

from __future__ import annotations

import os
import time
from datetime import datetime

from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (QCheckBox, QFileDialog, QHBoxLayout,
                             QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
                             QVBoxLayout, QWidget)

from core import report as RP
from core.logging_bus import log
from ui.widgets import Card, label, safe_slot
from theme import C_MINT, C_YELLOW

SECTIONS = [("meta", "任务信息"), ("summary", "结果概览"), ("assets", "资产清单"),
            ("ports", "开放端口"), ("vulns", "安全问题"),
            ("flows", "HTTP 流量"), ("dirs", "路径发现")]


class ReportTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = RP.ReportData()
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        card = Card("📄 报告导出")

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.addWidget(label("标题", "Dim"))
        self.ed_title = QLineEdit(self.data.title)
        r1.addWidget(self.ed_title, 2)
        r1.addWidget(label("执行人", "Dim"))
        self.ed_operator = QLineEdit()
        self.ed_operator.setPlaceholderText("可留空")
        r1.addWidget(self.ed_operator, 1)
        r1.addWidget(label("测试范围", "Dim"))
        self.ed_scope = QLineEdit()
        self.ed_scope.setPlaceholderText("例如 192.168.5.0/24")
        r1.addWidget(self.ed_scope, 1)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        r2.addWidget(label("备注", "Dim"))
        self.ed_notes = QLineEdit()
        self.ed_notes.setPlaceholderText("例如：本次为授权内网自查，测试时间窗口 xx")
        r2.addWidget(self.ed_notes, 1)
        card.add(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(12)
        r3.addWidget(label("包含章节", "Dim"))
        self.chk_sections: dict[str, QCheckBox] = {}
        for key, name in SECTIONS:
            cb = QCheckBox(name)
            cb.setChecked(True)
            self.chk_sections[key] = cb
            r3.addWidget(cb)
        r3.addStretch(1)
        card.add(r3)

        r4 = QHBoxLayout()
        r4.setSpacing(8)
        self.btn_collect = QPushButton("🔄 采集数据")
        self.btn_collect.setObjectName("Primary")
        self.btn_collect.setToolTip("从资产发现 / 端口扫描 / 安全体检 / 流量劫持 / 目录爆破各页读取现有结果")
        self.btn_collect.clicked.connect(self.collect)
        self.btn_md = QPushButton("导出 Markdown")
        self.btn_md.setObjectName("Ghost")
        self.btn_md.clicked.connect(lambda: self.export("md"))
        self.btn_html = QPushButton("导出 HTML")
        self.btn_html.setObjectName("Ghost")
        self.btn_html.clicked.connect(lambda: self.export("html"))
        self.btn_preview = QPushButton("刷新预览")
        self.btn_preview.setObjectName("Ghost")
        self.btn_preview.clicked.connect(self.refresh_preview)
        for b in (self.btn_collect, self.btn_preview, self.btn_md, self.btn_html):
            r4.addWidget(b)
        r4.addStretch(1)
        self.lbl_state = label("还没采集数据", "Dim")
        r4.addWidget(self.lbl_state)
        card.add(r4)
        lay.addWidget(card)

        card2 = Card("预览（Markdown 源码）")
        self.txt = QPlainTextEdit()
        self.txt.setFont(QFont("Cascadia Mono", 9))
        self.txt.setMinimumHeight(340)
        card2.add(self.txt)
        lay.addWidget(card2, 1)

        self.refresh_preview()

    # ---------------- 采集 ----------------

    def bind(self, main_window):
        self.win = main_window

    @safe_slot
    def collect(self):
        d = RP.ReportData(
            title=self.ed_title.text().strip() or "网络运维工具箱 · 检测报告",
            operator=self.ed_operator.text().strip(),
            scope=self.ed_scope.text().strip(),
            notes=self.ed_notes.text().strip(),
            generated_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        win = getattr(self, "win", None)
        if win is None:
            QMessageBox.warning(self, "内部错误", "报告页没有绑定主窗口")
            return

        # 资产
        try:
            for a in win.tab_assets.assets.values():
                d.assets.append({
                    "ip": a.ip, "mac": a.mac, "vendor": a.vendor,
                    "hostname": a.hostname, "ports": ",".join(str(p) for p in a.open_ports),
                    "status": "在线" if a.online else "离线"})
            d.assets.sort(key=lambda x: tuple(int(i) for i in x["ip"].split(".")))
        except Exception as exc:
            log(f"报告：读取资产失败 {exc}", "debug", "report")

        # 端口
        try:
            for p in win.tab_ports.results:
                d.ports.append({"host": p.host, "port": p.port,
                                "service": p.service, "banner": p.banner})
        except Exception as exc:
            log(f"报告：读取端口失败 {exc}", "debug", "report")

        # 安全问题
        try:
            for f in win.tab_vuln.findings:
                d.vulns.append({"host": f.host, "port": f.port, "name": f.name,
                                "severity": f.severity, "detail": f.detail,
                                "evidence": f.evidence})
        except Exception as exc:
            log(f"报告：读取体检结果失败 {exc}", "debug", "report")

        # HTTP 流量
        try:
            for fl in win.tab_mitm.flows.values():
                d.flows.append({"time": fl.ts, "client": fl.client,
                                "method": fl.method, "url": fl.url,
                                "status": fl.status})
        except Exception as exc:
            log(f"报告：读取流量失败 {exc}", "debug", "report")

        # 目录爆破
        try:
            for r in getattr(win.tab_dirbrute, "results", []):
                d.dirs.append({"url": getattr(r, "url", str(r)),
                               "status": getattr(r, "status", ""),
                               "length": getattr(r, "length", ""),
                               "note": getattr(r, "title", "")})
        except Exception as exc:
            log(f"报告：读取目录爆破失败 {exc}", "debug", "report")

        self.data = d
        counts = "、".join(f"{k} {v}" for k, v in d.counts().items())
        self.lbl_state.setText(f"已采集：{counts}" if not d.empty else "没有采集到数据")
        self.lbl_state.setStyleSheet(
            f"color:{C_MINT}; font-weight:700;" if not d.empty else f"color:{C_YELLOW};")
        log(f"报告数据采集完成：{counts}", "success", "report")
        self.refresh_preview()

    def _enabled_sections(self) -> set:
        return {k for k, cb in self.chk_sections.items() if cb.isChecked()}

    @safe_slot
    def refresh_preview(self):
        self.txt.setPlainText(
            RP.render_markdown(self.data, self._enabled_sections()))

    # ---------------- 导出 ----------------

    @safe_slot
    def export(self, kind: str):
        if self.data.empty:
            if QMessageBox.question(
                    self, "还没有数据",
                    "现在还没有采集到任何数据，仍然要导出空报告吗？",
                    QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                return
        self.data.title = self.ed_title.text().strip() or self.data.title
        self.data.operator = self.ed_operator.text().strip()
        self.data.scope = self.ed_scope.text().strip()
        self.data.notes = self.ed_notes.text().strip()
        sec = self._enabled_sections()
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        if kind == "html":
            default = f"netops_report_{stamp}.html"
            content = RP.render_html(self.data, sec)
            filt = "HTML 文件 (*.html)"
        else:
            default = f"netops_report_{stamp}.md"
            content = RP.render_markdown(self.data, sec)
            filt = "Markdown 文件 (*.md)"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出报告", os.path.join(os.path.expanduser("~"), "Desktop", default),
            filt)
        if not path:
            return
        ok, msg = RP.save(path, content)
        if ok:
            log(f"报告已导出：{path}", "success", "report")
            QMessageBox.information(self, "导出成功", f"报告已保存到：\n{path}")
        else:
            QMessageBox.warning(self, "导出失败", msg)
