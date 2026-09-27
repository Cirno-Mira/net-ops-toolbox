# -*- coding: utf-8 -*-
"""
流量劫持页（内建透明代理）
==========================

配合「ARP 流量牵引 + DNS 引流」使用：被牵引设备访问网站时，
请求会直接打到本机，这一页就能看到明文（HTTPS 需要目标装了本机的根证书）。

功能：
* 实时请求列表（方法 / 状态码 / 主机 / 路径 / 大小）
* 请求与响应全文查看（正文自动 gunzip）
* **编辑后重放**：直接改原始请求报文再发一次
* **断点**：URL 命中规则时挂起，人工放行 / 改后放行 / 丢弃
* 一键把根证书导出到桌面，方便装到目标设备上
"""

from __future__ import annotations

import os
import subprocess

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (QCheckBox, QFileDialog, QHBoxLayout, QLineEdit,
                             QMessageBox, QPlainTextEdit, QPushButton, QSpinBox,
                             QSplitter, QVBoxLayout, QWidget)

from core import appconfig
from core import mitm as MI
from core import netdiag as ND
from core.logging_bus import log
from ui.widgets import Card, hline, label, make_table, set_row
from theme import C_MINT, C_RED, C_YELLOW

HEADERS = ["#", "时间", "来源", "方法", "状态", "主机", "路径", "大小", "状态说明"]


def _safe_text(data: bytes, limit: int = 200000) -> str:
    if not data:
        return ""
    data = data[:limit]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("gb18030")
        except UnicodeDecodeError:
            return data.decode("latin-1", "replace")


class MitmTab(QWidget):
    flow_signal = pyqtSignal(object)
    pending_signal = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.proxy: MI.MitmProxy | None = None
        self.ca: MI.CertAuthority | None = None
        self.rows: dict[int, int] = {}          # fid -> row
        self.flows: dict[int, MI.Flow] = {}
        self.arp_iface = None                   # ARP 页当前网卡（自检用）
        self.dns_probe = None                   # 取 DNS 引流状态的回调（自检用）
        self._build()
        self.flow_signal.connect(self.on_flow)
        self.pending_signal.connect(self.on_pending)

    # ================= 界面 =================

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)

        outer.addWidget(self._build_control())

        split = QSplitter(Qt.Vertical)
        split.addWidget(self._build_table())
        split.addWidget(self._build_detail())
        split.setSizes([300, 420])
        outer.addWidget(split, 1)

    def _build_control(self) -> QWidget:
        card = Card("🕵 透明代理")
        r1 = QHBoxLayout()
        r1.setSpacing(6)
        self.btn_start = QPushButton("▶ 启动代理")
        self.btn_start.setObjectName("Primary")
        self.btn_start.clicked.connect(self.toggle_proxy)
        r1.addWidget(self.btn_start)
        r1.addWidget(label("HTTP 端口", "Dim"))
        self.sp_http = QSpinBox()
        self.sp_http.setRange(1, 65535)
        self.sp_http.setValue(int(appconfig.CFG.get("mitm_http_port", 80)))
        self.sp_http.setToolTip(
            "★ 这里是「我方透明代理监听哪个端口」，被 DNS 引流过来的目标会连这个端口。\n"
            "应该保持 80（HTTPS 保持 443）。\n\n"
            "如果你想用 Reqable / Fiddler 来看包，勾选下面的\n"
            "「把流量转交给本地抓包工具」，把它自己的监听端口填到【那一栏】，\n"
            "这里仍然保持 80/443 —— 两个端口不是一回事。")
        r1.addWidget(self.sp_http)
        r1.addWidget(label("HTTPS 端口", "Dim"))
        self.sp_https = QSpinBox()
        self.sp_https.setRange(1, 65535)
        self.sp_https.setValue(int(appconfig.CFG.get("mitm_https_port", 443)))
        self.sp_https.setToolTip("同上，HTTPS 保持 443。解密 HTTPS 需要目标设备信任我们的根证书。")
        r1.addWidget(self.sp_https)
        r1.addWidget(label("二级代理", "Dim"))
        self.ed_upstream = QLineEdit()
        self.ed_upstream.setPlaceholderText("可留空，如 127.0.0.1:7890")
        self.ed_upstream.setFixedWidth(150)
        r1.addWidget(self.ed_upstream)
        r1.addStretch(1)
        self.lbl_state = label("未启动", "Dim")
        r1.addWidget(self.lbl_state)
        card.add(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(6)
        self.chk_forward_tool = QCheckBox("把流量转交给本地抓包工具（Reqable/Fiddler）")
        self.chk_forward_tool.setToolTip(
            "开启后，被劫持的连接会被转成代理请求发给本地工具，"
            "由它来做解密与展示（HTTP 走代理格式，HTTPS 走 CONNECT 隧道）。")
        r2.addWidget(self.chk_forward_tool)
        self.sp_forward_port = QSpinBox()
        self.sp_forward_port.setRange(1, 65535)
        self.sp_forward_port.setValue(int(appconfig.CFG.get("mitm_forward_port", 8888)))
        self.sp_forward_port.setToolTip(
            "填本地抓包工具自己的监听端口（各工具默认值不同，在它设置里能看到）")
        r2.addWidget(self.sp_forward_port)
        r2.addStretch(1)
        btn_ca = QPushButton("导出根证书")
        btn_ca.setObjectName("Ghost")
        btn_ca.setToolTip("把 CA 证书导出到桌面，装到目标设备的受信任根里才能解 HTTPS")
        btn_ca.clicked.connect(self.export_ca)
        r2.addWidget(btn_ca)
        btn_dir = QPushButton("打开证书目录")
        btn_dir.setObjectName("Ghost")
        btn_dir.clicked.connect(self.open_cert_dir)
        r2.addWidget(btn_dir)
        card.add(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(6)
        r3.addWidget(label("断点规则", "Dim"))
        self.ed_break = QLineEdit()
        self.ed_break.setPlaceholderText("URL 关键字或正则，例如 login 或 /api/.*token")
        self.ed_break.returnPressed.connect(self.add_break)
        r3.addWidget(self.ed_break, 1)
        btn_add = QPushButton("添加断点")
        btn_add.setObjectName("Ghost")
        btn_add.clicked.connect(self.add_break)
        r3.addWidget(btn_add)
        self.chk_block_all = QCheckBox("挂起全部请求")
        self.chk_block_all.setToolTip("打开后每个请求都会挂起等你放行，慎用（会拖慢对方）")
        self.chk_block_all.toggled.connect(self._on_block_all)
        r3.addWidget(self.chk_block_all)
        btn_clear_break = QPushButton("清除断点")
        btn_clear_break.setObjectName("Ghost")
        btn_clear_break.clicked.connect(self.clear_breaks)
        r3.addWidget(btn_clear_break)
        card.add(r3)
        self.lbl_breaks = label("暂无断点规则", "Dim")
        self.lbl_breaks.setWordWrap(True)
        card.add(self.lbl_breaks)

        card.add(hline())
        r4 = QHBoxLayout()
        r4.setSpacing(6)
        btn_diag = QPushButton("🔍 引流自检")
        btn_diag.setObjectName("Primary")
        btn_diag.setToolTip("把整条链路逐环检查一遍，告诉你卡在哪一步")
        btn_diag.clicked.connect(self.run_diag)
        btn_fw = QPushButton("放行防火墙端口")
        btn_fw.setObjectName("Ghost")
        btn_fw.setToolTip("给监听端口加入站放行规则（需要管理员）\n"
                          "Public 配置文件开启时，外部连接会被丢弃，这是常见坑")
        btn_fw.clicked.connect(self.allow_firewall)
        btn_help = QPushButton("使用说明")
        btn_help.setObjectName("Ghost")
        btn_help.clicked.connect(self.show_help)
        r4.addWidget(btn_diag)
        r4.addWidget(btn_fw)
        r4.addWidget(btn_help)
        r4.addStretch(1)
        card.add(r4)

        self.txt_diag = QPlainTextEdit()
        self.txt_diag.setReadOnly(True)
        self.txt_diag.setMinimumHeight(150)
        self.txt_diag.setMaximumHeight(190)
        self.txt_diag.setFont(QFont("Microsoft YaHei UI", 9))
        self.txt_diag.setPlainText(
            "点「🔍 引流自检」检查整条链路。\n"
            "核心原理：ARP 牵引只让流量『经过』本机，目标连的还是真实服务器 IP；\n"
            "必须靠 DNS 引流把目标骗到本机 IP，透明代理才能拿到明文请求。")
        card.add(self.txt_diag)
        return card

    def _build_table(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        bar = QHBoxLayout()
        bar.addWidget(label("请求列表", "CardT"))
        bar.addStretch(1)
        self.lbl_count = label("0 条", "Dim")
        bar.addWidget(self.lbl_count)
        for text, fn in (("清空", self.clear_flows),
                         ("放行挂起", lambda: self.resolve_pending("release")),
                         ("丢弃挂起", lambda: self.resolve_pending("drop"))):
            b = QPushButton(text)
            b.setObjectName("Ghost")
            b.clicked.connect(fn)
            bar.addWidget(b)
        lay.addLayout(bar)
        self.table = make_table(HEADERS, stretch_col=6)
        # 流量列表要保持时间顺序，不能被自动排序打乱
        self.table.setSortingEnabled(False)
        self.table.setColumnWidth(0, 50)
        self.table.setColumnWidth(1, 80)
        self.table.setColumnWidth(2, 140)
        self.table.setColumnWidth(3, 60)
        self.table.setColumnWidth(4, 55)
        self.table.setColumnWidth(5, 180)
        self.table.setColumnWidth(7, 70)
        self.table.setColumnWidth(8, 90)
        self.table.itemSelectionChanged.connect(self.show_selected)
        lay.addWidget(self.table)
        return w

    def _build_detail(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        bar = QHBoxLayout()
        bar.addWidget(label("报文详情（上面这块可以直接改，然后「改后重放」）", "CardT"))
        bar.addStretch(1)
        self.btn_orig = QPushButton("原样重放")
        self.btn_orig.setObjectName("Ghost")
        self.btn_orig.clicked.connect(lambda: self.replay(edited=False))
        self.btn_edit = QPushButton("改后重放")
        self.btn_edit.setObjectName("Primary")
        self.btn_edit.clicked.connect(lambda: self.replay(edited=True))
        self.btn_reset = QPushButton("还原报文")
        self.btn_reset.setObjectName("Ghost")
        self.btn_reset.clicked.connect(self.show_selected)
        for b in (self.btn_orig, self.btn_edit, self.btn_reset):
            bar.addWidget(b)
        lay.addLayout(bar)

        split = QSplitter(Qt.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(2)
        ll.addWidget(label("请求", "Dim"))
        self.txt_req = QPlainTextEdit()
        self.txt_req.setFont(QFont("Cascadia Mono", 9))
        self.txt_req.setPlaceholderText("选中上面一条请求后，这里显示原始请求报文")
        ll.addWidget(self.txt_req)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(2)
        rl.addWidget(label("响应", "Dim"))
        self.txt_resp = QPlainTextEdit()
        self.txt_resp.setReadOnly(True)
        self.txt_resp.setFont(QFont("Cascadia Mono", 9))
        rl.addWidget(self.txt_resp)

        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([520, 520])
        lay.addWidget(split, 1)
        return w

    # ================= 代理控制 =================

    def toggle_proxy(self):
        if self.proxy is not None and self.proxy.running:
            self.proxy.stop()
            self.proxy = None
            self.lbl_state.setText("未启动")
            self.btn_start.setText("▶ 启动代理")
            return
        from core import hostinfo as HI
        if not HI.is_admin():
            QMessageBox.warning(self, "需要管理员权限",
                                "监听 80/443 需要管理员权限，请重启工具箱并在 UAC 里点「是」。\n"
                                "（也可以把端口改成 8080 之类免提权的端口，"
                                "但那需要目标设备手动设置代理）")
            return
        cfg = appconfig.CFG
        ca_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              str(cfg.get("mitm_ca_dir", "certs")))
        self.ca = MI.CertAuthority(ca_dir)
        if not self.ca.available:
            QMessageBox.warning(self, "缺少 cryptography",
                                "HTTPS 需要 cryptography 库：pip install cryptography")
            return
        self.ca.ensure_ca()

        self.proxy = MI.MitmProxy(
            ca=self.ca,
            http_port=self.sp_http.value(),
            https_port=self.sp_https.value(),
            upstream_proxy=self.ed_upstream.text().strip(),
            forward_to_tool=self.chk_forward_tool.isChecked(),
            forward_port=self.sp_forward_port.value(),
            on_flow=self.flow_signal.emit,
            on_pending=self.pending_signal.emit,
        )
        self.proxy.start()
        if self.proxy.running:
            self.btn_start.setText("■ 停止代理")
            self.lbl_state.setText(
                f"监听 {self.sp_http.value()}/{self.sp_https.value()}")
            appconfig.CFG.update(mitm_http_port=self.sp_http.value(),
                                 mitm_https_port=self.sp_https.value(),
                                 mitm_forward_port=self.sp_forward_port.value())
            appconfig.CFG.save()
            if self.proxy.bind_errors:
                QMessageBox.warning(
                    self, "部分端口没监听成功",
                    "\n\n".join(self.proxy.bind_errors) +
                    "\n\n（其余端口仍然在跑，可以先点「🔍 引流自检」看整体情况）")
        else:
            errs = "\n\n".join(self.proxy.bind_errors) or "端口没能监听成功，看下面的日志"
            self.proxy = None
            self.lbl_state.setText("启动失败")
            self.btn_start.setText("▶ 启动代理")
            QMessageBox.warning(self, "启动失败", errs)

    def _on_block_all(self, on: bool):
        if self.proxy is not None:
            self.proxy.block_upstream = on
        log("已开启「挂起全部请求」" if on else "已关闭「挂起全部请求」", "warn", "mitm")

    def add_break(self):
        pattern = self.ed_break.text().strip()
        if not pattern:
            return
        if self.proxy is None:
            QMessageBox.information(self, "代理未启动", "先启动代理再添加断点规则")
            return
        self.proxy.add_break(pattern)
        self.ed_break.clear()
        self._refresh_breaks()

    def clear_breaks(self):
        if self.proxy is not None:
            self.proxy.clear_breaks()
        self.chk_block_all.setChecked(False)
        self._refresh_breaks()

    def _refresh_breaks(self):
        rules = self.proxy.break_rules if self.proxy else []
        if not rules:
            self.lbl_breaks.setText("暂无断点规则")
        else:
            self.lbl_breaks.setText("已启用：" + "　".join(
                f"{r.pattern}（命中 {r.hit} 次）" for r in rules))

    # ================= 流处理 =================

    def on_flow(self, flow: MI.Flow):
        rid = flow.fid
        if rid in self.rows:
            row = self.rows[rid]
        else:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.rows[rid] = row
        self.flows[rid] = flow
        colors = {}
        if flow.state == "挂起中":
            colors[8] = C_YELLOW
        elif flow.error:
            colors[8] = C_RED
            colors[4] = C_RED
        else:
            colors[4] = C_MINT if 200 <= (flow.status or 0) < 400 else C_RED
        set_row(self.table, row, flow.row(), colors)
        self.lbl_count.setText(f"{len(self.flows)} 条")
        if flow.state == "挂起中" and self.table.currentRow() < 0:
            self.table.selectRow(row)

    def on_pending(self, flow: MI.Flow):
        self.on_flow(flow)
        log(f"断点挂起：{flow.method} {flow.url}（选中后点「放行挂起」或「丢弃挂起」）",
            "warn", "mitm")

    def selected_flow(self) -> MI.Flow | None:
        row = self.table.currentRow()
        if row < 0:
            return None
        it = self.table.item(row, 0)
        if it is None:
            return None
        try:
            return self.flows.get(int(it.text()))
        except ValueError:
            return None

    def show_selected(self):
        flow = self.selected_flow()
        if flow is None:
            self.txt_req.setPlainText("")
            self.txt_resp.setPlainText("")
            return
        self.txt_req.setPlainText(self._raw_request(flow))
        self.txt_resp.setPlainText(self._raw_response(flow))

    @staticmethod
    def _raw_request(flow: MI.Flow) -> str:
        head = f"{flow.method} {flow.path} {flow.version}\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in flow.req_headers)
        body = MI.decode_body(flow.req_body, flow.req_headers)
        return head + "\r\n" + _safe_text(body)

    @staticmethod
    def _raw_response(flow: MI.Flow) -> str:
        head = f"HTTP/1.1 {flow.status} {flow.reason}\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in flow.resp_headers)
        body = MI.decode_body(flow.resp_body, flow.resp_headers)
        extra = ""
        if flow.error:
            extra = f"\n\n[错误] {flow.error}"
        if flow.duration_ms:
            extra += f"\n\n[耗时] {flow.duration_ms:.0f} ms"
        return head + "\r\n" + _safe_text(body) + extra

    @staticmethod
    def _parse_raw(text: str):
        text = text.replace("\r\n", "\n")
        head, _, body = text.partition("\n\n")
        lines = head.split("\n")
        if not lines:
            raise ValueError("报文为空")
        parts = lines[0].split()
        if len(parts) < 2:
            raise ValueError("请求行不合法")
        method, path = parts[0], parts[1]
        version = parts[2] if len(parts) > 2 else "HTTP/1.1"
        headers = []
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers.append((k.strip(), v.strip()))
        return method, path, version, headers, body.encode("utf-8")

    def replay(self, edited: bool):
        flow = self.selected_flow()
        if flow is None:
            QMessageBox.information(self, "没有选中", "先在上面选一条请求")
            return
        if self.proxy is None:
            QMessageBox.information(self, "代理未启动", "重放需要代理处于启动状态")
            return
        method, path, version, headers, body = "", "", "", None, None
        if edited:
            try:
                method, path, version, headers, body = self._parse_raw(
                    self.txt_req.toPlainText())
            except Exception as exc:
                QMessageBox.warning(self, "报文解析失败", str(exc))
                return
        new = self.proxy.replay(
            flow,
            method=method,
            url=(path if edited else ""),
            headers=headers, body=body)
        log(f"重放 {new.method} {new.url} -> {new.status or new.error}",
            "success" if not new.error else "error", "mitm")
        if self.table.rowCount() and self.table.item(self.table.rowCount() - 1, 0):
            self.table.selectRow(self.table.rowCount() - 1)

    def resolve_pending(self, action: str):
        flow = self.selected_flow()
        if self.proxy is None or flow is None:
            return
        if not self.proxy.resolve_pending(flow.fid, action):
            QMessageBox.information(self, "不是挂起的请求",
                                    "只有状态为「挂起中」的请求可以放行/丢弃")
            return
        log(f"断点已{'放行' if action == 'release' else '丢弃'}：{flow.url}",
            "info", "mitm")

    def clear_flows(self):
        self.table.setRowCount(0)
        self.rows.clear()
        self.flows.clear()
        if self.proxy is not None:
            self.proxy.clear()
        self.lbl_count.setText("0 条")

    # ================= 自检 / 防火墙 =================

    def run_diag(self):
        from core import hostinfo as HI
        iface = self.arp_iface or HI.primary_iface()
        dns_running, dns_spoofed = False, 0
        if callable(self.dns_probe):
            try:
                dns_running, dns_spoofed = self.dns_probe()
            except Exception:
                pass
        running = bool(self.proxy and self.proxy.running)
        conns = int(self.proxy.stats.get("connections", 0)) if self.proxy else 0
        items = ND.diagnose(
            iface=iface,
            http_port=self.sp_http.value(),
            https_port=self.sp_https.value(),
            forward_port=self.sp_forward_port.value(),
            forward_to_tool=self.chk_forward_tool.isChecked(),
            proxy_running=running,
            proxy_connections=conns,
            dns_running=dns_running,
            dns_spoofed=dns_spoofed,
        )
        self.txt_diag.setPlainText(ND.format_report(items))
        bad = [i for i in items if i["ok"] is False]
        if bad:
            log(f"引流自检：{len(bad)} 项有问题 —— {bad[0]['name']}：{bad[0]['detail']}",
                "warn", "mitm")
        else:
            log("引流自检：链路全部就绪", "success", "mitm")

    def allow_firewall(self):
        ports = [p for p in (self.sp_http.value(), self.sp_https.value()) if p]
        ok, msg = ND.allow_firewall(ports)
        if ok:
            QMessageBox.information(self, "已放行", msg + "\n\n现在让目标设备重新访问试试。")
        else:
            QMessageBox.warning(self, "放行失败", msg)
        if self.txt_diag.toPlainText():
            self.run_diag()

    def show_help(self):
        QMessageBox.information(
            self, "流量劫持怎么用",
            "要让「他访问网站，我这边直接看到」，必须三步都到位：\n\n"
            "1) ARP 页：模式选「双向中间人」，勾上「开启 IP 转发」和「DNS 引流」，\n"
            "   点开始。（DNS 引流是关键 —— 没有它，目标的流量只是经过本机，\n"
            "   目的 IP 还是真实服务器，本地代理收不到）\n\n"
            "2) 本页：端口保持 80 / 443，勾上「同时启动内建透明代理」，点「启动代理」。\n"
            "   注意 80/443 是「目标连过来的端口」，不是抓包工具的监听端口。\n\n"
            "3) 想用 Reqable / Fiddler：勾选「把流量转交给本地抓包工具」，\n"
            "   把它的监听端口填在【那一栏】，监听端口仍保持 80/443。\n\n"
            "HTTPS 还要多一步：点「导出根证书」，把 netops-ca.crt 装到目标设备的\n"
            "「受信任的根证书颁发机构」里。\n\n"
            "还是没流量？点「🔍 引流自检」，它会告诉你卡在哪一环。\n"
            "常见原因：目标设备开了 DoH/DoT（加密 DNS，劫持不到）、\n"
            "防火墙拦了入站、目标直接用 IP 访问而不是域名。")

    # ================= 证书 =================

    def export_ca(self):
        ca_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              str(appconfig.CFG.get("mitm_ca_dir", "certs")))
        ca = self.ca or MI.CertAuthority(ca_dir)
        ca.ensure_ca()
        target, _ = QFileDialog.getSaveFileName(
            self, "导出根证书", os.path.join(os.path.expanduser("~"), "Desktop",
                                            "netops-ca.crt"),
            "证书 (*.crt *.pem)")
        if not target:
            return
        try:
            with open(target, "wb") as fh:
                fh.write(ca.ca_pem_bytes())
            QMessageBox.information(
                self, "导出成功",
                f"已导出到：\n{target}\n\n"
                "把这个文件装到**目标设备**的「受信任的根证书颁发机构」里，"
                "才能解密它的 HTTPS 流量。")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))

    def open_cert_dir(self):
        ca_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              str(appconfig.CFG.get("mitm_ca_dir", "certs")))
        os.makedirs(ca_dir, exist_ok=True)
        try:
            subprocess.Popen(["explorer", os.path.normpath(ca_dir)])
        except Exception as exc:
            QMessageBox.warning(self, "打开失败", str(exc))

    def shutdown(self):
        if self.proxy is not None and self.proxy.running:
            self.proxy.stop()
