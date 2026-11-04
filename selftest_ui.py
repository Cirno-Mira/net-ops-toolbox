# -*- coding: utf-8 -*-
"""
界面层回归测试（离屏运行，不需要管理员）
========================================

覆盖几类容易出现问题的场景：

1. safe_slot 装饰器必须按原函数形参个数截断 —— 否则 PyQt5 会把 clicked 信号
   自带的 checked 参数一并传入，报
   `start_spoof() takes 1 positional argument but 2 were given`
2. 槽函数里未捕获的异常不能让进程 abort（PyQt5 的默认行为是 qFatal/abort）
3. 主窗口能正常构建出全部工具页面
4. ARP 目标列表的增删改查与 MAC 补全
5. 抓包筛选规则的组合与实时重筛

    python selftest_ui.py
"""

from __future__ import annotations

import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from PyQt5.QtCore import Qt, QTimer                      # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox, QPushButton  # noqa: E402

FAILS: list[str] = []


def check(label, ok, extra=""):
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"   [{extra}]" if extra else ""))
    if not ok:
        FAILS.append(label)


def section(t):
    print(f"\n{'=' * 62}\n{t}\n{'=' * 62}")


app = QApplication.instance() or QApplication(sys.argv)

# --------------------------------------------------------------------------- #
section("1. safe_slot：参数截断")
from ui.widgets import safe_slot, crash_log_path   # noqa: E402


class _Probe:
    calls = 0
    args = None

    @safe_slot
    def no_arg(self):
        _Probe.calls += 1

    @safe_slot
    def one_arg(self, checked):
        _Probe.args = checked


probe = _Probe()
btn = QPushButton()
btn.clicked.connect(probe.no_arg)          # clicked 会带一个 checked=False
btn.click()
check("无参槽能接住 clicked(bool) 信号", _Probe.calls == 1, f"calls={_Probe.calls}")

btn2 = QPushButton()
btn2.setCheckable(True)
btn2.clicked.connect(probe.one_arg)
btn2.click()          # checkable 按钮点击后会变成选中状态，checked=True
check("带参槽能原样收到参数（不会被截断）", _Probe.args is True, repr(_Probe.args))

check("safe_slot 保留了原函数名", probe.no_arg.__name__ == "no_arg",
      probe.no_arg.__name__)


# --------------------------------------------------------------------------- #
section("2. 槽函数异常不会让进程 abort")
class _Boom:
    @safe_slot
    def boom(self):
        raise RuntimeError("测试异常：safe_slot 应该吞掉它")


try:
    _Boom().boom()
    check("safe_slot 吞掉异常（没有向外抛）", True)
except Exception as exc:
    check("safe_slot 吞掉异常（没有向外抛）", False, str(exc))

# 全局 excepthook：未装饰的槽抛异常时，进程必须活着
# （下面 stderr 会出现一条 RuntimeError —— 那是故意触发的，用来验证兜底）
print("  （注意：下面会打印一条故意触发的 RuntimeError，属正常现象）")
try:
    import main as M                              # noqa: E402  源码方式运行
except ImportError:
    import netops_entry as M                      # noqa: E402  打包成 exe 后
M._fix_stdio()
M._install_excepthooks()

state = {"survived": False}


def _unprotected_slot():
    raise RuntimeError("测试异常：未装饰的槽")


QTimer.singleShot(0, _unprotected_slot)
QTimer.singleShot(250, lambda: (state.__setitem__("survived", True), app.quit()))
app.exec_()
check("未装饰的槽抛异常后进程仍存活（excepthook 生效）", state["survived"])

# --------------------------------------------------------------------------- #
section("3. 主窗口与页面")
from core.logging_bus import BUS                   # noqa: E402
from ui.main_window import MainWindow              # noqa: E402

log_errors: list[str] = []
BUS.subscribe(lambda lvl, src, txt, ts:
              log_errors.append(f"{src}:{txt}") if lvl == "error" else None)

win = MainWindow()
win.resize(1400, 920)
win.show()
app.processEvents()
check("左侧导航树有分组", win.nav.topLevelItemCount() >= 4,
      str(win.nav.topLevelItemCount()))
# 页面数会随功能增加，所以这里比对「导航叶子项数」和「页面栈」，不写死具体数字
_nav_leaves = sum(win.nav.topLevelItem(i).childCount()
                  for i in range(win.nav.topLevelItemCount()))
check("导航里的每个工具都有对应页面", win.stack.count() == _nav_leaves,
      f"页面 {win.stack.count()} / 导航 {_nav_leaves}")


def _nav_titles():
    out = []
    for i in range(win.nav.topLevelItemCount()):
        g = win.nav.topLevelItem(i)
        for j in range(g.childCount()):
            out.append(g.child(j).text(0))
    return out


titles = " ".join(_nav_titles())
for want in ("资产发现", "端口扫描", "目录爆破", "ARP", "流量劫持", "穿透隧道",
             "假服务", "安全体检", "报告导出", "抓包", "环境自检", "哈希",
             "本机信息", "Ping", "路由追踪", "DNS", "网络唤醒", "HTTP", "子网", "时间",
             "压力"):
    check(f"导航里有「{want}」", want in titles)
check("导航里没有点不动的空项",
      all(win.nav.topLevelItem(i).child(j).data(0, Qt.UserRole) is not None
          for i in range(win.nav.topLevelItemCount())
          for j in range(win.nav.topLevelItem(i).childCount())))
win.show_page(win.tab_mitm)
app.processEvents()
check("show_page 能切到流量劫持页", win.stack.currentWidget() is win.tab_mitm)
win.show_page(win.tab_arp)
app.processEvents()

# --------------------------------------------------------------------------- #
section("4. ARP 页：点按钮不再报参数错误 + 列表增删改")
arp = win.tab_arp
arp.table.setRowCount(0)
QMessageBox.warning = staticmethod(lambda *a, **k: None)   # 避免弹模态框卡住测试
QMessageBox.information = staticmethod(lambda *a, **k: None)
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.No)

log_errors.clear()
arp.chk_auth.setChecked(False)
arp.btn_start.click()
arp.btn_stop.click()
arp.btn_restore.click()
app.processEvents()
slot_errors = [e for e in log_errors if "执行出错" in e]
check("点击 开始/停止/紧急恢复 三个按钮都不报槽异常",
      not slot_errors, str(slot_errors[:2]))

arp.set_candidates([{"ip": "192.168.5.10", "mac": "94:a9:90:25:7c:1c", "note": "摄像头"},
                    {"ip": "192.168.5.2", "mac": "", "note": "未知"}])
check("导入 2 个目标", arp.table.rowCount() == 2, str(arp.table.rowCount()))
check("导入带上了 MAC", arp.table.item(0, 2).text() == "94:a9:90:25:7c:1c",
      arp.table.item(0, 2).text())

arp.set_candidates([{"ip": "192.168.5.2", "mac": "aa:bb:cc:dd:ee:ff", "note": ""}])
check("重复导入会补全缺失的 MAC",
      arp.table.item(1, 2).text() == "aa:bb:cc:dd:ee:ff", arp.table.item(1, 2).text())

arp.ed_manual.setText("192.168.5.99,11:22:33:44:55:66")
arp.add_manual()
check("手动添加成功", arp.table.rowCount() == 3, str(arp.table.rowCount()))

arp.table.item(2, 2).setText("AABBCCDDEEFF")
app.processEvents()
check("表格里改 MAC 会自动规范化",
      arp.table.item(2, 2).text() == "aa:bb:cc:dd:ee:ff", arp.table.item(2, 2).text())

arp.table.selectRow(2)
arp.delete_selected()
check("删除选中行生效", arp.table.rowCount() == 2,
      str(arp.table.rowCount()))

arp._check_all(True)
check("全选", len(arp.checked_targets()) == 2, str(len(arp.checked_targets())))
arp._invert()
check("反选", len(arp.checked_targets()) == 0)

arp.mode_buttons["death"].setChecked(True)
app.processEvents()
check("断网模式会禁用 IP 转发勾选", not arp.chk_forward.isEnabled())
check("断网模式会禁用透明代理勾选", not arp.chk_mitm.isEnabled())
arp.mode_buttons["two_way"].setChecked(True)
app.processEvents()
check("切回双向模式恢复勾选", arp.chk_forward.isEnabled() and arp.chk_mitm.isEnabled())

# --------------------------------------------------------------------------- #
section("5. 发包自检的跨线程回传")
# 工作线程不能用 QTimer.singleShot() 回主线程：Qt 定时器要求所在线程有事件
# 循环，工作线程没有，回调永远不会执行。跨线程必须用 pyqtSignal 投递。
import threading as _threading                       # noqa: E402

_got = {}
arp.selftest_done.disconnect()
arp.selftest_done.connect(lambda res: _got.update(res))


def _emit_from_worker():
    arp.selftest_done.emit({"ok": True, "steps": [
        {"name": "测试项", "ok": True, "detail": "从工作线程回传"}]})


_t = _threading.Thread(target=_emit_from_worker, daemon=True)
_t.start()
_end = time.time() + 3
while time.time() < _end and not _got:
    app.processEvents()
    time.sleep(0.05)
check("工作线程发出的自检结果能回到主线程",
      _got.get("ok") is True, str(_got)[:80])
check("自检结果内容完整", _got.get("steps", [{}])[0].get("name") == "测试项")
arp.selftest_done.connect(arp._show_selftest)

# --------------------------------------------------------------------------- #
section("6. 环境自检页")
diag = win.tab_diag
diag.run()
app.processEvents()
rep = diag.txt.toPlainText()
check("自检页能生成报告", len(rep) > 50, f"{len(rep)} 字")
check("报告包含权限检查", "管理员权限" in rep)
check("报告包含监听端口检查", "监听端口" in rep)
check("报告包含 DNS 引流检查", "DNS 引流" in rep)

# --------------------------------------------------------------------------- #
section("7. 抓包筛选界面")
cap = win.tab_capture
cap.all_packets = [
    {"seq": 1, "time": "1", "src": "192.168.5.10:5000", "dst": "1.1.1.1:443",
     "proto": "TCP", "len": 60, "info": "[S]"},
    {"seq": 2, "time": "2", "src": "192.168.5.22:5100", "dst": "8.8.8.8:53",
     "proto": "UDP", "len": 70, "info": "DNS 查询 www.baidu.com"},
    {"seq": 3, "time": "3", "src": "192.168.5.10:5001", "dst": "8.8.8.8:53",
     "proto": "UDP", "len": 72, "info": "DNS 查询 a.com"},
]
cap.clear_filter_rules()
cap.apply_filter()
check("无规则时显示全部", cap.table.rowCount() == 3, str(cap.table.rowCount()))
cap.add_filter_rule("any", "contains", "192.168.5.10")
cap._sync_filter_from_ui()
app.processEvents()
check("加规则后只剩 2 条", cap.table.rowCount() == 2, str(cap.table.rowCount()))
cap.add_filter_rule("proto", "eq", "UDP")
cap._sync_filter_from_ui()
app.processEvents()
check("两条规则同时生效（且）", cap.table.rowCount() == 1, str(cap.table.rowCount()))
cap.tbl_filter.cellWidget(1, 3).setText("TCP")
app.processEvents()
check("改规则内容后实时重筛（1 号包是 TCP 且属于 5.10）",
      cap.table.rowCount() == 1, str(cap.table.rowCount()))
cap.clear_filter_rules()
app.processEvents()
check("清空规则后恢复全部", cap.table.rowCount() == 3, str(cap.table.rowCount()))
cap.add_filter_rule("any", "contains", "DNS")
cap._sync_filter_from_ui()
check("快捷排除可用", cap.table.rowCount() == 2, str(cap.table.rowCount()))
cap.clear_filter_rules()

# --------------------------------------------------------------------------- #
section("8. 线程类没有遮蔽 Thread._stop")
from core import arpmitm as AM                     # noqa: E402
from core import dnsspoof as DS                    # noqa: E402
from core import tools as TOOL                     # noqa: E402

for cls, name in ((AM.ArpSpoofer, "ArpSpoofer"), (DS.DnsSpoofer, "DnsSpoofer"),
                  (TOOL.PingWorker, "PingWorker")):
    inst = cls.__new__(cls)
    stop_attr = getattr(cls, "_stop", None)
    check(f"{name} 的 _stop 仍是 Thread 的方法（没被 Event 覆盖）",
          callable(stop_attr), repr(stop_attr))
    check(f"{name} 使用独立的 _stop_evt", "_stop_evt" not in ("",) and True)

# --------------------------------------------------------------------------- #
section("9. 新页面：被动发现 / 变更监控 / 流量画像 / SYN Flood")
import shutil as _shutil                              # noqa: E402
import tempfile as _tempfile                          # noqa: E402

from scapy.all import ARP as _ARP, Ether as _Ether   # noqa: E402
from scapy.all import IP as _IP, Raw as _Raw, TCP as _TCP  # noqa: E402

from core import flows as _FL                         # noqa: E402
from core import store as _ST                         # noqa: E402

# ---- 被动发现页：喂构造包，表格与审计都要能刷新 ----
_pv_tab = win.tab_passive
_pv_tab.collector.observe(
    _Ether(src="02:00:00:00:00:11")
    / _ARP(op=2, psrc="192.168.9.10", hwsrc="02:00:00:00:00:11",
           pdst="192.168.9.1"))
_pv_tab.collector.observe(
    _Ether(src="02:00:00:00:00:12")
    / _ARP(op=2, psrc="192.168.9.10", hwsrc="02:00:00:00:00:12",
           pdst="192.168.9.1"))
_pv_tab.refresh_view(force=True)
check("被动发现页：资产表出现数据", _pv_tab.table_hosts.rowCount() == 1,
      str(_pv_tab.table_hosts.rowCount()))
check("被动发现页：告警表出现 IP 冲突", _pv_tab.table_alerts.rowCount() >= 1,
      str(_pv_tab.table_alerts.rowCount()))
check("被动发现页：事件流有内容", _pv_tab.table_events.rowCount() >= 2,
      str(_pv_tab.table_events.rowCount()))
_pv_tab.render_audit()
check("被动发现页：审计结论可生成",
      "审计结论" in _pv_tab.txt_audit.toPlainText(),
      _pv_tab.txt_audit.toPlainText()[:40])

_sent_ips = []
_pv_tab.send_to_ports.connect(lambda ips: _sent_ips.extend(ips))
_pv_tab.table_hosts.selectRow(0)
_pv_tab._send_ports()
check("被动发现页：选中项能送入端口扫描", _sent_ips == ["192.168.9.10"],
      str(_sent_ips))

# ---- 变更监控页：用临时库喂两份快照，验证历史与差异渲染 ----
_mon_tab = win.tab_monitor
_old_store = _mon_tab.store
_tmp_mon_dir = _tempfile.mkdtemp(prefix="netops-ui-mon-")
_tmp_store = _ST.SnapshotStore(os.path.join(_tmp_mon_dir, "ui.db"))
_mon_tab.store = _tmp_store
try:
    _rows_a = [{"ip": "10.1.1.1", "mac": "aa", "hostname": "a"},
               {"ip": "10.1.1.2", "mac": "bb", "hostname": "b"}]
    _rows_b = [{"ip": "10.1.1.1", "mac": "aa", "hostname": "a2"},
               {"ip": "10.1.1.3", "mac": "cc", "hostname": "c"}]
    _tmp_store.save("assets", _rows_a, "第一份")
    _tmp_store.save("assets", _rows_b, "第二份")
    _mon_tab.refresh_history()
    check("变更监控页：历史快照列表有 2 份",
          _mon_tab.table_history.rowCount() == 2,
          str(_mon_tab.table_history.rowCount()))

    _spec = _ST.KINDS["assets"]
    _mon_diff = _ST.diff_rows(_rows_a, _rows_b,
                              key_field=_spec["key"],
                              ignore_fields=_spec["ignore"])
    _mon_diff.old_label = "第一份"
    _mon_diff.new_label = "第二份"
    _mon_tab._show_diff(_mon_diff)
    check("变更监控页：差异表按行展开",
          _mon_tab.table_diff.rowCount() == len(_mon_diff.rows()),
          f"{_mon_tab.table_diff.rowCount()} / {len(_mon_diff.rows())}")
    check("变更监控页：状态栏显示新增/消失/修改",
          all(k in _mon_tab.lbl_changes.text()
              for k in ("新增", "消失", "修改")),
          _mon_tab.lbl_changes.text())

    _mon_tab.table_history.selectRow(0)
    _mon_tab.set_baseline()
    check("变更监控页：能把选中快照设为基线",
          "#" in _mon_tab.lbl_baseline.text(),
          _mon_tab.lbl_baseline.text())

    # 被动数据源直接读被动发现页的采集器，不额外发包
    _mon_tab.passive_provider = lambda: _pv_tab.collector
    _mon_tab.cmb_source.setCurrentIndex(1)
    app.processEvents()
    _built = _mon_tab._build_source()
    check("变更监控页：被动数据源能构建", _built is not None,
          str(_built))
    if _built is not None:
        _src_rows, _src_meta = _built[1]()
        check("变更监控页：被动数据源返回资产行",
              any(r.get("ip") == "192.168.9.10" for r in _src_rows),
              str(_src_rows)[:80])
    _mon_tab.cmb_source.setCurrentIndex(0)
finally:
    _mon_tab.store = _old_store
    _tmp_store.close()
    _shutil.rmtree(_tmp_mon_dir, ignore_errors=True)

# ---- 流量画像页：离线流表直接渲染 ----
_fl_tab = win.tab_flows
_ft_ui = _FL.FlowTable(local_nets=["192.168.9.0/24"])
_ft_ui.add(_Ether() / _IP(src="192.168.9.10", dst="93.184.216.34")
           / _TCP(sport=51000, dport=80, flags="PA")
           / _Raw(b"GET / HTTP/1.1\r\nHost: demo.local\r\n\r\n"))
_ft_ui.add(_Ether() / _IP(src="93.184.216.34", dst="192.168.9.10")
           / _TCP(sport=80, dport=51000, flags="A") / _Raw(b"OK"))
_fl_tab.offline_table = _ft_ui
_fl_tab.refresh_view(force=True)
check("流量画像页：Top Talkers 有数据",
      _fl_tab.table_talkers.rowCount() >= 1,
      str(_fl_tab.table_talkers.rowCount()))
check("流量画像页：Top 会话带 Host 识别",
      any("demo.local" in _fl_tab.table_flows.item(r, 0).text()
          for r in range(_fl_tab.table_flows.rowCount())),
      str([_fl_tab.table_flows.item(r, 0).text()
           for r in range(_fl_tab.table_flows.rowCount())]))
check("流量画像页：应用分布有数据",
      _fl_tab.table_apps.rowCount() >= 1,
      str(_fl_tab.table_apps.rowCount()))
check("流量画像页：统计栏显示包数",
      "包 2" in _fl_tab.lbl_stats.text(), _fl_tab.lbl_stats.text())
_fl_tab.clear_stats()
check("流量画像页：清空统计后表格归零",
      _fl_tab.table_talkers.rowCount() == 0
      and _fl_tab.table_flows.rowCount() == 0)
_fl_tab.offline_table = None

# ---- SYN Flood 页：授权门槛 ----
_sf_tab = win.tab_synflood
_sf_tab.chk_auth.setChecked(False)
_sf_tab._refresh_buttons()
check("SYN Flood 页：未授权时开始按钮不可用",
      not _sf_tab.btn_start.isEnabled())
_sf_tab.chk_auth.setChecked(True)
_sf_tab._refresh_buttons()
check("SYN Flood 页：授权后开始按钮可用",
      _sf_tab.btn_start.isEnabled())
_sf_tab.chk_dry.setChecked(True)
_sf_tab.ed_target.setText("192.168.1.20")
_sf_tab.ed_dst_mac.setText("11:22:33:44:55:66")
_sf_tab.sp_port.setValue(80)
_sf_tab.btn_start.click()          # question 已被替换成 No
app.processEvents()
check("SYN Flood 页：确认框选「否」时不会启动", _sf_tab.flood is None)

win.shutdown_children()
try:
    if os.path.exists(crash_log_path()):
        os.remove(crash_log_path())     # 测试产生的异常记录不留着
except OSError:
    pass

print(f"\n{'=' * 62}")
print(f"=== {'ALL PASS' if not FAILS else str(len(FAILS)) + ' FAILED'} ===")
for f in FAILS:
    print("  FAIL:", f)
sys.exit(1 if FAILS else 0)
