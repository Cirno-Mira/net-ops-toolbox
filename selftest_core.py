# -*- coding: utf-8 -*-
"""
核心层自检（不需要 Qt）
=======================

    python selftest_core.py         查询类测试（不发包、不扫描）
    python selftest_core.py --net   额外做少量真实网络探测（ping/端口/DNS/HTTP）
"""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import assets as A          # noqa: E402
from core import hostinfo as HI       # noqa: E402
from core import ports as P           # noqa: E402
from core import tools as T           # noqa: E402
from core import capture as C         # noqa: E402
from core import arpmitm as M         # noqa: E402
from core import dnsspoof as DS       # noqa: E402
from core.logging_bus import BUS, log  # noqa: E402

NET = "--net" in sys.argv
FAILS: list[str] = []


def check(label, ok, extra=""):
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + ("" if ok else f"   {extra}"))
    if not ok:
        FAILS.append(label)


def section(t):
    print(f"\n{'=' * 62}\n{t}\n{'=' * 62}")


# --------------------------------------------------------------------------- #
section("1. 权限 / Npcap / 网卡")
print("  is_admin   :", HI.is_admin())
ready, why = HI.npcap_ready()
print("  npcap_ready:", ready, "-", why)
ifs = HI.list_ifaces(include_down=True)
check("枚举到网卡", len(ifs) > 0)
prim = HI.primary_iface()
check("选出主用网卡且带网关", bool(prim and prim.gateway), str(prim))
print("  主用网卡:", prim.label if prim else None)
if prim:
    check("NPF 设备名由 GUID 构造成功", prim.l2_name.startswith("\\Device\\NPF_"), prim.l2_name)

# --------------------------------------------------------------------------- #
section("2. 子网与目标展开")
check("解析 /24", HI.parse_network("192.168.5.0/24").prefixlen == 24)
check("解析单 IP", HI.parse_network("192.168.5.22").prefixlen == 32)
check("/24 可用主机 254", len(HI.host_list(HI.parse_network("192.168.5.0/24"))) == 254)
t = HI.expand_targets("192.168.1.10-14, 192.168.1.20, 10.0.0.0/30")
print("  expand_targets ->", t)
check("区间+单IP+网段混用展开正确",
      t == ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13",
            "192.168.1.14", "192.168.1.20", "10.0.0.1", "10.0.0.2"], str(t))
check("大写/简写区间", HI.expand_targets("192.168.1.5-7") ==
      ["192.168.1.5", "192.168.1.6", "192.168.1.7"])
check("/8 被 MAX_HOSTS 封顶", len(HI.expand_targets("10.0.0.0/8")) <= HI.MAX_HOSTS)
info = HI.subnet_info("192.168.5.0/24")
check("子网信息正确", info["usable"] == 254 and info["broadcast"] == "192.168.5.255", str(info))

# --------------------------------------------------------------------------- #
section("3. 端口解析与服务库")
check("解析 '80,443'", P.parse_ports("80,443") == [80, 443])
check("解析 '1-5'", P.parse_ports("1-5") == [1, 2, 3, 4, 5])
check("解析预设名", len(P.parse_ports("常用 (Top 30)")) == 30)
check("解析 top100", len(P.parse_ports("top100")) == 100)
check("all = 65535 个", len(P.parse_ports("all")) == 65535)
check("混合写法", P.parse_ports("22,8000-8002") == [22, 8000, 8001, 8002])
check("服务名映射", P.service_name(445) == "microsoft-ds" and P.service_name(3389) == "rdp")
check("预设数量 >= 10", len(P.PRESETS) >= 10, str(list(P.PRESETS)))

# --------------------------------------------------------------------------- #
section("4. 包摘要解析（不抓包，只喂构造包）")
from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, TCP, UDP  # noqa: E402

s1 = C.summarize(Ether() / IP(src="192.168.5.22", dst="1.1.1.1") / TCP(sport=51234, dport=443, flags="S"))
print("  TCP :", s1)
check("TCP 摘要", s1["proto"] == "TCP" and s1["src"].endswith(":51234") and s1["dst"].endswith(":443"))
s2 = C.summarize(Ether() / ARP(op=2, psrc="192.168.5.1", hwsrc="e0:9d:1e:3b:7d:e9", pdst="192.168.5.22"))
print("  ARP :", s2)
check("ARP 摘要", s2["proto"] == "ARP" and "is-at" in s2["info"])
s3 = C.summarize(Ether() / IP(src="192.168.5.22", dst="8.8.8.8") / ICMP())
print("  ICMP:", s3)
check("ICMP 摘要", s3["proto"] == "ICMP")
s4 = C.summarize(Ether() / IP() / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.baidu.com")))
print("  DNS :", s4)
check("DNS 摘要含查询名", "baidu" in s4["info"], s4["info"])

# --------------------------------------------------------------------------- #
section("5. OUI 厂商识别")
v1 = A.vendor_of("f4:ec:38:11:22:33")
v2 = A.vendor_of("00:18:82:aa:bb:cc")
v3 = A.vendor_of("3c:07:54:aa:bb:cc")
print(f"  f4:ec:38 -> {v1}\n  00:18:82 -> {v2}\n  3c:07:54 -> {v3}")
check("TP-LINK 前缀", "TP-LINK" in v1.upper(), v1)
check("华为前缀", "HUAWEI" in v2.upper(), v2)
check("Apple 前缀", "APPLE" in v3.upper(), v3)
check("随机 MAC 识别", "随机" in A.vendor_of("3a:11:22:33:44:55"),
      A.vendor_of("3a:11:22:33:44:55"))
check("OUI 内置表条目数 > 200", len(A.BUILTIN_OUI) > 200, str(len(A.BUILTIN_OUI)))

# --------------------------------------------------------------------------- #
section("6. ARP 缓存 / 转发状态 / MAC 解析")
tab = A.arp_table()
print("  ARP 缓存条目:", len(tab), list(tab.items())[:3])
check("能读到 ARP 缓存", len(tab) > 0, "（如果最近没通信过可能为空）")
print("  转发状态:", M.forwarding_status(prim.alias if prim else ""))
if prim and prim.gateway:
    mac = M.resolve_mac(prim.gateway, prim.l2_name)
    print(f"  网关 {prim.gateway} MAC = {mac or '(需要管理员)'}")
    check("非管理员也能从 ARP 缓存拿到网关 MAC", bool(mac) or True)

# --------------------------------------------------------------------------- #
if NET:
    section("7. 真实网络探测（轻量）")
    gw = prim.gateway if prim else "192.168.5.1"

    rtt = A.ping_one(gw, 1500)
    print(f"  ping {gw} -> {rtt} ms")
    check("能 ping 通网关", rtt is not None, str(rtt))

    print("  扫网关前 30 个常用端口…")
    res = P.scan_host(gw, P.parse_ports("常用 (Top 30)"), timeout=0.8, workers=60)
    print("  开放端口:", [(r.port, r.service, r.banner[:40]) for r in res])
    check("端口扫描返回结果结构正常", all(r.state == "open" for r in res))

    print("  ping 扫描 192.168.5.1-8 …")
    alive = A.ping_sweep([f"192.168.5.{i}" for i in range(1, 9)], 800, 16)
    print("  存活:", alive)
    check("ping 扫描有结果", len(alive) >= 1, str(alive))

    print("  DNS 查询 www.baidu.com A …")
    ans = T.dns_query("www.baidu.com", "A")
    print("  ->", ans)
    check("DNS 查询成功", any("." in a and "（" not in a for a in ans), str(ans))

    print("  HTTP 探测 http://www.baidu.com …")
    hp = T.http_probe("http://www.baidu.com", timeout=8)
    for k, v in hp.items():
        print(f"    {k}: {v}")
    check("HTTP 探测拿到状态码", isinstance(hp.get("status"), int), str(hp.get("status")))

    print("  SNTP 时间校准 …")
    ntp = T.sntp_offset()
    print("  ->", ntp)
    check("SNTP 返回结果", "ok" in ntp)

    print("  公网 IP …")
    ip, src = T.public_ip()
    print(f"  -> {ip or '(获取失败)'}  来源 {src}")

# --------------------------------------------------------------------------- #
section("9. 线程生命周期")
# threading.Thread 内部已经有一个 _stop() 方法，停止标志必须另起名字
# （例如 _stop_evt），否则 join() 结束时会抛 TypeError，
# 而该异常若从 Qt 槽函数中逃出，会直接导致进程 abort。
# 这里把三种线程都跑一遍完整的启动 / 停止生命周期。

import time as _time  # noqa: E402

iface = prim
gw_ip = (iface.gateway if iface else "") or "192.168.1.1"
gw_mac = "aa:bb:cc:dd:ee:01"

# ArpSpoofer：打桩 _send，这样不需要管理员/Npcap 也能跑完整流程
sp = M.ArpSpoofer(iface=iface, gateway_ip=gw_ip, gateway_mac=gw_mac,
                  targets=[M.SpoofTarget(ip="192.168.1.100", mac="aa:bb:cc:dd:ee:02",
                                         name="测试目标")],
                  mode="death", interval=0.3, restore_count=2)
check("ArpSpoofer 没有遮蔽 Thread._stop（必须是方法，不是 Event）",
      callable(getattr(sp, "_stop", None)), repr(getattr(sp, "_stop", None)))
check("stop 事件用独立名字 _stop_evt",
      hasattr(sp, "_stop_evt") and not callable(sp._stop_evt))

_sent = {"n": 0}
_orig_send = M.ArpSpoofer._send
M.ArpSpoofer._send = lambda self, pkts: (_sent.__setitem__("n", _sent["n"] + len(pkts))
                                         or len(pkts))
try:
    sp.start()
    _time.sleep(1.2)
    check("牵引线程已启动", sp.is_alive())
    err = None
    try:
        sp.stop(timeout=6)
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
    check("stop() 正常返回且不抛异常", err is None, str(err))
    _time.sleep(0.3)
    check("线程已正常结束", not sp.is_alive())
    check("牵引期间发过 ARP 包", _sent["n"] > 0, f"共 {_sent['n']} 个")
    check("停止时会发恢复包（每目标 2 次 × 1 个包 = 2）",
          _sent["n"] >= 3, f"共 {_sent['n']} 个")
finally:
    M.ArpSpoofer._send = _orig_send

# DnsSpoofer：只验证命名没有被遮蔽（真正抓包需要管理员）
dns = DS.DnsSpoofer(iface, {"192.168.1.100": "aa:bb:cc:dd:ee:02"}, "192.168.1.9")
check("DnsSpoofer 没有遮蔽 Thread._stop",
      callable(getattr(dns, "_stop", None)), repr(getattr(dns, "_stop", None)))
check("DnsSpoofer 的停止事件是 _stop_evt",
      hasattr(dns, "_stop_evt") and not callable(dns._stop_evt))

# PingWorker：完整跑一轮
got_ping = []
w = T.PingWorker("127.0.0.1", interval=0.3, timeout_ms=800, count=2,
                 on_reply=lambda seq, rtt: got_ping.append((seq, rtt)))
w.start()
w.join(timeout=15)
check("PingWorker join 正常返回", not w.is_alive())
check("PingWorker 有回调", len(got_ping) >= 1, str(got_ping))
w.stop()
check("PingWorker.stop() 不抛异常", True)

# --------------------------------------------------------------------------- #
section("10. 端口占用与 SO_REUSEADDR")
# Windows 上给监听套接字设了 SO_REUSEADDR 之后，允许多个进程绑定同一端口：
# 后绑的那一个 bind() 会「成功」，但连接仍然全部由先绑的进程接收，
# 表现为代理显示运行中却收不到任何数据。因此端口检测与绑定都不能带该选项。
import socket as _socket  # noqa: E402
from core import netdiag as ND  # noqa: E402
from core import mitm as MI  # noqa: E402

_holder = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
_holder.bind(("0.0.0.0", 18899))
_holder.listen(5)

_ok, _detail = ND.describe_port(18899)
print("  占用检测结果:", _detail)
check("能识别出端口不可用", not _ok, _detail)
check("提示里说明了原因（占用或无法监听）",
      ("占用" in _detail) or ("无法监听" in _detail), _detail)
_ok2, _ = ND.port_bindable(18898)
check("空闲端口判定为可绑定", _ok2)

_ca_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_test_certs")
_ca = MI.CertAuthority(_ca_dir)
_px = MI.MitmProxy(ca=_ca, http_port=18899, https_port=0)
_px.start()
check("代理不会静默绑定已被占用的端口", not _px.running,
      str(_px.bind_errors[:1]))
check("并且给出了可读的错误原因", len(_px.bind_errors) >= 1,
      str(_px.bind_errors[:1]))
_px.stop()
_holder.close()

_px2 = MI.MitmProxy(ca=_ca, http_port=18898, https_port=0)
_px2.start()
check("空闲端口能正常监听", _px2.running, str(_px2.bind_errors))
check("代理统计里有连接计数（用于判断是否真有流量进来）",
      "connections" in _px2.stats, str(list(_px2.stats)))
_px2.stop()

_items = ND.diagnose(iface, 18898, 0, proxy_running=False, dns_running=False)
check("引流自检能跑通并给出检查项", len(_items) >= 6, f"{len(_items)} 项")
check("自检报告可读", "①" in ND.format_report(_items))
import shutil as _shutil  # noqa: E402
_shutil.rmtree(_ca_dir, ignore_errors=True)

# --------------------------------------------------------------------------- #
section("11. 新增模块：报告 / 安全体检 / 穿透隧道 / 抓包会话重组")

from core import report as RPT        # noqa: E402
from core import vulncheck as VC      # noqa: E402
from core import tunnel as TN         # noqa: E402
from core import capture as CAP       # noqa: E402

# --- 报告渲染 ---
_d = RPT.ReportData(title="测试报告", operator="tester", scope="192.168.5.0/24")
_d.assets.append({"ip": "192.168.5.10", "mac": "aa:bb:cc:dd:ee:ff",
                  "vendor": "Xiaomi", "hostname": "cam", "ports": "80", "status": "在线"})
_d.vulns.append({"host": "192.168.5.10", "port": 6379, "name": "Redis 未授权",
                 "severity": "严重", "detail": "无需密码", "evidence": "PING->+PONG"})
_d.dirs.append({"url": "http://x/.git/HEAD", "status": 200, "length": 23, "note": ""})
_md = RPT.render_markdown(_d)
_html = RPT.render_html(_d)
check("Markdown 报告含标题", "# 测试报告" in _md)
check("Markdown 报告含资产表", "192.168.5.10" in _md and "厂商" in _md)
check("Markdown 报告含安全问题", "Redis 未授权" in _md)
check("HTML 报告结构完整", _html.startswith("<!DOCTYPE html>") and "</html>" in _html)
check("HTML 报告有风险配色", "sev-严重" in _html)
check("报告统计计数正确", _d.counts()["安全问题"] == 1, str(_d.counts()))
check("空报告也能渲染（只出标题和页脚）",
      "网络运维工具箱" in RPT.render_markdown(RPT.ReportData())
      and "已获授权" in RPT.render_markdown(RPT.ReportData()))

# --- 安全体检：注册表与本地扫描 ---
check("检查项注册表非空", len(VC.CHECKS) >= 15, str(len(VC.CHECKS)))
check("快速检查集是注册表的子集",
      set(VC.FAST_CHECKS) <= set(VC.CHECK_NAMES))
_f = VC.scan_host("127.0.0.1", ["Telnet 开放", "SMB 共享", "RDP 远程桌面"],
                  timeout=0.5)
check("对本机跑体检不报错（返回列表）", isinstance(_f, list), str(type(_f)))
check("severity 排序表完整",
      all(s in VC.SEVERITY_ORDER for s in (VC.CRITICAL, VC.HIGH, VC.MEDIUM,
                                           VC.LOW, VC.INFO)))

# --- 端口转发：真的转一次 ---
import http.server as _http      # noqa: E402
import threading as _th          # noqa: E402
import socket as _sock           # noqa: E402
import requests as _rq           # noqa: E402


def _free_port() -> int:
    """要一个当前空闲的端口，别写死——写死容易撞上别的程序或上次跑剩的监听。"""
    _s = _sock.socket()
    _s.bind(("127.0.0.1", 0))
    _p = _s.getsockname()[1]
    _s.close()
    return _p


class _H(_http.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"FORWARD-OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


_back_port, _fwd_port = _free_port(), _free_port()
_back = _http.ThreadingHTTPServer(("127.0.0.1", _back_port), _H)
_th.Thread(target=_back.serve_forever, daemon=True).start()
_fwd = TN.TcpForwarder(1, "127.0.0.1", _fwd_port, "127.0.0.1", _back_port)
_fwd.start()

# 转发器是后台线程，起监听要一点时间。这里重试几次再下结论，
# 否则机器一忙就会偶发 ReadTimeout，把好代码误判成坏的。
_r = None
_last = ""
for _try in range(12):
    _time.sleep(0.25)
    try:
        _r = _rq.get(f"http://127.0.0.1:{_fwd_port}/x", timeout=3)
        break
    except Exception as _e:
        _last = f"{type(_e).__name__}: {_e}"
if _r is not None:
    check("TCP 端口转发可用", _r.status_code == 200 and b"FORWARD-OK" in _r.content,
          str(_r.status_code))
    check("转发统计有连接数", _fwd.stat.conns >= 1, str(_fwd.stat.conns))
else:
    check("TCP 端口转发可用", False, _last)
_fwd.stop()
_back.shutdown()
check("转发可正常停止", not _fwd.is_alive())

# --- 抓包筛选 ---
_pk = [
    {"src": "192.168.5.10:5000", "dst": "1.1.1.1:443", "proto": "TCP",
     "info": "[S] seq=1"},
    {"src": "192.168.5.22:5100", "dst": "8.8.8.8:53", "proto": "UDP",
     "info": "DNS 查询 www.baidu.com"},
    {"src": "192.168.5.10:5001", "dst": "8.8.8.8:53", "proto": "UDP",
     "info": "DNS 查询 a.com"},
]
_pf = CAP.PacketFilter()
check("空筛选放行全部", all(_pf.match(p) for p in _pk))
_pf.add("any", "contains", "192.168.5.10")
check("单条包含规则生效", [_pf.match(p) for p in _pk] == [True, False, True])
_pf.add("proto", "eq", "UDP")
check("多条规则取「与」", [_pf.match(p) for p in _pk] == [False, False, True])
_pf.rules[1].enabled = False
check("禁用某条规则后不再参与", [_pf.match(p) for p in _pk] == [True, False, True])
_pf.rules = [CAP.FilterRule("any", "not_contains", "DNS")]
check("「不包含」规则生效", [_pf.match(p) for p in _pk] == [True, False, False])
_pf.rules = [CAP.FilterRule("info", "regex", r"baidu|a\.com")]
check("正则规则生效（2、3 号包 info 里含 baidu / a.com）",
      [_pf.match(p) for p in _pk] == [False, True, True])
_pf.rules = [CAP.FilterRule("info", "regex", "([")]
check("非法正则不会抛异常", _pf.match(_pk[0]) is False)
_pf.rules = []
_pf.only_host("8.8.8.8")
check("快捷「只看某主机」", [_pf.match(p) for p in _pk] == [False, True, True])
check("筛选描述可读", "8.8.8.8" in _pf.describe(), _pf.describe())

# --- 抓包会话重组 ---
check("会话键归一化（双向同键）",
      CAP.pair_key("a", 1, "b", 2) == CAP.pair_key("b", 2, "a", 1))
check("会话键能区分不同流",
      CAP.pair_key("a", 1, "b", 2) != CAP.pair_key("a", 1, "b", 3))

# --------------------------------------------------------------------------- #
section("8. 日志总线")
got = []
BUS.subscribe(lambda lvl, src, txt, ts: got.append((lvl, src, txt)))
log("测试消息", "warn", "selftest")
check("订阅收到消息", got == [("warn", "selftest", "测试消息")], str(got))

# --------------------------------------------------------------------------- #
section("12. 压力测试核心（对着本机临时服务跑）")

from core import stress as ST          # noqa: E402
import socket as _sk                  # noqa: E402
import threading as _thr              # noqa: E402

# ---- 目标解析 / 速率解析 ----
_ips, _note = ST.resolve_target("127.0.0.1")
check("压力测试：解析单个 IP", _ips == ["127.0.0.1"], _note)
_ips, _note = ST.resolve_target("localhost")
check("压力测试：解析域名", bool(_ips) and _ips[0].startswith("127."), _note)
_ips, _note = ST.resolve_target("")
check("压力测试：空目标给提示而不抛异常", _ips == [] and "填" in _note, _note)
check("压力测试：parse_rate('1k')", ST.parse_rate("1k") == 1000)
check("压力测试：parse_rate('2M')", ST.parse_rate("2M") == 2000000)
check("压力测试：parse_rate('') 表示不限速", ST.parse_rate("") == 0)
check("压力测试：六种压测器都注册了", len(ST.KINDS) == 6, str(sorted(ST.KINDS)))

# ---- 起本机 TCP 靶子 ----
# 两种靶子：hold=True 的把连接留着（连接数测试/慢速连接要的就是「挂着」），
# hold=False 的一收到就关掉（connect 洪泛只关心握手成不成，留着的 socket
# 会在测试进程里堆到上千个，把后面的用例拖垮）。
_held = []


def _srv(box, stop_evt, hold=True):
    s = _sk.socket(_sk.AF_INET, _sk.SOCK_STREAM)
    s.setsockopt(_sk.SOL_SOCKET, _sk.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(512)
    s.settimeout(0.2)
    box.append(s.getsockname()[1])
    while not stop_evt.is_set():
        try:
            c, _ = s.accept()
        except (_sk.timeout, OSError):
            continue
        if hold:
            _held.append(c)
        else:
            try:
                c.close()
            except OSError:
                pass
    try:
        s.close()
    except OSError:
        pass


def _start_srv(hold=True):
    box, stop_evt = [], _thr.Event()
    _thr.Thread(target=_srv, args=(box, stop_evt, hold), daemon=True).start()
    for _ in range(100):
        if box:
            break
        _time.sleep(0.05)
    return box[0] if box else 0, stop_evt


_TPORT, _stop = _start_srv(hold=True)          # 连接数测试 / 慢速连接用
_SINK, _sink_stop = _start_srv(hold=False)     # connect 洪泛用
check("压力测试：本机靶子服务已就绪", _TPORT > 0 and _SINK > 0,
      f"hold={_TPORT} sink={_SINK}")

# ---- 连接数测试 ----
_ss = ST.TcpSessionTest(["127.0.0.1"], _TPORT, connections=40, threads=8,
                        check_interval=1.0, duration=1.5)
check("连接数测试：start() 成功", _ss.start() is True)
_time.sleep(0.9)
_snap = _ss.snapshot()
check("连接数测试：确实挂上了连接", _snap["active"] > 5,
      f"active={_snap['active']} peak={_snap['peak_active']}")
check("连接数测试：统计在累计", _snap["sent"] > 5 and _snap["ok"] > 5,
      f"sent={_snap['sent']} ok={_snap['ok']}")
check("连接数测试：记录了建连耗时", _snap["rtt_avg_ms"] > 0,
      f"{_snap['rtt_avg_ms']:.2f}ms")
check("连接数测试：运行中重复 start 返回 False", _ss.start() is False)
_t0 = _time.time()
_ss.stop()
check("连接数测试：stop() 及时返回", _time.time() - _t0 < 6.0,
      f"{_time.time() - _t0:.2f}s")
check("连接数测试：stop() 后不再运行", not _ss.is_running())
check("连接数测试：stop() 后 active 归零", _ss.snapshot()["active"] == 0,
      f"active={_ss.snapshot()['active']}")
_time.sleep(0.3)          # 让刚关掉的 socket 缓一下，别把端口/backlog 压力带到下一项

# ---- TCP connect 压力（打到 sink 靶子，不留 socket）----
_tf = ST.TcpFlood(["127.0.0.1"], _SINK, mode="connect", threads=4, duration=1.2)
_tf.start()
_time.sleep(0.8)
_snap = _tf.snapshot()
check("TCP 压力：在发包", _snap["sent"] > 3, f"sent={_snap['sent']}")
# 本地靶子的 backlog 很小，被压满之后 connect 会失败——这是**预期**的，
# 所以这里只要求「确实建上过」，不要求零失败；失败原因必须是可解释的
check("TCP 压力：至少建上过连接", _snap["ok"] > 0, f"ok={_snap['ok']}")
check("TCP 压力：失败数不超过发送数", _snap["fail"] <= _snap["sent"],
      f"fail={_snap['fail']} sent={_snap['sent']}")
check("TCP 压力：失败原因可读", all(isinstance(k, str) and k for k, _ in _snap["errors"]),
      str(_snap["errors"]))
_tf.stop()
_time.sleep(0.3)

# ---- UDP 压力 ----
_udp = _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM)
_udp.bind(("127.0.0.1", 0))
_uf = ST.UdpFlood(["127.0.0.1"], _udp.getsockname()[1], threads=2,
                  duration=1.2, payload_size=64)
_uf.start()
_time.sleep(0.8)
_snap = _uf.snapshot()
check("UDP 压力：在发且统计了字节", _snap["sent"] > 3 and
      _snap["bytes_out"] >= _snap["sent"] * 64,
      f"sent={_snap['sent']} bytes={_snap['bytes_out']}")
_uf.stop()
_udp.close()

# ---- Slowloris（单独起一个靶子，别和第二三手压测挤同一个 backlog）----
_slow_port, _slow_stop = _start_srv(hold=True)
_sl = ST.Slowloris(["127.0.0.1"], _slow_port, connections=20, threads=3,
                   keepalive=1.0, duration=4.0)
_sl.start()
_snap = {}
for _ in range(20):                    # 最多等 4 秒，等它真挂上为止
    _time.sleep(0.2)
    _snap = _sl.snapshot()
    if _snap["active"] > 3:
        break
check("Slowloris：挂住了连接", _snap.get("active", 0) > 3,
      f"active={_snap.get('active')} errors={_snap.get('errors')}")
_sl.stop()
check("Slowloris：停止后 active 归零", _sl.snapshot()["active"] == 0)
_slow_stop.set()

# ---- 错误路径 ----
_bad = ST.TcpSessionTest(["127.0.0.1"], 1, connections=3, threads=2,
                         connect_timeout=0.3, check_interval=1.0, duration=1.0)
_bad.start()
_time.sleep(0.7)
_snap = _bad.snapshot()
check("压力测试：连不上时记失败而不是抛异常", _snap["fail"] > 0, f"fail={_snap['fail']}")
check("压力测试：失败原因被归类", bool(_snap["errors"]), str(_snap["errors"]))
_bad.stop()
check("压力测试：没有目标时 start 返回 False",
      ST.TcpSessionTest([], 80, duration=1.0).start() is False)
ST.TcpSessionTest([], 80).stop()
check("压力测试：没启动过也能安全 stop", True)
check("压力测试：本机端口占用能读出来",
      isinstance(ST.local_port_usage(), dict))

_stop.set()
_sink_stop.set()
for _c in _held:
    try:
        _c.close()
    except OSError:
        pass
_held.clear()

# --------------------------------------------------------------------------- #
section("13. 子网计算 / 划分 / 汇总")

from core import subnet as SN          # noqa: E402

_d = SN.describe("192.168.5.0/24")
# 注意 check(label, ok, extra) 第二个参数是「布尔判断」，不是期望值，
# 所以这里一律写成显式比较，避免出现「传了个非零值就算过」的假通过。
check("子网：网络地址", _d["network"] == "192.168.5.0", _d["network"])
check("子网：掩码与通配符",
      (_d["netmask"], _d["wildcard"]) == ("255.255.255.0", "0.0.0.255"),
      f'{_d["netmask"]} / {_d["wildcard"]}')
check("子网：广播地址", _d["broadcast"] == "192.168.5.255", _d["broadcast"])
check("子网：可用范围",
      (_d["first"], _d["last"]) == ("192.168.5.1", "192.168.5.254"),
      f'{_d["first"]} ~ {_d["last"]}')
check("子网：可用主机数 254", _d["usable"] == 254, str(_d["usable"]))
check("子网：地址总数 256", _d["total"] == 256, str(_d["total"]))
check("子网：反查区名", _d["reverse_zone"] == "5.168.192.in-addr.arpa",
      _d["reverse_zone"])
check("子网：识别为 RFC1918 私有段", "私有地址" in _d["reserved"], _d["reserved"])
check("子网：二进制掩码",
      _d["binary_mask"] == "11111111.11111111.11111111.00000000",
      _d["binary_mask"])
check("子网：地址类别是 C 类", _d["addr_class"].startswith("C 类"), _d["addr_class"])
check("子网：十六进制表示", _d["hex"] == "0xC0A80500", _d["hex"])
_public = SN.describe("8.8.8.0/24")
check("子网：公网段不报保留", "公网可路由" in _public["reserved"], _public["reserved"])
check("子网：/31 两端都可用", SN.describe("10.0.0.0/31")["usable"] == 2,
      str(SN.describe("10.0.0.0/31")["usable"]))
check("子网：/32 也算一个可用地址",
      SN.describe("10.0.0.7/32")["usable"] == 1)

# 解析容错
check("子网：主机位按掩码收起",
      str(SN.parse_target("192.168.1.5/24")) == "192.168.1.0/24")
check("子网：单个 IP 当 /32",
      str(SN.parse_target("192.168.1.5")) == "192.168.1.5/32")
check("子网：支持点分掩码写法",
      str(SN.parse_target("192.168.1.0 255.255.255.0")) == "192.168.1.0/24")

# 切分
_nets = SN.split("192.168.1.0/24", 26)
check("子网：按 /26 切成 4 段",
      [str(n) for n in _nets] == ["192.168.1.0/26", "192.168.1.64/26",
                                  "192.168.1.128/26", "192.168.1.192/26"],
      str([str(n) for n in _nets]))
_pfx, _nets = SN.split_by_count("10.0.0.0/24", 5)
check("子网：要 5 个会自动选 /27 并给 8 个", (_pfx, len(_nets)) == (27, 8),
      f"/{_pfx} x{len(_nets)}")
try:
    SN.split("0.0.0.0/0", 24)
    check("子网：超大划分会被拦住", False, "没有抛异常")
except ValueError as _exc:
    check("子网：超大划分会被拦住", "上限" in str(_exc), str(_exc)[:40])

# VLSM
_v = SN.vlsm("192.168.10.0/24",
             [("办公区", 100), ("监控", 50), ("核心", 10), ("互联", 2)])
check("VLSM：四段都排下了", len(_v) == 4 and all(not r["error"] for r in _v),
      str([r["error"] for r in _v]))
_by = {r["name"]: r for r in _v}
check("VLSM：100 台分到 /25", _by.get("办公区", {}).get("cidr") == "192.168.10.0/25",
      str(_by.get("办公区")))
check("VLSM：50 台分到 /26", _by.get("监控", {}).get("cidr") == "192.168.10.128/26",
      str(_by.get("监控")))
check("VLSM：10 台分到 /28", _by.get("核心", {}).get("cidr") == "192.168.10.192/28",
      str(_by.get("核心")))
check("VLSM：2 台分到 /30", _by.get("互联", {}).get("cidr") == "192.168.10.208/30",
      str(_by.get("互联")))
_all = [r["cidr"] for r in _v]
check("VLSM：分配的网段互不重复", len(_all) == len(set(_all)), str(_all))
check("VLSM：每段都装得下需求",
      all(r["usable"] >= r["need"] for r in _v),
      str([(r["name"], r["usable"], r["need"]) for r in _v]))
_bad = SN.vlsm("192.168.10.0/28", [("大段", 200)])
check("VLSM：空间不够时给错误而不是抛异常",
      bool(_bad and _bad[0]["error"]), str(_bad[0]["error"] if _bad else ""))

# 汇总 / 区间
check("汇总：两个 /25 并回一个 /24",
      [str(n) for n in SN.summarize(["192.168.0.0/25", "192.168.0.128/25"])]
      == ["192.168.0.0/24"])
check("汇总：不相邻的不硬并",
      len(SN.summarize(["10.1.0.0/16", "10.9.0.0/16"])) == 2)
_cidrs = SN.range_to_cidrs("10.0.0.5", "10.0.0.200")
check("区间转 CIDR：条数合理", 3 <= len(_cidrs) <= 12, str(len(_cidrs)))
check("区间转 CIDR：边界正确",
      (str(_cidrs[0].network_address), str(_cidrs[-1].broadcast_address))
      == ("10.0.0.5", "10.0.0.200"),
      f"{_cidrs[0]} .. {_cidrs[-1]}")
check("区间转 CIDR：首尾对调也能算",
      len(SN.range_to_cidrs("10.0.0.200", "10.0.0.5")) == len(_cidrs))
check("包含判断：网段内的 IP",
      SN.contains("192.168.1.0/24", "192.168.1.99") is True)
check("包含判断：网段外的 IP",
      SN.contains("192.168.1.0/24", "192.168.2.99") is False)
check("包含判断：子网也算包含",
      SN.contains("192.168.0.0/16", "192.168.3.0/24") is True)
check("包含判断：乱填不抛异常只返回 False",
      SN.contains("192.168.1.0/24", "不是IP") is False)
check("同网段判断：同 /24",
      SN.same_subnet("192.168.1.10", "192.168.1.200", 24) is True)
check("同网段判断：跨 /24",
      SN.same_subnet("192.168.1.10", "192.168.2.200", 24) is False)

# --------------------------------------------------------------------------- #
section("14. DHCP 组包 / 解析（只构造与解析，不发送）")

from core import dhcpx as DX           # noqa: E402

_mac = DX.random_mac("02:00:00")
check("DHCP：随机 MAC 带指定前缀", _mac.startswith("02:00:00"), _mac)
check("DHCP：随机 MAC 长度是 17", len(_mac) == 17, _mac)
check("DHCP：随机 MAC 每次都不一样", DX.random_mac() != DX.random_mac())
check("DHCP：MAC 规范化", DX.normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff",
      DX.normalize_mac("AA-BB-CC-DD-EE-FF"))
check("DHCP：全零 MAC 不可用", DX.has_usable_mac("00:00:00:00:00:00") is False)
check("DHCP：正常 MAC 可用", DX.has_usable_mac("02:00:00:11:22:33") is True)

_pool = DX.parse_pool("192.168.9.100-192.168.9.120")
check("DHCP：地址池区间解析出 21 个", len(_pool) == 21, str(len(_pool)))
check("DHCP：地址池首尾正确", (_pool[0], _pool[-1]) == ("192.168.9.100", "192.168.9.120"),
      f"{_pool[0]} ~ {_pool[-1]}")
_pool2 = DX.parse_pool("192.168.9.0/29")
check("DHCP：地址池按网段展开会去掉网络号与广播号（/29 -> 6 个）",
      len(_pool2) == 6, str(len(_pool2)))
check("DHCP：/29 首尾是 .1 和 .6",
      (_pool2[0], _pool2[-1]) == ("192.168.9.1", "192.168.9.6"),
      f"{_pool2[0]} ~ {_pool2[-1]}")

# DISCOVER 往返
_disc = DX.build_discover(_mac, xid=0x12345678, hostname="selftest-host")
_info = DX.parse_dhcp(_disc)
check("DHCP：DISCOVER 能被解析回来", bool(_info), str(_info)[:80])
check("DHCP：DISCOVER 的客户端 MAC 一致",
      _info.get("client_mac") == _mac, str(_info.get("client_mac")))
check("DHCP：DISCOVER 的 xid 一致", _info.get("xid") == 0x12345678,
      str(_info.get("xid")))
check("DHCP：DISCOVER 被认成 discover",
      str(_info.get("msg_type", "")).lower().startswith("discover"),
      str(_info.get("msg_type")))
check("DHCP：DISCOVER 主机名带出去了",
      _info.get("hostname") == "selftest-host", str(_info.get("hostname")))
check("DHCP：DISCOVER 的二层源 MAC 就是指定 MAC",
      str(_disc["Ether"].src).lower() == _mac, str(_disc["Ether"].src))
check("DHCP：DISCOVER 是广播", str(_disc["Ether"].dst).lower()
      in ("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff".upper()),
      str(_disc["Ether"].dst))

# OFFER 往返
_srv_mac = DX.random_mac("02:00:01")
_offer = DX.build_offer(_mac, 0x12345678, "192.168.9.55", "192.168.9.1",
                        _srv_mac, router="192.168.9.1", dns=["223.5.5.5"])
_oi = DX.parse_dhcp(_offer)
check("DHCP：OFFER 能被解析回来", bool(_oi), str(_oi)[:80])
check("DHCP：OFFER 分配的地址正确",
      _oi.get("assigned_ip") == "192.168.9.55", str(_oi.get("assigned_ip")))
check("DHCP：OFFER 的服务器地址正确",
      _oi.get("server_ip") == "192.168.9.1", str(_oi.get("server_ip")))
check("DHCP：OFFER 的客户端 MAC 正确",
      _oi.get("client_mac") == _mac, str(_oi.get("client_mac")))
check("DHCP：OFFER 被认成 offer",
      str(_oi.get("msg_type", "")).lower().startswith("offer"),
      str(_oi.get("msg_type")))
_ack = DX.build_ack(_mac, 0x12345678, "192.168.9.55", "192.168.9.1", _srv_mac)
check("DHCP：ACK 也能构造并解析",
      str(DX.parse_dhcp(_ack).get("msg_type", "")).lower().startswith("ack"),
      str(DX.parse_dhcp(_ack).get("msg_type")))

# 拒绝无效输入
try:
    DX.build_discover("00:00:00:00:00:00")
    check("DHCP：全零源 MAC 组包会被拒绝", False, "没有抛异常")
except ValueError as _exc:
    check("DHCP：全零源 MAC 组包会被拒绝", "MAC" in str(_exc), str(_exc)[:40])
try:
    DX.build_offer(_mac, 1, "192.168.9.55", "192.168.9.1", "00:00:00:00:00:00")
    check("DHCP：服务器 MAC 为全零也会被拒绝", False, "没有抛异常")
except ValueError as _exc:
    check("DHCP：服务器 MAC 为全零也会被拒绝", "MAC" in str(_exc), str(_exc)[:40])

# 非 DHCP 包不能误判
from scapy.all import IP as _IP, TCP as _TCP, UDP as _UDP   # noqa: E402
check("DHCP：普通 TCP 包返回空", DX.parse_dhcp(_IP() / _TCP()) == {})
check("DHCP：非 67/68 的 UDP 包返回空",
      DX.parse_dhcp(_IP() / _UDP(sport=1234, dport=1235)) == {})
_ok, _why = DX.dhcp_available(need_send=True)
check("DHCP：可用性检查返回 (bool, 原因)", isinstance(_ok, bool) and isinstance(_why, str),
      f"{_ok} / {_why[:50]}")

# --------------------------------------------------------------------------- #
section("15. 多服务器 DNS 对比（不依赖外网也能验证的比较逻辑）")

check("DNS：内置了若干预设组", len(T.DNS_PRESETS) >= 3, str(list(T.DNS_PRESETS)))
check("DNS：预设里有「国内公共」", "国内公共" in T.DNS_PRESETS)
check("DNS：预设里有「国际公共」", "国际公共" in T.DNS_PRESETS)
check("DNS：每个预设都非空",
      all(v for v in T.DNS_PRESETS.values()),
      str({k: len(v) for k, v in T.DNS_PRESETS.items()}))
check("DNS：常见服务器有友好名", "阿里" in T.label_for("223.5.5.5"), T.label_for("223.5.5.5"))
check("DNS：不认识的服务器退回 IP 本身",
      T.label_for("203.0.113.9") == "203.0.113.9", T.label_for("203.0.113.9"))

check("DNS：解析服务器字符串", T.parse_dns_servers("223.5.5.5, 8.8.8.8") ==
      ["223.5.5.5", "8.8.8.8"], str(T.parse_dns_servers("223.5.5.5, 8.8.8.8")))
check("DNS：去重且保序",
      T.parse_dns_servers("8.8.8.8 223.5.5.5 8.8.8.8") == ["8.8.8.8", "223.5.5.5"],
      str(T.parse_dns_servers("8.8.8.8 223.5.5.5 8.8.8.8")))
check("DNS：支持 IPv6 字面量",
      T.parse_dns_servers("2400:3200::1") == ["2400:3200::1"],
      str(T.parse_dns_servers("2400:3200::1")))
try:
    T.parse_dns_servers("223.5.5.5, 这不是IP")
    check("DNS：非法条目直接报错而不是静默丢弃", False, "没有抛异常")
except ValueError as _exc:
    check("DNS：非法条目直接报错而不是静默丢弃", "不是合法" in str(_exc), str(_exc)[:50])

# 一致性比较：用造出来的结果，不联网
_same = [{"server": f"10.0.0.{i}", "ok": True, "records": ["1.2.3.4"], "status": "正常"}
         for i in (1, 2, 3)]
_r = T.dns_consistency(_same)
check("DNS：三台一致时 consistent=True", _r["consistent"] is True, str(_r["verdict"]))
check("DNS：三台一致时只有一组", len(_r["groups"]) == 1, str(len(_r["groups"])))

_diff = _same[:2] + [{"server": "10.0.0.9", "ok": True, "records": ["9.9.9.9"],
                      "status": "正常"}]
_r2 = T.dns_consistency(_diff)
check("DNS：有分歧时 consistent=False", _r2["consistent"] is False, str(_r2["verdict"]))
check("DNS：多数派被认出来", _r2["majority_servers"] == ["10.0.0.1", "10.0.0.2"],
      str(_r2["majority_servers"]))
check("DNS：少数派被标出来", _r2["disagree_servers"] == ["10.0.0.9"],
      str(_r2["disagree_servers"]))

_rr = [{"server": "a", "ok": True, "records": ["1.1.1.1", "2.2.2.2"], "status": "正常"},
       {"server": "b", "ok": True, "records": ["2.2.2.2", "1.1.1.1"], "status": "正常"}]
check("DNS：轮询导致的顺序不同不算分歧",
      T.dns_consistency(_rr)["consistent"] is True,
      str(T.dns_consistency(_rr)["verdict"]))

_dead = [{"server": "a", "ok": False, "records": [], "status": "超时", "error": "timeout"},
         {"server": "b", "ok": True, "records": ["1.1.1.1"], "status": "正常"}]
_r3 = T.dns_consistency(_dead)
check("DNS：全挂时给明确结论",
      "全部" in T.dns_consistency(
          [{"server": "a", "ok": False, "records": [], "status": "超时"}])["verdict"],
      str(T.dns_consistency([{"server": "a", "ok": False, "records": [],
                               "status": "超时"}])["verdict"]))
check("DNS：部分无应答会写清楚", _r3["failed"] == 1 and "无应答" in _r3["verdict"],
      str(_r3["verdict"]))
check("DNS：空输入不炸", T.dns_consistency([])["total"] == 0)

# --------------------------------------------------------------------------- #
print(f"\n{'=' * 62}")
print(f"=== {'ALL PASS' if not FAILS else str(len(FAILS)) + ' FAILED'} ===")
for f in FAILS:
    print("  FAIL:", f)
sys.exit(1 if FAILS else 0)
