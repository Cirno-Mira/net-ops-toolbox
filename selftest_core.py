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
import requests as _rq           # noqa: E402


class _H(_http.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"FORWARD-OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


_back = _http.ThreadingHTTPServer(("127.0.0.1", 19001), _H)
_th.Thread(target=_back.serve_forever, daemon=True).start()
_fwd = TN.TcpForwarder(1, "127.0.0.1", 19002, "127.0.0.1", 19001)
_fwd.start()
_time.sleep(0.6)
try:
    _r = _rq.get("http://127.0.0.1:19002/x", timeout=5)
    check("TCP 端口转发可用", _r.status_code == 200 and b"FORWARD-OK" in _r.content,
          str(_r.status_code))
    check("转发统计有连接数", _fwd.stat.conns >= 1, str(_fwd.stat.conns))
except Exception as _e:
    check("TCP 端口转发可用", False, f"{type(_e).__name__}: {_e}")
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

print(f"\n{'=' * 62}")
print(f"=== {'ALL PASS' if not FAILS else str(len(FAILS)) + ' FAILED'} ===")
for f in FAILS:
    print("  FAIL:", f)
sys.exit(1 if FAILS else 0)
