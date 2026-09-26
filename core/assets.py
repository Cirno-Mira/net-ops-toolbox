# -*- coding: utf-8 -*-
"""
局域网资产发现
==============

* ARP 扫描（scapy + Npcap，需要管理员）：拿到 IP↔MAC，最快最准
* Ping 扫描（调用系统 ping，不需要管理员）：能覆盖跨网段主机
* 本机 ARP 缓存（arp -a）：不发包也能看到最近通信过的设备
* 主机名：反向 DNS / NetBIOS(nbtstat) / mDNS(zeroconf)
* 厂商：mac-vendor-lookup（联网更新过厂商库）+ 内置常见 OUI 兜底
"""

from __future__ import annotations

import concurrent.futures as cf
import re
import socket
import time
from dataclasses import dataclass, field

from .hostinfo import Iface, is_admin, npcap_ready, run_hidden
from .logging_bus import log
from .ports import _connect_probe


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #

@dataclass
class Asset:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    os_guess: str = ""
    open_ports: list[int] = field(default_factory=list)
    online: bool = True
    rtt_ms: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""
    note: str = ""

    def row(self) -> list:
        return [
            self.ip, self.mac or "-", self.vendor or "-", self.hostname or "-",
            ",".join(str(p) for p in self.open_ports) or "-",
            "在线" if self.online else "离线",
            self.os_guess or "-", self.source or "-",
            self.last_seen,
        ]


# --------------------------------------------------------------------------- #
# 内置 OUI 厂商表（离线兜底；联网可用 mac-vendor-lookup 更新完整库）
# --------------------------------------------------------------------------- #

from .oui import BUILTIN_OUI      # 内置离线 OUI 厂商表（详见 core/oui.py）


_mac_lookup = None
_mac_lookup_ready = False


def _vendor_online(mac: str) -> str:
    """用 mac-vendor-lookup 查厂商（需要先更新过厂商库）。"""
    global _mac_lookup, _mac_lookup_ready
    if not _mac_lookup_ready:
        _mac_lookup_ready = True
        try:
            from mac_vendor_lookup import MacLookup
            _mac_lookup = MacLookup()
        except Exception as exc:
            log(f"厂商库不可用，改用内置表：{exc}", "debug", "assets")
            _mac_lookup = None
    if _mac_lookup is None:
        return ""
    try:
        return _mac_lookup.lookup(mac) or ""
    except Exception:
        return ""


def update_vendor_db() -> tuple[bool, str]:
    """下载完整 IEEE OUI 厂商库（需要联网，几 MB）。"""
    try:
        from mac_vendor_lookup import MacLookup
        MacLookup().update_vendors()
        return True, "厂商库已更新"
    except Exception as exc:
        return False, f"厂商库更新失败：{type(exc).__name__}: {exc}"


def vendor_of(mac: str) -> str:
    """MAC -> 厂商。先查在线库，再查内置表。"""
    if not mac:
        return ""
    key = re.sub(r"[^0-9a-f]", "", mac.lower())[:6]
    if len(key) < 6:
        return ""
    name = _vendor_online(mac)
    if name:
        return name
    name = BUILTIN_OUI.get(key.upper(), "")
    if name:
        return name
    # 第二字节的 bit1 = 1 表示本地管理地址（手机随机 MAC 隐私地址）
    try:
        if int(key[1], 16) & 0x2:
            return "本地随机 MAC"
    except ValueError:
        pass
    return "未知厂商"


# --------------------------------------------------------------------------- #
# 基础探测
# --------------------------------------------------------------------------- #

def arp_table() -> dict[str, str]:
    """读取本机 ARP 缓存：{ip: mac}（不发包，零成本）。"""
    out = run_hidden(["arp", "-a"])
    table: dict[str, str] = {}
    for line in out.splitlines():
        m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
        if m:
            table[m.group(1)] = m.group(2).replace("-", ":").lower()
    return table


def ping_one(ip: str, timeout_ms: int = 1200) -> float | None:
    """调系统 ping 探活，返回 RTT(ms) 或 None。"""
    out = run_hidden(["ping", "-n", "1", "-w", str(timeout_ms), ip], timeout=8)
    if "TTL=" not in out.upper():
        return None
    m = re.search(r"(?:时间|time)[=<]\s*(\d+)\s*ms", out, re.I)
    if m:
        return float(m.group(1))
    return 0.0 if "TTL=" in out.upper() else None


def ping_sweep(hosts: list[str], timeout_ms: int = 1200, workers: int = 100,
               cancel=None, progress=None) -> dict[str, float]:
    """并发 ping 扫一批主机，返回 {ip: rtt_ms}。"""
    alive: dict[str, float] = {}
    done = 0
    total = len(hosts)

    def work(ip):
        return ip, ping_one(ip, timeout_ms)

    with cf.ThreadPoolExecutor(max_workers=max(1, min(workers, total or 1))) as pool:
        futs = {pool.submit(work, ip): ip for ip in hosts}
        for fut in cf.as_completed(futs):
            if cancel is not None and cancel.is_set():
                for f in futs:
                    f.cancel()
                break
            ip, rtt = fut.result()
            done += 1
            if rtt is not None:
                alive[ip] = rtt
            if progress and (done % 16 == 0 or done == total):
                progress(done, total, f"ping {ip}")
    return alive


def arp_scan(hosts: list[str], l2_name: str = "", timeout: float = 2.0,
             cancel=None, progress=None) -> dict[str, str]:
    """
    ARP 扫描：一次广播拿到 IP↔MAC。需要 Npcap + 管理员。
    返回 {ip: mac}。
    """
    if not hosts:
        return {}
    ok, why = npcap_ready()
    if not is_admin():
        raise PermissionError("ARP 扫描需要管理员权限（原始二层收发）。" + why)
    if not ok:
        raise RuntimeError(why)

    from scapy.all import ARP, Ether
    from .rawsock import srp_locked
    found: dict[str, str] = {}
    batch = 512
    total = len(hosts)
    for i in range(0, total, batch):
        if cancel is not None and cancel.is_set():
            break
        chunk = hosts[i:i + batch]
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=chunk)
        try:
            ans, _ = srp_locked(pkt, l2_name or "", timeout)
        except Exception as exc:
            raise RuntimeError(f"ARP 收发包失败：{type(exc).__name__}: {exc}") from exc
        for _snd, rcv in ans:
            found[rcv.psrc] = (rcv.hwsrc or "").lower()
        if progress:
            progress(min(i + batch, total), total, f"ARP {i + 1}-{i + len(chunk)}")
    return found


# --------------------------------------------------------------------------- #
# 深度探测：TTL 操作系统指纹 / IPv6 NDP
# --------------------------------------------------------------------------- #

# TTL 初值 → 大致系统（只是提示，经过路由器会递减）
TTL_OS = [
    (32, "Windows 95/98/ME"),
    (60, "旧版 Linux / 嵌入式设备"),
    (64, "Linux / macOS / Android / iOS"),
    (128, "Windows"),
    (255, "网络设备（路由器/交换机/防火墙）"),
]


def guess_os_by_ttl(ttl: int) -> str:
    """按 TTL 猜一个大概的系统类型。"""
    if not ttl:
        return ""
    for base, name in TTL_OS:
        if ttl <= base:
            return f"{name}（TTL≈{ttl}）"
    return f"未知（TTL={ttl}）"


def ping_ttl(ip: str, timeout_ms: int = 1200) -> tuple[float | None, int]:
    """ping 一次，返回 (rtt_ms, ttl)；探测不到就是 (None, 0)。"""
    out = run_hidden(["ping", "-n", "1", "-w", str(timeout_ms), ip], timeout=8)
    if "TTL=" not in out.upper():
        return None, 0
    ttl = 0
    m = re.search(r"TTL=(\d+)", out, re.I)
    if m:
        ttl = int(m.group(1))
    r = re.search(r"(?:时间|time)[=<]\s*(\d+)\s*ms", out, re.I)
    return (float(r.group(1)) if r else 0.0), ttl


def ndp_scan(l2_name: str = "", timeout: float = 4.0, cancel=None,
             progress=None) -> dict[str, str]:
    """
    IPv6 邻居发现扫描：向全节点组播（ff02::1）发 ICMPv6 Echo，收集回应。

    返回 {ipv6 地址: MAC}。需要管理员 + Npcap。
    """
    if not is_admin():
        raise PermissionError("IPv6 扫描需要管理员权限（原始二层收发）")
    ok, why = npcap_ready()
    if not ok:
        raise RuntimeError(why)

    from scapy.all import Ether, ICMPv6EchoRequest, IPv6
    from .rawsock import srp_locked
    found: dict[str, str] = {}
    pkt = Ether(dst="33:33:00:00:00:01") / IPv6(dst="ff02::1") / ICMPv6EchoRequest()
    if progress:
        progress(0, 1, "IPv6 NDP 扫描中…")
    ans, _ = srp_locked(pkt, l2_name or "", timeout)
    for _snd, rcv in ans:
        try:
            addr = rcv[IPv6].src
            if addr:
                found[addr] = (rcv.src or "").lower()
        except Exception:
            continue
    if progress:
        progress(1, 1, f"IPv6 发现 {len(found)} 个邻居")
    log(f"IPv6 NDP 扫描到 {len(found)} 个邻居", "success" if found else "info", "assets")
    return found


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def useful_name(ip: str, name: str) -> str:
    """
    过滤掉没用的主机名：很多家用路由器会把未知设备的 PTR 指回 IP 本身，
    这种「名字」和没有一样，直接丢掉。
    """
    name = (name or "").strip().rstrip(".")
    if not name or name == ip:
        return ""
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
        return ""
    if name.lower() in ("localhost", "localhost.localdomain"):
        return ""
    return name


def netbios_name(ip: str) -> str:
    """用系统自带 nbtstat 拿 NetBIOS 名（Windows 局域网设备名很好用）。"""
    out = run_hidden(["nbtstat", "-A", ip], timeout=6)
    if not out:
        return ""
    best = ""
    for line in out.splitlines():
        m = re.match(r"\s*(\S+)\s+<(\w\w)>\s+(\w+)", line)
        if not m:
            continue
        name, suffix, kind = m.group(1), m.group(2).upper(), m.group(3).upper()
        if name == "..__MSBROWSE__.":
            continue
        if suffix == "00" and kind == "UNIQUE" and not name.isdigit():
            return name
        if suffix == "20" and kind == "UNIQUE":
            best = best or name
    return best


def mdns_hosts(timeout: float = 3.0) -> dict[str, str]:
    """
    用 mDNS 找设备名（打印机 / 电视 / 音箱 / 手机等会自报家门）。
    返回 {ip: 主机名}。不需要管理员。
    """
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except Exception:
        return {}

    found: dict[str, str] = {}
    zc = Zeroconf()

    class _Listener:
        def add_service(self, zc_, type_, name):
            try:
                info = zc_.get_service_info(type_, name, timeout=1500)
                if not info:
                    return
                host = (info.server or "").rstrip(".")
                for addr in info.parsed_addresses():
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", addr):
                        nice = name.split(".")[0]
                        found.setdefault(addr, nice or host)
            except Exception:
                pass

        def update_service(self, *a):
            pass

        def remove_service(self, *a):
            pass

    browsers = []
    try:
        for stype in ("_services._dns-sd._udp.local.", "_http._tcp.local.",
                      "_workstation._tcp.local.", "_smb._tcp.local.",
                      "_device-info._tcp.local.", "_airplay._tcp.local.",
                      "_googlecast._tcp.local.", "_printer._tcp.local.",
                      "_raop._tcp.local.", "_ipp._tcp.local."):
            try:
                browsers.append(ServiceBrowser(zc, stype, _Listener()))
            except Exception:
                pass
        time.sleep(max(0.5, timeout))
    finally:
        for b in browsers:
            try:
                b.cancel()
            except Exception:
                pass
        try:
            zc.close()
        except Exception:
            pass
    return found


# --------------------------------------------------------------------------- #
# 发现编排
# --------------------------------------------------------------------------- #

def discover(hosts: list[str], iface: Iface | None = None, *,
             use_arp: bool = True, use_ping: bool = True,
             resolve_names: bool = True, lookup_vendor: bool = True,
             probe_ports: list[int] | None = None,
             use_arp_cache: bool = True, use_mdns: bool = False,
             deep: bool = False,
             arp_timeout: float = 2.0, ping_timeout_ms: int = 1200,
             workers: int = 100, cancel=None,
             on_asset=None, progress=None) -> list[Asset]:
    """
    完整的资产发现流程：

      1) ARP 扫描（管理员）或 ping 扫描（普通权限）判定存活
      2) 补上本机 ARP 缓存里已知的设备
      3) 解析主机名（反向 DNS / NetBIOS / 可选 mDNS）
      4) 识别厂商
      5) 可选：探测常见端口

    每个阶段都会通过 on_asset(Asset) 实时回调，UI 可以边扫边显示。
    progress(done, total, message)
    """
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    assets: dict[str, Asset] = {}

    def upsert(ip: str, **kw) -> Asset:
        a = assets.get(ip)
        if a is None:
            a = Asset(ip=ip, first_seen=now)
            assets[ip] = a
        for k, v in kw.items():
            if v not in (None, "", []):
                setattr(a, k, v)
        a.last_seen = now
        if on_asset:
            on_asset(a)
        return a

    # --- 1. 存活判定 ---
    live: dict[str, float] = {}
    macs: dict[str, str] = {}

    if use_arp:
        try:
            if progress:
                progress(0, len(hosts), "ARP 扫描中…")
            macs = arp_scan(hosts, iface.l2_name if iface else "", arp_timeout,
                            cancel, progress)
            live = {ip: 0.0 for ip in macs}
            log(f"ARP 扫描到 {len(macs)} 台在线设备", "success", "assets")
        except Exception as exc:
            log(f"ARP 扫描不可用，改用 ping：{exc}", "warn", "assets")
            macs, live = {}, {}

    if use_ping:
        rest = [h for h in hosts if h not in live]
        if rest:
            if progress:
                progress(0, len(rest), "Ping 扫描中…")
            alive = ping_sweep(rest, ping_timeout_ms, workers, cancel, progress)
            live.update(alive)
            log(f"Ping 发现 {len(alive)} 台在线主机", "success", "assets")

    for ip, rtt in live.items():
        upsert(ip, mac=macs.get(ip, ""), online=True, rtt_ms=rtt,
               source="arp" if ip in macs else "ping")

    # --- 2. ARP 缓存兜底 ---
    # 注意：ping 扫描本身会把对方的 ARP 记录写进本机缓存，所以这里读到的 MAC
    # 要能补到「已经由 ping 发现」的主机上，而不只是补 ARP 缓存里的新 IP。
    if use_arp_cache:
        cached = arp_table()
        for ip, mac in cached.items():
            if ip.endswith(".255") or ip.startswith(("224.", "239.", "255.")):
                continue
            if ip in assets:
                if not assets[ip].mac:
                    upsert(ip, mac=mac)
                continue
            if hosts and ip not in hosts:
                continue
            upsert(ip, mac=mac, online=False, source="arp缓存")
        if progress:
            progress(len(hosts), len(hosts), "ARP 缓存已合并")

    if cancel is not None and cancel.is_set():
        return list(assets.values())

    # --- 3. 主机名 ---
    mdns_map: dict[str, str] = {}
    if resolve_names and use_mdns:
        try:
            if progress:
                progress(0, 1, "mDNS 查询中…")
            mdns_map = mdns_hosts(3.0)
        except Exception as exc:
            log(f"mDNS 查询失败：{exc}", "debug", "assets")

    if resolve_names:
        targets = list(assets.keys())
        done = 0

        def name_work(ip: str) -> tuple[str, str]:
            nm = reverse_dns(ip)
            if not nm:
                nm = netbios_name(ip)
            return ip, useful_name(ip, nm)

        with cf.ThreadPoolExecutor(max_workers=max(1, min(60, len(targets) or 1))) as pool:
            futs = {pool.submit(name_work, ip): ip for ip in targets}
            for fut in cf.as_completed(futs):
                if cancel is not None and cancel.is_set():
                    for f in futs:
                        f.cancel()
                    break
                ip, nm = fut.result()
                nm = nm or mdns_map.get(ip, "")
                if nm:
                    upsert(ip, hostname=nm)
                done += 1
                if progress and (done % 8 == 0 or done == len(targets)):
                    progress(done, len(targets), f"解析名称 {ip}")

    if cancel is not None and cancel.is_set():
        return list(assets.values())

    # --- 4. 厂商 ---
    if lookup_vendor:
        for i, (ip, a) in enumerate(list(assets.items()), 1):
            if a.mac:
                upsert(ip, vendor=vendor_of(a.mac))
            if progress and (i % 8 == 0 or i == len(assets)):
                progress(i, len(assets), f"识别厂商 {ip}")

    # --- 5. 端口探测 ---
    if probe_ports:
        items = [ip for ip, a in assets.items() if a.online]
        done = 0
        for ip in items:
            if cancel is not None and cancel.is_set():
                break
            opened = []
            for port in probe_ports:
                state, _ = _connect_probe(ip, port, 0.4)
                if state == "open":
                    opened.append(port)
            if opened:
                upsert(ip, open_ports=sorted(opened))
            done += 1
            if progress:
                progress(done, len(items), f"探测端口 {ip}")

    # --- 6. 深度探测：TTL 操作系统指纹 ---
    if deep:
        items = [ip for ip, a in assets.items() if a.online]
        done = 0
        for ip in items:
            if cancel is not None and cancel.is_set():
                break
            rtt, ttl = ping_ttl(ip, ping_timeout_ms)
            if ttl:
                upsert(ip, os_guess=guess_os_by_ttl(ttl), rtt_ms=rtt or 0.0)
            done += 1
            if progress:
                progress(done, len(items), f"系统指纹 {ip}")

    result = sorted(assets.values(), key=lambda a: tuple(int(x) for x in a.ip.split(".")))
    if progress:
        progress(len(hosts), len(hosts), f"完成，共 {len(result)} 条记录")
    return result