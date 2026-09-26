# -*- coding: utf-8 -*-
"""
本机网络信息与权限
==================

* 网卡枚举（psutil + scapy.arch.windows.get_windows_if_list 交叉匹配）
* 默认网关（解析 `route print -4`，与语言无关）
* 管理员判定与「以管理员身份重启」
* 子网 / CIDR 计算
* Npcap 原始发包设备名（\\Device\\NPF_{GUID}，可直接由 GUID 构造）

注意：Npcap 安装时若勾选了「仅管理员可访问」，非管理员进程只能看到
Loopback 设备，ARP 扫描 / 流量牵引 / 抓包都会失败——这时程序会明确提示。
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass

import psutil

from .logging_bus import log

MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
MAX_HOSTS = 4096          # 单次扫描主机数上限，防止 /8 把机器打死


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #

def norm_mac(mac: str) -> str:
    """把 aa-bb-cc-dd-ee-ff / aabbccddeeff 统一成 aa:bb:cc:dd:ee:ff。"""
    if not mac:
        return ""
    h = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(h) != 12:
        return mac.lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def python_launcher() -> str:
    """
    返回用来重启自己的解释器路径。

    打包成 exe 时直接返回 exe 本身；源码运行时优先 pythonw.exe
    （GUI 子系统程序，不会弹出控制台窗口）。
    """
    from .paths import is_frozen
    if is_frozen():
        return sys.executable
    exe = sys.executable or ""
    if exe.lower().endswith("python.exe"):
        cand = exe[: -len("python.exe")] + "pythonw.exe"
        if os.path.exists(cand):
            return cand
    return exe


def relaunch_as_admin(extra_args: list[str] | None = None) -> bool:
    """
    通过 UAC 以管理员身份重新启动自己（成功返回 True，调用方应退出当前进程）。

    源码运行时用 pythonw 启动，因此不会出现控制台黑窗；
    额外参数用于告知子进程「这是提权后的实例」，避免 UAC 被拒时反复重启。
    """
    if is_admin():
        return False
    try:
        from .paths import is_frozen
        keep = [a for a in sys.argv[1:] if a != "--elevated"]
        if is_frozen():
            launcher = sys.executable
            args = keep + list(extra_args or [])
        else:
            launcher = python_launcher()
            args = [os.path.abspath(sys.argv[0])] + keep + list(extra_args or [])
        params = " ".join(f'"{a}"' for a in args)
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", launcher, params,
                                                 os.getcwd(), 1)
        return int(rc) > 32
    except Exception:
        return False


def run_hidden(cmd: list[str], timeout: int = 20, encoding: str = "gbk") -> str:
    """跑一个命令并返回 stdout（中文 Windows 用 gbk 解码）。"""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        raw = p.stdout or b""
    except Exception:
        return ""
    for enc in (encoding, "utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# 网卡
# --------------------------------------------------------------------------- #

@dataclass
class Iface:
    alias: str                     # "WLAN"（Windows 里的连接名）
    desc: str = ""                 # "Realtek 8852CE WiFi 6E PCI-E NIC"
    ip: str = ""
    mask: str = ""
    prefix: int = 24
    mac: str = ""
    gateway: str = ""
    guid: str = ""
    is_up: bool = False
    speed: int = 0
    l2_name: str = ""              # \Device\NPF_{GUID}

    @property
    def cidr(self) -> str:
        try:
            return str(ipaddress.ip_network(f"{self.ip}/{self.prefix}", strict=False))
        except Exception:
            return ""

    @property
    def label(self) -> str:
        mark = "●" if self.is_up else "○"
        return f"{mark} {self.alias}  {self.ip}/{self.prefix}" + (
            f"  →{self.gateway}" if self.gateway else "")

    def to_dict(self) -> dict:
        return {
            "alias": self.alias, "desc": self.desc, "ip": self.ip, "mask": self.mask,
            "prefix": self.prefix, "mac": self.mac, "gateway": self.gateway,
            "guid": self.guid, "up": self.is_up, "cidr": self.cidr,
            "l2_name": self.l2_name,
        }


def _default_routes() -> dict[str, str]:
    """解析 route print -4：返回 {本机接口IP: 网关IP}（只取默认路由）。"""
    out = run_hidden(["route", "print", "-4"])
    routes: dict[str, str] = {}
    best: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gw, iface_ip = parts[2], parts[3]
            try:
                metric = int(parts[4])
            except ValueError:
                metric = 9999
            if iface_ip == "0.0.0.0":
                continue
            if iface_ip not in best or metric < best[iface_ip]:
                best[iface_ip] = metric
                routes[iface_ip] = gw
    return routes


def _windows_adapters() -> list[dict]:
    """scapy 从 Windows API 拿到全部适配器（不需要管理员）。"""
    try:
        from scapy.arch.windows import get_windows_if_list
        return list(get_windows_if_list())
    except Exception:
        return []


def _npf_names() -> list[str]:
    """当前能真正收发包的 Npcap 设备名（非管理员通常只有 Loopback）。"""
    try:
        from scapy.interfaces import get_if_list
        return list(get_if_list())
    except Exception as exc:
        log(f"枚举 Npcap 设备失败：{type(exc).__name__}: {exc}", "debug", "hostinfo")
        return []


def prefix_from_mask(mask: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        return 24


def list_ifaces(include_down: bool = False) -> list[Iface]:
    """枚举本机 IPv4 网卡（带上网关 / MAC / GUID / Npcap 设备名）。"""
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    routes = _default_routes()
    adapters = _windows_adapters()
    npf_names = _npf_names()
    npf_lower = {n.lower(): n for n in npf_names}
    result: list[Iface] = []

    for alias, alist in addrs.items():
        ip = mask = mac = ""
        for a in alist:
            if a.family == socket.AF_INET and a.address and not a.address.startswith("127."):
                ip, mask = a.address, a.netmask or "255.255.255.0"
            elif getattr(psutil, "AF_LINK", -1) == a.family and MAC_RE.match(a.address or ""):
                mac = norm_mac(a.address)
        if not ip:
            continue
        up = bool(stats[alias].isup) if alias in stats else False
        if not up and not include_down:
            continue

        guid = desc = ""
        for w in adapters:
            wips = w.get("ips") or []
            if ip in wips or (mac and norm_mac(w.get("mac") or "") == mac and w.get("mac")):
                guid = (w.get("guid") or "").strip("{}")
                desc = w.get("description") or w.get("name") or ""
                if ip in wips:
                    break

        l2 = npf_lower.get(f"\\device\\npf_{{{guid}}}".lower(), "") if guid else ""
        if not l2 and guid:
            l2 = f"\\Device\\NPF_{{{guid}}}"      # Npcap 的固定命名，可直接构造

        result.append(Iface(
            alias=alias, desc=desc, ip=ip, mask=mask,
            prefix=prefix_from_mask(mask), mac=mac,
            gateway=routes.get(ip, ""), guid=guid, is_up=up,
            speed=int(stats[alias].speed) if alias in stats else 0,
            l2_name=l2,
        ))

    result.sort(key=lambda i: (not i.is_up, not i.gateway, i.alias))
    return result


def primary_iface() -> Iface | None:
    """挑一个用来干活的网卡：优先「有网关且在线」的。"""
    ifs = list_ifaces()
    for i in ifs:
        if i.is_up and i.gateway:
            return i
    return ifs[0] if ifs else None


def npcap_ready() -> tuple[bool, str]:
    """
    检查 Npcap 原始收发能力是否可用。
    返回 (是否可用, 说明)。不可用时说明里会写清原因和怎么办。
    """
    dll = (os.path.exists(r"C:\Windows\System32\Npcap\wpcap.dll")
           or os.path.exists(r"C:\Windows\System32\wpcap.dll"))
    if not dll:
        return False, "没有找到 Npcap（wpcap.dll）。请安装 Npcap（Wireshark 安装包内附带）。"

    names = _npf_names()
    real = [n for n in names if "loopback" not in n.lower()]
    if real:
        return True, f"Npcap 可用，可收发设备 {len(real)} 个"

    if not is_admin():
        return False, ("Npcap 驱动已装，但当前不是管理员：Npcap 只向管理员暴露网卡设备，"
                       "所以 ARP 扫描 / 流量牵引 / 抓包需要「以管理员身份重启」。")
    return False, ("已是管理员但仍只看到 Loopback 设备。请检查 Npcap 安装选项"
                   "（是否启用了「Restrict Npcap driver's access to Administrators only」"
                   "之外的限制），必要时重装 Npcap 并勾选 WinPcap API 兼容模式。")


# --------------------------------------------------------------------------- #
# 子网计算
# --------------------------------------------------------------------------- #

def parse_network(text: str) -> ipaddress.IPv4Network:
    """接受 192.168.1.0/24、192.168.1.5/24、192.168.1.5 等写法（仅 CIDR/单 IP）。"""
    text = (text or "").strip()
    if not text:
        raise ValueError("目标为空")
    if "/" not in text:
        return ipaddress.ip_network(text + "/32", strict=False)
    return ipaddress.ip_network(text, strict=False)


def host_list(net: ipaddress.IPv4Network, cap: int = MAX_HOSTS) -> list[str]:
    """给出网段内可扫描的主机列表（/31 /32 特殊处理），并做数量封顶。"""
    if net.prefixlen >= 31:
        return [str(h) for h in net]
    hosts = [str(h) for h in net.hosts()]
    return hosts[:cap]


def _expand_one(token: str, cap: int) -> list[str]:
    """展开单个目标写法，返回 IP 列表。"""
    token = token.strip()
    if not token:
        return []

    # 区间：192.168.1.10-192.168.1.50 或 192.168.1.10-50
    if "-" in token:
        left, right = [x.strip() for x in token.split("-", 1)]
        try:
            if "." not in right:                       # 简写尾段
                right = ".".join(left.split(".")[:3]) + "." + right
            a, b = ipaddress.IPv4Address(left), ipaddress.IPv4Address(right)
            if int(b) < int(a):
                a, b = b, a
            return [str(ipaddress.IPv4Address(x)) for x in range(int(a), min(int(b), int(a) + cap - 1) + 1)]
        except Exception:
            return []

    # 网段或单 IP
    if "/" in token or re.match(r"^\d+\.\d+\.\d+\.\d+$", token):
        try:
            return host_list(parse_network(token), cap)
        except Exception:
            return []

    # 域名
    try:
        infos = socket.getaddrinfo(token, None, socket.AF_INET)
        return sorted({i[4][0] for i in infos})
    except Exception:
        log(f"无法解析目标：{token}", "warn", "hostinfo")
        return []


def expand_targets(text: str, cap: int = MAX_HOSTS) -> list[str]:
    """
    把用户输入展开成去重后的 IP 列表，支持逗号/空格/换行分隔，可混用：
        192.168.1.5                  单个 IP
        192.168.1.0/24               网段
        192.168.1.10-192.168.1.50    区间
        192.168.1.10-50              区间简写
        example.com                  域名
    """
    tokens = [t for t in re.split(r"[,\s;]+", (text or "").strip()) if t]
    seen: list[str] = []
    for tk in tokens:
        for ip in _expand_one(tk, cap):
            if ip not in seen:
                seen.append(ip)
            if len(seen) >= cap:
                return seen
    return seen


def subnet_info(target: str) -> dict:
    """给「子网计算器」用的一堆信息。"""
    net = parse_network(target)
    hosts = host_list(net)
    info = {
        "network": str(net.network_address),
        "netmask": str(net.netmask),
        "prefix": net.prefixlen,
        "broadcast": str(net.broadcast_address),
        "first": hosts[0] if hosts else "-",
        "last": hosts[-1] if hosts else "-",
        "total": net.num_addresses,
        "usable": max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses,
        "is_private": net.is_private,
        "scannable": min(len(hosts), MAX_HOSTS),
    }
    return info
