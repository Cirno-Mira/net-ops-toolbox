# -*- coding: utf-8 -*-
"""
被动资产发现（旁路嗅探）
========================

不开扫描器、不主动发包，只把网卡上「本来就在跑」的流量收集起来还原资产：

* ARP 请求 / 应答 / 免费 ARP  →  IP↔MAC、IP 冲突、MAC 漂移、ARP 欺骗嫌疑
* DHCP DISCOVER/REQUEST/ACK    →  主机名、厂商类、地址分配、流氓 DHCP
* mDNS / NBNS                  →  主机名
* LLDP / CDP                   →  交换机邻居、端口、管理地址
* IPv4 TTL                     →  粗略操作系统

设计要点：

* 核心层零 Qt：`PassiveCollector` 只做「吃一个包 → 更新状态」，
  抓包放在 `PassiveSniffer` 的 AsyncSniffer 后台线程里；
* 所有解析都能离线调用，自检时用构造包喂进去即可，不需要管理员权限；
* 告警按 `(类型, IP, MAC)` 去重，避免同一件事刷满整屏。
"""

from __future__ import annotations

import csv
import importlib
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

from .hostinfo import is_admin, norm_mac
from .logging_bus import log

MDNS_PORT = 5353
NBNS_PORTS = {137, 138}
LLDP_ETHERTYPE = 0x88CC
CDP_MAC = "01:00:0c:cc:cc:cc"

SEVERITY_ORDER = {"info": 0, "low": 1, "mid": 2, "high": 3}
SEVERITY_LABEL = {"info": "提示", "low": "低", "mid": "中", "high": "高"}

_VENDOR_CACHE: dict[str, str] = {}
_MODULE_STATE: dict[str, bool] = {}


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #

def _text(value) -> str:
    """把 scapy 里的 bytes / str / 其它值统一成去掉空字符的 str。"""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "ignore").replace("\x00", "").strip()
    return str(value).replace("\x00", "").strip()


def _fmt_ts(epoch: float) -> str:
    if not epoch:
        return "-"
    return datetime.fromtimestamp(epoch).strftime("%H:%M:%S")


def _ip_key(ip: str):
    try:
        return tuple(int(p) for p in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def _module(name: str) -> bool:
    """按需导入 scapy 的 contrib 模块（LLDP / CDP 只有导入后才能解析）。"""
    if name in _MODULE_STATE:
        return _MODULE_STATE[name]
    try:
        importlib.import_module(name)
        _MODULE_STATE[name] = True
    except Exception as exc:
        _MODULE_STATE[name] = False
        log(f"{name} 不可用：{type(exc).__name__}: {exc}", "debug", "passive")
    return _MODULE_STATE[name]


def vendor_of(mac: str) -> str:
    """带缓存的厂商查询；查不到返回空串（不阻断采集）。"""
    mac = norm_mac(mac)
    if not mac:
        return ""
    if mac in _VENDOR_CACHE:
        return _VENDOR_CACHE[mac]
    try:
        from .assets import vendor_of as _lookup
        _VENDOR_CACHE[mac] = _lookup(mac) or ""
    except Exception:
        _VENDOR_CACHE[mac] = ""
    return _VENDOR_CACHE[mac]


def _os_from_ttl(ttl: int) -> str:
    if not ttl:
        return ""
    if ttl <= 64:
        return "Linux / Unix"
    if ttl <= 128:
        return "Windows"
    return "网络设备 / 嵌入式"


def _rr_items(section) -> list:
    """DNS 的 qd/an/ns/ar 可能是 None、单条记录或列表，统一成列表。"""
    if section is None:
        return []
    if isinstance(section, (list, tuple)):
        return [x for x in section if x is not None]
    try:
        return [x for x in section]
    except TypeError:
        return [section]


def _clean_name(name: str) -> str:
    name = _text(name).strip(".").strip()
    name = re.sub(r"<[0-9A-Fa-f]{2}>", "", name)      # NBNS 的 <20> 后缀
    name = name.replace("\x20", "")
    if not name or name in (".", "-"):
        return ""
    if name.lower().startswith("_") or name.lower() in ("local", "wpad"):
        return ""
    return name[:63]


def _mac_from_bytes(value) -> str:
    if isinstance(value, bytes) and len(value) >= 6:
        return norm_mac(value[:6].hex())
    return norm_mac(_text(value))


_DHCP_TYPES = {"discover": 1, "offer": 2, "request": 3, "decline": 4,
               "ack": 5, "nak": 6, "release": 7, "inform": 8}


def _dhcp_msg_type(value) -> int:
    """scapy 有时给整数、有时给 'ack' 这类字符串，统一成数字。"""
    if isinstance(value, int):
        return value
    text = _text(value).lower()
    if text in _DHCP_TYPES:
        return _DHCP_TYPES[text]
    try:
        return int(text)
    except (TypeError, ValueError):
        return 0


def _addr_text(value) -> str:
    """DHCP 选项里的 4 字节地址 → 点分十进制。"""
    if isinstance(value, bytes) and len(value) == 4:
        return ".".join(str(b) for b in value)
    return _text(value)


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #

@dataclass
class PassiveHost:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    os_guess: str = ""
    dhcp_vendor: str = ""
    sources: set = field(default_factory=set)
    mac_history: list = field(default_factory=list)
    ttl: int = 0
    packets: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    def touch(self, ts: float) -> None:
        if not self.first_seen:
            self.first_seen = ts
        self.last_seen = ts
        self.packets += 1

    def row(self) -> list:
        return [
            self.ip, self.mac or "-", self.vendor or "-", self.hostname or "-",
            self.os_guess or "-", self.dhcp_vendor or "-",
            " / ".join(sorted(self.sources)) or "-", self.packets,
            _fmt_ts(self.first_seen), _fmt_ts(self.last_seen),
        ]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "mac": self.mac, "vendor": self.vendor,
            "hostname": self.hostname, "os_guess": self.os_guess,
            "dhcp_vendor": self.dhcp_vendor,
            "sources": sorted(self.sources), "ttl": self.ttl,
            "packets": self.packets,
            "first_seen": _fmt_ts(self.first_seen),
            "last_seen": _fmt_ts(self.last_seen),
            "mac_history": list(self.mac_history),
        }


@dataclass
class Link:
    local: str
    remote: str
    remote_port: str = ""
    mgmt_ip: str = ""
    platform: str = ""
    source: str = ""
    last_seen: float = 0.0

    def key(self) -> tuple:
        return (self.source, self.remote, self.remote_port, self.mgmt_ip)

    def row(self) -> list:
        return [self.local or "-", self.remote or "-", self.remote_port or "-",
                self.mgmt_ip or "-", self.platform or "-", self.source or "-",
                _fmt_ts(self.last_seen)]


@dataclass
class Alert:
    kind: str
    severity: str
    ip: str
    mac: str
    detail: str
    at: float

    def row(self) -> list:
        return [SEVERITY_LABEL.get(self.severity, self.severity), self.kind,
                self.ip or "-", self.mac or "-", self.detail, _fmt_ts(self.at)]


# --------------------------------------------------------------------------- #
# 采集器
# --------------------------------------------------------------------------- #

class PassiveCollector:
    """把包流折叠成资产表、拓扑邻居和告警。线程安全。"""

    def __init__(self, local_iface: str = "", trusted_dhcp=None,
                 gateway_ip: str = "", gateway_mac: str = ""):
        self.local_iface = local_iface
        self.trusted_dhcp = {ip for ip in (trusted_dhcp or []) if ip}
        self.gateway_ip = gateway_ip
        self.gateway_mac = norm_mac(gateway_mac)

        self.hosts: dict[str, PassiveHost] = {}
        self.links: dict[tuple, Link] = {}
        self.alerts: list[Alert] = []
        self.dhcp_clients: dict[str, dict] = {}
        self.events: deque = deque(maxlen=3000)
        self.counters = {"packets": 0, "arp": 0, "dhcp": 0, "mdns": 0,
                         "nbns": 0, "lldp": 0, "cdp": 0, "other": 0}
        self.started_at = time.time()

        self._lock = threading.RLock()
        self._mac_owner: dict[str, set] = {}
        self._alert_keys: set = set()
        self._arp_targets: dict[str, list] = {}

    # ---------------- 对外 ----------------

    def reset(self) -> None:
        with self._lock:
            self.hosts.clear()
            self.links.clear()
            self.alerts.clear()
            self.dhcp_clients.clear()
            self.events.clear()
            self._mac_owner.clear()
            self._alert_keys.clear()
            self._arp_targets.clear()
            for key in self.counters:
                self.counters[key] = 0
            self.started_at = time.time()

    def observe(self, pkt, ts: float | None = None) -> dict | None:
        """吃一个包，返回给界面流式显示的事件（不需要就返回 None）。"""
        ts = time.time() if ts is None else ts
        try:
            with self._lock:
                event = self._observe_locked(pkt, ts)
                if event is not None:
                    event["time"] = _fmt_ts(ts)
                    self.events.append(event)
                return event
        except Exception as exc:                 # 单个畸形包不能拖垮整条采集
            log(f"解析数据包失败：{type(exc).__name__}: {exc}", "debug", "passive")
            return None

    def snapshot(self) -> dict:
        with self._lock:
            hosts = sorted(self.hosts.values(), key=lambda h: _ip_key(h.ip))
            links = sorted(self.links.values(), key=lambda ln: ln.key())
            alerts = sorted(self.alerts, key=lambda a: a.at, reverse=True)
            return {
                "hosts": [h.to_dict() for h in hosts],
                "links": [{"local": ln.local, "remote": ln.remote,
                           "remote_port": ln.remote_port,
                           "mgmt_ip": ln.mgmt_ip, "platform": ln.platform,
                           "source": ln.source,
                           "last_seen": _fmt_ts(ln.last_seen)} for ln in links],
                "alerts": [{"severity": a.severity, "kind": a.kind,
                            "ip": a.ip, "mac": a.mac, "detail": a.detail,
                            "at": _fmt_ts(a.at)} for a in alerts],
                "counters": dict(self.counters),
                "events": [{"time": e.get("time", ""), "kind": e.get("kind", ""),
                            "src": e.get("src", ""), "dst": e.get("dst", ""),
                            "mac": e.get("mac", ""), "info": e.get("info", "")}
                           for e in list(self.events)[-500:]],
                "uptime": round(time.time() - self.started_at, 1),
                "host_count": len(hosts),
                "link_count": len(links),
                "alert_count": len(alerts),
            }

    def audit(self) -> list[dict]:
        with self._lock:
            return audit(list(self.hosts.values()), list(self.alerts),
                         gateway_ip=self.gateway_ip,
                         gateway_mac=self.gateway_mac)

    # ---------------- 分发 ----------------

    def _observe_locked(self, pkt, ts: float) -> dict | None:
        self.counters["packets"] += 1
        eth_src = norm_mac(_text(getattr(pkt, "src", "")))
        event = None

        if pkt.haslayer("ARP"):
            event = self._observe_arp(pkt, ts, eth_src)
        elif pkt.haslayer("DHCP") or pkt.haslayer("BOOTP"):
            event = self._observe_dhcp(pkt, ts)
        elif pkt.haslayer("IP"):
            event = self._observe_ip(pkt, ts, eth_src)
        elif _is_lldp(pkt):
            event = self._observe_lldp(pkt, ts)
        elif _is_cdp(pkt):
            event = self._observe_cdp(pkt, ts)

        if event is None:
            self.counters["other"] += 1
        return event

    # ---------------- ARP ----------------

    def _observe_arp(self, pkt, ts: float, eth_src: str) -> dict:
        self.counters["arp"] += 1
        arp = pkt["ARP"]
        op = int(getattr(arp, "op", 0) or 0)
        psrc = _text(getattr(arp, "psrc", ""))
        pdst = _text(getattr(arp, "pdst", ""))
        hwsrc = norm_mac(_text(getattr(arp, "hwsrc", ""))) or eth_src

        if op == 1:
            if psrc and psrc != "0.0.0.0" and hwsrc:
                self._learn(psrc, hwsrc, "ARP 请求", ts)
            if hwsrc and pdst and pdst != "0.0.0.0":
                self._note_arp_target(hwsrc, pdst, ts)
            info = f"who-has {pdst} tell {psrc}"
        elif op == 2:
            if psrc and hwsrc:
                self._learn(psrc, hwsrc, "ARP 应答", ts)
            info = f"{psrc} is-at {hwsrc}"
            if psrc and psrc == pdst:
                self._alert("gratuitous_arp", "low", psrc, hwsrc,
                            "收到免费 ARP（设备在主动宣告地址，也可能是在抢网关）", ts)
        else:
            info = f"ARP op={op} {psrc} → {pdst}"

        return {"kind": "arp", "ts": ts, "op": op, "src": psrc,
                "dst": pdst, "mac": hwsrc, "info": info}

    def _note_arp_target(self, mac: str, target: str, ts: float) -> None:
        """一个 MAC 在 10 秒内问了很多不同地址 —— 典型 ARP 扫描特征。"""
        window = [item for item in self._arp_targets.get(mac, [])
                  if ts - item[0] <= 10.0]
        window.append((ts, target))
        self._arp_targets[mac] = window[-200:]
        targets = {t for _t, t in window}
        if len(targets) >= 20:
            self._alert("arp_scan", "mid", "", mac,
                        f"10 秒内向 {len(targets)} 个不同地址发 ARP 请求，疑似 ARP 扫描",
                        ts)

    # ---------------- DHCP ----------------

    def _observe_dhcp(self, pkt, ts: float) -> dict:
        self.counters["dhcp"] += 1
        bootp = pkt.getlayer("BOOTP")
        dhcp = pkt.getlayer("DHCP")
        opts: dict = {}
        if dhcp is not None:
            for opt in (getattr(dhcp, "options", None) or []):
                if isinstance(opt, tuple) and len(opt) == 2:
                    # scapy 里选项名是连字符（message-type），这里统一成下划线
                    key = str(opt[0]).replace("-", "_").lower()
                    opts[key] = opt[1]

        msg_type = _dhcp_msg_type(opts.get("message_type", 0))
        hostname = _clean_name(_text(opts.get("hostname", "")))
        vendor_class = _text(opts.get("vendor_class_id", ""))
        requested = _addr_text(opts.get("requested_addr", ""))
        mac = _mac_from_bytes(getattr(bootp, "chaddr", b"")) if bootp else ""
        client_ip = _text(getattr(bootp, "ciaddr", "")) if bootp else ""
        assigned = _text(getattr(bootp, "yiaddr", "")) if bootp else ""
        server_ip = _text(getattr(bootp, "siaddr", "")) if bootp else ""
        if not server_ip and pkt.haslayer("IP"):
            server_ip = _text(pkt["IP"].src)

        if mac:
            info = self.dhcp_clients.setdefault(
                mac, {"hostname": "", "vendor_class": "", "last_ip": "",
                      "last_type": 0, "first_seen": ts})
            if hostname:
                info["hostname"] = hostname
            if vendor_class:
                info["vendor_class"] = vendor_class
            info["last_type"] = msg_type
            if assigned and assigned != "0.0.0.0":
                info["last_ip"] = assigned

        # ACK / OFFER 里已经带了地址，直接落进资产表
        if assigned and assigned != "0.0.0.0" and mac:
            src = "DHCP ACK" if msg_type == 5 else "DHCP"
            self._learn(assigned, mac, src, ts)
            host = self.hosts.get(assigned)
            if host is not None:
                if hostname:
                    host.hostname = hostname
                if vendor_class:
                    host.dhcp_vendor = vendor_class
        elif client_ip and client_ip != "0.0.0.0" and mac:
            self._learn(client_ip, mac, "DHCP 续约", ts)

        # 流氓 DHCP：只有用户填了受信任服务器才判断，避免误报
        if msg_type in (2, 5) and self.trusted_dhcp and server_ip:
            if server_ip not in self.trusted_dhcp:
                self._alert("rogue_dhcp", "high", server_ip, "01:00:5e:00:00:01",
                            f"非受信任服务器 {server_ip} 下发了 DHCP "
                            f"{'OFFER' if msg_type == 2 else 'ACK'}", ts)

        name_map = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
                    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
        label = name_map.get(msg_type, f"type={msg_type}")
        info = f"DHCP {label} mac={mac or '-'}"
        if hostname:
            info += f" host={hostname}"
        if assigned and assigned != "0.0.0.0":
            info += f" ip={assigned}"
        if requested and requested != "0.0.0.0":
            info += f" req={requested}"
        return {"kind": "dhcp", "ts": ts, "op": msg_type, "src": client_ip,
                "dst": server_ip, "mac": mac, "info": info}

    # ---------------- IP / mDNS / NBNS / LLDP / CDP ----------------

    def _observe_ip(self, pkt, ts: float, eth_src: str) -> dict | None:
        ip = pkt["IP"]
        src, dst = _text(ip.src), _text(ip.dst)
        ttl = int(getattr(ip, "ttl", 0) or 0)

        # 只用 IP 头补全「已经认识的主机」的 TTL/OS，不把公网地址收进资产表
        host = self.hosts.get(src)
        if host is not None:
            host.touch(ts)
            if ttl and not host.ttl:
                host.ttl = ttl
                host.os_guess = _os_from_ttl(ttl)

        sport = dport = 0
        if pkt.haslayer("UDP"):
            sport = int(pkt["UDP"].sport or 0)
            dport = int(pkt["UDP"].dport or 0)

        if dport == MDNS_PORT or sport == MDNS_PORT:
            return self._observe_mdns(pkt, ts, src, dst)
        if dport in NBNS_PORTS or sport in NBNS_PORTS:
            return self._observe_nbns(pkt, ts, src, dst)

        proto = "TCP" if pkt.haslayer("TCP") else ("UDP" if pkt.haslayer("UDP") else "IP")
        return {"kind": "ip", "ts": ts, "op": 0, "src": src, "dst": dst,
                "mac": eth_src, "info": f"{proto} {src} → {dst}"
                                        + (f" :{dport}" if dport else "")}

    def _observe_mdns(self, pkt, ts: float, src: str, dst: str) -> dict:
        self.counters["mdns"] += 1
        names = _dns_names(pkt)
        hostname = ""
        for name in names:
            cleaned = _clean_name(name)
            if cleaned and cleaned.lower().endswith(".local"):
                hostname = cleaned[:-6]
                break
        if not hostname and names:
            hostname = _clean_name(names[0])
        if hostname and src and src not in ("0.0.0.0", "224.0.0.251", "ff02::fb"):
            mac = norm_mac(_text(getattr(pkt, "src", "")))
            self._learn(src, mac, "mDNS", ts)
            host = self.hosts.get(src)
            if host is not None and hostname and not host.hostname:
                host.hostname = hostname
        info = "mDNS " + (hostname or (names[0] if names else "查询"))
        return {"kind": "mdns", "ts": ts, "op": 0, "src": src, "dst": dst,
                "mac": norm_mac(_text(getattr(pkt, "src", ""))), "info": info}

    def _observe_nbns(self, pkt, ts: float, src: str, dst: str) -> dict:
        self.counters["nbns"] += 1
        names = []
        for raw in _dns_names(pkt):
            # NBNS 的 <20> / <00> 后缀要先去掉，否则会把 "PC1<20>" 变成 "PC120"
            cleaned = re.sub(r"<[0-9A-Fa-f]{2}>", "", _text(raw))
            token = re.sub(r"[^A-Za-z0-9_.-]", "", cleaned)
            if token:
                names.append(token)
        hostname = _clean_name(names[0]) if names else ""
        if hostname and src:
            mac = norm_mac(_text(getattr(pkt, "src", "")))
            self._learn(src, mac, "NBNS", ts)
            host = self.hosts.get(src)
            if host is not None and not host.hostname:
                host.hostname = hostname
        info = "NBNS " + (hostname or "查询")
        return {"kind": "nbns", "ts": ts, "op": 0, "src": src, "dst": dst,
                "mac": norm_mac(_text(getattr(pkt, "src", ""))), "info": info}

    def _observe_lldp(self, pkt, ts: float) -> dict:
        self.counters["lldp"] += 1
        _module("scapy.contrib.lldp")
        name = _layer_str(pkt, "LLDPDUSystemName", "system_name")
        port = _layer_str(pkt, "LLDPDUPortID", "id")
        desc = _layer_str(pkt, "LLDPDUSystemDescription", "description")
        mgmt = _layer_ip(pkt, "LLDPDUManagementAddress", "management_address")
        self._add_link(name or "LLDP 邻居", port, mgmt, desc, "LLDP", ts)
        info = f"LLDP {name or '?'}" + (f" / {port}" if port else "")
        return {"kind": "lldp", "ts": ts, "op": 0, "src": mgmt,
                "dst": self.local_iface, "mac": "", "info": info}

    def _observe_cdp(self, pkt, ts: float) -> dict:
        self.counters["cdp"] += 1
        _module("scapy.contrib.cdp")
        name = _layer_str(pkt, "CDPMsgDeviceID", "val")
        port = _layer_str(pkt, "CDPMsgPortID", "iface")
        platform = _layer_str(pkt, "CDPMsgPlatform", "val")
        mgmt = _cdp_mgmt(pkt)
        self._add_link(name or "CDP 邻居", port, mgmt, platform, "CDP", ts)
        info = f"CDP {name or '?'}" + (f" / {port}" if port else "")
        return {"kind": "cdp", "ts": ts, "op": 0, "src": mgmt,
                "dst": self.local_iface, "mac": "", "info": info}

    def _add_link(self, remote: str, port: str, mgmt: str, platform: str,
                  source: str, ts: float) -> None:
        if not remote:
            return
        link = Link(local=self.local_iface, remote=remote, remote_port=port,
                    mgmt_ip=mgmt, platform=platform, source=source,
                    last_seen=ts)
        old = self.links.get(link.key())
        if old is None:
            self.links[link.key()] = link
        else:
            old.last_seen = ts
            old.platform = platform or old.platform
        if mgmt:
            self._learn(mgmt, "", f"{source} 邻居", ts)
            host = self.hosts.get(mgmt)
            if host is not None:
                host.hostname = host.hostname or remote

    # ---------------- 资产表 ----------------

    def _learn(self, ip: str, mac: str, source: str, ts: float) -> None:
        ip = (ip or "").strip()
        if not ip or ip in ("0.0.0.0", "255.255.255.255"):
            return
        mac = norm_mac(mac)
        host = self.hosts.get(ip)

        if host is None:
            host = PassiveHost(ip=ip, mac=mac, vendor=vendor_of(mac) if mac else "")
            host.first_seen = ts
            self.hosts[ip] = host
        else:
            if mac and host.mac and mac != host.mac:
                self._alert(
                    "ip_conflict", "high", ip, mac,
                    f"同一 IP 出现两个 MAC：{host.mac}（先）→ {mac}（新），"
                    f"可能是 IP 冲突或 ARP 欺骗", ts)
                if mac not in host.mac_history:
                    host.mac_history.append(mac)
            elif mac and not host.mac:
                host.mac = mac
                host.vendor = host.vendor or vendor_of(mac)

        host.sources.add(source)
        host.touch(ts)

        if mac:
            owners = self._mac_owner.setdefault(mac, set())
            if ip not in owners:
                if owners:
                    sample = ", ".join(sorted(owners, key=_ip_key)[:4])
                    self._alert("mac_multi_ip", "low", ip, mac,
                                f"同一 MAC 对应多个 IP：{sample} → {ip}"
                                f"（代理 ARP、虚拟机或 NAT 也会这样）", ts)
                owners.add(ip)

    def _alert(self, kind: str, severity: str, ip: str, mac: str,
               detail: str, ts: float) -> None:
        key = (kind, ip, mac)
        if key in self._alert_keys:
            return
        self._alert_keys.add(key)
        self.alerts.append(Alert(kind=kind, severity=severity, ip=ip, mac=mac,
                                 detail=detail, at=ts))
        if len(self.alerts) > 2000:
            del self.alerts[:500]
        log(f"[被动告警] {detail}", "warn" if severity in ("mid", "high") else "info",
            "passive")


def _is_lldp(pkt) -> bool:
    try:
        return int(getattr(pkt, "type", 0) or 0) == LLDP_ETHERTYPE
    except Exception:
        return False


def _is_cdp(pkt) -> bool:
    try:
        dst = norm_mac(_text(getattr(pkt, "dst", "")))
    except Exception:
        return False
    return dst == CDP_MAC


def _dns_names(pkt) -> list[str]:
    dns = pkt.getlayer("DNS")
    if dns is None:
        return []
    names: list[str] = []
    for section in (getattr(dns, "qd", None), getattr(dns, "an", None),
                    getattr(dns, "ns", None), getattr(dns, "ar", None)):
        for rr in _rr_items(section):
            for attr in ("qname", "rrname"):
                value = getattr(rr, attr, None)
                if value:
                    name = _text(value)
                    if name and name not in names:
                        names.append(name)
    return names


def _layer_str(pkt, layer: str, attr: str) -> str:
    try:
        lay = pkt.getlayer(layer)
    except Exception:
        lay = None
    if lay is None:
        return ""
    return _text(getattr(lay, attr, ""))


def _layer_ip(pkt, layer: str, attr: str) -> str:
    try:
        lay = pkt.getlayer(layer)
    except Exception:
        lay = None
    if lay is None:
        return ""
    value = getattr(lay, attr, b"")
    if isinstance(value, bytes) and len(value) == 4:
        return ".".join(str(b) for b in value)
    return _text(value)


def _cdp_mgmt(pkt) -> str:
    try:
        lay = pkt.getlayer("CDPMsgMgmtAddr")
    except Exception:
        return ""
    for rec in getattr(lay, "addr", None) or []:
        value = getattr(rec, "addr", "")
        if value:
            return _text(value)
    return ""


# --------------------------------------------------------------------------- #
# 审计
# --------------------------------------------------------------------------- #

def audit(hosts: list, alerts: list | None = None, gateway_ip: str = "",
          gateway_mac: str = "") -> list[dict]:
    """
    把采集结果整理成「可直接贴进交付报告」的条目。

    hosts 既可以是 `PassiveHost`，也可以是 `snapshot()` 出来的 dict。
    """
    def get(obj, key, default=""):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    findings: list[dict] = []
    alerts = alerts or []

    gw_mac = norm_mac(gateway_mac)
    if gateway_ip and gw_mac:
        for host in hosts:
            if get(host, "ip") == gateway_ip:
                actual = norm_mac(get(host, "mac"))
                if actual and actual != gw_mac:
                    findings.append({
                        "severity": "high", "title": "网关 MAC 与预期不一致",
                        "detail": f"网关 {gateway_ip} 期望 {gw_mac}，"
                                  f"实际看到 {actual}，高度怀疑 ARP 欺骗或网关更换",
                        "items": [gateway_ip]})
                break

    conflicts = [a for a in alerts if get(a, "kind") == "ip_conflict"]
    if conflicts:
        findings.append({
            "severity": "high", "title": "IP 地址冲突 / ARP 欺骗嫌疑",
            "detail": f"发现 {len(conflicts)} 个 IP 被不同 MAC 同时使用",
            "items": [get(a, "ip") for a in conflicts][:20]})

    rogue = [a for a in alerts if get(a, "kind") == "rogue_dhcp"]
    if rogue:
        findings.append({
            "severity": "high", "title": "非受信任 DHCP 服务器",
            "detail": "有服务器在给客户端下发地址，可能劫持默认网关与 DNS",
            "items": [get(a, "ip") for a in rogue][:20]})

    scans = [a for a in alerts if get(a, "kind") == "arp_scan"]
    if scans:
        findings.append({
            "severity": "mid", "title": "疑似 ARP 扫描",
            "detail": "有主机在短时间内探测大量地址，可能在做资产扫描",
            "items": [get(a, "mac") for a in scans][:20]})

    multi = [a for a in alerts if get(a, "kind") == "mac_multi_ip"]
    if multi:
        findings.append({
            "severity": "low", "title": "同一 MAC 对应多个 IP",
            "detail": "可能是代理 ARP、虚拟化 / 容器 NAT；若非预期建议核对",
            "items": [get(a, "detail") for a in multi][:10]})

    no_mac = [h for h in hosts if not get(h, "mac")]
    if no_mac:
        findings.append({
            "severity": "info", "title": "只有 IP、没有 MAC 的条目",
            "detail": "通常来自 LLDP/CDP 管理地址或 DHCP 选项，属正常现象",
            "items": [get(h, "ip") for h in no_mac][:20]})

    unknown = [h for h in hosts if get(h, "mac") and not get(h, "vendor")]
    if unknown:
        findings.append({
            "severity": "info", "title": "未识别厂商的设备",
            "detail": f"{len(unknown)} 台设备的 MAC 不在本地 OUI 表里，"
                      f"可更新厂商库后复查",
            "items": [get(h, "ip") for h in unknown][:20]})

    for item in findings:
        item["items"] = [str(x) for x in item["items"] if x]
    return findings


# --------------------------------------------------------------------------- #
# 抓包封装
# --------------------------------------------------------------------------- #

class PassiveSniffer:
    """AsyncSniffer 的薄封装：后台线程收包 → 交给采集器。"""

    def __init__(self, iface, collector: PassiveCollector | None = None,
                 bpf: str = "", on_event=None, on_alert=None):
        self.iface = iface
        self.collector = collector or PassiveCollector(
            local_iface=getattr(iface, "alias", "") or "")
        self.bpf = (bpf or "").strip()
        self.on_event = on_event
        self.on_alert = on_alert
        self._sniffer = None
        self._seen_alerts = 0

    @property
    def running(self) -> bool:
        return self._sniffer is not None

    def start(self) -> None:
        if self.running:
            return
        if not is_admin():
            raise PermissionError("被动发现需要管理员权限（Npcap 原始收包）")
        from scapy.all import AsyncSniffer

        self.collector.local_iface = getattr(self.iface, "alias", "") or ""
        self.collector.started_at = time.time()
        self._seen_alerts = len(self.collector.alerts)
        try:
            self._sniffer = AsyncSniffer(
                iface=getattr(self.iface, "l2_name", "") or None,
                filter=self.bpf or None,
                prn=self._on_packet,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:
            self._sniffer = None
            raise RuntimeError(
                f"启动被动发现失败：{type(exc).__name__}: {exc}") from exc
        log(f"被动资产发现已开始：{getattr(self.iface, 'alias', '')}"
            + (f"  过滤={self.bpf}" if self.bpf else ""), "success", "passive")

    def _on_packet(self, pkt) -> None:
        event = self.collector.observe(pkt)
        if event and self.on_event is not None:
            try:
                self.on_event(event)
            except Exception:
                pass
        alerts = self.collector.alerts
        if len(alerts) > self._seen_alerts:
            self._seen_alerts = len(alerts)
            if self.on_alert is not None:
                try:
                    self.on_alert(alerts[-1])
                except Exception:
                    pass

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                log(f"停止被动发现出错：{exc}", "warn", "passive")
            self._sniffer = None
            log("被动资产发现已停止", "info", "passive")


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #

def bpf_for(modes: dict | None = None) -> str:
    """按勾选的协议拼一个 BPF 过滤串。"""
    modes = modes or {}
    parts: list[str] = []
    if modes.get("arp", True):
        parts.append("arp")
    if modes.get("dhcp", True):
        parts.append("(udp and (port 67 or port 68))")
    if modes.get("mdns", True):
        parts.append("(udp and port 5353)")
    if modes.get("nbns", True):
        parts.append("(udp and (port 137 or port 138))")
    if modes.get("lldp", True):
        parts.append("(ether proto 0x88cc)")
    if modes.get("cdp", True):
        parts.append("(ether dst 01:00:0c:cc:cc:cc)")
    return " or ".join(parts)


def export_csv(path: str, hosts: list) -> int:
    """导出资产表（hosts 可以是 PassiveHost 或 snapshot 里的 dict）。"""
    headers = ["IP", "MAC", "厂商", "主机名", "系统", "DHCP 厂商类",
               "来源", "包数", "首次发现", "最后发现"]
    rows = []
    for h in hosts:
        if isinstance(h, dict):
            rows.append([h.get("ip", ""), h.get("mac", ""), h.get("vendor", ""),
                         h.get("hostname", ""), h.get("os_guess", ""),
                         h.get("dhcp_vendor", ""),
                         " / ".join(h.get("sources", [])), h.get("packets", 0),
                         h.get("first_seen", ""), h.get("last_seen", "")])
        else:
            rows.append(h.row())
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(rows)
    return len(rows)
