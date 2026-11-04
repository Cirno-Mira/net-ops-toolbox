# -*- coding: utf-8 -*-
"""
流量画像（Flow 统计 + 应用识别）
================================

不存原始报文，只维护一张「五元组 → 计数」的流表，因此内存占用很小，
可以长时间挂着看谁在占带宽、在访问什么。

能做三件事：

1. **Top Talkers / Top 会话**：按字节数、包数排序；
2. **应用识别**：端口表 + 载荷特征（TLS SNI、HTTP Host、DNS 域名、协议横幅）；
3. **离线分析**：直接读 pcap 文件，不需要管理员，也不影响现场网络。

核心层零 Qt；实时抓包只做 AsyncSniffer 的薄封装，界面用 QTimer 主动拉快照。
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from dataclasses import dataclass, field

from .logging_bus import log

MAX_FLOWS = 20000
MAX_PAYLOAD = 1400

TCP_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS/TCP", 80: "HTTP", 81: "HTTP", 88: "Kerberos", 110: "POP3",
    111: "RPC", 135: "MS-RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog/TCP",
    587: "SMTP", 636: "LDAPS", 873: "Rsync", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2181: "ZooKeeper",
    2375: "Docker", 2376: "Docker/TLS", 3306: "MySQL", 3389: "RDP",
    5000: "HTTP-Alt", 5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "K8s API", 8000: "HTTP-Alt",
    8080: "HTTP-Alt", 8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "HTTP-Alt", 9092: "Kafka", 9200: "Elasticsearch",
    9300: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
    37777: "大华摄像头", 34567: "海康/摄像机", 554: "RTSP", 8554: "RTSP",
}

UDP_PORTS = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 111: "RPC",
    123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 161: "SNMP",
    162: "SNMP Trap", 500: "IKE", 514: "Syslog", 520: "RIP",
    5353: "mDNS", 5355: "LLMNR", 1900: "SSDP", 4500: "IPSec NAT-T",
    5060: "SIP", 5061: "SIP/TLS", 3478: "STUN", 4789: "VXLAN",
    51820: "WireGuard", 6000: "X11",
}

# 端口对不上时，用载荷特征兜底
PAYLOAD_SIGNATURES = [
    (b"SSH-", "SSH"),
    (b"\xfeSMB", "SMB"),
    (b"RFB 0", "VNC"),
    (b"* OK", "IMAP"),
    (b"+OK", "POP3"),
    (b"220 ", "SMTP/FTP"),
    (b"RTSP/", "RTSP"),
    (b"INVITE ", "SIP"),
    (b"REGISTER ", "SIP"),
    (b"HTTP/1.", "HTTP"),
    (b"\x16\x03", "TLS"),
]


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #

@dataclass
class Flow:
    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    direction: str = "lan"
    packets: int = 0
    nbytes: int = 0
    first: float = 0.0
    last: float = 0.0
    app: str = ""
    sni: str = ""
    host: str = ""
    dns: str = ""
    flags: set = field(default_factory=set)

    @property
    def key(self) -> tuple:
        return (self.proto, self.src, self.sport, self.dst, self.dport)

    def label(self) -> str:
        detail = self.sni or self.host or self.dns
        return f"{self.app or '未知'}" + (f" · {detail}" if detail else "")

    def peer(self) -> str:
        """对端（用于按目标聚合）。"""
        if self.direction == "out":
            return f"{self.dst}:{self.dport}"
        if self.direction == "in":
            return f"{self.src}:{self.sport}"
        return f"{self.dst}:{self.dport}"

    def local(self) -> str:
        if self.direction == "out":
            return self.src
        if self.direction == "in":
            return self.dst
        return self.src

    def row(self) -> list:
        span = max(0.0, self.last - self.first)
        rate = self.nbytes / span if span > 0.5 else 0.0
        return [
            self.label(), self.proto,
            f"{self.src}:{self.sport}", f"{self.dst}:{self.dport}",
            self.packets, format_bytes(self.nbytes), format_rate(rate),
            format_duration(span), ",".join(sorted(self.flags)) or "-",
        ]

    def to_dict(self) -> dict:
        return {"proto": self.proto, "src": self.src, "sport": self.sport,
                "dst": self.dst, "dport": self.dport,
                "direction": self.direction, "packets": self.packets,
                "bytes": self.nbytes, "app": self.app, "sni": self.sni,
                "host": self.host, "dns": self.dns,
                "flags": sorted(self.flags),
                "first": self.first, "last": self.last}


@dataclass
class Talker:
    host: str
    sent: int = 0
    recv: int = 0
    packets: int = 0
    flows: int = 0

    @property
    def total(self) -> int:
        return self.sent + self.recv

    def row(self) -> list:
        return [self.host, self.flows, self.packets,
                format_bytes(self.sent), format_bytes(self.recv),
                format_bytes(self.total)]


# --------------------------------------------------------------------------- #
# 载荷解析
# --------------------------------------------------------------------------- #

def tls_sni(payload: bytes) -> str:
    """从 TLS ClientHello 里取 SNI；解析失败返回空串。"""
    try:
        if len(payload) < 9 or payload[0] != 0x16 or payload[1] != 0x03:
            return ""
        length = int.from_bytes(payload[3:5], "big")
        body = payload[5:5 + length]
        if len(body) < 4 or body[0] != 0x01:          # handshake: ClientHello
            return ""
        handshake_len = int.from_bytes(body[1:4], "big")
        hello = body[4:4 + handshake_len]
        pos = 2 + 32                                   # version + random
        if len(hello) < pos + 1:
            return ""
        session_len = hello[pos]
        pos += 1 + session_len
        if len(hello) < pos + 2:
            return ""
        cipher_len = int.from_bytes(hello[pos:pos + 2], "big")
        pos += 2 + cipher_len
        if len(hello) < pos + 1:
            return ""
        comp_len = hello[pos]
        pos += 1 + comp_len
        if len(hello) < pos + 2:
            return ""
        ext_total = int.from_bytes(hello[pos:pos + 2], "big")
        pos += 2
        end = min(len(hello), pos + ext_total)
        while pos + 4 <= end:
            ext_type = int.from_bytes(hello[pos:pos + 2], "big")
            ext_len = int.from_bytes(hello[pos + 2:pos + 4], "big")
            pos += 4
            data = hello[pos:pos + ext_len]
            pos += ext_len
            if ext_type != 0x0000 or len(data) < 5:   # server_name
                continue
            # server_name_list: len(2) + type(1) + len(2) + name
            name_len = int.from_bytes(data[3:5], "big")
            name = data[5:5 + name_len]
            # SNI 是 ASCII / punycode；"idna" 编解码器不支持 errors="ignore"
            return name.decode("ascii", "ignore").strip().strip(".")
    except Exception:
        return ""
    return ""


def http_host(payload: bytes) -> str:
    """从 HTTP 请求头里取 Host。"""
    head = payload[:4096]
    if not re.match(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE)\s",
                    head):
        return ""
    match = re.search(rb"(?im)^Host:\s*([^\r\n]+)", head)
    if not match:
        return ""
    return match.group(1).decode("latin-1", "ignore").strip()[:120]


def http_method(payload: bytes) -> str:
    head = payload[:16]
    match = re.match(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE)\s",
                     head)
    return match.group(1).decode("ascii") if match else ""


def app_by_payload(proto: str, payload: bytes) -> str:
    if not payload:
        return ""
    for sig, name in PAYLOAD_SIGNATURES:
        if payload.startswith(sig):
            return name
    if payload[:1] == b"\x16" and len(payload) > 2 and payload[1] == 0x03:
        return "TLS"
    if proto == "UDP" and len(payload) >= 12 and payload[0] & 0x80:
        return "QUIC/HTTP3"
    return ""


def app_by_ports(proto: str, dport: int, sport: int) -> str:
    table = TCP_PORTS if proto == "TCP" else UDP_PORTS
    if dport in table:
        return table[dport]
    if sport in table:
        return table[sport]
    return ""


# --------------------------------------------------------------------------- #
# 流表
# --------------------------------------------------------------------------- #

class FlowTable:
    """五元组聚合。线程安全，但只在收包线程里写。"""

    def __init__(self, local_nets=None):
        self.flows: dict[tuple, Flow] = {}
        self.local_nets = [ipaddress.ip_network(n, strict=False)
                           for n in (local_nets or []) if n]
        self._lock = threading.RLock()
        self.started_at = time.time()
        self.packets = 0
        self.nbytes = 0
        self._names: dict[str, str] = {}
        self.dropped = 0

    # ---------------- 写入 ----------------

    def add(self, pkt) -> Flow | None:
        try:
            with self._lock:
                return self._add_locked(pkt)
        except Exception as exc:
            self.dropped += 1
            log(f"流表解析失败：{type(exc).__name__}: {exc}", "debug", "flows")
            return None

    def _add_locked(self, pkt) -> Flow | None:
        if not pkt.haslayer("IP"):
            return None
        ip = pkt["IP"]
        src, dst = str(ip.src), str(ip.dst)
        proto = ""
        sport = dport = 0
        payload = b""
        flags = set()

        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            proto = "TCP"
            sport, dport = int(tcp.sport or 0), int(tcp.dport or 0)
            payload = bytes(tcp.payload)[:MAX_PAYLOAD]
            for bit, name in ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"),
                              (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")):
                if int(tcp.flags) & bit:
                    flags.add(name)
        elif pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            proto = "UDP"
            sport, dport = int(udp.sport or 0), int(udp.dport or 0)
            payload = bytes(udp.payload)[:MAX_PAYLOAD]
        else:
            return None

        dns_name = _dns_answer_name(pkt, src)
        if dns_name:
            self._names[src] = dns_name

        key = (proto, src, sport, dst, dport)
        now = time.time()
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= MAX_FLOWS:
                self._prune_oldest()
            flow = Flow(proto=proto, src=src, sport=sport, dst=dst,
                        dport=dport, first=now, direction=self._direction(src, dst))
            self.flows[key] = flow

        flow.packets += 1
        size = int(getattr(ip, "len", 0) or 0) or len(bytes(pkt))
        flow.nbytes += size
        flow.last = now
        flow.flags |= flags
        self.packets += 1
        self.nbytes += size

        app = app_by_ports(proto, dport, sport)
        detail = ""
        if payload:
            if not flow.sni:
                sni = tls_sni(payload)
                if sni:
                    flow.sni = sni
                    detail = sni
            if not flow.host:
                host = http_host(payload)
                if host:
                    flow.host = host
                    detail = host
            if dns_name:
                flow.dns = dns_name
                detail = detail or dns_name
            if not app:
                app = app_by_payload(proto, payload)
            if proto == "TCP" and flow.host and not app:
                app = "HTTP"
        if dport == 53 or sport == 53:
            app = app or "DNS"
        if not app and flow.dns:
            app = "DNS 关联"
        if not app:
            app = "未知"
        flow.app = app
        if detail and not (flow.sni or flow.host):
            flow.dns = flow.dns or detail
        return flow

    def _direction(self, src: str, dst: str) -> str:
        src_local = self._local(src)
        dst_local = self._local(dst)
        if src_local and not dst_local:
            return "out"
        if dst_local and not src_local:
            return "in"
        return "lan"

    def _local(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if not self.local_nets:
            return addr.is_private or addr.is_loopback or addr.is_link_local
        return any(addr in net for net in self.local_nets)

    def _prune_oldest(self) -> None:
        if not self.flows:
            return
        ordered = sorted(self.flows.items(), key=lambda kv: kv[1].last)
        for key, _flow in ordered[: max(1, len(ordered) // 10)]:
            self.flows.pop(key, None)

    # ---------------- 读取 ----------------

    def reset(self) -> None:
        with self._lock:
            self.flows.clear()
            self._names.clear()
            self.packets = 0
            self.nbytes = 0
            self.dropped = 0
            self.started_at = time.time()

    def snapshot(self, top: int = 200) -> dict:
        with self._lock:
            flows = sorted(self.flows.values(),
                           key=lambda f: f.nbytes, reverse=True)[:top]
            talkers = self._talkers()
            apps = self._by_app()
            return {
                "flows": [f.to_dict() for f in flows],
                "talkers": [{"host": t.host, "sent": t.sent, "recv": t.recv,
                             "total": t.total, "packets": t.packets,
                             "flows": t.flows} for t in talkers[:top]],
                "apps": apps,
                "packets": self.packets,
                "bytes": self.nbytes,
                "flows_total": len(self.flows),
                "dropped": self.dropped,
                "uptime": round(time.time() - self.started_at, 1),
                "pps": self.pps(),
                "bps": self.bps(),
            }

    def _talkers(self) -> list[Talker]:
        talkers: dict[str, Talker] = {}
        for flow in self.flows.values():
            host = flow.local()
            if not host:
                continue
            talker = talkers.get(host)
            if talker is None:
                talker = Talker(host=host)
                talkers[host] = talker
            talker.flows += 1
            talker.packets += flow.packets
            if flow.direction == "out":
                talker.sent += flow.nbytes
            else:
                talker.recv += flow.nbytes
        return sorted(talkers.values(), key=lambda t: t.total, reverse=True)

    def _by_app(self) -> list[dict]:
        stats: dict[str, dict] = {}
        for flow in self.flows.values():
            item = stats.setdefault(flow.app or "未知",
                                    {"app": flow.app or "未知",
                                     "bytes": 0, "packets": 0, "flows": 0})
            item["bytes"] += flow.nbytes
            item["packets"] += flow.packets
            item["flows"] += 1
        return sorted(stats.values(), key=lambda x: x["bytes"], reverse=True)

    def top_talkers(self, n: int = 10) -> list[Talker]:
        with self._lock:
            return self._talkers()[:n]

    def top_apps(self, n: int = 8) -> list[tuple]:
        with self._lock:
            return [(item["app"], item["bytes"]) for item in self._by_app()[:n]]

    def top_destinations(self, n: int = 10) -> list[tuple]:
        with self._lock:
            stats: dict[str, int] = {}
            for flow in self.flows.values():
                peer = flow.dst if flow.direction == "out" else flow.src
                stats[peer] = stats.get(peer, 0) + flow.nbytes
            return sorted(stats.items(), key=lambda kv: kv[1], reverse=True)[:n]

    def pps(self) -> float:
        span = max(1.0, time.time() - self.started_at)
        return round(self.packets / span, 1)

    def bps(self) -> float:
        span = max(1.0, time.time() - self.started_at)
        return round(self.nbytes * 8 / span, 1)

    def flow_rows(self, top: int = 200) -> list[list]:
        with self._lock:
            flows = sorted(self.flows.values(),
                           key=lambda f: f.nbytes, reverse=True)[:top]
            return [f.row() for f in flows]


def _dns_answer_name(pkt, src: str) -> str:
    """从 DNS 应答里取第一个 A 记录的名字，用来给后续流打标签。"""
    dns = pkt.getlayer("DNS")
    if dns is None or not getattr(dns, "ancount", 0):
        return ""
    for rr in getattr(dns, "an", None) or []:
        name = getattr(rr, "rrname", None)
        if name:
            text = name.decode("utf-8", "ignore") if isinstance(name, bytes) else str(name)
            return text.strip(".")
    return ""


# --------------------------------------------------------------------------- #
# 实时 / 离线
# --------------------------------------------------------------------------- #

class FlowMonitor:
    """AsyncSniffer 薄封装：只喂流表，不落盘。"""

    def __init__(self, iface, bpf: str = "ip", local_nets=None):
        self.iface = iface
        self.bpf = (bpf or "ip").strip()
        self.table = FlowTable(local_nets=local_nets)
        self._sniffer = None

    @property
    def running(self) -> bool:
        return self._sniffer is not None

    def start(self) -> None:
        if self.running:
            return
        from scapy.all import AsyncSniffer
        self.table.started_at = time.time()
        try:
            self._sniffer = AsyncSniffer(
                iface=getattr(self.iface, "l2_name", "") or None,
                filter=self.bpf or None,
                prn=self.table.add,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:
            self._sniffer = None
            raise RuntimeError(f"启动流量画像失败：{type(exc).__name__}: {exc}") from exc
        log(f"流量画像已开始：{getattr(self.iface, 'alias', '')}"
            f"  过滤={self.bpf}", "success", "flows")

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                log(f"停止流量画像出错：{exc}", "warn", "flows")
            self._sniffer = None
            log("流量画像已停止", "info", "flows")


def analyze_pcap(path: str, limit: int = 200000, local_nets=None,
                 progress=None) -> FlowTable:
    """离线分析 pcap / pcapng。不需要管理员权限。"""
    from scapy.utils import PcapReader

    table = FlowTable(local_nets=local_nets)
    try:
        with PcapReader(path) as reader:
            for index, pkt in enumerate(reader, 1):
                table.add(pkt)
                if progress is not None and index % 500 == 0:
                    progress(index)
                if index >= limit:
                    break
    except Exception as exc:
        raise RuntimeError(f"读取 {path} 失败：{type(exc).__name__}: {exc}") from exc
    log(f"离线分析完成：{path}（{table.packets} 个包，{len(table.flows)} 条流）",
        "success", "flows")
    return table


# --------------------------------------------------------------------------- #
# 格式化
# --------------------------------------------------------------------------- #

def format_bytes(value: float) -> str:
    value = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def format_rate(bps: float) -> str:
    value = float(bps or 0) * 8
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if value < 1000 or unit == "Gbps":
            return f"{value:.0f} {unit}" if unit == "bps" else f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} Gbps"


def format_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds or 0))
    if seconds < 60:
        return f"{seconds:.0f} 秒"
    minutes, sec = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes} 分 {sec:02d} 秒"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} 时 {minutes:02d} 分"
