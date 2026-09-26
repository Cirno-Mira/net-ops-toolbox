# -*- coding: utf-8 -*-
"""
抓包
====

用 scapy 的 AsyncSniffer 在指定网卡上抓包：

* 支持 BPF 过滤（走 Npcap/libpcap）
* 支持边抓边写 .pcap（可直接用 Wireshark 打开分析）
* 包摘要放在线程安全缓冲区里，由界面定时拉取（drain），
  避免高流量时逐个信号把 UI 刷爆
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from .hostinfo import Iface, is_admin
from .logging_bus import log


# --------------------------------------------------------------------------- #
# 包摘要
# --------------------------------------------------------------------------- #

def summarize(pkt) -> dict:
    """把一个 scapy 包压成表格里能显示的一行。"""
    info = {
        "time": time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}",
        "src": "", "dst": "", "proto": "", "len": len(pkt), "info": "",
    }
    try:
        if pkt.haslayer("ARP"):
            a = pkt["ARP"]
            op = {1: "who-has", 2: "is-at"}.get(int(a.op), str(a.op))
            info.update(src=a.psrc, dst=a.pdst, proto="ARP",
                        info=f"{op} {a.psrc} -> {a.pdst}"
                             + (f" [{a.hwsrc}]" if int(a.op) == 2 else ""))
            return info

        if pkt.haslayer("IP"):
            ip = pkt["IP"]
            info["src"], info["dst"] = ip.src, ip.dst
            if pkt.haslayer("TCP"):
                t = pkt["TCP"]
                flags = str(t.flags)
                info["src"] += f":{t.sport}"
                info["dst"] += f":{t.dport}"
                info["proto"] = "TCP"
                extra = ""
                if pkt.haslayer("Raw"):
                    try:
                        extra = bytes(pkt["Raw"].load)[:60].decode("utf-8", "replace")
                        extra = " " + extra.replace("\r", " ").replace("\n", " ").strip()
                    except Exception:
                        extra = ""
                info["info"] = f"[{flags}] seq={t.seq} win={t.window}{extra}"
            elif pkt.haslayer("UDP"):
                u = pkt["UDP"]
                info["src"] += f":{u.sport}"
                info["dst"] += f":{u.dport}"
                info["proto"] = "UDP"
                if pkt.haslayer("DNS"):
                    d = pkt["DNS"]
                    q = d.qd.qname.decode("utf-8", "replace") if d.qd else ""
                    if int(d.qr) == 0:
                        info["info"] = f"标准查询 {q} type={d.qd.qtype if d.qd else ''}"
                    else:
                        info["info"] = f"响应 {q} answers={d.ancount}"
                else:
                    info["info"] = f"len={len(u.payload)}"
            elif pkt.haslayer("ICMP"):
                ic = pkt["ICMP"]
                info["proto"] = "ICMP"
                info["info"] = f"type={ic.type} code={ic.code}"
            else:
                info["proto"] = f"IP/{ip.proto}"
                info["info"] = f"proto={ip.proto} ttl={ip.ttl}"
            return info

        if pkt.haslayer("IPv6"):
            v6 = pkt["IPv6"]
            info.update(src=v6.src, dst=v6.dst, proto="IPv6", info=f"nh={v6.nh}")
            return info

        info["proto"] = pkt.lastlayer().name if pkt.lastlayer() else "?"
        info["info"] = pkt.summary()
    except Exception:
        info["info"] = "解析失败"
    return info


def pair_key(src: str, sport: int, dst: str, dport: int):
    """把一条流归一成「无向」的会话键，用来把双向合并展示。"""
    a, b = (src, sport), (dst, dport)
    return (a, b) if a <= b else (b, a)


@dataclass
class FilterRule:
    """一条抓包筛选规则。多条规则之间是「与」的关系。"""
    field: str = "any"          # any / src / dst / proto / info
    op: str = "contains"        # contains / not_contains / eq / not_eq / regex
    value: str = ""
    enabled: bool = True

    def describe(self) -> str:
        return f"{FIELD_LABELS.get(self.field, self.field)} " \
               f"{OP_LABELS.get(self.op, self.op)} {self.value}"


FIELD_LABELS = {
    "any": "任意字段", "src": "源地址", "dst": "目的地址",
    "proto": "协议", "info": "摘要",
}
OP_LABELS = {
    "contains": "包含", "not_contains": "不包含",
    "eq": "等于", "not_eq": "不等于", "regex": "正则匹配",
}


class PacketFilter:
    """
    抓包筛选器：只保留（或不保留）含有指定字符串的包。

    可以同时启用多条规则，规则之间取「与」——全部命中才留下。
    例：源地址包含 192.168.5.10  **并且**  协议等于 TCP
    """

    def __init__(self, rules: list[FilterRule] | None = None) -> None:
        self.rules: list[FilterRule] = list(rules or [])

    # ---------- 规则管理 ----------

    def add(self, field: str = "any", op: str = "contains", value: str = "") -> FilterRule:
        r = FilterRule(field=field, op=op, value=value)
        self.rules.append(r)
        return r

    def remove(self, index: int) -> None:
        if 0 <= index < len(self.rules):
            del self.rules[index]

    def clear(self) -> None:
        self.rules.clear()

    def active(self) -> list[FilterRule]:
        return [r for r in self.rules if r.enabled and r.value.strip()]

    @property
    def is_empty(self) -> bool:
        return not self.active()

    def describe(self) -> str:
        act = self.active()
        if not act:
            return "未启用筛选"
        return " 且 ".join(r.describe() for r in act)

    # ---------- 匹配 ----------

    @staticmethod
    def _text_of(field: str, packet: dict) -> str:
        if field == "src":
            return str(packet.get("src", ""))
        if field == "dst":
            return str(packet.get("dst", ""))
        if field == "proto":
            return str(packet.get("proto", ""))
        if field == "info":
            return str(packet.get("info", ""))
        # any：所有字段拼一起找
        return " ".join(str(packet.get(k, "")) for k in
                        ("src", "dst", "proto", "info"))

    @staticmethod
    def _match_one(rule: FilterRule, packet: dict) -> bool:
        text = PacketFilter._text_of(rule.field, packet)
        want = rule.value.strip()
        if not want:
            return True
        if rule.op == "regex":
            try:
                return re.search(want, text, re.I) is not None
            except re.error:
                return False
        low_text, low_want = text.lower(), want.lower()
        if rule.op == "eq":
            return low_text.strip() == low_want
        if rule.op == "not_eq":
            return low_text.strip() != low_want
        if rule.op == "not_contains":
            return low_want not in low_text
        return low_want in low_text          # contains（默认）

    def match(self, packet: dict) -> bool:
        for rule in self.active():
            if not self._match_one(rule, packet):
                return False
        return True

    # ---------- 快捷规则 ----------

    def only_host(self, text: str) -> None:
        """快捷：只保留和某台主机相关的包（源或目的里有这个字符串）。"""
        self.rules = [FilterRule(field="any", op="contains", value=text)]

    def exclude(self, text: str) -> None:
        """快捷：排除包含某个字符串的包。"""
        self.rules.append(FilterRule(field="any", op="not_contains", value=text))


@dataclass
class CaptureStats:
    running: bool = False
    packets: int = 0
    bytes: int = 0
    dropped: int = 0
    started_at: float = 0.0
    pcap_path: str = ""
    last_error: str = ""
    by_proto: dict = field(default_factory=dict)

    @property
    def uptime(self) -> str:
        if not self.started_at:
            return "00:00:00"
        s = int(time.time() - self.started_at)
        h, r = divmod(s, 3600)
        m, sec = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{sec:02d}"

    @property
    def pps(self) -> float:
        up = time.time() - self.started_at if self.started_at else 0
        return self.packets / up if up > 0.5 else 0.0


class PacketCapture:
    """抓包器：start() / stop()，用 drain() 取新包，stats 看统计。"""

    def __init__(self, iface: Iface, bpf: str = "", pcap_path: str = "",
                 max_buffer: int = 5000) -> None:
        self.iface = iface
        self.bpf = (bpf or "").strip()
        self.pcap_path = pcap_path
        self.stats = CaptureStats(pcap_path=pcap_path)
        self._buf: deque = deque(maxlen=max_buffer)
        self._lock = threading.Lock()
        # TCP 会话重组：把同一条流的载荷按序拼起来，CTF 里传文件的题很好用
        self.streams: dict[tuple, dict] = {}
        self.max_streams = 500
        self.max_stream_bytes = 16 * 1024 * 1024
        self._stream_total = 0
        self._sniffer = None
        self._writer = None
        self._pending = 0

    # ---------------- 生命周期 ----------------

    def start(self) -> None:
        if not is_admin():
            raise PermissionError("抓包需要管理员权限（Npcap 原始收包）")
        from scapy.all import AsyncSniffer

        if self.pcap_path:
            try:
                from scapy.utils import PcapWriter
                self._writer = PcapWriter(self.pcap_path, append=False, sync=False)
            except Exception as exc:
                log(f"创建 pcap 文件失败：{exc}", "error", "capture")
                self._writer = None

        self.stats = CaptureStats(running=True, started_at=time.time(),
                                  pcap_path=self.pcap_path)
        try:
            self._sniffer = AsyncSniffer(
                iface=self.iface.l2_name or None,
                filter=self.bpf or None,
                prn=self._on_packet,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:
            self.stats.running = False
            raise RuntimeError(f"启动抓包失败：{type(exc).__name__}: {exc}") from exc

        log(f"开始抓包：{self.iface.alias}"
            + (f"  过滤={self.bpf}" if self.bpf else "")
            + (f"  → {self.pcap_path}" if self.pcap_path else ""), "success", "capture")

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                log(f"停止抓包出错：{exc}", "warn", "capture")
            self._sniffer = None
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None
        if self.stats.running:
            self.stats.running = False
            log(f"抓包结束：{self.stats.packets} 个包，{self.stats.bytes} 字节",
                "success", "capture")

    # ---------------- 收包 ----------------

    def _on_packet(self, pkt) -> None:
        try:
            if self._writer is not None:
                self._writer.write(pkt)
                self._pending += 1
                if self._pending >= 64:
                    self._pending = 0
                    try:
                        self._writer.flush()
                    except Exception:
                        pass
        except Exception as exc:
            self.stats.last_error = str(exc)

        s = summarize(pkt)
        try:
            s["raw"] = bytes(pkt)          # 留原始字节，供「编辑并重放」用
        except Exception:
            s["raw"] = b""
        self._track_stream(pkt)
        with self._lock:
            self._buf.append(s)
            self.stats.packets += 1
            self.stats.bytes += s["len"]
            self.stats.by_proto[s["proto"]] = self.stats.by_proto.get(s["proto"], 0) + 1

    # ---------------- TCP 会话重组 ----------------

    def _track_stream(self, pkt) -> None:
        """把 TCP 载荷按「方向」缓存起来，便于把传输的文件/响应体整段导出。"""
        try:
            if not (pkt.haslayer("IP") and pkt.haslayer("TCP")):
                return
            if not pkt.haslayer("Raw"):
                return
            ip, tcp = pkt["IP"], pkt["TCP"]
            key = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
            with self._lock:
                st = self.streams.get(key)
                if st is None:
                    if len(self.streams) >= self.max_streams * 2:
                        return
                    st = {"key": key, "src": f"{ip.src}:{tcp.sport}",
                          "dst": f"{ip.dst}:{tcp.dport}",
                          "payload": bytearray(), "packets": 0,
                          "first": time.strftime("%H:%M:%S")}
                    self.streams[key] = st
                if self._stream_total < self.max_stream_bytes:
                    data = bytes(pkt["Raw"].load)
                    st["payload"] += data
                    self._stream_total += len(data)
                st["packets"] += 1
        except Exception:
            pass

    def stream_list(self) -> list[dict]:
        """按「双向会话」聚合展示，每条给出两个方向各自的字节数。"""
        with self._lock:
            pairs: dict[tuple, dict] = {}
            for key, st in self.streams.items():
                (a, b) = pair_key(*key)
                item = pairs.get((a, b))
                if item is None:
                    item = {"pair": (a, b), "a": f"{a[0]}:{a[1]}", "b": f"{b[0]}:{b[1]}",
                            "a_bytes": 0, "b_bytes": 0, "packets": 0,
                            "first": st["first"],
                            "a_key": None, "b_key": None}
                    pairs[(a, b)] = item
                item["packets"] += st["packets"]
                n = len(st["payload"])
                if (st["src"]) == f"{a[0]}:{a[1]}":
                    item["a_bytes"] += n
                    item["a_key"] = key
                else:
                    item["b_bytes"] += n
                    item["b_key"] = key
            out = list(pairs.values())
            out.sort(key=lambda x: -(x["a_bytes"] + x["b_bytes"]))
            return out

    def stream_data(self, key) -> bytes:
        with self._lock:
            st = self.streams.get(key)
            return bytes(st["payload"]) if st else b""

    def save_stream(self, key, path: str) -> tuple[bool, str]:
        data = self.stream_data(key)
        if not data:
            return False, "这个方向没有载荷数据"
        try:
            with open(path, "wb") as fh:
                fh.write(data)
            return True, path
        except OSError as exc:
            return False, str(exc)

    def reset_streams(self) -> None:
        with self._lock:
            self.streams.clear()
            self._stream_total = 0

    def drain(self, limit: int = 400) -> list[dict]:
        """取出缓冲区里的新包（界面定时调用）。"""
        out = []
        with self._lock:
            while self._buf and len(out) < limit:
                out.append(self._buf.popleft())
        return out

    def clear(self) -> None:
        with self._lock:
            self._buf.clear()

    @property
    def running(self) -> bool:
        return bool(self.stats.running)
