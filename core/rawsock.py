# -*- coding: utf-8 -*-
"""
原始套接字（Npcap）统一出入口
==============================

scapy 的 `sendp()` 每次调用都会新开一个 pcap 句柄、发完再关掉。
ARP 牵引每 2 秒发一轮、DNS 引流每收到一个查询就回一个包，
再叠加若干个常驻的 `AsyncSniffer`，会让 Npcap 设备被反复开关，
容易在 `wpcap.dll` / `Packet.dll` 中触发访问违例——这类 native 崩溃
无法被 Python 的异常机制捕获。

本模块的做法：
1. 每个网卡只保留一个常驻发送句柄，反复复用，不再开关
2. 所有收发与句柄创建都经过同一把全局可重入锁，避免多线程同时访问 Npcap
3. 提供 `close_all()`，退出前统一释放句柄
"""

from __future__ import annotations

import threading

from .logging_bus import log

# 所有原始收发都串行化。用 RLock 是因为 send_packets 内部还会调 get_sender。
RAW_LOCK = threading.RLock()

_senders: dict[str, object] = {}
_sender_errors: dict[str, str] = {}


def get_sender(iface_name: str):
    """取（或创建）这块网卡的常驻发送句柄。"""
    key = iface_name or ""
    with RAW_LOCK:
        sender = _senders.get(key)
        if sender is not None:
            return sender
        try:
            from scapy.all import conf
            sender = conf.L2socket(iface=iface_name or None)
            _senders[key] = sender
            _sender_errors.pop(key, None)
            log(f"已建立常驻发包句柄：{iface_name or '(默认网卡)'}", "debug", "rawsock")
        except Exception as exc:
            _sender_errors[key] = f"{type(exc).__name__}: {exc}"
            log(f"建立发包句柄失败（{iface_name}）：{exc}", "error", "rawsock")
            return None
        return sender


def send_packets(pkts: list, iface_name: str = "") -> int:
    """
    用常驻句柄把包发出去。失败会重试一次（重建句柄）。
    返回成功发出的包数；0 表示一个都没发出去。
    """
    if not pkts:
        return 0
    with RAW_LOCK:
        for attempt in (1, 2):
            sender = get_sender(iface_name)
            if sender is None:
                return 0
            try:
                for p in pkts:
                    sender.send(p)
                return len(pkts)
            except Exception as exc:
                log(f"发送失败（第 {attempt} 次）：{type(exc).__name__}: {exc}",
                    "warn" if attempt == 1 else "error", "rawsock")
                # 句柄可能已经失效，丢掉重建再试一次
                _close_sender(iface_name)
        return 0


def _close_sender(iface_name: str) -> None:
    key = iface_name or ""
    sender = _senders.pop(key, None)
    if sender is not None:
        try:
            sender.close()
        except Exception:
            pass


def srp_locked(pkt, iface_name: str = "", timeout: float = 3.0, retry: int = 0):
    """
    串行化的 srp（发一层包并收回应）。同时只允许一个 srp 在跑，
    避免它和常驻嗅探器抢 Npcap 句柄。
    """
    from scapy.all import srp
    with RAW_LOCK:
        try:
            return srp(pkt, iface=iface_name or None, timeout=timeout,
                       verbose=0, retry=retry)
        except Exception as exc:
            log(f"srp 收发失败：{type(exc).__name__}: {exc}", "debug", "rawsock")
            return [], []


def sendp_locked(pkts, iface_name: str = "") -> int:
    """兼容旧调用名。"""
    return send_packets(pkts, iface_name)


def close_all() -> None:
    """退出前统一释放所有常驻句柄（一定要在解释器退出前调用）。"""
    with RAW_LOCK:
        for key in list(_senders):
            _close_sender(key)


def sender_status() -> dict:
    with RAW_LOCK:
        return {"open": list(_senders), "errors": dict(_sender_errors)}
