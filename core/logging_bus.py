# -*- coding: utf-8 -*-
"""
统一日志总线
============

核心层不依赖 Qt，所以这里用一个极简的发布/订阅实现：
工作线程调用 log()，UI 层订阅后把消息转成 Qt 信号（队列连接）投递到主线程。

    from core.logging_bus import log, BUS
    log("扫描完成", "success", "assets")
"""

from __future__ import annotations

import threading
from datetime import datetime

LEVELS = ("debug", "info", "success", "warn", "error")


class LogBus:
    def __init__(self) -> None:
        self._subs: list = []
        self._lock = threading.Lock()
        self._history: list[tuple[str, str, str, str]] = []
        self.max_history = 2000

    def subscribe(self, fn) -> None:
        """fn(level: str, source: str, text: str, ts: str)"""
        with self._lock:
            self._subs.append(fn)

    def unsubscribe(self, fn) -> None:
        with self._lock:
            if fn in self._subs:
                self._subs.remove(fn)

    def emit(self, level: str, source: str, text: str) -> None:
        level = level if level in LEVELS else "info"
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._history.append((level, source, text, ts))
            if len(self._history) > self.max_history:
                del self._history[: len(self._history) - self.max_history]
            subs = list(self._subs)
        for fn in subs:
            try:
                fn(level, source, text, ts)
            except Exception:       # 日志本身不能把程序搞崩
                pass

    def history(self) -> list[tuple[str, str, str, str]]:
        with self._lock:
            return list(self._history)

    def clear(self) -> None:
        with self._lock:
            self._history.clear()


BUS = LogBus()


def log(text: str, level: str = "info", source: str = "core") -> None:
    BUS.emit(level, source, text)
