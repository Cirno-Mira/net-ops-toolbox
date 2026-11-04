# -*- coding: utf-8 -*-
"""
资产变更监控
============

把「定期采样 → 存快照 → 和上一份对比 → 报变化」串起来。

三种数据源都已接好：

* `make_assets_source(...)`   主动扫描（复用 core.assets.discover）
* `make_passive_source(...)`  被动采集（复用 PassiveCollector.snapshot）
* `make_snmp_source(...)`     交换机接口表（复用 core.snmp.interfaces）

`MonitorSession` 自身是个普通后台线程，界面用 QTimer 轮询 `status()` /
`last_diff` 即可 —— 不要把 Qt 控件或 QTimer 带进工作线程。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from . import store as ST
from .logging_bus import log


@dataclass
class Sample:
    at: str
    snapshot_id: int
    rows: int
    changes: int = 0
    error: str = ""


@dataclass
class MonitorStatus:
    running: bool = False
    kind: str = ""
    label: str = ""
    interval: float = 60.0
    samples: int = 0
    errors: int = 0
    last_at: str = ""
    last_snapshot_id: int = 0
    last_rows: int = 0
    next_at: str = ""
    history: list = field(default_factory=list)
    last_error: str = ""


class MonitorSession:
    """
    定期采样器。

    source 是一个无参函数，返回 `rows` 或 `(rows, meta)`；主键与忽略字段默认
    取自 `core.store.KINDS[kind]`。
    """

    def __init__(self, snapshot_store: ST.SnapshotStore, kind: str, source,
                 label: str = "", interval: float = 60.0,
                 key_field: str = "", ignore_fields=(),
                 baseline_id: int = 0, max_history: int = 120):
        spec = ST.KINDS.get(kind, {})
        self.store = snapshot_store
        self.kind = kind
        self.source = source
        self.label = label or spec.get("label", kind)
        self.interval = max(5.0, float(interval or 60.0))
        self.key_field = key_field or spec.get("key", "ip")
        self.ignore_fields = tuple(ignore_fields or spec.get("ignore", ()))
        self.max_history = max(10, int(max_history))

        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._last_rows: list = []
        self._last_diff: ST.DiffResult | None = None
        self._baseline: ST.Snapshot | None = None
        self._samples: list[Sample] = []
        self._errors = 0
        self._last_error = ""
        self._last_at = ""
        self._last_snapshot_id = 0
        self._next_at = 0.0

        if baseline_id:
            snap = self.store.load(baseline_id)
            if snap is not None:
                self._baseline = snap

    # ---------------- 生命周期 ----------------

    def start(self, immediate: bool = True) -> bool:
        if self.is_running():
            return False
        if not self.store.available:
            return False
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._loop, args=(immediate,),
                                        name=f"monitor-{self.kind}", daemon=True)
        self._thread.start()
        log(f"变更监控已启动：{self.label}，每 {human_interval(self.interval)} 采样一次",
            "success", "monitor")
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_evt.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(max(0.5, timeout))
        self._thread = None
        log(f"变更监控已停止：{self.label}", "info", "monitor")

    def is_running(self) -> bool:
        return bool(self._thread is not None and self._thread.is_alive())

    def _loop(self, immediate: bool) -> None:
        if immediate and not self._stop_evt.is_set():
            self.tick()
        while not self._stop_evt.is_set():
            self._next_at = time.time() + self.interval
            if self._stop_evt.wait(self.interval):
                break
            if self._stop_evt.is_set():
                break
            self.tick()

    # ---------------- 采样 ----------------

    def tick(self) -> ST.DiffResult | None:
        """立刻采一份快照并对比。返回本次差异（失败返回 None）。"""
        try:
            rows, meta = self._collect()
        except Exception as exc:
            self._errors += 1
            self._last_error = f"{type(exc).__name__}: {exc}"
            log(f"监控采样失败（{self.label}）：{self._last_error}", "error", "monitor")
            return None

        if not isinstance(rows, list):
            rows = list(rows or [])
        meta = dict(meta or {})
        meta.setdefault("source", self.kind)
        meta.setdefault("label", self.label)

        try:
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            snapshot_id = self.store.save(
                self.kind, rows, label=f"{self.label} {stamp}", meta=meta)
            previous = self.store.previous(self.kind, snapshot_id)
        except Exception as exc:
            self._errors += 1
            self._last_error = f"{type(exc).__name__}: {exc}"
            log(f"快照保存失败：{self._last_error}", "error", "monitor")
            return None

        diff = ST.diff_rows(previous.rows if previous else [], rows,
                            key_field=self.key_field,
                            ignore_fields=self.ignore_fields)
        diff.old_label = previous.label if previous else "（首次采样）"
        diff.new_label = f"#{snapshot_id} {stamp}"

        with self._lock:
            self._last_rows = rows
            self._last_diff = diff
            self._last_at = stamp
            self._last_snapshot_id = snapshot_id
            self._last_error = ""
            self._samples.append(Sample(at=stamp, snapshot_id=snapshot_id,
                                        rows=len(rows),
                                        changes=diff.total_changes))
            if len(self._samples) > self.max_history:
                del self._samples[:len(self._samples) - self.max_history]

        if previous is not None:
            if diff.total_changes:
                log(f"{self.label} 检测到变化：{diff.summary()}",
                    "warn", "monitor")
            else:
                log(f"{self.label} 无变化（{len(rows)} 行）", "info", "monitor")
        else:
            log(f"{self.label} 首次采样：{len(rows)} 行，已建立基线",
                "success", "monitor")
        return diff

    def _collect(self) -> tuple[list, dict]:
        result = self.source() if callable(self.source) else self.source
        if isinstance(result, tuple) and len(result) == 2:
            rows, meta = result
            return rows, meta
        return result or [], {}

    # ---------------- 基线 ----------------

    def set_baseline(self, snapshot_id: int = 0) -> ST.Snapshot | None:
        snap = (self.store.load(snapshot_id) if snapshot_id
                else self.store.latest(self.kind))
        if snap is not None:
            self._baseline = snap
            log(f"已把快照 #{snap.id} 设为基线", "info", "monitor")
        return snap

    def compare_to_baseline(self) -> ST.DiffResult | None:
        baseline = self._baseline
        if baseline is None:
            baseline = self.set_baseline()
        if baseline is None:
            return None
        with self._lock:
            rows = list(self._last_rows)
        diff = ST.diff_rows(baseline.rows, rows, key_field=self.key_field,
                            ignore_fields=self.ignore_fields)
        diff.old_label = f"基线 #{baseline.id} {baseline.created_at}"
        diff.new_label = "当前"
        return diff

    # ---------------- 状态 ----------------

    @property
    def last_diff(self) -> ST.DiffResult | None:
        with self._lock:
            return self._last_diff

    @property
    def baseline(self) -> ST.Snapshot | None:
        return self._baseline

    def status(self) -> MonitorStatus:
        with self._lock:
            samples = list(self._samples)[-20:]
            return MonitorStatus(
                running=self.is_running(), kind=self.kind, label=self.label,
                interval=self.interval, samples=len(self._samples),
                errors=self._errors, last_at=self._last_at,
                last_snapshot_id=self._last_snapshot_id,
                last_rows=len(self._last_rows),
                next_at=(datetime.fromtimestamp(self._next_at).strftime("%H:%M:%S")
                         if self._next_at else ""),
                history=samples, last_error=self._last_error)


# --------------------------------------------------------------------------- #
# 数据源
# --------------------------------------------------------------------------- #

def make_assets_source(hosts: list, iface, use_arp: bool = True,
                       use_ping: bool = True, use_cache: bool = True,
                       resolve_names: bool = False,
                       lookup_vendor: bool = True, probe_ports=None,
                       cancel=None):
    """主动扫描数据源：每采一次就跑一轮 discover。"""
    def source():
        from .assets import discover
        result = discover(
            hosts, iface, use_arp=use_arp, use_ping=use_ping,
            resolve_names=resolve_names, lookup_vendor=lookup_vendor,
            probe_ports=probe_ports, use_arp_cache=use_cache,
            use_mdns=False, cancel=cancel)
        return ST.rows_from_assets(result), {"hosts": len(hosts)}
    return source


def make_passive_source(collector):
    """被动采集数据源：直接读采集器当前状态，不额外发包。"""
    def source():
        snap = collector.snapshot()
        return ST.rows_from_passive(snap.get("hosts", [])), {
            "alerts": snap.get("alert_count", 0)}
    return source


def make_snmp_source(host: str, community: str = "public", version: int = 2,
                     port: int = 161, timeout: float = 2.0):
    """SNMP 数据源：采设备接口表。"""
    def source():
        from . import snmp as SN
        ifaces = SN.interfaces(host, community, version, port, timeout)
        return ST.rows_from_snmp(ifaces), {"host": host, "community": community}
    return source


def human_interval(seconds: float) -> str:
    seconds = max(1, int(seconds))
    if seconds < 60:
        return f"{seconds} 秒"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} 分钟" + (f" {sec} 秒" if sec else "")
    hours, minutes = divmod(minutes, 60)
    return f"{hours} 小时" + (f" {minutes} 分钟" if minutes else "")


def diff_markdown(diff: ST.DiffResult) -> str:
    """把差异整理成报告片段。"""
    lines = [f"## 变更对比：{diff.old_label} → {diff.new_label}", "",
             f"- {diff.summary()}", ""]
    if diff.added:
        lines.append("### 新增")
        lines.append("")
        lines.append("| 主键 | 摘要 |")
        lines.append("|---|---|")
        for row in diff.added[:200]:
            lines.append(f"| {row.get(diff.key_field, '')} | "
                         f"{ST._short(row, 120)} |")
        lines.append("")
    if diff.removed:
        lines.append("### 消失")
        lines.append("")
        lines.append("| 主键 | 摘要 |")
        lines.append("|---|---|")
        for row in diff.removed[:200]:
            lines.append(f"| {row.get(diff.key_field, '')} | "
                         f"{ST._short(row, 120)} |")
        lines.append("")
    if diff.changed:
        lines.append("### 字段变化")
        lines.append("")
        lines.append("| 主键 | 字段 | 旧值 | 新值 |")
        lines.append("|---|---|---|---|")
        for change in diff.changed[:400]:
            lines.append(f"| {change['key']} | {change['field']} | "
                         f"{ST._val(change['old'])} | {ST._val(change['new'])} |")
        lines.append("")
    if not diff.total_changes:
        lines.append("本次没有任何变化。")
        lines.append("")
    return "\n".join(lines)
