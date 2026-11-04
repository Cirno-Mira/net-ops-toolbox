# -*- coding: utf-8 -*-
"""
快照仓库（SQLite）
==================

把每次扫描 / 被动采集 / SNMP 读取的结果按「一份快照」存进本地 SQLite，
之后可以随时和任意一份历史快照做差异对比，回答运维最常见的问题：

* 多了哪台设备？少了哪台？
* 哪台设备的 MAC / 主机名 / 开放端口变了？
* 交换机的某个端口从 up 变成 down 了没有？

数据库默认放在程序目录下的 `netops_history.db`，纯本地文件，不上传。
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime

from .logging_bus import log

DB_NAME = "netops_history.db"

# 快照类型：界面上显示的名字、用于对比的主键、默认忽略的字段
KINDS = {
    "assets": {
        "label": "主动扫描资产",
        "key": "ip",
        "ignore": ("last_seen", "packets", "rtt_ms", "first_seen"),
    },
    "passive": {
        "label": "被动发现资产",
        "key": "ip",
        "ignore": ("last_seen", "packets", "first_seen"),
    },
    "snmp": {
        "label": "SNMP 接口表",
        "key": "index",
        "ignore": ("speed_text", "type_name"),
    },
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL,
    label       TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL,
    rows_json   TEXT    NOT NULL,
    meta_json   TEXT    NOT NULL DEFAULT '{}',
    row_count   INTEGER NOT NULL DEFAULT 0,
    checksum    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_snapshots_kind
    ON snapshots (kind, created_at DESC);
"""


def default_db_path() -> str:
    from .paths import app_path
    return app_path(DB_NAME)


@dataclass
class Snapshot:
    id: int
    kind: str
    label: str
    created_at: str
    rows: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    checksum: str = ""

    @property
    def row_count(self) -> int:
        return len(self.rows)

    def head(self) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label,
                "created_at": self.created_at, "row_count": len(self.rows),
                "checksum": self.checksum, "meta": self.meta}


def _canonical(rows: list) -> str:
    return json.dumps(rows, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _checksum(rows: list) -> str:
    return hashlib.sha256(_canonical(rows).encode("utf-8")).hexdigest()[:16]


class SnapshotStore:
    """线程安全的快照库。工作线程写、界面线程读都用同一个连接 + 一把锁。"""

    def __init__(self, path: str = ""):
        self.path = path or default_db_path()
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._ensure()

    # ---------------- 连接 ----------------

    def _ensure(self) -> sqlite3.Connection:
        with self._lock:
            if self._conn is not None:
                return self._conn
            folder = os.path.dirname(os.path.abspath(self.path))
            if folder:
                os.makedirs(folder, exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(_SCHEMA)
            conn.commit()
            self._conn = conn
            return conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.commit()
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None

    @property
    def available(self) -> bool:
        try:
            self._ensure()
            return True
        except Exception as exc:
            log(f"快照库不可用：{type(exc).__name__}: {exc}", "error", "store")
            return False

    # ---------------- 写 ----------------

    def save(self, kind: str, rows: list, label: str = "",
             meta: dict | None = None) -> int:
        with self._lock:
            conn = self._ensure()
            created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            payload = json.dumps(rows, ensure_ascii=False, default=str)
            meta_json = json.dumps(meta or {}, ensure_ascii=False, default=str)
            cur = conn.execute(
                "INSERT INTO snapshots (kind, label, created_at, rows_json,"
                " meta_json, row_count, checksum) VALUES (?,?,?,?,?,?,?)",
                (kind, label, created, payload, meta_json, len(rows),
                 _checksum(rows)))
            conn.commit()
            snapshot_id = int(cur.lastrowid)
        log(f"已保存快照 #{snapshot_id}（{KINDS.get(kind, {}).get('label', kind)}，"
            f"{len(rows)} 行）", "success", "store")
        return snapshot_id

    def delete(self, snapshot_id: int) -> bool:
        with self._lock:
            conn = self._ensure()
            cur = conn.execute("DELETE FROM snapshots WHERE id=?", (int(snapshot_id),))
            conn.commit()
            return cur.rowcount > 0

    def prune(self, kind: str | None = None, keep: int = 50) -> int:
        """每类只保留最近 keep 份，返回删除份数。"""
        keep = max(1, int(keep))
        removed = 0
        with self._lock:
            conn = self._ensure()
            kinds = [kind] if kind else [r["kind"] for r in
                                        conn.execute(
                                            "SELECT DISTINCT kind FROM snapshots")]
            for k in kinds:
                rows = conn.execute(
                    "SELECT id FROM snapshots WHERE kind=? ORDER BY id DESC",
                    (k,)).fetchall()
                for row in rows[keep:]:
                    conn.execute("DELETE FROM snapshots WHERE id=?", (row["id"],))
                    removed += 1
            conn.commit()
        if removed:
            log(f"快照清理：删除 {removed} 份旧记录", "info", "store")
        return removed

    # ---------------- 读 ----------------

    def list(self, kind: str | None = None, limit: int = 200) -> list[dict]:
        with self._lock:
            conn = self._ensure()
            if kind:
                rows = conn.execute(
                    "SELECT id, kind, label, created_at, row_count, checksum,"
                    " meta_json FROM snapshots WHERE kind=?"
                    " ORDER BY id DESC LIMIT ?", (kind, int(limit))).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, kind, label, created_at, row_count, checksum,"
                    " meta_json FROM snapshots ORDER BY id DESC LIMIT ?",
                    (int(limit),)).fetchall()
        out = []
        for row in rows:
            try:
                meta = json.loads(row["meta_json"] or "{}")
            except Exception:
                meta = {}
            out.append({"id": row["id"], "kind": row["kind"],
                        "label": row["label"],
                        "created_at": row["created_at"],
                        "row_count": row["row_count"],
                        "checksum": row["checksum"], "meta": meta})
        return out

    def load(self, snapshot_id: int) -> Snapshot | None:
        with self._lock:
            conn = self._ensure()
            row = conn.execute("SELECT * FROM snapshots WHERE id=?",
                               (int(snapshot_id),)).fetchone()
        if row is None:
            return None
        try:
            rows = json.loads(row["rows_json"] or "[]")
        except Exception:
            rows = []
        try:
            meta = json.loads(row["meta_json"] or "{}")
        except Exception:
            meta = {}
        return Snapshot(id=row["id"], kind=row["kind"], label=row["label"],
                        created_at=row["created_at"], rows=rows, meta=meta,
                        checksum=row["checksum"])

    def latest(self, kind: str) -> Snapshot | None:
        items = self.list(kind, limit=1)
        return self.load(items[0]["id"]) if items else None

    def previous(self, kind: str, before_id: int) -> Snapshot | None:
        with self._lock:
            conn = self._ensure()
            row = conn.execute(
                "SELECT id FROM snapshots WHERE kind=? AND id<?"
                " ORDER BY id DESC LIMIT 1", (kind, int(before_id))).fetchone()
        return self.load(row["id"]) if row else None

    def kinds(self) -> list[dict]:
        with self._lock:
            conn = self._ensure()
            rows = conn.execute(
                "SELECT kind, COUNT(*) AS total, MAX(created_at) AS last_at"
                " FROM snapshots GROUP BY kind ORDER BY kind").fetchall()
        return [{"kind": r["kind"],
                 "label": KINDS.get(r["kind"], {}).get("label", r["kind"]),
                 "total": r["total"], "last_at": r["last_at"]} for r in rows]

    def export_json(self, path: str, snapshot_id: int | None = None) -> int:
        """导出单份或全部快照为 JSON，方便留档。"""
        with self._lock:
            conn = self._ensure()
            if snapshot_id is None:
                rows = conn.execute("SELECT * FROM snapshots ORDER BY id").fetchall()
            else:
                rows = conn.execute("SELECT * FROM snapshots WHERE id=?",
                                    (int(snapshot_id),)).fetchall()
        data = []
        for row in rows:
            data.append({"id": row["id"], "kind": row["kind"],
                         "label": row["label"], "created_at": row["created_at"],
                         "meta": json.loads(row["meta_json"] or "{}"),
                         "rows": json.loads(row["rows_json"] or "[]")})
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        return len(data)


# --------------------------------------------------------------------------- #
# 差异对比
# --------------------------------------------------------------------------- #

@dataclass
class DiffResult:
    kind: str = "assets"
    key_field: str = "ip"
    added: list = field(default_factory=list)
    removed: list = field(default_factory=list)
    changed: list = field(default_factory=list)
    unchanged: int = 0
    old_label: str = ""
    new_label: str = ""

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.changed)

    def counts(self) -> dict:
        return {"added": len(self.added), "removed": len(self.removed),
                "changed": len(self.changed), "unchanged": self.unchanged}

    def summary(self) -> str:
        return (f"新增 {len(self.added)} / 消失 {len(self.removed)} / "
                f"变化 {len(self.changed)} / 未变 {self.unchanged}")

    def rows(self) -> list[list]:
        """给表格用的扁平行：[类型, 主键, 字段, 旧值, 新值]。"""
        out: list[list] = []
        for row in self.added:
            out.append(["新增", _key_text(row, self.key_field), "-", "-",
                        _short(row)])
        for row in self.removed:
            out.append(["消失", _key_text(row, self.key_field), "-",
                        _short(row), "-"])
        for change in self.changed:
            out.append(["变化", change.get("key", ""), change.get("field", ""),
                        _val(change.get("old", "")), _val(change.get("new", ""))])
        return out


def _key_text(row: dict, key: str) -> str:
    return str(row.get(key, ""))


def _val(value) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value) if value else "-"
    if value is None or value == "":
        return "-"
    return str(value)


def _short(row: dict, limit: int = 90) -> str:
    parts = []
    for key, value in row.items():
        if key in ("last_seen", "first_seen", "packets"):
            continue
        text = _val(value)
        if text != "-":
            parts.append(f"{key}={text}")
        if len(", ".join(parts)) > limit:
            break
    return ", ".join(parts)[:limit]


def diff_rows(old_rows: list, new_rows: list, key_field: str = "ip",
              ignore_fields=()) -> DiffResult:
    """按主键对比两份行集合，字段级列出变化。"""
    ignore = set(ignore_fields or ())
    result = DiffResult(key_field=key_field)
    old_map = {str(r.get(key_field, "")): r for r in old_rows
               if str(r.get(key_field, "")) != ""}
    new_map = {str(r.get(key_field, "")): r for r in new_rows
               if str(r.get(key_field, "")) != ""}

    for key, row in new_map.items():
        if key not in old_map:
            result.added.append(row)
    for key, row in old_map.items():
        if key not in new_map:
            result.removed.append(row)

    for key, new_row in new_map.items():
        old_row = old_map.get(key)
        if old_row is None:
            continue
        changed_any = False
        for fld in sorted(set(old_row) | set(new_row)):
            if fld == key_field or fld in ignore:
                continue
            old_value = old_row.get(fld)
            new_value = new_row.get(fld)
            if _same(old_value, new_value):
                continue
            result.changed.append({"key": key, "field": fld,
                                   "old": old_value, "new": new_value})
            changed_any = True
        if not changed_any:
            result.unchanged += 1

    result.added.sort(key=lambda r: str(r.get(key_field, "")))
    result.removed.sort(key=lambda r: str(r.get(key_field, "")))
    result.changed.sort(key=lambda c: (c["key"], c["field"]))
    return result


def _same(a, b) -> bool:
    if isinstance(a, (list, tuple)) or isinstance(b, (list, tuple)):
        return list(a or []) == list(b or [])
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return float(a) == float(b)
    return _val(a) == _val(b)


# --------------------------------------------------------------------------- #
# 数据整形
# --------------------------------------------------------------------------- #

def rows_from_assets(assets) -> list[dict]:
    """把 `core.assets.Asset` 列表（或 dict）整理成快照行。"""
    rows = []
    for item in assets or []:
        if isinstance(item, dict):
            rows.append(dict(item))
            continue
        rows.append({
            "ip": item.ip, "mac": item.mac, "vendor": item.vendor,
            "hostname": item.hostname, "os_guess": item.os_guess,
            "open_ports": list(item.open_ports or []),
            "online": item.online, "source": item.source,
        })
    return rows


def rows_from_passive(hosts) -> list[dict]:
    """把被动发现的 host 列表整理成快照行（去掉易变字段）。"""
    rows = []
    for item in hosts or []:
        if isinstance(item, dict):
            rows.append({k: v for k, v in item.items()
                         if k not in ("packets", "first_seen", "last_seen")})
        else:
            rows.append({"ip": item.ip, "mac": item.mac,
                         "vendor": item.vendor, "hostname": item.hostname,
                         "os_guess": item.os_guess,
                         "dhcp_vendor": item.dhcp_vendor,
                         "sources": sorted(item.sources)})
    return rows


def rows_from_snmp(ifaces) -> list[dict]:
    rows = []
    for item in ifaces or []:
        if isinstance(item, dict):
            rows.append(dict(item))
    return rows
