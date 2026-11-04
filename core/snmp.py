# -*- coding: utf-8 -*-
"""
SNMP v1 / v2c（手写 BER，不依赖 pysnmp）
========================================

设备侧只要开着 SNMP，就能一趟拿到型号、运行时长、接口表、ARP 表和 LLDP 邻居。
这里自己实现 ASN.1 BER 编解码，好处是：

* 不用装 pysnmp（它的依赖链在新 Python 上经常装不上）；
* 报文完全可控，便于排错和在自检里做字节级回环验证；
* 只做客户端，不监听 161，不改变本机防火墙状态。

支持：GET / GETNEXT / GETBULK / SET，v1 与 v2c。
**不支持 SNMPv3**（v3 的 USM 认证加密是另一套工程量，且现场 v2c 仍占多数）。
"""

from __future__ import annotations

import random
import socket
import time
from dataclasses import dataclass, field

from .logging_bus import log

# --------------------------------------------------------------------------- #
# BER 基础
# --------------------------------------------------------------------------- #

TAG_INTEGER = 0x02
TAG_OCTETS = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_IPADDRESS = 0x40
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_OPAQUE = 0x44
TAG_COUNTER64 = 0x47

PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2
PDU_SET = 0xA3
PDU_TRAP_V1 = 0xA4
PDU_GETBULK = 0xA5
PDU_INFORM = 0xA6
PDU_TRAP_V2 = 0xA7
PDU_REPORT = 0xA8

PDU_NAMES = {
    PDU_GET: "GetRequest", PDU_GETNEXT: "GetNextRequest",
    PDU_RESPONSE: "GetResponse", PDU_SET: "SetRequest",
    PDU_TRAP_V1: "Trap(v1)", PDU_GETBULK: "GetBulkRequest",
    PDU_INFORM: "InformRequest", PDU_TRAP_V2: "Trap(v2)",
    PDU_REPORT: "Report",
}

ERROR_TEXT = {
    0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue",
    4: "readOnly", 5: "genErr", 6: "noAccess", 7: "wrongType",
    8: "wrongLength", 9: "wrongEncoding", 10: "wrongValue",
    11: "noCreation", 12: "inconsistentValue", 13: "resourceUnavailable",
    14: "commitFailed", 15: "undoFailed", 16: "authorizationError",
    17: "notWritable", 18: "inconsistentName",
}


class BERError(ValueError):
    """报文不符合 BER / SNMP 结构。"""


def _len_bytes(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _len_bytes(len(payload)) + payload


def _int_bytes(value: int) -> bytes:
    length = 1
    while not (-(1 << (8 * length - 1)) <= value < (1 << (8 * length - 1))):
        length += 1
    return value.to_bytes(length, "big", signed=True)


def encode_int(value: int) -> bytes:
    return tlv(TAG_INTEGER, _int_bytes(int(value)))


def encode_octets(value) -> bytes:
    if isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8", "replace")
    return tlv(TAG_OCTETS, raw)


def encode_oid(oid: str) -> bytes:
    """点分 OID → BER 内容字节（不含 tag / 长度）。"""
    parts = [int(x) for x in str(oid).strip().strip(".").split(".") if x != ""]
    if len(parts) < 2:
        raise BERError(f"OID 至少需要两段：{oid!r}")
    if parts[0] not in (0, 1, 2):
        raise BERError(f"OID 首段必须是 0/1/2：{oid!r}")
    values = [parts[0] * 40 + parts[1]] + parts[2:]
    out = bytearray()
    for num in values:
        if num < 0:
            raise BERError(f"OID 子标识不能为负：{oid!r}")
        chunk = [num & 0x7F]
        num >>= 7
        while num:
            chunk.append((num & 0x7F) | 0x80)
            num >>= 7
        out.extend(reversed(chunk))
    return bytes(out)


def decode_oid(raw: bytes) -> str:
    values: list[int] = []
    num = 0
    for byte in raw:
        num = (num << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(num)
            num = 0
    if not values:
        raise BERError("OID 内容为空")
    first = values[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(x) for x in head + values[1:])


def read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """读取一个 TLV，返回 (tag, 内容字节, 下一个偏移)。"""
    if offset >= len(data):
        raise BERError("数据提前结束")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise BERError("缺少长度字段")
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0:
            raise BERError("不支持不定长编码")
        if offset + count > len(data):
            raise BERError("长度字段越界")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        length = first
    end = offset + length
    if end > len(data):
        raise BERError(f"内容长度越界：需要 {length}，只剩 {len(data) - offset}")
    return tag, data[offset:end], end


def _children(raw: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(raw):
        tag, value, offset = read_tlv(raw, offset)
        out.append((tag, value))
    return out


def _expect(tag: int, want: int, what: str) -> None:
    if tag != want:
        raise BERError(f"{what} 的 tag 应为 0x{want:02X}，实际 0x{tag:02X}")


# --------------------------------------------------------------------------- #
# 报文构造
# --------------------------------------------------------------------------- #

def _varbind(oid: str, value_tlv: bytes = b"\x05\x00") -> bytes:
    return tlv(TAG_SEQUENCE, tlv(TAG_OID, encode_oid(oid)) + value_tlv)


def _pdu(tag: int, request_id: int, varbinds: list[bytes],
         error_status: int = 0, error_index: int = 0,
         extra: bytes = b"") -> bytes:
    body = (encode_int(request_id) + encode_int(error_status)
            + encode_int(error_index) + extra
            + tlv(TAG_SEQUENCE, b"".join(varbinds)))
    return tlv(tag, body)


def build_message(pdu: bytes, community: str = "public", version: int = 2) -> bytes:
    """version: 1 表示 SNMPv1(0)，2 表示 SNMPv2c(1)。"""
    ver = 0 if int(version) == 1 else 1
    return tlv(TAG_SEQUENCE, encode_int(ver) + encode_octets(community) + pdu)


def _new_request_id() -> int:
    return random.randint(1, 0x7FFFFFFF)


def build_get(oids: list[str], community: str = "public", version: int = 2,
              request_id: int | None = None) -> bytes:
    rid = _new_request_id() if request_id is None else int(request_id)
    pdu = _pdu(PDU_GET, rid, [_varbind(oid) for oid in oids])
    return build_message(pdu, community, version)


def build_getnext(oids: list[str], community: str = "public", version: int = 2,
                  request_id: int | None = None) -> bytes:
    rid = _new_request_id() if request_id is None else int(request_id)
    pdu = _pdu(PDU_GETNEXT, rid, [_varbind(oid) for oid in oids])
    return build_message(pdu, community, version)


def build_getbulk(oids: list[str], community: str = "public",
                  non_repeaters: int = 0, max_repetitions: int = 10,
                  request_id: int | None = None) -> bytes:
    rid = _new_request_id() if request_id is None else int(request_id)
    extra = encode_int(non_repeaters) + encode_int(max_repetitions)
    pdu = _pdu(PDU_GETBULK, rid, [_varbind(oid) for oid in oids], extra=extra)
    return build_message(pdu, community, 2)


def build_set(community: str, values: list[tuple[str, str, object]],
              version: int = 2, request_id: int | None = None) -> bytes:
    """
    values: [(oid, 类型, 值)]，类型支持 'string' / 'int' / 'oid' / 'ip'。

    只应修改 sysName / sysLocation 这类可写标量；改错可能影响设备管理。
    """
    rid = _new_request_id() if request_id is None else int(request_id)
    varbinds = []
    for oid, kind, value in values:
        kind = (kind or "string").lower()
        if kind == "int":
            payload = encode_int(int(value))
        elif kind == "oid":
            payload = tlv(TAG_OID, encode_oid(str(value)))
        elif kind == "ip":
            parts = [int(x) for x in str(value).split(".")]
            if len(parts) != 4 or any(not 0 <= p < 256 for p in parts):
                raise BERError(f"不是合法 IPv4：{value!r}")
            payload = tlv(TAG_IPADDRESS, bytes(parts))
        else:
            payload = encode_octets(value)
        varbinds.append(_varbind(oid, payload))
    pdu = _pdu(PDU_SET, rid, varbinds)
    return build_message(pdu, community, version)


# --------------------------------------------------------------------------- #
# 报文解析
# --------------------------------------------------------------------------- #

@dataclass
class VarBind:
    oid: str
    value: object = None
    tag: int = TAG_NULL

    def display(self) -> str:
        if self.value is None:
            return "<空>"
        if self.tag == TAG_TIMETICKS and isinstance(self.value, int):
            return format_ticks(self.value)
        if self.tag == TAG_OCTETS and isinstance(self.value, bytes):
            return self.value.hex(":")
        return str(self.value)

    def to_dict(self) -> dict:
        return {"oid": self.oid, "value": self.display(),
                "raw": self.value, "tag": self.tag,
                "name": oid_name(self.oid)}


@dataclass
class Response:
    version: int = 1
    community: str = ""
    pdu_tag: int = PDU_RESPONSE
    request_id: int = 0
    error_status: int = 0
    error_index: int = 0
    varbinds: list = field(default_factory=list)
    size: int = 0

    @property
    def ok(self) -> bool:
        return self.pdu_tag in (PDU_RESPONSE, PDU_REPORT) and self.error_status == 0

    @property
    def error_text(self) -> str:
        if self.pdu_tag == PDU_REPORT:
            return "设备返回 Report（v3/未知引擎）"
        return ERROR_TEXT.get(self.error_status, f"错误码 {self.error_status}")

    def to_dict(self) -> dict:
        return {"version": self.version, "community": self.community,
                "pdu": PDU_NAMES.get(self.pdu_tag, hex(self.pdu_tag)),
                "request_id": self.request_id, "error": self.error_text,
                "ok": self.ok, "size": self.size,
                "varbinds": [v.to_dict() for v in self.varbinds]}


def _decode_value(tag: int, raw: bytes):
    if tag == TAG_INTEGER:
        return int.from_bytes(raw, "big", signed=True)
    if tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS, TAG_COUNTER64):
        return int.from_bytes(raw, "big", signed=False)
    if tag == TAG_NULL:
        return None
    if tag == TAG_OID:
        return decode_oid(raw)
    if tag == TAG_IPADDRESS:
        return ".".join(str(b) for b in raw) if len(raw) == 4 else raw.hex()
    if tag == TAG_OCTETS:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return bytes(raw)
    return bytes(raw)


def parse_message(data: bytes) -> Response:
    """解析 GetResponse；结构不对会抛 BERError。"""
    tag, body, _ = read_tlv(data, 0)
    _expect(tag, TAG_SEQUENCE, "SNMP 消息")
    outer = _children(body)
    if len(outer) < 3:
        raise BERError(f"SNMP 消息字段不足：{len(outer)}")

    vtag, vraw = outer[0]
    _expect(vtag, TAG_INTEGER, "version")
    version = int.from_bytes(vraw, "big", signed=True)

    ctag, craw = outer[1]
    _expect(ctag, TAG_OCTETS, "community")
    community = craw.decode("utf-8", "replace")

    ptag, praw = outer[2]
    pdu = _children(praw)
    if len(pdu) < 4:
        raise BERError(f"PDU 字段不足：{len(pdu)}")
    _expect(pdu[0][0], TAG_INTEGER, "request-id")
    _expect(pdu[1][0], TAG_INTEGER, "error-status")
    _expect(pdu[2][0], TAG_INTEGER, "error-index")
    _expect(pdu[3][0], TAG_SEQUENCE, "varbind list")

    varbinds: list[VarBind] = []
    for btag, braw in _children(pdu[3][1]):
        _expect(btag, TAG_SEQUENCE, "varbind")
        parts = _children(braw)
        if len(parts) < 2:
            raise BERError("varbind 字段不足")
        _expect(parts[0][0], TAG_OID, "varbind OID")
        varbinds.append(VarBind(oid=decode_oid(parts[0][1]),
                                value=_decode_value(parts[1][0], parts[1][1]),
                                tag=parts[1][0]))

    return Response(version=version, community=community, pdu_tag=ptag,
                    request_id=int.from_bytes(pdu[0][1], "big", signed=True),
                    error_status=int.from_bytes(pdu[1][1], "big", signed=True),
                    error_index=int.from_bytes(pdu[2][1], "big", signed=True),
                    varbinds=varbinds, size=len(data))


def format_ticks(ticks: int) -> str:
    """TimeTicks（1/100 秒）→ 人类可读。"""
    total = int(ticks) // 100
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    if days:
        return f"{days}天 {hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


# --------------------------------------------------------------------------- #
# 传输
# --------------------------------------------------------------------------- #

def exchange(host: str, payload: bytes, port: int = 161, timeout: float = 1.5,
             retries: int = 1) -> Response:
    """发一个 SNMP 报文并等应答。超时/无响应会抛 OSError。"""
    addr = (host, int(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(max(0.2, float(timeout)))
    try:
        last: Exception | None = None
        for attempt in range(max(1, int(retries) + 1)):
            try:
                sock.sendto(payload, addr)
                data, _src = sock.recvfrom(65535)
                return parse_message(data)
            except socket.timeout as exc:
                last = exc
                if attempt >= int(retries):
                    break
            except OSError as exc:
                last = exc
                break
        raise OSError(f"{host}:{port} 无 SNMP 应答"
                      f"（{type(last).__name__ if last else 'timeout'}）")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def get(host: str, oids: list[str], community: str = "public", version: int = 2,
        port: int = 161, timeout: float = 1.5, retries: int = 1) -> Response:
    return exchange(host, build_get(oids, community, version), port, timeout, retries)


def getnext(host: str, oids: list[str], community: str = "public",
            version: int = 2, port: int = 161, timeout: float = 1.5,
            retries: int = 1) -> Response:
    return exchange(host, build_getnext(oids, community, version),
                    port, timeout, retries)


def getbulk(host: str, oids: list[str], community: str = "public",
            max_repetitions: int = 10, port: int = 161, timeout: float = 1.5,
            retries: int = 1) -> Response:
    return exchange(host, build_getbulk(oids, community, 0, max_repetitions),
                    port, timeout, retries)


def set_values(host: str, values: list[tuple[str, str, object]],
               community: str = "public", version: int = 2, port: int = 161,
               timeout: float = 2.0, retries: int = 1) -> Response:
    return exchange(host, build_set(community, values, version),
                    port, timeout, retries)


def _under(oid: str, base: str) -> bool:
    return oid == base or oid.startswith(base + ".")


def walk(host: str, base_oid: str, community: str = "public", version: int = 2,
         max_rows: int = 2000, timeout: float = 1.5, port: int = 161,
         cancel=None, progress=None) -> list[VarBind]:
    """
    用 GETNEXT 遍历一个子树。碰到越界 / noSuchName / endOfMibView 就停。
    设备上的环状 OID 也靠 `seen` 兜住，不会死循环。
    """
    out: list[VarBind] = []
    current = base_oid
    seen: set[str] = set()
    while len(out) < max_rows:
        if cancel is not None and cancel.is_set():
            break
        resp = getnext(host, [current], community, version, port, timeout)
        if not resp.ok or not resp.varbinds:
            break
        vb = resp.varbinds[0]
        if vb.value is None or not _under(vb.oid, base_oid):
            break
        if vb.oid in seen:
            break
        seen.add(vb.oid)
        out.append(vb)
        if vb.oid == current:
            break
        current = vb.oid
        if progress is not None:
            progress(len(out), vb)
    return out


def bulk_walk(host: str, base_oid: str, community: str = "public",
              max_rows: int = 2000, batch: int = 20, timeout: float = 1.5,
              port: int = 161) -> list[VarBind]:
    """v2c 专用：GETBULK 一次拿一批，比 GETNEXT 快得多。"""
    out: list[VarBind] = []
    current = base_oid
    while len(out) < max_rows:
        resp = getbulk(host, [current], community, min(batch, max_rows - len(out)),
                       port, timeout)
        if not resp.ok or not resp.varbinds:
            break
        moved = False
        for vb in resp.varbinds:
            if vb.value is None or not _under(vb.oid, base_oid):
                return out
            if vb.oid == current:
                continue
            out.append(vb)
            current = vb.oid
            moved = True
            if len(out) >= max_rows:
                break
        if not moved:
            break
    return out


# --------------------------------------------------------------------------- #
# 常用 OID
# --------------------------------------------------------------------------- #

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
OID_SYS_SERVICES = "1.3.6.1.2.1.1.7.0"

IF_BASE = "1.3.6.1.2.1.2.2.1"
IF_COLUMNS = {"descr": 2, "type": 3, "speed": 5, "mac": 6,
              "admin": 7, "oper": 8}

ARP_BASE = "1.3.6.1.2.1.4.22.1"
IP_ADDR_BASE = "1.3.6.1.2.1.4.20.1"

LLDP_REM_BASE = "1.0.8802.1.1.2.1.4.1"
LLDP_REM_COLUMNS = {"chassis": 5, "port_id": 7, "port_desc": 8,
                    "sys_name": 9, "sys_desc": 10}

SYS_INFO_OIDS = [
    (OID_SYS_DESCR, "sysDescr"),
    (OID_SYS_OBJECT_ID, "sysObjectID"),
    (OID_SYS_UPTIME, "sysUpTime"),
    (OID_SYS_CONTACT, "sysContact"),
    (OID_SYS_NAME, "sysName"),
    (OID_SYS_LOCATION, "sysLocation"),
    (OID_SYS_SERVICES, "sysServices"),
]

OID_LABELS = {
    OID_SYS_DESCR: "系统描述",
    OID_SYS_OBJECT_ID: "设备 OID",
    OID_SYS_UPTIME: "运行时长",
    OID_SYS_CONTACT: "联系人",
    OID_SYS_NAME: "设备名",
    OID_SYS_LOCATION: "位置",
    OID_SYS_SERVICES: "服务层级",
}

IF_TYPE_NAMES = {
    1: "other", 6: "ethernet", 24: "softwareLoopback", 53: "propVirtual",
    131: "tunnel", 135: "l2vlan", 136: "l3ipvlan", 161: "ieee8023adLag",
}

IF_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown",
             5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}

DEFAULT_COMMUNITIES = ["public", "private", "cisco", "admin", "snmp",
                       "community", "readonly", "monitor"]


def oid_name(oid: str) -> str:
    if oid in OID_LABELS:
        return OID_LABELS[oid]
    for prefix, label in ((IF_BASE, "ifTable"), (ARP_BASE, "ipNetToMedia"),
                          (IP_ADDR_BASE, "ipAddrTable"),
                          (LLDP_REM_BASE, "lldpRemTable")):
        if _under(oid, prefix):
            return f"{label}.{oid[len(prefix) + 1:]}"
    return ""


def guess_vendor(sys_descr: str = "", sys_object_id: str = "") -> str:
    text = f"{sys_descr} {sys_object_id}".lower()
    table = [
        ("cisco", "Cisco"), ("huawei", "Huawei"), ("h3c", "H3C"),
        ("ruijie", "Ruijie"), ("hpe", "HPE"), ("hewlett", "HPE"),
        ("aruba", "Aruba"), ("juniper", "Juniper"), ("fortinet", "Fortinet"),
        ("mikrotik", "MikroTik"), ("tp-link", "TP-LINK"), ("tplink", "TP-LINK"),
        ("dlink", "D-Link"), ("d-link", "D-Link"), ("zyxel", "Zyxel"),
        ("netgear", "Netgear"), ("ubiquiti", "Ubiquiti"), ("unifi", "Ubiquiti"),
        ("dell", "Dell"), ("brocade", "Brocade"), ("extreme", "Extreme"),
        ("palo alto", "Palo Alto"), ("sonicwall", "SonicWall"),
        ("windows", "Windows"), ("linux", "Linux"), ("vmware", "VMware"),
        ("apc", "APC"), ("eaton", "Eaton"), ("synology", "Synology"),
        ("qnap", "QNAP"), ("printer", "打印机"), ("jetdirect", "HP 打印机"),
    ]
    for key, name in table:
        if key in text:
            return name
    return ""


def sys_info(host: str, community: str = "public", version: int = 2,
             port: int = 161, timeout: float = 1.5) -> dict:
    """一次 GET 拿齐 sysDescr / sysName / Uptime 等标量。"""
    resp = get(host, [oid for oid, _ in SYS_INFO_OIDS], community, version,
               port, timeout)
    if not resp.ok:
        raise OSError(f"SNMP 返回错误：{resp.error_text}")
    info = {"host": host, "community": community, "version": version}
    for (want, name), vb in zip(SYS_INFO_OIDS, resp.varbinds):
        if vb.oid != want:
            continue
        if vb.tag == TAG_TIMETICKS and isinstance(vb.value, int):
            info[name] = format_ticks(vb.value)
        elif isinstance(vb.value, bytes):
            info[name] = vb.value.hex(":")
        else:
            info[name] = "" if vb.value is None else str(vb.value)
    info["vendor"] = guess_vendor(info.get("sysDescr", ""),
                                  info.get("sysObjectID", ""))
    return info


def _walk_column(host: str, base: str, sub: int, community: str,
                 version: int, timeout: float, max_rows: int) -> dict[str, VarBind]:
    prefix = f"{base}.{sub}"
    rows = walk(host, prefix, community, version, max_rows=max_rows,
                timeout=timeout)
    out: dict[str, VarBind] = {}
    for vb in rows:
        index = vb.oid[len(prefix) + 1:] if vb.oid.startswith(prefix + ".") else ""
        if index:
            out[index] = vb
    return out


def interfaces(host: str, community: str = "public", version: int = 2,
               port: int = 161, timeout: float = 2.0,
               max_rows: int = 500) -> list[dict]:
    """接口表：按 ifIndex 合并 6 个列。"""
    cols: dict[str, dict[str, VarBind]] = {}
    for name, sub in IF_COLUMNS.items():
        cols[name] = _walk_column(host, IF_BASE, sub, community, version,
                                  timeout, max_rows)
    indexes = set()
    for values in cols.values():
        indexes.update(values)
    result = []
    for idx in sorted(indexes, key=lambda s: (len(s), s)):
        row = {"index": idx}
        for name, values in cols.items():
            vb = values.get(idx)
            row[name] = vb.value if vb is not None else None
        row["type_name"] = IF_TYPE_NAMES.get(int(row.get("type") or 0), "unknown")
        row["admin"] = IF_STATUS.get(int(row.get("admin") or 0), "-")
        row["oper"] = IF_STATUS.get(int(row.get("oper") or 0), "-")
        row["speed_text"] = format_speed(row.get("speed") or 0)
        mac = row.get("mac")
        row["mac_text"] = mac.hex(":") if isinstance(mac, bytes) else (mac or "-")
        result.append(row)
    return result


def format_speed(bps: int) -> str:
    bps = int(bps or 0)
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:g} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:g} Mbps"
    if bps >= 1000:
        return f"{bps / 1000:g} Kbps"
    return f"{bps} bps"


def arp_table(host: str, community: str = "public", version: int = 2,
              port: int = 161, timeout: float = 2.0,
              max_rows: int = 2000) -> list[dict]:
    """
    设备的 ARP / 邻居表（ipNetToMediaTable）。
    OID 索引是 ifIndex + 4 字节 IP，所以从后缀里把 IP 还原出来。
    """
    mac_rows = walk(host, f"{ARP_BASE}.2", community, version,
                    max_rows=max_rows, timeout=timeout)
    type_rows = {vb.oid.rsplit(".", 1)[0]: vb.value
                 for vb in walk(host, f"{ARP_BASE}.3", community, version,
                                max_rows=max_rows, timeout=timeout)}
    result = []
    for vb in mac_rows:
        suffix = vb.oid[len(f"{ARP_BASE}.2") + 1:]
        parts = suffix.split(".")
        if len(parts) < 5:
            continue
        ip = ".".join(parts[-4:])
        mac = vb.value.hex(":") if isinstance(vb.value, bytes) else str(vb.value or "")
        if mac in ("", "00:00:00:00:00:00"):
            continue
        ifindex = ".".join(parts[:-4])
        kind = type_rows.get(vb.oid.rsplit(".", 1)[0])
        result.append({"ip": ip, "mac": mac, "ifindex": ifindex,
                       "type": {1: "other", 2: "invalid", 3: "dynamic",
                                4: "static"}.get(kind, "-")})
    result.sort(key=lambda r: tuple(int(p) for p in r["ip"].split(".")))
    return result


def ip_addresses(host: str, community: str = "public", version: int = 2,
                 port: int = 161, timeout: float = 2.0,
                 max_rows: int = 500) -> list[dict]:
    """ipAddrTable：接口上配了哪些地址。"""
    addrs = _walk_column(host, IP_ADDR_BASE, 1, community, version,
                         timeout, max_rows)
    result = []
    for suffix, vb in addrs.items():
        result.append({"ip": str(vb.value or ""), "ifindex": suffix})
    result.sort(key=lambda r: tuple(int(p) for p in r["ip"].split("."))
                if r["ip"].count(".") == 3 else (999, 999, 999, 999))
    return result


def lldp_neighbors(host: str, community: str = "public", version: int = 2,
                   port: int = 161, timeout: float = 2.5,
                   max_rows: int = 500) -> list[dict]:
    """LLDP-MIB 远端邻居表（不是所有设备都实现）。"""
    cols: dict[str, dict[str, VarBind]] = {}
    for name, sub in LLDP_REM_COLUMNS.items():
        cols[name] = _walk_column(host, LLDP_REM_BASE, sub, community,
                                  version, timeout, max_rows)
    indexes = set()
    for values in cols.values():
        indexes.update(values)
    result = []
    for idx in sorted(indexes):
        row = {"index": idx}
        for name, values in cols.items():
            vb = values.get(idx)
            value = vb.value if vb is not None else ""
            if isinstance(value, bytes):
                value = value.hex(":")
            row[name] = str(value or "")
        result.append(row)
    return result


def probe_communities(host: str, port: int = 161, version: int = 2,
                      timeout: float = 1.0,
                      candidates: list[str] | None = None) -> tuple[str, dict]:
    """按候选社区名逐个试，返回第一个可用的。"""
    for community in (candidates or DEFAULT_COMMUNITIES):
        try:
            info = sys_info(host, community, version, port, timeout)
            if info.get("sysDescr") or info.get("sysName"):
                log(f"{host} 使用社区名 {community!r} 可读", "success", "snmp")
                return community, info
        except Exception:
            continue
    return "", {}


def security_report(info: dict, community: str,
                    ifaces: list | None = None) -> list[dict]:
    """把「能看到什么」翻译成风险条目，只描述事实、不夸大。"""
    findings: list[dict] = []
    if community in ("public", "private", "cisco", "admin", "snmp", "community"):
        findings.append({
            "severity": "high", "title": "使用常见默认团体名",
            "detail": f"社区名 {community!r} 属于厂商默认值，任何人都能读取"
                      f"设备信息；v2c 明文传输，同一广播域可被嗅探",
            "items": [community]})
    descr = (info.get("sysDescr") or "")
    if descr:
        findings.append({
            "severity": "info", "title": "系统描述暴露型号与固件",
            "detail": descr[:200], "items": []})
    if (info.get("sysLocation") or "").strip() not in ("", " "):
        findings.append({
            "severity": "low", "title": "设备位置信息对外可见",
            "detail": f"sysLocation = {info['sysLocation'][:120]}",
            "items": []})
    if (info.get("sysContact") or "").strip() not in ("", " "):
        findings.append({
            "severity": "low", "title": "联系人信息对外可见",
            "detail": f"sysContact = {info['sysContact'][:120]}",
            "items": []})
    if ifaces:
        down = sum(1 for i in ifaces if i.get("oper") == "down")
        if down:
            findings.append({
                "severity": "info", "title": "存在 down 的接口",
                "detail": f"{down} 个接口当前 down，可核对是否有闲置端口",
                "items": [str(i.get("descr")) for i in ifaces
                          if i.get("oper") == "down"][:20]})
    return findings


def now_stamp() -> str:
    return time.strftime("%H:%M:%S")
