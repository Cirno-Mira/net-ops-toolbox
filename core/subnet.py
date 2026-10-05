# -*- coding: utf-8 -*-
"""
子网计算 / 划分 / 汇总
======================

比「网络地址 + 广播地址」更实用的一套：

* `describe()`        —— 一个网段的完整画像：掩码、通配符、反查区、二进制、
                          地址类别、是否保留段、可用范围
* `split()`           —— 按目标前缀切成若干等长小网段
* `split_by_count()`  —— 按「至少要几个子网」自动挑前缀
* `vlsm()`            —— 变长子网划分：按各段需求从大到小依次分配
* `summarize()`       —— 把一堆网段汇总成最少的几条路由（CIDR 聚合）
* `range_to_cidrs()`  —— 把一段 IP 区间转成最少的 CIDR（配防火墙白名单用）
* `contains()`        —— 判断某个 IP / 某段是否落在网段里

全部是纯 `ipaddress` 计算，不发包、不联网。
"""

from __future__ import annotations

import ipaddress

MAX_SPLIT = 4096          # 一次最多列这么多子网，防止 0/0 切成 40 亿条把界面卡死

# 一些常见的保留网段，用来给「这个地址能不能直接用在公网」下判断
RESERVED = [
    ("0.0.0.0/8", "本网络（RFC1122）"),
    ("10.0.0.0/8", "私有地址（RFC1918）"),
    ("100.64.0.0/10", "运营商级 NAT（RFC6598）"),
    ("127.0.0.0/8", "回环"),
    ("169.254.0.0/16", "链路本地（APIPA）"),
    ("172.16.0.0/12", "私有地址（RFC1918）"),
    ("192.0.0.0/24", "IETF 协议保留"),
    ("192.0.2.0/24", "文档用 TEST-NET-1"),
    ("192.88.99.0/24", "6to4 中继"),
    ("192.168.0.0/16", "私有地址（RFC1918）"),
    ("198.18.0.0/15", "基准测试"),
    ("198.51.100.0/24", "文档用 TEST-NET-2"),
    ("203.0.113.0/24", "文档用 TEST-NET-3"),
    ("224.0.0.0/4", "组播"),
    ("240.0.0.0/4", "保留（原 E 类）"),
]


def parse_target(text: str) -> ipaddress.IPv4Network:
    """
    把用户输入变成一个网段。容忍几种常见写法：

        192.168.1.0/24        标准 CIDR
        192.168.1.5/24        按掩码收起（变成 192.168.1.0/24）
        192.168.1.5           当成 /32
        192.168.1.0 255.255.255.0   地址 + 点分掩码
    """
    s = (text or "").strip().replace("　", " ")
    if not s:
        raise ValueError("请输入网段，例如 192.168.1.0/24")

    parts = [p for p in s.replace(",", " ").split() if p]
    if len(parts) == 2 and "." in parts[1] and "/" not in parts[1]:
        # 地址 + 点分掩码
        host = ipaddress.IPv4Address(parts[0])
        net = ipaddress.IPv4Network(f"{host}/{parts[1]}", strict=False)
        return net

    token = parts[0]
    if "/" in token:
        return ipaddress.IPv4Network(token, strict=False)
    return ipaddress.IPv4Network(f"{token}/32", strict=False)


def wildcard(net: ipaddress.IPv4Network) -> str:
    """通配符掩码（ACL / 路由器里用，就是掩码取反）。"""
    m = int(net.netmask)
    return str(ipaddress.IPv4Address(m ^ 0xFFFFFFFF))


def reverse_zone(net: ipaddress.IPv4Network) -> str:
    """这个网段对应的反向解析区名（PTR 区域）。"""
    if net.prefixlen <= 8:
        return f"{net.network_address.packed[0]}.in-addr.arpa"
    if net.prefixlen <= 16:
        b = net.network_address.packed
        return f"{b[1]}.{b[0]}.in-addr.arpa"
    if net.prefixlen <= 24:
        b = net.network_address.packed
        return f"{b[2]}.{b[1]}.{b[0]}.in-addr.arpa"
    b = net.network_address.packed
    return f"{b[3]}.{b[2]}.{b[1]}.{b[0]}.in-addr.arpa"


def address_class(ip: ipaddress.IPv4Address) -> str:
    """传统的有类地址类别（考试和排错时还会被问到）。"""
    first = int(ip) >> 24
    if first == 0:
        return "0.x（本网络）"
    if first < 128:
        return "A 类（/8，默认掩码 255.0.0.0）"
    if first < 192:
        return "B 类（/16，默认掩码 255.255.0.0）"
    if first < 224:
        return "C 类（/24，默认掩码 255.255.255.0）"
    if first < 240:
        return "D 类（组播）"
    return "E 类（保留/实验）"


def reserved_note(net: ipaddress.IPv4Network) -> str:
    """这个网段落在哪些保留段里。"""
    hits = []
    for cidr, why in RESERVED:
        try:
            if net.subnet_of(ipaddress.IPv4Network(cidr)):
                hits.append(why)
        except (TypeError, ValueError):
            continue
    return "、".join(hits) if hits else "公网可路由地址"


def usable_range(net: ipaddress.IPv4Network) -> tuple[str, str]:
    """
    可分配的主机地址范围。

    /31 与 /32 按 RFC3021 没有网络号/广播号的保留，两端都可用。
    """
    if net.prefixlen >= 31:
        hosts = list(net.hosts())
        if not hosts:
            return str(net.network_address), str(net.network_address)
        return str(hosts[0]), str(hosts[-1])
    hosts = list(net.hosts())
    if not hosts:
        return "-", "-"
    return str(hosts[0]), str(hosts[-1])


def describe(target) -> dict:
    """一个网段的完整画像。`target` 可以是字符串或 IPv4Network。"""
    net = target if isinstance(target, ipaddress.IPv4Network) else parse_target(target)
    total = net.num_addresses
    usable = max(0, total - 2) if net.prefixlen < 31 else total
    first, last = usable_range(net)
    nb, hb = net.prefixlen, 32 - net.prefixlen
    return {
        "network": str(net.network_address),
        "cidr": str(net),
        "netmask": str(net.netmask),
        "wildcard": wildcard(net),
        "prefix": net.prefixlen,
        "mask_bits": "/" + str(net.prefixlen),
        "host_bits": hb,
        "broadcast": str(net.broadcast_address),
        "first": first,
        "last": last,
        "total": total,
        "usable": usable,
        "binary_mask": _bits(int(net.netmask)),
        "binary_network": _bits(int(net.network_address)),
        "reverse_zone": reverse_zone(net),
        "addr_class": address_class(net.network_address),
        "reserved": reserved_note(net),
        "is_private": net.is_private,
        "is_global": net.is_global,
        "hex": f"0x{int(net.network_address):08X}",
        "int": int(net.network_address),
        "summary": f"{net.network_address}/{net.prefixlen}"
                   f"  ({nb} 位网络 + {hb} 位主机, {total:,} 个地址)",
        "explain": (f"掩码 {net.netmask} 表示前 {nb} 位是网络位、后 {hb} 位是主机位；"
                    f"这个网段共 {total:,} 个地址，可分配给设备的有 {usable:,} 个。"
                    if net.prefixlen < 31 else
                    f"/{net.prefixlen} 是点对点链路用的超小网段，两端都可当主机用。"),
    }


def _bits(value: int) -> str:
    s = f"{value:032b}"
    return ".".join(s[i:i + 8] for i in range(0, 32, 8))


def split(target, new_prefix: int, limit: int = MAX_SPLIT) -> list[ipaddress.IPv4Network]:
    """
    按目标前缀切成等长小网段。

    超过 `limit` 条会抛 ValueError——0.0.0.0/0 切成 /24 是 1600 万条，
    与其把界面卡死不如直接说清楚。
    """
    net = target if isinstance(target, ipaddress.IPv4Network) else parse_target(target)
    new_prefix = int(new_prefix)
    if new_prefix <= net.prefixlen:
        raise ValueError(f"新前缀 /{new_prefix} 必须比原前缀 /{net.prefixlen} 长")
    if new_prefix > 32:
        raise ValueError("前缀最长到 /32")
    count = 2 ** (new_prefix - net.prefixlen)
    if count > limit:
        raise ValueError(f"会切出 {count:,} 个子网，超过 {limit:,} 条上限，"
                         f"请用更长一点的原始网段或更短的新前缀")
    return list(net.subnets(new_prefix=new_prefix))


def split_by_count(target, count: int, limit: int = MAX_SPLIT) -> tuple[int, list]:
    """按「至少切出 count 个子网」自动挑最合适的前缀。返回 (前缀, 子网列表)。"""
    net = target if isinstance(target, ipaddress.IPv4Network) else parse_target(target)
    count = max(1, int(count))
    extra = 0
    while (2 ** extra) < count:
        extra += 1
    new_prefix = net.prefixlen + extra
    if new_prefix > 32:
        raise ValueError(f"/{net.prefixlen} 最多只能切出 "
                         f"{2 ** (32 - net.prefixlen):,} 个子网")
    return new_prefix, split(net, new_prefix, limit=limit)


def vlsm(target, needs, limit: int = 256) -> list[dict]:
    """
    变长子网划分。

    `needs` 是 [(名称, 需要的主机数), ...]。按需求从大到小分配，返回
    [{name, need, cidr, size, usable, first, last}, ...]。
    需求超出现有空间时，多出来的部分会带 `error` 字段而不抛异常。
    """
    net = target if isinstance(target, ipaddress.IPv4Network) else parse_target(target)
    items = [(str(n), max(1, int(c))) for n, c in (needs or []) if str(n).strip()]
    if not items:
        return []
    if len(items) > limit:
        raise ValueError(f"一次最多划 {limit} 段")

    order = sorted(range(len(items)), key=lambda i: -items[i][1])
    free = [net]
    out: list[dict] = [None] * len(items)          # type: ignore[list-item]

    for idx in order:
        name, need = items[idx]
        # 需要的主机数 -> 前缀：主机位要能装下 need（还要放网络号+广播）
        bits = 0
        while (2 ** bits) - 2 < need and bits < 32:
            bits += 1
        want = 32 - bits
        placed = False
        for j, block in enumerate(free):
            if block.prefixlen > want:
                continue
            try:
                subs = list(block.subnets(new_prefix=want))
            except ValueError:
                continue
            take, rest = subs[0], subs[1:]
            free.pop(j)
            free[j:j] = rest
            first, last = usable_range(take)
            out[idx] = {
                "name": name, "need": need, "cidr": str(take),
                "size": take.num_addresses, "usable": max(0, take.num_addresses - 2),
                "first": first, "last": last,
                "netmask": str(take.netmask), "error": "",
            }
            placed = True
            break
        if not placed:
            out[idx] = {"name": name, "need": need, "cidr": "-", "size": 0,
                        "usable": 0, "first": "-", "last": "-", "netmask": "-",
                        "error": f"空间不够，剩不下 {need} 个主机的块"}
    return out


def summarize(cidrs) -> list[ipaddress.IPv4Network]:
    """
    把一堆网段汇总成最少的几条路由（CIDR 聚合）。

    例：192.168.0.0/25 与 192.168.0.128/25 -> 192.168.0.0/24
    """
    nets = []
    for c in cidrs:
        if isinstance(c, ipaddress.IPv4Network):
            nets.append(c)
        else:
            s = str(c).strip()
            if s:
                nets.append(ipaddress.IPv4Network(s, strict=False))
    if not nets:
        return []
    return list(ipaddress.collapse_addresses(nets))


def range_to_cidrs(start: str, end: str) -> list[ipaddress.IPv4Network]:
    """
    把一段 IP 区间转成最少的 CIDR 列表——写防火墙白名单时特别有用，
    比一条条列 IP 短得多。
    """
    a = ipaddress.IPv4Address(str(start).strip())
    b = ipaddress.IPv4Address(str(end).strip())
    if int(a) > int(b):
        a, b = b, a
    return list(ipaddress.summarize_address_range(a, b))


def contains(target, ip: str) -> bool:
    """判断 ip（字符串，也允许再填一个网段）是否落在 target 网段里。"""
    net = target if isinstance(target, ipaddress.IPv4Network) else parse_target(target)
    s = str(ip).strip()
    try:
        if "/" in s:
            return ipaddress.IPv4Network(s, strict=False).subnet_of(net)
        return ipaddress.IPv4Address(s) in net
    except (ValueError, TypeError):
        return False


def same_subnet(ip_a: str, ip_b: str, prefix: int) -> bool:
    """两个 IP 在给定前缀下是否同网段（判断「能不能直接二层通信」）。"""
    a = ipaddress.IPv4Network(f"{ip_a}/{prefix}", strict=False)
    b = ipaddress.IPv4Network(f"{ip_b}/{prefix}", strict=False)
    return a.network_address == b.network_address


def format_table(rows: list) -> str:
    """把 [(键, 值)] 排成对齐的多行文本（自检和 --fetch 之类的终端输出用）。"""
    if not rows:
        return ""
    width = max(len(str(k)) for k, _ in rows)
    return "\n".join(f"{str(k).ljust(width)} : {v}" for k, v in rows)
