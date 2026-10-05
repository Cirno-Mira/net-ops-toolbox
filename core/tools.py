# -*- coding: utf-8 -*-
"""
运维小工具集合
==============

ping / traceroute / DNS 查询 / 反向解析 / Wake-on-LAN / HTTP(S) 探测 /
SNTP 时间校准 / 本机信息汇总。全部是纯 Python + 系统命令，尽量不依赖管理员。
"""

from __future__ import annotations

import getpass
import ipaddress
import platform
import re
import socket
import ssl
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .hostinfo import list_ifaces
from .logging_bus import log


# --------------------------------------------------------------------------- #
# 本机信息
# --------------------------------------------------------------------------- #

def dns_servers() -> list[str]:
    """拿系统 DNS 服务器（dnspython 会读注册表，跨语言环境可靠）。"""
    try:
        import dns.resolver
        return [str(x) for x in dns.resolver.Resolver().nameservers]
    except Exception:
        return []


def public_ip(timeout: float = 6.0) -> tuple[str, str]:
    """查本机公网出口 IP，返回 (ip, 说明)。"""
    endpoints = [
        ("https://api.ipify.org", "text"),
        ("https://ifconfig.me/ip", "text"),
        ("https://ipv4.icanhazip.com", "text"),
        ("http://members.3322.org/dyndns/getip", "text"),
    ]
    try:
        import requests
    except Exception:
        return "", "未安装 requests"
    for url, _kind in endpoints:
        try:
            r = requests.get(url, timeout=timeout,
                             headers={"User-Agent": "curl/8.0"})
            if r.status_code == 200:
                ip = r.text.strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    return ip, url
        except Exception:
            continue
    return "", "所有查询源都不可用（可能没联网）"


def local_info(with_public: bool = True) -> dict:
    """本机信息汇总。"""
    info = {
        "主机名": socket.gethostname(),
        "当前用户": getpass.getuser(),
        "操作系统": f"{platform.system()} {platform.release()} ({platform.version()})",
        "Python": platform.python_version(),
        "DNS 服务器": "、".join(dns_servers()) or "未知",
        "网卡": [],
    }
    for i in list_ifaces(include_down=False):
        info["网卡"].append({
            "名称": i.alias,
            "IP": f"{i.ip}/{i.prefix}",
            "MAC": i.mac or "-",
            "网关": i.gateway or "-",
            "网段": i.cidr,
            "描述": i.desc,
        })
    if with_public:
        ip, src = public_ip()
        info["公网 IP"] = ip or f"获取失败（{src}）"
    return info


# --------------------------------------------------------------------------- #
# Ping
# --------------------------------------------------------------------------- #

class PingWorker(threading.Thread):
    """
    持续 ping。每 ping 一次回调 on_reply(seq, rtt_ms or None)，统计丢包与延迟。
    """

    def __init__(self, host: str, interval: float = 1.0, timeout_ms: int = 1000,
                 on_reply=None, count: int = 0) -> None:
        super().__init__(daemon=True, name="PingWorker")
        self.host = host
        self.interval = max(0.2, interval)
        self.timeout_ms = timeout_ms
        self.on_reply = on_reply
        self.count = count                      # 0 = 一直 ping
        self.seq = 0
        self.sent = 0
        self.recv = 0
        self.rtts: list[float] = []
        self._stop_evt = threading.Event()

    def run(self) -> None:
        from .assets import ping_one
        while not self._stop_evt.is_set():
            if self.count and self.seq >= self.count:
                break
            self.seq += 1
            self.sent += 1
            rtt = ping_one(self.host, self.timeout_ms)
            if rtt is not None:
                self.recv += 1
                self.rtts.append(rtt)
                if len(self.rtts) > 600:
                    del self.rtts[:200]
            if self.on_reply:
                try:
                    self.on_reply(self.seq, rtt)
                except Exception:
                    pass
            self._stop_evt.wait(self.interval)

    def stop(self) -> None:
        self._stop_evt.set()

    @property
    def stats(self) -> dict:
        loss = (1 - self.recv / self.sent) * 100 if self.sent else 0.0
        return {
            "sent": self.sent, "recv": self.recv,
            "loss": loss,
            "min": min(self.rtts) if self.rtts else 0,
            "max": max(self.rtts) if self.rtts else 0,
            "avg": sum(self.rtts) / len(self.rtts) if self.rtts else 0,
            "last": self.rtts[-1] if self.rtts else None,
        }


# --------------------------------------------------------------------------- #
# Traceroute
# --------------------------------------------------------------------------- #

def traceroute(host: str, max_hops: int = 30, timeout_ms: int = 1000,
               on_hop=None, cancel=None) -> list[dict]:
    """
    路由追踪。走系统 tracert（不需要管理员）。
    on_hop({"hop":n,"ip":..,"rtt":[...]}) 每跳回调一次。
    """
    hops: list[dict] = []
    try:
        proc = subprocess.Popen(
            ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_ms), host],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception as exc:
        log(f"启动 tracert 失败：{exc}", "error", "tools")
        return hops

    try:
        for raw in iter(proc.stdout.readline, b""):
            if cancel is not None and cancel.is_set():
                proc.kill()
                break
            line = raw.decode("gbk", "replace").rstrip()
            m = re.match(r"\s*(\d+)\s+(.*)$", line)
            if not m:
                continue
            idx = int(m.group(1))
            rest = m.group(2)
            ips = re.findall(r"\d+\.\d+\.\d+\.\d+", rest)
            rtts = [int(x) for x in re.findall(r"(\d+)\s*ms", rest)]
            hop = {"hop": idx, "ip": ips[-1] if ips else "*", "rtt": rtts}
            hops.append(hop)
            if on_hop:
                on_hop(hop)
    finally:
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    if not hops:
        log("tracert 没有解析出任何跳数（可能被防火墙拦了 ICMP）", "warn", "tools")
    return hops


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #

DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA"]

# 系统 DNS 不通时的回退公共 DNS（国内可达性较好）
PUBLIC_DNS = ["223.5.5.5", "119.29.29.29", "114.114.114.114", "180.76.76.76"]

# 多服务器对比用的预设服务器组（顺序 = 界面下拉里的顺序）
DNS_PRESETS: dict[str, list[str]] = {
    "国内公共": [
        "223.5.5.5", "223.6.6.6",              # 阿里 AliDNS
        "119.29.29.29",                        # 腾讯 DNSPod
        "114.114.114.114", "114.114.115.115",  # 114DNS
        "180.76.76.76",                        # 百度 BaiduDNS
        "180.184.1.1",                         # 字节 / 火山引擎
    ],
    "国际公共": [
        "8.8.8.8", "8.8.4.4",                  # Google
        "1.1.1.1", "1.0.0.1",                  # Cloudflare
        "9.9.9.9",                             # Quad9
        "208.67.222.222",                      # OpenDNS
    ],
    # 这几个多半查不到（家用路由器通常不对外开 DNS，或者直接拒绝），
    # 留着是为了跟公网结果对照 —— 能答上来的那台就是内网解析器。
    "路由器/内网": ["192.168.1.1", "192.168.0.1", "10.0.0.1"],
    # ⚠ 这些是 DoH 服务的域名，不是 IP，直接当 nameserver 填进去必然失败；
    # 要先过一遍 resolve_dns_hosts() 解析成 IP（界面上有「解析域名为 IP」按钮）。
    "DoH 服务器地址": ["dns.alidns.com", "doh.pub", "dns.google",
                       "cloudflare-dns.com", "dns.quad9.net"],
}

# 每个预设的说明，界面上直接显示给用户看
DNS_PRESET_NOTES: dict[str, str] = {
    "国内公共": "国内可达性好，适合当对比基线。",
    "国际公共": "可能被污染或干脆不可达；跟国内结果不一样时，多半是分区域解析或 CDN 调度。",
    "路由器/内网": "家用路由器多半不对外提供 DNS，查不到是正常的；能答上来的那台可用来判断内网解析是否被劫持。",
    "DoH 服务器地址": "这些是 DoH 服务域名、不是 IP，不能直接当 DNS 服务器用，请先点「解析域名为 IP」。",
}

# IP -> 好认的名字（界面「名称」列用）
DNS_SERVER_LABELS: dict[str, str] = {
    "223.5.5.5": "阿里 AliDNS",
    "223.6.6.6": "阿里 AliDNS（备用）",
    "119.29.29.29": "腾讯 DNSPod",
    "114.114.114.114": "114DNS",
    "114.114.115.115": "114DNS（备用）",
    "180.76.76.76": "百度 BaiduDNS",
    "180.184.1.1": "字节 / 火山引擎",
    "8.8.8.8": "Google",
    "8.8.4.4": "Google（备用）",
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare（备用）",
    "9.9.9.9": "Quad9",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS（备用）",
    "149.112.112.112": "Quad9（备用）",
    "1.12.12.12": "腾讯 DNSPod（DoH）",
    "120.53.53.53": "腾讯 DNSPod（DoH 备用）",
    "2001:4860:4860::8888": "Google（IPv6）",
    "2001:4860:4860::8844": "Google（IPv6 备用）",
    "2606:4700:4700::1111": "Cloudflare（IPv6）",
    "2620:fe::fe": "Quad9（IPv6）",
    "192.168.1.1": "内网网关（常见）",
    "192.168.0.1": "内网网关（常见）",
    "10.0.0.1": "内网网关（常见）",
    "127.0.0.1": "本机",
    "::1": "本机（IPv6）",
}

# 用户手填的服务器列表里，允许出现的分隔符（中英文逗号/分号/顿号/空白）
_DNS_SPLIT_RE = re.compile(r"[,;，、；\s]+")


def label_for(ip: str) -> str:
    """把 IP 换成好认的名字，查不到对应名字就原样返回 IP。"""
    key = str(ip).strip()
    return DNS_SERVER_LABELS.get(key, key)


def split_dns_servers(text: str) -> list[str]:
    """只按分隔符拆开、不去重不校验（域名也能拆），给「解析域名为 IP」用。"""
    return [tok for tok in (t.strip() for t in _DNS_SPLIT_RE.split(str(text or "")))
            if tok]


def parse_dns_servers(text: str) -> list[str]:
    """
    解析用户手填的服务器列表（逗号/分号/空格/换行分隔），返回去重后的列表。

    逐条校验是不是合法的 IPv4/IPv6 字面量：**不合法就直接抛 ValueError**，
    绝不静默丢弃 —— 否则用户以为查了 8 台，实际只查了 7 台，对比结论会骗人。
    顺序按用户填写的顺序保留。
    """
    out: list[str] = []
    bad: list[str] = []
    for token in split_dns_servers(text):
        cand = token.strip().strip("[]")        # 兼容 [2400:3200::1] 这种写法
        try:
            ipaddress.ip_address(cand)
        except ValueError:
            bad.append(token)
            continue
        if cand not in out:
            out.append(cand)
    if bad:
        shown = "、".join(bad[:6]) + ("…" if len(bad) > 6 else "")
        raise ValueError(f"不是合法的 IP 地址：{shown}")
    return out


def _dns_format_records(answers, rtype: str) -> list[str]:
    """把 dnspython 的答案对象格式化成人能读的记录字符串。"""
    out = []
    for a in answers:
        if rtype.upper() == "MX":
            out.append(f"{a.preference} {a.exchange}")
        elif rtype.upper() == "SOA":
            out.append(f"{a.mname} serial={a.serial} refresh={a.refresh}")
        else:
            out.append(str(a).strip('"'))
    return out


def _dns_try(name: str, rtype: str, server: str, timeout: float):
    """查一次，返回 (记录列表, 错误信息)。"""
    import dns.resolver
    r = dns.resolver.Resolver()
    if server:
        r.nameservers = [server]
    r.timeout = timeout
    r.lifetime = timeout
    try:
        answers = r.resolve(name, rtype.upper())
    except dns.resolver.NXDOMAIN:
        return ["（域名不存在 NXDOMAIN）"], ""
    except dns.resolver.NoAnswer:
        return [f"（没有 {rtype.upper()} 记录）"], ""
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"

    out = _dns_format_records(answers, rtype)
    return out, ""


def dns_query(name: str, rtype: str = "A", server: str = "",
              timeout: float = 5.0, fallback: bool = True) -> list[str]:
    """
    用 dnspython 查 DNS 记录。不指定 server 时先用系统 DNS，
    失败且 fallback=True 就依次试公共 DNS，并在日志里说明用的是哪台。
    """
    attempts = [server] if server else [""]
    if not server and fallback:
        attempts += PUBLIC_DNS

    last_err = ""
    for srv in attempts:
        records, err = _dns_try(name, rtype, srv, timeout)
        if records:
            if srv:
                log(f"DNS {rtype.upper()} {name} -> 由 {srv} 应答", "debug", "tools")
            elif attempts.index(srv) == 0 and server == "":
                log(f"DNS {rtype.upper()} {name} -> 由系统 DNS 应答", "debug", "tools")
            return records
        last_err = err or last_err

    return [f"（查询失败：{last_err or '所有 DNS 服务器都无响应'}）"]


def _dns_multi_one(name: str, rtype: str, server: str, timeout: float) -> dict:
    """
    问一台服务器，**任何异常都收敛成返回值**，绝不往外抛。

    ⚠ 必须是「一个 server 一个 Resolver 实例」：Resolver 上记着 nameservers /
    超时 / EDNS 这些状态，多线程共用一台实例会互相串结果。
    """
    import dns.exception
    import dns.resolver

    r = dns.resolver.Resolver()
    r.nameservers = [server]
    r.timeout = timeout
    r.lifetime = timeout

    records: list[str] = []
    error = ""
    status = "正常"
    ok = False
    t0 = time.perf_counter()
    try:
        answers = r.resolve(name, rtype.upper())
        records = _dns_format_records(answers, rtype)
        ok = True
        if not records:
            status = "无此记录"
    except dns.resolver.NXDOMAIN:
        # 服务器明确回答「这域名不存在」——算有应答，只是没有记录
        status, ok = "NXDOMAIN", True
    except dns.resolver.NoAnswer:
        status, ok = "无此记录", True
    except dns.exception.Timeout:
        status, error = "超时", f"{timeout:g}s 内没有响应"
    except dns.resolver.NoNameservers as exc:
        first = str(exc).strip().splitlines()
        status = "超时" if "time" in str(exc).lower() else "无应答"
        error = first[0] if first else type(exc).__name__
    except Exception as exc:
        status, error = "查询失败", f"{type(exc).__name__}: {exc}"
    return {
        "server": server,
        "label": label_for(server),
        "ok": ok,
        "records": records,
        "error": error,
        "rtt_ms": (time.perf_counter() - t0) * 1000.0,
        "status": status,
    }


def dns_query_multi(name: str, rtype: str = "A", servers=None,
                    timeout: float = 5.0, workers: int = 8) -> list[dict]:
    """
    并发问一批 DNS 服务器同一条记录，用来对比分区域解析 / 劫持 / 死服务器。

    servers=None 时用系统 DNS，读不到就退回 PUBLIC_DNS。结果按传入顺序排列，
    每项：{"server", "label", "ok", "records", "error", "rtt_ms", "status"}。

    ⚠ 线程池并发，不是一台一台串着问：死服务器只拖自己，不影响别的。
    某一台炸了只体现在它自己的 ok/error/status 上，不会连累其它服务器。
    """
    if servers is None:
        servers = dns_servers() or list(PUBLIC_DNS)
    srv_list: list[str] = []
    for s in servers:
        s = str(s).strip()
        if s and s not in srv_list:
            srv_list.append(s)
    if not srv_list:
        return []

    n = max(1, min(int(workers) or 1, len(srv_list)))
    try:
        with ThreadPoolExecutor(max_workers=n) as pool:
            return list(pool.map(
                lambda srv: _dns_multi_one(name, rtype, srv, timeout), srv_list))
    except Exception as exc:
        # 线程池本身都起不来（极端情况）：也要给调用方一份完整结果，不能抛
        log(f"多服务器 DNS 查询失败：{type(exc).__name__}: {exc}", "error", "tools")
        return [{"server": s, "label": label_for(s), "ok": False, "records": [],
                 "error": f"{type(exc).__name__}: {exc}", "rtt_ms": 0.0,
                 "status": "查询失败"} for s in srv_list]


def dns_consistency(results: list[dict]) -> dict:
    """
    比较多台服务器的应答，找出谁跟谁不一样。

    返回：
        {"total", "answered", "failed", "consistent": bool,
         "groups": [{"records": [...], "servers": [...], "count": n}],  # 台数从多到少
         "majority_servers", "majority_records", "disagree_servers", "verdict"}

    空记录（NXDOMAIN / 无此记录）按「状态」单独成一组，免得跟真的空答案混在一起。
    ⚠ 按**集合**比较、不看顺序：A 记录轮询（round-robin）/ CDN 调度会让同一份
    答案的返回顺序不一样，那不算「结果不同」，否则天天误报劫持。
    """
    answered = [r for r in results if r.get("ok")]
    failed = [r for r in results if not r.get("ok")]

    groups: list[dict] = []
    for r in answered:
        records = [str(x) for x in (r.get("records") or [])]
        key = tuple(sorted(records)) if records else (str(r.get("status") or "无此记录"),)
        for g in groups:
            if g["key"] == key:
                g["servers"].append(str(r.get("server", "")))
                g["count"] += 1
                break
        else:
            groups.append({"key": key, "records": records,
                           "servers": [str(r.get("server", ""))], "count": 1})
    groups.sort(key=lambda g: -g["count"])

    total, n_ok = len(results), len(answered)
    if not total:
        verdict = "没有要查询的服务器"
    elif not n_ok:
        verdict = f"全部 {total} 台都没应答（网络或防火墙问题）"
    elif len(groups) == 1:
        verdict = f"{n_ok}/{total} 台一致"
    else:
        verdict = f"发现 {len(groups)} 种不同结果（可能存在分区域解析或劫持）"
    if n_ok and failed:
        verdict += f"，{len(failed)} 台无应答"

    return {
        "total": total,
        "answered": n_ok,
        "failed": len(failed),
        "consistent": len(groups) == 1 and n_ok > 0 and not failed,
        "groups": [{k: v for k, v in g.items() if k != "key"} for g in groups],
        "majority_servers": list(groups[0]["servers"]) if groups else [],
        "majority_records": list(groups[0]["records"]) if groups else [],
        "disagree_servers": [s for g in groups[1:] for s in g["servers"]],
        "verdict": verdict,
    }


def resolve_dns_hosts(hosts, timeout: float = 3.0,
                      workers: int = 6) -> tuple[list[str], list[str]]:
    """
    把 DoH 域名解析成 IP —— DNS_PRESETS["DoH 服务器地址"] 里给的是域名，
    必须先变成 IP 才能当 nameserver 用。已经是 IP 的原样保留。

    优先取 IPv4（A）：很多网络根本没有 IPv6 出口，混进一堆 v6 地址只会
    让对比表里一半服务器超时；只有这个域名没有 A 记录时才退回 IPv6（AAAA）。

    并发解析，返回 (IP 列表, 没解析出来的名字列表)，同样不抛异常。
    """
    import dns.resolver

    items = [str(h).strip() for h in (hosts or [])]
    items = [h for h in items if h]
    ips: list[str] = []
    missing: list[str] = []

    def one(host: str) -> tuple[str, list[str]]:
        cand = host.strip().strip("[]")
        try:
            ipaddress.ip_address(cand)
            return host, [cand]                 # 本来就是 IP
        except ValueError:
            pass
        out: list[str] = []
        for qtype in ("A", "AAAA"):
            r = dns.resolver.Resolver()
            r.timeout = timeout
            r.lifetime = timeout
            try:
                for a in r.resolve(host, qtype):
                    val = str(a).strip()
                    if val and val not in out:
                        out.append(val)
            except Exception:
                continue                        # 这种域名没有该类型记录很常见
            if out:
                break                           # 有 A 就不再要 AAAA 了
        return host, out

    pairs: list[tuple[str, list[str]]] = []
    if items:
        n = max(1, min(int(workers) or 1, len(items)))
        try:
            with ThreadPoolExecutor(max_workers=n) as pool:
                pairs = list(pool.map(one, items))
        except Exception as exc:
            log(f"解析 DoH 域名失败：{type(exc).__name__}: {exc}", "warn", "tools")
            pairs = [(h, []) for h in items]

    for host, got in pairs:
        if not got:
            missing.append(host)
            continue
        for ip in got:
            if ip not in ips:
                ips.append(ip)
    return ips, missing


def reverse_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "（没有 PTR 记录）"


# --------------------------------------------------------------------------- #
# Wake-on-LAN
# --------------------------------------------------------------------------- #

def wake_on_lan(mac: str, broadcast: str = "255.255.255.255",
                port: int = 9) -> tuple[bool, str]:
    """发魔术包唤醒设备。"""
    hexs = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexs) != 12:
        return False, f"MAC 格式不对：{mac}"
    payload = b"\xff" * 6 + bytes.fromhex(hexs) * 16
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(payload, (broadcast, port))
        s.close()
        return True, f"魔术包已发往 {broadcast}:{port}（MAC {mac}）"
    except Exception as exc:
        return False, f"发送失败：{type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------- #
# HTTP(S) 探测
# --------------------------------------------------------------------------- #

def http_probe(url: str, timeout: float = 8.0, check_tls: bool = True) -> dict:
    """探测 HTTP/HTTPS：状态码、耗时、Server、标题、TLS 证书到期时间。"""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    result: dict = {"url": url}
    try:
        import requests
        t0 = time.perf_counter()
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 NetOpsToolbox"})
        result["status"] = r.status_code
        result["耗时"] = f"{(time.perf_counter() - t0) * 1000:.0f} ms"
        result["最终地址"] = r.url
        result["Server"] = r.headers.get("Server", "-")
        result["内容长度"] = f"{len(r.content)} 字节"
        ctype = r.headers.get("Content-Type", "")
        result["Content-Type"] = ctype
        if "html" in ctype.lower():
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
            result["标题"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else "-"
        else:
            result["标题"] = "-"
    except Exception as exc:
        result["status"] = f"失败：{type(exc).__name__}: {exc}"

    if check_tls and url.startswith("https://"):
        m = re.match(r"https://([^/:]+)(?::(\d+))?", url)
        if m:
            host = m.group(1)
            port = int(m.group(2) or 443)
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ss:
                        cert = ss.getpeercert()
                        not_after = cert.get("notAfter", "")
                        result["TLS 协议"] = ss.version()
                        result["证书到期"] = not_after
                        if not_after:
                            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days = (exp - datetime.utcnow()).days
                            result["证书剩余"] = f"{days} 天"
            except Exception as exc:
                result["证书到期"] = f"读取失败：{type(exc).__name__}"
    return result


def tcp_check(host: str, port: int, timeout: float = 2.0) -> tuple[bool, str]:
    """快速测一个 TCP 端口通不通。"""
    from .ports import _connect_probe
    state, dt = _connect_probe(host, port, timeout)
    return state == "open", f"{state}  {dt:.0f} ms"


# --------------------------------------------------------------------------- #
# SNTP 时间校准
# --------------------------------------------------------------------------- #

def sntp_offset(server: str = "ntp.aliyun.com", timeout: float = 4.0) -> dict:
    """查询 NTP 服务器与本机的时间差（纯 socket，不依赖额外库）。"""
    pkt = b"\x1b" + 47 * b"\x00"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t0 = time.time()
        s.sendto(pkt, (server, 123))
        data, addr = s.recvfrom(1024)
        t3 = time.time()
        if len(data) < 48:
            return {"ok": False, "msg": "返回数据不完整"}
        secs = struct.unpack("!I", data[40:44])[0]
        ntp_time = secs - 2208988800            # 1900 -> 1970
        offset = ntp_time - (t0 + t3) / 2
        return {
            "ok": True, "server": addr[0],
            "服务器时间": datetime.fromtimestamp(ntp_time, timezone.utc)
                          .astimezone().strftime("%Y-%m-%d %H:%M:%S"),
            "本机时间": datetime.fromtimestamp((t0 + t3) / 2).strftime("%Y-%m-%d %H:%M:%S"),
            "偏差": f"{offset * 1000:+.0f} ms",
            "偏差秒": round(offset, 3),
        }
    except Exception as exc:
        return {"ok": False, "msg": f"{type(exc).__name__}: {exc}"}
    finally:
        try:
            s.close()
        except Exception:
            pass
