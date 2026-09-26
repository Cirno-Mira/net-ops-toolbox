# -*- coding: utf-8 -*-
"""
运维小工具集合
==============

ping / traceroute / DNS 查询 / 反向解析 / Wake-on-LAN / HTTP(S) 探测 /
SNTP 时间校准 / 本机信息汇总。全部是纯 Python + 系统命令，尽量不依赖管理员。
"""

from __future__ import annotations

import getpass
import platform
import re
import socket
import ssl
import struct
import subprocess
import threading
import time
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

    out = []
    for a in answers:
        if rtype.upper() == "MX":
            out.append(f"{a.preference} {a.exchange}")
        elif rtype.upper() == "SOA":
            out.append(f"{a.mname} serial={a.serial} refresh={a.refresh}")
        else:
            out.append(str(a).strip('"'))
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
