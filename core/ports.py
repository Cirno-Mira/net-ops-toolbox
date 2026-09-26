# -*- coding: utf-8 -*-
"""
端口扫描
========

* TCP connect 扫描：纯 socket，**不需要管理员**
* SYN 半开扫描：scapy + Npcap，需要管理员（更快、更隐蔽）
* 服务名映射、banner 抓取、端口预设

对外主入口：scan_hosts()
"""

from __future__ import annotations

import concurrent.futures as cf
import re
import socket
import time
from dataclasses import dataclass

from .hostinfo import is_admin
from .logging_bus import log

# --------------------------------------------------------------------------- #
# 服务名表（常用端口）
# --------------------------------------------------------------------------- #

SERVICES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time",
    42: "wins", 43: "whois", 49: "tacacs", 53: "dns", 67: "dhcp", 68: "dhcp",
    69: "tftp", 70: "gopher", 79: "finger", 80: "http", 81: "http-alt",
    82: "http-alt", 83: "http-alt", 88: "kerberos", 102: "iso-tsap", 110: "pop3",
    111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 162: "snmptrap", 177: "xdmcp", 179: "bgp", 194: "irc",
    199: "smux", 389: "ldap", 427: "svrloc", 443: "https", 444: "snpp",
    445: "microsoft-ds", 464: "kpasswd", 465: "smtps", 500: "isakmp",
    512: "exec", 513: "login", 514: "syslog", 515: "lpd", 520: "rip",
    523: "ibm-db2", 524: "ncp", 540: "uucp", 548: "afp", 554: "rtsp",
    587: "submission", 623: "ipmi", 631: "ipp", 636: "ldaps", 646: "ldp",
    873: "rsync", 888: "accessbuilder", 902: "vmware-auth", 989: "ftps-data",
    990: "ftps", 993: "imaps", 995: "pop3s", 1025: "nfs-or-iis", 1026: "lsa",
    1027: "iad", 1028: "ms-lsa", 1029: "ms-lsa", 1080: "socks", 1099: "rmi",
    1110: "nfs", 1194: "openvpn", 1433: "mssql", 1434: "mssql-mon",
    1521: "oracle", 1701: "l2tp", 1723: "pptp", 1720: "h323", 1812: "radius",
    1883: "mqtt", 1900: "upnp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2181: "zookeeper", 2222: "ssh-alt", 2375: "docker", 2376: "docker-ssl",
    3000: "node/grafana", 3128: "squid", 3260: "iscsi", 3306: "mysql",
    3307: "mysql-alt", 3389: "rdp", 3478: "stun", 4000: "icq", 4369: "epmd",
    4443: "https-alt", 4444: "krb524", 4505: "salt", 4506: "salt",
    5000: "upnp/flask", 5038: "asterisk", 5222: "xmpp", 5269: "xmpp-server",
    5353: "mdns", 5432: "postgres", 5555: "adb/freeciv", 5601: "kibana",
    5672: "amqp", 5683: "coap", 5900: "vnc", 5901: "vnc-1", 5984: "couchdb",
    5985: "winrm-http", 5986: "winrm-https", 6000: "x11", 6379: "redis",
    6443: "k8s-api", 6667: "irc", 7001: "weblogic", 7002: "weblogic-ssl",
    7474: "neo4j", 8000: "http-alt", 8006: "proxmox", 8008: "http-alt",
    8009: "ajp13", 8010: "http-alt", 8020: "http-alt", 8032: "http-alt",
    8042: "http-alt", 8069: "odoo", 8080: "http-proxy", 8081: "http-alt",
    8082: "http-alt", 8083: "http-alt", 8086: "influxdb", 8088: "http-alt",
    8090: "http-alt", 8091: "couchbase", 8096: "jellyfin", 8123: "homeassistant",
    8161: "activemq", 8180: "http-alt", 8200: "http-alt", 8222: "vmware",
    8300: "http-alt", 8443: "https-alt", 8500: "consul", 8529: "arangodb",
    8834: "nessus", 8883: "mqtt-ssl", 8888: "http-alt", 8983: "solr",
    9000: "php-fpm", 9001: "tor/portainer", 9042: "cassandra", 9060: "http-alt",
    9090: "prometheus", 9091: "transmission", 9092: "kafka", 9100: "jetdirect",
    9200: "elasticsearch", 9300: "es-transport", 9418: "git", 9443: "https-alt",
    9600: "http-alt", 9999: "http-alt", 10000: "webmin", 10050: "zabbix-agent",
    10051: "zabbix-server", 10250: "kubelet", 11211: "memcached",
    15672: "rabbitmq-mgmt", 16379: "redis-alt", 27017: "mongodb",
    27018: "mongodb", 32400: "plex", 37777: "dahua-dvr", 49152: "windows-rpc",
    50000: "db2/sap", 50070: "hadoop-namenode", 54321: "http-alt",
    55553: "http-alt", 62078: "iphone-sync",
}

# 摄像头 / NVR 常见端口（海康、大华、宇视等）
CAMERA_PORTS = [80, 443, 554, 8000, 8080, 8443, 34567, 37777, 37778, 8899]

TOP100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
    79, 80, 81, 82, 83, 84, 85, 88, 89, 99,
    100, 106, 109, 110, 111, 113, 119, 125, 135, 139,
    143, 144, 146, 161, 163, 179, 199, 211, 212, 222,
    254, 255, 256, 259, 264, 280, 301, 306, 311, 340,
    366, 389, 406, 407, 416, 417, 425, 427, 443, 444,
    445, 458, 464, 465, 481, 497, 500, 512, 513, 514,
    515, 524, 541, 543, 544, 545, 548, 554, 555, 563,
    587, 593, 616, 617, 625, 631, 636, 646, 648, 666,
    667, 668, 683, 687, 691, 700, 705, 711, 714, 720,
]

PRESETS: dict[str, list[int] | tuple[int, int]] = {
    "常用 (Top 30)": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389,
                      443, 445, 465, 587, 631, 993, 995, 1433, 1521, 3306, 3389,
                      5432, 5900, 6379, 8080, 8443, 27017],
    "Web 服务": [80, 81, 82, 83, 84, 85, 88, 443, 444, 800, 801, 888, 3000, 5000,
                 8000, 8008, 8009, 8010, 8020, 8032, 8042, 8069, 8080, 8081, 8082,
                 8083, 8086, 8088, 8090, 8096, 8123, 8180, 8200, 8300, 8443, 8888,
                 8983, 9000, 9001, 9060, 9090, 9091, 9200, 9443, 9600, 9999, 10000],
    "数据库": [1433, 1434, 1521, 3306, 3307, 5432, 5900, 6379, 9042, 9200, 9300,
               11211, 16379, 27017, 27018, 50000, 2181, 9092, 5672, 15672, 8500],
    "远程管理": [22, 23, 3389, 5900, 5901, 5985, 5986, 512, 513, 514, 873, 10000,
                 8006, 9090, 2375, 2376, 6443, 10250],
    "文件共享": [139, 445, 137, 138, 21, 20, 69, 111, 2049, 548, 873, 3260, 9100,
                 515, 631],
    "监控/摄像头": CAMERA_PORTS + [554, 1935, 7001, 7002],
    "Windows 常见": [135, 137, 138, 139, 445, 464, 593, 636, 3268, 3269, 3389,
                     5357, 5985, 5986, 49152, 49153, 49154, 49155, 49156],
    "Top 100": TOP100,
    "1-1024": (1, 1024),
    "1-10000": (1, 10000),
    "全端口 1-65535": (1, 65535),
}

BANNER_PORTS = {
    21, 22, 23, 25, 80, 110, 143, 443, 587, 993, 995, 3306, 5432, 6379, 8080,
    8443, 8000, 8888, 27017, 9200, 11211, 5900, 3389, 1883, 5672,
}
HTTP_PORTS = {80, 81, 82, 83, 84, 85, 88, 443, 444, 800, 888, 3000, 5000, 8000,
              8008, 8080, 8081, 8082, 8083, 8086, 8088, 8090, 8096, 8123, 8180,
              8443, 8888, 9000, 9090, 9200, 9443, 10000}


# --------------------------------------------------------------------------- #
# 端口规格解析
# --------------------------------------------------------------------------- #

def _preset_lookup(name: str):
    """按名字找预设，忽略大小写与空格（'常用 (Top 30)' / '常用(top30)' 都认）。"""
    key = re.sub(r"\s+", "", name or "").lower()
    if not key:
        return None
    for pname, value in PRESETS.items():
        if re.sub(r"\s+", "", pname).lower() == key:
            return value
    return None


def _preset_ports(value) -> list[int]:
    if isinstance(value, tuple):
        return list(range(value[0], value[1] + 1))
    return sorted(set(value))


def parse_ports(spec: str) -> list[int]:
    """
    解析端口规格：'80,443'、'1-1024'、'常用 (Top 30)'、'top100'、'all'，
    也可混用：'22,80,8000-8100'。
    """
    spec = (spec or "").strip()
    if not spec:
        return []
    low = spec.lower()
    if low in ("all", "全部", "全端口"):
        return list(range(1, 65536))
    if low in ("top100", "top 100"):
        return sorted(set(TOP100))

    # 整串就是一个预设名（可能带空格，所以要在切分之前判断）
    preset = _preset_lookup(spec)
    if preset is not None:
        return _preset_ports(preset)

    ports: set[int] = set()
    for token in re.split(r"[,\s;]+", spec):
        if not token:
            continue
        preset = _preset_lookup(token)
        if preset is not None:
            ports.update(_preset_ports(preset))
            continue
        if "-" in token:
            a, _, b = token.partition("-")
            try:
                lo, hi = int(a), int(b)
                lo, hi = max(1, lo), min(65535, hi)
                if hi >= lo:
                    ports.update(range(lo, hi + 1))
            except ValueError:
                log(f"忽略无法解析的端口段：{token}", "warn", "ports")
        else:
            try:
                p = int(token)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                log(f"忽略无法解析的端口：{token}", "warn", "ports")
    return sorted(ports)


def service_name(port: int) -> str:
    return SERVICES.get(port, "")


# --------------------------------------------------------------------------- #
# 结果与扫描
# --------------------------------------------------------------------------- #

@dataclass
class PortResult:
    host: str
    port: int
    state: str = "closed"          # open / closed / filtered
    service: str = ""
    banner: str = ""
    rtt_ms: float = 0.0

    def row(self) -> list:
        return [self.host, self.port, self.state,
                self.service or service_name(self.port) or "-",
                f"{self.rtt_ms:.0f} ms" if self.state == "open" else "-",
                self.banner]


def _connect_probe(host: str, port: int, timeout: float) -> tuple[str, float]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        rc = s.connect_ex((host, port))
        dt = (time.perf_counter() - t0) * 1000
        if rc == 0:
            return "open", dt
        if rc in (10061, 111, 61, 10054):         # 连接被拒绝 = 端口关闭
            return "closed", dt
        if rc in (10060, 10065, 10051, 10013):    # 超时 / 不可达 / 被策略拦
            return "filtered", dt
        return "closed", dt
    except socket.timeout:
        return "filtered", (time.perf_counter() - t0) * 1000
    except OSError:
        return "filtered", (time.perf_counter() - t0) * 1000
    finally:
        try:
            s.close()
        except Exception:
            pass


def grab_banner(host: str, port: int, timeout: float = 1.5) -> str:
    """尽量抓一点服务指纹：HTTP 状态行 / SSH 版本 / 数据库握手等。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((host, port)) != 0:
            return ""
        if port in HTTP_PORTS:
            req = (f"HEAD / HTTP/1.0\r\nHost: {host}\r\n"
                   "User-Agent: NetOpsToolbox/1.0\r\nAccept: */*\r\n\r\n")
            s.sendall(req.encode())
            data = s.recv(1024)
            text = data.decode("utf-8", "replace")
            first = text.splitlines()[0] if text else ""
            server = ""
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    break
            return (first + (f" | {server}" if server else "")).strip()[:160]
        data = s.recv(256)
        if not data:
            return ""
        return data.decode("utf-8", "replace").strip().replace("\r", " ").replace("\n", " ")[:160]
    except Exception:
        return ""
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan_host(host: str, ports: list[int], timeout: float = 0.6, workers: int = 200,
              cancel=None, progress=None, banners: bool = True) -> list[PortResult]:
    """扫单个主机的端口（多线程 TCP connect）。"""
    results: list[PortResult] = []
    done = 0
    total = len(ports)

    def work(p: int):
        return p, _connect_probe(host, p, timeout)

    with cf.ThreadPoolExecutor(max_workers=max(1, min(workers, total or 1))) as pool:
        futs = {pool.submit(work, p): p for p in ports}
        for fut in cf.as_completed(futs):
            if cancel is not None and cancel.is_set():
                for f in futs:
                    f.cancel()
                break
            p, (state, dt) = fut.result()
            if state == "open":
                results.append(PortResult(host=host, port=p, state=state,
                                          service=service_name(p), rtt_ms=dt))
            done += 1
            if progress and (done % 50 == 0 or done == total):
                progress(done, total, host)

    if banners:
        for r in results:
            if r.port in BANNER_PORTS or r.port in HTTP_PORTS:
                r.banner = grab_banner(host, r.port)
                if r.banner and not r.service:
                    r.service = r.banner.split()[0][:20]

    results.sort(key=lambda r: r.port)
    return results


def scan_hosts(targets: list[str], ports: list[int], timeout: float = 0.6,
               workers: int = 200, host_workers: int = 8, cancel=None,
               progress=None, banners: bool = True,
               on_result=None) -> list[PortResult]:
    """
    扫多个主机。progress(done_hosts, total_hosts, message)，on_result(PortResult) 逐条回调。
    """
    all_results: list[PortResult] = []
    total = len(targets)
    done = 0
    for host in targets:
        if cancel is not None and cancel.is_set():
            break
        try:
            res = scan_host(host, ports, timeout, workers, cancel, None, banners)
        except Exception as exc:
            log(f"{host} 扫描出错：{type(exc).__name__}: {exc}", "error", "ports")
            res = []
        all_results.extend(res)
        if on_result:
            for r in res:
                on_result(r)
        done += 1
        if progress:
            progress(done, total, host)
    return all_results


# --------------------------------------------------------------------------- #
# SYN 半开扫描（需要管理员）
# --------------------------------------------------------------------------- #

def syn_scan(targets: list[str], ports: list[int], l2_name: str = "",
             timeout: float = 2.0, progress=None, cancel=None) -> list[PortResult]:
    """用 scapy 发 SYN 的半开扫描，比 connect 扫描快很多，需要 Npcap + 管理员。"""
    if not is_admin():
        raise PermissionError("SYN 扫描需要管理员权限（原始套接字收发）")
    from scapy.all import IP, TCP, sr

    results: list[PortResult] = []
    total = len(targets)
    for idx, host in enumerate(targets, 1):
        if cancel is not None and cancel.is_set():
            break
        pkts = IP(dst=host) / TCP(dport=ports, flags="S")
        ans, _ = sr(pkts, timeout=timeout, verbose=0, iface=l2_name or None)
        for _sent, rcv in ans:
            if rcv.haslayer(TCP) and int(rcv[TCP].flags) & 0x12 == 0x12:   # SYN+ACK
                results.append(PortResult(host=host, port=int(rcv[TCP].sport),
                                          state="open",
                                          service=service_name(int(rcv[TCP].sport))))
        if progress:
            progress(idx, total, host)
    results.sort(key=lambda r: (r.host, r.port))
    return results


def summarize(results: list[PortResult], scanned_ports: int = 0,
              host_count: int = 0) -> str:
    """
    给日志/状态栏用的一句话总结。

    顺带做一个合理性自检：如果「开放端口 / (主机数 × 端口数)」高得离谱，
    通常不是目标真的全开，而是本地防火墙、杀软、VPN 或中间设备在伪造握手
    （典型表现：目标上并无进程监听某端口，connect 却返回成功）。
    """
    hosts = {r.host for r in results}
    txt = f"{len(hosts)} 台主机发现 {len(results)} 个开放端口"
    if scanned_ports and host_count:
        total = scanned_ports * host_count
        if total >= 20 and len(results) / total > 0.8:
            txt += ("　⚠ 开放比例异常高，可能有本地防火墙/安全软件/中间设备伪造握手，"
                    "建议换台机器或关掉安全软件复核")
    return txt
