# -*- coding: utf-8 -*-
"""
漏洞 / 错误配置快速指纹扫描
===========================

定位：**只做检测，不做利用**。用来在授权测试或 CTF 里快速找出
「明显没设防」的服务，然后你自己决定下一步。

覆盖的检查（都是只读的、发一个探针看响应，不写数据、不执行命令）：

    未授权访问：Redis / Memcached / MongoDB / Elasticsearch / Docker API /
               ZooKeeper / CouchDB / Hadoop YARN / Kibana / RabbitMQ 管理台 /
               Kubernetes API / etcd
    匿名与弱配置：FTP 匿名登录、Telnet 开放、SMB 开放、RDP 开放、
                VNC 无认证、rsync 未授权列出、SVN/Git 源码泄露

**弱口令爆破单独放在 `weak_credentials()`，默认不在自动检查里跑**，
需要显式调用，界面上也要求先勾选授权确认。
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import re
import socket
import struct
import time
from dataclasses import dataclass, field

from .logging_bus import log

# 严重程度
CRITICAL = "严重"
HIGH = "高危"
MEDIUM = "中危"
LOW = "低危"
INFO = "信息"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}


@dataclass
class Finding:
    host: str
    port: int
    name: str
    severity: str
    detail: str
    evidence: str = ""
    checked_at: str = field(default_factory=lambda: time.strftime("%H:%M:%S"))

    def row(self) -> list:
        return [self.host, self.port, self.name, self.severity, self.detail, self.evidence[:80]]


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #

def _tcp(host: str, port: int, timeout: float = 3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((host, port)) != 0:
            return None
        return s
    except OSError:
        try:
            s.close()
        except Exception:
            pass
        return None


def _send_recv(sock, data: bytes, size: int = 4096, timeout: float = 3.0) -> bytes:
    try:
        sock.settimeout(timeout)
        sock.sendall(data)
        return sock.recv(size)
    except Exception:
        return b""


def _http_get(host: str, port: int, path: str = "/", timeout: float = 4.0,
              tls: bool = False) -> tuple[int, str]:
    """极简 HTTP 客户端，返回 (状态码, 正文片段)。"""
    s = _tcp(host, port, timeout)
    if s is None:
        return 0, ""
    try:
        if tls:
            import ssl
            ctx = ssl._create_unverified_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        req = (f"GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\n"
               "User-Agent: NetOpsToolbox\r\nAccept: */*\r\n"
               "Connection: close\r\n\r\n")
        sock = s
        sock.settimeout(timeout)
        sock.sendall(req.encode())
        buf = b""
        while len(buf) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        text = buf.decode("utf-8", "replace")
        m = re.match(r"HTTP/\d\.\d\s+(\d+)", text)
        code = int(m.group(1)) if m else 0
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
        return code, body
    except Exception:
        return 0, ""
    finally:
        try:
            s.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# 单项检查：每个函数返回 Finding 或 None
# --------------------------------------------------------------------------- #

def check_redis(host: str, port: int = 6379, timeout: float = 3.0) -> Finding | None:
    s = _tcp(host, port, timeout)
    if s is None:
        return None
    try:
        resp = _send_recv(s, b"PING\r\n")
        if b"+PONG" in resp:
            info = _send_recv(s, b"INFO server\r\n", 8192)
            ver = ""
            m = re.search(rb"redis_version:([\d.]+)", info)
            if m:
                ver = m.group(1).decode()
            keys = _send_recv(s, b"DBSIZE\r\n", 256).strip()
            return Finding(host, port, "Redis 未授权访问", CRITICAL,
                           "无需密码即可执行命令，可读写数据甚至写文件拿 shell",
                           f"PING->+PONG 版本={ver or '?'} {keys.decode('latin-1')[:40]}")
    finally:
        s.close()
    return None


def check_memcached(host: str, port: int = 11211, timeout: float = 3.0) -> Finding | None:
    s = _tcp(host, port, timeout)
    if s is None:
        return None
    try:
        resp = _send_recv(s, b"stats\r\n", 4096)
        if resp.startswith(b"STAT"):
            items = b""
            m = re.search(rb"curr_items:(\d+)", resp)
            if m:
                items = m.group(1)
            return Finding(host, port, "Memcached 未授权访问", HIGH,
                           "可读写缓存数据，常被用来放大攻击或窃取会话",
                           f"stats 返回正常，curr_items={items.decode() or '?'}")
    finally:
        s.close()
    return None


def check_mongodb(host: str, port: int = 27017, timeout: float = 3.0) -> Finding | None:
    """发一个 legacy OP_QUERY isMaster，看是否无需认证就返回。"""
    s = _tcp(host, port, timeout)
    if s is None:
        return None
    try:
        # OP_QUERY -> admin.$cmd  {isMaster:1}
        bson = (b"\x13\x00\x00\x00" b"\x10isMaster\x00\x01\x00\x00\x00\x00")
        body = b"\x00\x00\x00\x00" + b"admin.$cmd\x00" + b"\x00\x00\x00\x00" + b"\xff\xff\xff\xff" + bson
        msg = struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body
        resp = _send_recv(s, msg, 4096)
        if len(resp) > 16 and (b"ismaster" in resp.lower() or b"maxBsonObjectSize" in resp):
            return Finding(host, port, "MongoDB 未授权访问", CRITICAL,
                           "无需认证即可查询数据库",
                           "isMaster 命令返回了数据库信息")
    finally:
        s.close()
    return None


def check_elasticsearch(host: str, port: int = 9200, timeout: float = 4.0) -> Finding | None:
    code, body = _http_get(host, port, "/_cat/indices?v", timeout)
    if code == 200 and ("index" in body.lower() or "health" in body.lower()):
        return Finding(host, port, "Elasticsearch 未授权访问", CRITICAL,
                       "可直接列出/读取全部索引数据",
                       body.strip().splitlines()[0][:70] if body.strip() else "")
    return None


def check_docker_api(host: str, port: int = 2375, timeout: float = 4.0) -> Finding | None:
    code, body = _http_get(host, port, "/version", timeout)
    if code == 200 and "ApiVersion" in body:
        try:
            ver = json.loads(body).get("Version", "?")
        except Exception:
            ver = "?"
        return Finding(host, port, "Docker API 未授权", CRITICAL,
                       "可直接创建特权容器挂载宿主机根目录，等于拿到宿主机",
                       f"Docker 版本 {ver}")
    return None


def check_zookeeper(host: str, port: int = 2181, timeout: float = 3.0) -> Finding | None:
    s = _tcp(host, port, timeout)
    if s is None:
        return None
    try:
        if b"imok" in _send_recv(s, b"ruok\n", 64):
            return Finding(host, port, "ZooKeeper 未授权访问", HIGH,
                           "四字命令开放，可读取集群信息甚至改配置",
                           "ruok -> imok")
    finally:
        s.close()
    return None


def check_couchdb(host: str, port: int = 5984, timeout: float = 4.0) -> Finding | None:
    code, body = _http_get(host, port, "/_all_dbs", timeout)
    if code == 200 and body.strip().startswith("["):
        return Finding(host, port, "CouchDB 未授权访问", HIGH,
                       "可枚举全部数据库", f"返回 {body[:60]}")
    return None


def check_hadoop_yarn(host: str, port: int = 8088, timeout: float = 4.0) -> Finding | None:
    code, body = _http_get(host, port, "/ws/v1/cluster/info", timeout)
    if code == 200 and "clusterInfo" in body:
        return Finding(host, port, "Hadoop YARN 未授权", CRITICAL,
                       "可通过 REST API 提交任务执行任意命令",
                       "cluster info 可未授权读取")
    return None


def check_kibana(host: str, port: int = 5601, timeout: float = 4.0) -> Finding | None:
    code, body = _http_get(host, port, "/api/status", timeout)
    if code == 200 and "version" in body:
        return Finding(host, port, "Kibana 管理台开放", MEDIUM,
                       "管理界面无需认证即可访问", body[:60])
    return None


def check_rabbitmq(host: str, port: int = 15672, timeout: float = 4.0) -> Finding | None:
    code, _ = _http_get(host, port, "/api/overview", timeout)
    if code == 200:
        return Finding(host, port, "RabbitMQ 管理台未授权", HIGH,
                       "可管理队列/用户；默认 guest/guest 也常可用", "api/overview 200")
    return None


def check_etcd(host: str, port: int = 2379, timeout: float = 4.0) -> Finding | None:
    code, body = _http_get(host, port, "/v2/keys/?recursive=true", timeout)
    if code == 200 and "node" in body:
        return Finding(host, port, "etcd 未授权访问", CRITICAL,
                       "可读取（甚至篡改）集群全部键值，含各种凭证",
                       body[:60])
    return None


def check_kubernetes(host: str, port: int = 8080, timeout: float = 4.0) -> Finding | None:
    code, body = _http_get(host, port, "/api/v1/namespaces", timeout)
    if code == 200 and "namespaces" in body:
        return Finding(host, port, "Kubernetes API 未授权", CRITICAL,
                       "可读写集群资源，可创建 Pod 逃逸到宿主机", body[:60])
    return None


def check_ftp_anonymous(host: str, port: int = 21, timeout: float = 4.0) -> Finding | None:
    s = _tcp(host, port, timeout)
    if s is None:
        return None
    try:
        banner = s.recv(256).decode("latin-1", "replace").strip()
        if not banner.startswith("220"):
            return None
        resp = _send_recv(s, b"USER anonymous\r\n", 256).decode("latin-1", "replace")
        if not resp.startswith("331"):
            resp = _send_recv(s, b"USER ftp\r\n", 256).decode("latin-1", "replace")
        if resp.startswith("331"):
            resp = _send_recv(s, b"PASS anonymous@test.com\r\n", 256).decode("latin-1", "replace")
        if resp.startswith("230"):
            return Finding(host, port, "FTP 匿名登录", HIGH,
                           "任何人可登录并可能读写文件",
                           f"banner={banner[:50]} 登录成功")
    finally:
        s.close()
    return None


def check_telnet(host: str, port: int = 23, timeout: float = 3.0) -> Finding | None:
    s = _tcp(host, port, timeout)
    if s is None:
        return None
    try:
        s.settimeout(2.0)
        try:
            data = s.recv(256)
        except Exception:
            data = b""
        if data:
            return Finding(host, port, "Telnet 服务开放", MEDIUM,
                           "明文传输账号密码，建议改用 SSH",
                           data[:40].decode("latin-1", "replace").strip())
    finally:
        s.close()
    return None


def check_smb(host: str, port: int = 445, timeout: float = 3.0) -> Finding | None:
    s = _tcp(host, port, timeout)
    if s is None:
        return None
    s.close()
    return Finding(host, port, "SMB 文件共享开放", INFO,
                   "确认是否允许匿名/空会话访问，以及是否强制签名",
                   "445 端口可连")


def check_rdp(host: str, port: int = 3389, timeout: float = 3.0) -> Finding | None:
    s = _tcp(host, port, timeout)
    if s is None:
        return None
    try:
        # 发 X.224 连接请求，看是否回 confirm
        pkt = (b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00"
               b"\x01\x00\x08\x00\x03\x00\x00\x00")
        resp = _send_recv(s, pkt, 64)
        if resp[:1] == b"\x03":
            return Finding(host, port, "RDP 远程桌面开放", MEDIUM,
                           "暴露在网络上易被暴力破解，确认是否必须对外开放",
                           f"协商响应 {resp[:8].hex()}")
    finally:
        s.close()
    return None


def check_vnc_noauth(host: str, port: int = 5900, timeout: float = 3.0) -> Finding | None:
    s = _tcp(host, port, timeout)
    if s is None:
        return None
    try:
        s.settimeout(2.5)
        banner = s.recv(32)
        if not banner.startswith(b"RFB"):
            return None
        ver = banner[:12].decode("latin-1", "replace")
        s.sendall(b"RFB 003.008\n")
        types = s.recv(64)
        if len(types) >= 2 and types[0] > 0:
            offered = list(types[1:1 + types[0]])
            if 1 in offered:                      # 1 = None 认证
                return Finding(host, port, "VNC 无认证", CRITICAL,
                               "任何人都能直接看到并操作对方桌面",
                               f"{ver} 支持 None 认证")
            return Finding(host, port, "VNC 服务开放", HIGH,
                           f"需要密码，但 VNC 密码易被破解；认证类型={offered}",
                           ver)
    finally:
        s.close()
    return None


def check_rsync(host: str, port: int = 873, timeout: float = 3.0) -> Finding | None:
    s = _tcp(host, port, timeout)
    if s is None:
        return None
    try:
        data = s.recv(1024)
        if data.startswith(b"@RSYNCD"):
            mods = data.decode("latin-1", "replace")
            m = re.findall(r"^(\S+)\s", mods, re.M)
            return Finding(host, port, "rsync 未授权列出模块", HIGH,
                           "可能可以匿名同步整个目录", f"模块: {','.join(m[:5]) or '?'}")
    finally:
        s.close()
    return None


def check_git_leak(host: str, port: int = 80, timeout: float = 4.0,
                   tls: bool = False) -> Finding | None:
    code, body = _http_get(host, port, "/.git/HEAD", timeout, tls)
    if code == 200 and ("ref:" in body or re.match(r"^[0-9a-f]{40}", body.strip())):
        return Finding(host, port, "网站源码泄露 (.git)", HIGH,
                       "可用 git-dumper 等工具完整还原源码，里面常有数据库口令和 flag",
                       body.strip()[:50])
    return None


def check_dirlist(host: str, port: int = 80, timeout: float = 4.0,
                  tls: bool = False) -> Finding | None:
    code, body = _http_get(host, port, "/", timeout, tls)
    if code == 200 and re.search(r"<title>\s*Index of /", body, re.I):
        return Finding(host, port, "目录列表可浏览", LOW,
                       "Web 目录没有索引文件，全部文件对外可列", "Index of /")
    return None


# 检查项注册表：(名称, 端口, 函数, 协议)
CHECKS = [
    ("Redis 未授权", 6379, check_redis, "tcp"),
    ("Memcached 未授权", 11211, check_memcached, "tcp"),
    ("MongoDB 未授权", 27017, check_mongodb, "tcp"),
    ("Elasticsearch 未授权", 9200, check_elasticsearch, "http"),
    ("Docker API 未授权", 2375, check_docker_api, "http"),
    ("ZooKeeper 未授权", 2181, check_zookeeper, "tcp"),
    ("CouchDB 未授权", 5984, check_couchdb, "http"),
    ("Hadoop YARN 未授权", 8088, check_hadoop_yarn, "http"),
    ("Kibana 管理台", 5601, check_kibana, "http"),
    ("RabbitMQ 管理台", 15672, check_rabbitmq, "http"),
    ("etcd 未授权", 2379, check_etcd, "http"),
    ("Kubernetes API", 8080, check_kubernetes, "http"),
    ("FTP 匿名登录", 21, check_ftp_anonymous, "tcp"),
    ("Telnet 开放", 23, check_telnet, "tcp"),
    ("SMB 共享", 445, check_smb, "tcp"),
    ("RDP 远程桌面", 3389, check_rdp, "tcp"),
    ("VNC", 5900, check_vnc_noauth, "tcp"),
    ("rsync 未授权", 873, check_rsync, "tcp"),
    ("网站 .git 泄露", 80, check_git_leak, "http"),
    ("Web 目录列表", 80, check_dirlist, "http"),
]

CHECK_NAMES = [c[0] for c in CHECKS]

# 想快点扫就先只跑这些「命中率高、危害大」的
FAST_CHECKS = ["Redis 未授权", "Memcached 未授权", "Elasticsearch 未授权",
               "Docker API 未授权", "FTP 匿名登录", "网站 .git 泄露",
               "ZooKeeper 未授权", "MongoDB 未授权"]


# --------------------------------------------------------------------------- #
# 扫描编排
# --------------------------------------------------------------------------- #

def scan_host(host: str, checks: list[str] | None = None, timeout: float = 3.0,
              cancel=None) -> list[Finding]:
    """对单台主机跑一组检查。"""
    wanted = set(checks) if checks else set(CHECK_NAMES)
    findings = []
    for name, port, fn, _proto in CHECKS:
        if name not in wanted:
            continue
        if cancel is not None and cancel.is_set():
            break
        try:
            if fn in (check_git_leak, check_dirlist):
                for p, tls in ((80, False), (443, True), (8080, False)):
                    f = fn(host, p, timeout, tls)
                    if f:
                        findings.append(f)
                        break
                continue
            f = fn(host, port, timeout)
            if f:
                findings.append(f)
        except Exception as exc:
            log(f"{host} 检查「{name}」出错：{type(exc).__name__}: {exc}", "debug", "vuln")
    return findings


def scan(hosts: list[str], checks: list[str] | None = None, timeout: float = 3.0,
         workers: int = 16, cancel=None, on_result=None, progress=None) -> list[Finding]:
    """并发扫多台主机。"""
    findings: list[Finding] = []
    total = len(hosts)
    done = 0
    with cf.ThreadPoolExecutor(max_workers=max(1, min(workers, total or 1))) as pool:
        futs = {pool.submit(scan_host, h, checks, timeout, cancel): h for h in hosts}
        for fut in cf.as_completed(futs):
            if cancel is not None and cancel.is_set():
                for f in futs:
                    f.cancel()
                break
            try:
                res = fut.result()
            except Exception:
                res = []
            for f in res:
                findings.append(f)
                if on_result:
                    on_result(f)
            done += 1
            if progress:
                progress(done, total, fut)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.host))
    return findings


def summarize(findings: list[Finding]) -> str:
    if not findings:
        return "没有发现明显问题"
    from collections import Counter
    c = Counter(f.severity for f in findings)
    parts = [f"{k} {v}" for k, v in sorted(c.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))]
    return f"{len(findings)} 个问题（" + "、".join(parts) + "）"


# --------------------------------------------------------------------------- #
# 弱口令检测（默认不自动跑，需要显式调用）
# --------------------------------------------------------------------------- #

DEFAULT_CREDS = [
    ("root", "root"), ("root", "123456"), ("root", "toor"), ("root", ""),
    ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
    ("admin", ""), ("test", "test"), ("guest", "guest"), ("user", "user"),
    ("redis", "redis"), ("mysql", "mysql"), ("postgres", "postgres"),
    ("oracle", "oracle"), ("sa", ""), ("sa", "sa"),
]


def weak_credentials(host: str, service: str, creds=None, timeout: float = 4.0,
                     cancel=None, on_try=None) -> Finding | None:
    """
    弱口令检测（**只在你拥有或已获授权的目标上使用**）。

    目前支持 ssh / ftp / mysql。每试一个口令都会真的登录一次，
    成功即返回。为了不把对方账号锁死，默认字典很短（18 条），
    并且每次尝试之间有间隔。
    """
    creds = creds or DEFAULT_CREDS
    service = service.lower()
    for user, pwd in creds:
        if cancel is not None and cancel.is_set():
            return None
        if on_try:
            on_try(user, pwd)
        ok = False
        try:
            if service == "ftp":
                ok = _try_ftp(host, user, pwd, timeout)
            elif service == "ssh":
                ok = _try_ssh(host, user, pwd, timeout)
            elif service == "mysql":
                ok = _try_mysql(host, user, pwd, timeout)
        except Exception:
            ok = False
        if ok:
            return Finding(host, 0, f"{service.upper()} 弱口令", CRITICAL,
                           f"用 {user}/{pwd or '(空)'} 成功登录",
                           f"{user}:{pwd or '<空>'}")
        time.sleep(0.15)          # 温柔一点，别把对方锁死
    return None


def _try_ftp(host: str, user: str, pwd: str, timeout: float) -> bool:
    s = _tcp(host, 21, timeout)
    if s is None:
        return False
    try:
        s.recv(256)
        r = _send_recv(s, f"USER {user}\r\n".encode(), 256).decode("latin-1", "replace")
        if not r.startswith("331"):
            return r.startswith("230")
        r = _send_recv(s, f"PASS {pwd}\r\n".encode(), 256).decode("latin-1", "replace")
        return r.startswith("230")
    finally:
        s.close()


def _try_ssh(host: str, user: str, pwd: str, timeout: float) -> bool:
    try:
        import paramiko
    except Exception:
        return False
    try:
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.connect(host, port=22, username=user, password=pwd,
                    timeout=timeout, allow_agent=False, look_for_keys=False)
        cli.close()
        return True
    except Exception:
        return False


def _try_mysql(host: str, user: str, pwd: str, timeout: float) -> bool:
    try:
        import pymysql
    except Exception:
        return False
    try:
        conn = pymysql.connect(host=host, user=user, password=pwd,
                               connect_timeout=int(timeout))
        conn.close()
        return True
    except Exception:
        return False
