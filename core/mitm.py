# -*- coding: utf-8 -*-
"""
内建 HTTP/HTTPS 透明拦截代理
============================

给被牵引设备（或本机）当透明代理用，直接把请求内容显示在界面上，支持：

* HTTP / HTTPS（HTTPS 用自签 CA 动态签发证书，目标设备需信任该 CA）
* 请求/响应完整查看，正文自动 gunzip / de-chunk
* **改包重放**：改方法/URL/头/正文后重发
* **断点**：URL 命中规则时挂起请求，人工决定放行 / 改后放行 / 丢弃
* 可选：把流量转交给 Reqable / Fiddler 等本地抓包工具

透明代理的关键点：篡改 DNS 后目标设备会直接连到本机，所以这里
不需要 WinDivert 那套 NAT，直接 accept 就能拿到明文/密文连接。
"""

from __future__ import annotations

import gzip
import io
import os
import re
import socket
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .logging_bus import log
from .netdiag import port_owner

# --------------------------------------------------------------------------- #
# 证书管理
# --------------------------------------------------------------------------- #

CA_CERT_NAME = "ca.crt"
CA_KEY_NAME = "ca.key"


class CertAuthority:
    """自签 CA + 按域名动态签发证书（带缓存）。"""

    def __init__(self, ca_dir: str) -> None:
        self.dir = ca_dir
        self.host_dir = os.path.join(ca_dir, "hosts")
        os.makedirs(self.host_dir, exist_ok=True)
        self.ca_cert_path = os.path.join(ca_dir, CA_CERT_NAME)
        self.ca_key_path = os.path.join(ca_dir, CA_KEY_NAME)
        self._ca_cert = None
        self._ca_key = None
        self._lock = threading.Lock()

    # ---------- CA ----------

    @property
    def available(self) -> bool:
        try:
            import cryptography  # noqa: F401
            return True
        except Exception:
            return False

    def ensure_ca(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        if self._ca_cert is not None:
            return self._ca_cert, self._ca_key
        if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
            with open(self.ca_cert_path, "rb") as fh:
                self._ca_cert = x509.load_pem_x509_certificate(fh.read())
            with open(self.ca_key_path, "rb") as fh:
                self._ca_key = serialization.load_pem_private_key(fh.read(), password=None)
            return self._ca_cert, self._ca_key

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "NetOps Toolbox CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetOps Toolbox"),
        ])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        with open(self.ca_cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(self.ca_key_path, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))
        self._ca_cert, self._ca_key = cert, key
        log(f"已生成根证书：{self.ca_cert_path}（把它装到目标设备的受信任根里才能解 HTTPS）",
            "warn", "mitm")
        return cert, key

    def ca_pem_bytes(self) -> bytes:
        self.ensure_ca()
        with open(self.ca_cert_path, "rb") as fh:
            return fh.read()

    # ---------- 站点证书 ----------

    def cert_for(self, host: str) -> tuple[str, str]:
        """返回 (cert_path, key_path)。"""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)[:120] or "unknown"
        cert_path = os.path.join(self.host_dir, f"{safe}.crt")
        key_path = os.path.join(self.host_dir, f"{safe}.key")
        with self._lock:
            if os.path.exists(cert_path) and os.path.exists(key_path):
                return cert_path, key_path

            ca_cert, ca_key = self.ensure_ca()
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])])
            now = datetime.now(timezone.utc)
            san = [x509.DNSName(host)]
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                import ipaddress
                san = [x509.IPAddress(ipaddress.ip_address(host))]
            cert = (x509.CertificateBuilder()
                    .subject_name(subject).issuer_name(ca_cert.subject)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=1))
                    .not_valid_after(now + timedelta(days=825))
                    .add_extension(x509.SubjectAlternativeName(san), critical=False)
                    .sign(ca_key, hashes.SHA256()))
            with open(cert_path, "wb") as fh:
                fh.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as fh:
                fh.write(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
            return cert_path, key_path


# --------------------------------------------------------------------------- #
# HTTP 解析
# --------------------------------------------------------------------------- #

@dataclass
class Flow:
    fid: int
    ts: str
    client: str
    scheme: str
    host: str
    port: int
    method: str = ""
    path: str = ""
    version: str = "HTTP/1.1"
    req_headers: list = field(default_factory=list)
    req_body: bytes = b""
    status: int = 0
    reason: str = ""
    resp_headers: list = field(default_factory=list)
    resp_body: bytes = b""
    duration_ms: float = 0.0
    error: str = ""
    state: str = "完成"          # 完成 / 挂起中 / 已丢弃 / 出错
    note: str = ""
    raw_request: bytes = b""

    @property
    def url(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        hostpart = self.host if self.port == default_port else f"{self.host}:{self.port}"
        return f"{self.scheme}://{hostpart}{self.path}"

    @property
    def length(self) -> int:
        return len(self.req_body) + len(self.resp_body)

    def req_header(self, name: str, default: str = "") -> str:
        for k, v in self.req_headers:
            if k.lower() == name.lower():
                return v
        return default

    def row(self) -> list:
        return [self.fid, self.ts, self.client, self.method,
                self.status or "-", self.host, self.path[:70],
                f"{len(self.resp_body)}", self.state]


def _read_line(rf: io.BufferedReader) -> bytes:
    line = rf.readline(65536)
    if not line:
        raise ConnectionError("连接关闭")
    return line


def read_head(rf: io.BufferedReader) -> tuple[str, list, list]:
    """读起始行 + 头部，返回 (start_line, [(k,v)], raw_lines)"""
    raw = []
    start = _read_line(rf)
    raw.append(start)
    if start in (b"\r\n", b"\n"):
        start = _read_line(rf)
        raw.append(start)
    start_line = start.decode("latin-1").rstrip("\r\n")
    headers = []
    while True:
        line = _read_line(rf)
        raw.append(line)
        if line in (b"\r\n", b"\n"):
            break
        text = line.decode("latin-1").rstrip("\r\n")
        if ":" in text:
            k, v = text.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return start_line, headers, raw


def _header(headers: list, name: str, default: str = "") -> str:
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return default


def read_body(rf: io.BufferedReader, headers: list, is_request: bool) -> bytes:
    """按 Content-Length / chunked 读正文，返回原始字节（chunked 保留分块格式）。"""
    te = _header(headers, "Transfer-Encoding").lower()
    if "chunked" in te:
        buf = b""
        while True:
            line = _read_line(rf)
            buf += line
            try:
                size = int(line.split(b";")[0].strip(), 16)
            except ValueError:
                break
            if size == 0:
                while True:
                    trailer = _read_line(rf)
                    buf += trailer
                    if trailer in (b"\r\n", b"\n"):
                        break
                break
            chunk = rf.read(size + 2)
            buf += chunk
        return buf
    cl = _header(headers, "Content-Length")
    if cl.isdigit() and int(cl) > 0:
        return rf.read(int(cl))
    return b""


def decode_body(body: bytes, headers: list) -> bytes:
    """去掉 chunked 分块并解压，方便界面上看。"""
    if not body:
        return b""
    if "chunked" in _header(headers, "Transfer-Encoding").lower():
        out, pos = b"", 0
        while pos < len(body):
            end = body.find(b"\r\n", pos)
            if end < 0:
                break
            try:
                size = int(body[pos:end].split(b";")[0].strip(), 16)
            except ValueError:
                break
            if size == 0:
                break
            out += body[end + 2:end + 2 + size]
            pos = end + 2 + size + 2
        body = out
    enc = _header(headers, "Content-Encoding").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            return zlib.decompress(body, -zlib.MAX_WBITS)
        if "br" in enc:
            return body
    except Exception:
        pass
    return body


def build_message(start_line: str, headers: list, body: bytes) -> bytes:
    out = start_line.encode("latin-1") + b"\r\n"
    for k, v in headers:
        out += f"{k}: {v}".encode("latin-1") + b"\r\n"
    out += b"\r\n"
    return out + (body or b"")


# --------------------------------------------------------------------------- #
# 代理主体
# --------------------------------------------------------------------------- #

@dataclass
class BreakRule:
    pattern: str
    enabled: bool = True
    hit: int = 0
    target: str = "both"        # both / request / response


@dataclass
class Pending:
    flow: Flow
    action: str = ""            # release / drop
    edited: dict | None = None
    event: threading.Event = field(default_factory=threading.Event)


class MitmProxy:
    """
    透明 HTTP/HTTPS 代理。

    回调：
        on_flow(flow)        新请求/响应进来（完成后）
        on_pending(flow)     命中断点，挂起了，等 UI 决定
        on_log(text, level)
    """

    def __init__(self, ca: CertAuthority, http_port: int = 80, https_port: int = 443,
                 upstream_proxy: str = "", bind_ip: str = "0.0.0.0",
                 forward_to_tool: bool = False, forward_port: int = 8888,
                 on_flow=None, on_pending=None, max_flows: int = 2000) -> None:
        self.ca = ca
        self.http_port = http_port
        self.https_port = https_port
        self.upstream_proxy = upstream_proxy.strip()
        self.bind_ip = bind_ip
        self.forward_to_tool = forward_to_tool
        self.forward_port = forward_port
        self.on_flow = on_flow
        self.on_pending = on_pending

        self.flows: list[Flow] = []
        self.max_flows = max_flows
        self.break_rules: list[BreakRule] = []
        self.pending: dict[int, Pending] = {}
        self.block_upstream = False        # 「全部挂起」开关
        self._fid = 0
        self._lock = threading.Lock()
        self._servers: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._stop_evt = threading.Event()
        self.running = False
        self.stats = {"total": 0, "http": 0, "https": 0, "blocked": 0,
                      "errors": 0, "connections": 0}
        self.bind_errors: list[str] = []

    # ---------------- 开关 ----------------

    def start(self) -> None:
        if self.running:
            return
        self._stop_evt.clear()
        self.bind_errors = []
        for port, tls in ((self.http_port, False), (self.https_port, True)):
            if port <= 0:
                continue

            # 先如实检查端口能否绑定。
            # 注意：Windows 上给监听套接字设置 SO_REUSEADDR 后，即使端口已被
            # Reqable / Fiddler 之类的进程占用，bind() 仍会「成功」，
            # 但连接会全部由先绑定的进程接收，本程序收不到任何数据包。
            # 因此这里不设置该选项，并在绑定前查出占用者一并提示。
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind((self.bind_ip, port))
            except OSError as exc:
                pid, name = port_owner(port)
                who = f"，已被 PID {pid} 的 {name} 占用" if pid else ""
                msg = (f"监听 {self.bind_ip}:{port} 失败{who}：{exc}。"
                       f"提示：本程序的透明代理应监听 80/443；"
                       f"若要配合 Reqable / Fiddler 使用，请勾选「把流量转交给"
                       f"本地抓包工具」并把其端口填到对应输入框。")
                self.bind_errors.append(msg)
                log(msg, "error", "mitm")
                continue
            finally:
                try:
                    probe.close()
                except Exception:
                    pass

            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.bind((self.bind_ip, port))
                srv.listen(64)
                srv.settimeout(1.0)
            except OSError as exc:
                msg = f"监听 {self.bind_ip}:{port} 失败：{exc}"
                self.bind_errors.append(msg)
                log(msg, "error", "mitm")
                continue
            self._servers.append(srv)
            t = threading.Thread(target=self._accept_loop, args=(srv, tls),
                                 daemon=True, name=f"mitm-{port}")
            t.start()
            self._threads.append(t)
            log(f"透明代理已监听 {self.bind_ip}:{port}（{'HTTPS' if tls else 'HTTP'}）",
                "success", "mitm")
        self.running = bool(self._servers)
        if not self.running and self.bind_errors:
            log("透明代理一个端口都没能监听成功，代理未生效", "error", "mitm")

    def stop(self) -> None:
        self._stop_evt.set()
        for srv in self._servers:
            try:
                srv.close()
            except Exception:
                pass
        self._servers.clear()
        # 放行所有挂起的请求，避免目标设备卡死
        for p in list(self.pending.values()):
            p.action = "release"
            p.event.set()
        self.running = False
        log("透明代理已停止", "info", "mitm")

    # ---------------- 断点 ----------------

    def add_break(self, pattern: str, target: str = "both") -> None:
        self.break_rules.append(BreakRule(pattern=pattern, target=target))
        log(f"已添加断点规则：{pattern}", "info", "mitm")

    def clear_breaks(self) -> None:
        self.break_rules.clear()
        self.block_upstream = False

    def _match_break(self, url: str) -> BreakRule | None:
        for r in self.break_rules:
            if not r.enabled:
                continue
            try:
                if re.search(r.pattern, url, re.I):
                    return r
            except re.error:
                if r.pattern.lower() in url.lower():
                    return r
        return None

    def _wait_pending(self, flow: Flow, kind: str) -> Pending | None:
        """挂起并等 UI 决定；返回 None 表示放行。"""
        if flow.fid in self.pending:
            return None
        rule = self._match_break(flow.url)
        need = self.block_upstream or (rule and rule.target in ("both", kind))
        if not need:
            return None
        if rule:
            rule.hit += 1
        p = Pending(flow=flow)
        flow.state = "挂起中"
        with self._lock:
            self.pending[flow.fid] = p
        self.stats["blocked"] += 1
        if self.on_flow:
            self.on_flow(flow)
        if self.on_pending:
            self.on_pending(flow)
        log(f"断点命中，已挂起：{flow.method} {flow.url}", "warn", "mitm")
        p.event.wait(timeout=300)          # 最多挂 5 分钟，防止把对方网络卡死
        with self._lock:
            self.pending.pop(flow.fid, None)
        return p

    # ---------------- 连接处理 ----------------

    def _accept_loop(self, srv: socket.socket, tls: bool) -> None:
        while not self._stop_evt.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle, args=(conn, addr, tls),
                                 daemon=True, name=f"mitm-conn-{addr[0]}")
            t.start()

    def _handle(self, conn: socket.socket, addr, tls: bool) -> None:
        client = f"{addr[0]}:{addr[1]}"
        self.stats["connections"] += 1
        log(f"代理收到来自 {client} 的连接（{'HTTPS' if tls else 'HTTP'}）",
            "info", "mitm")
        try:
            conn.settimeout(30)
        except Exception:
            pass

        try:
            if tls:
                self._serve_tls(conn, client)
            else:
                self._serve_plain(conn, client)
        except Exception as exc:
            log(f"[{client}] 处理连接出错：{type(exc).__name__}: {exc}", "debug", "mitm")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _serve_tls(self, conn: socket.socket, client: str) -> None:
        # 先偷看 ClientHello 拿 SNI
        conn.settimeout(15)
        peek = conn.recv(4096, socket.MSG_PEEK)
        if not peek:
            return
        host = sni_from_client_hello(peek) or ""
        if not host:
            # 拿不到 SNI，只能断开（不然没法签证书）
            log(f"[{client}] TLS 没有 SNI，跳过", "debug", "mitm")
            return
        cert_path, key_path = self.ca.cert_for(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        try:
            tls_conn = ctx.wrap_socket(conn, server_side=True)
        except Exception as exc:
            log(f"[{client}] TLS 握手失败（目标设备可能没装我们的根证书）：{exc}",
                "debug", "mitm")
            return
        self._serve_http(tls_conn, client, host, 443, "https")

    def _serve_plain(self, conn: socket.socket, client: str) -> None:
        self._serve_http(conn, client, "", 80, "http")

    def _serve_http(self, conn: socket.socket, client: str, host_hint: str,
                    port: int, scheme: str) -> None:
        rf = conn.makefile("rb")
        while not self._stop_evt.is_set():
            try:
                start_line, headers, _raw = read_head(rf)
            except Exception:
                return
            if not start_line:
                return
            parts = start_line.split()
            if len(parts) < 2:
                return
            method, path, version = parts[0], parts[1], (parts[2] if len(parts) > 2 else "HTTP/1.1")

            host = _header(headers, "Host", host_hint)
            host, hport = split_host_port(host, port)
            if scheme == "https":
                host = host_hint or host
                hport = port
            req_body = read_body(rf, headers, True)

            flow = self._new_flow(client, scheme, host, hport, method, path,
                                  version, headers, req_body)

            # 请求断点
            p = self._wait_pending(flow, "request")
            if p is not None:
                if p.action == "drop":
                    flow.state = "已丢弃"
                    self._emit(flow)
                    return
                if p.edited:
                    flow = self._apply_edit(flow, p.edited)

            # 转交给本地抓包工具（Reqable/Fiddler）
            if self.forward_to_tool:
                ok = self._relay_to_tool(conn, rf, flow, headers, req_body)
                if ok:
                    return

            # 正常转发
            t0 = time.time()
            try:
                status, reason, resp_headers, resp_body = self._upstream(
                    flow, headers, req_body)
            except Exception as exc:
                flow.error = f"{type(exc).__name__}: {exc}"
                flow.state = "出错"
                self.stats["errors"] += 1
                self._emit(flow)
                try:
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n"
                                 b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                except Exception:
                    pass
                return
            flow.duration_ms = (time.time() - t0) * 1000
            flow.status, flow.reason = status, reason
            flow.resp_headers, flow.resp_body = resp_headers, resp_body

            # 响应断点
            if self.block_upstream or self._match_break(flow.url):
                pass
            try:
                conn.sendall(build_message(f"HTTP/1.1 {status} {reason}",
                                           resp_headers, resp_body))
            except Exception:
                pass
            flow.state = "完成"
            self._emit(flow)

            if _header(headers, "Connection").lower() == "close" or version == "HTTP/1.0":
                return

    # ---------------- 转发 ----------------

    def _open_upstream(self, host: str, port: int, timeout: float = 15.0):
        if self.upstream_proxy:
            ph, _, pp = self.upstream_proxy.partition(":")
            sock = socket.create_connection((ph, int(pp or 8080)), timeout=timeout)
            return sock, True
        return socket.create_connection((host, port), timeout=timeout), False

    def _upstream(self, flow: Flow, headers: list, body: bytes):
        """把请求发给真实服务器，返回 (status, reason, headers, body)。"""
        sock, via_proxy = self._open_upstream(flow.host, flow.port)
        try:
            sock.settimeout(30)
            hdrs = [(k, v) for k, v in headers
                    if k.lower() not in ("proxy-connection",)]
            if via_proxy:
                target = flow.url
                hdrs = [(k, v) for k, v in hdrs if k.lower() != "host"]
                hdrs.insert(0, ("Host", flow.host))
                line = f"{flow.method} {target} {flow.version}"
            else:
                line = f"{flow.method} {flow.path} {flow.version}"
            req = build_message(line, hdrs, body)
            flow.raw_request = req
            sock.sendall(req)

            rf = sock.makefile("rb")
            start_line, resp_headers, _ = read_head(rf)
            parts = start_line.split(None, 2)
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            reason = parts[2] if len(parts) > 2 else ""
            resp_body = read_body(rf, resp_headers, False)
            return status, reason, resp_headers, resp_body
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _relay_to_tool(self, conn: socket.socket, rf, flow: Flow,
                       headers: list, body: bytes) -> bool:
        """
        把当前连接交给本地抓包工具（Reqable/Fiddler）处理：
        HTTP 改成绝对地址的代理请求；HTTPS 先发 CONNECT 建隧道再裸转发。
        """
        try:
            upstream, _ = self._open_upstream("127.0.0.1", self.forward_port, 5)
        except Exception as exc:
            log(f"连接本地抓包工具 127.0.0.1:{self.forward_port} 失败：{exc}",
                "warn", "mitm")
            return False
        try:
            if flow.scheme == "https":
                connect = (f"CONNECT {flow.host}:{flow.port} HTTP/1.1\r\n"
                           f"Host: {flow.host}:{flow.port}\r\n\r\n")
                upstream.sendall(connect.encode())
                srf = upstream.makefile("rb")
                line, _, _ = read_head(srf)
                if "200" not in line:
                    upstream.close()
                    return False
                # 裸转发后续字节
                self._pipe(conn, upstream)
            else:
                hdrs = [(k, v) for k, v in headers if k.lower() != "proxy-connection"]
                if not any(k.lower() == "host" for k, v in hdrs):
                    hdrs.insert(0, ("Host", flow.host))
                upstream.sendall(build_message(
                    f"{flow.method} {flow.url} {flow.version}", hdrs, body))
                self._pipe(conn, upstream)
            flow.note = f"已转交 127.0.0.1:{self.forward_port}"
            flow.state = "已转交"
            self._emit(flow)
            return True
        except Exception as exc:
            log(f"转交失败：{exc}", "warn", "mitm")
            try:
                upstream.close()
            except Exception:
                pass
            return False

    @staticmethod
    def _pipe(a: socket.socket, b: socket.socket) -> None:
        def one_way(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
        t = threading.Thread(target=one_way, args=(b, a), daemon=True)
        t.start()
        one_way(a, b)
        t.join(timeout=5)

    # ---------------- 流管理 ----------------

    def _new_flow(self, client, scheme, host, port, method, path,
                  version, headers, body) -> Flow:
        with self._lock:
            self._fid += 1
            fid = self._fid
        f = Flow(fid=fid, ts=datetime.now().strftime("%H:%M:%S"), client=client,
                 scheme=scheme, host=host, port=port, method=method, path=path,
                 version=version, req_headers=list(headers), req_body=body)
        self.stats["total"] += 1
        self.stats["https" if scheme == "https" else "http"] += 1
        return f

    def _emit(self, flow: Flow) -> None:
        with self._lock:
            self.flows.append(flow)
            if len(self.flows) > self.max_flows:
                del self.flows[: len(self.flows) - self.max_flows]
        if self.on_flow:
            self.on_flow(flow)

    def _apply_edit(self, flow: Flow, edit: dict) -> Flow:
        if edit.get("method"):
            flow.method = edit["method"]
        if edit.get("url"):
            m = re.match(r"^(https?)://([^/]+)(/.*)?$", edit["url"])
            if m:
                flow.scheme = m.group(1)
                flow.host, flow.port = split_host_port(
                    m.group(2), 443 if flow.scheme == "https" else 80)
                flow.path = m.group(3) or "/"
        if edit.get("headers") is not None:
            flow.req_headers = edit["headers"]
        if edit.get("body") is not None:
            flow.req_body = edit["body"] if isinstance(edit["body"], bytes) \
                else str(edit["body"]).encode()
            flow.req_headers = [(k, v) for k, v in flow.req_headers
                                if k.lower() != "content-length"]
            flow.req_headers.append(("Content-Length", str(len(flow.req_body))))
        flow.note = "已修改后放行"
        return flow

    def resolve_pending(self, fid: int, action: str, edit: dict | None = None) -> bool:
        p = self.pending.get(fid)
        if not p:
            return False
        p.action = action
        p.edited = edit
        p.event.set()
        return True

    def replay(self, flow: Flow, method: str = "", url: str = "",
               headers: list | None = None, body: bytes | None = None) -> Flow:
        """修改后重发，返回新的 flow。"""
        new = Flow(fid=0, ts=datetime.now().strftime("%H:%M:%S"), client="重放",
                   scheme=flow.scheme, host=flow.host, port=flow.port,
                   method=method or flow.method, path=flow.path,
                   version=flow.version,
                   req_headers=list(headers if headers is not None else flow.req_headers),
                   req_body=body if body is not None else flow.req_body)
        if url:
            if url.startswith("http"):
                m = re.match(r"^(https?)://([^/]+)(/.*)?$", url)
                if m:
                    new.scheme = m.group(1)
                    new.host, new.port = split_host_port(
                        m.group(2), 443 if new.scheme == "https" else 80)
                    new.path = m.group(3) or "/"
            else:
                new.path = url                      # 只改了路径
        with self._lock:
            self._fid += 1
            new.fid = self._fid
        t0 = time.time()
        try:
            status, reason, rh, rb = self._upstream(new, new.req_headers, new.req_body)
            new.status, new.reason = status, reason
            new.resp_headers, new.resp_body = rh, rb
            new.state = "重放完成"
        except Exception as exc:
            new.error = f"{type(exc).__name__}: {exc}"
            new.state = "重放出错"
        new.duration_ms = (time.time() - t0) * 1000
        self._emit(new)
        return new

    def clear(self) -> None:
        with self._lock:
            self.flows.clear()
        self.stats = {"total": 0, "http": 0, "https": 0, "blocked": 0, "errors": 0}


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #

def split_host_port(value: str, default_port: int) -> tuple[str, int]:
    value = (value or "").strip()
    if value.startswith("["):                      # IPv6 字面量
        end = value.find("]")
        host = value[1:end]
        rest = value[end + 1:]
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default_port
        return host, port
    if ":" in value:
        host, _, p = value.rpartition(":")
        if p.isdigit():
            return host, int(p)
    return value or "", default_port


def sni_from_client_hello(data: bytes) -> str:
    """从 TLS ClientHello 里抠出 SNI（不依赖 ssl 模块）。"""
    try:
        if len(data) < 50 or data[0] != 0x16:
            return ""
        pos = 5 + 4                                        # record -> handshake
        if data[pos] != 0x01:
            return ""
        pos += 4 + 2 + 32                                  # type+len+version+random
        sid_len = data[pos]
        pos += 1 + sid_len
        cs_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cs_len
        cm_len = data[pos]
        pos += 1 + cm_len
        ext_total = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(len(data), pos + ext_total)
        while pos + 4 <= end:
            etype = int.from_bytes(data[pos:pos + 2], "big")
            elen = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if etype == 0x00:                              # server_name
                p = pos + 2
                ntype = data[p]
                nlen = int.from_bytes(data[p + 1:p + 3], "big")
                if ntype == 0:
                    return data[p + 3:p + 3 + nlen].decode("ascii", "ignore")
            pos += elen
    except Exception:
        pass
    return ""
