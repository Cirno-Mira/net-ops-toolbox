# -*- coding: utf-8 -*-
"""
假服务（Fake DNS / Fake HTTP）
==============================

「一键起」两个本地服务，配合 ARP 牵引 / DNS 引流做演示与验证：

* FakeDnsServer  —— 真正能用的 UDP DNS 服务器。配几条 A 记录，
  命中的按配置回答；没命中的可以「转发上游」或者「回 NXDOMAIN」。
  对 AAAA 查询一律回空答案（NOERROR 无记录），逼对方走 IPv4，
  和我们自己的 DNS 引流思路一致。
* FakeHttpServer —— 可配置的 HTTP 服务，两种模式：
  固定内容（自定义状态码 / Content-Type）或把某个目录当根目录提供文件。

典型用法：把目标设备的 DNS 指到本机，或用 hosts 把域名指到本机，
然后它访问域名时就会看到我们准备好的页面——用来验证「流量到底有没有被牵引过来」。

本模块不依赖 Qt，回调都在服务工作线程里执行，界面层自己用信号投递回主线程。
"""

from __future__ import annotations

import fnmatch
import os
import socket
import socketserver
import threading
from collections import deque
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from .hostinfo import list_ifaces
from .logging_bus import log

# 没命中时的三种处理方式（界面下拉框的值就是这三个）
MISS_FORWARD = "forward"        # 转发到上游 DNS
MISS_NXDOMAIN = "nxdomain"      # 直接回 NXDOMAIN
MISS_SILENT = "silent"          # 不响应（让客户端自己超时）

MISS_LABELS = {
    MISS_FORWARD: "转发到上游 DNS",
    MISS_NXDOMAIN: "返回 NXDOMAIN",
    MISS_SILENT: "不响应（丢包）",
}

HTTP_MODES = ("fixed", "dir")   # 固定内容 / 目录

DEFAULT_UPSTREAM = "223.5.5.5"
DEFAULT_INDEX = "<h1>NetOpsToolbox fake http</h1>\n<p>这里是我们自己起的假 HTTP 服务。</p>\n"


def _log_debug(text: str) -> None:
    """核心库可能被单独调用（没有界面订阅日志），这里兜住异常。"""
    try:
        log(text, "debug", "fakeserv")
    except Exception:
        pass


def local_ips() -> list[str]:
    """
    本机可用于访问的 IPv4 列表（第一个通常是主用网卡）。

    复用 core.hostinfo.list_ifaces()，额外补上回环地址，
    方便界面直接展示「目标设备该把 DNS / hosts 指向哪个 IP」。
    """
    ips: list[str] = []
    try:
        ifaces = list_ifaces()
    except Exception as exc:
        _log_debug(f"枚举网卡失败：{type(exc).__name__}: {exc}")
        ifaces = []
    for i in ifaces:
        if i.ip and i.ip not in ips:
            ips.append(i.ip)
    if "127.0.0.1" not in ips:
        ips.append("127.0.0.1")
    return ips


def _norm_name(name: str) -> str:
    return (name or "").strip().rstrip(".").lower()


def parse_upstream(value: str) -> tuple[str, int]:
    """
    解析上游 DNS 写法，支持 `8.8.8.8`、`223.5.5.5:5353`、`dns.alidns.com`。
    只写 IP/域名时按标准 53 端口走。
    """
    text = (value or "").strip()
    if not text:
        return DEFAULT_UPSTREAM, 53
    host, _, port = text.rpartition(":")
    if host and port.isdigit():
        return host, int(port)
    return text, 53


# --------------------------------------------------------------------------- #
# 假 DNS 服务
# --------------------------------------------------------------------------- #

class _DnsUdpHandler(socketserver.BaseRequestHandler):
    """UDP 处理器：把报文和「回给谁」一起交给 FakeDnsServer 处理。"""

    def handle(self) -> None:
        data, sock = self.request
        me = self.server.srv
        # UDPServer 是单线程跑的，直接把当前客户端地址挂在自己身上即可；
        # 回复时用它 sendto()，不要依赖 req 里的端口。
        me._client = self.client_address
        try:
            me.handle_query(data, self.client_address, sock)
        except Exception as exc:                      # 单个包出错不能拖垮循环
            me._on_error(exc)
        finally:
            me._client = None


class _DnsUdpServer(socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


class FakeDnsServer:
    """
    本地假 DNS 服务器（真 UDP，端口默认 53）。

    记录配置用 set_records()：域名 -> IP，支持 *.example.com 这种通配。
    命中按配置回答；没命中按 miss_policy 处理（转发 / NXDOMAIN / 不响应）。

    回调：
        on_query(name, qtype, client_ip, answered)   answered 是简短结果说明
    """

    def __init__(self, bind_ip: str = "0.0.0.0", port: int = 53,
                 upstream: str = DEFAULT_UPSTREAM, miss_policy: str = MISS_FORWARD,
                 ttl: int = 60, on_query=None, upstream_timeout: float = 3.0) -> None:
        self.bind_ip = bind_ip or "0.0.0.0"
        self.port = int(port)
        self.upstream = (upstream or DEFAULT_UPSTREAM).strip()
        self.miss_policy = miss_policy if miss_policy in MISS_LABELS else MISS_FORWARD
        self.ttl = int(ttl)
        self.on_query = on_query
        self.upstream_timeout = float(upstream_timeout)

        self.records: dict[str, list[str]] = {}        # 域名（小写）-> [IP, ...]
        self.bind_errors: list[str] = []
        self.stats = {"queries": 0, "answered": 0, "nxdomain": 0,
                      "forwarded": 0, "silent": 0, "errors": 0}
        self.recent: deque = deque(maxlen=500)        # 给界面看的最近查询

        self._srv: _DnsUdpServer | None = None
        self._thread: threading.Thread | None = None
        self._client = None                           # 当前正在处理的客户端地址
        self.running = False

    # ---------------- 配置 ----------------

    def set_records(self, records) -> None:
        """
        设置记录表。接受：
            {"a.example.com": "192.168.1.10"}            简单映射
            [("a.example.com", "192.168.1.10"), ...]     列表
            [{"name": ..., "ip": ...}, ...]              界面表格那种
        同一个域名出现多次就会写进同一条应答（多个 A 记录）。
        """
        items: list = []
        if isinstance(records, dict):
            items = list(records.items())
        else:
            for r in records or []:
                if isinstance(r, dict):
                    items.append((r.get("name", ""), r.get("ip", "")))
                elif isinstance(r, (tuple, list)) and len(r) >= 2:
                    items.append((r[0], r[1]))
        table: dict[str, list[str]] = {}
        for name, ip in items:
            key = _norm_name(str(name))
            ip = str(ip).strip()
            if not key or not ip:
                continue
            table.setdefault(key, [])
            if ip not in table[key]:
                table[key].append(ip)
        self.records = table

    def set_miss_policy(self, policy: str) -> None:
        if policy in MISS_LABELS:
            self.miss_policy = policy

    def matched(self, name: str) -> list[str]:
        """查一条名字对应的 IP 列表（没有就返回空）。"""
        key = _norm_name(name)
        if not key:
            return []
        if key in self.records:
            return list(self.records[key])
        # 通配：*.example.com 也能匹配 a.b.example.com
        for pat, ips in self.records.items():
            if ("*" in pat or "?" in pat) and fnmatch.fnmatch(key, pat):
                return list(ips)
        return []

    # ---------------- 启停 ----------------

    def start(self) -> None:
        if self.running:
            return
        self.bind_errors = []
        # Windows 上 UDP 的 SO_REUSEADDR 允许两个进程绑同一端口（只有一个能收到包），
        # 光靠 bind() 判断不出冲突。所以先用一个「不设 SO_REUSEADDR」的探测 socket
        # 试绑一次：被占用就直接报错，别让用户以为服务起来了却一个包都收不到。
        if int(self.port) > 0:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.bind((self.bind_ip, self.port))
            except OSError as exc:
                msg = f"假 DNS 监听 {self.bind_ip}:{self.port} 失败：{exc}"
                if int(self.port) < 1024:
                    msg += "（53 这类低位端口需要管理员权限，或换成 5353 之类的端口）"
                self.bind_errors.append(msg)
                log(msg, "error", "fakeserv")
                self.running = False
                return
            finally:
                try:
                    probe.close()
                except Exception:
                    pass
        try:
            self._srv = _DnsUdpServer((self.bind_ip, self.port), _DnsUdpHandler)
            self._srv.srv = self
        except OSError as exc:
            msg = f"假 DNS 监听 {self.bind_ip}:{self.port} 失败：{exc}"
            if int(self.port) < 1024:
                msg += "（53 这类低位端口需要管理员权限，或换成 5353 之类的端口）"
            self.bind_errors.append(msg)
            log(msg, "error", "fakeserv")
            self._srv = None
            self.running = False
            return
        self.port = self._srv.server_address[1]
        self.running = True
        self._thread = threading.Thread(target=self._srv.serve_forever, kwargs={"poll_interval": 0.2},
                                        daemon=True, name="fakedns")
        self._thread.start()
        log(f"假 DNS 已启动：{self.bind_ip}:{self.port}，"
            f"{len(self.records)} 条记录，未命中策略「{MISS_LABELS[self.miss_policy]}」",
            "success", "fakeserv")

    def stop(self) -> None:
        self.running = False
        srv, self._srv = self._srv, None
        if srv is not None:
            try:
                srv.shutdown()                        # 让 serve_forever 立刻退出
            except Exception:
                pass
            try:
                srv.server_close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        log("假 DNS 已停止", "info", "fakeserv")

    def clear_stats(self) -> None:
        for k in self.stats:
            self.stats[k] = 0
        self.recent.clear()

    # ---------------- 处理 ----------------

    def _on_error(self, exc: Exception) -> None:
        self.stats["errors"] += 1
        _log_debug(f"假 DNS 处理查询出错：{type(exc).__name__}: {exc}")

    def handle_query(self, data: bytes, addr, sock) -> None:
        """收到一个 UDP 报文：解析 -> 查表 / 转发 -> 回包。"""
        import dns.message
        import dns.rdatatype

        client_ip = addr[0] if addr else ""
        try:
            req = dns.message.from_wire(data)
        except Exception as exc:
            self.stats["errors"] += 1
            _log_debug(f"假 DNS 收到无法解析的报文（{len(data)} 字节）：{exc}")
            return

        self.stats["queries"] += 1
        q = req.question[0] if req.question else None
        if q is None:
            self._reply_empty(req, sock, client_ip, "-", "空查询")
            return
        name = str(q.name)
        qtype = int(q.rdtype)
        type_name = dns.rdatatype.to_text(qtype)

        # 只对 A / AAAA 做手脚，其它类型按未命中策略走
        ips = self.matched(name) if qtype in (1, 28) else []
        if ips and qtype == 1:
            self._reply_a(req, sock, name, ips, client_ip, type_name)
            return
        if qtype == 28 and self.records:
            # 有配置记录说明我们在扮演「内网 DNS」：AAAA 一律回空答案（NOERROR），
            # 让目标乖乖用 IPv4，别绕开我们的假服务器。
            self._reply_empty(req, sock, client_ip, name, "AAAA 空答案")
            return
        self._handle_miss(req, sock, name, qtype, type_name, client_ip)

    def _handle_miss(self, req, sock, name: str, qtype: int,
                     type_name: str, client_ip: str) -> None:
        policy = self.miss_policy
        if policy == MISS_SILENT:
            self.stats["silent"] += 1
            self._emit(name, type_name, client_ip, "不响应")
            return
        if policy == MISS_NXDOMAIN:
            import dns.rcode
            resp = self._response(req)
            resp.set_rcode(dns.rcode.NXDOMAIN)
            self._send(sock, resp, client_ip)
            self.stats["nxdomain"] += 1
            self._emit(name, type_name, client_ip, "NXDOMAIN（未命中）")
            return

        # 转发上游：失败了就退化成 SERVFAIL，别让客户端干等
        import dns.message
        import dns.query
        import dns.rcode
        up_host, up_port = parse_upstream(self.upstream)
        try:
            up = dns.message.make_query(name, qtype, use_edns=True)
            up.id = req.id
            answer = dns.query.udp(up, up_host, port=up_port,
                                   timeout=self.upstream_timeout)
            self._send(sock, answer, client_ip)
            self.stats["forwarded"] += 1
            n = len(answer.answer)
            self._emit(name, type_name, client_ip,
                       f"转发 {self.upstream}（{n} 条应答）")
        except Exception as exc:
            resp = self._response(req)
            resp.set_rcode(dns.rcode.SERVFAIL)
            self._send(sock, resp, client_ip)
            self.stats["errors"] += 1
            _log_debug(f"转发上游 {self.upstream} 失败：{type(exc).__name__}: {exc}")
            self._emit(name, type_name, client_ip, f"转发失败：{type(exc).__name__}")

    # ---------------- 应答构造 ----------------

    def _response(self, req):
        import dns.flags
        import dns.message
        resp = dns.message.make_response(req)
        resp.flags |= dns.flags.AA | dns.flags.RA
        return resp

    def _reply_a(self, req, sock, name: str, ips: list[str],
                 client_ip: str, type_name: str) -> None:
        import dns.rrset
        resp = self._response(req)
        rr = dns.rrset.from_text_list(name, self.ttl, "IN", "A", ips)
        resp.answer.append(rr)
        self._send(sock, resp, client_ip)
        self.stats["answered"] += 1
        self._emit(name, type_name, client_ip, "、".join(ips))

    def _reply_empty(self, req, sock, client_ip: str,
                     name: str, why: str) -> None:
        resp = self._response(req)
        self._send(sock, resp, client_ip)
        self.stats["answered"] += 1
        self._emit(name, "-", client_ip, why)

    def _send(self, sock, resp, client_ip: str) -> None:
        """UDP 回包（sendto 到当前正在处理的客户端）。"""
        if self._client is None:
            self.stats["errors"] += 1
            return
        try:
            sock.sendto(resp.to_wire(), self._client)
        except Exception as exc:
            self.stats["errors"] += 1
            _log_debug(f"假 DNS 回包失败（{client_ip}）：{type(exc).__name__}: {exc}")

    def _emit(self, name: str, type_name: str, client_ip: str, result: str) -> None:
        row = (datetime.now().strftime("%H:%M:%S"), client_ip, name, type_name, result)
        self.recent.append(row)
        if self.on_query:
            try:
                self.on_query(name, type_name, client_ip, result)
            except Exception as exc:                 # 界面的问题不能影响服务
                _log_debug(f"on_query 回调出错：{type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------- #
# 假 HTTP 服务
# --------------------------------------------------------------------------- #

class _FakeHttpHandler(SimpleHTTPRequestHandler):
    """
    固定内容 / 目录 两种模式共用一个处理类，配置从 self.server.cfg 取。

    * 把默认的 stderr 访问日志压掉（只往日志总线写 debug），免得刷屏
    * 每个请求都通过 on_request(dict) 回调给界面
    """

    server_version = "FakeHttp/1.0"
    protocol_version = "HTTP/1.1"

    # ---------- 日志 ----------

    def log_message(self, fmt, *args):
        _log_debug(f"[假 HTTP] {self.address_string()} {fmt % args}")

    def log_error(self, fmt, *args):
        _log_debug(f"[假 HTTP] {fmt % args}")

    # ---------- 编码 ----------

    def guess_type(self, path):
        """
        给文本类文件补上 charset=utf-8。

        不然 SimpleHTTPRequestHandler 只回 `text/plain`，浏览器/requests 会按
        latin-1 猜，中文文件名和中文内容全是乱码。
        """
        ctype = SimpleHTTPRequestHandler.guess_type(self, path)
        if isinstance(ctype, str) and ctype.startswith("text/") and "charset" not in ctype:
            return ctype + "; charset=utf-8"
        return ctype

    # ---------- 回调 ----------

    def _notify(self) -> None:
        # 处理线程是 ThreadingHTTPServer 里那个内层 server 起的，它的 self.server
        # 是内层对象；真正的服务对象挂在 owner 上（否则统计永远记不进去）。
        srv = getattr(self.server, "owner", self.server)
        cfg = self.server.cfg
        info = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "method": self.command or "",
            "path": self.path or "/",
            "client": self.client_address[0] if self.client_address else "",
            "client_port": self.client_address[1] if self.client_address else 0,
            "ua": self.headers.get("User-Agent", "") if self.headers else "",
            "host": self.headers.get("Host", "") if self.headers else "",
        }
        # 统计与最近请求（界面靠回调刷新，这里供后台查询 / 导出用）
        try:
            srv.stats["requests"] += 1
            srv.requests.append(dict(info))
        except Exception:
            pass
        cb = cfg.get("on_request")
        if cb:
            try:
                cb(dict(info))
            except Exception as exc:                 # 界面的问题不能影响服务
                _log_debug(f"on_request 回调出错：{type(exc).__name__}: {exc}")

    # ---------- 响应 ----------

    def _send_payload(self, body: bytes, ctype: str, status: int) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", ctype or "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def do_GET(self):
        self._notify()
        cfg = self.server.cfg
        if cfg.get("mode") == "dir":
            return SimpleHTTPRequestHandler.do_GET(self)   # 目录模式：交给标准实现
        body = str(cfg.get("content", "")).encode("utf-8")
        self._send_payload(body, str(cfg.get("content_type", "")),
                           int(cfg.get("status", 200)))

    def do_HEAD(self):
        self._notify()
        cfg = self.server.cfg
        if cfg.get("mode") == "dir":
            return SimpleHTTPRequestHandler.do_HEAD(self)
        self._send_payload(b"", str(cfg.get("content_type", "")),
                           int(cfg.get("status", 200)))

    def do_POST(self):
        """POST 也回同一套内容（先把手上的正文读掉，免得客户端写失败）。"""
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 0:
                self.rfile.read(min(n, 1 << 20))
        except Exception:
            pass
        self.do_GET()

    # ---------- 目录列表：中文表头，保持和界面一致 ----------

    def list_directory(self, path):
        try:
            entries = sorted(os.listdir(path))
        except OSError:
            self.send_error(404, "目录不存在")
            return None
        rows = "\n".join(
            f'<li><a href="{name}">{name}</a></li>' for name in entries)
        html = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                f"<title>目录：{self.path}</title></head><body>"
                f"<h2>目录：{self.path}</h2><ul>{rows}</ul></body></html>")
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        return __import__("io").BytesIO(data)


class _FakeHttpServer(ThreadingHTTPServer):
    """
    ThreadingHTTPServer 的包装类。

    为什么不直接用 ThreadingHTTPServer：它每个请求都是新建一个内层 server 对象来
    跑处理器的，处理器里的 self.server 指向的是那个临时对象，不是我们持有的这个。
    所以这里在 server_bind 时把「真正的服务对象」挂成 owner，
    处理器统一从 self.server.owner 取统计 / 回调。
    """

    daemon_threads = True
    allow_reuse_address = True
    cfg: dict = {}
    owner = None


class FakeHttpServer:
    """
    本地假 HTTP 服务（ThreadingHTTPServer）。

    mode="fixed"：任何路径都返回 content（状态码 / Content-Type 可配）
    mode="dir"  ：把 directory 当根目录提供文件（自带的目录列表）

    回调：on_request(dict)，字段：时间 / 方法 / 路径 / 来源 IP / User-Agent / Host
    """

    def __init__(self, bind_ip: str = "0.0.0.0", port: int = 80,
                 mode: str = "fixed", content: str = DEFAULT_INDEX,
                 directory: str = "", status: int = 200,
                 content_type: str = "text/html; charset=utf-8",
                 on_request=None) -> None:
        self.bind_ip = bind_ip or "0.0.0.0"
        self.port = int(port)
        self.mode = mode if mode in HTTP_MODES else "fixed"
        self.content = content if content is not None else DEFAULT_INDEX
        self.directory = directory or ""
        self.status = int(status)
        self.content_type = content_type or "text/html; charset=utf-8"
        self.on_request = on_request

        self.requests: deque = deque(maxlen=500)      # 给界面看的最近请求
        self.bind_errors: list[str] = []
        self.stats = {"requests": 0, "errors": 0}
        self.started_at = ""

        self._srv: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.running = False

    # ---------------- 启停 ----------------

    def start(self) -> None:
        if self.running:
            return
        self.bind_errors = []
        cfg = {
            "mode": self.mode,
            "content": self.content,
            "content_type": self.content_type,
            "status": self.status,
            "on_request": self.on_request,
        }

        def handler(*args, **kw):
            return _FakeHttpHandler(*args, directory=self.directory or None, **kw)

        # 和 DNS 一样先探一下端口：ThreadingHTTPServer 默认会设 SO_REUSEADDR，
        # 在 Windows 上端口被别的进程占着时 bind() 也可能「成功」，但包全被对方接走。
        if int(self.port) > 0:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind((self.bind_ip, self.port))
            except OSError as exc:
                msg = f"假 HTTP 监听 {self.bind_ip}:{self.port} 失败：{exc}"
                if int(self.port) < 1024:
                    msg += "（80 这类低位端口需要管理员权限，或换成 8080）"
                self.bind_errors.append(msg)
                log(msg, "error", "fakeserv")
                self.running = False
                return
            finally:
                try:
                    probe.close()
                except Exception:
                    pass

        try:
            srv = _FakeHttpServer((self.bind_ip, self.port), handler)
            srv.cfg = cfg
            srv.owner = self
            self._srv = srv
        except OSError as exc:
            msg = f"假 HTTP 监听 {self.bind_ip}:{self.port} 失败：{exc}"
            if int(self.port) < 1024:
                msg += "（80 这类低位端口需要管理员权限，或换成 8080）"
            self.bind_errors.append(msg)
            log(msg, "error", "fakeserv")
            self._srv = None
            self.running = False
            return

        self.port = int(self._srv.server_address[1])
        self.running = True
        self.started_at = datetime.now().strftime("%H:%M:%S")
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        kwargs={"poll_interval": 0.2},
                                        daemon=True, name="fakehttp")
        self._thread.start()
        where = ("固定内容" if self.mode == "fixed"
                 else f"目录 {self.directory or '(未选择)'}")
        log(f"假 HTTP 已启动：http://{self.bind_ip}:{self.port}/（{where}，"
            f"状态码 {self.status}）", "success", "fakeserv")

    def stop(self) -> None:
        self.running = False
        srv, self._srv = self._srv, None
        if srv is not None:
            try:
                srv.shutdown()
            except Exception:
                pass
            try:
                srv.server_close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        log("假 HTTP 已停止", "info", "fakeserv")

    def clear_stats(self) -> None:
        for k in self.stats:
            self.stats[k] = 0
        self.requests.clear()
