# -*- coding: utf-8 -*-
"""
穿透隧道 / Shell 会话管理
=========================

三件事，都是标准渗透测试里最常用的连接管理：

1. **端口转发**：本地监听一个端口，收到的连接转发到目标 IP:端口（TCP / UDP）
   —— 相当于 lcx / netsh portproxy 的 GUI 版
2. **反向监听**：本地监听一个端口，等目标机器上的 shell 连回来，
   然后给你一个交互式控制台
3. **正向连接**：直接连到目标已经开好的 shell 端口

**这里只做连接管理和收发字节，不生成任何 payload、不做免杀、不做持久化。**
只能用于你本人拥有或已获得书面授权的目标。
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field

from .logging_bus import log


# --------------------------------------------------------------------------- #
# 会话（一条已经建立的双向连接）
# --------------------------------------------------------------------------- #

@dataclass
class Session:
    sid: int
    kind: str                    # reverse / connect
    peer: str
    sock: socket.socket
    opened_at: str = field(default_factory=lambda: time.strftime("%H:%M:%S"))
    bytes_in: int = 0
    bytes_out: int = 0
    closed: bool = False
    name: str = ""

    def start_reader(self, on_data, on_close) -> None:
        def loop():
            try:
                while not self.closed:
                    try:
                        self.sock.settimeout(1.0)
                        data = self.sock.recv(8192)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not data:
                        break
                    self.bytes_in += len(data)
                    if on_data:
                        on_data(self.sid, data)
            finally:
                self.closed = True
                try:
                    self.sock.close()
                except Exception:
                    pass
                if on_close:
                    on_close(self.sid)

        threading.Thread(target=loop, daemon=True,
                         name=f"session-{self.sid}").start()

    def send(self, data: bytes) -> bool:
        if self.closed:
            return False
        try:
            self.sock.sendall(data)
            self.bytes_out += len(data)
            return True
        except OSError:
            self.closed = True
            return False

    def close(self) -> None:
        self.closed = True
        try:
            self.sock.close()
        except Exception:
            pass

    @property
    def alive(self) -> bool:
        return not self.closed

    def row(self) -> list:
        return [self.sid, self.kind, self.peer, self.opened_at,
                f"{self.bytes_in}", f"{self.bytes_out}",
                "已断开" if self.closed else "在线"]


# --------------------------------------------------------------------------- #
# 端口转发
# --------------------------------------------------------------------------- #

@dataclass
class ForwardStat:
    fid: int
    proto: str
    listen: str
    target: str
    running: bool = False
    conns: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    last_error: str = ""

    def row(self) -> list:
        return [self.fid, self.proto, self.listen, self.target,
                "运行中" if self.running else "已停止",
                self.conns, f"{self.bytes_in}/{self.bytes_out}", self.last_error[:40]]


class TcpForwarder(threading.Thread):
    """本地监听 -> 目标端口 的 TCP 转发。"""

    def __init__(self, fid: int, listen_ip: str, listen_port: int,
                 target_host: str, target_port: int, on_stat=None) -> None:
        super().__init__(daemon=True, name=f"fwd-{fid}")
        self.stat = ForwardStat(fid, "TCP", f"{listen_ip}:{listen_port}",
                                f"{target_host}:{target_port}")
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.on_stat = on_stat
        self._stop_evt = threading.Event()
        self._srv: socket.socket | None = None

    def run(self) -> None:
        try:
            self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._srv.bind((self.listen_ip, self.listen_port))
            self._srv.listen(32)
            self._srv.settimeout(1.0)
        except OSError as exc:
            self.stat.last_error = f"监听失败：{exc}"
            self.stat.running = False
            log(f"端口转发 {self.stat.listen} 启动失败：{exc}", "error", "tunnel")
            if self.on_stat:
                self.on_stat(self.stat)
            return

        self.stat.running = True
        log(f"端口转发已启动：{self.stat.listen}  →  {self.stat.target}",
            "success", "tunnel")
        if self.on_stat:
            self.on_stat(self.stat)

        while not self._stop_evt.is_set():
            try:
                conn, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.stat.conns += 1
            threading.Thread(target=self._pipe, args=(conn, addr),
                             daemon=True).start()
            if self.on_stat:
                self.on_stat(self.stat)

        self.stat.running = False
        try:
            if self._srv:
                self._srv.close()
        except Exception:
            pass
        log(f"端口转发已停止：{self.stat.listen}", "info", "tunnel")
        if self.on_stat:
            self.on_stat(self.stat)

    def _pipe(self, conn: socket.socket, addr) -> None:
        try:
            upstream = socket.create_connection((self.target_host, self.target_port),
                                                timeout=6)
        except OSError as exc:
            self.stat.last_error = f"连目标失败：{exc}"
            log(f"{self.stat.listen} 连不上目标 {self.stat.target}：{exc}",
                "warn", "tunnel")
            try:
                conn.close()
            except Exception:
                pass
            return

        def pump(src, dst, attr):
            try:
                while not self._stop_evt.is_set():
                    src.settimeout(1.0)
                    try:
                        data = src.recv(16384)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not data:
                        break
                    setattr(self.stat, attr, getattr(self.stat, attr) + len(data))
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass

        threading.Thread(target=pump, args=(conn, upstream, "bytes_in"),
                         daemon=True).start()
        pump(upstream, conn, "bytes_out")
        for s in (conn, upstream):
            try:
                s.close()
            except Exception:
                pass

    def stop(self) -> None:
        self._stop_evt.set()
        try:
            if self._srv:
                self._srv.close()
        except Exception:
            pass
        if self.is_alive():
            self.join(timeout=3)


class UdpForwarder(threading.Thread):
    """本地 UDP 监听 -> 目标 UDP 端口（适合 DNS / SNMP 这类）。"""

    def __init__(self, fid: int, listen_ip: str, listen_port: int,
                 target_host: str, target_port: int, on_stat=None) -> None:
        super().__init__(daemon=True, name=f"udpfwd-{fid}")
        self.stat = ForwardStat(fid, "UDP", f"{listen_ip}:{listen_port}",
                                f"{target_host}:{target_port}")
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.on_stat = on_stat
        self._stop_evt = threading.Event()

    def run(self) -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.bind((self.listen_ip, self.listen_port))
            srv.settimeout(1.0)
        except OSError as exc:
            self.stat.last_error = f"监听失败：{exc}"
            log(f"UDP 转发启动失败：{exc}", "error", "tunnel")
            if self.on_stat:
                self.on_stat(self.stat)
            return

        self.stat.running = True
        log(f"UDP 转发已启动：{self.stat.listen} → {self.stat.target}",
            "success", "tunnel")
        if self.on_stat:
            self.on_stat(self.stat)

        clients: dict = {}
        try:
            while not self._stop_evt.is_set():
                try:
                    data, addr = srv.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                self.stat.bytes_in += len(data)
                up = clients.get(addr)
                if up is None:
                    try:
                        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        up.settimeout(1.0)
                        up.connect((self.target_host, self.target_port))
                        clients[addr] = up
                        self.stat.conns += 1
                    except OSError as exc:
                        self.stat.last_error = str(exc)
                        continue
                try:
                    up.send(data)
                except OSError:
                    continue
                # 收目标回包
                try:
                    back = up.recv(65535)
                    self.stat.bytes_out += len(back)
                    srv.sendto(back, addr)
                except socket.timeout:
                    pass
                except OSError:
                    pass
        finally:
            for s in clients.values():
                try:
                    s.close()
                except Exception:
                    pass
            try:
                srv.close()
            except Exception:
                pass
            self.stat.running = False
            if self.on_stat:
                self.on_stat(self.stat)
            log(f"UDP 转发已停止：{self.stat.listen}", "info", "tunnel")

    def stop(self) -> None:
        self._stop_evt.set()
        if self.is_alive():
            self.join(timeout=3)


# --------------------------------------------------------------------------- #
# Shell 监听 / 连接
# --------------------------------------------------------------------------- #

class ShellServer(threading.Thread):
    """反向 shell 监听器：等目标连回来，每来一个就开一个会话。"""

    def __init__(self, listen_ip: str, listen_port: int,
                 on_session=None, on_data=None, on_close=None,
                 on_stat=None) -> None:
        super().__init__(daemon=True, name="shell-listen")
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.on_session = on_session
        self.on_data = on_data
        self.on_close = on_close
        self.on_stat = on_stat
        self.sessions: dict[int, Session] = {}
        self.running = False
        self.last_error = ""
        self.conn_count = 0
        self._stop_evt = threading.Event()
        self._srv: socket.socket | None = None
        self._sid = 0

    def run(self) -> None:
        try:
            self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._srv.bind((self.listen_ip, self.listen_port))
            self._srv.listen(16)
            self._srv.settimeout(1.0)
        except OSError as exc:
            self.last_error = f"监听失败：{exc}"
            log(f"反向监听 {self.listen_ip}:{self.listen_port} 失败：{exc}",
                "error", "tunnel")
            if self.on_stat:
                self.on_stat(self)
            return

        self.running = True
        log(f"正在监听 {self.listen_ip}:{self.listen_port}，等待目标连回来…",
            "success", "tunnel")
        if self.on_stat:
            self.on_stat(self)

        while not self._stop_evt.is_set():
            try:
                conn, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._sid += 1
            self.conn_count += 1
            sess = Session(sid=self._sid, kind="reverse",
                           peer=f"{addr[0]}:{addr[1]}", sock=conn)
            sess.name = f"反弹 #{self._sid}"
            self.sessions[sess.sid] = sess
            log(f"收到反弹连接：{sess.peer}", "warn", "tunnel")
            sess.start_reader(self.on_data, self._on_close)
            if self.on_session:
                self.on_session(sess)

        self.running = False
        try:
            if self._srv:
                self._srv.close()
        except Exception:
            pass
        log("反向监听已停止", "info", "tunnel")
        if self.on_stat:
            self.on_stat(self)

    def _on_close(self, sid: int):
        if self.on_close:
            self.on_close(sid)

    def stop(self) -> None:
        self._stop_evt.set()
        try:
            if self._srv:
                self._srv.close()
        except Exception:
            pass
        for s in list(self.sessions.values()):
            s.close()
        if self.is_alive():
            self.join(timeout=3)


def connect_shell(host: str, port: int, timeout: float = 6.0,
                  on_data=None, on_close=None, sid: int = 0) -> Session:
    """主动连到目标已开好的 shell 端口。"""
    sock = socket.create_connection((host, port), timeout=timeout)
    sess = Session(sid=sid or int(time.time()) % 100000, kind="connect",
                   peer=f"{host}:{port}", sock=sock)
    sess.name = f"正向 {host}:{port}"
    sess.start_reader(on_data, on_close)
    log(f"已连接到 {sess.peer}", "success", "tunnel")
    return sess


def local_ips() -> list[str]:
    from .hostinfo import list_ifaces
    return [i.ip for i in list_ifaces() if i.ip and not i.ip.startswith("169.254.")]
