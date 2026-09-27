# -*- coding: utf-8 -*-
"""
引流链路自检 / 端口占用检测 / 防火墙放行
========================================

「被牵引设备的流量看不到」通常卡在下面某一环，这个模块负责把每一环都查一遍：

    ① 管理员权限 + Npcap          —— 没有它连包都发不出去
    ② 代理监听端口能不能绑         —— 已被别的抓包工具占用的端口会绑不上
    ③ Windows 防火墙是否放行入站   —— Public 配置文件开着时，外部连不进来
    ④ DNS 引流是否在跑             —— 没有它，目标的流量根本不会指向本机
    ⑤ 代理有没有真的收到连接       —— 用来区分「没引流到」和「引流到了但没显示」

注意一个 Windows 特有的坑：**加了 SO_REUSEADDR 之后，两个进程可以同时绑同一个端口**，
后绑的那个「绑定成功」但收不到任何连接。所以这里的检测故意不带 SO_REUSEADDR。
"""

from __future__ import annotations

import socket

from .hostinfo import Iface, is_admin, npcap_ready, run_hidden
from .logging_bus import log

FIREWALL_RULE = "NetOps Toolbox MITM"


# --------------------------------------------------------------------------- #
# 端口
# --------------------------------------------------------------------------- #

def port_owner(port: int, proto: str = "tcp") -> tuple[int | None, str]:
    """谁在监听这个端口？返回 (pid, 进程名)，没有则 (None, "")。"""
    try:
        import psutil
        for conn in psutil.net_connections(kind=proto):
            try:
                if (conn.laddr and getattr(conn.laddr, "port", None) == port
                        and conn.status == psutil.CONN_LISTEN):
                    name = ""
                    if conn.pid:
                        try:
                            name = psutil.Process(conn.pid).name()
                        except Exception:
                            name = "未知进程"
                    return conn.pid, name
            except Exception:
                continue
    except Exception as exc:
        log(f"查询端口占用失败（可能需要管理员）：{exc}", "debug", "netdiag")
    return None, ""


def port_bindable(port: int, ip: str = "0.0.0.0") -> tuple[bool, str]:
    """
    准确判断端口能不能绑。

    故意**不设** SO_REUSEADDR —— Windows 上设了以后即使端口被别的进程占着
    也会「绑定成功」，从而出现「代理显示在跑、但一个包都收不到」的鬼故事。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((ip, port))
        return True, ""
    except OSError as exc:
        return False, f"{exc}"
    finally:
        try:
            s.close()
        except Exception:
            pass


def describe_port(port: int, ip: str = "0.0.0.0") -> tuple[bool, str]:
    ok, err = port_bindable(port, ip)
    if ok:
        return True, f"{ip}:{port} 可以监听"
    pid, name = port_owner(port)
    if pid:
        return False, f"{ip}:{port} 已被占用（PID {pid} / {name}）"
    return False, f"{ip}:{port} 无法监听：{err}"


# --------------------------------------------------------------------------- #
# 防火墙
# --------------------------------------------------------------------------- #

def firewall_profiles() -> dict[str, bool]:
    """{'Domain': True, 'Private': False, 'Public': True}（True = 防火墙开着）"""
    out = run_hidden(["netsh", "advfirewall", "show", "allprofiles", "state"])
    result: dict[str, bool] = {}
    current = ""
    for line in out.splitlines():
        line = line.strip()
        low = line.lower()
        for key in ("domain", "private", "public"):
            if low.startswith(key) and "profile" in low:
                current = key.capitalize()
        if low.startswith("state") and current:
            result[current] = "on" in low.split()[-1].lower() or "启用" in line
            current = ""
    return result


def firewall_rule_exists(name: str = FIREWALL_RULE) -> bool:
    out = run_hidden(["netsh", "advfirewall", "firewall", "show", "rule",
                      f"name={name}"])
    return name in out


def allow_firewall(ports: list[int], name: str = FIREWALL_RULE) -> tuple[bool, str]:
    """给监听端口加入站放行规则（需要管理员）。"""
    if not is_admin():
        return False, "添加防火墙规则需要管理员权限"
    ports = sorted({int(p) for p in ports if p})
    if not ports:
        return False, "没有需要放行的端口"
    portspec = ",".join(str(p) for p in ports)
    out = run_hidden(["netsh", "advfirewall", "firewall", "add", "rule",
                      f"name={name}", "dir=in", "action=allow",
                      "protocol=TCP", f"localport={portspec}"])
    ok = "Ok" in out or "确定" in out or "ok" in out.lower() or not out.strip()
    if ok:
        log(f"已添加防火墙入站放行规则：TCP {portspec}", "success", "netdiag")
        return True, f"已放行 TCP {portspec}"
    return False, out.strip()[:200] or "添加失败"


def remove_firewall(name: str = FIREWALL_RULE) -> tuple[bool, str]:
    if not is_admin():
        return False, "删除防火墙规则需要管理员权限"
    out = run_hidden(["netsh", "advfirewall", "firewall", "delete", "rule",
                      f"name={name}"])
    return True, out.strip()[:200] or "已删除"


# --------------------------------------------------------------------------- #
# 综合自检
# --------------------------------------------------------------------------- #

def diagnose(iface: Iface | None, http_port: int, https_port: int,
             forward_port: int = 0, forward_to_tool: bool = False,
             proxy_running: bool = False, proxy_connections: int = 0,
             dns_running: bool = False, dns_spoofed: int = 0) -> list[dict]:
    """
    跑一遍完整链路检查，返回一串检查项：
        {"name": 步骤名, "ok": True/False/None, "detail": 说明, "fix": 建议}
    ok=None 表示「提醒」而不是错误。
    """
    items: list[dict] = []

    def add(name, ok, detail, fix=""):
        items.append({"name": name, "ok": ok, "detail": detail, "fix": fix})

    # ① 权限
    admin = is_admin()
    add("① 管理员权限", admin,
        "已获得管理员权限" if admin else "当前是普通用户",
        "" if admin else "关掉程序，重新启动并在 UAC 弹窗点「是」（或双击 启动.vbs）")

    # ② Npcap
    ready, why = npcap_ready()
    add("② Npcap 原始收发", ready, why,
        "" if ready else "安装/重装 Npcap（Wireshark 安装包内附带）")

    # ③ 网卡
    if iface is None:
        add("③ 网卡", False, "没有选到网卡", "在 ARP 页选一块有网关的网卡")
    else:
        add("③ 网卡", bool(iface.ip and iface.gateway),
            f"{iface.alias}  {iface.ip}/{iface.prefix}  网关 {iface.gateway or '(无)'}"
            + f"  本机MAC {iface.mac or '(未知)'}",
            "" if iface.gateway else "这块网卡没有网关，牵引会没有意义")

    # ④ 监听端口
    if forward_to_tool:
        add("④ 模式", None,
            f"已开启「转交给本地抓包工具 127.0.0.1:{forward_port}」，"
            f"我们的监听端口仍应是 80 / 443",
            "这跟下面的监听端口是两回事，别把监听端口也填成抓包工具那个")
    for label, port in (("HTTP", http_port), ("HTTPS", https_port)):
        if not port:
            continue
        if proxy_running and port in (http_port, https_port) and proxy_connections >= 0:
            pid, name = port_owner(port)
            if pid:
                add(f"④ {label} 监听端口 {port}", True,
                    f"代理正在监听（系统显示占用者：{name}）", "")
                continue
        ok, detail = describe_port(port)
        if ok:
            add(f"④ {label} 监听端口 {port}", True, detail + "（代理未占用时）", "")
        else:
            add(f"④ {label} 监听端口 {port}", False, detail,
                "换一个没被占用的端口；如果本意是把流量交给 Reqable/Fiddler，"
                "请勾选「转交给本地抓包工具」并把它的端口填到那一栏，"
                "我们的监听端口保持 80/443")

    if http_port and http_port == forward_port and forward_to_tool:
        add("④ 端口冲突", False, f"监听端口和转交端口都是 {http_port}，会自己转给自己",
            "监听端口用 80/443，转交端口填 Reqable/Fiddler 的端口")

    # ⑤ 防火墙
    profiles = firewall_profiles()
    if profiles:
        on = [k for k, v in profiles.items() if v]
        rule = firewall_rule_exists()
        if not on:
            add("⑤ 防火墙", True, "三个配置文件都是关闭的，不会拦入站", "")
        elif rule:
            add("⑤ 防火墙", True, f"{'、'.join(on)} 开启中，但已有放行规则", "")
        else:
            add("⑤ 防火墙", False,
                f"{'、'.join(on)} 配置文件已开启，且没有针对 {http_port}/{https_port} "
                f"的入站放行规则（外部连接可能被丢弃）",
                "点下面的「放行防火墙端口」按钮")

    # ⑥ 代理
    add("⑥ 透明代理", proxy_running,
        f"正在运行，已收到 {proxy_connections} 个连接" if proxy_running
        else "未启动",
        "" if proxy_running else "在「流量劫持」页点「启动代理」")

    # ⑦ DNS 引流
    add("⑦ DNS 引流", dns_running,
        f"正在运行，已劫持 {dns_spoofed} 个 DNS 查询" if dns_running
        else "未启动",
        "" if dns_running
        else "回到 ARP 页勾上「DNS 引流」，重新开始牵引 —— "
             "这是让目标连到本机的关键一步")

    # ⑧ 是否真的有连接进来
    if proxy_running:
        if proxy_connections > 0:
            add("⑧ 是否收到流量", True, f"已经收到 {proxy_connections} 个连接", "")
        elif dns_spoofed > 0:
            add("⑧ 是否收到流量", False,
                "DNS 已经劫持成功，但代理一个连接都没收到",
                "通常是：目标设备在跑 DoH/DoT（加密 DNS），或者防火墙拦了入站，"
                "或者目标访问的是 IP 而不是域名")
        else:
            add("⑧ 是否收到流量", False, "还没收到任何连接",
                "先确认 ARP 牵引 + DNS 引流都在跑，再让目标设备访问一个 http 网站试试")
    return items


def format_report(items: list[dict]) -> str:
    lines = []
    for it in items:
        mark = "✅" if it["ok"] is True else ("⚠️" if it["ok"] is None else "❌")
        lines.append(f"{mark} {it['name']}：{it['detail']}")
        if it["ok"] is not True and it.get("fix"):
            lines.append(f"      → {it['fix']}")
    return "\n".join(lines)
