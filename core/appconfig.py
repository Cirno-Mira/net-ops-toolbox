# -*- coding: utf-8 -*-
"""
工具箱配置（config.json）
========================

放在工具箱根目录，纯 JSON，改完重启生效；界面上的开关也会写回这里。
"""

from __future__ import annotations

import json
import threading

_LOCK = threading.Lock()

DEFAULTS: dict = {
    # 启动
    "auto_elevate": True,          # 启动时自动请求管理员权限（UAC）
    "remember_ack": False,         # 是否记住「已阅读授权声明」

    # ARP 牵引
    "arp_interval": 2,             # 发包间隔（秒）
    "arp_restore_count": 5,        # 停止时恢复次数
    "arp_auto_forward": True,      # 开启双向牵引前自动打开 IP 转发

    # 内建 MITM / 引流
    "mitm_enabled": False,
    "mitm_http_port": 80,          # 接收被牵引设备的 HTTP
    "mitm_https_port": 443,        # 接收被牵引设备的 HTTPS
    "mitm_upstream_proxy": "",     # 二级代理，例如 127.0.0.1:7890（留空=直连）
    "mitm_forward_to_tool": False, # 把流量转交给 Reqable/Fiddler
    "mitm_forward_port": 8888,     # 本地抓包工具的监听端口，填它自己设置里那个
    "mitm_ca_dir": "certs",        # CA 与动态证书存放目录

    # DNS 引流
    "dns_spoof": True,             # 把被牵引设备的 DNS 应答指向本机

    # 界面
    "font_pt": 10,
    "confirm_arp_start": True,
}


from .paths import app_path


def config_path() -> str:
    return app_path("config.json")


class Config:
    def __init__(self) -> None:
        self._data = dict(DEFAULTS)
        self.load()

    def load(self) -> None:
        try:
            with open(config_path(), "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._data.update({k: v for k, v in data.items() if k in DEFAULTS})
        except Exception:
            pass

    def save(self) -> None:
        with _LOCK:
            try:
                with open(config_path(), "w", encoding="utf-8") as fh:
                    json.dump(self._data, fh, ensure_ascii=False, indent=2)
            except OSError:
                pass

    def get(self, key: str, default=None):
        return self._data.get(key, DEFAULTS.get(key, default))

    def set(self, key: str, value) -> None:
        self._data[key] = value

    def update(self, **kw) -> None:
        self._data.update(kw)

    def as_dict(self) -> dict:
        return dict(self._data)


CFG = Config()
