# -*- coding: utf-8 -*-
"""
路径处理
========

打包成单文件 exe 之后，`__file__` 指向的是运行时的临时解包目录（_MEIPASS），
不能把配置、证书、日志写进去。这里区分两类路径：

* `app_dir()`        —— 可写的程序目录：exe 所在目录 / 源码项目根目录
* `resource_path()`  —— 只读的随包资源：图标等
"""

from __future__ import annotations

import os
import sys


def is_frozen() -> bool:
    """是否运行在 PyInstaller 打包出来的可执行文件里。"""
    return bool(getattr(sys, "frozen", False))


def app_dir() -> str:
    """可写目录：打包后是 exe 所在目录，源码运行时是项目根目录。"""
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def app_path(*parts: str) -> str:
    """拼一个位于可写目录下的路径（配置、缓存、证书、日志）。"""
    return os.path.join(app_dir(), *parts)


def resource_path(*parts: str) -> str:
    """拼一个只读资源路径（打包后在 _MEIPASS 里，源码运行时在项目根目录）。"""
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def icon_path() -> str:
    """应用图标：优先用打包进来的 .ico，找不到就退回 .png，都没有返回空串。"""
    for name in ("app.ico", "app.png"):
        p = resource_path("assets", name)
        if os.path.exists(p):
            return p
    return ""
