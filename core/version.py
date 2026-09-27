# -*- coding: utf-8 -*-
"""
版本与程序标识
==============

程序名、组织名、版本号只在这里写一份：`main.py` 拿它设置 QApplication，
界面拿它显示版本，打包脚本和 Release 也以这里为准。
**升版本只改这个文件。**

`APP_NAME` / `APP_ORG` 同时是 QSettings 的存储键，改了会让用户已保存的
配置读不回来，非必要别动。
"""

from __future__ import annotations

APP_NAME = "NetOpsToolbox"
APP_ORG = "NetOps"
APP_TITLE = "网络运维工具箱 · NetOps Toolbox"
APP_VERSION = "1.0.1"
