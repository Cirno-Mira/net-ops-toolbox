# -*- coding: utf-8 -*-
"""
图标生成脚本
============

用 Qt 渲染应用图标并写出 `assets/app.ico`（多尺寸）与 `assets/app.png`。
ICO 容器直接手写：现代 ICO 允许内部直接放 PNG 数据，比引入额外的图像库可靠。

    python tools/make_icon.py
"""

from __future__ import annotations

import os
import struct
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")

from PyQt5.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt  # noqa: E402
from PyQt5.QtGui import (QBrush, QColor, QLinearGradient, QPainter,  # noqa: E402
                         QPainterPath, QPen, QPixmap)
from PyQt5.QtWidgets import QApplication  # noqa: E402

SIZES = [16, 24, 32, 48, 64, 128, 256]
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "assets")

# QApplication 的引用必须一直留着：一旦被回收，Qt 就认为没有 GUI 应用，
# 后面再建 QPixmap 会直接报 "Must construct a QGuiApplication before a QPixmap"。
_QAPP = None


def render(size: int) -> QPixmap:
    """画一个圆角渐变底 + 网络拓扑图形的图标。"""
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)

    s = float(size)

    # 圆角底 + 紫色→青色渐变
    g = QLinearGradient(0, 0, s, s)
    g.setColorAt(0.0, QColor("#A78BFA"))
    g.setColorAt(0.55, QColor("#7FD8F7"))
    g.setColorAt(1.0, QColor("#63E3C6"))
    path = QPainterPath()
    path.addRoundedRect(QRectF(0, 0, s, s), s * 0.24, s * 0.24)
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(g))
    p.drawPath(path)

    # 三个节点 + 连线（网络拓扑）
    r = s * 0.115
    cx, cy = s / 2.0, s / 2.0
    nodes = [
        QPointF(cx, s * 0.26),            # 上
        QPointF(s * 0.26, s * 0.74),      # 左下
        QPointF(s * 0.74, s * 0.74),      # 右下
    ]
    pen = QPen(QColor(255, 255, 255, 220))
    pen.setWidthF(max(1.2, s * 0.045))
    pen.setCapStyle(Qt.RoundCap)
    p.setPen(pen)
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            p.drawLine(nodes[i], nodes[j])

    # 节点实心圆 + 中心高亮
    p.setPen(Qt.NoPen)
    p.setBrush(QColor("#FFFFFF"))
    for n in nodes:
        p.drawEllipse(n, r, r)
    p.setBrush(QColor(255, 255, 255, 90))
    p.drawEllipse(QPointF(cx, cy), s * 0.085, s * 0.085)
    p.end()
    return pm


def png_bytes(pm: QPixmap) -> bytes:
    buf = QBuffer(QByteArray())
    buf.open(QIODevice.WriteOnly)
    pm.save(buf, "PNG")
    data = bytes(buf.data())
    buf.close()
    return data


def write_ico(images: list[tuple[int, bytes]], path: str) -> None:
    """
    手写 ICO 容器。

    结构：ICONDIR(6 字节) + N × ICONDIRENTRY(16 字节) + 各尺寸图像数据。
    图像数据这里直接使用 PNG（Vista 之后的 ICO 都支持）。
    """
    count = len(images)
    header = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    entries, blobs = b"", b""
    for size, data in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32,
                               len(data), offset)
        blobs += data
        offset += len(data)
    with open(path, "wb") as fh:
        fh.write(header + entries + blobs)


def main() -> int:
    global _QAPP
    _QAPP = QApplication.instance() or QApplication(sys.argv)
    os.makedirs(OUT_DIR, exist_ok=True)

    images = []
    for size in SIZES:
        pm = render(size)
        images.append((size, png_bytes(pm)))
        if size == 256:
            pm.save(os.path.join(OUT_DIR, "app.png"), "PNG")

    ico_path = os.path.join(OUT_DIR, "app.ico")
    write_ico(images, ico_path)
    print(f"已生成 {ico_path}（{len(images)} 个尺寸：{SIZES}）")
    print(f"已生成 {os.path.join(OUT_DIR, 'app.png')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
