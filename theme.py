# -*- coding: utf-8 -*-
"""
配色与样式表（浅色多巴胺风格）
==============================

和主程序一致的柔和粉/奶油黄/天蓝/薰衣草紫渐变底 + 白色圆角卡片，
额外加了表格、标签页、分割条、日志框等控件样式。
"""

# ---------------- 颜色 ----------------
C_TEXT = "#3F3557"
C_TEXT_DIM = "#8A7FA8"
C_TEXT_MUTED = "#A79FBC"
C_PURPLE = "#7C5CFF"
C_PURPLE_DEEP = "#5B3FD1"
C_MINT = "#0FA98D"
C_MINT_BG = "#E4FAF3"
C_PINK = "#E8457C"
C_PINK_BG = "#FFE9F0"
C_YELLOW = "#C98A12"
C_YELLOW_BG = "#FFF6E0"
C_BLUE = "#2E86DE"
C_BLUE_BG = "#E8F3FF"
C_RED = "#D93A3A"
C_RED_BG = "#FFEAEA"
C_GREEN = "#1F9D55"

# 日志级别 -> 颜色
LEVEL_COLORS = {
    "debug": "#9C93B5",
    "info": "#3F3557",
    "success": "#0FA98D",
    "warn": "#C98A12",
    "error": "#D93A3A",
}

LEVEL_TAGS = {
    "debug": "调试", "info": "信息", "success": "成功",
    "warn": "警告", "error": "错误",
}


def make_qss(font_pt: int = 10) -> str:
    return f"""
QWidget#Root {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                stop:0.00 #FFF2F8,
                                stop:0.30 #FFFAED,
                                stop:0.62 #EAF7FF,
                                stop:1.00 #F3EDFF);
}}
QWidget {{
    font-family: 'Microsoft YaHei UI', 'Segoe UI', 'Segoe UI Emoji', sans-serif;
    font-size: {font_pt}pt;
    color: {C_TEXT};
}}
QLabel {{ background: transparent; }}
QLabel#H1      {{ font-size: 17pt; font-weight: 800; color: #332A4D; }}
QLabel#Sub     {{ font-size: 9pt; color: {C_TEXT_DIM}; }}
QLabel#CardT   {{ font-size: 10.5pt; font-weight: 700; color: {C_PURPLE_DEEP}; }}
QLabel#Dim     {{ font-size: 9pt; color: {C_TEXT_DIM}; }}
QLabel#Mono    {{ font-family: 'Cascadia Mono','Consolas',monospace; }}

/* ---------- 卡片 ---------- */
QFrame#Card {{
    background-color: rgba(255,255,255,0.90);
    border: 1px solid #EDE4FB;
    border-radius: 16px;
}}
QFrame#Line {{ background-color: #F0E9FF; border: none; max-height: 1px; }}

/* ---------- 标签页 ---------- */
QTabWidget::pane {{
    border: 1px solid #EDE4FB;
    border-radius: 16px;
    background-color: rgba(255,255,255,0.86);
    top: -1px;
}}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background: #F6F1FF;
    color: #6B5CA5;
    border: 1px solid #E7DCFA;
    border-bottom: none;
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
    padding: 7px 16px;
    margin-right: 4px;
    font-weight: 700;
}}
QTabBar::tab:hover {{ background: #EFE7FF; }}
QTabBar::tab:selected {{
    background: #FFFFFF;
    color: {C_PURPLE_DEEP};
    border-color: #D9C9F7;
}}

/* ---------- 按钮 ---------- */
QPushButton {{
    background-color: #FFFFFF;
    border: 1px solid #E7DCFA;
    border-radius: 10px;
    padding: 6px 14px;
    color: #5B4E86;
    font-weight: 700;
}}
QPushButton:hover   {{ background-color: #F7F2FF; border-color: #CDB8F7; }}
QPushButton:pressed {{ background-color: #EFE6FF; }}
QPushButton:disabled {{ color: #BDB3D4; background-color: #F7F5FB; border-color: #EDE8F6; }}
QPushButton#Primary {{
    background-color: {C_PURPLE}; border-color: {C_PURPLE}; color: #FFFFFF;
}}
QPushButton#Primary:hover {{ background-color: #8E72FF; }}
QPushButton#Danger {{
    background-color: {C_PINK}; border-color: {C_PINK}; color: #FFFFFF;
}}
QPushButton#Danger:hover {{ background-color: #F25C8D; }}
QPushButton#Success {{
    background-color: {C_MINT}; border-color: {C_MINT}; color: #FFFFFF;
}}
QPushButton#Success:hover {{ background-color: #14BC9D; }}
QPushButton#Ghost {{ padding: 4px 10px; font-size: 9pt; }}
/* 禁用态要盖过上面带 id 的配色规则，否则看起来还像能点 */
QPushButton#Primary:disabled, QPushButton#Danger:disabled,
QPushButton#Success:disabled, QPushButton#Ghost:disabled {{
    background-color: #F1EDF8; border-color: #E7E1F3; color: #B6ADC9;
}}

/* ---------- 输入控件 ---------- */
QLineEdit, QPlainTextEdit, QTextEdit {{
    background: #FFFFFF;
    border: 1px solid #E5DBFA;
    border-radius: 9px;
    padding: 5px 8px;
    selection-background-color: #D9C9F7;
    selection-color: #332A4D;
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border-color: #B9A3F0; }}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{ background: #F7F5FB; color: #B0A7C8; }}
QComboBox {{
    background: #FFFFFF; border: 1px solid #E5DBFA; border-radius: 9px;
    padding: 5px 8px; min-width: 80px;
}}
QComboBox:hover {{ border-color: #CDB8F7; }}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background: #FFFFFF; border: 1px solid #E5DBFA; border-radius: 8px;
    selection-background-color: #EFE6FF; selection-color: #332A4D;
    outline: none; padding: 4px;
}}
QSpinBox {{
    background: #FFFFFF; border: 1px solid #E5DBFA; border-radius: 9px;
    padding: 4px 6px; min-width: 62px;
}}
QCheckBox, QRadioButton {{ spacing: 7px; color: #574B7C; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 15px; height: 15px; border-radius: 5px;
    border: 1.5px solid #D9CDF5; background: #FFFFFF;
}}
QRadioButton::indicator {{ border-radius: 8px; }}
QCheckBox::indicator:hover, QRadioButton::indicator:hover {{ border-color: #B9A3F0; }}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
    background: {C_PURPLE}; border-color: {C_PURPLE};
}}

/* ---------- 表格 ---------- */
QTableWidget, QTableView {{
    background: #FFFFFF;
    alternate-background-color: #FBF9FF;
    border: 1px solid #EEE7FB;
    border-radius: 12px;
    gridline-color: #F3EEFC;
    selection-background-color: #EFE6FF;
    selection-color: #332A4D;
    outline: none;
}}
QTableWidget::item, QTableView::item {{ padding: 3px 6px; }}
QHeaderView {{ background: transparent; }}
QHeaderView::section {{
    background-color: #F6F1FF;
    color: #5B4E86;
    border: none;
    border-right: 1px solid #EDE4FB;
    border-bottom: 1px solid #EDE4FB;
    padding: 6px 8px;
    font-weight: 700;
}}
QHeaderView::section:first {{ border-top-left-radius: 11px; }}
QHeaderView::section:last  {{ border-top-right-radius: 11px; border-right: none; }}
QTableCornerButton::section {{ background-color: #F6F1FF; border: none; }}

/* ---------- 列表 ---------- */
QListWidget {{
    background: #FFFFFF; border: 1px solid #EEE7FB; border-radius: 12px;
    outline: none; padding: 5px;
}}
QListWidget::item {{ padding: 8px 10px; border-radius: 8px; color: #574B7C; }}
QListWidget::item:hover {{ background: #F7F2FF; }}
QListWidget::item:selected {{ background: #EFE6FF; color: {C_PURPLE_DEEP}; font-weight: 700; }}

/* ---------- 左侧导航树（整条工具链平铺在这里） ---------- */
QTreeWidget {{
    background-color: rgba(255,255,255,0.92);
    border: 1px solid #EEE7FB; border-radius: 14px;
    outline: none; padding: 8px 6px;
}}
QTreeWidget::item {{ padding: 8px 6px; border-radius: 9px; color: #574B7C; }}
QTreeWidget::item:hover {{ background: #F7F2FF; }}
QTreeWidget::item:selected {{ background: #EFE6FF; color: {C_PURPLE_DEEP}; font-weight: 700; }}
QTreeWidget::branch {{ background: transparent; }}

/* ---------- 进度条 ---------- */
QProgressBar {{
    border: none; border-radius: 7px; background-color: #F1ECFA;
    height: 13px; text-align: center; color: transparent;
}}
QProgressBar::chunk {{ border-radius: 7px; background-color: #A78BFA; }}

/* ---------- 分割条 ---------- */
QSplitter::handle {{ background-color: transparent; }}
QSplitter::handle:vertical {{ height: 8px; }}
QSplitter::handle:horizontal {{ width: 8px; }}
QSplitter::handle:hover {{ background-color: #E6DBFB; border-radius: 4px; }}

/* ---------- 滚动条 ---------- */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: #E0D6F5; border-radius: 5px; min-height: 36px; }}
QScrollBar::handle:vertical:hover {{ background: #C9B8F0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: #E0D6F5; border-radius: 5px; min-width: 36px; }}
QScrollBar::handle:horizontal:hover {{ background: #C9B8F0; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* ---------- 其它 ---------- */
QGroupBox {{
    border: 1px solid #EDE4FB; border-radius: 12px; margin-top: 10px;
    padding: 10px 8px 8px 8px; font-weight: 700; color: {C_PURPLE_DEEP};
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 5px; }}
QToolTip {{
    background-color: #FFFFFF; color: {C_TEXT}; border: 1px solid #E7DCFA;
    border-radius: 8px; padding: 6px 10px;
}}
QStatusBar {{ background: transparent; color: {C_TEXT_DIM}; }}
QMenu {{
    background: #FFFFFF; border: 1px solid #E7DCFA; border-radius: 10px; padding: 5px;
}}
QMenu::item {{ padding: 6px 22px 6px 14px; border-radius: 7px; }}
QMenu::item:selected {{ background: #EFE6FF; color: {C_PURPLE_DEEP}; }}
QMenu::separator {{ height: 1px; background: #F0E9FF; margin: 4px 8px; }}
"""


# 状态色 → (背景, 前景)，用于状态徽章
STATE_COLORS = {
    "ok": (C_MINT_BG, C_MINT),
    "warn": (C_YELLOW_BG, C_YELLOW),
    "error": (C_RED_BG, C_RED),
    "info": (C_BLUE_BG, C_BLUE),
    "idle": ("#F3F0FA", C_TEXT_DIM),
}
