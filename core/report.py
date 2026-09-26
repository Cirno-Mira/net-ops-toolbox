# -*- coding: utf-8 -*-
"""
报告一键导出
============

把各个页面扫出来的东西汇总成一份可直接交付的 Markdown / HTML 报告：
资产清单、开放端口、安全问题、HTTP 流量、目录爆破结果。

界面只负责挑「要包含哪些章节」，渲染逻辑全在这里（不依赖 Qt）。
"""

from __future__ import annotations

import html
import time
from dataclasses import dataclass, field


@dataclass
class ReportData:
    title: str = "网络运维工具箱 · 检测报告"
    operator: str = ""
    scope: str = ""
    notes: str = ""
    generated_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    assets: list[dict] = field(default_factory=list)     # ip/mac/vendor/hostname/ports/status
    ports: list[dict] = field(default_factory=list)      # host/port/service/banner
    vulns: list[dict] = field(default_factory=list)      # host/port/name/severity/detail/evidence
    flows: list[dict] = field(default_factory=list)      # time/client/method/url/status
    dirs: list[dict] = field(default_factory=list)       # url/status/length/note

    @property
    def empty(self) -> bool:
        return not (self.assets or self.ports or self.vulns or self.flows or self.dirs)

    def counts(self) -> dict:
        return {"资产": len(self.assets), "开放端口": len(self.ports),
                "安全问题": len(self.vulns), "HTTP 请求": len(self.flows),
                "路径发现": len(self.dirs)}


def _md_table(headers: list[str], rows: list[list]) -> str:
    if not rows:
        return "_（无）_\n"
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join([" --- "] * len(headers)) + "|"]
    for r in rows:
        cells = [str(c).replace("|", "\\|").replace("\n", " ") for c in r]
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def render_markdown(d: ReportData, sections: set[str] | None = None) -> str:
    sec = sections or {"meta", "summary", "assets", "ports", "vulns", "flows", "dirs"}
    L: list[str] = [f"# {d.title}\n"]

    if "meta" in sec:
        L.append("## 一、任务信息\n")
        L.append(f"- 生成时间：{d.generated_at}")
        if d.operator:
            L.append(f"- 执行人：{d.operator}")
        if d.scope:
            L.append(f"- 测试范围：{d.scope}")
        L.append("")
        if d.notes:
            L.append(f"> {d.notes}\n")

    if "summary" in sec:
        L.append("## 二、结果概览\n")
        for k, v in d.counts().items():
            L.append(f"- {k}：**{v}**")
        sev: dict[str, int] = {}
        for v in d.vulns:
            sev[v.get("severity", "?")] = sev.get(v.get("severity", "?"), 0) + 1
        if sev:
            order = ["严重", "高危", "中危", "低危", "信息"]
            L.append("- 风险分布：" + "、".join(
                f"{k} {sev[k]}" for k in order if k in sev))
        L.append("")

    if "assets" in sec and d.assets:
        L.append("## 三、资产清单\n")
        L.append(_md_table(["IP", "MAC", "厂商", "主机名", "开放端口", "状态"],
                           [[a.get("ip", ""), a.get("mac", ""), a.get("vendor", ""),
                             a.get("hostname", ""), a.get("ports", ""),
                             a.get("status", "")] for a in d.assets]))

    if "ports" in sec and d.ports:
        L.append("## 四、开放端口\n")
        L.append(_md_table(["主机", "端口", "服务", "Banner"],
                           [[p.get("host", ""), p.get("port", ""),
                             p.get("service", ""), p.get("banner", "")[:80]]
                            for p in d.ports]))

    if "vulns" in sec and d.vulns:
        L.append("## 五、安全问题\n")
        order = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "信息": 4}
        vs = sorted(d.vulns, key=lambda v: order.get(v.get("severity", "信息"), 9))
        L.append(_md_table(["严重程度", "主机", "端口", "问题", "说明", "证据"],
                           [[v.get("severity", ""), v.get("host", ""), v.get("port", ""),
                             v.get("name", ""), v.get("detail", ""),
                             v.get("evidence", "")[:80]] for v in vs]))

    if "flows" in sec and d.flows:
        L.append("## 六、HTTP 流量\n")
        L.append(_md_table(["时间", "来源", "方法", "URL", "状态"],
                           [[f.get("time", ""), f.get("client", ""), f.get("method", ""),
                             f.get("url", ""), f.get("status", "")] for f in d.flows[:500]]))

    if "dirs" in sec and d.dirs:
        L.append("## 七、路径发现\n")
        L.append(_md_table(["状态码", "长度", "URL", "备注"],
                           [[x.get("status", ""), x.get("length", ""),
                             x.get("url", ""), x.get("note", "")] for x in d.dirs[:500]]))

    L.append("\n---\n")
    L.append("> 本报告由「网络运维工具箱」生成，仅可用于已获授权的测试范围。\n")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

_CSS = """
body{font-family:'Microsoft YaHei UI','Segoe UI',sans-serif;background:#FFF8FB;
     color:#3F3557;margin:0;padding:28px 34px;line-height:1.6}
h1{font-size:24px;color:#5B3FD1;margin:0 0 4px}
h2{font-size:16px;color:#5B3FD1;margin:26px 0 8px;
   border-left:5px solid #A78BFA;padding-left:10px}
table{border-collapse:collapse;width:100%;margin:6px 0 14px;
      background:#fff;border-radius:10px;overflow:hidden;
      box-shadow:0 1px 3px rgba(124,92,255,.10)}
th{background:#F3EEFF;color:#5B4E86;text-align:left;padding:8px 10px;font-size:13px}
td{padding:7px 10px;border-top:1px solid #F3EEFC;font-size:13px;word-break:break-all}
tr:nth-child(even) td{background:#FCFAFF}
.meta{color:#8A7FA8;font-size:13px;margin-bottom:10px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:10px 0}
.card{background:#fff;border:1px solid #EFE6FF;border-radius:12px;
      padding:12px 18px;min-width:110px;box-shadow:0 1px 3px rgba(124,92,255,.08)}
.card b{display:block;font-size:22px;color:#5B3FD1}
.card span{font-size:12px;color:#8A7FA8}
.sev-严重{color:#C0392B;font-weight:700}
.sev-高危{color:#E8457C;font-weight:700}
.sev-中危{color:#C98A12;font-weight:700}
.sev-低危{color:#2E86DE}
.sev-信息{color:#8A7FA8}
footer{margin-top:26px;color:#A79FBC;font-size:12px;
       border-top:1px dashed #E6DBFB;padding-top:10px}
"""


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def _html_table(headers: list[str], rows: list[list], sev_col: int | None = None) -> str:
    if not rows:
        return "<p><i>（无）</i></p>"
    out = ["<table><thead><tr>"]
    out += [f"<th>{_esc(h)}</th>" for h in headers]
    out.append("</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>")
        for i, c in enumerate(r):
            cls = f' class="sev-{_esc(c)}"' if (sev_col is not None and i == sev_col) else ""
            out.append(f"<td{cls}>{_esc(c)}</td>")
        out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def render_html(d: ReportData, sections: set[str] | None = None) -> str:
    sec = sections or {"meta", "summary", "assets", "ports", "vulns", "flows", "dirs"}
    P: list[str] = [
        "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>",
        f"<title>{_esc(d.title)}</title><style>{_CSS}</style></head><body>",
        f"<h1>{_esc(d.title)}</h1>",
    ]
    if "meta" in sec:
        P.append("<div class='meta'>")
        P.append(f"生成时间：{_esc(d.generated_at)}")
        if d.operator:
            P.append(f" ｜ 执行人：{_esc(d.operator)}")
        if d.scope:
            P.append(f" ｜ 测试范围：{_esc(d.scope)}")
        P.append("</div>")
        if d.notes:
            P.append(f"<p>{_esc(d.notes)}</p>")

    if "summary" in sec:
        P.append("<h2>结果概览</h2><div class='cards'>")
        for k, v in d.counts().items():
            P.append(f"<div class='card'><b>{v}</b><span>{_esc(k)}</span></div>")
        P.append("</div>")

    if "assets" in sec and d.assets:
        P.append("<h2>资产清单</h2>")
        P.append(_html_table(["IP", "MAC", "厂商", "主机名", "开放端口", "状态"],
                             [[a.get("ip"), a.get("mac"), a.get("vendor"),
                               a.get("hostname"), a.get("ports"), a.get("status")]
                              for a in d.assets]))

    if "ports" in sec and d.ports:
        P.append("<h2>开放端口</h2>")
        P.append(_html_table(["主机", "端口", "服务", "Banner"],
                             [[p.get("host"), p.get("port"), p.get("service"),
                               (p.get("banner") or "")[:100]] for p in d.ports]))

    if "vulns" in sec and d.vulns:
        P.append("<h2>安全问题</h2>")
        order = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "信息": 4}
        vs = sorted(d.vulns, key=lambda v: order.get(v.get("severity", "信息"), 9))
        P.append(_html_table(["严重程度", "主机", "端口", "问题", "说明", "证据"],
                             [[v.get("severity"), v.get("host"), v.get("port"),
                               v.get("name"), v.get("detail"), (v.get("evidence") or "")[:100]]
                              for v in vs], sev_col=0))

    if "flows" in sec and d.flows:
        P.append("<h2>HTTP 流量</h2>")
        P.append(_html_table(["时间", "来源", "方法", "URL", "状态"],
                             [[f.get("time"), f.get("client"), f.get("method"),
                               f.get("url"), f.get("status")] for f in d.flows[:500]]))

    if "dirs" in sec and d.dirs:
        P.append("<h2>路径发现</h2>")
        P.append(_html_table(["状态码", "长度", "URL", "备注"],
                             [[x.get("status"), x.get("length"), x.get("url"),
                               x.get("note")] for x in d.dirs[:500]]))

    P.append("<footer>本报告由「网络运维工具箱」生成，仅可用于已获授权的测试范围。</footer>")
    P.append("</body></html>")
    return "".join(P)


def save(path: str, content: str) -> tuple[bool, str]:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return True, path
    except OSError as exc:
        return False, str(exc)
