# 网络运维工具箱 · NetOps Toolbox

浅色多巴胺风格的 PyQt5 网络运维 / CTF 工具链，一个窗口搞定资产发现、端口扫描、
ARP 牵引、流量劫持改包、抓包重放。

```
🎯 资产发现      ARP / Ping 扫描，识别 IP、MAC、厂商、主机名、开放端口
🔎 端口扫描      TCP connect 扫描 + Banner 抓取，11 种端口预设
⚡ ARP 牵引/断网   双向中间人 / 单向抓包 / 断网攻击(arp death) + DNS 引流
🕵 流量劫持      内建 HTTP/HTTPS 透明代理：看请求、改包重放、下断点
📡 抓包分析      scapy 实时抓包、落盘 pcap、选中包编辑重放、跳转 Wireshark
🧰 运维工具      本机信息 / Ping 曲线 / 路由追踪 / DNS / WOL / HTTP / 子网 / 时间
```

---

## 一、安装与运行

**不想装 Python**：到 [Releases](../../releases) 下载 `NetOpsToolbox.exe`，单文件免安装，
双击即用（会自己弹 UAC 提权）。抓包和 ARP 牵引需要机器上装有 **Npcap**，
装 Wireshark 时勾选即可。

想改代码就跑源码：

```powershell
conda activate ai
cd NetOpsToolbox
pip install -r requirements.txt

python main.py          # 启动（会自动弹 UAC 请求管理员权限）
```

**想完全没有控制台黑窗**：直接双击 **`启动.vbs`**。
它用 `pythonw.exe`（GUI 子系统程序）启动，不会有任何 cmd 窗口；
自动提权时同样用 `pythonw`，所以提权后也不会闪黑窗。

其他参数：

```powershell
python main.py --no-elevate    # 本次不自动提权
python main.py --selftest      # 核心层自检，不弹界面
```

配置写在同目录的 `config.json`（首次运行自动生成），常用项：

| 键 | 说明 |
| --- | --- |
| `auto_elevate` | 启动是否自动请求管理员（默认 true） |
| `mitm_http_port` / `mitm_https_port` | 透明代理监听端口（默认 80 / 443） |
| `mitm_forward_to_tool` / `mitm_forward_port` | 是否把流量转交给 Reqable(9000)/Fiddler(8888) |
| `mitm_upstream_proxy` | 二级代理，例如 `127.0.0.1:7890` |
| `arp_interval` / `arp_restore_count` | ARP 发包间隔、停止时恢复次数 |

### 权限

| 功能 | 权限 |
| --- | --- |
| 资产发现（Ping 方式）、端口扫描、全部运维小工具 | 普通用户 |
| ARP 扫描、ARP 牵引 / 断网、抓包、**透明代理** | **管理员 + Npcap** |

---

## 二、重点：为什么 Reqable / Fiddler 看不到被 ARP 那台机器的流量？

这是最常见的一个误解，原因很实在：

> **Reqable / Fiddler 是"本地代理"，只能拦到「本机进程发起」的连接。**
> ARP 牵引只是让目标的流量**经过**本机（二层转发），
> 目标 TCP 连接的目的 IP 仍然是真实服务器 —— 这些包根本不会进本机代理的套接字。

要让目标设备访问的网站内容直接显示在本机，必须再补一步 **DNS 引流**：

```
① ARP 牵引    目标设备的流量先到本机（否则它的 DNS 请求也无法到达）
② DNS 引流    收到域名查询时抢先应答「A 记录 = 本机 IP」  ← 关键
③ 于是它直接连到本机的 80/443，本机透明代理就拿到了明文
```

工具箱把这三步做成了一键：在 **⚡ ARP 牵引 / 断网** 页把
`DNS 引流` 和 `同时启动内建透明代理` 都勾上，点开始，
然后切到 **🕵 流量劫持** 页 —— 目标访问的网页请求就会一条条出现。

### 具体操作步骤（照这个来）

**第 1 步 · ARP 页**
- 网卡选对（有网关的那块）
- 模式选 **双向中间人（推荐）**
- 勾上 **开启 IP 转发**、**DNS 引流**、**同时启动内建透明代理**
- 勾选目标设备 → 点「开始」

**第 2 步 · 流量劫持页**
- **端口保持 80 / 443**（这是「目标连过来的端口」，**不是** Reqable 的 8888）
- 点「启动代理」
- 让目标设备打开一个 **http://** 网站（不要用 https，先排除证书问题）

**第 3 步 · 看结果**
- 请求出现在「请求列表」里 → 成功，可以改包重放了
- 还是空的 → 点 **「🔍 引流自检」**，它会逐环告诉你卡在哪

### ⚠️ 最常见的三个坑

| 现象 | 原因 | 解决 |
| --- | --- | --- |
| 代理显示在跑，一个包都没有 | **监听端口填成了 8888**（Reqable 占着）。Windows 上 `SO_REUSEADDR` 会让两个进程都绑成功，但连接全被 Reqable 接走 | 监听端口改回 **80 / 443**；想用 Reqable 就勾「转交给本地抓包工具」，把 8888 填到**那一栏** |
| 有 ARP 流量但代理没反应 | **没开 DNS 引流**。目标的流量只是「经过」本机，目的 IP 还是真实服务器 | 回 ARP 页勾上 DNS 引流，重新开始 |
| DNS 劫持数是 0 | 目标在用 **DoH / DoT**（加密 DNS），或者它直接用 IP 访问 | 在目标设备上关掉「安全 DNS / DoH」（Chrome：设置→隐私→安全→关闭「使用安全 DNS」），或换用目标 |

**HTTPS 额外一步**：点「导出根证书」，把 `netops-ca.crt` 装到**目标设备**的
「受信任的根证书颁发机构」里，否则它连不上（浏览器会报证书错误）。

### 想继续用 Reqable / Fiddler

在「流量劫持」页勾上 **「把流量转交给本地抓包工具」** 并填它的端口
（Reqable 默认 9000，Fiddler 默认 8888）。工具箱会把被劫持的连接
转成代理请求（HTTP 走代理格式、HTTPS 走 CONNECT 隧道）交给它处理。
**注意：本程序的监听端口仍然是 80/443，两者不是一回事。**

> **HTTPS 的前提**：不管用哪种方式，要解密 HTTPS 都得让**目标设备信任签发证书的根 CA**。
> 用「导出根证书」把 `netops-ca.crt` 导出，装到目标设备的
> 「受信任的根证书颁发机构」里即可（Fiddler 用 Fiddler 自己的 CA，同理）。

---

## 三、界面怎么用

打开后是 **左侧一棵导航树 + 右侧内容区**，整条工具链都平铺在这棵树里，
点一下即切换，不用在两层标签页里找：

```
🔍 发现与扫描
   🎯 资产发现        扫局域网：IP / MAC / 厂商 / 主机名 / 开放端口（可开深度探测做 TTL 系统指纹）
   🔎 端口扫描        TCP 扫描 + Banner 抓取
   📂 目录爆破        948 条内置字典，自动过滤软 404
⚡ 攻击与劫持
   ⚡ ARP 牵引 / 断网   双向中间人 / 单向抓包 / 断网(arp death) + DNS 引流
   🕵 流量劫持        看被牵引设备的请求，改包重放、下断点
   🕳 穿透隧道        端口转发（TCP/UDP）+ 正/反向 shell 交互控制台
   🎭 假服务          一键起 DNS / HTTP 服务，配合引流做取证演示
🛡 检测与报告
   🛡 安全体检        Redis/MongoDB/Docker/FTP… 未授权访问与错误配置快速指纹扫描
   📄 报告导出        把各页结果汇总成 Markdown / HTML 报告
📡 分析与诊断
   📡 抓包分析        实时抓包、TCP 会话重组导出、流量统计图、编辑重放、跳 Wireshark
   🩺 环境自检        权限/网卡/端口/防火墙体检 + 无害发包自检 + 导出报告
🔐 密码工具
   🔑 哈希与字典      哈希识别、字典爆破、社工字典生成
🧰 运维工具
   🖥 本机信息  📶 Ping 延迟  🧭 路由追踪  🌐 DNS 查询
   ⏻ 网络唤醒  🔗 HTTP 探测  🧮 子网计算  ⏱ 时间校准
```

左下角常驻一个 **「常用流程」** 提示卡；底部 **运行日志** 面板与主区域的
分隔条可以拖动调整高度。

### 新增工具速览

| 工具 | 能干什么 |
| --- | --- |
| **📂 目录爆破** | 948 条 CTF/渗透常见路径（`.git/HEAD`、`.env`、备份包、Swagger、flag…）× 8 种后缀，先探两个随机路径建立**软 404 基线**自动过滤假 200，结果可双击用浏览器打开、导出 CSV |
| **🛡 安全体检** | 20 项**只读探针**：Redis / Memcached / MongoDB / Elasticsearch / Docker API / ZooKeeper / CouchDB / YARN / Kibana / RabbitMQ / etcd / K8s 未授权，FTP 匿名、rsync 未授权、`.git` 泄露、VNC 无认证、目录列表… 按严重程度排序。弱口令检测默认关闭、需二次确认 |
| **🕳 穿透隧道** | TCP/UDP 端口转发（等价 lcx / netsh portproxy 的 GUI 版）；反向 shell 监听 + 交互控制台（命令历史、行尾选择）；正向连接。**只做连接管理与字节收发，不生成 payload、不做免杀/持久化** |
| **🎭 假服务** | 一键起本地 DNS（可配 A 记录、未命中转发上游或 NXDOMAIN）和 HTTP（固定内容 / 目录托管），带实时请求日志，配合引流做取证或钓鱼演示 |
| **📄 报告导出** | 一键采集资产 / 端口 / 安全体检 / HTTP 流量 / 目录爆破的结果，渲染成 Markdown 或 HTML（带风险配色和统计卡片） |
| **🔑 哈希与字典** | 识别 MD5/SHA/NTLM/bcrypt/`$6$`/JWT/Base64 等；字典爆破（内置 150 条弱口令 / 文件 / 自定义）；社工字典生成（姓名+年份+弱后缀组合） |
| **📡 抓包增强** | TCP 载荷按方向重组，可把「下载下来的文件」直接导出成二进制；协议分布 + Top 会话柱状图 |

---

### 卡住了？先看「🩺 环境自检」

被牵引设备的流量看不到、ARP 不生效之类的问题，直接点这一页的 **「重新体检」**，
它按链路顺序逐项打勾，**从上往下第一个 ❌ 就是卡住的地方**：

```
❌ ① 管理员权限：当前是普通用户
      → 关掉程序，重新启动并在 UAC 弹窗点「是」（或双击 启动.vbs）
✅ ③ 网卡：WLAN  192.168.5.22/24  网关 192.168.5.1
✅ ④ HTTP 监听端口 80：可以监听
❌ ⑤ 防火墙：Public 配置文件已开启，且没有入站放行规则
      → 点「放行防火墙端口」
❌ ⑦ DNS 引流：未启动
      → 回到 ARP 页勾上「DNS 引流」，重新开始牵引
```

配套还有 **「🔧 发包自检」**（只发正常的 ARP 请求，不做任何欺骗）：
检查本机 MAC / Npcap 设备名 / 能否向网关发包并收到应答 / 能否 ping 通目标 /
**目标 MAC 是否正确**。以及 **「导出报告」**，出问题直接贴给别人看。

---

## 四、各页面说明

### ⚡ ARP 牵引 / 断网

界面按四步排布，不会一屏按钮糊脸：

```
① 选网卡与网关  ② 选工作模式  ③ 选配套功能  ④ 开始
```

| 模式 | 效果 |
| --- | --- |
| **双向中间人** | 目标 ↔ 本机 ↔ 网关。目标不断网，流量经过本机，可抓包/改包/重放 |
| **单向抓包** | 只对目标冒充网关。目标会**断网**，适合快速抓一段 |
| **断网攻击 arp death** | 告诉目标「网关在一个不存在的 MAC 上」，流量进黑洞，直接踢下线 |

目标列表支持：全选 / 反选 / **删除选中**（或按 Delete）/ 清空 / **补全 MAC**；
IP、MAC、备注三列都能**双击直接改**（MAC 会自动规范成 `aa:bb:cc:dd:ee:ff`）；
从「资产发现」页导入时，已存在的行如果缺 MAC 会**自动补上**。

> 🛑 只能用于你本人拥有或已获书面授权的网络。
> 停止、关窗口、程序异常退出（`atexit`）都会自动把正确的 ARP 映射连发多次恢复；
> 另有独立的「🆘 紧急恢复」按钮。

### 🕵 流量劫持

* 实时请求列表：方法 / 状态码 / 主机 / 路径 / 大小（按时间顺序，不自动排序）
* 请求与响应全文，正文自动 gunzip / de-chunk
* **改后重放**：上面那块请求报文可以直接编辑（改请求行、头部、正文），点一下重发
* **断点**：填 URL 关键字或正则 → 命中就挂起，然后人工「放行挂起 / 丢弃挂起」；
  也可以开「挂起全部请求」做逐步调试
* 导出根证书、打开证书目录

### 📡 抓包分析

* scapy 实时抓包 + BPF 过滤 + 落盘 pcap + 一键用 Wireshark 打开
* **编辑并重放**：列表里选中任意一个包 → 改 MAC / IP / 端口 / TCP 标志 / 载荷 → 重新发出去
* 实时显示各协议包数与 pps

### 🎯 资产发现

留空=当前网段，也支持 `192.168.1.0/24`、`192.168.1.10-50`、逗号分隔多段、域名。
ARP 扫描（需管理员）最快最准；**没有管理员时**程序会在 ping 扫描之后再读一遍
本机 ARP 缓存，同样可以补齐 MAC 与厂商信息。
主机名来自 反向 DNS → NetBIOS → 可选 mDNS；厂商来自 500+ 内置 OUI + 可更新的 IEEE 库。

### 🔎 端口扫描

11 种预设 + 自定义（`22,80,8000-8100`），并发/超时/Banner 可调，导出 CSV。
如果开放比例异常高会给出黄色警告 —— 那通常是本机安全软件在伪造 TCP 握手，
不是目标真的全开。

### 🧰 运维工具

本机信息 / Ping 延迟折线 / 路由追踪 / DNS 查询（系统 DNS 不通自动回退公共 DNS）/
Wake-on-LAN / HTTP(S) 探测（含证书到期）/ 子网计算 / SNTP 时间校准。

---

## 五、目录结构

```
NetOpsToolbox/
├── main.py                 入口（启动自动提权 / 异常兜底 / --selftest）
├── 启动.vbs                无控制台窗口启动器
├── build_exe.py            一键打包单文件 exe
├── theme.py                配色与 QSS
├── config.json             配置（首次运行生成）
├── assets/                 图标资源（app.ico / app.png）
├── certs/                  MITM 根证书与动态站点证书（首次运行生成）
├── requirements.txt
├── selftest_core.py        核心层自检
├── selftest_ui.py          界面层自检
├── tools/
│   └── make_icon.py        生成 assets/app.ico
├── core/                   与界面无关的核心逻辑
│   ├── paths.py            路径解析（源码运行 / exe 运行都适用）
│   ├── hostinfo.py         网卡/网关/子网/权限/提权
│   ├── assets.py           资产发现
│   ├── oui.py              内置 OUI 厂商表
│   ├── ports.py            端口扫描
│   ├── arpmitm.py          ARP 牵引（双向/单向/断网）+ IP 转发
│   ├── dnsspoof.py         DNS 引流
│   ├── mitm.py             HTTP/HTTPS 透明拦截代理
│   ├── capture.py          抓包、流重组、过滤规则
│   ├── rawsock.py          二层收发共用套接字
│   ├── vulncheck.py        漏洞与指纹识别
│   ├── dirbrute.py         目录爆破
│   ├── tunnel.py           端口转发与反弹 shell
│   ├── fakeserv.py         假 DNS / 假 HTTP 服务
│   ├── hashkit.py          哈希计算与字典生成
│   ├── report.py           报告导出（MD / MHTML）
│   ├── netdiag.py          链路体检与防火墙操作
│   ├── tools.py            ping/traceroute/DNS/WOL/HTTP/SNTP
│   ├── appconfig.py        配置读写
│   └── logging_bus.py      日志总线
└── ui/
    ├── main_window.py      主窗口、左侧导航、日志面板、页面联动
    ├── widgets.py          通用控件（卡片/表格/图表/日志/安全槽）
    ├── tab_assets.py  tab_ports.py  tab_dirbrute.py
    ├── tab_arp.py     tab_mitm.py   tab_tunnel.py  tab_fakeserv.py
    ├── tab_capture.py tab_vuln.py   tab_report.py  tab_diag.py
    └── tab_tools.py   tab_hash.py
```

`core/` 完全不依赖 Qt，核心逻辑可以用 `python main.py --selftest` 脱离界面验证。

---

## 六、打包成单个 exe

```powershell
conda activate ai
pip install pyinstaller
python build_exe.py
```

产物是 `dist\NetOpsToolbox.exe`，**单文件、免安装、带图标**，双击即可运行
（会自己弹 UAC 提权）。打包参数都写在 `build_exe.py` 里：

* `--collect-all scapy` / `zeroconf`：这两个库大量模块是运行时才 import 的，静态分析看不到
* `CONDA_DLLS`：conda 把 OpenSSL / zlib / ffi 放在 `Library\bin`，不带上的话
  打出来的 exe 一碰 `ssl` / `hashlib` / `ctypes` 就崩
* `--add-data assets`：图标；`selftest_*.py` 也一起带上，方便直接验证打包结果

```powershell
# 打包后没有控制台，把自检结果写进文件来验证
.\dist\NetOpsToolbox.exe --selftest --selftest-out=selftest.txt

# 启动即退出时用它排查（单文件 + 控制台 + bootloader 日志）
python build_exe.py --debug
```

图标由 `tools/make_icon.py` 生成：脚本手写 ICO 容器，把 16~256 共 7 种尺寸
的 PNG 塞进同一个 `assets/app.ico`，所以任务栏、标题栏、Alt+Tab 都不会糊。
窗口图标和任务栏分组在 `main.py` 里通过 `setWindowIcon()` 与
`SetCurrentProcessExplicitAppUserModelID()` 设置。

---

## 七、常见问题

**Q：提权后还弹黑窗？**
用 `启动.vbs` 启动。自动提权本身已经改用 `pythonw.exe`，正常不会有控制台。

**Q：ARP 牵引开了，但「流量劫持」页一条都没有？**
99% 是没开 **DNS 引流**。ARP 只让流量经过本机，目标连的还是真实服务器 IP，
本地代理看不到。勾上「DNS 引流」再开始。

**Q：HTTPS 显示不出来 / 目标设备报证书错误？**
目标设备未信任本程序的根证书。到「流量劫持」页点「导出根证书」，
把 `netops-ca.crt` 装到目标设备的受信任根里。

**Q：抓包抓不到、但显示在跑？**
确认网卡选对、BPF 过滤写对（先用空过滤器试）。虚拟网卡（Tailscale、Wintun、
Wi-Fi Direct）通常抓不到有用流量。

**Q：端口扫描结果不对劲？**
见上文「开放比例异常」提示，优先怀疑本机安全软件/中间设备伪造握手。

**Q：退出后目标设备上不了网？**
程序停止/退出会自动恢复 ARP 表。如果进程被任务管理器强杀，点「🆘 紧急恢复」，
或让目标设备断网重连一次即可。

**Q：程序「闪退」了怎么办？**
先看同目录下的 **`crash.log`**（存在的话）。原因说明：

> PyQt5 在槽函数里出现未捕获异常时会直接调用 `abort()` 结束进程
> （退出码 `0xC0000409`）。若界面以 `pythonw` 启动且没有控制台，
> 表现就是毫无提示地退出。

本程序在 `main.py` 中安装了自定义的 `sys.excepthook` 与 `threading.excepthook`，
PyQt5 不会再 abort：异常会被**写入界面下方的日志面板**，同时记录到 `crash.log`，
程序继续运行。关键槽函数另外用 `@safe_slot` 做了兜底。

同目录下的 `.running` 文件用于记录运行状态与最近操作，正常退出时会被清除；
若上次未正常退出，启动时会在日志面板中提示。

`selftest_core.py` 第 9 节会完整跑一遍「启动牵引 → 停止恢复」的线程生命周期，
用于保证停止流程始终能干净收尾。
