# -*- coding: utf-8 -*-
"""
哈希识别 / 计算 / 爆破 / 字典生成
==================================

* identify_hash()：按长度 + 字符集 + 前缀猜哈希类型（能猜出多个候选就都返回）
* hash_text()：调 hashlib 算哈希，NTLM 会用 MD4（系统 OpenSSL 不给 md4 时自动降级）
* verify_hash()：比对明文与目标哈希（兼容 `$1$` / `$2b$` / `$6$` 这类 crypt 格式）
* crack_hash()：拿字典逐个试，带进度回调与取消
* gen_social_dict() / gen_mask_dict()：社工字典与掩码穷举
* DEFAULT_PASSWORDS：内置常见弱口令（中文环境）

纯逻辑，不依赖 Qt。对外主入口：identify_hash()、crack_hash()。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import itertools
import os
import re
import struct
from typing import Iterable, Iterator

from .logging_bus import log

# --------------------------------------------------------------------------- #
# 内置弱口令（中文环境常见：设备默认口令 + 拼音 + 常见撞库口令）
# --------------------------------------------------------------------------- #

DEFAULT_PASSWORDS: list[str] = [
    # —— 万金油 ——
    "123456", "123456789", "12345678", "1234567", "1234567890", "12345", "1234",
    "111111", "000000", "666666", "888888", "999999", "123123", "112233",
    "121212", "654321", "520520", "1314520", "5201314", "147258369",
    # —— 字母弱口令 ——
    "password", "password1", "password123", "passw0rd", "p@ssw0rd", "P@ssw0rd",
    "admin", "admin123", "admin888", "admin@123", "administrator", "root",
    "root123", "toor", "guest", "guest123", "test", "test123", "user", "user123",
    "qwerty", "qwerty123", "qwertyuiop", "abc123", "abcd1234", "a123456",
    "iloveyou", "welcome", "welcome1", "letmein", "monkey", "dragon",
    "master", "shadow", "sunshine", "princess", "football", "superman",
    "changeme", "default", "system", "manager", "operator", "service",
    # —— 中文拼音 / 国内常见 ——
    "woaini", "woaini1314", "woaini521", "woaini520", "woshishui", "nihao",
    "nihao123", "zhangsan", "zhangsan123", "lisi", "wangwu", "lihua",
    "xiaoming", "xiaohong", "zhonghua", "beijing", "shanghai", "shenzhen",
    "guangzhou", "hangzhou", "chengdu", "wuhan", "nanjing", "tianjin",
    "chongqing", "xian", "china", "chinese", "zhongguo", "hello123",
    "caonima", "nimabi", "shabi", "wodemima", "mima123", "mima123456",
    # —— 设备 / 厂商默认口令 ——
    "hik12345", "hikvision", "admin12345", "12345abc",
    "cisco", "cisco123", "huawei", "huawei123", "Huawei@123", "ruijie",
    "h3c", "h3capadmin", "tp-link", "tplink", "tenda", "mercury",
    "dlink", "netgear", "ubnt", "superadmin", "support", "security",
    "pass", "pass123", "88888888", "666888", "168168", "a1b2c3",
    # —— 键盘与符号组合 ——
    "1qaz2wsx", "1q2w3e4r", "1qaz@wsx", "qazwsx", "zaq12wsx", "q1w2e3r4",
    "asdfgh", "asdfghjkl", "zxcvbnm", "zxcvbn", "qwe123", "qweasd",
    "!qaz2wsx", "@wsx3edc", "Aa123456", "Aa123456!", "Abc123456",
    "Welcome123", "Admin@123", "Root@123", "Test@123", "Qwer1234",
]

# --------------------------------------------------------------------------- #
# 算法表
# --------------------------------------------------------------------------- #

# 算法名 -> hashlib 名称（None 表示要特殊处理）
HASHLIB_ALGOS: dict[str, str | None] = {
    "md5": "md5", "sha1": "sha1", "sha224": "sha224", "sha256": "sha256",
    "sha384": "sha384", "sha512": "sha512", "sha3_256": "sha3_256",
    "sha3_512": "sha3_512", "ripemd160": "ripemd160", "sm3": "sm3",
    "ntlm": None,
}

# 算法名 -> 摘要位数（用于识别结果与展示）
ALGO_BITS: dict[str, int] = {
    "MD5": 128, "NTLM": 128, "LM": 128, "MySQL4": 128,
    "SHA1": 160, "MySQL5": 160, "RIPEMD160": 160,
    "SHA224": 224, "SHA256": 256, "SHA384": 384, "SHA512": 512,
    "SHA3-256": 256, "SHA3-512": 512, "bcrypt": 184, "SM3": 256,
    "SHA512-crypt": 512, "MD5-crypt": 128, "JWT": 0, "Base64": 0,
    "URL 编码": 0, "Hex 编码": 0,
}

# 32 位十六进制同时可能是这几种，识别时一起给出来
_HEX32_ALIASES = [
    {"algo": "MD5", "bits": 128, "note": "32 位十六进制（最常见，也可能是 NTLM / MySQL4）"},
    {"algo": "NTLM", "bits": 128, "note": "Windows 账户口令哈希（与 MD5 同为 32 位十六进制）"},
    {"algo": "MySQL4", "bits": 128, "note": "MySQL 4.1 之前 PASSWORD() 出来的 16 字节十六进制"},
]

_RE_HEX = re.compile(r"^[0-9a-fA-F]+$")
_RE_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_RE_BCRYPT = re.compile(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$")
_RE_SHA512_CRYPT = re.compile(r"^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$")
_RE_SHA256_CRYPT = re.compile(r"^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$")
_RE_MD5_CRYPT = re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$")
_RE_URLENC = re.compile(r"%[0-9a-fA-F]{2}")
_RE_JWT = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$")


def _hex_note(bits: int, extra: str = "") -> str:
    txt = f"{bits // 4} 位十六进制"
    return f"{txt}，{extra}" if extra else txt


# --------------------------------------------------------------------------- #
# 哈希识别
# --------------------------------------------------------------------------- #

def identify_hash(text: str) -> list[dict]:
    """
    根据长度与字符集猜哈希类型，返回候选列表（可能多个）：

        identify_hash("e10adc3949ba59abbe56e057f20f883e")
        -> [{"algo": "MD5", "bits": 128, "note": "32 位十六进制…"}, ...]

    只做「形状」判断，不做数学验证，所以一律按「可能性从高到低」排列。
    """
    cands: list[dict] = []
    s = (text or "").strip()
    if not s:
        return cands

    def add(algo: str, note: str, bits: int | None = None):
        if any(c["algo"] == algo for c in cands):
            return
        cands.append({"algo": algo, "bits": ALGO_BITS.get(algo, 0) if bits is None else bits,
                      "note": note})

    # ---- 带固定前缀/结构的格式，优先判断 ----
    if _RE_BCRYPT.match(s):
        add("bcrypt", "Blowfish 慢哈希，带盐，无法直接用字典明文比对（需 bcrypt 库）")
        return cands

    if s.startswith(("$2a$", "$2b$", "$2y$", "$2x$", "$2$")):
        add("bcrypt", "bcrypt 前缀，但长度/字符集不像标准 60 字符摘要")
        return cands

    if s.startswith("$6$"):
        add("SHA512-crypt", "Linux /etc/shadow 的 SHA-512 加盐格式（$6$salt$hash）")
        return cands

    if s.startswith("$5$"):
        add("SHA256-crypt", "Linux SHA-256 加盐格式（$5$salt$hash）")
        return cands

    if s.startswith("$1$"):
        add("MD5-crypt", "Linux / Apache .htpasswd 的 MD5 加盐格式（$1$salt$hash）")
        return cands

    if s.startswith(("$argon2", "$y$", "$7$", "$2")):
        add("其它 crypt", f"crypt(3) 家族格式：{s[:7]}…")
        return cands

    if _RE_JWT.match(s):
        add("JWT", "三段点分结构（header.payload.signature），通常还需 Base64URL 解码看内容")
        return cands

    if s.startswith("*") and len(s) == 41 and _RE_HEX.match(s[1:]):
        add("MySQL5", "MySQL 4.1+ PASSWORD() 结果：* + 40 位十六进制（大写 SHA1）")
        return cands

    if s.startswith("{") and "}" in s[:12]:
        add("其它", f"带标签格式：{s[:s.index('}') + 1]}…（如 {{SSHA}} / {{CRYPT}} / {{MD5}}）")
        return cands

    # ---- 十六进制长度表 ----
    if _RE_HEX.match(s):
        n = len(s)
        table = {
            8: ("CRC32", 32, "8 位十六进制，常见于 CRC32 / 校验和"),
            16: ("MySQL4", 128, "16 位十六进制，MySQL 4.1 之前 PASSWORD() 的结果"),
            32: None,      # 单独处理，候选多
            40: ("SHA1", 160, "40 位十六进制（也可能是 MySQL5 去掉 * 号）"),
            56: ("SHA224", 224, "56 位十六进制"),
            64: ("SHA256", 256, "64 位十六进制；NTLM+用户名 的加盐组合也是这个长度"),
            96: ("SHA384", 384, "96 位十六进制"),
            128: ("SHA512", 512, "128 位十六进制；Windows 域内 Kerberos 凭据常见"),
        }
        if n == 32:
            for item in _HEX32_ALIASES:
                add(item["algo"], item["note"], item["bits"])
            return cands
        if n == 40:
            add("SHA1", table[40][2])
            add("MySQL5", "40 位十六进制，MySQL 4.1+ PASSWORD() 内部 SHA1（完整格式带 * 前缀）")
            add("RIPEMD160", "40 位十六进制，也可能是 RIPEMD-160")
            return cands
        if n in table:
            algo, bits, note = table[n]
            add(algo, note, bits)
            return cands
        # 其它长度的纯十六进制，只能是「某种编码/自定义摘要」
        if n >= 32:
            add("SHA 系列（长度异常）", f"{n} 位十六进制，不是标准摘要长度，可能是加盐拼接")
            return cands

    # ---- 百分号编码 ----
    if _RE_URLENC.search(s):
        add("URL 编码", "含 %XX 转义，可用 urllib.parse.unquote 还原（中文会是 %E4%B8%AD 这种）")

    # ---- Base64 ----
    b64_hit = False
    if len(s) % 4 == 0 and len(s) >= 8 and _RE_B64.match(s):
        if not (len(s) % 2 == 0 and _RE_HEX.match(s)):      # 纯十六进制不算 Base64
            try:
                raw = base64.b64decode(s, validate=True)
                b64_hit = bool(raw)
                if b64_hit:
                    add("Base64", f"可正常解码为 {len(raw)} 字节二进制"
                                  "（Base64 没有校验位，只能算「像」）")
            except (binascii.Error, ValueError):
                b64_hit = False
    # 无填充的 Base64（长度 %4 == 2 或 3）也认，但必须混有大写/数字，
    # 否则 "abcabc" 这种普通单词会被误判
    if not b64_hit and len(s) >= 8 and len(s) % 4 in (2, 3) \
            and re.fullmatch(r"[A-Za-z0-9+/]+", s) \
            and re.search(r"[A-Z0-9+/]", s):
        add("Base64", "字符集与长度符合无填充 Base64（未严格校验解码结果）")

    # ---- Base64URL（JWT 片段常见） ----
    if not b64_hit and "-" in s and "_" in s and re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", s):
        add("Base64URL", "含 - 与 _ 的 URL 安全变体（JWT / 文件下载链接常见）")

    # ---- 十六进制编码（可打印文本被转成 hex） ----
    if _RE_HEX.match(s) and len(s) % 2 == 0:
        try:
            raw = bytes.fromhex(s)
            printable = sum(1 for b in raw if 32 <= b < 127) / max(1, len(raw))
            if printable > 0.85 and len(raw) >= 3:
                add("Hex 编码", f"十六进制解码后是 {printable:.0%} 可打印文本："
                                f"{raw[:24].decode('latin-1')}…")
        except ValueError:
            pass

    # ---- 兜底 ----
    if not cands:
        if len(s) >= 20:
            add("未知/非标准", f"长度 {len(s)}，字符集不匹配已知哈希或编码格式")
        else:
            add("太短", f"只有 {len(s)} 个字符，不像完整哈希（口令字典里倒是常见）")
    return cands


def describe_identify(text: str) -> str:
    """把 identify_hash() 的结果压成一句话，给日志/状态标签用。"""
    cands = identify_hash(text)
    if not cands:
        return "没有可识别的内容"
    return "；".join(f"{c['algo']}（{c['note']}）" for c in cands[:3])


# --------------------------------------------------------------------------- #
# NTLM 需要的 MD4（RFC 1320 纯 Python 实现）
# --------------------------------------------------------------------------- #

def _md4(data: bytes) -> bytes:
    """纯 Python MD4，给 NTLM 用（OpenSSL 3.x 默认不提供 md4）。"""
    bit_len = len(data) * 8        # 注意：要记原始长度，不能在后补位之后再算
    msg = bytearray(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    mask = 0xFFFFFFFF

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & mask

    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    for off in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", bytes(msg[off:off + 64])))
        a, b, c, d = a0, b0, c0, d0

        # 第一轮：F 函数，X 顺序 0..15，左移 (3, 7, 11, 19)
        s = (3, 7, 11, 19)
        for i in range(16):
            k, m = i % 4, x[i]
            if k == 0:
                a = rol((a + f(b, c, d) + m) & mask, s[k])
            elif k == 1:
                d = rol((d + f(a, b, c) + m) & mask, s[k])
            elif k == 2:
                c = rol((c + f(d, a, b) + m) & mask, s[k])
            else:
                b = rol((b + f(c, d, a) + m) & mask, s[k])

        # 第二轮：G 函数，X 顺序按列取（0,4,8,12,1,5,…），左移 (3, 5, 9, 13)
        s = (3, 5, 9, 13)
        for i in range(16):
            k, m = i % 4, x[(i % 4) * 4 + i // 4]
            if k == 0:
                a = rol((a + g(b, c, d) + m + 0x5A827999) & mask, s[k])
            elif k == 1:
                d = rol((d + g(a, b, c) + m + 0x5A827999) & mask, s[k])
            elif k == 2:
                c = rol((c + g(d, a, b) + m + 0x5A827999) & mask, s[k])
            else:
                b = rol((b + g(c, d, a) + m + 0x5A827999) & mask, s[k])

        # 第三轮：H 函数，固定打乱顺序，左移 (3, 9, 11, 15)
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        s = (3, 9, 11, 15)
        for i, idx in enumerate(order):
            k, m = i % 4, x[idx]
            if k == 0:
                a = rol((a + h(b, c, d) + m + 0x6ED9EBA1) & mask, s[k])
            elif k == 1:
                d = rol((d + h(a, b, c) + m + 0x6ED9EBA1) & mask, s[k])
            elif k == 2:
                c = rol((c + h(d, a, b) + m + 0x6ED9EBA1) & mask, s[k])
            else:
                b = rol((b + h(c, d, a) + m + 0x6ED9EBA1) & mask, s[k])

        a0 = (a0 + a) & mask
        b0 = (b0 + b) & mask
        c0 = (c0 + c) & mask
        d0 = (d0 + d) & mask

    return struct.pack("<4I", a0, b0, c0, d0)


def _ntlm_digest(text: str) -> bytes:
    """
    NTLM 口令哈希：把口令按 UTF-16LE 编码后取 MD4。
    优先用系统 OpenSSL 的 md4；没有（OpenSSL 3.x 常见）就走纯 Python 实现。
    """
    raw = (text or "").encode("utf-16-le")
    try:
        h = hashlib.new("md4")
        h.update(raw)
        return h.digest()
    except (ValueError, TypeError, OSError):
        return _md4(raw)


def ntlm_available() -> bool:
    """当前环境能不能算 NTLM（纯 Python 兜底基本总是可用）。"""
    try:
        _ntlm_digest("test")
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# 计算与校验
# --------------------------------------------------------------------------- #

def supported_algos() -> list[str]:
    """当前环境真正可用的算法名（界面下拉用）。"""
    names = []
    for name, hl in HASHLIB_ALGOS.items():
        if hl is None:
            if ntlm_available():
                names.append(name)
            continue
        if hl in hashlib.algorithms_available:
            names.append(name)
    return names


def hash_text(algo: str, text: str) -> str:
    """
    计算哈希，返回小写十六进制字符串。

    * algo 支持 md5 / sha1 / sha224 / sha256 / sha384 / sha512 / sha3_256 /
      sha3_512 / ripemd160 / sm3 / ntlm
    * ntlm 用 MD4（UTF-16LE 编码的口令）；系统 OpenSSL 不提供 md4 时自动
      降级到内置纯 Python 实现，并在日志里说明。
    * 算法名不认识时抛 ValueError，界面层用 safe_slot 兜住。
    """
    name = (algo or "").strip().lower().replace("-", "_")
    if name not in HASHLIB_ALGOS:
        raise ValueError(f"不支持的算法：{algo}（可用：{', '.join(supported_algos())}）")

    if name == "ntlm":
        try:
            hashlib.new("md4")
        except (ValueError, TypeError, OSError):
            log("系统 OpenSSL 没有 md4，NTLM 已自动降级为内置 MD4 实现", "warn", "hash")
        return _ntlm_digest(text).hex()

    hl = HASHLIB_ALGOS[name]
    try:
        h = hashlib.new(hl)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"当前环境不支持 {algo}：{exc}") from exc
    h.update((text or "").encode("utf-8", "surrogatepass"))
    return h.hexdigest()


def _is_crypt_format(target: str) -> bool:
    """`$1$` / `$5$` / `$6$` / `$2b$` 这类自带盐的格式，要用 crypt 校验。"""
    t = (target or "").strip()
    return len(t) > 3 and t.startswith("$") and t.count("$") >= 2


def _crypt_verify(plain: str, target: str) -> bool | None:
    """用系统 crypt 校验加盐哈希；返回 None 表示当前环境校验不了。"""
    try:
        import crypt
    except ImportError:
        return None
    try:
        return crypt.crypt(plain, target) == target
    except (ValueError, OSError, TypeError):
        return None


def verify_hash(algo: str, plain: str, target: str) -> bool:
    """
    校验明文是否等于目标哈希。十六进制比较忽略大小写；
    `$1$`/`$5$`/`$6$`/`$2b$` 这类加盐格式交给系统 crypt 处理。
    """
    tgt = (target or "").strip()
    if not tgt:
        return False

    if _is_crypt_format(tgt):
        got = _crypt_verify(plain, tgt)
        if got is not None:
            return got
        log("当前环境没有可用的 crypt 模块，无法校验加盐哈希（Windows 上属正常）",
            "warn", "hash")
        return False

    name = (algo or "").strip().lower()
    if name in ("", "auto"):
        cands = identify_hash(tgt)
        name = cands[0]["algo"].lower() if cands else "md5"
        name = {"mysql5": "sha1", "mysql4": "md5", "ntlm": "ntlm"}.get(name, name)
    try:
        return hash_text(name, plain).lower() == tgt.lower()
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# 爆破
# --------------------------------------------------------------------------- #

def _crack_algo(target: str, algo: str) -> str:
    """把 algo="auto" 解析成真正要算的算法名。"""
    name = (algo or "auto").strip().lower()
    if name not in ("", "auto"):
        return name
    cands = identify_hash(target)
    if not cands:
        return "md5"
    first = cands[0]["algo"].lower()
    # 识别用的是展示名（MySQL5 等），转成 hashlib 算法名
    return {
        "mysql5": "sha1", "mysql4": "md5", "ntlm": "ntlm",
        "sha1": "sha1", "md5": "md5", "sha224": "sha224", "sha256": "sha256",
        "sha384": "sha384", "sha512": "sha512", "ripemd160": "ripemd160",
    }.get(first, first)


def crack_hash(target: str, words: Iterable[str], algo: str = "auto",
               on_progress=None, cancel=None) -> dict:
    """
    拿字典逐个试目标哈希。

    :param target: 目标哈希（支持带 * 前缀的 MySQL5、带盐的 $1$/$6$/$2b$）
    :param words:  口令候选（可迭代，字符串或字节都行）
    :param algo:   "auto" 时用 identify_hash() 的第一个候选
    :param on_progress: on_progress(tried, total, current_word)，每 200 次回调一次
    :param cancel: threading.Event，置位后立刻返回
    :return: {"found": bool, "plain": str, "algo": str, "tried": int}
    """
    tgt = (target or "").strip()
    result = {"found": False, "plain": "", "algo": "", "tried": 0}
    if not tgt:
        return result

    name = _crack_algo(tgt, algo)
    result["algo"] = name

    # MySQL5 的 * 前缀只是标记，比对时要去掉
    cmp_target = tgt
    if tgt.startswith("*") and len(tgt) == 41:
        cmp_target = tgt[1:]

    is_ntlm = name == "ntlm"
    is_crypt = _is_crypt_format(tgt)
    if is_crypt and _crypt_verify("x", tgt) is None:
        log("目标看起来是加盐哈希，但当前环境没有 crypt 模块，只能跳过", "warn", "hash")
        return result
    # ntlm 没有 hashlib 实现（要自己走 MD4），所以不建 hashlib 对象
    fast = None
    if not is_crypt and not is_ntlm:
        try:
            fast = hashlib.new(HASHLIB_ALGOS.get(name, "md5"))
        except (ValueError, TypeError):
            log(f"爆破时算法 {name} 不可用，已放弃", "error", "hash")
            return result

    try:
        total = len(words)          # 列表能直接给总数，生成器就是 0
    except TypeError:
        total = 0

    want = cmp_target.lower() if not is_crypt else cmp_target
    tried = 0
    for word in words:
        if cancel is not None and cancel.is_set():
            log(f"爆破已取消（试了 {tried} 个）", "warn", "hash")
            break
        plain = word.decode("utf-8", "replace") if isinstance(word, (bytes, bytearray)) else str(word)
        tried += 1
        hit = False
        if is_crypt:
            hit = _crypt_verify(plain, tgt) is True
        elif is_ntlm:
            hit = _ntlm_digest(plain).hex().lower() == want
        else:
            fast2 = fast.copy()
            fast2.update(plain.encode("utf-8", "surrogatepass"))
            hit = fast2.hexdigest().lower() == want
        if hit:
            result.update({"found": True, "plain": plain, "tried": tried})
            log(f"爆破成功：{name.upper()} 明文为 {plain}（试了 {tried} 个候选）",
                "success", "hash")
            if on_progress:
                on_progress(tried, total, plain)
            return result
        if on_progress and tried % 200 == 0:
            on_progress(tried, total, plain)

    result["tried"] = tried
    log(f"爆破结束：未命中（算法 {name.upper()}，共试 {tried} 个候选）", "warn", "hash")
    return result


# --------------------------------------------------------------------------- #
# 字典
# --------------------------------------------------------------------------- #

def load_wordlist(path: str) -> list[str]:
    """
    读字典文件：一行一个口令，utf-8 读不动就退回 gb18030，去重且保持原顺序。
    空行与 `#` 开头的注释行会被丢掉。
    """
    text = ""
    used = ""
    for enc in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            with open(path, "r", encoding=enc, errors="strict") as fh:
                text = fh.read()
            used = enc
            break
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            log(f"读取字典失败：{exc}", "error", "hash")
            return []
    if not used:
        # 编码都很乱：强行按 utf-8 忽略错误读一遍，能救多少算多少
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
            used = "utf-8(容错)"
        except OSError as exc:
            log(f"读取字典失败：{exc}", "error", "hash")
            return []

    seen: set[str] = set()
    words: list[str] = []
    for line in text.splitlines():
        w = line.strip()
        if not w or w.startswith("#"):
            continue
        if w not in seen:
            seen.add(w)
            words.append(w)
    log(f"字典 {os.path.basename(path)} 读入 {len(words)} 条（编码 {used}）", "info", "hash")
    return words


def _split_tokens(text) -> list[str]:
    """把「张三, zhangsan 李四」这种输入切成干净的小写词条（保留原样一份）。"""
    if not text:
        return []
    if isinstance(text, (list, tuple, set)):
        items = [str(x) for x in text]
    else:
        items = re.split(r"[,，;；\s、]+", str(text))
    out: list[str] = []
    for it in items:
        it = it.strip()
        if it and it not in out:
            out.append(it)
    return out


def gen_social_dict(names=(), keywords=(), digits: bool = True, years=None,
                    specials=None, min_len: int = 6, max_len: int = 16,
                    cap: int = 200000) -> list[str]:
    """
    社工字典：名字 / 关键词做大小写变形，再拼数字、年份、特殊符号与常见后缀。

    :param names:     姓名拼音、英文名、账号名（"zhangsan" 或 "张三,zhangsan"）
    :param keywords:  单位、项目、爱好、品牌等关键词
    :param digits:    True 用 0-9999；也可直接传一个数字列表
    :param years:     年份列表，默认 1990-2026
    :param specials:  特殊符号列表，默认 ["!", "@", "#", "$", ".", "_"]
    :param cap:       数量上限，防止爆内存（默认 20 万）
    """
    bases: list[str] = []
    for raw in list(_split_tokens(names)) + list(_split_tokens(keywords)):
        for v in (raw, raw.lower(), raw.upper(), raw.capitalize()):
            if v and v not in bases:
                bases.append(v)
    if not bases:
        log("没有可用的名字/关键词，社工字典为空", "warn", "hash")
        return []

    if digits is True:
        nums = [str(i) for i in range(10000)]
    elif digits:
        nums = [str(d) for d in digits]
    else:
        nums = []
    if years is None:
        year_list = [str(y) for y in range(1990, 2027)]
    else:
        year_list = [str(y) for y in years]
    spec_list = list(specials) if specials else ["!", "@", "#", "$", ".", "_"]

    suffixes = ["123", "1234", "12345", "123456", "12345678", "1", "01", "001",
                "666", "888", "99", "520", "521", "1314", "admin", "abc", "qwer"]
    # 特殊符号只留高频的几个，符号夹数字的组合最容易命中
    hot_specs = [sp + n for sp in spec_list
                 for n in ("123", "123456", "520", "521", "888", "1", "")]

    out: list[str] = []
    seen: set[str] = set()

    def push(word: str) -> bool:
        """返回 False 表示已经到上限，调用方要停。"""
        if not (min_len <= len(word) <= max_len):
            return True
        if word in seen:
            return True
        seen.add(word)
        out.append(word)
        return len(out) < cap

    full = False

    def fill(prefixes, maker) -> bool:
        """
        广度优先地拼：先让每个 base 都拿到这批后缀，再拼下一批。
        否则第一个名字会把 10000 个数字全吃光，后面的名字一条都出不来。
        返回 False 表示已经到上限，调用方要停。
        """
        nonlocal full
        for pfx in prefixes:
            for base in bases:
                if not push(maker(base, pfx)):
                    full = True
                    return False
        return True

    # 按「命中率从高到低」逐批拼，批次内部再轮着给每个 base 机会。
    # 数字 0-9999 放最后：它一个人就能吃满 20 万的上限。
    fill(["", "1", "2", "3", "12", "123", "1234", "12345", "123456", "12345678"],
         lambda b, p: b + p)
    if not full:
        fill(year_list, lambda b, y: b + y)
    if not full:
        fill(suffixes, lambda b, s: b + s)
    if not full:
        fill(hot_specs, lambda b, sp: b + sp)
    if not full:
        fill(nums, lambda b, n: b + n)
    # 大小写变形（大写、首字母大写、倒序）也常见，最后补一轮
    if not full:
        for base in bases:
            forms = [base.lower(), base.upper(), base.capitalize(),
                     base[::-1] if len(base) > 3 else base]
            for f in forms:
                fill(["", "123", "123456", "@123", "!@#"] + year_list[-6:],
                     lambda b, s: b + s)
                if full:
                    break
            if full:
                break

    log(f"社工字典生成完毕：{len(out)} 条（上限 {cap}）"
        + ("，已达上限已截断" if full else ""),
        "warn" if full else "success", "hash")
    return out


def gen_mask_dict(charset: str, length: int, cap: int = 200000) -> Iterator[str]:
    """
    按字符集穷举（掩码）生成候选，惰性产出，内存友好。

        gen_mask_dict("0123456789", 4)   # 0000 ~ 9999
        gen_mask_dict("abc123", 3)

    超过 cap 个组合时只产前 cap 个（并记一条日志提醒）。
    """
    cs = "".join(dict.fromkeys(charset or ""))
    if not cs:
        log("字符集为空，掩码字典没有内容", "warn", "hash")
        return
    if length <= 0:
        log("长度必须大于 0", "warn", "hash")
        return

    total = len(cs) ** length
    if total > cap:
        log(f"掩码组合共 {total} 个，超过上限 {cap}，只生成前 {cap} 个",
            "warn", "hash")
    emitted = 0
    for combo in itertools.product(cs, repeat=length):
        if emitted >= cap:
            return
        emitted += 1
        yield "".join(combo)


# --------------------------------------------------------------------------- #
# 便捷入口
# --------------------------------------------------------------------------- #

def quick_crack(target: str, words: Iterable[str], algo: str = "auto",
                cancel=None) -> dict:
    """不带进度回调的爆破（脚本 / 自检用）。"""
    return crack_hash(target, words, algo=algo, cancel=cancel)
