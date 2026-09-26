# -*- coding: utf-8 -*-
"""
目录爆破 / 敏感路径探测
=======================

* 内置字典：面向 CTF / 渗透测试的常见路径、备份、源码泄露、接口（900+ 条）
* requests 并发探测（ThreadPoolExecutor），只回传值得关注的状态码
* 自动过滤「软 404」：先探一个随机不存在的路径当基线，命中基线的结果丢掉
* 尽量少给结果表添垃圾：目录条目不再叠后缀，带后缀的条目只再试备份类后缀

对外主入口：scan()
"""

from __future__ import annotations

import concurrent.futures as cf
import random
import re
import string
import threading
from dataclasses import dataclass

from .logging_bus import log

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    _HAS_REQUESTS = True
except Exception:               # 没装 requests 也不让整个程序起不来
    requests = None
    InsecureRequestWarning = None
    _HAS_REQUESTS = False

SOURCE = "dirbrute"

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

# 只把这些状态码当作「值得关注」的结果回传
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}

# 默认后缀列表（"" = 无后缀，即字典原条目）
EXTENSIONS: list[str] = ["", ".php", ".html", ".txt", ".bak", ".zip", ".js", ".json"]

# 已经带后缀的条目（index.php / robots.txt）只再试这些「备份 / 泄露」后缀，
# 否则会生成 index.php.php、robots.txt.html 之类的垃圾请求
BACKUP_EXTS = (".bak", ".zip", ".txt", ".old", ".save", ".swp", ".sql", ".rar", ".tar.gz")

# 命中这些关键字的路径值得重点看（summarize 里用来自检提示）
SENSITIVE_HINTS = (".git", ".svn", ".env", ".ds_store", "backup", ".bak", ".sql",
                   ".zip", ".rar", "config", "admin", "manage", "login", "flag",
                   "phpmyadmin", "swagger", "api-docs", "actuator", "upload",
                   "phpinfo", "shell", "jenkins", "druid")

_ABS_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_EXT_RE = re.compile(r"\.[A-Za-z0-9]{1,6}$")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

_MAX_BODY = 64 * 1024          # 抓标题时最多读这么多正文
_MAX_COUNT = 5 * 1024 * 1024   # 统计长度时最多下载这么多（再大就按上限记）


# --------------------------------------------------------------------------- #
# 内置字典（CTF / 渗透常见路径）
# --------------------------------------------------------------------------- #

DEFAULT_PATHS: list[str] = [
    # ---- 后台 / 管理入口 ----
    "admin", "administrator", "admin.php", "admin.html", "admin.htm", "admin/",
    "admin1", "admin2", "admin123", "adminarea", "admin_area", "admin_area/",
    "admincp", "admincp/", "adminpanel", "adminpanel/", "admin_login",
    "admin-login", "admin_login.php", "admin/login", "admin/login.php",
    "admin/index.php", "admin/admin.php", "admin/home", "admin/main.php",
    "admin/dashboard", "admin/panel", "admin.php.bak",
    "manage", "manage/", "manager", "manager/", "management", "management/",
    "manage/login", "dashboard", "dashboard/", "console", "console/",
    "controlpanel", "controlpanel/", "control", "cpanel", "webadmin",
    "webadmin/", "sysadmin", "panel", "panel/", "backend", "backoffice",
    "login", "login.php", "login.html", "login/", "login.jsp", "login.aspx",
    "login.do", "logon", "signin", "sign_in", "sign-in", "user/login",
    "users/login", "account/login", "member/login", "auth", "auth/",
    "auth/login", "authenticate", "authorize", "oauth", "oauth2", "oauth/token",
    "sso", "sso/", "saml", "cas", "logout", "register", "register.php",
    "signup", "sign-up",
    "wp-admin", "wp-admin/", "wp-admin/index.php", "wp-login.php", "wp-content",
    "wp-content/", "wp-content/uploads", "wp-includes", "wp-json",
    "wp-json/wp/v2/users", "xmlrpc.php", "wordpress", "wordpress/", "joomla",
    "joomla/", "administrator/index.php",
    "phpmyadmin", "phpMyAdmin", "phpmyadmin/", "phpMyAdmin/", "pma", "pma/",
    "myadmin", "mysql", "mysqladmin", "dbadmin", "sqladmin", "pgadmin",
    "phppgadmin", "adminer.php", "adminer", "adminer/", "phpMyAdmin/setup/",

    # ---- 备份 / 源码泄露 ----
    ".git/HEAD", ".git/config", ".git/index", ".git/description",
    ".git/logs/HEAD", ".git/refs/heads/master", ".git/packed-refs",
    ".gitignore", ".gitattributes", ".git/",
    ".svn/entries", ".svn/wc.db", ".svn/", ".hg/", ".hg/store", ".bzr/",
    ".bzrignore", ".cvsignore", "CVS/Entries",
    ".env", ".env.local", ".env.dev", ".env.development", ".env.prod",
    ".env.production", ".env.test", ".env.bak", ".env.backup", ".env.old",
    ".env.example", ".env.save", ".env.swp", "env", "env.js", "env.json",
    ".DS_Store", ".htaccess", ".htaccess.bak", ".htaccess.old", ".htpasswd",
    ".user.ini", ".user.ini.bak", ".bash_history", ".zsh_history",
    ".ssh/id_rsa", ".ssh/id_rsa.pub", ".ssh/authorized_keys", ".ssh/known_hosts",
    ".ssh/config", ".idea/workspace.xml", ".idea/modules.xml",
    ".vscode/settings.json", ".vscode/launch.json",
    "www.zip", "www.rar", "www.tar.gz", "www.tar", "wwwroot.zip", "wwwroot.rar",
    "wwwroot.tar.gz", "wwwroot/", "web.zip", "web.rar", "web.tar.gz",
    "website.zip", "site.zip", "site.rar", "public.zip", "html.zip",
    "backup.zip", "backup.rar", "backup.tar.gz", "backup.tar", "backup.7z",
    "backups.zip", "source.zip", "source.rar", "src.zip", "code.zip",
    "archive.zip", "dist.zip", "release.zip", "sql.zip", "sql.tar.gz",
    "backup.sql", "backup.sql.gz", "db.sql", "db.sql.gz", "database.sql",
    "dump.sql", "data.sql", "mysql.sql", "test.sql", "1.sql",
    "index.php.bak", "index.php~", "index.php.swp", "index.php.save",
    "index.php.old", "index.php.orig", "index.php.txt", "index.php.zip",
    "index.bak", "index.old", "index.zip", "index.tar.gz", "index.html.bak",
    "index.jsp.bak", "index.asp.bak", "main.php.bak", "test.php.bak",
    "config.php.bak", "config.php~", "config.php.swp", "config.php.old",
    "config.php.save", "config.bak", "config.old", "robots.txt.bak",
    "web.config", "config.php", "config.inc.php", "config.inc",
    "configuration.php", "configuration.inc.php", "settings.php", "settings.py",
    "settings.json", "local_settings.py", "config.json", "config.yaml",
    "config.yml", "config.xml", "config.txt",
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    "yarn.lock", "requirements.txt", "Pipfile", "Pipfile.lock", "Gemfile",
    "Gemfile.lock", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerenv", "Makefile", "pom.xml", "build.gradle", "build.xml",
    ".npmrc", ".babelrc", ".eslintrc", ".eslintrc.js", ".prettierrc",
    ".editorconfig", ".travis.yml", ".gitlab-ci.yml", ".github/workflows/main.yml",
    "Jenkinsfile", ".dockerignore", "app.js.map", "main.js.map", "bundle.js.map",

    # ---- 常见接口 ----
    "api", "api/", "api/v1", "api/v1/", "api/v2", "api/v3", "api/v1/users",
    "api/v1/user", "api/v1/login", "api/v1/admin", "api/v1/config",
    "api/v1/info", "api/v1/status", "api/v1/health", "api/v1/version",
    "api/v1/token", "api/v1/auth", "api/v1/upload", "api/v1/files",
    "api/v1/search", "api/v1/flag", "api/user", "api/users", "api/login",
    "api/admin", "api/config", "api/info", "api/status", "api/health",
    "api/version", "api/token", "api/auth", "api/upload", "api/files",
    "api/docs", "api/swagger", "api/swagger.json", "api-docs", "api-docs/",
    "api-docs.json", "rest", "rest/", "rest/api", "rest/v1", "rest/user",
    "rest/users", "graphql", "graphql/", "graphiql", "graphql/console",
    "graphql/schema", "graphql.php",
    "swagger-ui.html", "swagger-ui/", "swagger-ui/index.html",
    "swagger/index.html", "swagger.json", "swagger.yaml", "swagger.yml",
    "swagger-resources", "v2/api-docs", "v3/api-docs", "openapi.json",
    "openapi.yaml", "redoc.html", "docs/", "docs/index.html",
    "actuator", "actuator/health", "actuator/info", "actuator/env",
    "actuator/beans", "actuator/mappings", "actuator/metrics", "actuator/trace",
    "actuator/dump", "actuator/heapdump", "actuator/httptrace",
    "actuator/configprops", "actuator/loggers",
    "health", "healthz", "health/", "status", "status/", "ping", "version",
    "version.txt", "metrics", "debug", "trace", "info",
    "ws", "websocket", "socket.io/", "socket.io/socket.io.js", "sockjs/info",
    "rpc", "jsonrpc", "soap", "wsdl", "services", "services/",
    "server-status", "server-info", ".well-known/security.txt", ".well-known/",
    ".well-known/openid-configuration",

    # ---- CTF 高频 ----
    "flag", "flag/", "flag.txt", "flag.php", "flag.html", "flag.htm", "flag.jsp",
    "flag.json", "flag.txt.bak", "flag.php.bak", "flag.zip", "flags", "FLAG",
    "FLAG.txt", "flag_is_here.txt", "flag1.txt", "flag2.txt", "get_flag.php",
    "getflag", "f1ag.txt",
    "robots.txt", "sitemap.xml", "sitemap.xml.gz", "sitemap/", "sitemap.php",
    "crossdomain.xml", "clientaccesspolicy.xml", "humans.txt", "security.txt",
    "hello.php", "hello.txt", "hello.html", "hello", "hello/world",
    "hello-world", "test.php", "test.txt", "test.html", "test/", "tests/",
    "testing/", "test1.php", "test123.txt", "test2", "test3",
    "shell.php", "shell.txt", "shell", "shell.php.bak", "cmd.php", "cmd",
    "webshell.php", "1.php", "2.php", "x.php", "a.php", "hack.php",
    "upload", "upload/", "upload.php", "uploads", "uploads/", "uploadify.php",
    "uploadfile", "upload_file.php", "up.php", "fileupload",
    "files", "files/", "file", "file.php", "download", "download.php",
    "downloads", "downloads/", "attachment", "attachments", "media", "media/",
    "1.txt", "2.txt", "3.txt", "1.jpg", "1.png", "1.zip", "1.rar", "1.tar.gz",
    "data.txt", "secret.txt", "secrets.txt", "passwd", "password.txt",
    "key.txt", "keys.txt", "id_rsa", "id_rsa.txt", "private.key",
    "hint.txt", "hint.php", "notes.txt", "note.txt", "note.php", "todo.txt",
    "log.txt", "access.log", "error.log", "debug.log",
    "source", "source/", "sources", "console.php", "puzzle.php", "challenge",
    "challenge/", "ctf", "ctf/", "vuln", "vuln.php", "vulnerable", "xss.php",
    "sqli.php", "lfi.php", "rfi.php", "ssrf.php", "exec.php", "eval.php",
    "system.php", "pass.php", "check.php", "listing", ".listing",

    # ---- 目录 ----
    "static", "static/", "assets", "assets/", "js", "js/", "css", "css/",
    "images", "images/", "img", "img/", "image", "fonts", "fonts/", "video",
    "videos", "include", "include/", "includes", "includes/", "inc", "inc/",
    "conf", "conf/", "config", "config/", "configuration", "setup", "setup/",
    "install", "install/", "installer", "install.php", "setup.php", "upgrade",
    "upgrade.php", "update", "update.php", "uninstall.php",
    "tmp", "tmp/", "temp", "temp/", "cache", "cache/", "data", "data/", "db",
    "db/", "database", "database/", "log", "logs", "log/", "logs/", "runtime",
    "runtime/", "storage", "storage/", "var", "var/", "backup", "backup/",
    "backups", "backups/", "bak", "bak/", "old", "old/", "new", "new/",
    "readme", "README.md", "readme.txt", "readme.html", "README", "license",
    "LICENSE", "LICENSE.txt", "CHANGELOG.md", "CHANGELOG", "TODO.md", "VERSION",
    "version.php",

    # ---- 常规页面 / 入口 ----
    "index", "index.php", "index.html", "index.htm", "index.asp", "index.aspx",
    "index.jsp", "index.do", "index.action", "index.cfm", "index.shtml",
    "default.php", "default.html", "default.asp", "default.aspx", "home",
    "home.php", "home/", "main", "main.php", "main.html", "portal", "portal/",
    "cms", "cms/", "blog", "blog/", "news", "news/", "forum", "forum/", "bbs",
    "bbs/", "shop", "shop/", "store", "mall", "order", "orders", "cart", "pay",
    "payment", "user", "users", "user/", "users/", "member", "members",
    "profile", "account", "accounts", "my", "me", "personal", "center", "uc",
    "space", "space/", "search", "search.php", "search/", "rss", "rss.xml",
    "feed", "atom.xml", "tags", "categories", "about", "about.php", "about.html",
    "contact", "contact.php", "help", "help.php", "faq", "support", "privacy",
    "terms", "service", "products", "product", "goods", "item", "list",
    "list.php", "detail", "show", "display", "error", "error.php",
    "error.html", "404", "404.php", "404.html", "403.php", "500.php",
    "not_found", "denied", "forbidden", "unauthorized",
    "redirect", "goto", "link", "links", "redirect.php", "url.php", "jump.php",
    "out.php", "proxy", "proxy.php", "fetch", "fetch.php", "curl", "curl.php",
    "request", "request.php", "http", "http.php", "sql", "sql.php", "query",
    "query.php", "exec", "run", "run.php", "do", "action", "process", "handler",
    "controller", "api.php", "ajax", "ajax.php", "ajax/", "json", "json.php",
    "jsonp", "xml", "xml.php", "rss.php", "captcha", "captcha.php", "verify",
    "verify.php", "code", "code.php", "validate", "sendmail", "sendmail.php",
    "mail.php", "smtp.php", "export", "export.php", "import", "import.php",
    "backup.php", "restore.php", "wizard", "wizard/", "init", "init.php",
    "start", "start.php", "stop", "restart", "monitor", "monitor/", "stats",
    "statistics", "report", "reports", "report.php",
    "_admin", "_admin/", "_private", "_private/", "private", "private/",
    "secret", "secret/", "hidden", "hidden/", "internal", "internal/", "staff",
    "staff/", "employee", "employees", "hr", "finance", "sales", "marketing",
    "demo", "demo/", "sample", "samples", "example", "examples", "dev", "dev/",
    "develop", "development", "stage", "staging", "uat", "pre", "prod",
    "production", "release", "beta", "alpha", "v1", "v2", "v3", "old_site",
    "oldsite", "new_site", "site", "site/", "web", "web/", "www", "www/",
    "html", "html/", "public", "public/", "public_html", "htdocs", "htdocs/",
    "webroot", "webroot/", "app", "app/", "application", "bin", "boot",
    "build", "build/", "dist", "dist/", "lib", "lib/", "library", "vendor",
    "vendor/", "node_modules", "node_modules/", "bower_components", "plugins",
    "plugins/", "plugin", "plugin/", "modules", "modules/", "module", "module/",
    "themes", "themes/", "theme", "theme/", "templates", "templates/",
    "template", "template/", "views", "views/", "view", "layouts", "partials",
    "sessions", "sessions/", "session",

    # ---- 中间件 / 运维面板 ----
    "manager/html", "host-manager/html", "examples/", "examples/servlets/",
    "jmx-console", "web-console", "jolokia", "jolokia/list", "weblogic",
    "console/login/LoginForm.jsp", "solr", "solr/", "solr/admin/", "jenkins",
    "jenkins/", "jenkins/login", "script", "gitlab", "gitlab/", "grafana",
    "grafana/", "kibana", "kibana/", "zabbix", "zabbix/", "nagios", "nagios/",
    "cacti", "cacti/", "prometheus", "prometheus/", "nacos", "nacos/", "eureka",
    "eureka/", "consul", "consul/", "minio", "minio/", "harbor", "harbor/",
    "rancher", "portainer", "portainer/", "rabbitmq", "rabbitmq/", "kafka",
    "kafka/", "redis", "redis/", "mongodb", "elasticsearch", "elasticsearch/",
    "_cat/indices", "_cluster/health", "druid", "druid/index.html",
    "druid/sql.html", "h2-console", "h2-console/", "admin-console",
    "phpinfo.php", "info.php", "phpinfo", "webmail", "webmail/", "mail",
    "mail/", "roundcube", "squirrelmail",
]


# --------------------------------------------------------------------------- #
# 目标展开
# --------------------------------------------------------------------------- #

def normalize_base(base_url: str) -> str:
    """补协议、去掉末尾斜杠：'127.0.0.1:8080/' → 'http://127.0.0.1:8080'。"""
    text = (base_url or "").strip()
    if not text:
        return ""
    if not _ABS_RE.match(text):
        text = "http://" + text
    return text.rstrip("/")


def parse_paths(text: str) -> list[str]:
    """把字典文本拆成条目（按行 / 逗号 / 空白），'#' 开头当作注释忽略。"""
    out: list[str] = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        for token in re.split(r"[,\s]+", line):
            token = token.strip()
            if token:
                out.append(token)
    return out


def parse_extensions(text: str) -> list[str]:
    """把 'php, .bak zip' 这种输入规范成 ['.php', '.bak', '.zip']。"""
    out: list[str] = []
    for token in re.split(r"[,\s;]+", text or ""):
        token = token.strip()
        if not token:
            continue
        if not token.startswith("."):
            token = "." + token
        if token != "." and token not in out:
            out.append(token)
    return out


def build_targets(base_url: str, paths: list[str],
                  extensions: list[str] | None = None) -> list[str]:
    """
    把「字典条目 × 后缀」展开成完整 URL 列表（去重、保持顺序）。

    * base_url 没写协议就补 http://
    * 以 / 结尾的条目只请求目录本身，不叠后缀（否则会出现 uploads/.php）
    * 已经带后缀的条目只再试 BACKUP_EXTS 里的备份 / 泄露后缀
    * 字典里直接写完整 URL 的条目原样保留
    """
    exts = list(EXTENSIONS) if extensions is None else list(extensions)
    if "" not in exts:
        exts = [""] + exts                 # 无后缀永远要试
    base = normalize_base(base_url)
    if not base:
        return []

    out: list[str] = []
    seen: set[str] = set()
    for raw in paths or []:
        p = (raw or "").strip()
        if not p:
            continue
        if _ABS_RE.match(p):               # 自带协议的完整 URL
            cands = [p]
        else:
            p = p.lstrip("/")
            if not p:
                cands = [base + "/"]
            elif p.endswith("/"):
                cands = [f"{base}/{p}"]
            elif _EXT_RE.search(p):
                cands = [f"{base}/{p}"]
                cands += [f"{base}/{p}{e}" for e in exts if e and e in BACKUP_EXTS]
            else:
                cands = [f"{base}/{p}{e}" for e in exts]
        for u in cands:
            if u not in seen:
                seen.add(u)
                out.append(u)
    return out


# --------------------------------------------------------------------------- #
# 结果
# --------------------------------------------------------------------------- #

@dataclass
class DirResult:
    url: str
    status: int
    length: int
    content_type: str = ""
    redirect: str = ""
    title: str = ""

    @property
    def path(self) -> str:
        """去掉协议和主机后的路径，表格里显示这个更紧凑。"""
        body = self.url.split("://", 1)[-1]
        return body.split("/", 1)[1] if "/" in body else ""

    def row(self) -> list:
        return [self.status, self.length, self.path, self.content_type,
                self.redirect, self.title]


# --------------------------------------------------------------------------- #
# 请求
# --------------------------------------------------------------------------- #

_TLS = threading.local()
_WARN_SILENCED = False


def _silence_warnings():
    """压掉 verify=False 带来的 InsecureRequestWarning 刷屏（只做一次）。"""
    global _WARN_SILENCED
    if _WARN_SILENCED or not _HAS_REQUESTS:
        return
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except Exception:
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass
    _WARN_SILENCED = True


def _session():
    """每个线程一个 Session 复用连接（requests.Session 不是线程安全的）。"""
    s = getattr(_TLS, "session", None)
    if s is None:
        s = requests.Session()
        _TLS.session = s
    return s


def _prepare_headers(headers: dict | None) -> dict:
    hdrs = dict(headers or {})
    hdrs.setdefault("User-Agent", USER_AGENT)
    hdrs.setdefault("Accept", "*/*")
    hdrs.setdefault("Accept-Encoding", "gzip, deflate")
    return hdrs


def _random_path() -> str:
    """随机文件名，用来探「软 404」基线。"""
    rnd = "".join(random.choice(string.ascii_lowercase + string.digits)
                  for _ in range(12))
    return f"{rnd}.html"


def _probe(url: str, method: str, timeout: float, headers: dict,
           follow_redirect: bool) -> DirResult | None:
    """请求单个 URL；网络层出错返回 None（当作没结果，不算失败结果）。"""
    try:
        resp = _session().request(method, url, timeout=timeout, verify=False,
                                  allow_redirects=follow_redirect,
                                  headers=headers, stream=True)
    except Exception:
        return None

    try:
        body = b""
        total = 0
        for chunk in resp.iter_content(8192):
            if not chunk:
                continue
            total += len(chunk)
            if len(body) < _MAX_BODY:
                body += chunk[:_MAX_BODY - len(body)]
            if total >= _MAX_COUNT:
                break

        clen = (resp.headers.get("Content-Length") or "").strip()
        length = int(clen) if clen.isdigit() else total

        loc = resp.headers.get("Location", "") or ""
        if follow_redirect and resp.history and resp.url != url:
            loc = resp.url

        ctype = (resp.headers.get("Content-Type", "") or "").split(";")[0].strip()

        title = ""
        if b"<title" in body[:4096].lower():
            m = _TITLE_RE.search(body.decode("utf-8", "ignore"))
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]

        return DirResult(url=url, status=resp.status_code, length=length,
                         content_type=ctype, redirect=loc, title=title)
    except Exception:
        return None
    finally:
        try:
            resp.close()
        except Exception:
            pass


def soft404_baseline(base_url: str, timeout: float = 5.0, method: str = "GET",
                     headers: dict | None = None,
                     follow_redirect: bool = False) -> tuple[int, int] | None:
    """
    探测「软 404」基线：先请求两个随机不存在的路径，记下 (状态码, 正文长度)。

    很多站点会把不存在的路径重定向到首页，或者返回一个 200 的自定义错误页，
    这样目录爆破出来的结果会全是 200，必须靠基线把它们丢掉。
    两次探测结果一致时最可信，不一致就退回用第一次的结果。
    """
    if not _HAS_REQUESTS:
        raise RuntimeError("目录爆破需要 requests 库：pip install requests")
    _silence_warnings()
    base = normalize_base(base_url)
    if not base:
        return None
    hdrs = _prepare_headers(headers)

    samples: list[tuple[int, int]] = []
    for _ in range(2):
        r = _probe(f"{base}/{_random_path()}", method, timeout, hdrs, follow_redirect)
        if r is not None:
            samples.append((r.status, r.length))
    if not samples:
        return None
    if len(samples) == 2 and samples[0] == samples[1]:
        return samples[0]
    return samples[0]


# --------------------------------------------------------------------------- #
# 主扫描
# --------------------------------------------------------------------------- #

def scan(base_url: str, paths: list[str], extensions: list[str] | None = None,
         workers: int = 30, timeout: float = 5.0, method: str = "GET",
         headers: dict | None = None, follow_redirect: bool = False,
         cancel=None, on_result=None, progress=None,
         interesting_codes=None, filter_soft404: bool = True,
         soft404_tolerance: int = 0,
         baseline: tuple[int, int] | None = None) -> list[DirResult]:
    """
    并发探测一组路径，返回「值得关注」的结果。

    * progress(done, total) 报进度，on_result(DirResult) 逐条回调（在工作线程里执行，
      UI 层必须用信号转回主线程）
    * cancel 是 threading.Event，置位后尽快收尾
    * filter_soft404=True 时先探软 404 基线，命中基线的结果直接丢掉；
      baseline 可以外部传进来（UI 想先显示基线状态时用），省得重复探测
    * soft404_tolerance 允许长度有少量偏差也算命中基线（默认 0 = 长度必须一样）
    """
    if not _HAS_REQUESTS:
        raise RuntimeError("目录爆破需要 requests 库：pip install requests")
    _silence_warnings()

    base = normalize_base(base_url)
    targets = build_targets(base, paths, extensions)
    total = len(targets)
    if not total:
        return []

    codes = set(interesting_codes) if interesting_codes else set(INTERESTING_CODES)
    hdrs = _prepare_headers(headers)

    if filter_soft404 and baseline is None:
        baseline = soft404_baseline(base, timeout, method, hdrs, follow_redirect)
        if baseline:
            log(f"软 404 基线：状态 {baseline[0]}，正文 {baseline[1]} 字节", "info", SOURCE)

    results: list[DirResult] = []
    done = 0
    failed = 0

    def keep(r: DirResult | None) -> bool:
        if r is None or r.status not in codes:
            return False
        if (baseline is not None and r.status == baseline[0]
                and abs(r.length - baseline[1]) <= soft404_tolerance):
            return False               # 和软 404 基线一模一样，丢掉
        return True

    pool = cf.ThreadPoolExecutor(max_workers=max(1, min(workers, total)))
    futs = {pool.submit(_probe, u, method, timeout, hdrs, follow_redirect): u
            for u in targets}
    try:
        for fut in cf.as_completed(futs):
            if cancel is not None and cancel.is_set():
                break
            try:
                r = fut.result()
            except Exception:
                r = None
            done += 1
            if r is None:
                failed += 1
            elif keep(r):
                results.append(r)
                if on_result:
                    try:
                        on_result(r)
                    except Exception:
                        pass
            if progress and (done % 20 == 0 or done == total):
                progress(done, total)
    finally:
        for f in futs:
            f.cancel()
        pool.shutdown(wait=True)

    if progress:
        progress(done, total)
    if failed and failed > max(5, total // 2):
        log(f"{failed}/{total} 个请求失败，可能目标不可达或被 WAF / 安全设备拦截",
            "warn", SOURCE)

    results.sort(key=lambda r: (r.status, r.url))
    return results


def summarize(results: list[DirResult]) -> str:
    """给日志 / 状态栏用的一句话总结。"""
    if not results:
        return "没有发现有效路径（可以换字典、加后缀，或关掉软 404 过滤再试）"

    cnt: dict[int, int] = {}
    for r in results:
        cnt[r.status] = cnt.get(r.status, 0) + 1
    detail = "、".join(f"{code}×{n}" for code, n in sorted(cnt.items()))

    txt = f"发现 {len(results)} 条有效路径（{detail}）"
    hot = sum(1 for r in results if any(k in r.url.lower() for k in SENSITIVE_HINTS))
    if hot:
        txt += f"　⚠ 其中 {hot} 条命中敏感关键字（后台 / 备份 / 配置 / flag）"
    return txt
