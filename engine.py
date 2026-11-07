# -*- coding: utf-8 -*-
"""Движок «Прокси США»: настройки, конфиг mihomo, системные функции, управление ядром.
Окно — в proxy_usa.pyw (pywebview)."""
import base64
import ctypes
import json
import os
import queue
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
import winreg
from ctypes import wintypes

import re

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CORE_DIR = os.path.join(APP_DIR, "core")
MIHOMO = os.path.join(CORE_DIR, "mihomo.exe")
RUN_YAML = os.path.join(CORE_DIR, "run.yaml")
LOG_PATH = os.path.join(CORE_DIR, "mihomo.log")
PID_PATH = os.path.join(CORE_DIR, "mihomo.pid")
CFG_PATH = os.path.join(APP_DIR, "настройки.json")
TASK_LOGON = "ProxyUSA_autostart"
TASK_RUN = "ProxyUSA_run"
NY_TZ = "Eastern Standard Time"
GEO_KEY = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
NOWIN = 0x08000000  # CREATE_NO_WINDOW

AI_DOMAINS = [
    # ChatGPT / OpenAI + их аналитика (иначе она видит российский IP)
    "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "sora.com",
    "statsigapi.net", "featuregates.org", "featureassets.org", "prodregistryv2.org",
    # Claude / Anthropic
    "claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com",
    # сервисы, встроенные в страницы нейросетей
    "intercom.io", "intercomcdn.com", "sentry.io", "segment.io", "segment.com",
    "stripe.com", "stripe.network", "challenges.cloudflare.com", "cloudflare-ech.com",
    # другие нейросети
    "gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
    "perplexity.ai", "grok.com", "x.ai",
    # сайты проверки — чтобы видеть ровно то, что видят нейросети
    "ipinfo.io", "browserleaks.com",
]
# Сервисы, которые сами блокируют Россию или заблокированы в РФ, — тоже через США.
# Список редактируется в окне программы (поле «Ещё сайты через США»).
EXTRA_DEFAULT = [
    "canva.com", "canva.dev", "canva.site", "canva-apps.com",   # Canva
    "notion.so", "notion.com", "notion.site",                    # Notion
    "elevenlabs.io", "suno.com", "runwayml.com", "midjourney.com",
    "discord.com", "discord.gg", "discordapp.com", "discordapp.net",
]
# Тяжёлые загрузки — в умном режиме напрямую (без лимита скорости прокси)
DIRECT_ALWAYS = [
    "windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com",
    "huggingface.co", "hf.co", "steamcontent.com", "steamserver.net",
]
DOH_DOMAINS = [  # DNS-over-HTTPS браузеров — блокируем, чтобы DNS шёл только через движок
    "dns.google", "dns.google.com", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net",
    "doh.opendns.com", "dns.adguard-dns.com", "dns.adguard.com", "dns.nextdns.io",
    "doh.cleanbrowsing.org", "common.dot.dns.yandex.net", "dns.mullvad.net", "doh.dns.sb",
]
BROWSERS = ["chrome.exe", "msedge.exe", "browser.exe", "firefox.exe", "opera.exe",
            "brave.exe", "vivaldi.exe", "yandex.exe"]
STUN_PORTS = ["3478", "3479", "5349", "19302-19309"]
PRIVATE_NETS = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "169.254.0.0/16", "224.0.0.0/4"]



# ---------------------------------------------------------------- DPAPI
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, encrypt: bool) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    inp = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = _Blob()
    fn = ctypes.windll.crypt32.CryptProtectData if encrypt else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("DPAPI")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def protect(s):
    return base64.b64encode(_dpapi(s.encode("utf-8"), True)).decode() if s else ""


def unprotect(s):
    try:
        return _dpapi(base64.b64decode(s), False).decode("utf-8") if s else ""
    except Exception:
        return ""


# ---------------------------------------------------------------- настройки
def load_cfg():
    cfg = {"ip": "80.243.17.229", "port": "10000", "login": "", "password": "", "mode": "smart",
           "tz": False, "geo": True, "block_udp": True, "browser_policies": True, "browser_lang": True,
           "orig_tz": "", "orig_geo": "", "extra": list(EXTRA_DEFAULT), "policy_backup": {}, "rep": {}}
    try:
        with open(CFG_PATH, encoding="utf-8") as f:
            cfg.update(json.load(f))
    except Exception:
        pass
    if not cfg.get("migr_v2"):  # 07.11.2026: часовой пояс по умолчанию выключен, "all" -> "smart"
        cfg["tz"] = False
        cfg["migr_v2"] = True
    if cfg.get("mode") == "all":
        cfg["mode"] = "smart"
    return cfg


def save_cfg(cfg):
    tmp = CFG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CFG_PATH)


# ---------------------------------------------------------------- конфиг движка
def norm_domain(s):
    """'https://www.canva.com/design/..' -> 'canva.com'; мусор -> ''."""
    d = (s or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0].strip(".")
    for pre in ("*.", "+.", "www."):
        if d.startswith(pre):
            d = d[len(pre):]
    return d if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", d) else ""


def us_domains(cfg):
    out = []
    for d in AI_DOMAINS + [norm_domain(x) for x in cfg.get("extra", [])]:
        if d and d not in out:
            out.append(d)
    return out


def build_config(mode, cfg, password, ctrl_port, secret, block_udp=True):
    """mode: smart | ai | off.  off = всё напрямую, но нейросети ЗАБЛОКИРОВАНЫ (не уйдут с российского IP)."""
    q = json.dumps
    L = [
        "allow-lan: false", "mode: rule", "log-level: warning", "ipv6: false",
        "unified-delay: true", "tcp-concurrent: true", "find-process-mode: strict",
        f"external-controller: 127.0.0.1:{ctrl_port}", f"secret: {q(secret)}",
        "geodata-mode: true", "geo-auto-update: false",
        "profile: {store-selected: false, store-fake-ip: false}",
        "tun:", "  enable: true", "  device: ProxyUSA", "  stack: mixed", "  auto-route: true",
        "  auto-detect-interface: true", "  strict-route: true",
        '  dns-hijack: ["any:53", "tcp://any:53"]',
        "  route-exclude-address: [" + ", ".join(n for n in PRIVATE_NETS if not n.startswith("127.")) + "]",
        "sniffer:", "  enable: true", "  force-dns-mapping: true", "  parse-pure-ip: true",
        "  override-destination: true", "  sniff:", "    HTTP: {ports: [80, 8080-8880]}",
        "    TLS: {ports: [443, 8443]}", "    QUIC: {ports: [443, 8443]}",
        # DNS: fake-ip (адреса проксируемых сайтов у нас не резолвятся), DNS-запросы движка идут по правилам
        "dns:", "  enable: true", "  ipv6: false", "  enhanced-mode: fake-ip",
        "  fake-ip-range: 198.18.0.1/16", "  respect-rules: true",
        "  fake-ip-filter: ['*.lan', '*.local', '+.msftconnecttest.com', '+.msftncsi.com', 'time.windows.com', '+.ntp.org']",
        "  default-nameserver: [77.88.8.8, 77.88.8.1]", "  nameserver: [77.88.8.8, 77.88.8.1]",
        "  proxy-server-nameserver: [77.88.8.8, 77.88.8.1]",
        "proxies:", "  - name: USA", "    type: http", f"    server: {q(cfg['ip'])}",
        f"    port: {int(cfg['port'])}",
    ]
    if cfg.get("login"):
        L += [f"    username: {q(cfg['login'])}", f"    password: {q(password)}"]
    L.append("rules:")
    for n in PRIVATE_NETS:
        L.append(f"  - IP-CIDR,{n},DIRECT,no-resolve")
    if mode == "off":
        # kill switch: пока прокси выключен — нейросети не открываются вообще
        for d in us_domains(cfg):
            L.append(f"  - DOMAIN-SUFFIX,{d},REJECT")
        L += ["  - GEOSITE,category-ai-!cn,REJECT", "  - MATCH,DIRECT"]
        return "\n".join(L) + "\n"
    for d in DOH_DOMAINS:
        L.append(f"  - DOMAIN-SUFFIX,{d},REJECT")
    L.append("  - DST-PORT,853,REJECT")
    for p in STUN_PORTS:  # тихо отбрасываем — браузер даже не узнаёт о попытке (как советуют на GitHub)
        L.append(f"  - DST-PORT,{p},REJECT-DROP")
    if block_udp:
        for b in BROWSERS:
            L.append(f"  - AND,((NETWORK,UDP),(PROCESS-NAME,{b})),REJECT")
    for d in us_domains(cfg):
        L.append(f"  - DOMAIN-SUFFIX,{d},USA")
    for d in DIRECT_ALWAYS:
        L.append(f"  - DOMAIN-SUFFIX,{d},DIRECT")
    L.append("  - GEOSITE,category-ai-!cn,USA")  # все зарубежные нейросети (список из базы)
    if mode == "smart":
        for d in ("ru", "su", "xn--p1ai", "xn--d1acj3b", "xn--80asehdb", "xn--c1avg", "by", "kz"):
            L.append(f"  - DOMAIN-SUFFIX,{d},DIRECT")
        L += ["  - GEOSITE,category-ru,DIRECT",
              "  - GEOIP,RU,DIRECT",          # сервер сайта в России — напрямую
              "  - NETWORK,UDP,DIRECT",       # звонки Telegram, игры (браузерный UDP и STUN уже закрыты выше)
              "  - MATCH,USA"]
    else:
        L.append("  - MATCH,DIRECT")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- политики браузеров
POLICY_KEYS = {"Chrome": r"SOFTWARE\Policies\Google\Chrome",
               "Edge": r"SOFTWARE\Policies\Microsoft\Edge",
               "Yandex": r"SOFTWARE\Policies\YandexBrowser"}
POLICY_VALUES = {  # имя: (тип, значение)
    "WebRtcIPHandlingPolicy": (winreg.REG_SZ, "disable_non_proxied_udp"),  # WebRTC только через прокси
    "DnsOverHttpsMode": (winreg.REG_SZ, "off"),                           # свой зашифрованный DNS браузера — выкл
    "DefaultGeolocationSetting": (winreg.REG_DWORD, 2),                   # сайтам нельзя спрашивать геолокацию
}
FORCED_LANGS = ["en-US", "en", "ru"]


def _reg_get(path, name):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            v, t = winreg.QueryValueEx(k, name)
            return [t, v]
    except OSError:
        return None


def _reg_set(path, name, t, v):
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, t, v)


def _reg_del(path, name):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
    except OSError:
        pass


def apply_browser_policies(cfg, protect_on, lang_on):
    """Ставит/снимает политики Chrome/Edge/Яндекс. Старые значения сохраняются в cfg['policy_backup']
    и возвращаются при выключении. Возвращает список ошибок (пустой — всё ок)."""
    backup = cfg.setdefault("policy_backup", {})
    errors = []
    wanted = {}
    for key in POLICY_KEYS.values():
        for name, (t, v) in POLICY_VALUES.items():
            wanted[(key, name)] = (t, v) if protect_on else None
        for i, lang in enumerate(FORCED_LANGS, 1):
            wanted[(key + r"\ForcedLanguages", str(i))] = (winreg.REG_SZ, lang) if lang_on else None
    for (path, name), val in wanted.items():
        bk = f"{path}|{name}"
        try:
            if val is not None:
                if bk not in backup:
                    backup[bk] = _reg_get(path, name)  # None = значения не было
                _reg_set(path, name, *val)
            elif bk in backup:
                old = backup.pop(bk)
                if old is None:
                    _reg_del(path, name)
                else:
                    _reg_set(path, name, old[0], old[1])
        except OSError as e:
            errors.append(f"{path}\\{name}: {e}")
    return errors


def browser_policies_state():
    """True, если политика WebRTC стоит в Chrome."""
    v = _reg_get(POLICY_KEYS["Chrome"], "WebRtcIPHandlingPolicy")
    return bool(v and v[1] == "disable_non_proxied_udp")


# ---------------------------------------------------------------- репутация IP
def ip_reputation(ip):
    """ipinfo (VPN/прокси) + scamalytics (fraud score). None — не удалось узнать."""
    res = {"time": time.time(), "ip": ip, "score": None, "vpn": None, "summary": ""}
    try:
        html = http_get(f"https://ipinfo.io/{ip}", timeout=20)
        m = re.search(r"<title>(.*?)</title>", html, re.S)
        title = (m.group(1) if m else "").strip()
        parts = [p.strip() for p in title.split("|")]
        res["summary"] = parts[1] if len(parts) > 2 else ""
        res["vpn"] = ("VPN Detected" in title) and ("Not Detected" not in title)
    except Exception as e:
        res["ipinfo_error"] = str(e)[:120]
    try:
        html = http_get(f"https://scamalytics.com/ip/{ip}", timeout=20)
        m = re.search(r"Fraud Score:\s*(\d+)", html)
        if m:
            res["score"] = int(m.group(1))
    except Exception as e:
        res["scam_error"] = str(e)[:120]
    return res


def reputation_bad(rep):
    return bool(rep and ((rep.get("score") is not None and rep["score"] >= 30) or rep.get("vpn")))


# ---------------------------------------------------------------- буфер обмена / QR
def clipboard_text():
    u, k = ctypes.windll.user32, ctypes.windll.kernel32
    u.GetClipboardData.restype = ctypes.c_void_p
    k.GlobalLock.argtypes = [ctypes.c_void_p]
    k.GlobalLock.restype = ctypes.c_void_p
    k.GlobalUnlock.argtypes = [ctypes.c_void_p]
    if not u.OpenClipboard(None):
        return ""
    try:
        h = u.GetClipboardData(13)  # CF_UNICODETEXT
        if not h:
            return ""
        p = k.GlobalLock(h)
        try:
            return ctypes.wstring_at(p) if p else ""
        finally:
            k.GlobalUnlock(h)
    finally:
        u.CloseClipboard()


def proxy_uri(cfg, password):
    from urllib.parse import quote
    auth = f"{quote(cfg.get('login', ''), safe='')}:{quote(password, safe='')}@" if cfg.get("login") else ""
    return f"http://{auth}{cfg['ip']}:{cfg['port']}"


def qr_data_uri(text):
    import io
    import qrcode
    img = qrcode.make(text, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


# ---------------------------------------------------------------- система
def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="oem", errors="replace",
                           timeout=timeout, creationflags=NOWIN)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return -1, str(e)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def pythonw():
    exe = sys.executable
    return exe[:-10] + "pythonw.exe" if exe.lower().endswith("python.exe") else exe


def task_exists(name):
    return run(["schtasks", "/Query", "/TN", name])[0] == 0


def set_autostart(on):
    script = os.path.abspath(__file__)
    if on:
        for name, extra, trig in ((TASK_LOGON, " --tray", ["/SC", "ONLOGON"]),
                                  (TASK_RUN, "", ["/SC", "ONCE", "/ST", "00:00"])):
            code, out = run(["schtasks", "/Create", "/TN", name, "/TR", f'"{pythonw()}" "{script}"{extra}',
                             *trig, "/RL", "HIGHEST", "/F"])
            if code != 0:
                raise OSError(out.strip())
    else:
        for name in (TASK_LOGON, TASK_RUN):
            run(["schtasks", "/Delete", "/TN", name, "/F"])


def get_tz():
    code, out = run(["tzutil", "/g"])
    return out.strip() if code == 0 else ""


def set_tz(name):
    return run(["tzutil", "/s", name])[0] == 0


def get_geo():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, GEO_KEY) as k:
            return winreg.QueryValueEx(k, "Value")[0]
    except OSError:
        return ""


def set_geo(value):
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, GEO_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "Value", 0, winreg.REG_SZ, value)
        return True
    except OSError:
        return False


def foreign_tunnels():
    """Другие перехватчики трафика (Koala Clash, sing-box и т.п.) — конфликтуют с TUN."""
    ps = ("Get-Process -Name mihomo,'Koala Clash',sing-box,clash-verge,'Clash Verge',v2rayN,hiddify,nekoray "
          "-ErrorAction SilentlyContinue | ForEach-Object { $_.Name + '|' + $_.Path }")
    code, out = run(["powershell", "-NoProfile", "-Command", ps], timeout=20)
    res = []
    for line in out.splitlines():
        name, _, path = line.partition("|")
        if name and os.path.normcase(path or "") != os.path.normcase(MIHOMO):
            res.append(name)
    return sorted(set(res))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def http_get(url, timeout=15):
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with op.open(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


# ---------------------------------------------------------------- движок
class Core:
    def __init__(self):
        self.proc = None
        self.port = 0
        self.secret = secrets.token_hex(16)
        self.log = None

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def api(self, method, path, body=None, timeout=10):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
                                     headers={"Authorization": f"Bearer {self.secret}",
                                              "Content-Type": "application/json"})
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with op.open(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")

    @staticmethod
    def kill_stale():
        try:
            with open(PID_PATH) as f:
                pid = int(f.read().strip())
            run(["taskkill", "/PID", str(pid), "/T", "/F"])
        except Exception:
            pass
        try:
            os.remove(PID_PATH)
        except OSError:
            pass

    def start(self, base_yaml_fn, full_yaml_fn):
        """base_yaml_fn/full_yaml_fn(port, secret) -> текст. На диск пишется только base (без пароля)."""
        self.stop()
        self.kill_stale()
        self.port = free_port()
        with open(RUN_YAML, "w", encoding="utf-8") as f:
            f.write(base_yaml_fn(self.port, self.secret))
        self.log = open(LOG_PATH, "w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen([MIHOMO, "-d", CORE_DIR, "-f", RUN_YAML], stdout=self.log,
                                     stderr=subprocess.STDOUT, creationflags=NOWIN)
        with open(PID_PATH, "w") as f:
            f.write(str(self.proc.pid))
        ok = False
        for _ in range(60):
            if not self.alive():
                break
            try:
                self.api("GET", "/version", timeout=2)
                ok = True
                break
            except Exception:
                time.sleep(0.25)
        try:
            os.remove(RUN_YAML)
        except OSError:
            pass
        if not ok:
            raise RuntimeError("Движок не запустился.\n" + self.tail())
        self.reload(full_yaml_fn(self.port, self.secret))

    def reload(self, yaml_text):
        self.api("PUT", "/configs?force=true", {"path": "", "payload": yaml_text}, timeout=20)

    def delay(self):
        """Задержка до прокси США в мс (через сам прокси), None — не отвечает."""
        try:
            url = urllib.request.quote("https://www.gstatic.com/generate_204", safe="")
            r = json.loads(self.api("GET", f"/proxies/USA/delay?timeout=6000&url={url}", timeout=10))
            return int(r["delay"]) if r.get("delay") else None
        except Exception:
            return None

    def stop(self):
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.proc = None
        if self.log:
            try:
                self.log.close()
            except Exception:
                pass
            self.log = None
        try:
            os.remove(PID_PATH)
        except OSError:
            pass

    @staticmethod
    def tail(n=8):
        try:
            with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
                lines = [l.strip() for l in f if l.strip()]
            return "\n".join(lines[-n:])
        except Exception:
            return ""


