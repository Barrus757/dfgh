# -*- coding: utf-8 -*-
"""Прокси США — свой «Koala Clash» под один ISP-прокси, с защитой от утечек.

Движок: mihomo (core\\mihomo.exe) в режиме TUN — перехватывает ВЕСЬ трафик компьютера.
Режимы:
  * «Включить» (умный)            — российское напрямую (.ru/.рф, российские сервисы, серверы в РФ),
                                    всё остальное — через США, без ручных списков;
  * «Только нейросети» (запасной)  — ChatGPT/Claude/... и сайты из списка через США, остальное напрямую;
  * «Выключить».
Защита: DNS не уходит наружу для проксируемых сайтов (fake-ip), DoH/DoT браузеров
заблокирован, STUN/WebRTC заблокирован, IPv6 выключен, strict-route (нельзя обойти TUN),
сниффер TLS/QUIC (правила работают даже если браузер подключается по IP).
Опции: часовой пояс Нью-Йорка, отключение геолокации Windows.
Пароль прокси хранится зашифрованным (DPAPI) и не пишется на диск открытым текстом:
движку он передаётся через локальный API.
"""
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
import tkinter as tk
from tkinter import ttk, messagebox

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

MODES = {
    "off": ("ВЫКЛЮЧЕН — всё напрямую", "#d9d9d9", "#333333", (150, 150, 150)),
    "ai": ("ТОЛЬКО НЕЙРОСЕТИ через США", "#c6efc6", "#0b3d0b", (90, 190, 220)),
    "smart": ("ВКЛЮЧЁН: Россия напрямую, остальное через США", "#9be59b", "#0b3d0b", (40, 170, 40)),
    "err": ("ОШИБКА — смотри ниже", "#ff8a8a", "#5a0000", (210, 30, 30)),
}


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
    cfg = {"ip": "80.243.17.229", "port": "10000", "login": "", "password": "", "mode": "off",
           "tz": True, "geo": True, "block_udp": True, "orig_tz": "", "orig_geo": "",
           "extra": list(EXTRA_DEFAULT)}
    try:
        with open(CFG_PATH, encoding="utf-8") as f:
            cfg.update(json.load(f))
    except Exception:
        pass
    return cfg


def save_cfg(cfg):
    tmp = CFG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CFG_PATH)


# ---------------------------------------------------------------- конфиг движка
def norm_domain(s):
    """'https://www.canva.com/design/..' -> 'canva.com'; мусор -> ''."""
    import re
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
        "dns:", "  enable: true", "  ipv6: false", "  enhanced-mode: fake-ip",
        "  fake-ip-range: 198.18.0.1/16",
        "  fake-ip-filter: ['*.lan', '*.local', '+.msftconnecttest.com', '+.msftncsi.com', 'time.windows.com', '+.ntp.org']",
        "  default-nameserver: [77.88.8.8, 8.8.8.8]", "  nameserver: [77.88.8.8, 8.8.8.8]",
        "proxies:", "  - name: USA", "    type: http", f"    server: {q(cfg['ip'])}",
        f"    port: {int(cfg['port'])}",
    ]
    if cfg.get("login"):
        L += [f"    username: {q(cfg['login'])}", f"    password: {q(password)}"]
    L.append("rules:")
    for n in PRIVATE_NETS:
        L.append(f"  - IP-CIDR,{n},DIRECT,no-resolve")
    for d in DOH_DOMAINS:
        L.append(f"  - DOMAIN-SUFFIX,{d},REJECT")
    L.append("  - DST-PORT,853,REJECT")
    for p in STUN_PORTS:
        L.append(f"  - DST-PORT,{p},REJECT")
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


# ---------------------------------------------------------------- трей
def make_icon(rgb):
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((4, 4, 60, 60), fill=rgb + (255,), outline=(255, 255, 255, 255), width=3)
    d.text((20, 18), "US", fill=(255, 255, 255, 255))
    return img


# ---------------------------------------------------------------- окно
class App(tk.Tk):
    def __init__(self, tray_start=False):
        super().__init__()
        self.title("Прокси США")
        self.geometry("600x860")
        self.minsize(560, 780)
        self.cfg = load_cfg()
        self.core = Core()
        self.q = queue.Queue()
        self.mode = "off"
        self.busy = False
        self.restarts = []
        self.tray = None

        st = ttk.Style(self)
        st.configure("Big.TButton", font=("Segoe UI", 12), padding=8)

        self.lbl_status = tk.Label(self, font=("Segoe UI", 16, "bold"), pady=14)
        self.lbl_status.pack(fill="x", padx=10, pady=(10, 6))
        bf = ttk.Frame(self)
        bf.pack(fill="x", padx=10)
        ttk.Button(bf, text="Включить (Россия напрямую, всё остальное через США)", style="Big.TButton",
                   command=lambda: self.set_mode("smart")).pack(fill="x", pady=3)
        ttk.Button(bf, text="Выключить", style="Big.TButton",
                   command=lambda: self.set_mode("off")).pack(fill="x", pady=3)
        ttk.Button(bf, text="Запасной режим: только нейросети и сайты из списка",
                   command=lambda: self.set_mode("ai")).pack(fill="x", pady=(3, 0))

        cf = ttk.LabelFrame(self, text="Проверка")
        cf.pack(fill="x", padx=10, pady=(10, 0))
        row = ttk.Frame(cf)
        row.pack(fill="x", padx=6, pady=4)
        ttk.Button(row, text="Проверить утечки", command=self.check).pack(side="left")
        ttk.Button(row, text="WebRTC в браузере", command=lambda: webbrowser.open("https://browserleaks.com/webrtc")).pack(side="left", padx=6)
        ttk.Button(row, text="DNS в браузере", command=lambda: webbrowser.open("https://browserleaks.com/dns")).pack(side="left")
        self.lbl_check = tk.Label(cf, text="", justify="left", anchor="w", font=("Segoe UI", 10))
        self.lbl_check.pack(fill="x", padx=6, pady=(0, 6))

        sf = ttk.LabelFrame(self, text="Прокси (из кабинета Proxy.Market)")
        sf.pack(fill="x", padx=10, pady=10)
        self.var_ip = tk.StringVar(value=self.cfg["ip"])
        self.var_port = tk.StringVar(value=str(self.cfg["port"]))
        self.var_login = tk.StringVar(value=self.cfg.get("login", ""))
        self.var_pass = tk.StringVar(value=unprotect(self.cfg.get("password", "")))
        for i, (lbl, var, show) in enumerate([("IP", self.var_ip, ""), ("Порт", self.var_port, ""),
                                              ("Логин", self.var_login, ""), ("Пароль", self.var_pass, "•")]):
            ttk.Label(sf, text=lbl).grid(row=i, column=0, sticky="w", padx=6, pady=2)
            e = ttk.Entry(sf, textvariable=var, show=show)
            e.grid(row=i, column=1, sticky="we", padx=6, pady=2)
            e.bind("<Button-3>", self.entry_menu)
        sf.columnconfigure(1, weight=1)
        ttk.Button(sf, text="Сохранить", command=self.save_settings).grid(row=4, column=1, sticky="e", padx=6, pady=4)
        # Ctrl+C/V/X/A по коду клавиши — работают и на русской раскладке
        self.bind_all("<Control-KeyPress>", self.ctrl_keys)

        xf = ttk.LabelFrame(self, text="Сайты через США для запасного режима (в умном режиме не нужно)")
        xf.pack(fill="x", padx=10, pady=(0, 10))
        self.txt_extra = tk.Text(xf, height=4, font=("Consolas", 10), wrap="none", undo=True)
        self.txt_extra.pack(fill="x", padx=6, pady=(4, 2))
        self.txt_extra.insert("1.0", "\n".join(self.cfg.get("extra", [])))
        self.txt_extra.bind("<Button-3>", self.entry_menu)
        xrow = ttk.Frame(xf)
        xrow.pack(fill="x", padx=6, pady=(0, 4))
        ttk.Label(xrow, foreground="#555", text="Можно вставлять ссылки целиком — домен выделится сам.").pack(side="left")
        ttk.Button(xrow, text="Применить", command=self.save_extra).pack(side="right")

        of = ttk.LabelFrame(self, text="Защита и удобство")
        of.pack(fill="x", padx=10)
        self.var_tz = tk.BooleanVar(value=self.cfg["tz"])
        self.var_geo = tk.BooleanVar(value=self.cfg["geo"])
        self.var_udp = tk.BooleanVar(value=self.cfg["block_udp"])
        self.var_auto = tk.BooleanVar(value=task_exists(TASK_LOGON))
        ttk.Checkbutton(of, text="Часовой пояс Нью-Йорка, пока прокси включён", variable=self.var_tz,
                        command=self.opt_changed).pack(anchor="w", padx=6)
        ttk.Checkbutton(of, text="Выключать геолокацию Windows, пока прокси включён", variable=self.var_geo,
                        command=self.opt_changed).pack(anchor="w", padx=6)
        ttk.Checkbutton(of, text="Блокировать UDP в браузерах (защита WebRTC; звонки в браузере не работают)",
                        variable=self.var_udp, command=self.opt_changed).pack(anchor="w", padx=6)
        ttk.Checkbutton(of, text="Запускать с Windows (без запроса администратора)", variable=self.var_auto,
                        command=self.toggle_autostart).pack(anchor="w", padx=6, pady=(0, 4))
        ttk.Label(self, foreground="#555", wraplength=570, justify="left",
                  text="Крестик — свернуть в трей (значок «US» у часов). Полный выход — через значок в трее.").pack(
            anchor="w", padx=10, pady=6)

        self.protocol("WM_DELETE_WINDOW", self.hide)
        self.start_tray()
        self.recover()
        self.show_status()
        last = self.cfg.get("mode", "off")
        last = "smart" if last == "all" else last
        if tray_start and last in ("ai", "smart"):
            self.set_mode(last)
        if tray_start:
            self.after(100, self.hide)
        self.after(150, self.poll)
        self.after(2000, self.watchdog)

    # ---------- восстановление после аварии
    def recover(self):
        Core.kill_stale()
        if self.cfg.get("orig_tz") and get_tz() == NY_TZ and self.cfg["orig_tz"] != NY_TZ:
            set_tz(self.cfg["orig_tz"])
        if self.cfg.get("orig_geo"):
            set_geo(self.cfg["orig_geo"])
        self.cfg["orig_tz"] = self.cfg["orig_geo"] = ""
        save_cfg(self.cfg)

    # ---------- буфер обмена
    def ctrl_keys(self, e):
        w = self.focus_get()
        if not isinstance(w, (tk.Entry, ttk.Entry, tk.Text)):
            return
        ev = {86: "<<Paste>>", 67: "<<Copy>>", 88: "<<Cut>>", 90: "<<Undo>>"}.get(e.keycode)
        if ev:
            if ev == "<<Undo>>" and not isinstance(w, tk.Text):
                return
            w.event_generate(ev)
            return "break"
        if e.keycode == 65:
            if isinstance(w, tk.Text):
                w.tag_add("sel", "1.0", "end-1c")
            else:
                w.select_range(0, "end")
                w.icursor("end")
            return "break"

    def save_extra(self):
        raw = self.txt_extra.get("1.0", "end").replace(",", "\n").replace(" ", "\n").splitlines()
        doms, bad = [], []
        for line in raw:
            if not line.strip():
                continue
            d = norm_domain(line)
            if d:
                if d not in doms:
                    doms.append(d)
            else:
                bad.append(line.strip())
        self.cfg["extra"] = doms
        save_cfg(self.cfg)
        self.txt_extra.delete("1.0", "end")
        self.txt_extra.insert("1.0", "\n".join(doms))
        msg = f"Сайтов через США: {len(doms)} ✔"
        if bad:
            msg += "\nНе понял: " + ", ".join(bad[:5])
        self.lbl_check.config(text=msg, fg="#0b6b0b" if not bad else "#a05a00")
        if self.mode in ("ai", "smart"):
            self.set_mode(self.mode)

    def entry_menu(self, e):
        w = e.widget
        w.focus_set()
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="Вставить", command=lambda: w.event_generate("<<Paste>>"))
        m.add_command(label="Копировать", command=lambda: w.event_generate("<<Copy>>"))
        m.add_command(label="Вырезать", command=lambda: w.event_generate("<<Cut>>"))
        m.tk_popup(e.x_root, e.y_root)

    # ---------- настройки
    def save_settings(self, silent=False):
        ip, port = self.var_ip.get().strip(), self.var_port.get().strip()
        if not ip or not port.isdigit():
            messagebox.showwarning("Прокси США", "Укажи IP и порт прокси.")
            return False
        self.cfg.update(ip=ip, port=port, login=self.var_login.get().strip(),
                        password=protect(self.var_pass.get()))
        save_cfg(self.cfg)
        if not silent:
            self.lbl_check.config(text="Сохранено ✔", fg="#0b6b0b")
            if self.mode in ("ai", "smart"):
                self.set_mode(self.mode)
        return True

    def opt_changed(self):
        self.cfg.update(tz=self.var_tz.get(), geo=self.var_geo.get(), block_udp=self.var_udp.get())
        save_cfg(self.cfg)
        if self.mode in ("ai", "smart"):
            self.apply_privacy(True)
            self.set_mode(self.mode)

    def toggle_autostart(self):
        try:
            set_autostart(self.var_auto.get())
        except OSError as e:
            messagebox.showerror("Прокси США", f"Не получилось настроить автозапуск:\n{e}")
            self.var_auto.set(task_exists(TASK_LOGON))

    # ---------- часовой пояс / геолокация
    def apply_privacy(self, on):
        if on:
            cur = get_tz()
            if self.var_tz.get():
                if not self.cfg.get("orig_tz") and cur and cur != NY_TZ:
                    self.cfg["orig_tz"] = cur
                if cur != NY_TZ:
                    set_tz(NY_TZ)
            elif self.cfg.get("orig_tz"):
                set_tz(self.cfg["orig_tz"])
                self.cfg["orig_tz"] = ""
            if self.var_geo.get():
                if not self.cfg.get("orig_geo"):
                    self.cfg["orig_geo"] = get_geo() or "Allow"
                set_geo("Deny")
            elif self.cfg.get("orig_geo"):
                set_geo(self.cfg["orig_geo"])
                self.cfg["orig_geo"] = ""
        else:
            if self.cfg.get("orig_tz"):
                set_tz(self.cfg["orig_tz"])
            if self.cfg.get("orig_geo"):
                set_geo(self.cfg["orig_geo"])
            self.cfg["orig_tz"] = self.cfg["orig_geo"] = ""
        save_cfg(self.cfg)

    # ---------- режимы
    def set_mode(self, mode):
        if self.busy:
            return
        if mode != "off":
            if not self.save_settings(silent=True):
                return
            if not self.cfg.get("login") and not messagebox.askyesno(
                    "Прокси США", "Логин и пароль не указаны. Всё равно включить?"):
                return
            if not self.core.alive():
                others = foreign_tunnels()
                if others:
                    messagebox.showwarning(
                        "Прокси США", "Сначала полностью закрой: " + ", ".join(others) +
                        "\n\nДва перехватчика трафика одновременно работать не могут.")
                    return
        self.busy = True
        self.lbl_status.config(text="Переключаю…", bg="#e8e8e8", fg="#333")
        threading.Thread(target=self._switch, args=(mode, self.var_udp.get()), daemon=True).start()

    def _switch(self, mode, udp):
        try:
            if mode == "off":
                self.core.stop()
                self.q.put(("privacy", False))
            else:
                pw = unprotect(self.cfg.get("password", ""))
                full = lambda p, s: build_config(mode, self.cfg, pw, p, s, udp)
                if self.core.alive():
                    self.core.reload(full(self.core.port, self.core.secret))
                else:
                    base = lambda p, s: build_config(mode, self.cfg, "", p, s, udp)
                    self.core.start(base, full)
                self.q.put(("privacy", True))
            self.q.put(("mode", mode))
        except Exception as e:
            self.core.stop()
            self.q.put(("privacy", False))
            self.q.put(("error", str(e)))

    def show_status(self, err=False):
        text, bg, fg, rgb = MODES["err" if err else self.mode]
        self.lbl_status.config(text=text, bg=bg, fg=fg)
        self.title(f"Прокси США — {'выкл' if self.mode == 'off' else 'вкл'}")
        if self.tray:
            try:
                self.tray.icon = make_icon(rgb)
                self.tray.title = "Прокси США — " + text
            except Exception:
                pass

    # ---------- проверка утечек
    def check(self):
        self.lbl_check.config(text="Проверяю…", fg="#555")

        def work():
            res = []
            ok_all = True
            try:
                j = json.loads(http_get("https://ipinfo.io/json"))
                us = j.get("country") == "US"
                ok_all &= us
                res.append(f"{'✔' if us else '✖'} Нейросети видят: {j.get('ip')} — {j.get('city')}, "
                           f"{j.get('country')} ({j.get('org', '')})")
                ai_ip = j.get("ip")
            except Exception as e:
                ok_all = False
                ai_ip = None
                res.append(f"✖ Нейросети: не открывается ({e})")
            try:
                ip2 = http_get("https://api.ipify.org").strip()
                if self.mode == "smart":
                    good = ip2 == ai_ip
                    ok_all &= good
                    res.append(f"{'✔' if good else '✖'} Остальные сайты видят: {ip2}"
                               f"{' (США)' if good else ' — НЕ через прокси!'}")
                else:
                    res.append(f"• Остальные сайты видят: {ip2}"
                               f"{' (напрямую — так и задумано)' if ip2 != ai_ip else ''}")
            except Exception as e:
                res.append(f"• Остальные сайты: не проверить ({e})")
            try:
                a = socket.gethostbyname("chatgpt.com")
                fake = a.startswith("198.18.")
                if self.mode != "off":
                    ok_all &= fake
                res.append(f"{'✔' if fake else '✖'} DNS: адрес ChatGPT {'не запрашивается снаружи' if fake else 'запрошен у обычного DNS'}")
            except Exception as e:
                res.append(f"• DNS: не проверить ({e})")
            tz = get_tz()
            tz_ok = tz == NY_TZ
            res.append(f"{'✔' if tz_ok else '•'} Часовой пояс Windows: {tz}")
            geo = get_geo()
            res.append(f"{'✔' if geo == 'Deny' else '•'} Геолокация Windows: {'выключена' if geo == 'Deny' else 'включена'}")
            res.append("Итог: " + ("всё в порядке ✔" if ok_all and self.mode != "off" else
                                   "прокси выключен" if self.mode == "off" else "есть проблемы ✖"))
            self.q.put(("check", "\n".join(res), "#0b6b0b" if ok_all and self.mode != "off" else "#a00000"))

        threading.Thread(target=work, daemon=True).start()

    # ---------- очередь событий из потоков
    def poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "mode":
                    self.mode = msg[1]
                    self.busy = False
                    self.cfg["mode"] = self.mode
                    save_cfg(self.cfg)
                    self.show_status()
                    if self.mode != "off":
                        self.after(2500, self.check)
                    else:
                        self.lbl_check.config(text="")
                elif kind == "privacy":
                    self.apply_privacy(msg[1])
                elif kind == "error":
                    self.busy = False
                    self.mode = "off"
                    self.cfg["mode"] = "off"
                    save_cfg(self.cfg)
                    self.show_status(err=True)
                    self.lbl_check.config(text=msg[1], fg="#a00000")
                elif kind == "check":
                    self.lbl_check.config(text=msg[1], fg=msg[2])
                elif kind == "tray":
                    self.tray_cmd(msg[1])
        except queue.Empty:
            pass
        self.after(150, self.poll)

    def watchdog(self):
        if self.mode != "off" and not self.busy and not self.core.alive():
            now = time.time()
            self.restarts = [t for t in self.restarts if now - t < 120] + [now]
            if len(self.restarts) <= 5:
                self.lbl_check.config(text="Движок остановился — перезапускаю…\n" + Core.tail(4), fg="#a00000")
                self.set_mode(self.mode)
            else:
                self.mode = "off"
                self.apply_privacy(False)
                self.show_status(err=True)
                self.lbl_check.config(text="Движок постоянно падает — выключил.\n" + Core.tail(6), fg="#a00000")
        self.after(2000, self.watchdog)

    # ---------- трей
    def start_tray(self):
        try:
            import pystray
        except Exception:
            return
        put = lambda cmd: (lambda icon, item: self.q.put(("tray", cmd)))
        menu = pystray.Menu(
            pystray.MenuItem("Открыть окно", put("show"), default=True),
            pystray.MenuItem("Включить (умный режим)", put("smart")),
            pystray.MenuItem("Только нейросети", put("ai")),
            pystray.MenuItem("Выключить", put("off")),
            pystray.MenuItem("Выход", put("quit")))
        self.tray = pystray.Icon("ProxyUSA", make_icon(MODES["off"][3]), "Прокси США", menu)
        self.tray.run_detached()

    def tray_cmd(self, cmd):
        if cmd == "show":
            self.deiconify()
            self.lift()
            self.focus_force()
        elif cmd in ("ai", "smart", "off"):
            self.set_mode(cmd)
        elif cmd == "quit":
            self.quit_app()

    def hide(self):
        if self.tray:
            self.withdraw()
        else:
            self.iconify()

    def quit_app(self):
        self.core.stop()
        self.apply_privacy(False)
        self.cfg["mode"] = "off"
        save_cfg(self.cfg)
        if self.tray:
            try:
                self.tray.stop()
            except Exception:
                pass
        self.destroy()


def main():
    tray_start = "--tray" in sys.argv
    if not is_admin():
        # есть задача автозапуска — стартуем через неё без окна UAC
        if task_exists(TASK_RUN) and run(["schtasks", "/Run", "/TN", TASK_RUN])[0] == 0:
            return
        args = " ".join(f'"{a}"' for a in [os.path.abspath(__file__)] + sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", pythonw(), args, APP_DIR, 1)
        return
    ctypes.windll.kernel32.CreateMutexW(None, False, "ProxyUSA_single_instance")
    if ctypes.windll.kernel32.GetLastError() == 183:
        ctypes.windll.user32.MessageBoxW(None, "«Прокси США» уже запущен — значок «US» в трее у часов.",
                                         "Прокси США", 0x40)
        return
    if not os.path.exists(MIHOMO):
        ctypes.windll.user32.MessageBoxW(None, f"Не найден движок:\n{MIHOMO}", "Прокси США", 0x10)
        return
    App(tray_start=tray_start).mainloop()


if __name__ == "__main__":
    main()
