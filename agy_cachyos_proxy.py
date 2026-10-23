#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agy_cachyos_proxy.py — Прокси-маршрутизатор, бинарный патчер региона и фоновый демон
для Antigravity CLI (agy) в среде Linux (CachyOS / Arch Linux).

Что нового в этой версии (исправление ошибки "Account is not eligible"):
1. Бинарный патч локальной копии `agy` (`ineligible` -> `inexigible` по методу confeden/Antigravity):
   снимает жесткую клиентскую блокировку региона аккаунта без изменения системного /usr/bin/agy.
2. Принудительное переключение сетевого стека Go (`GODEBUG=netdns=cgo`):
   заставляет Go-рантайм использовать системный резолвер glibc вместо прямых syscall в обход proxychains4.
3. Флаг `--reset-auth` для полной очистки закешированного статуса `ineligible` в ~/.gemini и ~/.config.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import select
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ==============================================================================
# ВПИШИТЕ ДАННЫЕ ВАШЕГО HTTP-ПРОКСИ СЮДА (4 ОТДЕЛЬНЫХ ПОЛЯ):
# ==============================================================================
PROXY_IP = "127.0.0.1"       # Например: "185.100.20.30"
PROXY_PORT = 8080            # Например: 8080
PROXY_LOGIN = ""             # Например: "my_login" (оставьте "", если без пароля)
PROXY_PASSWORD = ""          # Например: "my_password" (оставьте "", если без пароля)

# Либо одной строкой в формате "ip:port:login:password" (имеет приоритет, если заполнено):
RAW_PROXY_STRING = ""        # Например: "185.100.20.30:8080:my_login:my_password"

# Параметры локального моста
LOCAL_BRIDGE_HOST = "127.0.0.1"
LOCAL_BRIDGE_PORT = 18888
STREAM_SOCKET_TIMEOUT = 180.0
IDLE_SHUTDOWN_SECONDS = 60.0

CONFIG_DIR = Path.home() / ".config" / "agy-proxy"
SHARE_DIR = Path.home() / ".local" / "share" / "agy-proxy"
ENV_CONFIG_FILE = CONFIG_DIR / "proxy.env"
PROXYCHAINS_CONF = CONFIG_DIR / "proxychains.conf"
PID_FILE = CONFIG_DIR / "bridge.pid"
LOG_FILE = CONFIG_DIR / "bridge.log"
PATCHED_AGY_PATH = SHARE_DIR / "agy.patched"
PATCHED_META_PATH = SHARE_DIR / "agy.patched.meta.json"

ANTIGRAVITY_ENDPOINTS = [
    ("Antigravity CloudCode API", "https://daily-cloudcode-pa.googleapis.com"),
    ("Cloud AI Companion API", "https://cloudaicompanion.googleapis.com"),
    ("Google OAuth2 API", "https://oauth2.googleapis.com"),
    ("Antigravity Portal", "https://antigravity.google"),
]


def load_env_config() -> Dict[str, str]:
    """Читает ~/.config/agy-proxy/proxy.env, если он существует."""
    result: Dict[str, str] = {}
    if ENV_CONFIG_FILE.exists():
        try:
            for line in ENV_CONFIG_FILE.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                result[k.strip()] = v.strip().strip('"').strip("'")
        except Exception:
            pass
    return result


class UpstreamProxyConfig:
    """Универсальный парсер параметров пользовательского HTTP-прокси."""

    def __init__(
        self,
        raw_input: Optional[str] = None,
        ip: str = PROXY_IP,
        port: int = PROXY_PORT,
        login: str = PROXY_LOGIN,
        password: str = PROXY_PASSWORD,
    ) -> None:
        self.scheme: str = "http"
        self.host: str = ""
        self.port: int = 0
        self.username: Optional[str] = None
        self.password: Optional[str] = None

        env_cfg = load_env_config()
        raw_candidate = (
            raw_input
            or os.environ.get("AGY_HTTP_PROXY")
            or env_cfg.get("RAW_PROXY_STRING")
            or RAW_PROXY_STRING
        )

        if raw_candidate and raw_candidate.strip():
            self._parse_flexible_string(raw_candidate.strip())
        else:
            self.host = (env_cfg.get("PROXY_IP") or ip).strip()
            self.port = int(env_cfg.get("PROXY_PORT") or port)
            self.username = (env_cfg.get("PROXY_LOGIN") or login).strip() or None
            self.password = (env_cfg.get("PROXY_PASSWORD") or password).strip() or None

        if not self.host or not self.port:
            raise ValueError("Не указан IP или порт прокси.")

    def _parse_flexible_string(self, text: str) -> None:
        if "://" not in text and "@" not in text and text.count(":") >= 3:
            parts = text.split(":", 3)
            self.host = parts[0].strip()
            self.port = int(parts[1].strip())
            self.username = parts[2].strip() or None
            self.password = parts[3].strip() or None
            return

        raw = text if "://" in text else f"http://{text}"
        parsed = urllib.parse.urlparse(raw)
        if parsed.scheme in ("http", "https"):
            self.scheme = parsed.scheme
        if not parsed.hostname or not parsed.port:
            raise ValueError(f"Не удалось распознать адрес прокси: {text}")

        self.host = parsed.hostname
        self.port = int(parsed.port)
        self.username = (
            urllib.parse.unquote(parsed.username) if parsed.username else None
        )
        self.password = (
            urllib.parse.unquote(parsed.password) if parsed.password else None
        )

    @property
    def has_auth(self) -> bool:
        return bool(self.username and self.password is not None)

    @property
    def auth_header(self) -> Optional[str]:
        if not self.has_auth:
            return None
        creds = f"{self.username}:{self.password}".encode("utf-8")
        return f"Basic {base64.b64encode(creds).decode('ascii')}"

    @property
    def full_url(self) -> str:
        if self.has_auth:
            u = urllib.parse.quote(self.username or "", safe="")
            p = urllib.parse.quote(self.password or "", safe="")
            return f"{self.scheme}://{u}:{p}@{self.host}:{self.port}"
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def safe_display_url(self) -> str:
        if self.has_auth:
            return f"{self.scheme}://{self.username}:***@{self.host}:{self.port}"
        return f"{self.scheme}://{self.host}:{self.port}"


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class LocalProxyBridgeHandler(socketserver.BaseRequestHandler):
    """Локальный HTTP/CONNECT мост (127.0.0.1:18888) с автоматической Basic-авторизацией."""

    upstream: UpstreamProxyConfig

    def handle(self) -> None:
        try:
            self.request.settimeout(20.0)
            initial_data = self._read_until_header_end(self.request)
            if not initial_data:
                return

            header_end = initial_data.find(b"\r\n\r\n")
            if header_end == -1:
                return

            header_bytes = initial_data[:header_end]
            body_remainder = initial_data[header_end + 4 :]
            lines = header_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
            if not lines:
                return

            request_line = lines[0]
            headers = lines[1:]

            with socket.create_connection(
                (self.upstream.host, self.upstream.port), timeout=20.0
            ) as upstream_sock:
                upstream_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                upstream_sock.settimeout(None)
                self.request.settimeout(None)

                filtered = [
                    h
                    for h in headers
                    if not h.lower().startswith("proxy-authorization:")
                ]
                if self.upstream.auth_header:
                    filtered.append(
                        f"Proxy-Authorization: {self.upstream.auth_header}"
                    )

                rebuilt = (
                    "\r\n".join([request_line] + filtered) + "\r\n\r\n"
                ).encode("iso-8859-1") + body_remainder

                upstream_sock.sendall(rebuilt)
                self._bidirectional_tunnel(self.request, upstream_sock)
        except Exception:
            pass

    @staticmethod
    def _read_until_header_end(sock: socket.socket, max_bytes: int = 65536) -> bytes:
        buf = bytearray()
        while b"\r\n\r\n" not in buf and len(buf) < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    @staticmethod
    def _bidirectional_tunnel(
        client_sock: socket.socket, upstream_sock: socket.socket
    ) -> None:
        sockets = [client_sock, upstream_sock]
        while True:
            readable, _, exceptional = select.select(
                sockets, [], sockets, STREAM_SOCKET_TIMEOUT
            )
            if exceptional or not readable:
                break
            for s in readable:
                other = upstream_sock if s is client_sock else client_sock
                try:
                    data = s.recv(65536)
                    if not data:
                        return
                    other.sendall(data)
                except OSError:
                    return


def is_bridge_listening(
    host: str = LOCAL_BRIDGE_HOST, port: int = LOCAL_BRIDGE_PORT
) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return s.connect_ex((host, port)) == 0


def is_agy_process_running() -> bool:
    my_pid = os.getpid()
    proc_root = Path("/proc")
    if not proc_root.exists():
        return False

    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == my_pid:
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8", errors="ignore").strip()
            if comm in ("agy", "agy.patched", "antigravity", "language_server"):
                return True
        except Exception:
            continue
    return False


def create_patched_agy_binary(source_agy: Path, verbose: bool = False) -> Path:
    """
    Создает локальную пропатченную копию бинарника `agy` в ~/.local/share/agy-proxy/agy.patched.
    Заменяет 10-байтовую строку `ineligible` -> `inexigible` (и `INELIGIBLE` -> `INEXIGIBLE`),
    чтобы клиентская проверка региона (Eligibility check) не блокировала вход.
    Оригинальный системный файл (/usr/bin/agy) остается нетронутым!
    """
    SHARE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        src_stat = source_agy.stat()
        src_sig = f"{source_agy}:{src_stat.st_size}:{int(src_stat.st_mtime)}"

        if PATCHED_AGY_PATH.exists() and PATCHED_META_PATH.exists():
            meta = json.loads(PATCHED_META_PATH.read_text(encoding="utf-8"))
            if meta.get("source_sig") == src_sig:
                return PATCHED_AGY_PATH

        raw_bytes = source_agy.read_bytes()
        count_lower = raw_bytes.count(b"ineligible")
        count_upper = raw_bytes.count(b"INELIGIBLE")

        patched_bytes = raw_bytes.replace(b"ineligible", b"inexigible").replace(
            b"INELIGIBLE", b"INEXIGIBLE"
        )

        tmp_path = PATCHED_AGY_PATH.with_suffix(".tmp")
        tmp_path.write_bytes(patched_bytes)
        tmp_path.chmod(0o755)
        tmp_path.replace(PATCHED_AGY_PATH)

        PATCHED_META_PATH.write_text(
            json.dumps(
                {
                    "source_sig": src_sig,
                    "replaced_lower": count_lower,
                    "replaced_upper": count_upper,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        if verbose:
            print(
                f"[+] Создана пропатченная копия бинарника: {PATCHED_AGY_PATH}\n"
                f"    (заменено вхождений 'ineligible' -> 'inexigible': {count_lower + count_upper})"
            )
        return PATCHED_AGY_PATH
    except Exception as exc:
        if verbose:
            print(f"[!] Не удалось создать патч бинарника ({exc}), используем оригинал.")
        return source_agy


def reset_cached_eligibility_and_auth() -> None:
    """
    Очищает закешированный статус 'not eligible' в локальных папках Antigravity CLI,
    чтобы при следующем запуске выполнилась чистая проверка через прокси.
    """
    home = Path.home()
    targets = [
        home / ".gemini" / "antigravity-cli",
        home / ".config" / "Antigravity" / "Cache",
        home / ".config" / "Antigravity" / "Network",
        home / ".config" / "Antigravity" / "Session Storage",
        home / ".cache" / "antigravity",
        home / ".cache" / "agy",
    ]
    for t in targets:
        if t.exists():
            try:
                shutil.rmtree(t)
                print(f"[+] Очищен кэш сессии/региона: {t}")
            except Exception as exc:
                print(f"[!] Не удалось удалить {t}: {exc}")

    print(
        "[+] Локальный кэш региона сброшен.\n"
        "    Если вы уже залогинены в agy, введите внутри agy команду: /logout , а затем /login"
    )


def ensure_linux_configs(
    bridge_host: str = LOCAL_BRIDGE_HOST, bridge_port: int = LOCAL_BRIDGE_PORT
) -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    local_url = f"http://{bridge_host}:{bridge_port}"

    pc_content = f"""# Auto-generated by agy_cachyos_proxy.py
strict_chain
quiet_mode
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 180000
tcp_connect_time_out 15000

# Исключаем локальные адреса для штатной работы OAuth-коллбэка на localhost
localnet 127.0.0.0/255.0.0.0
localnet 10.0.0.0/255.0.0.0
localnet 172.16.0.0/255.240.0.0
localnet 192.168.0.0/255.255.0.0

[ProxyList]
http {bridge_host} {bridge_port}
"""
    PROXYCHAINS_CONF.write_text(pc_content, encoding="utf-8")

    agy_settings_dir = Path.home() / ".gemini" / "antigravity-cli"
    agy_settings_file = agy_settings_dir / "settings.json"
    try:
        agy_settings_dir.mkdir(parents=True, exist_ok=True)
        data: Dict[str, Any] = {}
        if agy_settings_file.exists():
            raw = agy_settings_file.read_text(encoding="utf-8", errors="replace").strip()
            if raw:
                data = json.loads(raw)
        data["proxy"] = local_url
        data["http.proxy"] = local_url
        agy_settings_file.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except Exception:
        pass

    return PROXYCHAINS_CONF


def verify_proxy_and_region(proxy: UpstreamProxyConfig) -> bool:
    print(f"[*] Проверка HTTP-прокси: {proxy.safe_display_url}")
    proxy_handler = urllib.request.ProxyHandler(
        {"http": proxy.full_url, "https": proxy.full_url}
    )
    opener = urllib.request.build_opener(
        proxy_handler,
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )

    try:
        req = urllib.request.Request(
            "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,hosting,query",
            headers={"User-Agent": "curl/8.7.1"},
        )
        with opener.open(req, timeout=12) as resp:
            info = json.loads(resp.read().decode("utf-8", errors="replace"))

        if info.get("status") == "success":
            cc = info.get("countryCode", "??")
            print(f"[+] Выходной IP прокси : {info.get('query')}")
            print(
                f"[+] Регион / Страна    : {info.get('country')} ({cc}) {info.get('city', '')}"
            )
            print(f"[+] Провайдер (ISP)    : {info.get('isp')}")
            if cc in {"RU", "BY", "CN", "HK", "IR", "KP", "CU", "SY"}:
                print(
                    f"[!] ВНИМАНИЕ: Страна прокси ({cc}) заблокирована для Antigravity!"
                )
            if info.get("hosting"):
                print(
                    "[!] ЗАМЕТКА: IP принадлежит дата-центру/хостингу (Datacenter ASN)."
                )
    except Exception as exc:
        print(f"[-] Ошибка соединения через прокси: {exc}")
        return False

    print("\n[*] Проверка HTTPS CONNECT до серверов Google Antigravity:")
    all_ok = True
    for name, url in ANTIGRAVITY_ENDPOINTS:
        try:
            req = urllib.request.Request(
                url, method="HEAD", headers={"User-Agent": "agy/2.0 (linux; x86_64)"}
            )
            with opener.open(req, timeout=10) as resp:
                print(f"  [OK] {name:<28} -> HTTP {resp.getcode()}")
        except urllib.error.HTTPError as http_err:
            print(f"  [OK] {name:<28} -> TLS-туннель установлен (HTTP {http_err.code})")
        except Exception as err:
            print(f"  [ОШИБКА] {name:<24} -> {err}")
            all_ok = False
    return all_ok


def run_bridge_daemon(
    upstream: UpstreamProxyConfig,
    host: str = LOCAL_BRIDGE_HOST,
    port: int = LOCAL_BRIDGE_PORT,
    auto_shutdown: bool = False,
) -> int:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ensure_linux_configs(host, port)

    class BoundBridgeHandler(LocalProxyBridgeHandler):
        pass

    BoundBridgeHandler.upstream = upstream

    try:
        server = ThreadedTCPServer((host, port), BoundBridgeHandler)
    except OSError as exc:
        print(f"[-] Порт {host}:{port} уже занят: {exc}", file=sys.stderr)
        return 1

    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    stop_event = threading.Event()

    def _sig_handler(signum: int, frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    print(
        f"[+] Мост для Antigravity CLI запущен на http://{host}:{port} -> {upstream.safe_display_url}",
        flush=True,
    )

    idle_since: Optional[float] = None
    try:
        while not stop_event.is_set():
            if auto_shutdown:
                if is_agy_process_running():
                    idle_since = None
                else:
                    if idle_since is None:
                        idle_since = time.monotonic()
                    elif (time.monotonic() - idle_since) >= IDLE_SHUTDOWN_SECONDS:
                        break
            stop_event.wait(2.0)
    finally:
        server.shutdown()
        try:
            if PID_FILE.exists():
                PID_FILE.unlink()
        except Exception:
            pass

    return 0


def spawn_background_daemon_if_needed(
    raw_proxy: Optional[str], host: str, port: int
) -> bool:
    if is_bridge_listening(host, port):
        return True

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--daemon",
        "--auto-shutdown",
        "--port",
        str(port),
    ]
    if raw_proxy:
        cmd.extend(["--proxy", raw_proxy])

    log_fp = open(LOG_FILE, "a", encoding="utf-8")
    subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=log_fp,
        stderr=log_fp,
        start_new_session=True,
    )

    for _ in range(40):
        if is_bridge_listening(host, port):
            return True
        time.sleep(0.1)

    return is_bridge_listening(host, port)


def find_real_agy_binary(custom_bin: Optional[str] = None) -> Optional[Path]:
    if custom_bin:
        p = Path(custom_bin).expanduser().resolve()
        if p.exists():
            return p

    my_self = Path(__file__).resolve()
    wrapper_path = (Path.home() / ".local" / "bin" / "agy").resolve()

    search_candidates = [
        Path("/usr/bin/agy"),
        Path("/opt/Antigravity/bin/agy"),
        Path("/usr/lib/antigravity-cli/agy"),
        Path.home() / ".local" / "share" / "agy-proxy" / "agy.real",
        Path.home() / ".antigravity" / "bin" / "agy",
        Path.home() / ".local" / "bin" / "agy.real",
    ]

    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        if not path_dir:
            continue
        search_candidates.append(Path(path_dir) / "agy")

    for cand in search_candidates:
        try:
            if not cand.exists():
                continue
            resolved = cand.resolve()
            if resolved in (my_self, wrapper_path, PATCHED_AGY_PATH.resolve()):
                continue
            if cand.stat().st_size < 4096:
                head = cand.read_bytes()[:512]
                if b"AGY_CACHYOS_WRAPPER" in head:
                    continue
            return cand
        except Exception:
            continue

    return None


def build_agy_environment(local_bridge_url: str) -> Dict[str, str]:
    """
    Формирует переменные окружения для Go/gRPC стека `agy`.
    Ключевая настройка для Linux: GODEBUG=netdns=cgo заставляет Go использовать
    резолвер glibc вместо прямых UDP/TCP syscalls в обход proxychains4.
    """
    env = os.environ.copy()
    no_proxy = "localhost,127.0.0.1,::1,0.0.0.0,.local"

    existing_godebug = env.get("GODEBUG", "")
    godebug_parts = [p for p in existing_godebug.split(",") if p]
    if not any(p.startswith("netdns=") for p in godebug_parts):
        godebug_parts.append("netdns=cgo")

    env.update(
        {
            "HTTP_PROXY": local_bridge_url,
            "HTTPS_PROXY": local_bridge_url,
            "ALL_PROXY": local_bridge_url,
            "http_proxy": local_bridge_url,
            "https_proxy": local_bridge_url,
            "all_proxy": local_bridge_url,
            "GRPC_PROXY_EXP": local_bridge_url,
            "AG_LS_PROXY": local_bridge_url,
            "DETECT_AND_USE_PROXY": "ENABLED",
            "DETECT_AND_USE_PROXY_ENABLED": "1",
            "NODE_USE_ENV_PROXY": "1",
            "GODEBUG": ",".join(godebug_parts),
            "NO_PROXY": no_proxy,
            "no_proxy": no_proxy,
        }
    )
    return env


def run_agy_with_proxy(
    real_agy: Path,
    bridge_host: str,
    bridge_port: int,
    agy_args: List[str],
    use_proxychains: bool = True,
    use_binary_patch: bool = True,
) -> int:
    local_bridge_url = f"http://{bridge_host}:{bridge_port}"
    pc_conf = ensure_linux_configs(bridge_host, bridge_port)
    env = build_agy_environment(local_bridge_url)

    target_binary = (
        create_patched_agy_binary(real_agy, verbose=False)
        if use_binary_patch
        else real_agy
    )

    cmd: List[str] = []
    if use_proxychains:
        pc_bin = shutil.which("proxychains4") or shutil.which("proxychains")
        if pc_bin:
            cmd.extend([pc_bin, "-q", "-f", str(pc_conf)])

    cmd.append(str(target_binary))
    cmd.extend(agy_args)

    try:
        proc = subprocess.Popen(cmd, env=env)
        return proc.wait()
    except KeyboardInterrupt:
        return 130


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CachyOS / Arch Linux HTTP Proxy Router & Unlocker для Antigravity CLI (agy)",
        add_help=False,
    )
    parser.add_argument("--proxy", type=str, default=None)
    parser.add_argument("--agy-bin", type=str, default=None)
    parser.add_argument("--port", type=int, default=LOCAL_BRIDGE_PORT)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--auto-shutdown", action="store_true")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--patch-only", action="store_true")
    parser.add_argument("--reset-auth", action="store_true")
    parser.add_argument("--stop-daemon", action="store_true")
    parser.add_argument("--no-proxychains", action="store_true")
    parser.add_argument("--no-binary-patch", action="store_true")
    parser.add_argument("--proxy-help", action="store_true")

    known, agy_args = parser.parse_known_args()

    if known.proxy_help:
        print(
            "Использование agy_cachyos_proxy.py:\n"
            "  --check-only       Проверить HTTP-прокси, регион IP и доступность серверов Antigravity\n"
            "  --patch-only       Создать пропатченную копию agy (ineligible -> inexigible)\n"
            "  --reset-auth       Сбросить закешированный статус 'not eligible' в ~/.gemini и ~/.config\n"
            "  --daemon           Запустить локальный HTTP/CONNECT мост (127.0.0.1:18888)\n"
            "  --stop-daemon      Остановить фоновый мост\n"
            "  --proxy STR        Передать прокси (ip:port:login:pass или http://login:pass@ip:port)\n"
            "  Все остальные аргументы передаются напрямую в бинарник `agy`."
        )
        return 0

    if known.reset_auth:
        reset_cached_eligibility_and_auth()
        if not agy_args and not known.patch_only and not known.check_only:
            return 0

    if known.patch_only:
        real_agy = find_real_agy_binary(known.agy_bin)
        if not real_agy:
            print("[-] Бинарник `agy` не найден в системе.", file=sys.stderr)
            return 1
        create_patched_agy_binary(real_agy, verbose=True)
        return 0

    if known.stop_daemon:
        if PID_FILE.exists():
            try:
                pid = int(PID_FILE.read_text(encoding="utf-8").strip())
                os.kill(pid, signal.SIGTERM)
                print(f"[+] Фоновый прокси-мост (PID {pid}) остановлен.")
            except Exception as exc:
                print(f"[!] Не удалось остановить процесс: {exc}")
            finally:
                PID_FILE.unlink(missing_ok=True)
        else:
            print("[*] Активный PID-файл фонового моста не найден.")
        return 0

    try:
        upstream = UpstreamProxyConfig(raw_input=known.proxy)
    except ValueError as err:
        print(f"[-] Ошибка настроек прокси: {err}", file=sys.stderr)
        return 1

    if known.check_only:
        ok = verify_proxy_and_region(upstream)
        return 0 if ok else 1

    if known.daemon:
        return run_bridge_daemon(
            upstream,
            host=LOCAL_BRIDGE_HOST,
            port=known.port,
            auto_shutdown=known.auto_shutdown,
        )

    ready = spawn_background_daemon_if_needed(
        known.proxy, LOCAL_BRIDGE_HOST, known.port
    )
    if not ready:
        print(
            "[-] Не удалось поднять локальный прокси-мост на 127.0.0.1:18888. Проверьте ~/.config/agy-proxy/bridge.log",
            file=sys.stderr,
        )
        return 1

    real_agy = find_real_agy_binary(known.agy_bin)
    if not real_agy:
        print(
            "[-] Бинарник `agy` не найден в системе.\n"
            "    Установите Antigravity CLI из AUR: paru -S antigravity-cli",
            file=sys.stderr,
        )
        return 1

    return run_agy_with_proxy(
        real_agy=real_agy,
        bridge_host=LOCAL_BRIDGE_HOST,
        bridge_port=known.port,
        agy_args=agy_args,
        use_proxychains=not known.no_proxychains,
        use_binary_patch=not known.no_binary_patch,
    )


if __name__ == "__main__":
    sys.exit(main())
