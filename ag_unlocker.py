#!/usr/bin/env python3
"""
Antigravity Unlocker for macOS
Адаптация обхода региональных ограничений и подключение своего HTTP-прокси для macOS.
"""

import os
import sys
import re
import socket
import ssl
import base64
import time
import json
import signal
import shutil
import threading
import subprocess
from pathlib import Path
from urllib.parse import unquote

GATE_HOSTS = {
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "cloudaicompanion.googleapis.com",
    "aiplatform.googleapis.com",
    "jetski-webchannel.googleapis.com",
}
PROBE_HOST = "daily-cloudcode-pa.googleapis.com"
DEFAULT_LOCAL_PORT = 53129
FALLBACK_PORTS = [43129, 44129, 45129, 46129, 47129, 48129]
PROXY_VAR_NAME = "AG_LS_PROXY"

# Паттерны байтовых замен в бинарниках (одинаковая длина байт!)
PATCH_INELIGIBLE_OLD = b"ineligible"
PATCH_INELIGIBLE_NEW = b"inexigible"

PATCH_TIERS_OLD = b"ineligible_tiers"
PATCH_TIERS_NEW = b"inexigible_tiers"

PATCH_PROXY_OLD = b"https_proxy"
PATCH_PROXY_NEW = b"AG_LS_PROXY"

# Сигнатуры для разблокировки входа в Google-аккаунт из-под санкций (JS-патчи)
RE_IDE_AUTH = re.compile(
    r'async\s+([A-Za-z_$0-9]+)\(([A-Za-z_$0-9]+)\)\s*\{\s*if\(this\.([A-Za-z_$0-9]+)\.send\(\{type:[A-Za-z_$0-9]+\.isGcpTos\?"GCP_SIGN_IN":"SIGN_IN"\}\),this\.([A-Za-z_$0-9]+)\.resetIsTierGCPTos\(\),this\.[A-Za-z_$0-9]+\.isGoogleInternal\)\{try\{await this\.([A-Za-z_$0-9]+)\.loadCodeAssist\([A-Za-z_$0-9]+\);const\{settings:([A-Za-z_$0-9]+),userTier:([A-Za-z_$0-9]+)\}=await this\.refreshUserStatus\([A-Za-z_$0-9]+\),([A-Za-z_$0-9]+)=([A-Za-z_$0-9]+)\([A-Za-z_$0-9]+\);this\.([A-Za-z_$0-9]+)\.pushUpdate\([A-Za-z_$0-9]+\),this\.[A-Za-z_$0-9]+\.send\(\{type:"AUTH_SUCCESS",tokenInfo:[A-Za-z_$0-9]+\}\),this\.([A-Za-z_$0-9]+)\.fire\(\{settings:[A-Za-z_$0-9]+,userTier:[A-Za-z_$0-9]+\}\)\}catch\(([A-Za-z_$0-9]+)\)\{.*?(?:return\}|return;\s*\})'
)

RE_EXT_STATUS = re.compile(
    r'const t=await ([A-Za-z_$][A-Za-z_$0-9.]*)\.UserStatus\.getUserStatus\(\);if\(!t\)return\[\];const n=\(0,([A-Za-z_$][A-Za-z_$0-9.]*)\)\(t,([A-Za-z_$][A-Za-z_$0-9.]*)\),\{email:([A-Za-z_$][A-Za-z_$0-9]*),name:([A-Za-z_$][A-Za-z_$0-9]*)\}=n;return""===([A-Za-z_$][A-Za-z_$0-9]*)\?\[\]:'
)

CONFIG_DIR = Path.home() / ".local" / "share" / "agunlocker"
UPSTREAM_FILE = CONFIG_DIR / "upstream.txt"
PID_FILE = CONFIG_DIR / "proxy.pid"
PORT_FILE = CONFIG_DIR / "proxy_port"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
LOG_FILE = CONFIG_DIR / "mac_unlocker.log"
LAST_ACTIVITY_FILE = CONFIG_DIR / "last_activity.txt"


def log(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def record_activity(msg: str):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        LAST_ACTIVITY_FILE.write_text(f"[{time.strftime('%H:%M:%S')}] {msg}", encoding="utf-8")
    except Exception:
        pass


def get_last_activity() -> str:
    if LAST_ACTIVITY_FILE.is_file():
        try:
            return LAST_ACTIVITY_FILE.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    return ""


class UpstreamProxy:
    def __init__(self, host: str, port: int, user: str = None, password: str = None):
        self.host = host
        self.port = port
        self.user = user
        self.password = password

    @property
    def auth_header(self) -> str:
        if self.user is not None and self.password is not None:
            raw = f"{self.user}:{self.password}".encode("utf-8")
            b64 = base64.b64encode(raw).decode("ascii")
            return f"Basic {b64}"
        return ""

    def display(self) -> str:
        if self.user:
            return f"http://{self.user}:***@{self.host}:{self.port}"
        return f"http://{self.host}:{self.port}"

    def to_config_line(self) -> str:
        if self.user is not None and self.password is not None:
            return f"{self.user}:{self.password}@{self.host}:{self.port}"
        return f"{self.host}:{self.port}"

    @classmethod
    def parse(cls, input_str: str) -> "UpstreamProxy":
        raw = input_str.strip()
        if not raw:
            raise ValueError("Пустая строка")

        rest = raw
        if rest.startswith("http://"):
            rest = rest[len("http://") :]
        elif rest.startswith("https://"):
            rest = rest[len("https://") :]

        if "://" in rest:
            raise ValueError("Поддерживается только HTTP-прокси (http://...)")

        if "@" in rest:
            auth_part, hostport_part = rest.rsplit("@", 1)
            if ":" not in auth_part:
                raise ValueError("Логин без пароля — формат: логин:пароль@хост:порт")
            user, password = auth_part.split(":", 1)
            user = unquote(user)
            password = unquote(password)
        else:
            user = None
            password = None
            hostport_part = rest

        hostport_part = hostport_part.rstrip("/")
        if ":" not in hostport_part:
            raise ValueError("Не указан порт — формат: хост:порт")

        host, port_str = hostport_part.rsplit(":", 1)
        host = host.strip("[]").strip()
        if not host:
            raise ValueError("Не указан хост/адрес")

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError("Порт должен быть от 1 до 65535")
        except ValueError:
            raise ValueError(f"Некорректный порт: {port_str}")

        return cls(host=host, port=port, user=user, password=password)


def save_upstream(up: UpstreamProxy):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    UPSTREAM_FILE.write_text(up.to_config_line(), encoding="utf-8")


def load_upstream() -> UpstreamProxy | None:
    if not UPSTREAM_FILE.is_file():
        return None
    try:
        content = UPSTREAM_FILE.read_text(encoding="utf-8").strip()
        if not content:
            return None
        return UpstreamProxy.parse(content)
    except Exception:
        return None


def clear_upstream():
    if UPSTREAM_FILE.is_file():
        try:
            UPSTREAM_FILE.unlink()
        except Exception:
            pass


def is_gate_host(host: str) -> bool:
    h = host.strip("[]").rstrip(".").lower()
    if h in GATE_HOSTS:
        return True
    if h.endswith(".googleapis.com") and not h.startswith("storage."):
        return True
    return False


def probe_upstream(up: UpstreamProxy, timeout: float = 8.0) -> tuple[bool, str]:
    try:
        sock = socket.create_connection((up.host, up.port), timeout=timeout)
        sock.settimeout(timeout)

        req = f"CONNECT {PROBE_HOST}:443 HTTP/1.1\r\nHost: {PROBE_HOST}:443\r\n"
        if up.auth_header:
            req += f"Proxy-Authorization: {up.auth_header}\r\n"
        req += "\r\n"
        sock.sendall(req.encode("ascii"))

        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(1024)
            if not chunk:
                return False, "Прокси разорвал соединение до ответа"
            response += chunk
            if len(response) > 8192:
                return False, "Ответ прокси слишком длинный"

        status_line = response.decode("iso-8859-1", errors="replace").split("\r\n")[0]
        if " 200" not in status_line:
            if " 407" in status_line:
                return False, "Ошибка 407: Прокси требует авторизацию (неверный логин/пароль)"
            if " 403" in status_line:
                return False, "Ошибка 403: Прокси запрещает подключение к Google"
            return False, f"Прокси отклонил запрос: {status_line}"

        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=PROBE_HOST)
        tls_sock.settimeout(timeout)

        tls_req = (
            f"GET /v1internal:probe HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}\r\n"
            f"User-Agent: AntigravityUnlocker/2.28 (Mac)\r\n"
            f"Connection: close\r\n\r\n"
        )
        tls_sock.sendall(tls_req.encode("ascii"))
        res = tls_sock.recv(256)
        tls_sock.close()

        if res:
            return True, f"Прокси отвечает! Доступ к Google подтверждён ({status_line.strip()})"
        return True, "CONNECT успешен, TLS соединение с Google установлено"
    except socket.timeout:
        return False, "Таймаут соединения с прокси"
    except Exception as e:
        return False, f"Ошибка подключения: {e}"


# ---------------------------------------------------------------------------
# Локальный CONNECT прокси (127.0.0.1:53129)
# ---------------------------------------------------------------------------

class LocalProxyServer:
    def __init__(self, port: int = DEFAULT_LOCAL_PORT):
        self.port = port
        self.server_sock = None
        self.running = False
        self.thread = None

    def start(self, background: bool = True) -> bool:
        candidate_ports = [self.port] + [p for p in FALLBACK_PORTS if p != self.port]
        bound = False
        for p in candidate_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", p))
                s.listen(128)
                self.server_sock = s
                self.port = p
                bound = True
                break
            except Exception:
                continue

        if not bound:
            log("Не удалось занять локальный порт для прокси")
            return False

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        PORT_FILE.write_text(str(self.port), encoding="utf-8")
        PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
        self.running = True

        log(f"Локальный прокси запущен на 127.0.0.1:{self.port}")

        if background:
            self.thread = threading.Thread(target=self._accept_loop, daemon=True)
            self.thread.start()
            return True
        else:
            self._accept_loop()
            return True

    def stop(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        if PID_FILE.is_file():
            try:
                PID_FILE.unlink()
            except Exception:
                pass
        log("Локальный прокси остановлен")

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, _ = self.server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                t.start()
            except Exception:
                if not self.running:
                    break
                time.sleep(0.05)

    def _handle_client(self, client: socket.socket):
        try:
            client.settimeout(10.0)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = client.recv(1024)
                if not chunk:
                    client.close()
                    return
                data += chunk
                if len(data) > 8192:
                    client.close()
                    return

            header_str = data.decode("iso-8859-1", errors="replace")
            first_line = header_str.split("\r\n")[0]
            parts = first_line.split()

            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                client.close()
                return

            target = parts[1]
            if ":" in target:
                host, port_s = target.rsplit(":", 1)
                port = int(port_s)
            else:
                host = target
                port = 443

            is_gate = (port == 443 and is_gate_host(host))
            up = load_upstream()

            if is_gate and up is not None:
                log(f"CONNECT {host}:{port} -> уходит через upstream прокси {up.display()}")
                record_activity(f"{host}:{port} -> через прокси {up.display()}")
                remote_sock = self._connect_upstream(up, host, port)
                if remote_sock is None:
                    log(f"CONNECT {host}:{port} -> прокси не ответил, фоллбек на прямое соединение")
                    remote_sock = socket.create_connection((host, port), timeout=8.0)
            else:
                log(f"CONNECT {host}:{port} -> прямое соединение (не gate host)")
                record_activity(f"{host}:{port} -> напрямую")
                remote_sock = socket.create_connection((host, port), timeout=8.0)

            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._splice(client, remote_sock)
        except Exception as e:
            try:
                client.close()
            except Exception:
                pass

    def _connect_upstream(self, up: UpstreamProxy, host: str, port: int) -> socket.socket | None:
        try:
            s = socket.create_connection((up.host, up.port), timeout=6.0)
            req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            if up.auth_header:
                req += f"Proxy-Authorization: {up.auth_header}\r\n"
            req += "\r\n"
            s.sendall(req.encode("ascii"))

            res = b""
            while b"\r\n\r\n" not in res:
                chunk = s.recv(1024)
                if not chunk:
                    s.close()
                    return None
                res += chunk

            if b" 200" not in res.split(b"\r\n")[0]:
                s.close()
                return None
            return s
        except Exception:
            return None

    def _splice(self, s1: socket.socket, s2: socket.socket):
        s1.settimeout(None)
        s2.settimeout(None)

        def pipe(src, dst):
            try:
                while True:
                    buf = src.recv(32768)
                    if not buf:
                        break
                    dst.sendall(buf)
            except Exception:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        t1 = threading.Thread(target=pipe, args=(s1, s2), daemon=True)
        t2 = threading.Thread(target=pipe, args=(s2, s1), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        try:
            s1.close()
        except Exception:
            pass
        try:
            s2.close()
        except Exception:
            pass


def is_proxy_daemon_running() -> tuple[bool, int, int]:
    if not PID_FILE.is_file():
        return False, 0, DEFAULT_LOCAL_PORT

    try:
        pid = int(PID_FILE.read_text().strip())
        port = int(PORT_FILE.read_text().strip()) if PORT_FILE.is_file() else DEFAULT_LOCAL_PORT

        try:
            os.kill(pid, 0)
        except OSError:
            PID_FILE.unlink(missing_ok=True)
            return False, 0, port

        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True, pid, port
        except Exception:
            return True, pid, port
    except Exception:
        return False, 0, DEFAULT_LOCAL_PORT


def stop_proxy_daemon():
    running, pid, _ = is_proxy_daemon_running()
    if running and pid > 0:
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.3)
        except Exception:
            pass
    PID_FILE.unlink(missing_ok=True)
    PORT_FILE.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Патчинг Antigravity на macOS
# ---------------------------------------------------------------------------

def find_mac_antigravity_installs() -> list[Path]:
    candidates = [
        Path("/Applications/Antigravity.app"),
        Path.home() / "Applications" / "Antigravity.app",
        Path("/Applications/Antigravity IDE.app"),
        Path.home() / "Applications" / "Antigravity IDE.app",
    ]
    cli_dirs = [
        Path.home() / ".gemini" / "bin",
        Path.home() / ".local" / "bin",
        Path("/usr/local/bin"),
    ]
    for c in cli_dirs:
        if (c / "agy").is_file():
            candidates.append(c)

    return [p for p in candidates if p.exists()]


def get_binary_targets(install_root: Path) -> list[Path]:
    targets = []
    if install_root.is_dir() and install_root.suffix == ".app":
        res_dir = install_root / "Contents" / "Resources"
        ext_bin = res_dir / "app" / "extensions" / "antigravity" / "bin"
        bin_dir = res_dir / "bin"

        for d in [ext_bin, bin_dir]:
            if d.is_dir():
                for item in d.iterdir():
                    if item.is_file() and not item.name.endswith(".ag_backup"):
                        name = item.name.lower()
                        if name.startswith("language_server") or name == "agy":
                            targets.append(item)

        gemini_bin = Path.home() / ".gemini" / "bin" / "agy"
        if gemini_bin.is_file() and gemini_bin not in targets:
            targets.append(gemini_bin)
    else:
        if install_root.is_file():
            targets.append(install_root)
        elif install_root.is_dir():
            for item in install_root.iterdir():
                if item.is_file() and not item.name.endswith(".ag_backup"):
                    if item.name.startswith("language_server") or item.name == "agy":
                        targets.append(item)

    # Дедупликация с сохранением порядка
    unique = []
    seen = set()
    for t in targets:
        try:
            r = t.resolve()
        except Exception:
            r = t
        if r not in seen:
            seen.add(r)
            unique.append(t)
    return unique


def inspect_binary(bin_path: Path) -> dict:
    name_lower = bin_path.name.lower()
    is_ls = "language_server" in name_lower

    res = {
        "path": bin_path,
        "name": bin_path.name,
        "is_ls": is_ls,
        "patched_eligibility": False,
        "patched_proxy_var": False,
        "can_patch": False,
        "is_done": False,
        "has_backup": bin_path.with_name(bin_path.name + ".ag_backup").is_file(),
    }
    try:
        data = bin_path.read_bytes()
        if PATCH_INELIGIBLE_NEW in data:
            res["patched_eligibility"] = True
        elif PATCH_INELIGIBLE_OLD in data:
            res["can_patch"] = True

        if PATCH_PROXY_NEW in data:
            res["patched_proxy_var"] = True

        if is_ls:
            # Для language_server критичен патч ineligible
            res["is_done"] = res["patched_eligibility"]
        else:
            # Для agy сигнатуры ineligible нет в оригинале, смотрим proxy_var или отсутствие старых сигнатур
            res["is_done"] = res["patched_proxy_var"] or (PATCH_INELIGIBLE_OLD not in data)
    except Exception:
        pass
    return res


def patch_binary_file(bin_path: Path) -> tuple[bool, str]:
    try:
        data = bytearray(bin_path.read_bytes())
        backup_path = bin_path.with_name(bin_path.name + ".ag_backup")

        if not backup_path.exists():
            shutil.copy2(bin_path, backup_path)

        count_ineligible = 0
        count_proxy = 0

        # 1. ineligible -> inexigible
        idx = 0
        while True:
            idx = data.find(PATCH_INELIGIBLE_OLD, idx)
            if idx == -1:
                break
            data[idx : idx + len(PATCH_INELIGIBLE_NEW)] = PATCH_INELIGIBLE_NEW
            count_ineligible += 1
            idx += len(PATCH_INELIGIBLE_NEW)

        # 2. ineligible_tiers -> inexigible_tiers
        idx = 0
        while True:
            idx = data.find(PATCH_TIERS_OLD, idx)
            if idx == -1:
                break
            data[idx : idx + len(PATCH_TIERS_NEW)] = PATCH_TIERS_NEW
            idx += len(PATCH_TIERS_NEW)

        # 3. https_proxy -> AG_LS_PROXY
        idx = 0
        while True:
            idx = data.find(PATCH_PROXY_OLD, idx)
            if idx == -1:
                break
            data[idx : idx + len(PATCH_PROXY_NEW)] = PATCH_PROXY_NEW
            count_proxy += 1
            idx += len(PATCH_PROXY_NEW)

        tmp_path = bin_path.with_name(bin_path.name + ".tmp")
        tmp_path.write_bytes(data)
        os.chmod(tmp_path, os.stat(bin_path).st_mode)
        tmp_path.replace(bin_path)

        # Ad-hoc codesign на macOS
        re_sign_macho(bin_path)

        return True, f"ineligible: {count_ineligible}, proxy_var: {count_proxy}"
    except Exception as e:
        return False, str(e)


def unpatch_binary_file(bin_path: Path) -> tuple[bool, str]:
    backup_path = bin_path.with_name(bin_path.name + ".ag_backup")
    if backup_path.is_file():
        try:
            shutil.copy2(backup_path, bin_path)
            re_sign_macho(bin_path)
            return True, "Восстановлено из бэкапа"
        except Exception as e:
            return False, f"Ошибка восстановления: {e}"

    try:
        data = bytearray(bin_path.read_bytes())
        data = data.replace(PATCH_INELIGIBLE_NEW, PATCH_INELIGIBLE_OLD)
        data = data.replace(PATCH_TIERS_NEW, PATCH_TIERS_OLD)
        data = data.replace(PATCH_PROXY_NEW, PATCH_PROXY_OLD)

        tmp_path = bin_path.with_name(bin_path.name + ".tmp")
        tmp_path.write_bytes(data)
        os.chmod(tmp_path, os.stat(bin_path).st_mode)
        tmp_path.replace(bin_path)
        re_sign_macho(bin_path)
        return True, "Патч снят обратной заменой"
    except Exception as e:
        return False, str(e)


def re_sign_macho(bin_path: Path):
    if sys.platform != "darwin":
        return
    try:
        subprocess.run(
            ["codesign", "--force", "--deep", "-s", "-", str(bin_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        pass


def kill_antigravity_processes():
    """Завершает все процессы Antigravity и языкового сервера перед патчем"""
    cmds = [
        ["killall", "-9", "Antigravity"],
        ["killall", "-9", "Antigravity IDE"],
        ["killall", "-9", "language_server"],
        ["killall", "-9", "language_server_darwin_arm64"],
        ["killall", "-9", "language_server_darwin_x64"],
        ["killall", "-9", "agy"],
        ["pkill", "-9", "-i", "-f", "language_server"],
        ["pkill", "-9", "-i", "-f", "antigravity"],
        ["pkill", "-9", "-i", "-f", "agy"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except Exception:
            pass
    time.sleep(1.0)


# ---------------------------------------------------------------------------
# Разблокировка входа в аккаунт из-под санкций (JS-патчи)
# ---------------------------------------------------------------------------

def get_js_targets(install_root: Path) -> list[Path]:
    targets = []
    if install_root.is_dir() and install_root.suffix == ".app":
        res_dir = install_root / "Contents" / "Resources"
        app_dir = res_dir / "app"

        ide_main = app_dir / "out" / "main.js"
        ext_main = app_dir / "extensions" / "antigravity" / "dist" / "extension.js"
        desktop_main = app_dir / "dist" / "main.js"

        for p in [ide_main, ext_main, desktop_main]:
            if p.is_file() and not p.name.endswith(".ag_backup"):
                targets.append(p)
    return targets


def inspect_js_file(js_path: Path) -> dict:
    res = {
        "path": js_path,
        "name": js_path.name,
        "patched": False,
        "has_backup": js_path.with_name(js_path.name + ".ag_backup").is_file(),
    }
    try:
        content = js_path.read_text(encoding="utf-8", errors="ignore")
        if "// UNLOCKED" in content or "/*[AG_EXT_PATCHED]*/" in content or "/*[AG_IDE_PATCHED]*/" in content:
            res["patched"] = True
    except Exception:
        pass
    return res


def patch_ide_main_js(main_js: Path) -> tuple[bool, str]:
    try:
        content = main_js.read_text(encoding="utf-8")
        if "// UNLOCKED" in content or "/*[AG_IDE_PATCHED]*/" in content:
            return True, "Уже пропатчен"

        m = RE_IDE_AUTH.search(content)
        if not m:
            return False, "Сигнатура авторизации в main.js не найдена"

        fname = m.group(1)
        var_t = m.group(2)
        var_t_send = m.group(3)
        var_y = m.group(4)
        var_i = m.group(8)
        var_func = m.group(9)
        var_f = m.group(10)
        var_h = m.group(11)

        payload = (
            f"async {fname}({var_t}){{\n"
            f"    this.{var_t_send}.send({{type:{var_t}.isGcpTos?\"GCP_SIGN_IN\":\"SIGN_IN\"}});\n"
            f"    this.{var_y}.resetIsTierGCPTos();\n"
            f"    try {{\n"
            f"        try {{ await this.{var_y}.loadCodeAssist({var_t}); }} catch(_) {{}}\n"
            f"        try {{ await this.{var_y}.onboardUser(\"standard-tier\", {var_t}); }} catch(_) {{\n"
            f"            try {{ await this.{var_y}.onboardUser(\"free-tier\", {var_t}); }} catch(__) {{}}\n"
            f"        }}\n"
            f"        let __res = {{ settings: {{}}, userTier: {{ id: \"pro\", description: \"Pro\" }} }};\n"
            f"        try {{ __res = await this.refreshUserStatus({var_t}); }} catch(_) {{}}\n"
            f"        const {var_i} = {var_func}({var_t});\n"
            f"        try {{ this.{var_f}.pushUpdate({var_i}); }} catch(_) {{}}\n"
            f"        this.{var_t_send}.send({{type:\"AUTH_SUCCESS\",tokenInfo:{var_t}}});\n"
            f"        this.{var_h}.fire({{settings:__res.settings, userTier:__res.userTier}});\n"
            f"    }} catch(e) {{}}\n"
            f"    return;\n"
        )

        backup_path = main_js.with_name(main_js.name + ".ag_backup")
        if not backup_path.exists():
            shutil.copy2(main_js, backup_path)

        new_content = content[: m.start()] + payload + content[m.end() :] + "\n/*[AG_IDE_PATCHED]*/\n// UNLOCKED\n"

        tmp_path = main_js.with_name(main_js.name + ".tmp")
        tmp_path.write_text(new_content, encoding="utf-8")
        os.chmod(tmp_path, os.stat(main_js).st_mode)
        tmp_path.replace(main_js)
        return True, "Патч авторизации main.js успешно применён"
    except Exception as e:
        return False, str(e)


def patch_extension_js(ext_js: Path) -> tuple[bool, str]:
    try:
        content = ext_js.read_text(encoding="utf-8")
        if "/*[AG_EXT_PATCHED]*/" in content:
            return True, "Уже пропатчен"

        m = RE_EXT_STATUS.search(content)
        if not m:
            return False, "Сигнатура UserStatus в extension.js не найдена"

        ns = m.group(1)
        p2 = m.group(2)
        dz7 = m.group(3)
        email = m.group(4)
        name = m.group(5)

        replacement = (
            f"const t=await {ns}.UserStatus.getUserStatus();let {email}=\"\",{name}=\"\";"
            f"try{{if(t){{const n=(0,{p2})(t,{dz7});{email}=n.email||\"\";{name}=n.name||\"\";}}}}catch(_){{}}"
            f"if({email}===\"\"){{{email}=\"antigravity-user\";{name}=\"User\";}}return false?[]:"
        )

        backup_path = ext_js.with_name(ext_js.name + ".ag_backup")
        if not backup_path.exists():
            shutil.copy2(ext_js, backup_path)

        new_content = "/*[AG_EXT_PATCHED]*/\n" + content[: m.start()] + replacement + content[m.end() :] + "\n// UNLOCKED\n"

        tmp_path = ext_js.with_name(ext_js.name + ".tmp")
        tmp_path.write_text(new_content, encoding="utf-8")
        os.chmod(tmp_path, os.stat(ext_js).st_mode)
        tmp_path.replace(ext_js)
        return True, "Патч UserStatus extension.js успешно применён"
    except Exception as e:
        return False, str(e)


def patch_desktop_main_js(desktop_js: Path) -> tuple[bool, str]:
    try:
        content = desktop_js.read_text(encoding="utf-8")
        if "// UNLOCKED" in content:
            return True, "Уже пропатчен"

        new_content = re.sub(
            r'_handleAuthErrorResponse\(([a-zA-Z_$]+)\)\{var ([a-zA-Z_$]+)=\1\?\.failureDetails;',
            r'_handleAuthErrorResponse(\1){var \2=\1?.failureDetails; if(\2?.case==="ineligible"){ this._authActor.send({type:"AUTH_SUCCESS",tokenInfo:{accessToken:""},scopes:[],isGcpTos:false}); return; }',
            content,
        )
        new_content = re.sub(
            r'\?\.failureDetails\?\.case==="ineligible"\?this\._authActor\.send\(\{type:"SET_INELIGIBLE"',
            r'?.failureDetails?.case==="NEVER_MATCH"?this._authActor.send({type:"SET_INELIGIBLE"',
            new_content,
        )

        if new_content != content:
            backup_path = desktop_js.with_name(desktop_js.name + ".ag_backup")
            if not backup_path.exists():
                shutil.copy2(desktop_js, backup_path)
            tmp_path = desktop_js.with_name(desktop_js.name + ".tmp")
            tmp_path.write_text(new_content + "\n// UNLOCKED\n", encoding="utf-8")
            os.chmod(tmp_path, os.stat(desktop_js).st_mode)
            tmp_path.replace(desktop_js)
            return True, "Патч Desktop main.js применён"
        return False, "Сигнатуры Desktop не найдены"
    except Exception as e:
        return False, str(e)


def patch_account_auth_all(installs: list[Path] | None = None) -> list[tuple[str, bool, str]]:
    results = []
    if installs is None:
        installs = find_mac_antigravity_installs()
    for inst in installs:
        targets = get_js_targets(inst)
        for t in targets:
            name = t.name
            parent = t.parent.name
            label = f"{parent}/{name}"
            if name == "main.js" and parent == "out":
                ok, msg = patch_ide_main_js(t)
            elif name == "extension.js":
                ok, msg = patch_extension_js(t)
            elif name == "main.js" and parent == "dist":
                ok, msg = patch_desktop_main_js(t)
            else:
                continue
            results.append((label, ok, msg))
    return results


def unpatch_account_auth_all(installs: list[Path] | None = None) -> int:
    count = 0
    if installs is None:
        installs = find_mac_antigravity_installs()
    for inst in installs:
        targets = get_js_targets(inst)
        for t in targets:
            backup_path = t.with_name(t.name + ".ag_backup")
            if backup_path.is_file():
                try:
                    shutil.copy2(backup_path, t)
                    count += 1
                except Exception:
                    pass
    return count


# ---------------------------------------------------------------------------
# Настройка системного окружения и settings.json Antigravity на macOS
# ---------------------------------------------------------------------------

def get_antigravity_settings_paths() -> list[Path]:
    candidates = [
        Path.home() / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json",
        Path.home() / "Library" / "Application Support" / "Antigravity IDE" / "User" / "settings.json",
        Path.home() / "Library" / "Application Support" / "antigravity" / "User" / "settings.json",
        Path.home() / ".config" / "Antigravity" / "User" / "settings.json",
        Path.home() / ".config" / "antigravity" / "User" / "settings.json",
    ]
    app_support = Path.home() / "Library" / "Application Support"
    if app_support.is_dir():
        for d in app_support.iterdir():
            if d.is_dir() and "antigravity" in d.name.lower():
                p = d / "User" / "settings.json"
                if p not in candidates:
                    candidates.append(p)
    return candidates


def configure_antigravity_settings(port: int = DEFAULT_LOCAL_PORT):
    proxy_url = f"http://127.0.0.1:{port}"
    for p in get_antigravity_settings_paths():
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            if p.is_file():
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    lines = p.read_text(encoding="utf-8").splitlines()
                    clean_lines = [l for l in lines if not l.strip().startswith("//")]
                    try:
                        data = json.loads("\n".join(clean_lines))
                    except Exception:
                        data = {}
            data["http.proxy"] = proxy_url
            data["http.proxySupport"] = "override"
            p.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
            log(f"Прокси прописан в {p}")
        except Exception as e:
            log(f"Ошибка настройки settings.json ({p}): {e}")


def remove_antigravity_settings():
    for p in get_antigravity_settings_paths():
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                data.pop("http.proxy", None)
                data.pop("http.proxySupport", None)
                p.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
                log(f"Прокси удалён из {p}")
            except Exception:
                pass


def apply_mac_environment(port: int = DEFAULT_LOCAL_PORT):
    proxy_url = f"http://127.0.0.1:{port}"

    # 1. Записываем в settings.json самого Antigravity (гарантирует подхват при любом способе запуска)
    configure_antigravity_settings(port)

    # 2. launchctl setenv — для GUI программ macOS
    if sys.platform == "darwin":
        try:
            subprocess.run(["launchctl", "setenv", PROXY_VAR_NAME, proxy_url], check=False)
            subprocess.run(["launchctl", "setenv", "HTTPS_PROXY", proxy_url], check=False)
        except Exception:
            pass

    # 3. Добавляем в ~/.zshrc (дефолтный шелл macOS)
    zshrc = Path.home() / ".zshrc"
    marker_start = "# >>> Antigravity Unlocker >>>"
    marker_end = "# <<< Antigravity Unlocker <<<"
    lines = [
        f'export {PROXY_VAR_NAME}="{proxy_url}"',
        f'export HTTPS_PROXY="{proxy_url}"',
    ]

    content = ""
    if zshrc.is_file():
        content = zshrc.read_text(encoding="utf-8")

    if marker_start in content and marker_end in content:
        pattern = re.compile(rf"{re.escape(marker_start)}.*?{re.escape(marker_end)}\n?", re.DOTALL)
        content = pattern.sub("", content)

    block = f"{marker_start}\n" + "\n".join(lines) + f"\n{marker_end}\n"
    content = content.rstrip() + "\n" + block
    zshrc.write_text(content, encoding="utf-8")


def remove_mac_environment():
    remove_antigravity_settings()

    if sys.platform == "darwin":
        try:
            subprocess.run(["launchctl", "unsetenv", PROXY_VAR_NAME], check=False)
            subprocess.run(["launchctl", "unsetenv", "HTTPS_PROXY"], check=False)
        except Exception:
            pass

    zshrc = Path.home() / ".zshrc"
    marker_start = "# >>> Antigravity Unlocker >>>"
    marker_end = "# <<< Antigravity Unlocker <<<"

    if zshrc.is_file():
        content = zshrc.read_text(encoding="utf-8")
        if marker_start in content:
            pattern = re.compile(rf"{re.escape(marker_start)}.*?{re.escape(marker_end)}\n?", re.DOTALL)
            content = pattern.sub("", content)
            zshrc.write_text(content, encoding="utf-8")


def launch_antigravity_app(port: int = DEFAULT_LOCAL_PORT):
    proxy_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env[PROXY_VAR_NAME] = proxy_url
    env["HTTPS_PROXY"] = proxy_url
    env["http_proxy"] = proxy_url
    env["https_proxy"] = proxy_url
    try:
        subprocess.run(["open", "-a", "Antigravity"], env=env, check=False)
        return True, "Antigravity запущен с настроенным прокси!"
    except Exception as e:
        return False, f"Ошибка запуска Antigravity: {e}"


# ---------------------------------------------------------------------------
# TUI (Интерактивный интерфейс терминала)
# ---------------------------------------------------------------------------

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"
    BG_BLUE = "\033[44m"


def clear_screen():
    print("\033[2J\033[H", end="")


class UnlockerTUI:
    def __init__(self):
        self.message = ""
        self.message_color = Colors.GREEN
        self.local_server = None

    def print_banner(self):
        print(f"{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}║           Antigravity Unlocker — Версия для macOS                    ║{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}║   Обход региональной ошибки 400 и подключение своего HTTP-прокси     ║{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}\n")

    def print_status(self):
        up = load_upstream()
        running, pid, port = is_proxy_daemon_running()
        installs = find_mac_antigravity_installs()

        if up:
            proxy_str = f"{Colors.GREEN}Подключён:{Colors.RESET} {up.display()}"
        else:
            proxy_str = f"{Colors.YELLOW}Не настроен{Colors.RESET} (нажмите 1 для ввода ссылки)"

        if running:
            service_str = f"{Colors.GREEN}Работает{Colors.RESET} (PID: {pid}, порт 127.0.0.1:{port})"
        else:
            service_str = f"{Colors.RED}Остановлен{Colors.RESET}"

        all_targets = []
        for inst in installs:
            all_targets.extend(get_binary_targets(inst))

        done_count = 0
        file_details = []
        for t in all_targets:
            info = inspect_binary(t)
            if info["is_done"]:
                done_count += 1
                status_icon = f"{Colors.GREEN}✓{Colors.RESET}"
            else:
                status_icon = f"{Colors.YELLOW}✗{Colors.RESET}"
            file_details.append(f"{status_icon} {t.name}")

        if not all_targets:
            patch_str = f"{Colors.YELLOW}Установка Antigravity не найдена{Colors.RESET}"
        elif done_count == len(all_targets) and len(all_targets) > 0:
            patch_str = f"{Colors.GREEN}Пропатчено полностью{Colors.RESET} ({done_count}/{len(all_targets)} файлов)"
        else:
            patch_str = f"{Colors.YELLOW}Частично ({done_count}/{len(all_targets)}){Colors.RESET}"

        # Статус разблокировки входа в аккаунт из-под санкций
        all_js = []
        for inst in installs:
            all_js.extend(get_js_targets(inst))

        js_done = 0
        for j in all_js:
            if inspect_js_file(j)["patched"]:
                js_done += 1

        if not all_js:
            account_str = f"{Colors.GRAY}Не требуется (v2.4+ / файлы не найдены){Colors.RESET}"
        elif js_done == len(all_js) and len(all_js) > 0:
            account_str = f"{Colors.GREEN}Разблокирован{Colors.RESET} ({js_done}/{len(all_js)} файлов)"
        elif js_done > 0:
            account_str = f"{Colors.YELLOW}Частично ({js_done}/{len(all_js)}){Colors.RESET}"
        else:
            account_str = f"{Colors.RED}Не разблокирован{Colors.RESET} ({len(all_js)} файлов найдено)"

        # Статус настроек прокси
        settings_configured = False
        for p in get_antigravity_settings_paths():
            if p.is_file():
                try:
                    c = p.read_text(encoding="utf-8")
                    if "http.proxy" in c and str(port) in c:
                        settings_configured = True
                        break
                except Exception:
                    pass

        env_val = os.environ.get(PROXY_VAR_NAME)
        if settings_configured:
            config_str = f"{Colors.GREEN}Настроен в settings.json + launchctl{Colors.RESET}"
        elif env_val:
            config_str = f"{Colors.GREEN}Активен в сессии ({env_val}){Colors.RESET}"
        else:
            config_str = f"{Colors.YELLOW}В .zshrc / launchctl{Colors.RESET}"

        last_act = get_last_activity()

        print(f"  {Colors.BOLD}• Свой HTTP-прокси:{Colors.RESET}      {proxy_str}")
        print(f"  {Colors.BOLD}• Локальная служба:{Colors.RESET}      {service_str}")
        print(f"  {Colors.BOLD}• Патч клиента (400):{Colors.RESET}    {patch_str}")
        if file_details:
            print(f"    {Colors.GRAY}Компоненты: {', '.join(file_details)}{Colors.RESET}")
        print(f"  {Colors.BOLD}• Вход из-под санкций:{Colors.RESET}  {account_str}")
        print(f"  {Colors.BOLD}• Конфигурация прокси:{Colors.RESET} {config_str}")
        if last_act:
            print(f"  {Colors.BOLD}• Трафик Antigravity:{Colors.RESET}  {Colors.CYAN}{last_act}{Colors.RESET}")
        print(f"{Colors.GRAY}────────────────────────────────────────────────────────────────────────{Colors.RESET}")

        if self.message:
            print(f"\n  {self.message_color}{Colors.BOLD}› {self.message}{Colors.RESET}\n")
            self.message = ""

    def run(self):
        while True:
            clear_screen()
            self.print_banner()
            self.print_status()

            print(f"  {Colors.BOLD}[1]{Colors.RESET} Ввести ссылку своего HTTP-прокси (например, http://user:pass@proxy.example.com:8080)")
            print(f"  {Colors.BOLD}[2]{Colors.RESET} Проверить работу прокси (тест связи с Google)")
            print(f"  {Colors.BOLD}[3]{Colors.RESET} {Colors.GREEN}Включить всё{Colors.RESET} (Патч 400 + Вход в аккаунт + settings.json + Запуск службы)")
            print(f"  {Colors.BOLD}[4]{Colors.RESET} {Colors.CYAN}Запустить Antigravity с прокси{Colors.RESET} (гарантированный обход 400)")
            print(f"  {Colors.BOLD}[5]{Colors.RESET} Разблокировать вход в аккаунт из-под санкций (отдельно)")
            print(f"  {Colors.BOLD}[6]{Colors.RESET} {Colors.YELLOW}Выключить всё{Colors.RESET} (Откат всех патчей + Остановка службы + Сброс)")
            print(f"  {Colors.BOLD}[7]{Colors.RESET} Перезапустить локальную службу прокси")
            print(f"  {Colors.BOLD}[8]{Colors.RESET} Остановить локальную службу прокси")
            print(f"  {Colors.BOLD}[9]{Colors.RESET} Восстановить оригиналы всех файлов (полный откат)")
            print(f"  {Colors.BOLD}[D]{Colors.RESET} Удалить сохранённый прокси")
            print(f"  {Colors.BOLD}[0]{Colors.RESET} Выход (служба продолжит работать в фоне)")
            print(f"\n{Colors.CYAN}Выберите действие (0-9, D):{Colors.RESET} ", end="", flush=True)

            try:
                choice = input().strip()
            except (KeyboardInterrupt, EOFError):
                print()
                break

            choice_lower = choice.lower()
            if choice == "1":
                self.action_input_proxy()
            elif choice == "2":
                self.action_test_proxy()
            elif choice == "3":
                self.action_enable_all()
            elif choice == "4":
                self.action_launch_app()
            elif choice == "5":
                self.action_patch_account()
            elif choice == "6":
                self.action_disable_all()
            elif choice == "7":
                self.action_start_proxy()
            elif choice == "8":
                self.action_stop_proxy()
            elif choice == "9":
                self.action_unpatch_all()
            elif choice_lower == "d":
                clear_upstream()
                self.message = "Прокси удалён"
                self.message_color = Colors.YELLOW
            elif choice == "0":
                break

    def action_input_proxy(self):
        clear_screen()
        self.print_banner()
        print(f"{Colors.BOLD}Ввод HTTP-прокси:{Colors.RESET}")
        print(f"{Colors.GRAY}Поддерживаемые форматы:{Colors.RESET}")
        print("  • http://user:pass@proxy.example.com:8080")
        print("  • user:pass@192.168.1.100:3128")
        print("  • http://proxy.example.com:8080 (без пароля)")
        print(f"\n{Colors.CYAN}Вставьте ссылку или нажмите Enter для отмены:{Colors.RESET}")
        print("› ", end="", flush=True)

        try:
            val = input().strip()
        except (KeyboardInterrupt, EOFError):
            return

        if not val:
            return

        try:
            up = UpstreamProxy.parse(val)
            save_upstream(up)
            print(f"\n{Colors.YELLOW}Проверяю прокси {up.display()}...{Colors.RESET}")
            ok, msg = probe_upstream(up)
            if ok:
                self.message = f"Прокси принят и проверен: {up.display()}"
                self.message_color = Colors.GREEN
            else:
                self.message = f"Прокси сохранён, но проверка не прошла: {msg}"
                self.message_color = Colors.YELLOW
        except Exception as e:
            self.message = f"Ошибка разбора прокси: {e}"
            self.message_color = Colors.RED

    def action_test_proxy(self):
        up = load_upstream()
        if not up:
            self.message = "Сначала укажите прокси (пункт 1)"
            self.message_color = Colors.RED
            return

        print(f"\n{Colors.YELLOW}Тестирование подключения к Google через {up.display()}...{Colors.RESET}")
        ok, msg = probe_upstream(up)
        if ok:
            self.message = f"Тест успешен: {msg}"
            self.message_color = Colors.GREEN
        else:
            self.message = f"Тест провален: {msg}"
            self.message_color = Colors.RED

    def action_start_proxy(self):
        stop_proxy_daemon()
        port = DEFAULT_LOCAL_PORT

        script_path = Path(__file__).resolve()
        proc = subprocess.Popen(
            [sys.executable, str(script_path), "--daemon"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.5)

        running, pid, bound_port = is_proxy_daemon_running()
        if running:
            apply_mac_environment(bound_port)
            self.message = f"Локальная служба запущена (PID {pid}) на 127.0.0.1:{bound_port}"
            self.message_color = Colors.GREEN
        else:
            self.message = "Не удалось запустить службу локального прокси"
            self.message_color = Colors.RED

    def action_stop_proxy(self):
        stop_proxy_daemon()
        self.message = "Локальный прокси остановлен"
        self.message_color = Colors.YELLOW

    def action_patch_account(self):
        installs = find_mac_antigravity_installs()
        if not installs:
            self.message = "Установка Antigravity не найдена в /Applications"
            self.message_color = Colors.RED
            return

        kill_antigravity_processes()
        res = patch_account_auth_all(installs)
        success = sum(1 for _, ok, _ in res if ok)
        total = len(res)
        if total == 0:
            self.message = "JS-файлы для патча аккаунта не найдены (в новых сборках может не требоваться)"
            self.message_color = Colors.YELLOW
        else:
            self.message = f"Вход в аккаунт: пропатчено {success} из {total} JS-файлов"
            self.message_color = Colors.GREEN if success == total else Colors.YELLOW

    def action_patch_all(self):
        installs = find_mac_antigravity_installs()
        if not installs:
            self.message = "Установка Antigravity не найдена в /Applications"
            self.message_color = Colors.RED
            return

        kill_antigravity_processes()

        targets = []
        for inst in installs:
            targets.extend(get_binary_targets(inst))

        success = 0
        for t in targets:
            ok, msg = patch_binary_file(t)
            if ok:
                success += 1

        self.message = f"Пропатчено {success} из {len(targets)} файлов Antigravity"
        self.message_color = Colors.GREEN if success > 0 else Colors.RED

    def action_unpatch_all(self):
        installs = find_mac_antigravity_installs()
        targets = []
        for inst in installs:
            targets.extend(get_binary_targets(inst))

        kill_antigravity_processes()

        count = 0
        for t in targets:
            ok, _ = unpatch_binary_file(t)
            if ok:
                count += 1

        count += unpatch_account_auth_all(installs)

        self.message = f"Восстановлено {count} файлов (бинарники + JS)"
        self.message_color = Colors.GREEN

    def action_enable_all(self):
        up = load_upstream()
        if not up:
            self.action_input_proxy()
            up = load_upstream()
            if not up:
                return

        # 1. Завершаем старые запущенные процессы Antigravity
        kill_antigravity_processes()

        # 2. Патчим бинарники (ошибка 400)
        self.action_patch_all()

        # 3. Патчим JS (вход в аккаунт под санкциями)
        patch_account_auth_all()

        # 4. Запускаем службу прокси
        self.action_start_proxy()

        # 5. Прописываем прокси в settings.json и launchctl
        _, _, port = is_proxy_daemon_running()
        apply_mac_environment(port)

        self.message = "«Включить всё» выполнено! Пропатчены бинарники и вход в аккаунт. Запустите Antigravity (пункт 4)."
        self.message_color = Colors.GREEN

    def action_launch_app(self):
        running, _, port = is_proxy_daemon_running()
        if not running:
            self.action_start_proxy()
            _, _, port = is_proxy_daemon_running()

        kill_antigravity_processes()
        ok, msg = launch_antigravity_app(port)
        self.message = msg
        self.message_color = Colors.GREEN if ok else Colors.RED

    def action_disable_all(self):
        self.action_stop_proxy()
        remove_mac_environment()
        self.action_unpatch_all()
        self.message = "Все компоненты обхода отключены, настройки сброшены."
        self.message_color = Colors.YELLOW


# ---------------------------------------------------------------------------
# CLI запуск
# ---------------------------------------------------------------------------

def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if "--daemon" in sys.argv:
        server = LocalProxyServer()
        server.start(background=False)
        return

    if "--proxy" in sys.argv:
        try:
            idx = sys.argv.index("--proxy")
            proxy_url = sys.argv[idx + 1]
            up = UpstreamProxy.parse(proxy_url)
            save_upstream(up)
            print(f"Прокси сохранён: {up.display()}")
            ok, msg = probe_upstream(up)
            print(f"Статус проверки: {msg}")
        except Exception as e:
            print(f"Ошибка: {e}")
            sys.exit(1)
        return

    if "--patch" in sys.argv:
        installs = find_mac_antigravity_installs()
        for inst in installs:
            for t in get_binary_targets(inst):
                ok, msg = patch_binary_file(t)
                print(f"Patch {t.name}: {msg}")
        return

    if "--unpatch" in sys.argv:
        installs = find_mac_antigravity_installs()
        for inst in installs:
            for t in get_binary_targets(inst):
                ok, msg = unpatch_binary_file(t)
                print(f"Unpatch {t.name}: {msg}")
        return

    if "--patch-account" in sys.argv:
        res = patch_account_auth_all()
        for label, ok, msg in res:
            print(f"Patch JS {label}: {msg}")
        return

    if "--unpatch-account" in sys.argv:
        count = unpatch_account_auth_all()
        print(f"Unpatched {count} JS files")
        return

    tui = UnlockerTUI()
    tui.run()


if __name__ == "__main__":
    main()
