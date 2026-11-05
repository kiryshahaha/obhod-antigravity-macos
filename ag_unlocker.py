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
from urllib.parse import urlparse, unquote

GATE_HOSTS = {
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
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

CONFIG_DIR = Path.home() / ".local" / "share" / "agunlocker"
UPSTREAM_FILE = CONFIG_DIR / "upstream.txt"
PID_FILE = CONFIG_DIR / "proxy.pid"
PORT_FILE = CONFIG_DIR / "proxy_port"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
LOG_FILE = CONFIG_DIR / "mac_unlocker.log"


def log(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


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

        # Удаляем протоколы
        rest = raw
        if rest.startswith("http://"):
            rest = rest[len("http://") :]
        elif rest.startswith("https://"):
            rest = rest[len("https://") :]

        if "://" in rest:
            raise ValueError("Поддерживается только HTTP-прокси (http://...)")

        # Разделение по последнему '@' на случай наличия '@' в пароле
        if "@" in rest:
            auth_part, hostport_part = rest.rsplit("@", 1)
            if ":" not in auth_part:
                raise ValueError("Логин без пароля — формат: логин:пароль@хост:порт")
            user, password = auth_part.split(":", 1)
            # URL decoding если были %XX
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


def probe_upstream(up: UpstreamProxy, timeout: float = 8.0) -> tuple[bool, str]:
    """
    Проверяет работу HTTP-прокси:
    1. Устанавливает TCP соединение с прокси
    2. Отправляет CONNECT запрос к daily-cloudcode-pa.googleapis.com:443
    3. Выполняет TLS рукопожатие с Google
    4. Отправляет проверочный GET запрос
    """
    try:
        sock = socket.create_connection((up.host, up.port), timeout=timeout)
        sock.settimeout(timeout)

        # 1. CONNECT запрос
        req = f"CONNECT {PROBE_HOST}:443 HTTP/1.1\r\nHost: {PROBE_HOST}:443\r\n"
        if up.auth_header:
            req += f"Proxy-Authorization: {up.auth_header}\r\n"
        req += "\r\n"
        sock.sendall(req.encode("ascii"))

        # Читаем HTTP статус
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

        # 2. TLS рукопожатие внутри туннеля
        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=PROBE_HOST)
        tls_sock.settimeout(timeout)

        # 3. HTTP GET к бэкенду Google
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
            return True, f"Прокси успешно отвечает! Бэкенд Google доступен ({status_line.strip()})"
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
        # Пробуем bind к дефолтному или запасному порту
        candidate_ports = [self.port] + [p for p in FALLBACK_PORTS if p != self.port]
        bound = False
        for p in candidate_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", p))
                s.listen(64)
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
                # Не CONNECT
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

            host_clean = host.strip("[]").rstrip(".").lower()
            is_gate = (port == 443 and host_clean in GATE_HOSTS)

            up = load_upstream()

            if is_gate and up is not None:
                # Маршрутизируем через свой HTTP-прокси
                remote_sock = self._connect_upstream(up, host, port)
                if remote_sock is None:
                    # Фоллбек на прямой туннель, если прокси не ответил
                    remote_sock = socket.create_connection((host, port), timeout=8.0)
            else:
                # Прямое соединение для всех остальных хостов
                remote_sock = socket.create_connection((host, port), timeout=8.0)

            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Двунаправленный сплайсинг
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
    """Возвращает (is_running, pid, port)"""
    if not PID_FILE.is_file():
        return False, 0, DEFAULT_LOCAL_PORT

    try:
        pid = int(PID_FILE.read_text().strip())
        port = int(PORT_FILE.read_text().strip()) if PORT_FILE.is_file() else DEFAULT_LOCAL_PORT

        # Проверка жив ли процесс
        try:
            os.kill(pid, 0)
        except OSError:
            PID_FILE.unlink(missing_ok=True)
            return False, 0, port

        # Проверка отвечает ли сокет
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
    # Добавляем пути если установлены только CLI
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
        # Это macOS App Bundle
        res_dir = install_root / "Contents" / "Resources"
        ext_bin = res_dir / "app" / "extensions" / "antigravity" / "bin"
        bin_dir = res_dir / "bin"
        macos_dir = install_root / "Contents" / "MacOS"

        # Ищем все language_server* и agy
        for d in [ext_bin, bin_dir, macos_dir]:
            if d.is_dir():
                for item in d.iterdir():
                    if item.is_file() and not item.name.endswith(".ag_backup"):
                        name = item.name.lower()
                        if name.startswith("language_server") or name == "agy":
                            targets.append(item)

        # Проверяем ~/.gemini/bin/agy если IDE использует внешний CLI
        gemini_bin = Path.home() / ".gemini" / "bin" / "agy"
        if gemini_bin.is_file() and gemini_bin not in targets:
            targets.append(gemini_bin)
    else:
        # Прямой путь к директории или бинарнику
        if install_root.is_file():
            targets.append(install_root)
        elif install_root.is_dir():
            for item in install_root.iterdir():
                if item.is_file() and not item.name.endswith(".ag_backup"):
                    if item.name.startswith("language_server") or item.name == "agy":
                        targets.append(item)

    return targets


def inspect_binary(bin_path: Path) -> dict:
    res = {
        "path": bin_path,
        "patched_eligibility": False,
        "patched_proxy_var": False,
        "can_patch": False,
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

        # Атомарная запись
        tmp_path = bin_path.with_name(bin_path.name + ".tmp")
        tmp_path.write_bytes(data)
        os.chmod(tmp_path, os.stat(bin_path).st_mode)
        tmp_path.replace(bin_path)

        # На macOS критично: переподписываем бинарник через ad-hoc codesign,
        # иначе система убьёт изменённый бинарник (Code Signature Invalid)!
        re_sign_macho(bin_path)

        return True, f"Заменено: eligibility: {count_ineligible}, proxy_var: {count_proxy}"
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

    # Если бэкапа нет, делаем обратную замену
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
    """Выполняет codesign --force --deep -s - для работы на macOS"""
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
    """Завершает фоновые процессы language_server и agy перед патчем"""
    patterns = ["language_server", "agy", "Antigravity"]
    for pat in patterns:
        try:
            subprocess.run(["pkill", "-f", pat], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    time.sleep(0.5)


# ---------------------------------------------------------------------------
# Настройка системного окружения на macOS
# ---------------------------------------------------------------------------

def apply_mac_environment(port: int = DEFAULT_LOCAL_PORT):
    proxy_url = f"http://127.0.0.1:{port}"
    # 1. launchctl setenv — для GUI программ macOS, запускаемых из Finder/Dock
    if sys.platform == "darwin":
        try:
            subprocess.run(["launchctl", "setenv", PROXY_VAR_NAME, proxy_url], check=False)
        except Exception:
            pass

    # 2. Добавляем в ~/.zshrc (дефолтный шелл macOS)
    zshrc = Path.home() / ".zshrc"
    marker_start = "# >>> Antigravity Unlocker >>>"
    marker_end = "# <<< Antigravity Unlocker <<<"
    line = f'export {PROXY_VAR_NAME}="{proxy_url}"'

    content = ""
    if zshrc.is_file():
        content = zshrc.read_text(encoding="utf-8")

    # Удаляем старую запись если была
    if marker_start in content and marker_end in content:
        pattern = re.compile(rf"{re.escape(marker_start)}.*?{re.escape(marker_end)}\n?", re.DOTALL)
        content = pattern.sub("", content)

    # Добавляем новую
    block = f"{marker_start}\n{line}\n{marker_end}\n"
    content = content.rstrip() + "\n" + block
    zshrc.write_text(content, encoding="utf-8")


def remove_mac_environment():
    if sys.platform == "darwin":
        try:
            subprocess.run(["launchctl", "unsetenv", PROXY_VAR_NAME], check=False)
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

        # Статус прокси
        if up:
            proxy_str = f"{Colors.GREEN}Подключён:{Colors.RESET} {up.display()}"
        else:
            proxy_str = f"{Colors.YELLOW}Не настроен{Colors.RESET} (нажмите 1 для ввода ссылки)"

        # Статус службы
        if running:
            service_str = f"{Colors.GREEN}Работает{Colors.RESET} (PID: {pid}, порт 127.0.0.1:{port})"
        else:
            service_str = f"{Colors.RED}Остановлен{Colors.RESET}"

        # Статус патча бинарников
        all_targets = []
        for inst in installs:
            all_targets.extend(get_binary_targets(inst))

        patched_count = 0
        for t in all_targets:
            info = inspect_binary(t)
            if info["patched_eligibility"]:
                patched_count += 1

        if not all_targets:
            patch_str = f"{Colors.YELLOW}Установка Antigravity не найдена{Colors.RESET}"
        elif patched_count == len(all_targets) and len(all_targets) > 0:
            patch_str = f"{Colors.GREEN}Пропатчено{Colors.RESET} ({patched_count}/{len(all_targets)} файлов)"
        elif patched_count > 0:
            patch_str = f"{Colors.YELLOW}Частично пропатчено{Colors.RESET} ({patched_count}/{len(all_targets)})"
        else:
            patch_str = f"{Colors.RED}Не пропатчено{Colors.RESET} ({len(all_targets)} найдено)"

        # Переменная окружения
        env_val = os.environ.get(PROXY_VAR_NAME)
        env_str = f"{Colors.GREEN}Активна{Colors.RESET} ({env_val})" if env_val else f"{Colors.YELLOW}В .zshrc / launchctl{Colors.RESET}"

        print(f"  {Colors.BOLD}• Свой HTTP-прокси:{Colors.RESET}      {proxy_str}")
        print(f"  {Colors.BOLD}• Локальная служба:{Colors.RESET}      {service_str}")
        print(f"  {Colors.BOLD}• Патч клиента (400):{Colors.RESET}    {patch_str}")
        print(f"  {Colors.BOLD}• Переменная {PROXY_VAR_NAME}:{Colors.RESET}  {env_str}")
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
            print(f"  {Colors.BOLD}[3]{Colors.RESET} {Colors.GREEN}Включить всё{Colors.RESET} (Патч + Запуск прокси + Переменные)")
            print(f"  {Colors.BOLD}[4]{Colors.RESET} {Colors.YELLOW}Выключить всё{Colors.RESET} (Откат патча + Остановка прокси + Сброс)")
            print(f"  {Colors.BOLD}[5]{Colors.RESET} Запустить / Перезапустить локальный прокси")
            print(f"  {Colors.BOLD}[6]{Colors.RESET} Остановить локальный прокси")
            print(f"  {Colors.BOLD}[7]{Colors.RESET} Патчить Antigravity (с ad-hoc переподписью codesign)")
            print(f"  {Colors.BOLD}[8]{Colors.RESET} Восстановить оригиналы Antigravity (откат)")
            print(f"  {Colors.BOLD}[9]{Colors.RESET} Удалить сохранённый прокси")
            print(f"  {Colors.BOLD}[0]{Colors.RESET} Выход (прокси продолжит работать в фоне)")
            print(f"\n{Colors.CYAN}Выберите действие (0-9):{Colors.RESET} ", end="", flush=True)

            try:
                choice = input().strip()
            except (KeyboardInterrupt, EOFError):
                print()
                break

            if choice == "1":
                self.action_input_proxy()
            elif choice == "2":
                self.action_test_proxy()
            elif choice == "3":
                self.action_enable_all()
            elif choice == "4":
                self.action_disable_all()
            elif choice == "5":
                self.action_start_proxy()
            elif choice == "6":
                self.action_stop_proxy()
            elif choice == "7":
                self.action_patch_all()
            elif choice == "8":
                self.action_unpatch_all()
            elif choice == "9":
                clear_upstream()
                self.message = "Прокси удалён."
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

        # Запускаем отдельный фоновый процесс
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
            self.message = f"Локальный прокси запущен (PID {pid}) на 127.0.0.1:{bound_port}"
            self.message_color = Colors.GREEN
        else:
            self.message = "Не удалось запустить службу локального прокси"
            self.message_color = Colors.RED

    def action_stop_proxy(self):
        stop_proxy_daemon()
        self.message = "Локальный прокси остановлен"
        self.message_color = Colors.YELLOW

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

        self.message = f"Пропатчено {success} из {len(targets)} бинарников Antigravity"
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

        self.message = f"Восстановлено {count} файлов"
        self.message_color = Colors.GREEN

    def action_enable_all(self):
        up = load_upstream()
        if not up:
            self.action_input_proxy()
            up = load_upstream()
            if not up:
                return

        # 1. Патчим бинарники
        self.action_patch_all()

        # 2. Запускаем прокси
        self.action_start_proxy()

        # 3. Применяем переменные
        _, _, port = is_proxy_daemon_running()
        apply_mac_environment(port)

        self.message = "«Включить всё» выполнено! Перезапустите Antigravity."
        self.message_color = Colors.GREEN

    def action_disable_all(self):
        self.action_stop_proxy()
        remove_mac_environment()
        self.action_unpatch_all()
        self.message = "Все компоненты обхода отключены, файлы восстановлены."
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
        # Режим фонового демона прокси
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

    # По умолчанию запускаем TUI
    tui = UnlockerTUI()
    tui.run()


if __name__ == "__main__":
    main()
