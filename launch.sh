#!/usr/bin/env bash
# Antigravity Unlocker for macOS - Launcher
set -eu

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Проверяем наличие python3
if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 не найден в системе."
    echo "Установите Command Line Tools командой: xcode-select --install"
    echo "Или скачайте с официального сайта: https://www.python.org/downloads/macos/"
    read -r -p "Нажмите Enter для выхода..." _
    exit 1
fi

chmod +x ag_unlocker.py

# Запуск TUI
python3 ag_unlocker.py "$@"
