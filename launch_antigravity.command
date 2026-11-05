#!/usr/bin/env bash
# Запуск Antigravity с гарантированным экспортом локального прокси
DIR="$(cd "$(dirname "$0")" && pwd)"
export AG_LS_PROXY="http://127.0.0.1:53129"
export HTTPS_PROXY="http://127.0.0.1:53129"
export HTTP_PROXY="http://127.0.0.1:53129"
export https_proxy="http://127.0.0.1:53129"
export http_proxy="http://127.0.0.1:53129"

# Завершаем старые процессы перед запуском
killall -9 Antigravity 2>/dev/null || true
sleep 0.5

# Запуск приложения
open -a Antigravity
