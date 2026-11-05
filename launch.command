#!/usr/bin/env bash
# Двойной клик в Finder на macOS запускает этот файл в Terminal.app
DIR="$(cd "$(dirname "$0")" && pwd)"
exec bash "$DIR/launch.sh" "$@"
