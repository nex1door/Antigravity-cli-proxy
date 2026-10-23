#!/usr/bin/env bash
# ==============================================================================
# setup_cachyos_agy.sh
# Автоматический установщик прокси-обвязки, бинарного патча (ineligible -> inexigible)
# и фонового сервиса для Antigravity CLI (agy) под CachyOS / Arch Linux.
# ==============================================================================
set -euo pipefail

# ------------------------------------------------------------------------------
# ВПИШИТЕ ДАННЫЕ ВАШЕГО ПРОКСИ СЮДА (или введите при запуске):
# ------------------------------------------------------------------------------
PROXY_IP="127.0.0.1"        # Ваш IP прокси
PROXY_PORT="8080"           # Ваш Порт прокси
PROXY_LOGIN=""              # Ваш Логин прокси
PROXY_PASSWORD=""           # Ваш Пароль прокси

# Либо одной строкой в формате "ip:port:login:password":
RAW_PROXY_STRING=""

INSTALL_DIR="$HOME/.local/share/agy-proxy"
CONFIG_DIR="$HOME/.config/agy-proxy"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
LOCAL_BIN_DIR="$HOME/.local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "======================================================================"
echo "  Установка прокси и обхода региона Antigravity CLI (agy) для CachyOS"
echo "======================================================================"

# 1. Если прокси еще не сохранен в ~/.config/agy-proxy/proxy.env и не вписан в шапку
if [[ -f "$CONFIG_DIR/proxy.env" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_DIR/proxy.env" || true
fi

if [[ -z "${RAW_PROXY_STRING:-}" && "${PROXY_IP:-127.0.0.1}" == "127.0.0.1" && -z "${PROXY_LOGIN:-}" ]]; then
    read -rp "Введите прокси в формате ip:port:login:password (или Enter, чтобы заполнить позже): " USER_INPUT || true
    if [[ -n "${USER_INPUT:-}" ]]; then
        RAW_PROXY_STRING="$USER_INPUT"
    fi
fi

# 2. Установка proxychains-ng в CachyOS / Arch Linux
if ! command -v proxychains4 >/dev/null 2>&1; then
    echo "[*] Устанавливаем proxychains-ng через pacman..."
    sudo pacman -S --needed --noconfirm proxychains-ng
else
    echo "[+] Пакет proxychains-ng уже установлен ($(command -v proxychains4))."
fi

# 3. Копируем скрипт и сохраняем конфигурацию прокси
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$SYSTEMD_USER_DIR" "$LOCAL_BIN_DIR"

cp -f "$SCRIPT_DIR/agy_cachyos_proxy.py" "$INSTALL_DIR/agy_cachyos_proxy.py"
chmod +x "$INSTALL_DIR/agy_cachyos_proxy.py"

cat > "$CONFIG_DIR/proxy.env" <<EOF
# Конфигурация HTTP-прокси для Antigravity CLI (agy) на CachyOS
PROXY_IP="$PROXY_IP"
PROXY_PORT="$PROXY_PORT"
PROXY_LOGIN="$PROXY_LOGIN"
PROXY_PASSWORD="$PROXY_PASSWORD"
RAW_PROXY_STRING="$RAW_PROXY_STRING"
EOF
chmod 600 "$CONFIG_DIR/proxy.env"
echo "[+] Конфигурация прокси сохранена в $CONFIG_DIR/proxy.env"

# 4. Если настоящий бинарник agy лежит в ~/.local/bin/agy, сохраняем его как agy.real
if [[ -f "$LOCAL_BIN_DIR/agy" ]] && ! grep -q "AGY_CACHYOS_WRAPPER" "$LOCAL_BIN_DIR/agy" 2>/dev/null; then
    mv -f "$LOCAL_BIN_DIR/agy" "$LOCAL_BIN_DIR/agy.real"
    echo "[+] Оригинальный ~/.local/bin/agy сохранен как ~/.local/bin/agy.real"
fi

# 5. Создаем прозрачный скрипт-обертку ~/.local/bin/agy
cat > "$LOCAL_BIN_DIR/agy" <<'EOF'
#!/usr/bin/env bash
# AGY_CACHYOS_WRAPPER
exec python3 "$HOME/.local/share/agy-proxy/agy_cachyos_proxy.py" "$@"
EOF
chmod +x "$LOCAL_BIN_DIR/agy"
echo "[+] Установлена прозрачная обертка: $LOCAL_BIN_DIR/agy"

# 6. Очищаем старый закешированный статус 'ineligible' и создаем пропатченную копию agy
echo "[*] Сбрасываем закешированный статус региона и создаем пропатченную копию бинарника agy..."
python3 "$INSTALL_DIR/agy_cachyos_proxy.py" --reset-auth || true
python3 "$INSTALL_DIR/agy_cachyos_proxy.py" --patch-only || true

# 7. Перезапускаем фоновый сервис systemd --user
cat > "$SYSTEMD_USER_DIR/agy-proxy-bridge.service" <<EOF
[Unit]
Description=Antigravity CLI (agy) Local HTTP Proxy Bridge
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/agy_cachyos_proxy.py --daemon
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now agy-proxy-bridge.service
systemctl --user restart agy-proxy-bridge.service
echo "[+] Фоновый сервис systemd (agy-proxy-bridge.service) перезапущен."

# 8. Настраиваем функцию `agy` для Fish (стандартный шелл CachyOS)
if [[ -d "$HOME/.config/fish" ]]; then
    mkdir -p "$HOME/.config/fish/functions"
    cat > "$HOME/.config/fish/functions/agy.fish" <<'EOF'
function agy --description 'Antigravity CLI via HTTP Proxy Bridge & Binary Patch'
    python3 "$HOME/.local/share/agy-proxy/agy_cachyos_proxy.py" $argv
end
EOF
    echo "[+] Обновлена функция agy для оболочки Fish (~/.config/fish/functions/agy.fish)."
fi

# 9. Проверяем соединение через прокси
echo ""
echo "[*] Проверяем соединение и выходной IP..."
python3 "$INSTALL_DIR/agy_cachyos_proxy.py" --check-only || true

echo ""
echo "======================================================================"
echo "  Готово! Что сделать сейчас:"
echo "  1. Запустите: agy"
echo "  2. Если сессия осталась старой — введите внутри agy: /logout и затем /login"
echo "======================================================================"
