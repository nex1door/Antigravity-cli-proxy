[readme.md](https://github.com/user-attachments/files/33894236/readme.md)
# Antigravity CLI (`agy`) Proxy Router & Region Unlocker for Linux (CachyOS / Arch Linux)

Комплексное решение для маршрутизации трафика **[Google Antigravity CLI (`agy`)](https://antigravity.google/docs/getting-started/)** через пользовательский HTTP-прокси (с авторизацией по логину и паролю) и обхода региональной блокировки `Eligibility check failed: Your current account is not eligible for Antigravity` в дистрибутивах **CachyOS** и **Arch Linux**.

## Описание проблемы

При попытке запуска официального бинарника [`agy`](https://aur.archlinux.org/packages/antigravity-cli) на Linux из неподдерживаемых регионов стандартные методы проксирования (`export HTTP_PROXY=...` или обычный `proxychains4`) не срабатывают по трем причинам:

1. **Игнорирование системных переменных прокси при проверке региона**: начиная с версий `agy` 1.0.1+ / 1.3.x+ / 2.x, встроенный сетевой клиент выполняет стартовый запрос проверки доступности региона напрямую, игнорируя `HTTP_PROXY`, `HTTPS_PROXY` и `ALL_PROXY` ([GitHub Issue #113](https://github.com/google-antigravity/antigravity-cli/issues/113)).
2. **Обход `LD_PRELOAD` встроенным резолвером Go**: поскольку `agy` написан на Go, его стандартный сетевой стек (`net.Dial`) использует собственный DNS-резолвер и прямые системные вызовы ядра (`syscall`), минуя библиотеку `glibc`, которую перехватывает `proxychains-ng`.
3. **Проверка страны в профиле Google-аккаунта**: даже если трафик идет через зарубежный IP-адрес, сервер сверяет страну, привязанную к профилю Google ([Условия использования Google](https://policies.google.com/terms)). Если аккаунт привязан к неподдерживаемой стране, сервер возвращает статус `"ineligible"`, а сам `agy` кеширует этот отказ в `~/.gemini/antigravity-cli/` ([обсуждение на форуме Google AI](https://discuss.ai.google.dev/t/paid-google-ai-pro-subscriber-blocked-by-eligibility-check-failed-not-currently-available-in-your-location-after-updating-to-agy-1-3-5/189478)).

## Архитектура и принцип работы проекта

Проект состоит из двух файлов (`agy_cachyos_proxy.py` и `setup_cachyos_agy.sh`), которые выстраивают четыре уровня защиты:

| Уровень | Механизм | Какую задачу решает |
| :--- | :--- | :--- |
| **1. Локальный HTTP/CONNECT мост (`127.0.0.1:18888`)** | Многопоточный TCP-туннель на Python (`socketserver.ThreadingMixIn`) с таймаутом `180 сек` под долгий стриминг рассуждающих моделей. | Принимает трафик от `agy` и `proxychains4` без пароля и автоматически подставляет заголовок `Proxy-Authorization: Basic ...` при обращении к вашему внешнему HTTP-прокси. |
| **2. Перевод Go на `glibc` + `proxychains-ng`** | Переменная `GODEBUG=netdns=cgo` + запуск через `proxychains4 -q -f ~/.config/agy-proxy/proxychains.conf`. | Заставляет Go-рантайм выполнять DNS-запросы и TCP-соединения через системные вызовы `glibc`, которые гарантированно перехватываются `proxychains4`. Подсеть `127.0.0.0/8` исключена (`localnet`), чтобы локальный OAuth-коллбэк при авторизации работал без сбоев. |
| **3. Автоматический бинарный патч (`ineligible` → `inexigible`)** | Создание локальной рабочей копии `~/.local/share/agy-proxy/agy.patched` с заменой 10-байтовой константы `ineligible` на `inexigible` ([метод confeden/Antigravity](https://github.com/confeden/Antigravity)). | Отключает клиентский блокиратор региона в `agy`, если в самом аккаунте Google указана неподдерживаемая страна. Оригинальный системный файл `/usr/bin/agy` остается нетронутым для корректных обновлений через `pacman` / `paru`. |
| **4. Автообновление и фоновый демон** | Пользовательский сервис `systemd --user` (`agy-proxy-bridge.service`) + встроенный сторожевой таймер (`spawn_background_daemon_if_needed`). | Поднимает локальный прокси-мост автоматически при входе в систему или мгновенно при вызове команды `agy` в терминале. При обновлении пакета `antigravity-cli` из AUR скрипт сам определяет изменение размера/даты `/usr/bin/agy` и пересоздает `agy.patched`. |

## Структура файлов репозитория и путей в системе

После запуска установщика `setup_cachyos_agy.sh` файлы распределяются по стандартным пользовательским директориям XDG (права `root` нужны только один раз для установки пакета `proxychains-ng`, если его еще нет в системе):

```text
~/.config/agy-proxy/
├── proxy.env                  # Ваши данные прокси (IP, порт, логин, пароль), права 0600
├── proxychains.conf           # Автогенерируемый конфиг proxychains4 (настроен на 127.0.0.1:18888)
├── bridge.pid                 # PID активного фонового процесса моста
└── bridge.log                 # Лог работы фонового моста

~/.local/share/agy-proxy/
├── agy_cachyos_proxy.py       # Основной исполняемый скрипт маршрутизатора и патчера
├── agy.patched                # Локальная пропатченная копия бинарника agy
└── agy.patched.meta.json      # Метаданные версии оригинала для автообновления патча

~/.local/bin/
└── agy                        # Прозрачная bash-обертка для запуска из любого терминала

~/.config/fish/functions/
└── agy.fish                   # Автоматическая функция для оболочки Fish (по умолчанию в CachyOS)

~/.config/systemd/user/
└── agy-proxy-bridge.service   # Фоновый пользовательский сервис systemd
```

## Требования

* ОС: **CachyOS**, **Arch Linux** или любой другой дистрибутив Linux с `glibc` и `Python 3.8+`.
* Установленный пакет **[`antigravity-cli`](https://aur.archlinux.org/packages/antigravity-cli)** из AUR:
  ```bash
  paru -S --needed antigravity-cli
  ```
* Пакет `proxychains-ng` (устанавливается скриптом `setup_cachyos_agy.sh` автоматически через `pacman`).
* HTTP-прокси (с поддержкой метода `CONNECT` на порт `443`) из поддерживаемой страны (например: США, Нидерланды, Германия, Япония, Сингапур).

## Установка и быстрый старт

1. Клонируйте репозиторий и перейдите в папку проекта:
   ```bash
   git clone <URL_ВАШЕГО_РЕПОЗИТОРИЯ> agy-cachyos-proxy
   cd agy-cachyos-proxy
   ```
2. Сделайте скрипты исполняемыми и запустите установщик:
   ```bash
   chmod +x setup_cachyos_agy.sh agy_cachyos_proxy.py
   ./setup_cachyos_agy.sh
   ```
3. Введите ваш прокси при запросе установщика в формате `ip:port:login:password` (например, `185.100.20.30:8080:myuser:mypass`) или укажите данные в конфигурационном файле `~/.config/agy-proxy/proxy.env`.
4. Запустите Antigravity CLI привычной командой:
   ```bash
   agy
   ```

## Настройка прокси (все поддерживаемые способы)

Приоритет чтения настроек прокси в `agy_cachyos_proxy.py` устроен следующим образом (от высшего к низшему):

1. **Аргумент командной строки `--proxy`**:
   ```bash
   agy --proxy "185.100.20.30:8080:my_login:my_password"
   ```
2. **Переменная окружения `AGY_HTTP_PROXY`**:
   ```bash
   export AGY_HTTP_PROXY="http://my_login:my_password@185.100.20.30:8080"
   ```
3. **Конфигурационный файл `~/.config/agy-proxy/proxy.env` (рекомендуемый способ для постоянной работы)**:
   Файл создается установщиком с правами доступа `600` (чтение только для вашего пользователя). Вы можете заполнить либо 4 отдельных поля, либо одну строку `RAW_PROXY_STRING`:
   ```ini
   PROXY_IP="185.100.20.30"
   PROXY_PORT="8080"
   PROXY_LOGIN="my_login"
   PROXY_PASSWORD="my_password"
   RAW_PROXY_STRING=""
   ```
4. **Константы внутри самого файла `agy_cachyos_proxy.py`**:
   Переменные `PROXY_IP`, `PROXY_PORT`, `PROXY_LOGIN`, `PROXY_PASSWORD` в начале скрипта.

После изменения файла `~/.config/agy-proxy/proxy.env` перезапустите фоновый мост:
```bash
systemctl --user restart agy-proxy-bridge
```

## Справочник команд и флагов

Все стандартные флаги и команды самого Antigravity CLI (`agy --model ...`, `agy --prompt ...`, `agy models`, `agy plugin`) передаются бинарнику прозрачно. Дополнительно обертка поддерживает сервисные флаги:

| Флаг | Описание |
| :--- | :--- |
| `agy --check-only` | Проверяет подключение к вашему HTTP-прокси, выводит внешний IP-адрес, гео-регион, провайдера (ISP vs Datacenter ASN) и тестирует `HTTPS CONNECT` до всех 4 серверов Antigravity. |
| `agy --reset-auth` | Удаляет закешированный статус `not eligible` и старые сетевые сессии в `~/.gemini/antigravity-cli`, `~/.config/Antigravity` и `~/.cache/agy`. |
| `agy --patch-only` | Принудительно пересоздает пропатченную копию `~/.local/share/agy-proxy/agy.patched` (`ineligible` → `inexigible`). |
| `agy --daemon` | Запускает локальный HTTP/CONNECT мост на `127.0.0.1:18888` в режиме демона. |
| `agy --stop-daemon` | Останавливает фоновый процесс моста по PID-файлу. |
| `agy --no-proxychains` | Запускает `agy` только с переменными окружения и бинарным патчем без обертки `proxychains4`. |
| `agy --no-binary-patch` | Запускает оригинальный немодифицированный `/usr/bin/agy` через прокси-мост. |
| `agy --proxy-help` | Выводит краткую справку по флагам прокси-маршрутизатора. |

## Устранение неполадок (Troubleshooting)

### 1. Ошибка `Your current account is not eligible for Antigravity` сохраняется после установки
Если вы запускали `agy` до установки прокси, статус отказа сохранился в системном хранилище ключей (`libsecret` / `gnome-keyring`) и локальном кэше.
1. Выполните сброс локального кэша и пересоздание патча:
   ```bash
   agy --reset-auth
   agy --patch-only
   ```
2. Запустите `agy` и внутри интерактивного окна CLI выполните выход и повторный вход ([инструкция с форума Google AI](https://discuss.ai.google.dev/t/paid-google-ai-pro-subscriber-blocked-by-eligibility-check-failed-not-currently-available-in-your-location-after-updating-to-agy-1-3-5/189478)):
   ```text
   /logout
   /login
   ```
3. Откройте появившуюся OAuth-ссылку в браузере, который также работает через зарубежный прокси/VPN.

### 2. Ошибка `FAILED_PRECONDITION (code 400): User location is not supported for the API use` при отправке сообщения
Эта ошибка возвращается самим API-сервером `daily-cloudcode-pa.googleapis.com`, когда выходной IP вашего прокси принадлежит известному хостинг-провайдеру (Datacenter ASN) с низким трастом у Google.
* Запустите диагностику: `agy --check-only`.
* Если скрипт выводит предупреждение `IP принадлежит дата-центру/хостингу (Datacenter ASN)`, замените прокси на резидентский (Residential / ISP HTTP proxy) из поддерживаемой страны.

### 3. В оболочке Zsh или Bash вызывается старый `/usr/bin/agy` вместо обертки
Убедитесь, что папка `~/.local/bin` находится в начале вашей переменной `PATH`:
* Для **Bash** (`~/.bashrc`) или **Zsh** (`~/.zshrc`):
  ```bash
  export PATH="$HOME/.local/bin:$PATH"
  ```
* Для **Fish** (`~/.config/fish/config.fish`): установщик автоматически создает функцию `~/.config/fish/functions/agy.fish`, которая перехватывает вызов `agy` независимо от порядка `PATH`.

## Полное удаление и откат изменений

Поскольку скрипт не изменяет системный бинарник `/usr/bin/agy`, для полного возврата системы в исходное состояние достаточно выполнить:

```bash
systemctl --user disable --now agy-proxy-bridge.service
rm -f ~/.config/systemd/user/agy-proxy-bridge.service
rm -rf ~/.config/agy-proxy ~/.local/share/agy-proxy
rm -f ~/.local/bin/agy ~/.config/fish/functions/agy.fish
systemctl --user daemon-reload
```
