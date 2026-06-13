> Внимание: Это пре-релиз версии 0.8.0. Проект готовится к v1.0-rc. Проведён внутренний код-аудит (см. docs/AUDIT-REPORT.md), но это НЕ замена профессиональному внешнему аудиту безопасности. Используйте на свой страх и риск.

# MorphVPN 🛡️
![Статус](https://img.shields.io/badge/статус-пре--релиз-yellow)
![Версия](https://img.shields.io/badge/версия-0.8.0-blue)
![Тесты](https://img.shields.io/badge/тесты-82-green)
![Лицензия](https://img.shields.io/badge/лицензия-MIT-green.svg)

**MorphVPN** — это высокопроизводительный стелс-VPN туннель на языке Rust, использующий Noise Protocol и продвинутые методы обфускации трафика.


> Экспериментальный VPN-туннель на Rust.  
> Пре-релиз. Написан одним самоучкой. Публикуется как есть.

[English version](README.md)

## О Проекте

MorphVPN — это консольный VPN/туннельный проект на Rust.  
Реализует полный Noise XXpsk3 handshake, двойное шифрование, интеграцию с TUN-интерфейсами, ACL-авторизацию пиров, TCP-фолбэк и кросс-платформенную сетевую логику.

Проект прошёл через 8 итераций (v0.1 → v0.8) с 82 тестами и готовится к v1.0-rc.

## Важное Предупреждение

MorphVPN все еще находится в стадии пре-релиза.

- Никаких гарантий
- Проведён внутренний код-аудит, но внешний аудит безопасности не проводился
- Нет обещаний продакшен-готовности
- Нет заявлений, что проект безопасен для реального чувствительного трафика

Проект написан одним человеком-самоучкой. Если у вас есть советы, замечания или идеи, обратная связь очень приветствуется.

## Что Реально Есть В Репозитории

- **`src/`** — Основной бинарник и runtime код (сервер, клиент, wizard настройки)
- **`morphvpn-protocol/`** — Протокольная библиотека (крипто, handshake, wire format, сессии, cookies, replay protection)
- **`tests/`** — 82 unit, интеграционных и TCP-тестов
- **`deploy/`** — Systemd-сервис, скрипты настройки, шаблоны конфигов
- **`docs/`** — RFC протокола, гайд по деплою, внутренний аудит

## Возможности

- **Noise XXpsk3 handshake** — 25519 ключи, ChaChaPoly, BLAKE2s
- **Двойное шифрование** — ChaCha20-Poly1305 (данные) + XChaCha20-Poly1305 (внешний слой)
- **Маскировка заголовков** — Обфускация трафика на базе ChaCha20
- **TCP-фолбэк** — Length-prefixed TCP фрейминг для сред с заблокированным UDP
- **Защита от утечки IPv6** — Блокировка IPv6 на TUN-интерфейсах (Linux/Windows/macOS)
- **Управление пирами** — Отслеживание подключённых пиров с состоянием, статистикой, жизненным циклом
- **X.509 сертификаты** — Генерация самоподписанных сертификатов, обмен отпечатками
- **Метрики** — Атомарные счётчики пакетов/байтов/ошибок, периодическое логирование
- **Health endpoint** — HTTP JSON статус с uptime, метриками, снимками пиров
- **Профили** — Пресеты video/gaming/https для keepalive, padding, MTU
- **Защита от утечки DNS** — Маршрутизация DNS через туннель (Linux iptables, Windows netsh)
- **Rekey механизм** — Автоматическая ротация ключей при исчерпании nonce
- **Cookie anti-DoS** — Stateless rate limiting с time-bucketed cookies
- **Защита от replay** — 2048-bit sliding window
- **Graceful shutdown** — 2-секундный drain при остановке
- **TOML конфигурация** — Секции server/client, PSK конфиг, cookie key
- **Интерактивный wizard настройки** — `morphvpn setup` для пошаговой настройки сервера/клиента
- **Скрипты деплоя** — `setup.sh` / `setup-client.sh` с `--dry-run` и подтверждением
- **CI/CD** — GitHub Actions с тестированием на Linux/macOS/Windows, clippy, security audit
- **Кросс-платформенность** — Поддержка Linux, Windows, macOS

## Быстрый Старт

### Вариант 1: Интерактивный Wizard (Рекомендуется)

```bash
# Сборка
cargo build --release

# Настройка сервера (интерактивный wizard)
./target/release/morphvpn setup

# Настройка клиента (интерактивный wizard)
./target/release/morphvpn setup
```

Wizard проведёт вас через генерацию ключей, создание конфигов и опциональную установку systemd.

### Вариант 2: Скрипты Деплоя (Linux)

```bash
# Сервер (запуск от root)
cd deploy
./setup.sh              # Интерактивно с подтверждением
./setup.sh --dry-run    # Предпросмотр изменений без применения

# Клиент (запуск от root)
./setup-client.sh
./setup-client.sh --dry-run
```

### Вариант 3: Ручной CLI

Сборка:

```bash
cargo build --release
```

Генерация ключей:

```bash
./target/release/morphvpn keygen --private-out server.key --public-out server.pub
./target/release/morphvpn keygen --private-out client.key --public-out client.pub
```

Запуск сервера:

```bash
export MORPHVPN_PSK_FILE=server.psk
./target/release/morphvpn server --bind 0.0.0.0:51820 --private-key server.key --acl deploy/config/acl.example.toml --tun tun0
```

Запуск клиента:

```bash
export MORPHVPN_PSK_FILE=client.psk
./target/release/morphvpn client --server 203.0.113.10:51820 --private-key client.key --server-public-key server.pub --tun tun1 --tun-ip 10.8.0.5
```

CLI больше не принимает открытый `--psk`. Используйте `--psk-file`, `MORPHVPN_PSK_FILE` или `MORPHVPN_PSK`.

## Что Нужно Для Запуска

- Установленный Rust и `cargo`
- Права администратора или root для TUN и изменения маршрутов
- Linux, Windows или macOS

## Структура Репозитория

```text
morphvpn/
├─ src/                    Основной бинарник/runtime код
│  ├─ runtime/             Shard-based обработка пакетов
│  ├─ sys_net.rs           Кросс-платформенная сетевая логика
│  ├─ setup.rs             Интерактивный wizard настройки
│  ├─ transport.rs         Абстракция UDP/TCP транспорта
│  ├─ peer.rs              Управление пирами
│  ├─ metrics.rs           Система метрик
│  ├─ health.rs            Health endpoint
│  ├─ cert.rs              Генерация X.509 сертификатов
│  ├─ config.rs            TOML конфигурация
│  ├─ acl.rs               Access control list
│  └─ identity.rs          Генерация ключей
├─ morphvpn-protocol/      Протокольная библиотека (крипто, handshake, wire, session)
├─ tests/                  Unit, интеграционные и TCP-тесты
├─ deploy/
│  ├─ config/              Шаблоны конфигов (сервер, клиент, ACL)
│  ├─ setup.sh             Скрипт настройки сервера
│  ├─ setup-client.sh      Скрипт настройки клиента
│  └─ morphvpn.service     Systemd-юнит
├─ docs/
│  ├─ protocol.md          RFC формата передачи
│  ├─ deploy.md            Гайд по деплою
│  └─ AUDIT-REPORT.md      Внутренний код-аудит
├─ Cargo.toml
├─ Cargo.lock
└─ README.ru.md
```

## История Версий

Проект эволюционировал через 8 версий:

- **v0.1** — Начальный бейзлайн: Noise handshake, двойное шифрование, TUN, ACL, UDP
- **v0.2** — Rekey механизм, TOML конфиги, интеграционные тесты
- **v0.3** — PMTUD, защита от утечки DNS, профили
- **v0.4** — Метрики, поддержка macOS, graceful shutdown
- **v0.5** — X.509 сертификаты, keepalive, структурированное логирование
- **v0.6** — Абстракция транспорта, health endpoint, валидация конфигов
- **v0.7** — TCP-форвардинг, управление пирами
- **v0.8** — Wizard настройки, скрипты деплоя, CI/CD, защита от утечки IPv6, RFC протокола

Подробности см. в [VERSIONS.md](VERSIONS.md).

## Чего Проект Не Обещает

- Он не заявляет, что готов для продакшена
- Он не заявляет, что прошел профессиональный аудит безопасности
- Он не заявляет, что завершен
- Он не заявляет, что лучше зрелых VPN-решений

## Почему Это Вообще Выложено

Этот репозиторий открыт потому, что прогресс важен, обучение в открытую важно и нормальная критика тоже важна.

Если вы опытнее и видите слабые места, спорные решения или более чистый путь, такие советы здесь действительно нужны.

## Напоминание По Безопасности

Не коммитьте:

- Настоящие приватные ключи
- Реальные IP-адреса серверов
- Личные логи
- Токены, секреты и данные локальной машины

## Лицензия

Проект распространяется по лицензии MIT. См. [LICENSE](LICENSE).
