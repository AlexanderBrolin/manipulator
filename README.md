# SSHADmin

Система централизованного управления SSH-доступом на Linux-серверах.

Администратор через веб-интерфейс управляет пользователями, SSH-ключами, паролями, группами серверов и политиками доступа. Агент на каждом сервере автоматически применяет изменения.

## Архитектура

```
┌──────────────────┐         HTTPS          ┌────────────────────────┐
│  Linux-сервер    │ ◄────────────────────► │  Центр управления      │
│  (agent.sh)      │   pull / heartbeat     │  (Flask + SQLite)      │
│  curl + jq       │                        │  Tailwind CSS UI       │
└──────────────────┘                        └────────────────────────┘
         │                                            │
    systemd сервис                              Docker / bare metal
    /opt/sshadmin/                             Nginx reverse proxy
```

- **Центр управления** — Python/Flask с кастомным UI (Jinja2 + Tailwind CSS + Alpine.js), работает в Docker или напрямую
- **Агент** — чистый bash-скрипт (без Python на управляемых серверах), зависимости: `curl`, `jq`
- **Bootstrap** — установщик агента одной командой с pre-flight проверками

## Возможности

- Автоматическое создание/удаление SSH-пользователей на серверах
- Два режима доступа: по SSH-ключам или по паролю (настраивается per-группа)
- Прямое назначение пользователей на сервер (без групп) или через группы
- Обнаружение существующих пользователей (UID >= 1000 и UID=0 кроме root) при установке агента
- Группы серверов с назначением пользователей и SSH-политик
- Блокировка пользователей (password lock + account expiry + удаление authorized_keys)
- Управление sudo-доступом (`/etc/sudoers.d/`)
- Аудит всех изменений
- Поддержка любого Linux-дистрибутива с systemd (Debian, Ubuntu, CentOS, RHEL, Rocky, Alma, Fedora)

## Быстрый старт

### 1. Запуск центра управления (Docker Compose)

```bash
git clone <repo-url> SSHADmin
cd SSHADmin
```

Отредактируйте `docker-compose.yml` — замените секреты:

```yaml
environment:
  - SECRET_KEY=ваш-секретный-ключ-здесь
  - JWT_SECRET_KEY=ваш-jwt-ключ-здесь
  - DATABASE_URL=sqlite:////app/data/sshadmin.db
```

Создайте каталог для данных и запустите:

```bash
mkdir -p data
docker-compose up -d
```

> SQLite встроен в Python — отдельный контейнер для БД не нужен.
> Файл `sshadmin.db` хранится в каталоге `./data/` рядом с `docker-compose.yml`.

Создайте администратора:

```bash
docker-compose exec controlcenter flask --app server.app:create_app auth create-admin admin
```

Или используйте seed-скрипт (создаст `admin` / `admin`):

```bash
docker-compose exec controlcenter python server/seed.py
```

Веб-интерфейс доступен по адресу: **http://your-server:5000/**

### 2. Запуск без Docker

```bash
cd SSHADmin
pip install -r server/requirements.txt
python server/seed.py                         # admin / admin
flask --app server.app:create_app run --host 0.0.0.0
```

### 3. Nginx reverse proxy (production)

Скопируйте конфиг:

```bash
cp sshadmin.conf /etc/nginx/sites-available/sshadmin.conf
ln -s /etc/nginx/sites-available/sshadmin.conf /etc/nginx/sites-enabled/
```

Отредактируйте `server_name` и пути к SSL-сертификатам, затем:

```bash
nginx -t && systemctl reload nginx
```

Подробности в файле [sshadmin.conf](sshadmin.conf).

## Установка агента на сервер

На каждом управляемом Linux-сервере выполните от root:

```bash
curl -sL https://your-center.example.com/api/bootstrap.sh | bash -s -- https://your-center.example.com
```

Скрипт автоматически:

1. Определит ОС и пакетный менеджер (`apt` / `yum` / `dnf`)
2. Выполнит pre-flight проверки:
   - `systemd` — должен быть (агент работает как сервис)
   - `sshd` — проверит что запущен
   - `sudo` — установит если отсутствует (на Debian 12 его нет по умолчанию)
   - `curl`, `jq` — установит если отсутствуют
   - `useradd`, `userdel`, `usermod`, `chpasswd`, `groupadd` — проверит наличие
   - Сетевая доступность центра управления
   - Повторная установка — откажет если агент уже установлен
3. Соберёт информацию о существующих пользователях (UID >= 1000 и UID=0 кроме root), их SSH-ключах и sudo-статусе
4. Зарегистрирует сервер в центре управления (статус: **pending**)
5. Скачает `agent.sh` в `/opt/sshadmin/`
6. Создаст и запустит systemd-сервис `sshadmin-agent`

После установки зайдите в веб-интерфейс и **подтвердите** (approve) сервер — только после этого агент начнёт применять изменения.

## Работа агента

Агент — bash-скрипт `/opt/sshadmin/agent.sh`, работающий как systemd-сервис.

### Цикл синхронизации

Каждые N секунд (по умолчанию 300 = 5 минут) агент:

1. Запрашивает желаемое состояние: `GET /api/pull`
2. Сравнивает с текущими пользователями в системе
3. Создаёт новых пользователей (`useradd -m`)
4. Удаляет пользователей, которых больше нет в конфиге (`userdel -r`)
5. Синхронизирует SSH-ключи (`~/.ssh/authorized_keys`)
6. Устанавливает пароли (`chpasswd`)
7. Управляет sudo (`/etc/sudoers.d/<username>`)
8. Блокирует/разблокирует пользователей (password lock + account expiry + authorized_keys)
9. Обновляет sshd_config (`PasswordAuthentication`, `PubkeyAuthentication`)
10. Отправляет heartbeat: `POST /api/heartbeat`

### Блокировка пользователей

При блокировке агент выполняет три действия для гарантии невозможности входа:

- `usermod -L` — блокирует пароль
- `usermod -e 1` — устанавливает дату истечения аккаунта (блокирует вход по ключам)
- Перемещает `authorized_keys` → `authorized_keys.blocked`

При разблокировке: пароль и аккаунт разблокируются, ключи синхронизируются заново.

### Удаление пользователей

При удалении пользователя из системы (или снятии доступа к серверу) агент:

- Выполняет `userdel -r` (удаление аккаунта + домашнего каталога)
- Удаляет `/etc/sudoers.d/<username>`

Это происходит автоматически: если пользователь исчезает из ответа `/api/pull`, агент считает его лишним и удаляет.

### Конфигурация агента

Файл: `/opt/sshadmin/agent.conf`

```bash
CONTROL_CENTER_URL="https://your-center.example.com"
AGENT_TOKEN="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
POLL_INTERVAL=300
```

### Изменение частоты опроса

```bash
sed -i 's/^POLL_INTERVAL=.*/POLL_INTERVAL=60/' /opt/sshadmin/agent.conf
systemctl restart sshadmin-agent
```

### Управление сервисом агента

```bash
# Статус
systemctl status sshadmin-agent

# Логи (в реальном времени)
journalctl -u sshadmin-agent -f

# Перезапуск
systemctl restart sshadmin-agent

# Удаление агента
systemctl stop sshadmin-agent
systemctl disable sshadmin-agent
rm -f /etc/systemd/system/sshadmin-agent.service
rm -rf /opt/sshadmin
systemctl daemon-reload
```

### Защита

Агент **никогда** не трогает системных пользователей. Список защищённых аккаунтов зашит в скрипт:
`root`, `nobody`, `daemon`, `sshd`, `www-data`, `centos`, `ec2-user` и др.

Перед изменением `sshd_config` создаётся backup и проверяется валидность через `sshd -t`.

## Веб-интерфейс

Кастомный UI на базе Tailwind CSS и Alpine.js: **http://your-center:5000/**

### Dashboard

- Общая статистика: серверы, пользователи, группы
- Последние зарегистрированные серверы
- Лог последних действий

### Серверы

- Список всех зарегистрированных серверов
- Кликабельный hostname — переход на страницу сервера
- На странице сервера: информация, прямое назначение пользователей, таблица всех пользователей с доступом (с указанием источника — direct/группа)
- Статусы: `pending` → `approved` / `rejected`
- Время последнего heartbeat

### Пользователи

- Имя, SSH-ключи (textarea), пароль, sudo, shell
- Поле `source`: `manual` (создан вручную) / `discovered` (найден при bootstrap, отмечен фиолетовым бейджем)
- Блокировка/разблокировка
- Назначение в группы и прямое назначение на серверы
- На странице редактирования: список всех серверов, к которым у пользователя есть доступ

### Группы

- Объединяют серверы и пользователей
- SSH-политики per-группа:
  - `PubKey Auth` — вход по ключам
  - `Password Auth` — вход по паролю

### Аудит

- Лог всех изменений (последние 200 записей)
- Кто, когда, что сделал

## API

| Метод | Endpoint | Auth | Описание |
|-------|----------|------|----------|
| `POST` | `/api/register` | нет | Регистрация сервера + импорт существующих пользователей |
| `GET` | `/api/pull` | Bearer token | Получить desired state для сервера |
| `POST` | `/api/heartbeat` | Bearer token | Heartbeat агента |
| `GET` | `/api/bootstrap.sh` | нет | Скачать bootstrap-скрипт |
| `GET` | `/api/agent.sh` | нет | Скачать агент |

### Пример: ответ `/api/pull`

```json
{
  "users": [
    {
      "username": "ivan",
      "ssh_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... ivan@laptop"],
      "password": "",
      "is_sudo": true,
      "is_blocked": false,
      "shell": "/bin/bash"
    }
  ],
  "ssh_policy": {
    "password_auth": false,
    "pubkey_auth": true
  }
}
```

## Тесты

```bash
pip install pytest
python -m pytest server/tests/ -v
```

## Структура проекта

```
SSHADmin/
├── server/                     # Центр управления (Python/Flask)
│   ├── app.py                 # Flask application factory
│   ├── models.py              # SQLAlchemy модели (Server, User, Group, AuditLog, AdminUser)
│   ├── api.py                 # API endpoints (register, pull, heartbeat)
│   ├── views.py               # Веб-интерфейс (dashboard, CRUD серверов/пользователей/групп)
│   ├── auth.py                # Аутентификация (session + Bearer token)
│   ├── config.py              # Конфигурация
│   ├── seed.py                # Seed-скрипт (первый админ)
│   ├── requirements.txt
│   ├── templates/             # Jinja2 шаблоны (Tailwind CSS + Alpine.js)
│   │   ├── base.html          # Базовый layout с sidebar
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── servers.html
│   │   ├── server_detail.html
│   │   ├── users.html
│   │   ├── user_edit.html
│   │   ├── groups.html
│   │   ├── group_edit.html
│   │   └── audit.html
│   └── tests/
│       ├── conftest.py
│       ├── test_api.py
│       └── test_models.py
├── agent/
│   └── agent.sh               # Агент (чистый bash)
├── bootstrap.sh               # Установщик агента (чистый bash)
├── sshadmin.conf               # Nginx vhost конфиг
├── Dockerfile
├── docker-compose.yml
└── .gitignore
```
