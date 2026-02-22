# SSHADmin (Manipulator)

Система централизованного управления SSH-доступом на Linux-серверах.

Администратор через веб-интерфейс управляет пользователями, SSH-ключами, группами серверов и политиками доступа. Агент на каждом сервере автоматически применяет изменения.

## Архитектура

```
┌──────────────────┐         HTTPS          ┌────────────────────────┐
│  Linux-сервер    │ ◄────────────────────► │  Центр управления      │
│  (agent.sh)      │   pull / heartbeat     │  (Flask + SQLite)      │
│  curl + jq       │                        │  Flask-Admin UI        │
└──────────────────┘                        └────────────────────────┘
         │                                            │
    systemd сервис                              Docker / bare metal
    /root/manipulator/                          Nginx reverse proxy
```

- **Центр управления** — Python/Flask, работает в Docker или напрямую
- **Агент** — чистый bash-скрипт (без Python на управляемых серверах), зависимости: `curl`, `jq`, `sudo`
- **Bootstrap** — установщик агента одной командой с pre-flight проверками

## Возможности

- Автоматическое создание/удаление SSH-пользователей на серверах
- Два режима доступа: по SSH-ключам или по паролю (настраивается per-группа)
- Обнаружение существующих пользователей (UID >= 1000) при установке агента
- Группы серверов с назначением пользователей и SSH-политик
- Блокировка/разблокировка пользователей (`usermod -L / -U`)
- Управление sudo-доступом (`/etc/sudoers.d/`)
- Аудит всех изменений
- Поддержка любого Linux-дистрибутива (Debian, Ubuntu, CentOS, RHEL, Rocky, Alma, Fedora)
- Zero-touch onboarding серверов (`curl | bash`)

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
> Файл `sshadmin.db` хранится в каталоге `./data/` рядом с `docker-compose.yml`,
> а не в Docker volume — его легко бекапить, просматривать и переносить.

Создайте администратора:

```bash
docker-compose exec controlcenter flask --app server.app:create_app auth create-admin admin
```

Или используйте seed-скрипт (создаст `admin` / `admin`):

```bash
docker-compose exec controlcenter python server/seed.py
```

Админка доступна по адресу: **http://your-server:5000/admin/**

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
cp manipulator.conf /etc/nginx/sites-available/manipulator.conf
ln -s /etc/nginx/sites-available/manipulator.conf /etc/nginx/sites-enabled/
```

Отредактируйте `server_name` и пути к SSL-сертификатам, затем:

```bash
nginx -t && systemctl reload nginx
```

Подробности в файле [manipulator.conf](manipulator.conf).

## Установка агента на сервер

На каждом управляемом Linux-сервере выполните от root:

```bash
curl -sL https://your-center.example.com/api/bootstrap.sh | bash -s -- https://your-center.example.com
```

Скрипт автоматически:

1. Определит ОС и пакетный менеджер (`apt` / `yum` / `dnf`)
2. Выполнит pre-flight проверки:
   - `systemd` — должен быть (агент работает как сервис)
   - `sshd` — проверит что запущен (предупредит если нет)
   - `sudo` — установит если отсутствует (на Debian 12 его нет по умолчанию)
   - `curl`, `jq` — установит если отсутствуют
   - `useradd`, `userdel`, `usermod`, `chpasswd`, `groupadd` — проверит наличие
   - `/etc/ssh/sshd_config` — предупредит если отсутствует
   - Сетевая доступность центра управления
   - Повторная установка — откажет если агент уже установлен
3. Соберёт информацию о существующих пользователях (UID >= 1000), их SSH-ключах и sudo-статусе
4. Зарегистрирует сервер в центре управления (статус: **pending**)
5. Скачает `agent.sh` в `/root/manipulator/`
6. Создаст и запустит systemd-сервис `sshadmin-agent`

После установки зайдите в админку и **подтвердите** (approve) сервер — только после этого агент начнёт применять изменения.

## Работа агента

Агент — это bash-скрипт `/root/manipulator/agent.sh`, работающий как systemd-сервис.

### Цикл синхронизации

Каждые N секунд (по умолчанию 300 = 5 минут) агент:

1. Запрашивает желаемое состояние: `GET /api/pull`
2. Сравнивает с текущими пользователями в системе
3. Создаёт новых пользователей (`useradd -m`)
4. Удаляет пользователей, которых больше нет в конфиге (`userdel -r`)
5. Синхронизирует SSH-ключи (`~/.ssh/authorized_keys`)
6. Управляет sudo (`/etc/sudoers.d/<username>`)
7. Блокирует/разблокирует пользователей (`usermod -L / -U`)
8. Обновляет sshd_config (`PasswordAuthentication`, `PubkeyAuthentication`)
9. Отправляет heartbeat: `POST /api/heartbeat`

### Конфигурация агента

Файл: `/root/manipulator/agent.conf`

```bash
# URL центра управления
CONTROL_CENTER_URL="https://your-center.example.com"

# Токен агента (выдаётся при регистрации, не менять вручную)
AGENT_TOKEN="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Интервал опроса в секундах (по умолчанию 300 = 5 минут)
POLL_INTERVAL=300
```

### Изменение частоты опроса

Отредактируйте `POLL_INTERVAL` в конфиге и перезапустите сервис:

```bash
# Установить интервал в 60 секунд (1 минута)
sed -i 's/^POLL_INTERVAL=.*/POLL_INTERVAL=60/' /root/manipulator/agent.conf

# Перезапустить агент
systemctl restart sshadmin-agent
```

Или вручную:

```bash
nano /root/manipulator/agent.conf
# Измените POLL_INTERVAL=60
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

# Остановка
systemctl stop sshadmin-agent

# Удаление агента
systemctl stop sshadmin-agent
systemctl disable sshadmin-agent
rm -f /etc/systemd/system/sshadmin-agent.service
rm -rf /root/manipulator
systemctl daemon-reload
```

### Защита

Агент **никогда** не трогает системных пользователей. Список защищённых аккаунтов зашит в скрипт:
`root`, `nobody`, `daemon`, `sshd`, `www-data`, `centos`, `ec2-user` и др.

Перед изменением `sshd_config` создаётся backup и проверяется валидность через `sshd -t`.

## Управление через веб-интерфейс

Админка на базе Flask-Admin: **http://your-center:5000/admin/**

### Серверы

- Список всех зарегистрированных серверов
- Статусы: `pending` → `approved` / `rejected`
- Inline-редактирование статуса (approve одним кликом)
- Время последнего heartbeat

### Пользователи

- CRUD: имя, SSH-ключи (textarea), sudo, shell
- Поле `source`: `manual` (создан вручную) / `discovered` (найден при bootstrap)
- Блокировка/разблокировка через чекбокс `is_blocked`
- Назначение в группы

### Группы

- Объединяют серверы и пользователей
- SSH-политики per-группа:
  - `PubKey Auth` — вход по ключам (вкл/выкл)
  - `Password Auth` — вход по паролю (вкл/выкл)

### Аудит

- Read-only лог всех изменений
- Кто, когда, что сделал
- Фильтры по actor, action, target

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
│   ├── admin.py               # Flask-Admin views
│   ├── auth.py                # Аутентификация (session + Bearer token)
│   ├── config.py              # Конфигурация
│   ├── seed.py                # Seed-скрипт (первый админ)
│   ├── requirements.txt
│   └── tests/
│       ├── conftest.py
│       ├── test_api.py
│       └── test_models.py
├── agent/
│   └── agent.sh               # Агент (чистый bash)
├── bootstrap.sh               # Установщик агента (чистый bash)
├── manipulator.conf            # Nginx vhost конфиг
├── Dockerfile
├── docker-compose.yml
└── .gitignore
```
