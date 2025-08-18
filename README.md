# ГОСТ 2012: проверка откреплённой подписи (CMS/CAdES)

Проверка откреплённой подписи ГОСТ Р 34.10‑2012 (256/512) без OpenSSL и внешних сервисов. Публичный ключ берётся из сертификата в CMS. В комплекте: веб‑UI (FastAPI + Vue) и CLI.

## Стек
- Python 3.11
- asn1crypto
- gostcrypto
 - FastAPI, Uvicorn
 - ReportLab (PDF‑отчёт)

## Входные параметры
- Подписанный файл: например, `samples/doc.pdf`
- Открепленная подпись: `samples/doc.sig` (CMS/CAdES)

## Запуск в Docker (Ubuntu)
```bash
docker compose up --build
```
Откройте `http://localhost:8000/`, перетащите `PDF` и `SIG`. Доступна кнопка «Скачать протокол (PDF)».

Для CLI‑проверки можно временно переопределить команду контейнера:
```bash
docker compose run -T --rm gost-verify python verify_gost_detached.py /data/your.pdf /data/your.sig
```

## Команды для воспроизведения (Docker)

- Короткий вывод:
```bash
docker compose run -T --rm gost-verify python verify_gost_detached.py /data/doc.pdf /data/doc.sig
```

- Диагностический (с перебором кривых):
```bash
docker compose run -T --rm gost-verify python verify_gost_detached.py /data/doc.pdf /data/doc.sig --verbose
```

- Пересобрать образ и запустить проверку заново:
```bash
docker compose down -v --remove-orphans
docker compose build --no-cache
docker compose run -T --rm gost-verify python verify_gost_detached.py /data/doc.pdf /data/doc.sig
docker compose run -T --rm gost-verify python verify_gost_detached.py /data/doc.pdf /data/doc.sig --verbose
```

## Локальный запуск (без Docker)
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r src/requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```
CLI:
```bash
python3 src/verify_gost_detached.py <file.pdf> <file.sig>
```

## Вывод CLI
Успех:
```
Signature OK
Signer subject: ...
Issuer: ...
Serial: ...
GOST mode: 256
messageDigest OK (Streebog-256)
Проверка подписи: блок 1 (gostcrypto). Кандидатов кривых: N
  -> кривая: <имя>
Выбранные параметры проверки:
  кривая: <имя>
  вариант данных: <variant>
  вариант ключа: <variant>
  вариант подписи: <variant>
Script finished
```
Ошибка: `ERROR: ...` или `Signature FAIL: ...`

## Примечания реализации
- Поддерживается извлечение публичного ключа из SPKI без OID-зависимостей.
- Поддержана нормализация `signedAttrs` (универсальный SET) и совместимость форматов R||S/S||R, X||Y/реверс.
- Используются только open-source библиотеки; OpenSSL и внешние сервисы не применяются.

## Примечание
Папка `samples/` исключена из репозитория (`.gitignore`).


## Создание откреплённой подписи (API)

В проекте реализовано API для создания CMS/CAdES detached‑подписи (ГОСТ 2012) без OpenSSL и внешних сервисов.

Эндпоинты:
- `POST /api/sign` — по явным данным сертификата и приватного ключа
  - form‑data: `pdf` (файл), `cert` (X.509 в PEM/DER), `private_key_hex` (hex скаляр d: 64 символа для ГОСТ‑256, 128 — для ГОСТ‑512)
  - ответ: поток `application/pkcs7-signature` (`.sig`).
- `POST /api/sign/pfx` — (опционально) из контейнера PKCS#12 (PFX)
  - form‑data: `pdf`, `pfx`, `password`
  - ограничение текущей версии: поддержан только незашифрованный `KeyBag (PrivateKeyInfo)` + x509 `certBag`; `ShroudedKeyBag` (зашифрованный приватный ключ) не поддержан.

Пример (PowerShell) — создать подпись по cert+hex и проверить её:
```powershell
# Создать подпись
$fd = New-Object System.Net.Http.MultipartFormDataContent
$fd.Add((New-Object System.Net.Http.StreamContent([IO.File]::OpenRead('samples/doc.pdf'))),'pdf','doc.pdf')
$fd.Add((New-Object System.Net.Http.StreamContent([IO.File]::OpenRead('samples/cert.cer'))),'cert','cert.cer')
$fd.Add((New-Object System.Net.Http.StringContent('001122...AABB')),'private_key_hex')
$hc = New-Object System.Net.Http.HttpClient
$r = $hc.PostAsync('http://localhost:8000/api/sign',$fd).Result
[IO.File]::WriteAllBytes('samples/new.sig', $r.Content.ReadAsByteArrayAsync().Result)

# Проверка созданной подписи (CLI в Docker)
cmd /c "docker compose run -T --rm gost-verify python verify_gost_detached.py /data/doc.pdf /data/new.sig --verbose"
```

Вспомогательно: извлечение сертификата из `.sig`:
```bash
# PEM
docker compose run -T --rm gost-verify python extract_cert.py /data/doc.sig > samples/cert.pem
# DER (корректная запись байтов под Windows)
cmd /c "docker compose run -T --rm gost-verify python extract_cert.py /data/doc.sig --der > samples\\cert.cer"
```

Планы:
- Добавить расшифровку `ShroudedKeyBag` (PBES2/PBKDF2/ГОСТ‑алгоритмы) для PFX без внешних провайдеров (нужны тестовые файлы).


