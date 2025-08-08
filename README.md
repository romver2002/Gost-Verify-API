# ГОСТ 2012: Проверка открепленной подписи (detached CMS)

Проект выполняет проверку открепленной электронной подписи ГОСТ Р 34.10-2012 (256/512) без использования OpenSSL и внешних сервисов. Публичный ключ берётся из сертификата внутри CMS, отдельный файл ключа не требуется.

## Стек
- Python 3.11
- asn1crypto
- gostcrypto

## Входные параметры
- Подписанный файл: например, `samples/doc.pdf`
- Открепленная подпись: `samples/doc.sig` (CMS/CAdES)

## Запуск в Docker (Ubuntu)
1. Сборка:
   ```bash
   docker compose build --no-cache
   ```
2. Запуск проверки:
   ```bash
   docker compose run -T --rm gost-verify
   ```
   По умолчанию контейнер использует `samples/doc.pdf` и `samples/doc.sig` (см. `Dockerfile`).

Для проверки других файлов примонтируйте их в том же volume (`./samples:/data:ro`) и измените CMD в `Dockerfile` или передайте аргументы при запуске:
```bash
docker compose run -T --rm gost-verify python verify_gost_detached.py /data/your.pdf /data/your.sig
```

## Локальный запуск (без Docker)
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r src/requirements.txt
python3 src/verify_gost_detached.py samples/doc.pdf samples/doc.sig
```

## Вывод
- Успех:
  ```
  Signature OK
  Signer subject: ...
  Issuer: ...
  Serial: ...
  GOST mode: 256
  ```
- Ошибка:
  - `ERROR: ...` или `Signature FAIL: ...`

## Примечания реализации
- Поддерживается извлечение публичного ключа из SPKI без OID-зависимостей.
- Поддержана нормализация `signedAttrs` (универсальный SET) и совместимость форматов R||S/S||R, X||Y/реверс.
- Используются только open-source библиотеки; OpenSSL и внешние сервисы не применяются.


