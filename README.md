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


