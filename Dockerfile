FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN python -m pip install --upgrade pip setuptools wheel
COPY src/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY src/ /app/
# По умолчанию запускаем API; для CLI можно переопределить CMD в compose
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
