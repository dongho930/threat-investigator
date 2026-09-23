FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
# 런타임에는 pip가 필요 없다. pip 내부 라이브러리(msgpack 등)의 취약점이 이미지에 남지 않도록 설치 후 제거한다.
RUN pip install -r requirements.txt && pip uninstall -y pip

COPY alembic.ini .
COPY alembic ./alembic
COPY app ./app

# 비root 계정으로 실행
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser
USER 10001

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
