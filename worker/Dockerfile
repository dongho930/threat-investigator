# Playwright 버전과 같은 공식 이미지(동봉된 Chromium 포함)를 사용한다.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY worker ./worker

# 이미지에 포함된 비root 계정. Chromium 샌드박스를 끄지 않는다(--no-sandbox 금지).
USER pwuser

CMD ["python", "-m", "worker.main"]
