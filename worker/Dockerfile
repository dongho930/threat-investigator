# Playwright 버전과 같은 공식 이미지(동봉된 Chromium 포함)를 사용한다.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
# 런타임에는 pip가 필요 없다. pip 내부 라이브러리(msgpack 등)의 취약점이 이미지에 남지 않도록 설치 후 제거하고,
# 베이스 이미지가 남긴 virtualenv 휠 캐시(구버전 pip·setuptools)도 지운다.
RUN pip install -r requirements.txt && pip uninstall -y pip && rm -rf /root/.cache

COPY worker ./worker

# 이미지에 포함된 비root 계정. Chromium 샌드박스를 끄지 않는다(--no-sandbox 금지).
USER pwuser

CMD ["python", "-m", "worker.main"]
