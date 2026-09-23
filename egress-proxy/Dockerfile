FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
# 표준 라이브러리만 쓰므로 설치할 패키지가 없다. pip도 지운다.
RUN pip uninstall -y pip \
    && useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin proxyuser

COPY egress_proxy ./egress_proxy

USER 10002
EXPOSE 3128
CMD ["python", "-m", "egress_proxy.main"]
