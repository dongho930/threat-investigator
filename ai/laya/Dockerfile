# Laya multilingual 판정 모델 서버 (CPU). 가중치는 빌드 때 고정 리비전에서 받고 SHA-256을 검증한다.
# 실행 중에는 인터넷이 없는 ai 네트워크에만 붙고, 모델을 다시 받지 않는다(HF_HUB_OFFLINE=1).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HUB_OFFLINE=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    TOKENIZERS_PARALLELISM=false

WORKDIR /app
COPY requirements.txt .
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch==2.14.0+cpu \
    && pip install -r requirements.txt \
    && pip uninstall -y pip

# convaiinnovations/laya-multilingual @ 82d57fc (Apache-2.0). 커밋 고정 URL + 파일별 SHA-256.
ARG LAYA_REV=82d57fc4f2d1be3d2caac494045f2ec51d0842f3
ARG HF=https://huggingface.co/convaiinnovations/laya-multilingual/resolve/${LAYA_REV}
ADD --chmod=0444 --checksum=sha256:9d628fd971b700382ac6f65920a86f149777b2e748e0c955fb3b19695aa8f204 ${HF}/model.safetensors /models/laya-multilingual/model.safetensors
ADD --chmod=0444 --checksum=sha256:25061739243b617ad88d1219ba6f8a9c86c5881ca28df024fa2d9b3b2fcc30c6 ${HF}/rl_agent_config.json /models/laya-multilingual/rl_agent_config.json
ADD --chmod=0444 --checksum=sha256:83f6916d13ef0f556ac461f28308dc2bffa7ebeadee8ec9e2db5812020ea5bb4 ${HF}/encoder/config.json /models/laya-multilingual/encoder/config.json
ADD --chmod=0444 --checksum=sha256:609d8f4c067cd3950f88594c5a802616cea245823836ef5848ee4fc40aab5b6f ${HF}/tokenizer/tokenizer.json /models/laya-multilingual/tokenizer/tokenizer.json
ADD --chmod=0444 --checksum=sha256:424b69444bf7b5809dc2cd2e36d0bd71b8055124dd24274d6db3c655d38205e7 ${HF}/tokenizer/tokenizer_config.json /models/laya-multilingual/tokenizer/tokenizer_config.json

# laya는 불러올 때 tokenizer_config.json을 transformers 5용으로 고쳐 쓴다. 실행 중에는 모델 폴더를 쓸 수 없으므로
# 빌드 때 한 번 같은 함수로 고치고, 결과도 해시로 확인한다(원본 해시 → 고친 뒤 해시 둘 다 고정).
RUN python -c "from laya.agent import _fix_tokenizer_config; _fix_tokenizer_config('/models/laya-multilingual')"     && echo "6c6b2d8e3c84ce0e671c129cd6b374b235d6f9863042a5836358d00a89bbb5a1  /models/laya-multilingual/tokenizer/tokenizer_config.json" | sha256sum -c -     && chmod -R a+rX,a-w /models

COPY server.py .

ENV LAYA_MODEL_DIR=/models/laya-multilingual \
    LAYA_REVISION=${LAYA_REV}

RUN useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin laya
USER 10002

EXPOSE 8000
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
