# 소형 생성 LLM 서버: llama.cpp(CPU) + Qwen3-1.7B GGUF(Q8_0, Apache-2.0).
# - 서버 이미지는 다이제스트로 고정한다. Ollama 이미지(9.2GB, GPU 라이브러리 포함) 대신 CPU용 llama.cpp(1.2GB)를 쓴다.
# - 가중치는 Qwen 공식 저장소의 커밋 고정 URL에서 받고 SHA-256을 검증한다(Hugging Face LFS oid와 같은 값).
# - 실행 중에는 인터넷이 없는 ai 네트워크에만 붙는다. 비root, 읽기 전용, 웹 UI 끔.
FROM ghcr.io/ggml-org/llama.cpp:server@sha256:a94b642b3e2620749bf2ff5672df922c23a6202710e54a8f7667e58df70aba5a

ARG QWEN_REV=90862c4b9d2787eaed51d12237eafdfe7c5f6077
ADD --chmod=0444 --checksum=sha256:061b54daade076b5d3362dac252678d17da8c68f07560be70818cace6590cb1a \
    https://huggingface.co/Qwen/Qwen3-1.7B-GGUF/resolve/${QWEN_REV}/Qwen3-1.7B-Q8_0.gguf /models/qwen3-1.7b-q8_0.gguf

# ADD --chmod는 새로 만든 폴더에도 같은 권한(실행 비트 없음)을 줘 비root가 들어갈 수 없다 → 읽기·통과만 허용
RUN chmod -R a+rX,a-w /models

USER 65534:65534
EXPOSE 8080
# -c 4096: 페이지 요약 1건 + 지시문이면 충분. -np 1: 동시 요청 1건(메모리 제한). --no-webui: 웹 화면 끔.
CMD ["-m", "/models/qwen3-1.7b-q8_0.gguf", "--alias", "qwen3-1.7b-q8_0", "--host", "0.0.0.0", "--port", "8080", \
     "-c", "4096", "-np", "1", "-t", "4", "--no-webui"]
