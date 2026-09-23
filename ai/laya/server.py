"""Laya 판정 모델 서버.

- 인터넷이 없는 ai 네트워크에서 ai-judge만 호출한다. 포트를 공개하지 않는다.
- 요청 크기·질문 수·선택지 수를 제한한다. choice 질문만 받는다(noul은 시험에서 거의 모든 입력에 '예'로 답해 쓰지 않음).
- 오류 응답에 내부 경로·예외 내용을 넣지 않는다.
"""

import logging
import os
import time
from typing import Annotated

import laya
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("laya-server")

MODEL_DIR = os.environ.get("LAYA_MODEL_DIR", "/models/laya-multilingual")
REVISION = os.environ.get("LAYA_REVISION", "unknown")
MAX_BODY = 64 * 1024

Key = Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,32}$")]
ShortText = Annotated[str, StringConstraints(max_length=300)]


class ChoiceQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Annotated[str, StringConstraints(pattern=r"^choice$")]
    instructions: ShortText
    criteria: dict[Key, ShortText] = Field(min_length=2, max_length=8)


class DecideRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: dict[Key, Annotated[str, StringConstraints(max_length=4000)]] = Field(min_length=1, max_length=6)
    questions: dict[Key, ChoiceQuestion] = Field(min_length=1, max_length=4)


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
agent = laya.load(MODEL_DIR, device="cpu")
logger.info("laya loaded revision=%s", REVISION)


@app.middleware("http")
async def limit_body(request: Request, call_next):  # type: ignore[no-untyped-def]
    declared = request.headers.get("content-length")
    if declared is None or not declared.isdigit() or int(declared) > MAX_BODY:
        return JSONResponse(status_code=413, content={"code": "body_too_large"})
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"code": "invalid_request"})


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("decide failed")
    return JSONResponse(status_code=500, content={"code": "model_error"})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "revision": REVISION}


@app.post("/v1/decide")
def decide(body: DecideRequest) -> dict[str, object]:
    questions = {k: q.model_dump() for k, q in body.questions.items()}
    started = time.perf_counter()
    result = agent.predict(dict(body.state), questions)
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    answers = {}
    for key, answer in result.get("answers", {}).items():
        answers[key] = {
            "choice": answer.get("choice"),
            "probabilities": {k: float(v) for k, v in (answer.get("probabilities") or {}).items()},
        }
    logger.info("decide questions=%d elapsed_ms=%d", len(answers), elapsed_ms)
    return {"model": "laya-multilingual", "revision": REVISION, "answers": answers, "elapsed_ms": elapsed_ms}
