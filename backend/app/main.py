from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.api.router import api_router
from app.db.session import create_all
from app.core.exceptions import PipelineException, RepositoryCloneException, SecurityScanException

# 모든 ORM 모델을 import해야 Base.metadata가 테이블을 인식한다
import app.db.models.project  # noqa: F401
import app.db.models.pipeline  # noqa: F401
import app.db.models.vulnerability  # noqa: F401
import app.db.models.report  # noqa: F401
import app.db.models.cve_catalog  # noqa: F401

@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_all()
    yield

app = FastAPI(
    title="Mirae Naeil - DevSecOps Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(api_router, prefix="/api")

@app.exception_handler(PipelineException)
async def pipeline_exception_handler(request: Request, exc: PipelineException):
    return JSONResponse(status_code=500, content={"detail": str(exc)})

@app.exception_handler(RepositoryCloneException)
async def clone_exception_handler(request: Request, exc: RepositoryCloneException):
    return JSONResponse(status_code=422, content={"detail": str(exc)})

@app.get("/health")
async def health_check():
    return {"status": "ok"}
