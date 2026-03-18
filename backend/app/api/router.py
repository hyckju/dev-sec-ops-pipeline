from fastapi import APIRouter
from app.api.v1 import pipelines, projects

api_router = APIRouter()
api_router.include_router(pipelines.router, prefix="/v1/pipelines", tags=["pipelines"])
api_router.include_router(projects.router, prefix="/v1/projects", tags=["projects"])
