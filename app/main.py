from fastapi import FastAPI
from app.api.students import router as students_router

app = FastAPI(title="Digital Dean API", version="0.1.0")

@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}

app.include_router(students_router)
