from fastapi import FastAPI
from app.api.accounts import router as accounts_router
from app.api.asymmetric_lab import router as asymmetric_router
from app.api.crypto_lab import router as crypto_router
from app.api.hash_lab import router as hash_router
from app.api.secure_notes import router as secure_notes_router
from app.api.students import router as students_router

app = FastAPI(
    title="Digital Dean API",
    version="0.5.0",
)

@app.get("/health")
def health_check():
    return {"status": "ok"}

app.include_router(accounts_router)
app.include_router(asymmetric_router)
app.include_router(crypto_router)
app.include_router(hash_router)
app.include_router(secure_notes_router)
app.include_router(students_router)