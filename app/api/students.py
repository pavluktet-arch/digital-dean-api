import uuid
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict

from app.schemas.secure_note import NoteCreate
from app.security.context import note_aad
from app.security.adapters import seal_bytes, open_bytes, CiphertextError
from app.security.nonce import NonceSequence

router = APIRouter(prefix="/api/v1/students", tags=["students"])

# Сховище у пам'яті
STUDENTS_DB = {
    "student-1": {"id": "student-1", "name": "Студент 1", "notes": {}},
    "student-2": {"id": "student-2", "name": "Студент 2", "notes": {}},
    "student-3": {"id": "student-3", "name": "Студент 3", "notes": {}},
}

# Генератор nonce та фіксований ключ для тестування
nonce_seq = NonceSequence(limit=1000)
FIXED_KEY = b"\x00" * 32  # 32 байти


class StudentCreate(BaseModel):
    name: str
    model_config = ConfigDict(extra="forbid")


@router.post("", status_code=status.HTTP_201_CREATED)
def create_student(student: StudentCreate):
    student_id = f"student-{uuid.uuid4().hex[:6]}"
    STUDENTS_DB[student_id] = {"id": student_id, "name": student.name, "notes": {}}
    return STUDENTS_DB[student_id]


@router.get("", status_code=status.HTTP_200_OK)
def list_students():
    return list(STUDENTS_DB.values())


@router.get("/{student_id}", status_code=status.HTTP_200_OK)
def get_student(student_id: str):
    if student_id not in STUDENTS_DB:
        raise HTTPException(status_code=404, detail="Student not found")
    return STUDENTS_DB[student_id]


@router.post("/{student_id}/notes", status_code=status.HTTP_201_CREATED)
def create_note(student_id: str, note_in: NoteCreate):
    if student_id not in STUDENTS_DB:
        STUDENTS_DB[student_id] = {"id": student_id, "name": "Test Student", "notes": {}}

    note_id = str(uuid.uuid4())
    try:
        nonce = nonce_seq.next()
    except RuntimeError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nonce sequence limit reached"
        )

    aad = note_aad(student_id, note_id, "aes-gcm", "default-key")
    ciphertext, tag = seal_bytes(
        backend="aes-gcm",
        algorithm="aes-gcm",
        key=FIXED_KEY,
        nonce=nonce,
        data=note_in.text.encode("utf-8"),
        aad=aad
    )

    STUDENTS_DB[student_id]["notes"][note_id] = {
        "id": note_id,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag,
    }

    return {"id": note_id}


@router.get("/{student_id}/notes/{note_id}", status_code=status.HTTP_200_OK)
def get_note(student_id: str, note_id: str):
    if student_id not in STUDENTS_DB or note_id not in STUDENTS_DB[student_id]["notes"]:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Protected note unavailable"
        )

    record = STUDENTS_DB[student_id]["notes"][note_id]
    aad = note_aad(student_id, note_id, "aes-gcm", "default-key")

    try:
        plaintext_bytes = open_bytes(
            backend="aes-gcm",
            algorithm="aes-gcm",
            key=FIXED_KEY,
            nonce=record["nonce"],
            ciphertext=record["ciphertext"],
            tag=record["tag"],
            aad=aad
        )
        return {"id": note_id, "text": plaintext_bytes.decode("utf-8")}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Protected note unavailable"
        )