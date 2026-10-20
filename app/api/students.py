from typing import List, Optional
from uuid import UUID, uuid4
from fastapi import APIRouter, HTTPException, Query, status
from app.schemas.student import StudentCreate, StudentRead, StudentUpdate

router = APIRouter(prefix="/api/v1/students", tags=["students"])

db: dict[UUID, StudentRead] = {}

@router.post("", response_model=StudentRead, status_code=status.HTTP_201_CREATED)
def create_student(student_in: StudentCreate):
    for student in db.values():
        if student.email.lower() == student_in.email.lower():
            raise HTTPException(status_code=409, detail="Email вже існує")
    
    student_id = uuid4()
    student_read = StudentRead(id=student_id, **student_in.model_dump())
    db[student_id] = student_read
    return student_read

@router.get("", response_model=List[StudentRead])
def get_students(study_program: Optional[str] = Query(None)):
    students = list(db.values())
    if study_program:
        students = [s for s in students if study_program.lower() in s.study_program.lower()]
    return students

@router.get("/{student_id}", response_model=StudentRead)
def get_student_by_id(student_id: UUID):
    if student_id not in db:
        raise HTTPException(status_code=404, detail="Студента не знайдено")
    return db[student_id]

@router.patch("/{student_id}", response_model=StudentRead)
def update_student(student_id: UUID, update_in: StudentUpdate):
    if student_id not in db:
        raise HTTPException(status_code=404, detail="Студента не знайдено")
    if not update_in.check_has_updates():
        raise HTTPException(status_code=422, detail="Порожнє оновлення")
    
    existing = db[student_id].model_dump()
    update_data = update_in.model_dump(exclude_unset=True)
    
    existing.update(update_data)
    updated_student = StudentRead(**existing)
    db[student_id] = updated_student
    return updated_student
