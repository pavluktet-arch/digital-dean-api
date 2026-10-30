from typing import Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, EmailStr, Field

class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

class StudentBase(StrictModel):
    full_name: str = Field(..., min_length=5, max_length=120)
    email: EmailStr
    group_code: str = Field(..., pattern=r"^[A-ZА-ЯІЇЄa-zа-яіїє0-9]+-[0-9]{2}$")
    study_program: str = Field(..., min_length=2, max_length=100)  # Варіант 0

class StudentCreate(StudentBase):
    pass

class StudentRead(StudentBase):
    id: UUID

class StudentUpdate(StrictModel):
    full_name: Optional[str] = Field(None, min_length=5, max_length=120)
    email: Optional[EmailStr] = None
    group_code: Optional[str] = Field(None, pattern=r"^[A-ZА-ЯІЇЄa-zа-яіїє0-9]+-[0-9]{2}$")
    study_program: Optional[str] = Field(None, min_length=2, max_length=100)

    def check_has_updates(self) -> bool:
        return any(value is not None for value in self.model_dump(exclude_unset=True).values())
