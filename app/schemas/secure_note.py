from pydantic import BaseModel, ConfigDict, field_validator


class NoteCreate(BaseModel):
    text: str

    model_config = ConfigDict(extra="forbid")

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("Text must be a string")
        
        # Перевірка на лише пробіли
        if not value.strip():
            raise ValueError("Text cannot be empty or whitespace only")

        # Перевірка розміру у байтах UTF-8 (від 1 до 4096 байтів)
        raw_bytes = value.encode("utf-8")
        if len(raw_bytes) < 1 or len(raw_bytes) > 4096:
            raise ValueError("Text length in UTF-8 bytes must be between 1 and 4096")

        return value