def note_aad(student_id: str, note_id: str, algorithm: str, key_id: str) -> bytes:
    """Канонічна серіалізація додаткових аутентифікаційних даних (AAD) з версією 1."""
    canonical_str = f"v=1;student={student_id};note={note_id};alg={algorithm};key={key_id}"
    return canonical_str.encode("utf-8")