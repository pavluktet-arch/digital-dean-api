import pytest
from fastapi.testclient import TestClient
from uuid import uuid4
from app.main import app
from app.api.students import db

client = TestClient(app)

@pytest.fixture(autouse=True)
def clear_db():
    db.clear()

def test_health_check():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}

def test_create_student_success():
    payload = {
        "full_name": "Олена Коваль",
        "email": "olena.koval@example.com",
        "group_code": "КН-31",
        "study_program": "Комп'ютерні науки"
    }
    res = client.post("/api/v1/students", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert "id" in data
    assert data["study_program"] == "Комп'ютерні науки"

def test_create_student_invalid_email():
    payload = {
        "full_name": "Олена Коваль",
        "email": "invalid-email",
        "group_code": "КН-31",
        "study_program": "Комп'ютерні науки"
    }
    res = client.post("/api/v1/students", json=payload)
    assert res.status_code == 422

def test_get_students_list():
    payload = {
        "full_name": "Іван Петренко",
        "email": "ivan@example.com",
        "group_code": "КН-31",
        "study_program": "Інженерія ПЗ"
    }
    client.post("/api/v1/students", json=payload)
    res = client.get("/api/v1/students")
    assert res.status_code == 200
    assert len(res.json()) == 1

def test_get_student_by_id_success():
    payload = {
        "full_name": "Марія Бондар",
        "email": "maria@example.com",
        "group_code": "КН-32",
        "study_program": "Кібербезпека"
    }
    created = client.post("/api/v1/students", json=payload).json()
    res = client.get(f"/api/v1/students/{created['id']}")
    assert res.status_code == 200

def test_get_student_by_id_not_found():
    res = client.get(f"/api/v1/students/{uuid4()}")
    assert res.status_code == 404

def test_patch_student_success():
    payload = {
        "full_name": "Петро Сидоренко",
        "email": "petro@example.com",
        "group_code": "КН-31",
        "study_program": "Комп'ютерні науки"
    }
    created = client.post("/api/v1/students", json=payload).json()
    res = client.patch(f"/api/v1/students/{created['id']}", json={"group_code": "КН-32"})
    assert res.status_code == 200
    assert res.json()["group_code"] == "КН-32"

def test_patch_student_unknown_field():
    payload = {
        "full_name": "Тарас Шевченко",
        "email": "taras@example.com",
        "group_code": "КН-31",
        "study_program": "Комп'ютерні науки"
    }
    created = client.post("/api/v1/students", json=payload).json()
    res = client.patch(f"/api/v1/students/{created['id']}", json={"is_admin": True})
    assert res.status_code == 422

def test_filter_by_study_program():
    client.post("/api/v1/students", json={
        "full_name": "Студент 1", "email": "s1@example.com", "group_code": "КН-31", "study_program": "Кібербезпека"
    })
    res = client.get("/api/v1/students?study_program=Кібербезпека")
    assert res.status_code == 200
    assert len(res.json()) == 1

def test_study_program_min_length_valid():
    res = client.post("/api/v1/students", json={
        "full_name": "Тест Мін", "email": "min@example.com", "group_code": "КН-31", "study_program": "ІТ"
    })
    assert res.status_code == 201

def test_study_program_too_short_invalid():
    res = client.post("/api/v1/students", json={
        "full_name": "Тест Короткий", "email": "short@example.com", "group_code": "КН-31", "study_program": "А"
    })
    assert res.status_code == 422
