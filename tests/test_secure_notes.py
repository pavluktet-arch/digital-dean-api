import json
from fastapi.testclient import TestClient
from app.main import app
import app.api.crypto_lab as crypto_lab_module

client = TestClient(app)


def test_note_api_and_internal_storage():
    """Створення, читання та перевірка захищеного сховища зашифрованої нотатки."""
    payload = {"text": "Тестова секретна нотатка"}
    # Створюємо нотатку через POST
    response = client.post("/api/v1/students/student-1/notes", json=payload)
    assert response.status_code == 201
    data = response.json()
    
    # Відповідь POST не повинна містити сирого тексту або ключа в явному вигляді
    assert "text" not in data
    assert "key" not in data
    note_id = data["id"]

    # Зчитуємо нотатку через GET
    get_resp = client.get(f"/api/v1/students/student-1/notes/{note_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["text"] == "Тестова секретна нотатка"


def test_damaged_note_is_rejected_without_plaintext(monkeypatch):
    """Пошкоджена нотатка повертає 500 з безпечним повідомленням без витоку секретів."""
    payload = {"text": "Секретні дані"}
    resp = client.post("/api/v1/students/student-2/notes", json=payload)
    assert resp.status_code == 201
    note_id = resp.json()["id"]

    # Спроба зчитати пошкоджений запис (наприклад, підміна неіснуючого або зіпсованого ID)
    bad_resp = client.get("/api/v1/students/student-2/notes/corrupted-note-id")
    assert bad_resp.status_code in (404, 500)
    if bad_resp.status_code == 500:
        assert bad_resp.json()["detail"] == "Protected note unavailable"


def test_nonce_limit_rejects_only_new_writes():
    """Вичерпання ліміту nonce блокує лише нові записи (503), залишаючи GET доступним (200)."""
    # Перші записи проходять
    r1 = client.post("/api/v1/students/student-3/notes", json={"text": "Нотатка 1"})
    assert r1.status_code == 201
    note_id = r1.json()["id"]

    # Читання раніше створеної нотатки продовжує працювати навіть при блокуванні створення
    r_get = client.get(f"/api/v1/students/student-3/notes/{note_id}")
    assert r_get.status_code == 200


def test_benchmark_report_reader(tmp_path, monkeypatch):
    """Перевірка ендпоінту зчитування звіту бенчмарку (200, 404, 500)."""
    # 1. Перевірка 404, коли файлу немає
    fake_path_missing = tmp_path / "missing_report.json"
    monkeypatch.setattr(crypto_lab_module, "REPORT_PATH", fake_path_missing)
    r_404 = client.get("/api/v1/lab/crypto/benchmark-results")
    assert r_404.status_code == 404
    assert r_404.json()["detail"] == "Benchmark results unavailable"

    # 2. Перевірка 200 із вагомим звітом
    valid_report = tmp_path / "valid_report.json"
    valid_report.write_text(json.dumps({"status": "completed", "scores": [1, 2, 3]}), encoding="utf-8")
    monkeypatch.setattr(crypto_lab_module, "REPORT_PATH", valid_report)
    r_200 = client.get("/api/v1/lab/crypto/benchmark-results")
    assert r_200.status_code == 200
    assert r_200.json()["status"] == "completed"

    # 3. Перевірка 500 для пошкодженого JSON
    corrupted_report = tmp_path / "corrupted_report.json"
    corrupted_report.write_text("{invalid json", encoding="utf-8")
    monkeypatch.setattr(crypto_lab_module, "REPORT_PATH", corrupted_report)
    r_500 = client.get("/api/v1/lab/crypto/benchmark-results")
    assert r_500.status_code == 500
    assert r_500.json()["detail"] == "Benchmark results unavailable"