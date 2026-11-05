import sqlite3
from typing import Optional
from app.db.connection import open_database, write_transaction
from app.schemas.user_account import UserCreate, UserPublic
from app.security.passwords import make_password_record, verify_password

class UserReferenced(Exception):
    """Виникає при спробі видалити користувача, на якого посилаються оцінки у таблиці grade."""
    pass

class UserConflict(Exception):
    """Виникає при спробі створити користувача з існуючим login або email."""
    pass

class UserRepository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)

    def register_user(self, user_create: UserCreate) -> UserPublic:
        """Реєструє нового користувача, обчислює PBKDF2-пароль та зберігає у БД."""
        pwd_record, salt_hex = make_password_record(user_create.password)
        status_id = user_create.status_id if user_create.status_id is not None else 0
        canonical_email = user_create.email.strip().casefold()

        with open_database(self.db_path) as con:
            try:
                with write_transaction(con):
                    cursor = con.execute(
                        """
                        INSERT INTO "user" (name, email, login, password, salt, status_id)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            user_create.name,
                            canonical_email,
                            user_create.login,
                            pwd_record,
                            salt_hex,
                            status_id,
                        ),
                    )
                    user_id = cursor.lastrowid
            except sqlite3.IntegrityError as e:
                raise UserConflict("user already exists") from e

            return UserPublic(
                id=user_id,
                name=user_create.name,
                email=canonical_email,
                login=user_create.login,
                status_id=status_id,
            )

    def get_by_id(self, user_id: int) -> Optional[UserPublic]:
        """Отримує обліковий запис користувача за його ID (без парольних даних)."""
        with open_database(self.db_path) as con:
            row = con.execute(
                'SELECT id, name, email, login, status_id FROM "user" WHERE id = ?',
                (user_id,),
            ).fetchone()
            
            if not row:
                return None
            return UserPublic(
                id=row["id"],
                name=row["name"],
                email=row["email"],
                login=row["login"],
                status_id=row["status_id"],
            )

    def delete_user(self, user_id: int) -> bool:
        """
        Фізично видаляє користувача.
        Якщо користувач має прив'язані оцінки у grade, викидає UserReferenced.
        """
        with open_database(self.db_path) as con:
            with write_transaction(con):
                user_row = con.execute('SELECT id FROM "user" WHERE id = ?', (user_id,)).fetchone()
                if not user_row:
                    return False

                # Перевірка зовнішніх ключів у таблиці grade (student_id або teacher_id)
                grade_ref = con.execute(
                    "SELECT 1 FROM grade WHERE student_id = ? OR teacher_id = ? LIMIT 1",
                    (user_id, user_id),
                ).fetchone()

                if grade_ref:
                    raise UserReferenced("user has grade references")

                # Видалення ролей (CASCADE) та самого користувача
                con.execute("DELETE FROM user_role WHERE user_id = ?", (user_id,))
                con.execute('DELETE FROM "user" WHERE id = ?', (user_id,))
                return True

    def block_user(self, user_id: int) -> Optional[UserPublic]:
        """Установлює status_id = 2 (blocked) для заповненого ID."""
        with open_database(self.db_path) as con:
            with write_transaction(con):
                user = self.get_by_id(user_id)
                if not user:
                    return None

                con.execute('UPDATE "user" SET status_id = 2 WHERE id = ?', (user_id,))
                user.status_id = 2
                return user

    def login(self, login: str, password_candidate: str) -> bool:
        """Перевіряє правильність пароля та статус активності акаунта (status_id == 1)."""
        with open_database(self.db_path) as con:
            row = con.execute(
                'SELECT password, salt, status_id FROM "user" WHERE login = ?',
                (login,),
            ).fetchone()

            if not row or row["status_id"] != 1:
                return False

            return verify_password(password_candidate, row["password"], row["salt"])

    # Синонім для сумісності з API-роутером
    authenticate_user = login