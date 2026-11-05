from pathlib import Path
from typing import Union
from app.db.connection import open_database, write_transaction
from app.db.schema import DDL_STATEMENTS, STATUS_ROWS, ROLE_ROWS

def initialize_database(db_path: Union[str, Path]) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open_database(path) as con:
        with write_transaction(con):
            for statement in DDL_STATEMENTS:
                con.execute(statement)

            for status_id, status_name in STATUS_ROWS:
                con.execute(
                    "INSERT INTO status (id, name) VALUES (?, ?) ON CONFLICT(id) DO NOTHING",
                    (status_id, status_name),
                )

            for role_id, role_name in ROLE_ROWS:
                con.execute(
                    "INSERT INTO role (id, name) VALUES (?, ?) ON CONFLICT(id) DO NOTHING",
                    (role_id, role_name),
                )

        # Перевірка збігу ID та Назви довідників
        cur = con.execute("SELECT id, name FROM status ORDER BY id")
        fetched_statuses = [tuple(row) for row in cur.fetchall()]
        if fetched_statuses != list(STATUS_ROWS):
            raise ValueError("Status rows inconsistency after initialization")

        cur = con.execute("SELECT id, name FROM role ORDER BY id")
        fetched_roles = [tuple(row) for row in cur.fetchall()]
        if fetched_roles != list(ROLE_ROWS):
            raise ValueError("Role rows inconsistency after initialization")

if __name__ == "__main__":
    from app.db.connection import DEFAULT_DB_PATH
    initialize_database(DEFAULT_DB_PATH)