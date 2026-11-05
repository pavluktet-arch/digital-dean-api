import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Union

DEFAULT_DB_PATH = Path("var/digital-dean.sqlite3")

def check_sqlite_version() -> None:
    if sqlite3.sqlite_version_info < (3, 24, 0):
        raise sqlite3.DatabaseError(
            f"SQLite version 3.24.0 or higher is required, but current is {sqlite3.sqlite_version}"
        )

@contextmanager
def open_database(db_path: Union[str, Path]) -> Generator[sqlite3.Connection, None, None]:
    check_sqlite_version()
    
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Без autocommit для сумісності з Python 3.9
    con = sqlite3.connect(str(path), timeout=5.0)
    con.row_factory = sqlite3.Row

    try:
        con.execute("PRAGMA foreign_keys = ON")
        fk_check = con.execute("PRAGMA foreign_keys").fetchone()
        if not fk_check or fk_check[0] != 1:
            raise sqlite3.DatabaseError("Failed to enable SQLite foreign_keys constraint")
        
        yield con
    finally:
        con.close()

@contextmanager
def write_transaction(con: sqlite3.Connection) -> Generator[None, None, None]:
    con.execute("BEGIN IMMEDIATE")
    try:
        yield
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise