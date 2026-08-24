# db.py
# Camada de conexão com o Postgres (Supabase) com fallback automático para
# SQLite local (securescope.db) caso o Postgres esteja inacessível.
#
# A classe PGConnection e a classe SQLiteConnection possuem a MESMA interface
# de conveniência do sqlite3 — conn.execute(query, params).fetchone() / .fetchall()
# — permitindo que o resto do sistema (banco.py, app.py, ia.py) funcione de
# forma transparente em qualquer um dos dois bancos.

import os
import re
import sqlite3
from pathlib import Path
import psycopg2
import psycopg2.extras
import psycopg2.pool

_pool = None
_use_sqlite = False
_sqlite_conn = None


def _is_production():
    return os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "development")).lower() == "production"


def _dsn():
    return os.environ.get("DATABASE_URL")


class SQLiteCursor:
    """Wrapper sobre cursor sqlite3 que traduz SQL Postgres (SERIAL, %s,
    information_schema) para comandos compatíveis com SQLite."""

    def __init__(self, raw_cursor):
        self._cursor = raw_cursor

    def _translate_query(self, query: str, params=None):
        q = query.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
        q = q.replace("%s", "?")
        translated_params = params or ()

        # Traduz consultas ao information_schema.columns para pragma_table_info do SQLite
        match = re.search(
            r"SELECT\s+column_name\s+FROM\s+information_schema\.columns\s+WHERE\s+table_name\s*=\s*'([^']+)'",
            q,
            re.IGNORECASE
        )
        if match:
            q = "SELECT name AS column_name FROM pragma_table_info(?)"
            translated_params = (match.group(1),)

        return q, translated_params

    def execute(self, query, params=None):
        query_sql, translated_params = self._translate_query(query, params)
        self._cursor.execute(query_sql, translated_params)
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is not None and not isinstance(row, dict):
            return dict(row)
        return row

    def fetchall(self):
        rows = self._cursor.fetchall()
        return [dict(r) if not isinstance(r, dict) else r for r in rows]

    @property
    def lastrowid(self):
        return self._cursor.lastrowid


class SQLiteConnection:
    """Wrapper sobre conexão sqlite3 que mantém a mesma interface PGConnection."""

    def __init__(self, raw_conn):
        self._conn = raw_conn

    def execute(self, query, params=None):
        cur = self._conn.cursor()
        return SQLiteCursor(cur).execute(query, params)

    def cursor(self):
        return SQLiteCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        # Mantém conexão SQLite aberta entre chamadas para evitar reconectar a cada request
        pass


def _init_db():
    global _pool, _use_sqlite, _sqlite_conn

    if os.environ.get("USE_SQLITE", "").lower() in ("1", "true", "yes"):
        if _is_production() and os.environ.get("ALLOW_SQLITE_IN_PRODUCTION", "").lower() not in ("1", "true", "yes"):
            raise RuntimeError("SQLite esta desabilitado em producao. Configure DATABASE_URL.")
        _use_sqlite = True

    if not _use_sqlite and _pool is None:
        dsn = _dsn()
        if not dsn:
            if _is_production():
                raise RuntimeError("DATABASE_URL deve ser configurada em producao.")
            print("[db] DATABASE_URL não configurada. Usando fallback SQLite local.")
            _use_sqlite = True
        else:
            min_conn = int(os.environ.get("DB_POOL_MIN", 1))
            max_conn = int(os.environ.get("DB_POOL_MAX", 10))
            if min_conn < 1 or max_conn < min_conn or max_conn > 50:
                raise RuntimeError("DB_POOL_MIN e DB_POOL_MAX possuem valores invalidos.")
            try:
                # connect_timeout=3 evita travamento longo se o Postgres/IPv6 estiver inacessível
                dsn_timeout = dsn + ("&" if "?" in dsn else "?") + "connect_timeout=3" if "connect_timeout" not in dsn else dsn
                if _is_production() and "sslmode=" not in dsn_timeout:
                    dsn_timeout += ("&" if "?" in dsn_timeout else "?") + "sslmode=require"
                _pool = psycopg2.pool.ThreadedConnectionPool(
                    minconn=min_conn,
                    maxconn=max_conn,
                    dsn=dsn_timeout,
                    cursor_factory=psycopg2.extras.RealDictCursor,
                )
                print(f"[db] Pool Postgres iniciado com sucesso (min={min_conn}, max={max_conn}).")
            except Exception as e:
                if _is_production():
                    raise RuntimeError("Nao foi possivel conectar ao Postgres em producao.") from e
                print(f"[db] Aviso: Postgres indisponível ({e}). Alternando para SQLite local...")
                _use_sqlite = True
                _pool = None

    if _use_sqlite and _sqlite_conn is None:
        db_path = Path(
            os.environ.get(
                "SQLITE_DATABASE_PATH",
                str(Path(__file__).resolve().parent / "securescope.db"),
            )
        ).resolve()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        raw_conn = sqlite3.connect(str(db_path), check_same_thread=False)
        raw_conn.row_factory = sqlite3.Row
        raw_conn.execute("PRAGMA foreign_keys = ON")
        _sqlite_conn = SQLiteConnection(raw_conn)
        print(f"[db] Banco SQLite local conectado com sucesso ({db_path.name}).")


class PGCursor:
    def __init__(self, raw_cursor):
        self._cursor = raw_cursor

    def execute(self, query, params=None):
        query_pg = query.replace("?", "%s")
        self._cursor.execute(query_pg, params or ())
        return self

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()


class PGConnection:
    def __init__(self, raw_conn, pool=None):
        self._conn = raw_conn
        self._pool = pool

    def execute(self, query, params=None):
        return PGCursor(self._conn.cursor()).execute(query, params)

    def cursor(self):
        return PGCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        if self._pool is not None:
            self._pool.putconn(self._conn)
        else:
            self._conn.close()


def get_db_connection():
    """Ponto único de conexão usado por app.py e banco.py."""
    _init_db()

    if _use_sqlite:
        return _sqlite_conn

    raw_conn = _pool.getconn()
    return PGConnection(raw_conn, _pool)
