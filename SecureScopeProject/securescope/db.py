# db.py
# Camada de conexão com o Postgres (Supabase). Substitui o antigo uso direto
# de sqlite3 em banco.py/app.py/ia.py.
#
# A classe PGConnection existe para que o resto do código (banco.py, app.py,
# ia.py) continue funcionando com a MESMA sintaxe de conveniência do sqlite3
# — conn.execute(query, params).fetchone() / .fetchall() — sem precisar
# reescrever cada chamada para "cursor = conn.cursor(); cursor.execute(...)".
#
# Configuração (variável de ambiente obrigatória):
#   DATABASE_URL = "postgresql://postgres:<senha>@<host>:5432/postgres"
#   (essa string vem do painel do Supabase em Project Settings > Database >
#   Connection string > URI)
#
# Connection Pooling:
#   Usa psycopg2.pool.ThreadedConnectionPool para reutilizar conexões
#   em vez de abrir/fechar uma nova a cada request. Configurável via:
#     DB_POOL_MIN (padrão: 1) — conexões mínimas mantidas abertas
#     DB_POOL_MAX (padrão: 10) — conexões máximas simultâneas

import os
import psycopg2
import psycopg2.extras
import psycopg2.pool

# Pool global — inicializado sob demanda na primeira chamada a get_db_connection().
_pool = None


def _dsn():
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError(
            "DATABASE_URL não configurada. Defina a variável de ambiente "
            "com a connection string do Postgres do Supabase "
            "(Project Settings > Database > Connection string > URI)."
        )
    return dsn


def _get_pool():
    """Inicializa o pool de conexões na primeira chamada (lazy init).
    Thread-safe graças ao ThreadedConnectionPool do psycopg2."""
    global _pool
    if _pool is None:
        min_conn = int(os.environ.get("DB_POOL_MIN", 1))
        max_conn = int(os.environ.get("DB_POOL_MAX", 10))
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=min_conn,
            maxconn=max_conn,
            dsn=_dsn(),
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        print(f"[db] Pool de conexões iniciado (min={min_conn}, max={max_conn}).")
    return _pool


class PGCursor:
    """Wrapper fino sobre o cursor psycopg2 que traduz os placeholders
    '?' (estilo sqlite3, usado em todo o código de ia.py/app.py/banco.py)
    para '%s' (estilo psycopg2), assim nenhuma query precisou ser reescrita."""

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

    @property
    def lastrowid(self):
        # psycopg2 não tem lastrowid — quem precisar do id gerado deve usar
        # "RETURNING id" na query e ler via fetchone()["id"].
        raise AttributeError(
            "psycopg2 não suporta lastrowid; use 'RETURNING id' na query "
            "e leia o id via fetchone()['id']."
        )


class PGConnection:
    """Wrapper fino sobre a conexão psycopg2 para preservar a API de
    conveniência do sqlite3 usada no restante do projeto.

    Quando criado via pool (padrão), close() devolve a conexão ao pool
    em vez de destruí-la — permitindo reutilização entre requests."""

    def __init__(self, raw_conn, pool=None):
        self._conn = raw_conn
        self._pool = pool

    def execute(self, query, params=None):
        """Equivalente ao conn.execute(...) do sqlite3: traduz os
        placeholders '?' para '%s' (padrão do psycopg2) e devolve o cursor,
        para permitir encadear .fetchone()/.fetchall() como antes."""
        return PGCursor(self._conn.cursor()).execute(query, params)

    def cursor(self):
        return PGCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        """Devolve a conexão ao pool (se houver) em vez de fechá-la.
        Isso permite reutilizar conexões entre requests, evitando o
        overhead de abrir/fechar conexão TCP a cada chamada."""
        if self._pool is not None:
            self._pool.putconn(self._conn)
        else:
            self._conn.close()


def get_db_connection():
    """Ponto único de conexão usado por app.py e banco.py.
    Obtém uma conexão do pool (reutilizada) em vez de criar uma nova."""
    pool = _get_pool()
    raw_conn = pool.getconn()
    return PGConnection(raw_conn, pool)
