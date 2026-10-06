"""Migrações aditivas para colaboração e execuções persistentes."""


def migrar(conn):
    additions = {
        'usuarios': {'alerta_sla_dias': 'INTEGER NOT NULL DEFAULT 3'},
        'vulnerabilidades': {
            'equipe_id': 'INTEGER REFERENCES equipes(id)',
            'responsavel_id': 'INTEGER REFERENCES usuarios(id)',
            'corrigida_em': 'TEXT',
            'fingerprint': 'TEXT',
        },
        'scans': {
            'tipo': "TEXT NOT NULL DEFAULT ''",
            'alvo': "TEXT NOT NULL DEFAULT ''",
            'progresso': 'INTEGER NOT NULL DEFAULT 0',
            'etapa': "TEXT NOT NULL DEFAULT ''",
            'erro': "TEXT NOT NULL DEFAULT ''",
            'payload': 'TEXT',
            'resultado': 'TEXT',
            'modo_scan': "TEXT NOT NULL DEFAULT ''",
            'token_execucao': 'TEXT',
            'iniciado_worker_em': 'TEXT',
        },
    }
    conn.execute('''CREATE TABLE IF NOT EXISTS equipes (
        id SERIAL PRIMARY KEY, nome TEXT NOT NULL,
        dono_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
        criado_em TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS equipe_membros (
        equipe_id INTEGER NOT NULL REFERENCES equipes(id) ON DELETE CASCADE,
        usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
        papel TEXT NOT NULL CHECK(papel IN ('gestor','analista','leitor')),
        PRIMARY KEY(equipe_id, usuario_id))''')
    for table, columns in additions.items():
        existing = {r['column_name'] for r in conn.execute(
            f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table}'"
        ).fetchall()}
        for name, definition in columns.items():
            if name not in existing:
                conn.execute(f'ALTER TABLE {table} ADD COLUMN {name} {definition}')
    conn.execute('''CREATE UNIQUE INDEX IF NOT EXISTS vuln_fingerprint_usuario
        ON vulnerabilidades(usuario_id, fingerprint)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS scan_achados (
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        vulnerabilidade_id INTEGER NOT NULL REFERENCES vulnerabilidades(id) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL, snapshot TEXT NOT NULL,
        PRIMARY KEY(scan_id, fingerprint))''')
    conn.execute('''CREATE TABLE IF NOT EXISTS comentarios (
        id SERIAL PRIMARY KEY,
        vulnerabilidade_id INTEGER NOT NULL REFERENCES vulnerabilidades(id) ON DELETE CASCADE,
        usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
        texto TEXT NOT NULL, criado_em TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS alertas_lidos (
        usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
        vulnerabilidade_id INTEGER NOT NULL REFERENCES vulnerabilidades(id) ON DELETE CASCADE,
        chave TEXT NOT NULL, lido_em TEXT NOT NULL,
        PRIMARY KEY(usuario_id, vulnerabilidade_id, chave))''')
    conn.execute('CREATE INDEX IF NOT EXISTS scans_fila ON scans(status, id)')
    conn.execute('CREATE INDEX IF NOT EXISTS vulnerabilidades_equipe ON vulnerabilidades(equipe_id)')
    conn.commit()
