# banco.py
import db
from datetime import datetime

VALORES_STATUS = ("Aberta", "Validada", "Isolada (Circuit Breaker)")  # corrigido

def conectar_banco(nome_banco=None):
    """Mantido por compatibilidade com o bloco __main__ deste arquivo.
    'nome_banco' não é mais usado — a conexão agora é sempre com o Postgres
    do Supabase, configurado via variável de ambiente DATABASE_URL (ver db.py)."""
    return db.get_db_connection()

def criar_tabelas(conn):
    cursor = conn.cursor()

    # M3 — Tabela de usuários para autenticação JWT.
    # Criada ANTES de vulnerabilidades porque a coluna usuario_id (adicionada
    # na migração abaixo, ver COLUNAS_IA_CONTEXTO) referencia esta tabela.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            nome TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analista' CHECK(role IN ('analista', 'admin')),
            criado_em TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilidades (
            id SERIAL PRIMARY KEY,
            nome TEXT NOT NULL,
            impacto REAL NOT NULL CHECK(impacto BETWEEN 0 AND 100),
            frequencia REAL NOT NULL CHECK(frequencia BETWEEN 0 AND 100),
            gravidade REAL NOT NULL CHECK(gravidade BETWEEN 0 AND 100),
            score REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'Aberta',
            data TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS historico (
            id SERIAL PRIMARY KEY,
            vulnerabilidade_id INTEGER,
            acao TEXT NOT NULL,
            responsavel TEXT NOT NULL,
            data TEXT NOT NULL,
            FOREIGN KEY(vulnerabilidade_id) REFERENCES vulnerabilidades(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS relatorios (
            id SERIAL PRIMARY KEY,
            data_geracao TEXT NOT NULL,
            conteudo TEXT NOT NULL
        )
    ''')

    # Scanner — Fase 1: rastreia cada execução do scanner automatizado.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            usuario_id INTEGER REFERENCES usuarios(id),
            nome_arquivo TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'em_progresso',
            total_achados INTEGER NOT NULL DEFAULT 0,
            data_inicio TEXT NOT NULL,
            data_fim TEXT
        )
    ''')

    conn.commit()
    print("Tabelas criadas/verificadas com sucesso.")

# Colunas novas usadas pelo motor de priorização/correlação da IA.
# ALTER TABLE ... ADD COLUMN é seguro em Postgres e não apaga dados existentes.
COLUNAS_IA_CONTEXTO = {
    "exposta_internet":         "INTEGER NOT NULL DEFAULT 0",
    "exploit_publico":          "INTEGER NOT NULL DEFAULT 0",
    "dados_sensiveis":          "INTEGER NOT NULL DEFAULT 0",
    "escalonamento_privilegio": "INTEGER NOT NULL DEFAULT 0",
    "ambiente_producao":        "INTEGER NOT NULL DEFAULT 0",
    "categoria":                "TEXT NOT NULL DEFAULT 'Geral/Desconhecida'",
    "prioridade":                "REAL NOT NULL DEFAULT 0",
    "explicacao":                "TEXT NOT NULL DEFAULT ''",
    "origem":                    "TEXT NOT NULL DEFAULT 'Manual/Pentest'",
    "ativo":                     "TEXT NOT NULL DEFAULT ''",
    # M1 — Modelo tripartido CVSS + EPSS + KEV (padrão de mercado: CrowdStrike, Palo Alto)
    "cvss_score":               "REAL NOT NULL DEFAULT 0.0",
    "epss_score":               "REAL NOT NULL DEFAULT 0.0",
    "cve_id":                   "TEXT NOT NULL DEFAULT ''",
    "no_kev":                   "INTEGER NOT NULL DEFAULT 0",
    # M2 — SLAs formais por nível de prioridade (NIST SP 800-53 SI-2 / ISO 27001 A.8.8)
    "sla_prazo_dias":           "INTEGER NOT NULL DEFAULT 90",
    "sla_prioridade":           "TEXT NOT NULL DEFAULT 'P3'",
    # Multi-tenant — cada vulnerabilidade passa a pertencer a um usuário.
    # Sem valor padrão fixo: registros antigos ficam com usuario_id NULL e
    # devem ser atribuídos manualmente a um usuário (ver plano de migração).
    "usuario_id":               "INTEGER REFERENCES usuarios(id)",
    # Scanner — Fase 1: rastreabilidade de achados gerados automaticamente.
    "origem_scan":              "INTEGER DEFAULT NULL",   # FK para scans.id (NULL = entrada manual)
    "confianca_ia":             "REAL NOT NULL DEFAULT 0.0",  # Reservado para consenso multi-LLM (Fase 3)
}

def migrar_colunas_contexto_ia(conn):
    """Adiciona as colunas de contexto/priorização da IA na tabela
    vulnerabilidades caso ainda não existam. Idempotente e não destrutivo:
    pode ser chamada toda vez que a aplicação sobe."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'vulnerabilidades'"
    )
    colunas_existentes = {linha["column_name"] for linha in cursor.fetchall()}

    for coluna, definicao in COLUNAS_IA_CONTEXTO.items():
        if coluna not in colunas_existentes:
            cursor.execute(f"ALTER TABLE vulnerabilidades ADD COLUMN {coluna} {definicao}")
            print(f"[migração] Coluna '{coluna}' adicionada em vulnerabilidades.")

    # M2 — Tabela de SLAs formais: rastreia status em tempo real por vulnerabilidade.
    # Permite gerar evidência auditável exigida por ISO 27001 A.8.8 e NIST CA-7.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sla_vulnerabilidades (
            id SERIAL PRIMARY KEY,
            vulnerabilidade_id INTEGER NOT NULL,
            nivel_sla TEXT NOT NULL,
            prazo_dias INTEGER NOT NULL,
            data_inicio TEXT NOT NULL,
            data_prazo TEXT NOT NULL,
            data_resolucao TEXT,
            status_sla TEXT DEFAULT 'Em Prazo',
            FOREIGN KEY(vulnerabilidade_id) REFERENCES vulnerabilidades(id)
        )
    ''')

    # Scanner — Fase 1: garantir que a tabela scans existe (idempotente).
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            usuario_id INTEGER REFERENCES usuarios(id),
            nome_arquivo TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'em_progresso',
            total_achados INTEGER NOT NULL DEFAULT 0,
            data_inicio TEXT NOT NULL,
            data_fim TEXT
        )
    ''')

    # M2 — Trilha de auditoria enriquecida na tabela historico
    # Adiciona rastreabilidade de origem e diff de dados (NIST SP 800-53 SI-2(2) / ISO 27001 A.8.8).
    # ALTER TABLE é idempotente em Postgres — seguro em bancos já existentes.
    cursor.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'historico'"
    )
    colunas_historico = {linha["column_name"] for linha in cursor.fetchall()}

    colunas_audit = {
        "ip_origem":       "TEXT NOT NULL DEFAULT ''",
        "dados_anteriores": "TEXT NOT NULL DEFAULT ''",
        "dados_novos":     "TEXT NOT NULL DEFAULT ''",
    }
    for coluna, definicao in colunas_audit.items():
        if coluna not in colunas_historico:
            cursor.execute(f"ALTER TABLE historico ADD COLUMN {coluna} {definicao}")
            print(f"[migração] Coluna '{coluna}' adicionada em historico.")

    conn.commit()

def calcular_score(impacto, frequencia, gravidade):
    return round((impacto * 0.4) + (frequencia * 0.3) + (gravidade * 0.3), 2)

def inserir_vulnerabilidade(conn, nome, impacto, frequencia, gravidade, status="Aberta"):
    for campo, valor in [("impacto", impacto), ("frequencia", frequencia), ("gravidade", gravidade)]:
        if not (0 <= valor <= 100):
            raise ValueError(f"O campo '{campo}' deve estar entre 0 e 100. Recebido: {valor}")

    if status not in VALORES_STATUS:
        raise ValueError(f"Status inválido: '{status}'. Use: {VALORES_STATUS}")

    cursor = conn.cursor()
    score = calcular_score(impacto, frequencia, gravidade)
    data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute('''
        INSERT INTO vulnerabilidades (nome, impacto, frequencia, gravidade, score, status, data)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    ''', (nome, impacto, frequencia, gravidade, score, status, data_atual))

    vulnerabilidade_id = cursor.fetchone()["id"]
    conn.commit()

    print(f"Vulnerabilidade '{nome}' registrada!")
    print(f"Risk Index™ Calculado: {score:.2f}\n")

    return vulnerabilidade_id

def inserir_historico(conn, vulnerabilidade_id, acao, responsavel):
    cursor = conn.cursor()
    data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute('''
        INSERT INTO historico (vulnerabilidade_id, acao, responsavel, data)
        VALUES (%s, %s, %s, %s)
    ''', (vulnerabilidade_id, acao, responsavel, data_atual))

    conn.commit()

def listar_vulnerabilidades(conn, ordenar_por_score=True):
    cursor = conn.cursor()
    if ordenar_por_score:
        cursor.execute("SELECT * FROM vulnerabilidades ORDER BY score DESC")
    else:
        cursor.execute("SELECT * FROM vulnerabilidades")
    return cursor.fetchall()

if __name__ == '__main__':
    # Este bloco só roda se você executar "python banco.py" diretamente.
    # Ele NÃO insere mais dados de teste a cada execução — só garante que
    # o schema (tabelas + colunas da IA) existe. Rodar isso é opcional:
    # o app.py já faz a mesma coisa sozinho toda vez que o servidor sobe.
    conexao = conectar_banco()
    criar_tabelas(conexao)
    migrar_colunas_contexto_ia(conexao)

    total = conexao.execute("SELECT COUNT(*) FROM vulnerabilidades").fetchone()["count"]
    print(f"Banco pronto (Postgres/Supabase). {total} vulnerabilidade(s) já cadastrada(s).")
    print("Para usar o sistema, rode: python app.py")

    conexao.close()
