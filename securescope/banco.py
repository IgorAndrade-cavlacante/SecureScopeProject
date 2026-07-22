# banco.py
import sqlite3
from datetime import datetime

VALORES_STATUS = ("Aberta", "Validada", "Isolada (Circuit Breaker)")  # corrigido

def conectar_banco(nome_banco="vulnerabilidades.db"):
    try:
        conn = sqlite3.connect(nome_banco)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    except sqlite3.Error as e:
        raise RuntimeError(f"Erro ao conectar ao banco: {e}")

def criar_tabelas(conn):
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilidades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerabilidade_id INTEGER,
            acao TEXT NOT NULL,
            responsavel TEXT NOT NULL,
            data TEXT NOT NULL,
            FOREIGN KEY(vulnerabilidade_id) REFERENCES vulnerabilidades(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS relatorios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data_geracao TEXT NOT NULL,
            conteudo TEXT NOT NULL
        )
    ''')

    conn.commit()
    print("Tabelas criadas/verificadas com sucesso.")

# Colunas novas usadas pelo motor de priorização/correlação da IA.
# ALTER TABLE ... ADD COLUMN é seguro em SQLite e não apaga dados existentes.
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
}

def migrar_colunas_contexto_ia(conn):
    """Adiciona as colunas de contexto/priorização da IA na tabela
    vulnerabilidades caso ainda não existam. Idempotente e não destrutivo:
    pode ser chamada toda vez que a aplicação sobe."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(vulnerabilidades)")
    colunas_existentes = {linha[1] for linha in cursor.fetchall()}

    for coluna, definicao in COLUNAS_IA_CONTEXTO.items():
        if coluna not in colunas_existentes:
            cursor.execute(f"ALTER TABLE vulnerabilidades ADD COLUMN {coluna} {definicao}")
            print(f"[migração] Coluna '{coluna}' adicionada em vulnerabilidades.")

    # M2 — Tabela de SLAs formais: rastreia status em tempo real por vulnerabilidade.
    # Permite gerar evidência auditável exigida por ISO 27001 A.8.8 e NIST CA-7.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sla_vulnerabilidades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (nome, impacto, frequencia, gravidade, score, status, data_atual))

    vulnerabilidade_id = cursor.lastrowid
    conn.commit()

    print(f"Vulnerabilidade '{nome}' registrada!")
    print(f"Risk Index™ Calculado: {score:.2f}\n")

    return vulnerabilidade_id

def inserir_historico(conn, vulnerabilidade_id, acao, responsavel):
    cursor = conn.cursor()
    data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute('''
        INSERT INTO historico (vulnerabilidade_id, acao, responsavel, data)
        VALUES (?, ?, ?, ?)
    ''', (vulnerabilidade_id, acao, responsavel, data_atual))

    conn.commit()

def listar_vulnerabilidades(conn, ordenar_por_score=True):
    cursor = conn.cursor()
    ordem = "ORDER BY score DESC" if ordenar_por_score else ""
    cursor.execute(f"SELECT * FROM vulnerabilidades {ordem}")
    return cursor.fetchall()

if __name__ == '__main__':
    # Este bloco só roda se você executar "python banco.py" diretamente.
    # Ele NÃO insere mais dados de teste a cada execução — só garante que
    # o schema (tabelas + colunas da IA) existe. Rodar isso é opcional:
    # o app.py já faz a mesma coisa sozinho toda vez que o servidor sobe.
    conexao = conectar_banco()
    criar_tabelas(conexao)
    migrar_colunas_contexto_ia(conexao)

    total = conexao.execute("SELECT COUNT(*) FROM vulnerabilidades").fetchone()[0]
    print(f"Banco pronto. {total} vulnerabilidade(s) já cadastrada(s).")
    print("Para usar o sistema, rode: python app.py")

    conexao.close()