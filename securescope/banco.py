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
    conexao = conectar_banco()
    criar_tabelas(conexao)

    print("Inserindo dados de teste...")
    id_vuln = inserir_vulnerabilidade(
        conexao,
        nome="Falha de Autenticação na API",
        impacto=85,
        frequencia=40,
        gravidade=90
    )

    inserir_historico(
        conexao,
        vulnerabilidade_id=id_vuln,
        acao="Identificação e registro inicial",
        responsavel="Equipe Blue Team"
    )

    print("Vulnerabilidades no banco:")
    for v in listar_vulnerabilidades(conexao):
        print(v)

    conexao.close()