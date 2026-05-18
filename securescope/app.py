from flask import Flask, request, jsonify
from flask_cors import CORS 
import sqlite3
from datetime import datetime
import ia

app = Flask(__name__)
CORS(app)
DB_NAME = 'vulnerabilidades.db'

VALORES_STATUS = ("Aberta", "Validada", "Isolada (Circuit Breaker)")

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def registrar_historico(vulnerabilidade_id, acao, responsavel="API System"):
    conn = get_db_connection()
    data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute('''
        INSERT INTO historico (vulnerabilidade_id, acao, responsavel, data)
        VALUES (?, ?, ?, ?)
    ''', (vulnerabilidade_id, acao, responsavel, data_atual))
    conn.commit()
    conn.close()

def vulnerabilidade_existe(conn, id):
    result = conn.execute(
        "SELECT id FROM vulnerabilidades WHERE id = ?", (id,)
    ).fetchone()
    return result is not None

# ─────────────────────────────────────────────
# ROTAS PADRÃO (1 a 7)
# ─────────────────────────────────────────────

@app.route('/vulnerabilidades', methods=['GET'])
def listar_vulnerabilidades():
    conn = get_db_connection()
    vulnerabilidades = conn.execute('SELECT * FROM vulnerabilidades ORDER BY score DESC').fetchall()
    conn.close()
    return jsonify([dict(vuln) for vuln in vulnerabilidades]), 200

@app.route('/vulnerabilidades/<int:id>', methods=['GET'])
def buscar_vulnerabilidade(id):
    conn = get_db_connection()
    vuln = conn.execute('SELECT * FROM vulnerabilidades WHERE id = ?', (id,)).fetchone()
    conn.close()
    if vuln is None:
        return jsonify({"erro": f"Vulnerabilidade {id} não encontrada."}), 404
    return jsonify(dict(vuln)), 200

@app.route('/vulnerabilidades', methods=['POST'])
def adicionar_vulnerabilidade():
    dados = request.get_json()
    campos_obrigatorios = ['nome', 'impacto', 'frequencia', 'gravidade']
    for campo in campos_obrigatorios:
        if campo not in dados or dados[campo] is None:
            return jsonify({"erro": f"Campo obrigatório ausente: '{campo}'"}), 400

    nome, impacto, frequencia, gravidade = dados['nome'], dados['impacto'], dados['frequencia'], dados['gravidade']
    score = round((impacto * 0.4) + (frequencia * 0.3) + (gravidade * 0.3), 2)
    data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO vulnerabilidades (nome, impacto, frequencia, gravidade, score, status, data)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (nome, impacto, frequencia, gravidade, score, "Aberta", data_atual))
    vulnerabilidade_id = cursor.lastrowid
    conn.commit()
    conn.close()
    registrar_historico(vulnerabilidade_id, "Vulnerabilidade registrada", "Scanner Automático")
    return jsonify({"message": "Vulnerabilidade criada com sucesso!", "id": vulnerabilidade_id, "Risk Index™": score}), 201

@app.route('/vulnerabilidades/<int:id>/validar', methods=['PUT'])
def validar_vulnerabilidade(id):
    conn = get_db_connection()
    if not vulnerabilidade_existe(conn, id):
        conn.close()
        return jsonify({"erro": f"Vulnerabilidade {id} não encontrada."}), 404
    conn.execute("UPDATE vulnerabilidades SET status = 'Validada' WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    registrar_historico(id, "Marcação como Validada", "Analista Blue Team")
    return jsonify({"message": f"Vulnerabilidade {id} validada com sucesso!"}), 200

@app.route('/circuit-breaker/<int:id>', methods=['POST'])
def acionar_circuit_breaker(id):
    conn = get_db_connection()
    if not vulnerabilidade_existe(conn, id):
        conn.close()
        return jsonify({"erro": f"Vulnerabilidade {id} não encontrada."}), 404
    conn.execute("UPDATE vulnerabilidades SET status = 'Isolada (Circuit Breaker)' WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    registrar_historico(id, "Ameaça contida e isolada via Circuit Breaker", "Sistema de Defesa Ativa")
    return jsonify({"alerta": "Circuit Breaker acionado!", "message": f"Vulnerabilidade {id} isolada com sucesso."}), 200

@app.route('/relatorio', methods=['GET'])
def gerar_relatorio():
    conn = get_db_connection()
    relatorio = conn.execute('SELECT * FROM vulnerabilidades ORDER BY score DESC').fetchall()
    conn.close()
    return jsonify([dict(risco) for risco in relatorio]), 200

@app.route('/vulnerabilidades/<int:id>/historico', methods=['GET'])
def ver_historico(id):
    conn = get_db_connection()
    if not vulnerabilidade_existe(conn, id):
        conn.close()
        return jsonify({"erro": f"Vulnerabilidade {id} não encontrada."}), 404
    historico = conn.execute('SELECT * FROM historico WHERE vulnerabilidade_id = ? ORDER BY data ASC', (id,)).fetchall()
    conn.close()
    return jsonify([dict(h) for h in historico]), 200

# ─────────────────────────────────────────────
# ROTAS DE IA (Devem estar antes do app.run)
# ─────────────────────────────────────────────

@app.route('/ia/sugerir', methods=['POST'])
def sugerir_valores_ia():
    dados = request.get_json()
    nome_ameaca = dados.get('nome', '')
    sugestao = ia.analisar_nome(nome_ameaca)
    return jsonify(sugestao)

@app.route('/ia/insights', methods=['GET'])
def insights_ia():
    conn = get_db_connection()
    insights = ia.aprender_com_historico(conn)
    conn.close()
    return jsonify(insights)

# ─────────────────────────────────────────────
# INICIALIZAÇÃO
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("Iniciando a API SecureScope com IA...")
    # O app.run deve ser a ÚLTIMA coisa do ficheiro
    app.run(debug=True, port=5000)