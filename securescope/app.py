from flask import Flask, request, jsonify
from flask_cors import CORS 
import sqlite3
from datetime import datetime
import ia
import banco

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

def preparar_banco_para_ia():
    """Garante as colunas novas do motor de IA e classifica/prioriza
    registros antigos que ainda não passaram por essa análise. Roda uma
    vez, na subida da aplicação — não é destrutivo."""
    conn = get_db_connection()
    banco.migrar_colunas_contexto_ia(conn)

    pendentes = conn.execute(
        "SELECT id, nome, score FROM vulnerabilidades "
        "WHERE categoria = 'Geral/Desconhecida' OR categoria IS NULL"
    ).fetchall()

    for linha in pendentes:
        categoria = ia.detectar_categoria(linha["nome"])
        prioridade, _ = ia.calcular_prioridade(linha["score"], {})
        conn.execute(
            "UPDATE vulnerabilidades SET categoria = ?, prioridade = ? WHERE id = ?",
            (categoria, prioridade, linha["id"])
        )

    if pendentes:
        conn.commit()
        print(f"[migração] {len(pendentes)} vulnerabilidade(s) antiga(s) classificada(s) pela IA.")

    conn.close()

preparar_banco_para_ia()

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

    # Fatores de contexto marcados pelo analista no formulário (checkboxes).
    fatores = {
        "exposta_internet":         bool(dados.get("exposta_internet", False)),
        "exploit_publico":          bool(dados.get("exploit_publico", False)),
        "dados_sensiveis":          bool(dados.get("dados_sensiveis", False)),
        "escalonamento_privilegio": bool(dados.get("escalonamento_privilegio", False)),
        "ambiente_producao":        bool(dados.get("ambiente_producao", False)),
    }

    # Origem do achado (qual "ferramenta" teria detectado isso) e o ativo
    # afetado — simulam os pilares de Asset Discovery e ingestão multi-fonte.
    origem = dados.get("origem") or "Manual/Pentest"
    if origem not in ia.ORIGENS_VALIDAS:
        origem = "Manual/Pentest"
    ativo = (dados.get("ativo") or "").strip()

    categoria = ia.detectar_categoria(nome)

    conn = get_db_connection()

    # Correlação de risco: por categoria repetida E por ativo concentrando risco.
    correlacao_categoria = ia.correlacionar_historico(conn, categoria)
    correlacao_ativo = ia.correlacionar_por_ativo(conn, ativo)

    # Motor de priorização: Risk Index™ base + fatores de contexto reais.
    prioridade, explicacao_fatores = ia.calcular_prioridade(score, fatores)
    if correlacao_categoria["alerta"]:
        prioridade = round(min(prioridade + 5, 100.0), 1)
        explicacao_fatores.append(f"+5 pontos — {correlacao_categoria['mensagem']}")
    if correlacao_ativo["alerta"]:
        prioridade = round(min(prioridade + 3, 100.0), 1)
        explicacao_fatores.append(f"+3 pontos — {correlacao_ativo['mensagem']}")

    explicacao_texto = " | ".join(explicacao_fatores)

    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO vulnerabilidades
            (nome, impacto, frequencia, gravidade, score, status, data,
             exposta_internet, exploit_publico, dados_sensiveis,
             escalonamento_privilegio, ambiente_producao,
             categoria, prioridade, explicacao, origem, ativo)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        nome, impacto, frequencia, gravidade, score, "Aberta", data_atual,
        int(fatores["exposta_internet"]), int(fatores["exploit_publico"]),
        int(fatores["dados_sensiveis"]), int(fatores["escalonamento_privilegio"]),
        int(fatores["ambiente_producao"]), categoria, prioridade, explicacao_texto,
        origem, ativo
    ))
    vulnerabilidade_id = cursor.lastrowid
    conn.commit()
    conn.close()
    registrar_historico(vulnerabilidade_id, "Vulnerabilidade registrada", "Scanner Automático")

    return jsonify({
        "message": "Vulnerabilidade criada com sucesso!",
        "id": vulnerabilidade_id,
        "Risk Index™": score,
        "categoria": categoria,
        "prioridade": prioridade,
        "explicacao": explicacao_fatores,
        "guia_remediacao": ia.gerar_guia_remediacao(categoria),
        "correlacao_categoria": correlacao_categoria,
        "correlacao_ativo": correlacao_ativo,
        "dread": ia.calcular_dread(gravidade, frequencia, fatores)
    }), 201

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

@app.route('/ia/origens', methods=['GET'])
def listar_origens():
    return jsonify(list(ia.ORIGENS_VALIDAS))

@app.route('/ia/sugerir', methods=['POST'])
def sugerir_valores_ia():
    dados = request.get_json()
    nome_ameaca = dados.get('nome', '')
    sugestao = ia.analisar_nome(nome_ameaca)
    sugestao['perguntas'] = ia.gerar_perguntas_contexto(sugestao.get('categoria', 'Geral/Desconhecida'))
    return jsonify(sugestao)

@app.route('/ia/insights', methods=['GET'])
def insights_ia():
    conn = get_db_connection()
    insights = ia.aprender_com_historico(conn)
    conn.close()
    return jsonify(insights)

@app.route('/vulnerabilidades/<int:id>/analise', methods=['GET'])
def analise_vulnerabilidade(id):
    conn = get_db_connection()
    vuln = conn.execute('SELECT * FROM vulnerabilidades WHERE id = ?', (id,)).fetchone()
    conn.close()

    if vuln is None:
        return jsonify({"erro": f"Vulnerabilidade {id} não encontrada."}), 404

    vuln = dict(vuln)
    categoria = vuln.get("categoria") or "Geral/Desconhecida"
    explicacao_texto = vuln.get("explicacao") or ""

    fatores = {
        "exposta_internet": bool(vuln.get("exposta_internet")),
        "exploit_publico": bool(vuln.get("exploit_publico")),
        "dados_sensiveis": bool(vuln.get("dados_sensiveis")),
        "escalonamento_privilegio": bool(vuln.get("escalonamento_privilegio")),
        "ambiente_producao": bool(vuln.get("ambiente_producao")),
    }

    return jsonify({
        "id": vuln["id"],
        "nome": vuln["nome"],
        "categoria": categoria,
        "origem": vuln.get("origem") or "Manual/Pentest",
        "ativo": vuln.get("ativo") or "(não informado)",
        "risk_index_base": vuln["score"],
        "prioridade": vuln.get("prioridade", vuln["score"]),
        "explicacao": explicacao_texto.split(" | ") if explicacao_texto else [],
        "guia_remediacao": ia.gerar_guia_remediacao(categoria),
        "fatores": fatores,
        "dread": ia.calcular_dread(vuln["gravidade"], vuln["frequencia"], fatores)
    }), 200

# ─────────────────────────────────────────────
# INICIALIZAÇÃO
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("Iniciando a API SecureScope com IA...")
    # O app.run deve ser a ÚLTIMA coisa do ficheiro
    app.run(debug=True, port=5000)