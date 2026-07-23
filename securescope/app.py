from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime, timedelta
import ia
import banco

app = Flask(__name__)

# M3 — JWT: chave secreta e expiração de token (1 dia)
app.config["JWT_SECRET_KEY"] = "securescope-jwt-secret-2024-mude-em-producao"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
jwt = JWTManager(app)

# M3 — CORS aberto para desenvolvimento
CORS(app, resources={r"/*": {"origins": "*"}})

DB_NAME = 'vulnerabilidades.db'

VALORES_STATUS = ("Aberta", "Validada", "Isolada (Circuit Breaker)")

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def registrar_historico(vulnerabilidade_id, acao, responsavel=None):
    """M3 — responsavel vem do JWT quando disponível, senão usa 'Sistema'."""
    if responsavel is None:
        try:
            responsavel = get_jwt_identity() or "Sistema"
        except RuntimeError:
            responsavel = "Sistema"
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
    banco.criar_tabelas(conn)
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
# M3 — AUTENTICAÇÃO (JWT)
# ─────────────────────────────────────────────

@app.route('/auth/register', methods=['POST'])
def registrar_usuario():
    """Cria um novo usuário. Em produção, esta rota deveria ser protegida
    por um admin. Por ora, é aberta para facilitar o primeiro acesso."""
    dados = request.get_json()
    for campo in ['email', 'senha', 'nome']:
        if not dados or not dados.get(campo):
            return jsonify({"erro": f"Campo obrigatório ausente: '{campo}'"}), 400

    email = dados['email'].strip().lower()
    senha_hash = generate_password_hash(dados['senha'])
    nome = dados['nome'].strip()
    role = dados.get('role', 'analista')
    criado_em = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    existe = conn.execute("SELECT id FROM usuarios WHERE email = ?", (email,)).fetchone()
    if existe:
        conn.close()
        return jsonify({"erro": "Este e-mail já está cadastrado."}), 409

    conn.execute(
        "INSERT INTO usuarios (email, senha_hash, nome, role, criado_em) VALUES (?, ?, ?, ?, ?)",
        (email, senha_hash, nome, role, criado_em)
    )
    conn.commit()
    conn.close()
    return jsonify({"message": f"Usuário '{nome}' criado com sucesso!"}), 201


@app.route('/auth/login', methods=['POST'])
def login():
    """Valida credenciais e retorna um JWT de acesso."""
    dados = request.get_json()
    if not dados or not dados.get('email') or not dados.get('senha'):
        return jsonify({"erro": "E-mail e senha são obrigatórios."}), 400

    email = dados['email'].strip().lower()
    conn = get_db_connection()
    usuario = conn.execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not usuario or not check_password_hash(usuario['senha_hash'], dados['senha']):
        return jsonify({"erro": "Credenciais inválidas."}), 401

    # identity = email do usuário (fica gravada no token e recuperável via get_jwt_identity())
    token = create_access_token(identity=usuario['email'])
    return jsonify({
        "access_token": token,
        "nome": usuario['nome'],
        "email": usuario['email'],
        "role": usuario['role']
    }), 200


@app.route('/auth/me', methods=['GET'])
@jwt_required()
def me():
    """Retorna os dados do usuário autenticado a partir do token."""
    email = get_jwt_identity()
    conn = get_db_connection()
    usuario = conn.execute("SELECT id, email, nome, role, criado_em FROM usuarios WHERE email = ?", (email,)).fetchone()
    conn.close()
    if not usuario:
        return jsonify({"erro": "Usuário não encontrado."}), 404
    return jsonify(dict(usuario)), 200


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
@jwt_required()
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

    # M1 — Campos do modelo tripartido CVSS + EPSS + KEV
    cvss_score  = float(dados.get("cvss_score", 0.0) or 0.0)
    epss_score  = float(dados.get("epss_score", 0.0) or 0.0)
    cve_id      = (dados.get("cve_id") or "").strip()
    no_kev      = bool(dados.get("no_kev", False))

    categoria = ia.detectar_categoria(nome)

    conn = get_db_connection()

    # Correlação de risco: por categoria repetida E por ativo concentrando risco.
    correlacao_categoria = ia.correlacionar_historico(conn, categoria)
    correlacao_ativo = ia.correlacionar_por_ativo(conn, ativo)

    # M1 — Motor de priorização: usa v2 (tripartido) quando CVSS > 0, legado caso contrário.
    if cvss_score > 0 or no_kev:
        prioridade, nivel_sla, sla_prazo_dias, explicacao_fatores = ia.calcular_prioridade_v2(
            cvss_score, epss_score, no_kev, fatores
        )
        sla_prioridade = nivel_sla
    else:
        prioridade, explicacao_fatores = ia.calcular_prioridade(score, fatores)
        # Determinar SLA pelo score legado
        if prioridade >= 90:
            sla_prioridade, sla_prazo_dias = "P1", 15
        elif prioridade >= 70:
            sla_prioridade, sla_prazo_dias = "P2", 30
        elif prioridade >= 40:
            sla_prioridade, sla_prazo_dias = "P3", 90
        else:
            sla_prioridade, sla_prazo_dias = "P4", 180

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
             categoria, prioridade, explicacao, origem, ativo,
             cvss_score, epss_score, cve_id, no_kev, sla_prazo_dias, sla_prioridade)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        nome, impacto, frequencia, gravidade, score, "Aberta", data_atual,
        int(fatores["exposta_internet"]), int(fatores["exploit_publico"]),
        int(fatores["dados_sensiveis"]), int(fatores["escalonamento_privilegio"]),
        int(fatores["ambiente_producao"]), categoria, prioridade, explicacao_texto,
        origem, ativo, cvss_score, epss_score, cve_id, int(no_kev),
        sla_prazo_dias, sla_prioridade
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
        "sla_prioridade": sla_prioridade,
        "sla_prazo_dias": sla_prazo_dias,
        "cvss_score": cvss_score,
        "epss_score": epss_score,
        "no_kev": no_kev,
        "explicacao": explicacao_fatores,
        "guia_remediacao": ia.gerar_guia_remediacao(categoria),
        "correlacao_categoria": correlacao_categoria,
        "correlacao_ativo": correlacao_ativo,
        "dread": ia.calcular_dread(gravidade, frequencia, fatores)
    }), 201

@app.route('/vulnerabilidades/<int:id>/validar', methods=['PUT'])
@jwt_required()
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
@jwt_required()
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

# ─────────────────────────────────────────────
# M2 — SLA STATUS (NIST SI-2(2) / ISO 27001 A.8.8)
# ─────────────────────────────────────────────

@app.route('/sla/status', methods=['GET'])
def status_slas():
    """M2 — Retorna todas as vulnerabilidades com status de SLA calculado em
    tempo real (Em Prazo / Em Risco / Violado). Fornece evidência auditável
    exigida por NIST SP 800-53 SI-2(2) e ISO 27001 A.8.8."""
    conn = get_db_connection()
    agora = datetime.now()

    vulns = conn.execute(
        "SELECT id, nome, sla_prioridade, sla_prazo_dias, data, status FROM vulnerabilidades "
        "WHERE status NOT IN ('Isolada (Circuit Breaker)')"
    ).fetchall()

    resultados = []
    for v in vulns:
        try:
            data_registro = datetime.strptime(v["data"], "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            continue
        prazo_dias = v["sla_prazo_dias"] or 90
        prazo = data_registro + timedelta(days=prazo_dias)
        dias_restantes = (prazo - agora).days

        if dias_restantes < 0:
            status_sla = "Violado"
        elif dias_restantes <= 3:
            status_sla = "Em Risco"
        else:
            status_sla = "Em Prazo"

        resultados.append({
            "id": v["id"],
            "nome": v["nome"],
            "nivel": v["sla_prioridade"] or "P3",
            "prazo_dias": prazo_dias,
            "dias_restantes": dias_restantes,
            "status_sla": status_sla
        })

    conn.close()
    return jsonify(resultados), 200

# ─────────────────────────────────────────────
# M4 — OWASP SAMM MATURITY SCORE
# ─────────────────────────────────────────────

@app.route('/governance/maturity', methods=['GET'])
def calcular_maturidade_samm():
    """M4 — Calcula Score de Maturidade OWASP SAMM simplificado (0 a 3).
    Nível 0 = Inexistente | Nível 1 = Básico | Nível 2 = Gerenciado | Nível 3 = Otimizado.
    KPI de alto valor executivo — o que CISOs apresentam ao board."""
    conn = get_db_connection()
    total = conn.execute("SELECT COUNT(*) FROM vulnerabilidades").fetchone()[0]
    validadas = conn.execute("SELECT COUNT(*) FROM vulnerabilidades WHERE status='Validada'").fetchone()[0]
    com_sla = conn.execute(
        "SELECT COUNT(*) FROM vulnerabilidades WHERE sla_prioridade IS NOT NULL AND sla_prioridade != ''"
    ).fetchone()[0]
    com_ativo = conn.execute(
        "SELECT COUNT(*) FROM vulnerabilidades WHERE ativo != '' AND ativo IS NOT NULL"
    ).fetchone()[0]
    origens_distintas = conn.execute("SELECT COUNT(DISTINCT origem) FROM vulnerabilidades").fetchone()[0]
    conn.close()

    if total == 0:
        return jsonify({"nivel_samm": 0, "descricao": "Sem dados suficientes para avaliação.", "detalhes": []}), 200

    score = 0
    detalhes = []
    taxa_validacao = validadas / total
    taxa_com_ativo = com_ativo / total
    taxa_com_sla = com_sla / total

    # Nível 1: Processo básico — vulnerabilidades sendo registradas
    if total > 0:
        score += 1
        detalhes.append("Nível 1 atingido: registro de vulnerabilidades ativo.")

    # Nível 2: Processo gerenciado — validação e múltiplas origens
    if taxa_validacao >= 0.5 and origens_distintas >= 2:
        score += 1
        detalhes.append(f"Nível 2 atingido: {taxa_validacao:.0%} de validação | {origens_distintas} origens distintas.")

    # Nível 3: Processo otimizado — SLAs, ativos mapeados e correlação ativa
    if taxa_com_ativo >= 0.7 and taxa_com_sla >= 0.7:
        score += 1
        detalhes.append(f"Nível 3 atingido: {taxa_com_ativo:.0%} com ativo mapeado | {taxa_com_sla:.0%} com SLA definido.")

    descricoes = {
        0: "Inicial (Ad-hoc) — sem processo definido.",
        1: "Básico — processo de registro existe, mas inconsistente.",
        2: "Gerenciado — processo aplicado com validação e múltiplas fontes.",
        3: "Otimizado — governança por SLA, ativos mapeados e rastreabilidade completa."
    }

    return jsonify({
        "nivel_samm": score,
        "descricao": descricoes.get(score),
        "detalhes": detalhes,
        "taxa_validacao": round(taxa_validacao, 2),
        "origens_distintas": origens_distintas,
        "total_vulnerabilidades": total
    }), 200

# ─────────────────────────────────────────────
# M6 — KPIs DE GOVERNÂNÇA (NIST CA-7 / Seção 9 da pesquisa)
# ─────────────────────────────────────────────

@app.route('/governance/kpis', methods=['GET'])
def kpis_governanca():
    """M6 — KPIs operacionais de governança: SLA Breach Rate e Scan Coverage.
    Esses KPIs são os mesmos definidos na Seção 9 da pesquisa ASPM e medidos
    por plataformas como Microsoft Defender for Cloud."""
    conn = get_db_connection()
    agora = datetime.now()

    total = conn.execute("SELECT COUNT(*) FROM vulnerabilidades").fetchone()[0]

    # SLA Breach Rate — % de vulnerabilidades em aberto que ultrapassaram o SLA
    total_aberto = conn.execute(
        "SELECT COUNT(*) FROM vulnerabilidades WHERE status NOT IN ('Isolada (Circuit Breaker)')"
    ).fetchone()[0]

    violados = 0
    if total_aberto > 0:
        vulns_abertas = conn.execute(
            "SELECT data, sla_prazo_dias FROM vulnerabilidades "
            "WHERE status NOT IN ('Isolada (Circuit Breaker)') AND sla_prazo_dias > 0"
        ).fetchall()
        for v in vulns_abertas:
            try:
                data_reg = datetime.strptime(v["data"], "%Y-%m-%d %H:%M:%S")
                prazo = data_reg + timedelta(days=v["sla_prazo_dias"])
                if agora > prazo:
                    violados += 1
            except (ValueError, TypeError):
                pass

    sla_breach_rate = round((violados / total_aberto * 100), 1) if total_aberto > 0 else 0

    # Scan Coverage Rate — % de vulnerabilidades com ativo mapeado
    com_ativo = conn.execute(
        "SELECT COUNT(*) FROM vulnerabilidades WHERE ativo != '' AND ativo IS NOT NULL"
    ).fetchone()[0]
    scan_coverage = round((com_ativo / total * 100), 1) if total > 0 else 0

    # Distribuição por origem (ingestão multi-fonte)
    origens = conn.execute(
        "SELECT origem, COUNT(*) as c FROM vulnerabilidades GROUP BY origem ORDER BY c DESC"
    ).fetchall()

    # Distribuição por nível SLA
    sla_dist = conn.execute(
        "SELECT sla_prioridade, COUNT(*) as c FROM vulnerabilidades GROUP BY sla_prioridade ORDER BY sla_prioridade"
    ).fetchall()

    # Vulnerabilidades críticas (P0 + P1)
    criticas = conn.execute(
        "SELECT COUNT(*) FROM vulnerabilidades WHERE sla_prioridade IN ('P0', 'P1') AND status != 'Isolada (Circuit Breaker)'"
    ).fetchone()[0]

    conn.close()

    return jsonify({
        "total_vulnerabilidades": total,
        "vulnerabilidades_em_aberto": total_aberto,
        "criticas_p0_p1": criticas,
        "sla_breach_rate_percent": sla_breach_rate,
        "sla_violados": violados,
        "scan_coverage_rate_percent": scan_coverage,
        "ativos_mapeados": com_ativo,
        "distribuicao_por_origem": {o["origem"]: o["c"] for o in origens},
        "distribuicao_por_sla": {s["sla_prioridade"]: s["c"] for s in sla_dist},
        "timestamp": agora.strftime("%Y-%m-%d %H:%M:%S")
    }), 200

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