from dotenv import load_dotenv
load_dotenv()  # Carrega variáveis do arquivo .env antes de qualquer outra importação

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import re
import json
import secrets
import logging
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
import ia
import banco
import db
import scanner

APP_DIR = Path(__file__).resolve().parent
PROJECT_DIR = APP_DIR.parent
HOME_DIR = PROJECT_DIR / "Home"
IMAGES_DIR = PROJECT_DIR / "images"
RATE_DIR = PROJECT_DIR / "rate"
ABOUT_DIR = PROJECT_DIR / "about"

# O frontend fica em diretorios diferentes do backend. As rotas explicitas
# evitam expor o diretorio inteiro do app (inclusive arquivos como o .env).
app = Flask(__name__, static_folder=None)

_proxy_count = int(os.environ.get("TRUST_PROXY_COUNT", "0"))
if _proxy_count > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=_proxy_count,
        x_proto=_proxy_count,
        x_host=_proxy_count,
    )

@app.route('/')
@app.route('/home')
@app.route('/Home/Home.html')
def serve_home():
    return send_from_directory(HOME_DIR, 'Home.html')

@app.route('/painel')
@app.route('/painel/')
@app.route('/securescope/index.html')
def serve_painel():
    return send_from_directory(APP_DIR, 'index.html')

@app.route('/home.css')
@app.route('/Home/home.css')
def serve_home_css():
    return send_from_directory(HOME_DIR, 'home.css')

@app.route('/painel.css')
def serve_painel_css():
    return send_from_directory(APP_DIR, 'painel.css')

@app.route('/script.js')
def serve_painel_script():
    return send_from_directory(APP_DIR, 'script.js')

@app.route('/site-search.js')
def serve_site_search_script():
    return send_from_directory(APP_DIR, 'site-search.js')

@app.route('/site-header.css')
def serve_site_header_css():
    return send_from_directory(APP_DIR, 'site-header.css')

@app.route('/images/<path:filename>')
def serve_images(filename):
    return send_from_directory(IMAGES_DIR, filename)

@app.route('/rate')
@app.route('/rate/')
def serve_rate():
    return send_from_directory(RATE_DIR, 'Rate.html')

@app.route('/rate/<path:filename>')
def serve_rate_files(filename):
    return send_from_directory(RATE_DIR, filename)

@app.route('/about')
@app.route('/about/')
def serve_about():
    return send_from_directory(ABOUT_DIR, 'about.html')

@app.route('/about/<path:filename>')
def serve_about_files(filename):
    return send_from_directory(ABOUT_DIR, filename)

APP_ENV = os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "development")).lower()
IS_PRODUCTION = APP_ENV == "production"

# Em desenvolvimento, uma chave efemera evita segredos fixos no codigo. Em
# producao, a aplicacao falha na inicializacao se a chave estiver ausente ou
# for fraca, em vez de subir com uma configuracao previsivel.
_jwt_secret = os.environ.get("JWT_SECRET_KEY", "")
if IS_PRODUCTION and len(_jwt_secret) < 32:
    raise RuntimeError("JWT_SECRET_KEY deve existir e ter ao menos 32 caracteres em producao.")
if not _jwt_secret:
    _jwt_secret = secrets.token_urlsafe(48)
    logging.warning("JWT_SECRET_KEY ausente; usando chave efemera apenas para desenvolvimento.")

app.config.update(
    JWT_SECRET_KEY=_jwt_secret,
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(
        minutes=int(os.environ.get("JWT_ACCESS_TOKEN_MINUTES", "60"))
    ),
    JWT_TOKEN_LOCATION=["cookies"],
    JWT_COOKIE_SECURE=IS_PRODUCTION,
    JWT_COOKIE_SAMESITE="Strict",
    JWT_COOKIE_CSRF_PROTECT=True,
    JWT_ACCESS_COOKIE_PATH="/",
)

# Limite de upload: rejeita no nível WSGI antes de bufferizar na memória.
# 15 MB dá margem acima do limite de 10 MB por arquivo do scanner.py.
# Aplica-se a TODAS as rotas (incluindo /scanner/analisar e /scanner/analisar-codigo).
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024  # 15 MB

jwt = JWTManager(app)

# Nunca usa CORS aberto. O frontend principal e servido pela mesma aplicacao;
# origens adicionais precisam ser declaradas explicitamente.
_origins_env = os.environ.get("ALLOWED_ORIGINS")
if IS_PRODUCTION and not _origins_env:
    raise RuntimeError("ALLOWED_ORIGINS deve ser configurada em producao.")
_origins = (
    [o.strip().rstrip("/") for o in _origins_env.split(",") if o.strip()]
    if _origins_env
    else ["http://127.0.0.1:5000", "http://localhost:5000"]
)
CORS(
    app,
    resources={r"/*": {"origins": _origins}},
    supports_credentials=True,
)

_rate_storage = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
if IS_PRODUCTION and _rate_storage == "memory://":
    raise RuntimeError("RATELIMIT_STORAGE_URI deve usar Redis ou outro storage compartilhado em producao.")
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=_rate_storage,
    headers_enabled=True,
)


def rate_limit_usuario():
    """Limita por usuario autenticado e usa IP como fallback."""
    try:
        identidade = get_jwt_identity()
        if identidade:
            return f"usuario:{identidade}"
    except RuntimeError:
        pass
    return f"ip:{get_remote_address()}"


def rate_limit_conta_login():
    """Protege uma conta contra tentativas distribuidas sem armazenar o e-mail."""
    dados = request.get_json(silent=True) or {}
    email = str(dados.get("email", "")).strip().lower()
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
    return f"conta:{digest}"


@app.after_request
def aplicar_cabecalhos_seguranca(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["Cache-Control"] = "no-store" if request.path.startswith("/auth/") else response.headers.get("Cache-Control", "no-cache")
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(429)
def limite_excedido(_erro):
    return jsonify({"erro": "Muitas requisicoes. Aguarde antes de tentar novamente."}), 429


@jwt.unauthorized_loader
def jwt_ausente(_motivo):
    return jsonify({"erro": "Autenticacao necessaria."}), 401


@jwt.invalid_token_loader
def jwt_invalido(_motivo):
    return jsonify({"erro": "Sessao invalida."}), 401


@jwt.expired_token_loader
def jwt_expirado(_cabecalho, _payload):
    return jsonify({"erro": "Sessao expirada."}), 401

VALORES_STATUS = ("Aberta", "Validada", "Isolada (Circuit Breaker)")

def get_db_connection():
    return db.get_db_connection()


def serializar_detalhes_scanner(achado, tipo):
    """Preserva metadados técnicos sem poluir a tabela principal."""
    detalhes = {
        "tipo": tipo.upper(),
        "titulo": achado.get("_titulo", ""),
        "descricao": achado.get("_descricao", ""),
        "risco": achado.get("_risco", ""),
        "remediacao": achado.get("_remediacao", []),
        "referencias": achado.get("_referencias", []),
    }

    if tipo == "sast":
        detalhes.update({
            "arquivo": achado.get("ativo", ""),
            "linha": achado.get("_linha", ""),
            "codigo": achado.get("_codigo_trecho", ""),
            "test_id": achado.get("_test_id", ""),
            "test_name": achado.get("_test_name", ""),
            "cwe": f"CWE-{achado.get('_cwe_id', '')}" if achado.get("_cwe_id") else "",
            "cwe_link": achado.get("_cwe_link", ""),
            "confianca_ferramenta": achado.get("_confianca", ""),
        })
    elif tipo == "sca":
        detalhes.update({
            "pacote": achado.get("ativo", ""),
            "versao_afetada": achado.get("_versao_afetada", ""),
            "versao_corrigida": achado.get("_versao_corrigida", ""),
            "osv_id": achado.get("_osv_id", ""),
        })
    elif tipo == "dast":
        detalhes.update({
            "url": achado.get("ativo", ""),
            "cwe": f"CWE-{achado.get('_cwe_id', '')}" if achado.get("_cwe_id") else "",
            "evidencia": achado.get("_evidencia", ""),
            "solucao": achado.get("_solucao", ""),
            "confianca_ferramenta": achado.get("_confianca", ""),
        })

    return json.dumps(detalhes, ensure_ascii=False)


def desserializar_detalhes_scanner(valor):
    if not valor:
        return {}
    try:
        detalhes = json.loads(valor)
        return detalhes if isinstance(detalhes, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}

def usuario_id_atual(conn=None):
    """Resolve o id numerico do usuario autenticado a partir do JWT.
    Levanta erro se usado fora de uma
    rota protegida por @jwt_required().

    Aceita um parâmetro opcional 'conn' para reutilizar a conexão da rota
    chamadora — evitando abrir uma conexão extra só para buscar o id."""
    try:
        identidade = int(get_jwt_identity())
    except (TypeError, ValueError):
        return None
    fechar = conn is None
    if conn is None:
        conn = get_db_connection()
    usuario = conn.execute("SELECT id FROM usuarios WHERE id = ?", (identidade,)).fetchone()
    if fechar:
        conn.close()
    if not usuario:
        return None
    return usuario["id"]

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

def vulnerabilidade_existe(conn, id, usuario_id=None):
    """Se usuario_id for passado, só considera 'existente' se a vulnerabilidade
    pertencer a esse usuário — usado para isolar dados por perfil (multi-tenant)."""
    if usuario_id is not None:
        result = conn.execute(
            "SELECT id FROM vulnerabilidades WHERE id = ? AND usuario_id = ?", (id, usuario_id)
        ).fetchone()
    else:
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

    # Corrige registros criados pelo motor v2 antigo, que aplicava 30%
    # diretamente ao CVSS na escala 0-10 (CVSS 8.0 virava prioridade 2.4).
    subestimadas = conn.execute('''
        SELECT id, score, prioridade, cvss_score, epss_score, no_kev,
               exposta_internet, exploit_publico, dados_sensiveis,
               escalonamento_privilegio, ambiente_producao, explicacao
        FROM vulnerabilidades
        WHERE prioridade < score
    ''').fetchall()

    for linha in subestimadas:
        fatores = {
            "exposta_internet": bool(linha.get("exposta_internet")),
            "exploit_publico": bool(linha.get("exploit_publico")),
            "dados_sensiveis": bool(linha.get("dados_sensiveis")),
            "escalonamento_privilegio": bool(linha.get("escalonamento_privilegio")),
            "ambiente_producao": bool(linha.get("ambiente_producao")),
        }
        cvss = float(linha.get("cvss_score") or 0)
        epss = float(linha.get("epss_score") or 0)
        no_kev = bool(linha.get("no_kev"))
        if cvss > 0 or no_kev:
            prioridade, nivel, prazo, explicacao = ia.calcular_prioridade_v2(
                cvss,
                epss,
                no_kev,
                fatores,
                risk_index_base=linha["score"],
                epss_disponivel=epss > 0,
            )
        else:
            prioridade, explicacao = ia.calcular_prioridade(linha["score"], fatores)
            nivel, prazo = ia.classificar_sla(prioridade)

        prefixos_antigos = (
            "CVSS:", "EPSS:", "Score Base:", "Priority Score Final:",
            "Risk Index™ observado:", "Score técnico combinado:",
        )
        extras = [
            item.strip() for item in (linha.get("explicacao") or "").split(" | ")
            if item.strip()
            and not item.strip().startswith(prefixos_antigos)
            and not item.strip().startswith("+")
        ]
        explicacao_texto = " | ".join(explicacao + extras)
        conn.execute('''
            UPDATE vulnerabilidades
            SET prioridade = ?, sla_prioridade = ?, sla_prazo_dias = ?, explicacao = ?
            WHERE id = ?
        ''', (prioridade, nivel, prazo, explicacao_texto, linha["id"]))

    if subestimadas:
        conn.commit()
        print(f"[migração] Prioridade corrigida em {len(subestimadas)} registro(s) subestimado(s).")

    conn.close()

preparar_banco_para_ia()

# ─────────────────────────────────────────────
# M3 — AUTENTICAÇÃO (JWT)
# ─────────────────────────────────────────────

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")
SENHA_MINIMA = 12
SENHA_MAXIMA = 128
_HASH_COMPARACAO = generate_password_hash(secrets.token_urlsafe(32), method="scrypt")
CADASTRO_PUBLICO_ATIVO = os.environ.get(
    "ALLOW_PUBLIC_REGISTRATION", "0" if IS_PRODUCTION else "1"
).lower() in ("1", "true", "yes")


def validar_senha(senha):
    if not isinstance(senha, str) or not SENHA_MINIMA <= len(senha) <= SENHA_MAXIMA:
        return f"A senha deve ter entre {SENHA_MINIMA} e {SENHA_MAXIMA} caracteres."
    if not re.search(r"[a-z]", senha) or not re.search(r"[A-Z]", senha) or not re.search(r"\d", senha):
        return "A senha deve conter letra maiuscula, letra minuscula e numero."
    return None

@app.route('/auth/register', methods=['POST'])
@limiter.limit(os.environ.get("RATELIMIT_REGISTER", "5 per hour"))
def registrar_usuario():
    """Cria um novo usuário. Em produção, esta rota deveria ser protegida
    por um admin. Por ora, é aberta para facilitar o primeiro acesso."""
    if not CADASTRO_PUBLICO_ATIVO:
        return jsonify({"erro": "Cadastro publico desabilitado."}), 403

    dados = request.get_json(silent=True)
    for campo in ['email', 'senha', 'nome']:
        if not dados or not dados.get(campo):
            return jsonify({"erro": f"Campo obrigatório ausente: '{campo}'"}), 400
    if not all(isinstance(dados[campo], str) for campo in ('email', 'senha', 'nome')):
        return jsonify({"erro": "Campos de cadastro invalidos."}), 400

    email = dados['email'].strip().lower()
    nome = dados['nome'].strip()
    if not EMAIL_RE.fullmatch(email):
        return jsonify({"erro": "E-mail invalido."}), 400
    if not 2 <= len(nome) <= 100:
        return jsonify({"erro": "O nome deve ter entre 2 e 100 caracteres."}), 400
    erro_senha = validar_senha(dados['senha'])
    if erro_senha:
        return jsonify({"erro": erro_senha}), 400

    senha_hash = generate_password_hash(dados['senha'], method="scrypt")
    # Cadastro publico sempre recebe o menor privilegio. Contas administrativas
    # devem ser criadas por um fluxo administrativo separado.
    role = 'analista'
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
@limiter.limit(os.environ.get("RATELIMIT_LOGIN", "5 per minute;20 per hour"))
@limiter.limit(os.environ.get("RATELIMIT_LOGIN_ACCOUNT", "10 per hour"), key_func=rate_limit_conta_login)
def login():
    """Valida credenciais e retorna um JWT de acesso."""
    dados = request.get_json(silent=True)
    if not dados or not dados.get('email') or not dados.get('senha'):
        return jsonify({"erro": "E-mail e senha são obrigatórios."}), 400
    if not isinstance(dados['email'], str) or not isinstance(dados['senha'], str):
        return jsonify({"erro": "Credenciais inválidas."}), 401
    if len(dados['email']) > 320 or len(dados['senha']) > SENHA_MAXIMA:
        return jsonify({"erro": "Credenciais inválidas."}), 401

    email = dados['email'].strip().lower()
    conn = get_db_connection()
    usuario = conn.execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone()
    conn.close()

    hash_armazenado = usuario['senha_hash'] if usuario else _HASH_COMPARACAO
    credenciais_validas = check_password_hash(hash_armazenado, dados['senha'])
    if not usuario or not credenciais_validas:
        conta_hash = hashlib.sha256(email.encode("utf-8")).hexdigest()[:12]
        app.logger.warning(
            "Falha de login conta=%s ip=%s", conta_hash, get_remote_address()
        )
        return jsonify({"erro": "Credenciais inválidas."}), 401

    token = create_access_token(identity=str(usuario['id']))
    resposta = jsonify({
        "nome": usuario['nome'],
        "email": usuario['email'],
        "role": usuario['role']
    })
    set_access_cookies(resposta, token)
    return resposta, 200


@app.route('/auth/logout', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute", key_func=rate_limit_usuario)
def logout():
    resposta = jsonify({"message": "Sessao encerrada."})
    unset_jwt_cookies(resposta)
    return resposta, 200


@app.route('/auth/me', methods=['GET'])
@jwt_required()
def me():
    """Retorna os dados do usuário autenticado a partir do token."""
    uid = usuario_id_atual()
    conn = get_db_connection()
    usuario = conn.execute("SELECT id, email, nome, role, criado_em FROM usuarios WHERE id = ?", (uid,)).fetchone()
    conn.close()
    if not usuario:
        return jsonify({"erro": "Usuário não encontrado."}), 404
    return jsonify(dict(usuario)), 200


# ─────────────────────────────────────────────
# ROTAS PADRÃO (1 a 7)
# ─────────────────────────────────────────────

@app.route('/vulnerabilidades', methods=['GET'])
@jwt_required()
def listar_vulnerabilidades():
    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    vulnerabilidades = conn.execute(
        'SELECT * FROM vulnerabilidades WHERE usuario_id = ? ORDER BY score DESC', (uid,)
    ).fetchall()
    conn.close()
    return jsonify([dict(vuln) for vuln in vulnerabilidades]), 200

@app.route('/vulnerabilidades/<int:id>', methods=['GET'])
@jwt_required()
def buscar_vulnerabilidade(id):
    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    vuln = conn.execute(
        'SELECT * FROM vulnerabilidades WHERE id = ? AND usuario_id = ?', (id, uid)
    ).fetchone()
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
    uid = usuario_id_atual(conn)

    # Correlação de risco: por categoria repetida E por ativo concentrando
    # risco, sempre restrita aos dados do usuário autenticado.
    correlacao_categoria = ia.correlacionar_historico(conn, categoria, uid)
    correlacao_ativo = ia.correlacionar_por_ativo(conn, ativo, uid)

    # M1 — Motor de priorização: usa v2 (tripartido) quando CVSS > 0, legado caso contrário.
    if cvss_score > 0 or no_kev:
        prioridade, nivel_sla, sla_prazo_dias, explicacao_fatores = ia.calcular_prioridade_v2(
            cvss_score,
            epss_score,
            no_kev,
            fatores,
            risk_index_base=score,
            epss_disponivel=epss_score > 0,
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

    # Correlações podem elevar o score para outra faixa; mantenha o SLA coerente.
    sla_prioridade, sla_prazo_dias = ia.classificar_sla(prioridade, no_kev)

    explicacao_texto = " | ".join(explicacao_fatores)

    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO vulnerabilidades
            (nome, impacto, frequencia, gravidade, score, status, data,
             exposta_internet, exploit_publico, dados_sensiveis,
             escalonamento_privilegio, ambiente_producao,
             categoria, prioridade, explicacao, origem, ativo,
             cvss_score, epss_score, cve_id, no_kev, sla_prazo_dias, sla_prioridade,
             usuario_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
    ''', (
        nome, impacto, frequencia, gravidade, score, "Aberta", data_atual,
        int(fatores["exposta_internet"]), int(fatores["exploit_publico"]),
        int(fatores["dados_sensiveis"]), int(fatores["escalonamento_privilegio"]),
        int(fatores["ambiente_producao"]), categoria, prioridade, explicacao_texto,
        origem, ativo, cvss_score, epss_score, cve_id, int(no_kev),
        sla_prazo_dias, sla_prioridade, uid
    ))
    vulnerabilidade_id = cursor.fetchone()["id"]
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
    uid = usuario_id_atual(conn)
    if not vulnerabilidade_existe(conn, id, uid):
        conn.close()
        return jsonify({"erro": f"Vulnerabilidade {id} não encontrada."}), 404
    conn.execute("UPDATE vulnerabilidades SET status = 'Validada' WHERE id = ? AND usuario_id = ?", (id, uid))
    conn.commit()
    conn.close()
    registrar_historico(id, "Marcação como Validada", "Analista Blue Team")
    return jsonify({"message": f"Vulnerabilidade {id} validada com sucesso!"}), 200

@app.route('/circuit-breaker/<int:id>', methods=['POST'])
@jwt_required()
def acionar_circuit_breaker(id):
    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    if not vulnerabilidade_existe(conn, id, uid):
        conn.close()
        return jsonify({"erro": f"Vulnerabilidade {id} não encontrada."}), 404
    conn.execute(
        "UPDATE vulnerabilidades SET status = 'Isolada (Circuit Breaker)' WHERE id = ? AND usuario_id = ?",
        (id, uid)
    )
    conn.commit()
    conn.close()
    registrar_historico(id, "Ameaça contida e isolada via Circuit Breaker", "Sistema de Defesa Ativa")
    return jsonify({"alerta": "Circuit Breaker acionado!", "message": f"Vulnerabilidade {id} isolada com sucesso."}), 200

@app.route('/relatorio', methods=['GET'])
@jwt_required()
def gerar_relatorio():
    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    relatorio = conn.execute(
        'SELECT * FROM vulnerabilidades WHERE usuario_id = ? ORDER BY score DESC', (uid,)
    ).fetchall()
    conn.close()
    return jsonify([dict(risco) for risco in relatorio]), 200

@app.route('/vulnerabilidades/<int:id>/historico', methods=['GET'])
@jwt_required()
def ver_historico(id):
    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    if not vulnerabilidade_existe(conn, id, uid):
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
@jwt_required()
@limiter.limit(os.environ.get("RATELIMIT_IA", "30 per hour"), key_func=rate_limit_usuario)
def sugerir_valores_ia():
    dados = request.get_json(silent=True) or {}
    nome_ameaca = str(dados.get('nome', ''))[:200]
    sugestao = ia.analisar_nome(nome_ameaca)
    sugestao['perguntas'] = ia.gerar_perguntas_contexto(sugestao.get('categoria', 'Geral/Desconhecida'))
    return jsonify(sugestao)

@app.route('/ia/insights', methods=['GET'])
@jwt_required()
def insights_ia():
    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    insights = ia.aprender_com_historico(conn, uid)
    conn.close()
    return jsonify(insights)

# ─────────────────────────────────────────────
# M2 — SLA STATUS (NIST SI-2(2) / ISO 27001 A.8.8)
# ─────────────────────────────────────────────

@app.route('/sla/status', methods=['GET'])
@jwt_required()
def status_slas():
    """M2 — Retorna todas as vulnerabilidades DO USUÁRIO AUTENTICADO com
    status de SLA calculado em tempo real (Em Prazo / Em Risco / Violado).
    Fornece evidência auditável exigida por NIST SP 800-53 SI-2(2) e
    ISO 27001 A.8.8."""
    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    agora = datetime.now()

    vulns = conn.execute(
        "SELECT id, nome, sla_prioridade, sla_prazo_dias, data, status FROM vulnerabilidades "
        "WHERE status NOT IN ('Isolada (Circuit Breaker)') AND usuario_id = ?", (uid,)
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
@jwt_required()
def calcular_maturidade_samm():
    """M4 — Calcula Score de Maturidade OWASP SAMM simplificado (0 a 3)
    PARA O USUÁRIO AUTENTICADO. Nível 0 = Inexistente | Nível 1 = Básico |
    Nível 2 = Gerenciado | Nível 3 = Otimizado. KPI de alto valor executivo
    — o que CISOs apresentam ao board."""
    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    total = conn.execute(
        "SELECT COUNT(*) as total FROM vulnerabilidades WHERE usuario_id = ?", (uid,)
    ).fetchone()["total"]
    validadas = conn.execute(
        "SELECT COUNT(*) as total FROM vulnerabilidades WHERE status='Validada' AND usuario_id = ?", (uid,)
    ).fetchone()["total"]
    com_sla = conn.execute(
        "SELECT COUNT(*) as total FROM vulnerabilidades "
        "WHERE sla_prioridade IS NOT NULL AND sla_prioridade != '' AND usuario_id = ?", (uid,)
    ).fetchone()["total"]
    com_ativo = conn.execute(
        "SELECT COUNT(*) as total FROM vulnerabilidades "
        "WHERE ativo != '' AND ativo IS NOT NULL AND usuario_id = ?", (uid,)
    ).fetchone()["total"]
    origens_distintas = conn.execute(
        "SELECT COUNT(DISTINCT origem) as total FROM vulnerabilidades WHERE usuario_id = ?", (uid,)
    ).fetchone()["total"]
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
@jwt_required()
def kpis_governanca():
    """M6 — KPIs operacionais de governança DO USUÁRIO AUTENTICADO: SLA
    Breach Rate e Scan Coverage. Esses KPIs são os mesmos definidos na
    Seção 9 da pesquisa ASPM e medidos por plataformas como Microsoft
    Defender for Cloud."""
    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    agora = datetime.now()

    total = conn.execute(
        "SELECT COUNT(*) as total FROM vulnerabilidades WHERE usuario_id = ?", (uid,)
    ).fetchone()["total"]

    # SLA Breach Rate — % de vulnerabilidades em aberto que ultrapassaram o SLA
    total_aberto = conn.execute(
        "SELECT COUNT(*) as total FROM vulnerabilidades "
        "WHERE status NOT IN ('Isolada (Circuit Breaker)') AND usuario_id = ?", (uid,)
    ).fetchone()["total"]

    violados = 0
    if total_aberto > 0:
        vulns_abertas = conn.execute(
            "SELECT data, sla_prazo_dias FROM vulnerabilidades "
            "WHERE status NOT IN ('Isolada (Circuit Breaker)') AND sla_prazo_dias > 0 AND usuario_id = ?",
            (uid,)
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
        "SELECT COUNT(*) as total FROM vulnerabilidades "
        "WHERE ativo != '' AND ativo IS NOT NULL AND usuario_id = ?", (uid,)
    ).fetchone()["total"]
    scan_coverage = round((com_ativo / total * 100), 1) if total > 0 else 0

    # Distribuição por origem (ingestão multi-fonte)
    origens = conn.execute(
        "SELECT origem, COUNT(*) as c FROM vulnerabilidades WHERE usuario_id = ? "
        "GROUP BY origem ORDER BY c DESC", (uid,)
    ).fetchall()

    # Distribuição por nível SLA
    sla_dist = conn.execute(
        "SELECT sla_prioridade, COUNT(*) as c FROM vulnerabilidades WHERE usuario_id = ? "
        "GROUP BY sla_prioridade ORDER BY sla_prioridade", (uid,)
    ).fetchall()

    # Vulnerabilidades críticas (P0 + P1)
    criticas = conn.execute(
        "SELECT COUNT(*) as total FROM vulnerabilidades WHERE sla_prioridade IN ('P0', 'P1') "
        "AND status != 'Isolada (Circuit Breaker)' AND usuario_id = ?", (uid,)
    ).fetchone()["total"]

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
@jwt_required()
def analise_vulnerabilidade(id):
    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    vuln = conn.execute(
        'SELECT * FROM vulnerabilidades WHERE id = ? AND usuario_id = ?', (id, uid)
    ).fetchone()
    conn.close()

    if vuln is None:
        return jsonify({"erro": f"Vulnerabilidade {id} não encontrada."}), 404

    vuln = dict(vuln)
    categoria = vuln.get("categoria") or "Geral/Desconhecida"
    explicacao_texto = vuln.get("explicacao") or ""
    detalhes = desserializar_detalhes_scanner(vuln.get("detalhes_scanner"))

    # Registros de scanner anteriores à migração não guardavam o trecho de
    # código. Ainda recuperamos arquivo/linha/teste a partir do nome legado.
    detalhes_completos = bool(detalhes)
    if not detalhes and str(vuln.get("nome", "")).startswith("[SAST]"):
        match = re.match(
            r"^\[SAST\]\s+(.+?):(\d+)\s+[—-]\s+(.+?)\s+\((B\d+)\)$",
            vuln["nome"],
        )
        if match:
            detalhes = {
                "tipo": "SAST",
                "arquivo": match.group(1),
                "linha": int(match.group(2)),
                "test_name": match.group(3),
                "test_id": match.group(4),
                "cwe": vuln.get("cve_id") or "",
            }

    fatores = {
        "exposta_internet": bool(vuln.get("exposta_internet")),
        "exploit_publico": bool(vuln.get("exploit_publico")),
        "dados_sensiveis": bool(vuln.get("dados_sensiveis")),
        "escalonamento_privilegio": bool(vuln.get("escalonamento_privilegio")),
        "ambiente_producao": bool(vuln.get("ambiente_producao")),
    }

    guia_categoria = ia.gerar_guia_remediacao(categoria)
    guia_especifico = detalhes.get("remediacao") or []

    return jsonify({
        "id": vuln["id"],
        "nome": vuln["nome"],
        "categoria": categoria,
        "origem": vuln.get("origem") or "Manual/Pentest",
        "ativo": vuln.get("ativo") or "(não informado)",
        "risk_index_base": vuln["score"],
        "prioridade": vuln.get("prioridade", vuln["score"]),
        "nivel_prioridade": vuln.get("sla_prioridade") or "",
        "sla_prazo_dias": vuln.get("sla_prazo_dias"),
        "metricas": {
            "impacto": vuln.get("impacto"),
            "frequencia": vuln.get("frequencia"),
            "gravidade": vuln.get("gravidade"),
            "cvss": vuln.get("cvss_score"),
            "epss": vuln.get("epss_score"),
        },
        "cve_cwe": vuln.get("cve_id") or "",
        "explicacao": explicacao_texto.split(" | ") if explicacao_texto else [],
        "guia_remediacao": guia_especifico or guia_categoria,
        "guia_complementar": guia_categoria if guia_especifico else [],
        "detalhes_scanner": detalhes,
        "detalhes_completos": detalhes_completos,
        "fatores": fatores,
        "dread": ia.calcular_dread(vuln["gravidade"], vuln["frequencia"], fatores)
    }), 200

# ─────────────────────────────────────────────
# SCANNER — FASE 1 (SCA / Software Composition Analysis)
# ─────────────────────────────────────────────

@app.route('/scanner/analisar', methods=['POST'])
@jwt_required()
@limiter.limit(os.environ.get("RATELIMIT_SCANNER", "10 per hour"), key_func=rate_limit_usuario)
def scanner_analisar():
    """Fase 1 — SCA: recebe um requirements.txt via multipart/form-data,
    executa a análise de composição de software contra o OSV.dev e insere
    os achados na tabela 'vulnerabilidades' existente.

    Campos do form-data:
        arquivo: arquivo requirements.txt (obrigatório)

    Retorna JSON com resumo do scan e lista de vulnerabilidades encontradas.
    """
    # — Validação do upload —
    if 'arquivo' not in request.files:
        return jsonify({"erro": "Campo 'arquivo' não encontrado no form-data."}), 400

    arquivo = request.files['arquivo']

    if not arquivo.filename:
        return jsonify({"erro": "Nenhum arquivo selecionado."}), 400

    nome_arquivo = arquivo.filename.strip()
    if not nome_arquivo.endswith('.txt'):
        return jsonify({
            "erro": "Apenas arquivos .txt são aceitos. Envie um requirements.txt."
        }), 400

    # Lê o conteúdo sem executar nada (estágio 1 do pipeline — entrada segura)
    try:
        conteudo = arquivo.read().decode('utf-8')
    except UnicodeDecodeError:
        return jsonify({"erro": "Não foi possível decodificar o arquivo. Use UTF-8."}), 400

    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    data_inicio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Cria registro do scan (status inicial: em_progresso)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (usuario_id, nome_arquivo, status, data_inicio) "
        "VALUES (?, ?, 'em_progresso', ?) RETURNING id",
        (uid, nome_arquivo, data_inicio)
    )
    scan_id = cursor.fetchone()["id"]
    conn.commit()

    # — Estágio 2: Varredura SCA —
    resultado_sca = scanner.executar_sca(conteudo)

    # Se houve erro de rede ou parse, encerra o scan com status de erro
    if resultado_sca["erro"]:
        erro_codigo = resultado_sca.get("erro_codigo")
        conn.execute(
            "UPDATE scans SET status = 'erro', data_fim = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_id)
        )
        conn.commit()
        conn.close()
        status_http = 400 if erro_codigo in {
            "REQUIREMENTS_INVALIDO", "LIMITE_PACOTES_EXCEDIDO"
        } else 502
        return jsonify({
            "scan_id": scan_id,
            "status": "erro",
            "erro": resultado_sca["erro"],
            "erro_codigo": erro_codigo,
            "total_pacotes_analisados": resultado_sca["total_pacotes"],
        }), status_http

    # — Estágio 3: (Multi-LLM já aplicado dentro de scanner.executar_sca) —

    # — Estágio 4: Consolidação na tabela vulnerabilidades —
    ids_inseridos = []
    achados_resumo = []

    try:
        for achado in resultado_sca["achados"]:
            # Categoria detectada pela IA local (mesmo motor usado no input manual)
            categoria = ia.detectar_categoria(achado["nome"])

            score = ia.calcular_risk_index(
                achado["impacto"], achado["frequencia"], achado["gravidade"]
            )
            fatores_achado = {
                "exposta_internet": achado["exposta_internet"],
                "exploit_publico": achado["exploit_publico"],
                "dados_sensiveis": achado["dados_sensiveis"],
                "escalonamento_privilegio": achado["escalonamento_privilegio"],
                "ambiente_producao": achado["ambiente_producao"],
            }

            # Prioridade via motor v2 (tripartido CVSS/EPSS/KEV) quando CVSS disponível
            cvss = achado["cvss_score"]
            if cvss > 0:
                prioridade, nivel_sla, sla_prazo_dias, explicacao_fatores = \
                    ia.calcular_prioridade_v2(
                        cvss,
                        achado["epss_score"],
                        achado["no_kev"],
                        fatores_achado,
                        risk_index_base=score,
                        epss_disponivel=achado.get("_epss_disponivel", False),
                    )
                sla_prioridade = nivel_sla
            else:
                prioridade, explicacao_fatores = ia.calcular_prioridade(score, fatores_achado)
                sla_prioridade, sla_prazo_dias = ia.classificar_sla(prioridade)
            explicacao_texto = " | ".join(explicacao_fatores)
            detalhes_scanner = serializar_detalhes_scanner(achado, "sca")
            data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO vulnerabilidades
                    (nome, impacto, frequencia, gravidade, score, status, data,
                     exposta_internet, exploit_publico, dados_sensiveis,
                     escalonamento_privilegio, ambiente_producao,
                     categoria, prioridade, explicacao, origem, ativo,
                     cvss_score, epss_score, cve_id, no_kev,
                     sla_prazo_dias, sla_prioridade,
                     usuario_id, origem_scan, confianca_ia, detalhes_scanner)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING id
            ''', (
                achado["nome"],
                achado["impacto"],
                achado["frequencia"],
                achado["gravidade"],
                score,
                "Aberta",
                data_atual,
                int(achado["exposta_internet"]),
                int(achado["exploit_publico"]),
                int(achado["dados_sensiveis"]),
                int(achado["escalonamento_privilegio"]),
                int(achado["ambiente_producao"]),
                categoria,
                prioridade,
                explicacao_texto,
                achado["origem"],
                achado["ativo"],
                achado["cvss_score"],
                achado["epss_score"],
                achado["cve_id"],
                int(achado["no_kev"]),
                sla_prazo_dias,
                sla_prioridade,
                uid,
                scan_id,
                achado.get("confianca_ia", 0.0),
                detalhes_scanner,
            ))
            vuln_id = cursor.fetchone()["id"]
            conn.commit()

            registrar_historico(
                vuln_id,
                f"Detectada via SCA (scan #{scan_id}) — {achado.get('_osv_id', '')}",
                "Scanner Automatizado"
            )
            ids_inseridos.append(vuln_id)

            achados_resumo.append({
                "vuln_id": vuln_id,
                "nome": achado.get("_titulo") or achado["nome"],
                "pacote": achado["ativo"],
                "cve_id": achado["cve_id"],
                "cvss_score": achado["cvss_score"],
                "prioridade": prioridade,
                "sla_prioridade": sla_prioridade,
                "versao_corrigida": achado.get("_versao_corrigida", ""),
                "gravidade": achado.get("_gravidade_texto", ""),
            })

    except Exception:
        app.logger.exception("Falha ao consolidar achados do SCA no banco")
        # Falha no meio do loop: faz rollback, marca scan como erro e fecha conn.
        conn.rollback()
        conn.execute(
            "UPDATE scans SET status = 'erro', data_fim = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_id)
        )
        conn.commit()
        conn.close()
        return jsonify({
            "scan_id": scan_id,
            "status": "erro",
            "erro": "Falha interna ao consolidar os achados.",
            "parcialmente_inseridos": len(ids_inseridos),
        }), 500

    # Finaliza o scan
    data_fim = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE scans SET status = 'concluido', total_achados = ?, data_fim = ? WHERE id = ?",
        (len(ids_inseridos), data_fim, scan_id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "scan_id": scan_id,
        "status": "concluido",
        "nome_arquivo": nome_arquivo,
        "total_pacotes_analisados": resultado_sca["total_pacotes"],
        "total_vulnerabilidades_encontradas": len(ids_inseridos),
        "achados_descartados": resultado_sca.get("achados_descartados", 0),
        "triagem_aplicada": resultado_sca.get("triagem_aplicada", False),
        "pacotes_sem_vulnerabilidades": resultado_sca["pacotes_sem_vuln"],
        "vulnerabilidades": achados_resumo,
        "data_inicio": data_inicio,
        "data_fim": data_fim,
    }), 201


@app.route('/scanner/analisar-codigo', methods=['POST'])
@jwt_required()
@limiter.limit(os.environ.get("RATELIMIT_SCANNER", "10 per hour"), key_func=rate_limit_usuario)
def scanner_analisar_codigo():
    """Fase 2 — SAST: recebe um arquivo .py ou .zip via multipart/form-data,
    executa o Bandit via subprocess (sem nunca executar o código enviado) e
    insere os achados na tabela 'vulnerabilidades' existente.

    Campos do form-data:
        arquivo: arquivo .py único ou .zip com múltiplos .py (obrigatório)

    Retorna JSON com resumo do scan e lista de vulnerabilidades encontradas.
    """
    # — Validação do upload —
    if 'arquivo' not in request.files:
        return jsonify({"erro": "Campo 'arquivo' não encontrado no form-data."}), 400

    arquivo = request.files['arquivo']
    if not arquivo.filename:
        return jsonify({"erro": "Nenhum arquivo selecionado."}), 400

    nome_arquivo = arquivo.filename.strip()
    extensao = nome_arquivo.rsplit('.', 1)[-1].lower() if '.' in nome_arquivo else ''

    if extensao not in ('py', 'zip'):
        return jsonify({
            "erro": "Apenas arquivos .py ou .zip são aceitos."
        }), 400

    # Lê bytes do upload — sem executar nada ainda
    conteudo = arquivo.read()

    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    data_inicio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Cria registro do scan (status inicial: em_progresso)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (usuario_id, nome_arquivo, status, data_inicio) "
        "VALUES (?, ?, 'em_progresso', ?) RETURNING id",
        (uid, nome_arquivo, data_inicio)
    )
    scan_id = cursor.fetchone()["id"]
    conn.commit()

    # — Estágio 2: Varredura SAST via Bandit —
    if extensao == 'py':
        resultado_sast = scanner.executar_sast(conteudo, nome_arquivo)
    else:
        resultado_sast = scanner.executar_sast_zip(conteudo)

    # Se houve erro na varredura, encerra o scan com status de erro
    if resultado_sast["erro"]:
        conn.execute(
            "UPDATE scans SET status = 'erro', data_fim = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_id)
        )
        conn.commit()
        conn.close()
        return jsonify({
            "scan_id": scan_id,
            "status": "erro",
            "erro": resultado_sast["erro"],
            "total_arquivos_analisados": resultado_sast.get("total_arquivos", 0),
        }), 502

    # — Estágio 3: (Multi-LLM já aplicado dentro de scanner.executar_sast/_zip) —

    # — Estágio 4: Consolidação na tabela vulnerabilidades —
    ids_inseridos = []
    achados_resumo = []

    try:
        for achado in resultado_sast["achados"]:
            # Categoria detectada pela IA local
            categoria = ia.detectar_categoria(achado["nome"])

            score = ia.calcular_risk_index(
                achado["impacto"], achado["frequencia"], achado["gravidade"]
            )
            fatores_achado = {
                "exposta_internet": achado["exposta_internet"],
                "exploit_publico": achado["exploit_publico"],
                "dados_sensiveis": achado["dados_sensiveis"],
                "escalonamento_privilegio": achado["escalonamento_privilegio"],
                "ambiente_producao": achado["ambiente_producao"],
            }

            # Prioridade via motor v2 (tripartido) quando CVSS disponível
            cvss = achado["cvss_score"]
            if cvss > 0:
                prioridade, nivel_sla, sla_prazo_dias, explicacao_fatores = \
                    ia.calcular_prioridade_v2(
                        cvss,
                        achado["epss_score"],
                        achado["no_kev"],
                        fatores_achado,
                        risk_index_base=score,
                        epss_disponivel=False,
                    )
                sla_prioridade = nivel_sla
            else:
                prioridade, explicacao_fatores = ia.calcular_prioridade(score, fatores_achado)
                sla_prioridade, sla_prazo_dias = ia.classificar_sla(prioridade)

            # Metadados técnicos ficam estruturados em detalhes_scanner; a
            # explicação contém apenas os fatores de priorização.
            explicacao_texto = " | ".join(explicacao_fatores)
            detalhes_scanner = serializar_detalhes_scanner(achado, "sast")
            data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO vulnerabilidades
                    (nome, impacto, frequencia, gravidade, score, status, data,
                     exposta_internet, exploit_publico, dados_sensiveis,
                     escalonamento_privilegio, ambiente_producao,
                     categoria, prioridade, explicacao, origem, ativo,
                     cvss_score, epss_score, cve_id, no_kev,
                     sla_prazo_dias, sla_prioridade,
                     usuario_id, origem_scan, confianca_ia, detalhes_scanner)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING id
            ''', (
                achado["nome"],
                achado["impacto"],
                achado["frequencia"],
                achado["gravidade"],
                score,
                "Aberta",
                data_atual,
                int(achado["exposta_internet"]),
                int(achado["exploit_publico"]),
                int(achado["dados_sensiveis"]),
                int(achado["escalonamento_privilegio"]),
                int(achado["ambiente_producao"]),
                categoria,
                prioridade,
                explicacao_texto,
                achado["origem"],
                achado["ativo"],
                achado["cvss_score"],
                achado["epss_score"],
                achado["cve_id"],
                int(achado["no_kev"]),
                sla_prazo_dias,
                sla_prioridade,
                uid,
                scan_id,
                achado.get("confianca_ia", 0.0),
                detalhes_scanner,
            ))
            vuln_id = cursor.fetchone()["id"]
            conn.commit()

            registrar_historico(
                vuln_id,
                f"Detectada via SAST/Bandit (scan #{scan_id}) — {achado.get('_test_id', '')}",
                "Scanner Automatizado"
            )
            ids_inseridos.append(vuln_id)

            achados_resumo.append({
                "vuln_id":          vuln_id,
                "nome":             achado.get("_titulo") or achado.get("_test_name", ""),
                "arquivo":          achado["ativo"],
                "linha":            achado.get("_linha", ""),
                "test_id":          achado.get("_test_id", ""),
                "test_name":        achado.get("_test_name", ""),
                "cwe":              f"CWE-{achado.get('_cwe_id', '')}",
                "cvss_score":       achado["cvss_score"],
                "prioridade":       prioridade,
                "sla_prioridade":   sla_prioridade,
                "gravidade":        achado.get("_gravidade_texto", ""),
                "confianca_bandit": achado.get("_confianca", ""),
            })

    except Exception:
        app.logger.exception("Falha ao consolidar achados do SAST no banco")
        # Falha no meio do loop: faz rollback, marca scan como erro e fecha conn.
        conn.rollback()
        conn.execute(
            "UPDATE scans SET status = 'erro', data_fim = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_id)
        )
        conn.commit()
        conn.close()
        return jsonify({
            "scan_id": scan_id,
            "status": "erro",
            "erro": "Falha interna ao consolidar os achados.",
            "parcialmente_inseridos": len(ids_inseridos),
        }), 500

    # Finaliza o scan
    data_fim = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE scans SET status = 'concluido', total_achados = ?, data_fim = ? WHERE id = ?",
        (len(ids_inseridos), data_fim, scan_id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "scan_id":                          scan_id,
        "status":                           "concluido",
        "nome_arquivo":                     nome_arquivo,
        "total_arquivos_analisados":        resultado_sast.get("total_arquivos", 1),
        "total_vulnerabilidades_encontradas": len(ids_inseridos),
        "achados_descartados":              resultado_sast.get("achados_descartados", 0),
        "triagem_aplicada":                 resultado_sast.get("triagem_aplicada", False),
        "vulnerabilidades":                 achados_resumo,
        "data_inicio":                      data_inicio,
        "data_fim":                         data_fim,
    }), 201


@app.route('/scanner/analisar-url', methods=['POST'])
@jwt_required()
@limiter.limit(os.environ.get("RATELIMIT_DAST", "3 per hour"), key_func=rate_limit_usuario)
def scanner_analisar_url():
    """Fase 4 — DAST: recebe uma URL de sistema alvo via JSON, executa
    Spider + Active Scan através da API HTTP do OWASP ZAP (com fallback
    simulado caso o daemon do ZAP não esteja rodando localmente) e insere
    os achados na tabela 'vulnerabilidades' existente.

    Corpo JSON esperado:
        { "url": "https://site-homologacao.com" }

    Retorna JSON com resumo do scan e lista de vulnerabilidades encontradas.
    """
    # — Validação da entrada —
    dados_requisicao = request.get_json(silent=True) or {}
    url_alvo = (dados_requisicao.get('url') or '').strip()

    if not url_alvo:
        return jsonify({"erro": "Campo 'url' não encontrado no corpo da requisição."}), 400

    conn = get_db_connection()
    uid = usuario_id_atual(conn)
    data_inicio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Cria registro do scan (status inicial: em_progresso) — reaproveita a
    # mesma tabela 'scans' das Fases 1/2, usando a URL no lugar do nome do arquivo.
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (usuario_id, nome_arquivo, status, data_inicio) "
        "VALUES (?, ?, 'em_progresso', ?) RETURNING id",
        (uid, url_alvo, data_inicio)
    )
    scan_id = cursor.fetchone()["id"]
    conn.commit()

    # — Estágio 2: Varredura DAST via OWASP ZAP (Spider + Active Scan) —
    resultado_dast = scanner.executar_dast(url_alvo)

    # Se houve erro na varredura (URL inválida, alvo bloqueado por política de
    # SSRF, ou falha de comunicação com o ZAP), encerra o scan com status de erro.
    if resultado_dast["erro"]:
        conn.execute(
            "UPDATE scans SET status = 'erro', data_fim = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_id)
        )
        conn.commit()
        conn.close()

        # Erros de validação de entrada (URL ausente/malformada, host que não
        # resolve, ou alvo bloqueado por apontar para rede interna) são erro
        # do cliente (400). Falha ao comunicar com o ZAP é erro de dependência
        # externa (502) — só essa segunda categoria não é responsabilidade
        # de quem chamou a rota.
        erro_msg = resultado_dast["erro"]
        eh_erro_de_validacao = any(trecho in erro_msg for trecho in (
            "URL inválida", "Informe a URL", "Alvo bloqueado",
            "Não foi possível resolver", "Não foi possível identificar",
            "URL malformada",
        ))
        status_http = 400 if eh_erro_de_validacao else 502

        return jsonify({
            "scan_id": scan_id,
            "status": "erro",
            "erro": erro_msg,
            "url_alvo": url_alvo,
        }), status_http

    # — Estágio 3: (Multi-LLM já aplicado dentro de scanner.executar_dast) —

    # — Estágio 4: Consolidação na tabela vulnerabilidades —
    ids_inseridos = []
    achados_resumo = []

    try:
        for achado in resultado_dast["achados"]:
            # Categoria detectada pela IA local
            categoria = ia.detectar_categoria(achado["nome"])

            score = ia.calcular_risk_index(
                achado["impacto"], achado["frequencia"], achado["gravidade"]
            )
            fatores_achado = {
                "exposta_internet": achado["exposta_internet"],
                "exploit_publico": achado["exploit_publico"],
                "dados_sensiveis": achado["dados_sensiveis"],
                "escalonamento_privilegio": achado["escalonamento_privilegio"],
                "ambiente_producao": achado["ambiente_producao"],
            }

            # Prioridade via motor v2 (tripartido) quando CVSS disponível
            cvss = achado["cvss_score"]
            if cvss > 0:
                prioridade, nivel_sla, sla_prazo_dias, explicacao_fatores = \
                    ia.calcular_prioridade_v2(
                        cvss,
                        achado["epss_score"],
                        achado["no_kev"],
                        fatores_achado,
                        risk_index_base=score,
                        epss_disponivel=False,
                    )
                sla_prioridade = nivel_sla
            else:
                prioridade, explicacao_fatores = ia.calcular_prioridade(score, fatores_achado)
                sla_prioridade, sla_prazo_dias = ia.classificar_sla(prioridade)

            # A explicação fica curta; detalhes técnicos do ZAP são preservados
            # separadamente para a tela de análise.
            explicacao_texto = " | ".join(explicacao_fatores)
            detalhes_scanner = serializar_detalhes_scanner(achado, "dast")
            data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO vulnerabilidades
                    (nome, impacto, frequencia, gravidade, score, status, data,
                     exposta_internet, exploit_publico, dados_sensiveis,
                     escalonamento_privilegio, ambiente_producao,
                     categoria, prioridade, explicacao, origem, ativo,
                     cvss_score, epss_score, cve_id, no_kev,
                     sla_prazo_dias, sla_prioridade,
                     usuario_id, origem_scan, confianca_ia, detalhes_scanner)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING id
            ''', (
                achado["nome"],
                achado["impacto"],
                achado["frequencia"],
                achado["gravidade"],
                score,
                "Aberta",
                data_atual,
                int(achado["exposta_internet"]),
                int(achado["exploit_publico"]),
                int(achado["dados_sensiveis"]),
                int(achado["escalonamento_privilegio"]),
                int(achado["ambiente_producao"]),
                categoria,
                prioridade,
                explicacao_texto,
                achado["origem"],
                achado["ativo"],
                achado["cvss_score"],
                achado["epss_score"],
                achado["cve_id"],
                int(achado["no_kev"]),
                sla_prazo_dias,
                sla_prioridade,
                uid,
                scan_id,
                achado.get("confianca_ia", 0.0),
                detalhes_scanner,
            ))
            vuln_id = cursor.fetchone()["id"]
            conn.commit()

            registrar_historico(
                vuln_id,
                f"Detectada via DAST/OWASP ZAP (scan #{scan_id}) — Severidade {achado.get('_gravidade_texto', '')}",
                "Scanner Automatizado"
            )
            ids_inseridos.append(vuln_id)

            achados_resumo.append({
                "vuln_id":         vuln_id,
                "nome":            achado["nome"],
                "url":             achado["ativo"],
                "cwe":             f"CWE-{achado.get('_cwe_id', '')}" if achado.get('_cwe_id') else "",
                "cvss_score":      achado["cvss_score"],
                "prioridade":      prioridade,
                "sla_prioridade":  sla_prioridade,
                "gravidade":       achado.get("_gravidade_texto", ""),
                "confianca_zap":   achado.get("_confianca", ""),
            })

    except Exception:
        app.logger.exception("Falha ao consolidar achados do DAST no banco")
        # Falha no meio do loop: faz rollback, marca scan como erro e fecha conn.
        conn.rollback()
        conn.execute(
            "UPDATE scans SET status = 'erro', data_fim = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_id)
        )
        conn.commit()
        conn.close()
        return jsonify({
            "scan_id": scan_id,
            "status": "erro",
            "erro": "Falha interna ao consolidar os achados.",
            "parcialmente_inseridos": len(ids_inseridos),
        }), 500

    # Finaliza o scan
    data_fim = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE scans SET status = 'concluido', total_achados = ?, data_fim = ? WHERE id = ?",
        (len(ids_inseridos), data_fim, scan_id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "scan_id":                            scan_id,
        "status":                             "concluido",
        "url_alvo":                           url_alvo,
        "total_alertas_zap":                  resultado_dast.get("total_alertas", 0),
        "total_vulnerabilidades_encontradas": len(ids_inseridos),
        "achados_descartados":                resultado_dast.get("achados_descartados", 0),
        "triagem_aplicada":                   resultado_dast.get("triagem_aplicada", False),
        "zap_mock_usado":                     resultado_dast.get("mock_usado", False),
        "vulnerabilidades":                   achados_resumo,
        "data_inicio":                        data_inicio,
        "data_fim":                           data_fim,
    }), 201



# ─────────────────────────────────────────────
# INICIALIZAÇÃO
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("Iniciando a API SecureScope com IA...")
    # O app.run deve ser a ÚLTIMA coisa do ficheiro
    debug_ativo = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=debug_ativo and not IS_PRODUCTION, use_reloader=False)
