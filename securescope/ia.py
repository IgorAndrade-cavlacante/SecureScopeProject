import numpy as np
from datetime import datetime


#Palavras chaves pra ia entender os bgl

REGRAS_CATEGORIAS = {
    "Acesso e Autenticação": {
        "keywords": ["senha", "login", "autenticação", "token", "bypass", "permissão", "auth", "credencial"],
        "impacto": 85,
        "frequencia": 60,
        "gravidade": 80
    },
    "Injeção e Scripts": {
        "keywords": ["sql", "xss", "injeção", "injection", "script", "comando", "rce", "exec"],
        "impacto": 90,
        "frequencia": 45,
        "gravidade": 85
    },
    "Exposição de Dados": {
        "keywords": ["vazamento", "exposição", "dados", "lgpd", "pessoal", "caminho", "diretório", "leak"],
        "impacto": 80,
        "frequencia": 50,
        "gravidade": 75
    },
    "Dependências e Supply Chain": {
        "keywords": ["dependência", "dependency", "package", "biblioteca", "versão", "outdated", "supply", "pacote"],
        "impacto": 75,
        "frequencia": 70,
        "gravidade": 70
    },
    "Criptografia": {
        "keywords": ["criptografia", "ssl", "tls", "certificado", "hash", "md5", "sha", "chave", "encrypt"],
        "impacto": 80,
        "frequencia": 40,
        "gravidade": 85
    },
    "Configuração": {
        "keywords": ["configuração", "config", "default", "hardcoded", "variável", "env", "segredo", "secret"],
        "impacto": 70,
        "frequencia": 55,
        "gravidade": 65
    }
}

VALORES_PADRAO = {
    "impacto": 50,
    "frequencia": 50,
    "gravidade": 50,
    "categoria": "Geral/Desconhecida"
}

# Guia de remediação por categoria: passos concretos, em ordem de execução.
GUIAS_REMEDIACAO = {
    "Acesso e Autenticação": [
        "Implementar autenticação multifator (MFA) nos pontos afetados.",
        "Revisar política de expiração e complexidade de senhas/tokens.",
        "Aplicar o princípio do menor privilégio nas permissões concedidas."
    ],
    "Injeção e Scripts": [
        "Validar e sanitizar todas as entradas de usuário (allowlist, não blocklist).",
        "Usar queries parametrizadas / prepared statements no lugar de concatenação.",
        "Aplicar Content Security Policy (CSP) para mitigar XSS."
    ],
    "Exposição de Dados": [
        "Classificar os dados e restringir acesso por necessidade (need-to-know).",
        "Criptografar dados sensíveis em repouso e em trânsito.",
        "Revisar logs e respostas de API para evitar exposição acidental (LGPD)."
    ],
    "Dependências e Supply Chain": [
        "Atualizar a biblioteca/pacote para a versão corrigida mais recente.",
        "Adicionar a dependência ao pipeline de SCA para monitoramento contínuo.",
        "Avaliar dependências transitivas que também possam estar vulneráveis."
    ],
    "Criptografia": [
        "Substituir algoritmos fracos (MD5/SHA1) por padrões atuais (SHA-256+, bcrypt/argon2).",
        "Garantir certificados válidos e TLS 1.2+ em todas as conexões.",
        "Rotacionar imediatamente chaves e segredos que possam ter sido comprometidos."
    ],
    "Configuração": [
        "Remover credenciais/segredos hardcoded do código-fonte.",
        "Mover configurações sensíveis para variáveis de ambiente ou secret manager.",
        "Revisar configurações padrão (default) antes de qualquer deploy em produção."
    ],
}

GUIA_REMEDIACAO_PADRAO = [
    "Investigar manualmente a causa raiz da vulnerabilidade.",
    "Classificar o ativo afetado quanto à criticidade de negócio.",
    "Definir prazo de correção proporcional ao Risk Index™."
]

# Peso (pontos) que cada fator de contexto soma na Priority Score, e o texto
# usado na explicabilidade. Pesos seguem a lógica de priorização citada no
# briefing: exposição na internet, exploit ativo, movimentação lateral,
# dados sensíveis, escalonamento de privilégio e ambiente de produção.
PESOS_FATORES_CONTEXTO = {
    "exposta_internet":         (8,  "Ativo exposto diretamente na internet"),
    "exploit_publico":          (10, "Exploit público disponível para a falha"),
    "dados_sensiveis":          (6,  "Vulnerabilidade envolve dados sensíveis"),
    "escalonamento_privilegio": (7,  "Permite escalonamento de privilégio"),
    "ambiente_producao":        (5,  "Ativo está em ambiente de produção"),
}

def calcular_risk_index(impacto, frequencia, gravidade):
    """Calcula o Risk Index™ usando a mesma fórmula do sistema."""
    return round((impacto * 0.4) + (frequencia * 0.3) + (gravidade * 0.3), 2)

def detectar_categoria(nome):
    """Compara o nome digitado com as palavras-chave e retorna a categoria
    com mais matches. Não sabendo classificar, retorna 'Geral/Desconhecida'."""
    if not nome:
        return "Geral/Desconhecida"

    nome_lower = nome.lower()
    melhor_categoria = None
    maior_matches = 0

    for categoria, dados in REGRAS_CATEGORIAS.items():
        matches = sum(1 for kw in dados["keywords"] if kw in nome_lower)
        if matches > maior_matches:
            maior_matches = matches
            melhor_categoria = categoria

    return melhor_categoria or "Geral/Desconhecida"

def analisar_nome(nome):

    #Vai ver o nome que foi digitado e comparar com as palavra chave lá em cima

    categoria = detectar_categoria(nome)

    if categoria == "Geral/Desconhecida":
        return dict(VALORES_PADRAO)

    dados = REGRAS_CATEGORIAS[categoria]
    return {
        "categoria": categoria,
        "impacto": dados["impacto"],
        "frequencia": dados["frequencia"],
        "gravidade": dados["gravidade"],
        "risk_index_sugerido": calcular_risk_index(
            dados["impacto"], dados["frequencia"], dados["gravidade"]
        )
    }

def gerar_guia_remediacao(categoria):
    """Retorna os passos de remediação recomendados para a categoria dada,
    em ordem de execução."""
    return GUIAS_REMEDIACAO.get(categoria, GUIA_REMEDIACAO_PADRAO)

# M1 — Tabela de SLAs por nível de prioridade (NIST SP 800-53 SI-2 / ISO 27001 A.8.8)
# P0 = exploração ativa confirmada (CISA KEV), P1-P4 por score de risco real.
PESOS_SLA = {
    "P0": 1,    # 24-72 horas (KEV Override: exploração ativa)
    "P1": 15,   # 15 dias
    "P2": 30,   # 30 dias
    "P3": 90,   # 90 dias
    "P4": 180,  # 180 dias ou aceite de risco
}

def calcular_prioridade_v2(cvss, epss, no_kev, fatores, criticidade_ativo=1.0):
    """
    M1 — Motor de priorização tripartido (estado da arte ASPM 2024-2026):
      Rp = [(CVSS × 0.30) + (EPSS × 100 × 0.70)] × C_ativo × E_fator

    Baseado na metodologia documentada em plataformas como CrowdStrike Falcon
    ASPM e Palo Alto Prisma Cloud, que combinam:
      - CVSS v4.0: Severidade técnica teórica (base estática)
      - EPSS v3 (FIRST): Probabilidade de exploração nos próximos 30 dias
      - CISA KEV: Exploração ativa confirmada em produção (urgente máxima)

    Retorna: (score, nivel_sla, prazo_dias, explicacao)
    """
    cvss = float(cvss or 0.0)
    epss = float(epss or 0.0)
    fatores = fatores or {}

    # KEV Override — se na lista CISA, prioridade máxima automática (P0)
    if no_kev:
        explicacao = [
            "KEV Override: vulnerabilidade com exploração ativa confirmada (CISA KEV).",
            f"CVSS: {cvss} | EPSS: {epss:.2%} | Ativo Crítico: {'Sim' if criticidade_ativo > 1 else 'Não'}",
            "SLA P0 atribuído automaticamente — remediação em até 72 horas."
        ]
        return 100.0, "P0", PESOS_SLA["P0"], explicacao

    # Score base ponderado (CVSS 30% + EPSS 70%)
    score_base = (cvss * 0.30) + (epss * 100 * 0.70)

    # Fator de exposição na internet (dobra o risco quando ativo está exposto)
    e_fator = 2.0 if fatores.get("exposta_internet") else 1.0

    # Score final limitado a 100
    rp = round(min(score_base * criticidade_ativo * e_fator, 100.0), 1)

    # Determinar nível SLA por score
    if rp >= 90 or (cvss >= 9.0 and epss >= 0.50):
        nivel = "P1"
    elif rp >= 70 or (cvss >= 7.0 and epss >= 0.30):
        nivel = "P2"
    elif rp >= 40:
        nivel = "P3"
    else:
        nivel = "P4"

    explicacao = [
        f"CVSS: {cvss:.1f} (peso 30% → {cvss * 0.30:.1f} pts)",
        f"EPSS: {epss:.2%} (peso 70% → {epss * 100 * 0.70:.1f} pts)",
        f"Score Base: {score_base:.1f} | Fator Exposição: {e_fator}x",
        f"Priority Score Final: {rp} → Nível {nivel} (SLA: {PESOS_SLA[nivel]} dias)"
    ]

    return rp, nivel, PESOS_SLA[nivel], explicacao


def calcular_prioridade(risk_index_base, fatores):
    """
    Motor de priorização legado: mantido para compatibilidade retroativa com
    registros antigos que não possuem CVSS/EPSS. Para novos registros, o
    endpoint usa calcular_prioridade_v2() quando cvss_score > 0.
    Retorna a Priority Score final (0-100) e a explicação passo a passo.
    """
    fatores = fatores or {}
    prioridade = float(risk_index_base)
    explicacao = [f"Base (Risk Index™): {risk_index_base:.1f} pontos"]

    for chave, (peso, descricao) in PESOS_FATORES_CONTEXTO.items():
        if fatores.get(chave):
            prioridade += peso
            explicacao.append(f"+{peso} pontos — {descricao}")

    prioridade = round(min(prioridade, 100.0), 1)
    return prioridade, explicacao

def correlacionar_historico(conn, categoria, status_ignorados=("Isolada (Circuit Breaker)",)):
    """
    Correlação de risco: verifica quantas vulnerabilidades da MESMA categoria
    já estão registradas (e ainda relevantes, ou seja, não isoladas). Se o
    padrão se repete, é sinal de falha sistêmica na esteira de desenvolvimento
    — não é só "mais uma vulnerabilidade", é um problema recorrente.
    """
    if categoria == "Geral/Desconhecida":
        return {"ocorrencias": 0, "alerta": False, "mensagem": None}

    placeholders = ",".join("?" for _ in status_ignorados)
    query = f"""
        SELECT COUNT(*) as c FROM vulnerabilidades
        WHERE categoria = ? AND status NOT IN ({placeholders})
    """
    cursor = conn.cursor()
    cursor.execute(query, (categoria, *status_ignorados))
    row = cursor.fetchone()

    try:
        ocorrencias = row["c"]
    except (TypeError, IndexError):
        ocorrencias = row[0]

    alerta = ocorrencias >= 2  # já existiam 2+ antes desta nova entrada
    mensagem = None
    if alerta:
        mensagem = (
            f"Padrão recorrente detectado: já existem {ocorrencias} "
            f"vulnerabilidade(s) da categoria '{categoria}' em aberto. "
            "Considere uma revisão sistêmica nessa área, não só a correção pontual."
        )

    return {"ocorrencias": ocorrencias, "alerta": alerta, "mensagem": mensagem}

# ─────────────────────────────────────────────
# WIZARD INTERATIVO — a IA pergunta, o analista responde
# ─────────────────────────────────────────────
# Cada categoria tem 5 perguntas na MESMA ordem dos fatores de contexto
# (exposta_internet, exploit_publico, dados_sensiveis,
# escalonamento_privilegio, ambiente_producao), mas com a redação adaptada
# ao tipo de vulnerabilidade — isso é o que torna a IA "conversacional" em
# vez de um formulário de checkboxes genérico.

PERGUNTAS_CONTEXTO = {
    "Acesso e Autenticação": [
        ("exposta_internet", "Esse ponto de acesso está exposto diretamente na internet?"),
        ("exploit_publico", "Existe algum exploit público conhecido pra esse tipo de falha de autenticação?"),
        ("dados_sensiveis", "Um invasor autenticado indevidamente chegaria a dados sensíveis?"),
        ("escalonamento_privilegio", "Essa falha permite virar administrador ou escalar privilégios?"),
        ("ambiente_producao", "Esse sistema já está rodando em produção?"),
    ],
    "Injeção e Scripts": [
        ("exposta_internet", "Esse formulário ou endpoint está acessível pela internet?"),
        ("exploit_publico", "Existe um exploit ou PoC público pra esse tipo de injeção?"),
        ("dados_sensiveis", "A injeção pode expor ou manipular dados sensíveis no banco?"),
        ("escalonamento_privilegio", "Dá pra usar essa injeção pra escalar privilégios no sistema?"),
        ("ambiente_producao", "Esse código já está publicado em produção?"),
    ],
    "Exposição de Dados": [
        ("exposta_internet", "Esses dados estão acessíveis publicamente pela internet?"),
        ("exploit_publico", "Existe alguma forma pública ou documentada de explorar essa exposição?"),
        ("dados_sensiveis", "Os dados expostos são pessoais, financeiros ou confidenciais?"),
        ("escalonamento_privilegio", "Alguém com esse acesso indevido conseguiria escalar privilégios?"),
        ("ambiente_producao", "Esses dados pertencem a um ambiente de produção real?"),
    ],
    "Dependências e Supply Chain": [
        ("exposta_internet", "A aplicação que usa essa biblioteca está exposta na internet?"),
        ("exploit_publico", "Essa biblioteca tem uma CVE pública com exploit conhecido?"),
        ("dados_sensiveis", "Essa dependência tem acesso a dados sensíveis da aplicação?"),
        ("escalonamento_privilegio", "Uma falha nessa dependência pode causar escalonamento de privilégio?"),
        ("ambiente_producao", "Essa biblioteca está em uso em produção (não só em dev/teste)?"),
    ],
    "Criptografia": [
        ("exposta_internet", "A comunicação afetada trafega pela internet pública?"),
        ("exploit_publico", "Existe uma técnica pública conhecida pra quebrar esse algoritmo/configuração?"),
        ("dados_sensiveis", "Essa criptografia protege dados sensíveis, como senhas ou cartões?"),
        ("escalonamento_privilegio", "Quebrar essa criptografia poderia levar a escalonamento de privilégio?"),
        ("ambiente_producao", "Está configurado assim em produção?"),
    ],
    "Configuração": [
        ("exposta_internet", "Esse recurso mal configurado está acessível pela internet?"),
        ("exploit_publico", "Existe um método público conhecido pra abusar dessa configuração?"),
        ("dados_sensiveis", "Essa configuração dá acesso a dados sensíveis?"),
        ("escalonamento_privilegio", "Ela permite escalonamento de privilégio?"),
        ("ambiente_producao", "Essa configuração está assim em produção?"),
    ],
}

PERGUNTAS_PADRAO = [
    ("exposta_internet", "Esse ativo está exposto diretamente na internet?"),
    ("exploit_publico", "Existe um exploit público conhecido pra essa falha?"),
    ("dados_sensiveis", "Essa vulnerabilidade envolve dados sensíveis?"),
    ("escalonamento_privilegio", "Ela permite escalonamento de privilégio?"),
    ("ambiente_producao", "O ativo afetado está em ambiente de produção?"),
]

def gerar_perguntas_contexto(categoria):
    """Retorna as 5 perguntas do wizard, adaptadas à categoria detectada,
    na ordem que corresponde aos fatores de PESOS_FATORES_CONTEXTO."""
    perguntas = PERGUNTAS_CONTEXTO.get(categoria, PERGUNTAS_PADRAO)
    return [{"chave": chave, "pergunta": texto} for chave, texto in perguntas]

# ─────────────────────────────────────────────
# ORIGEM DO ACHADO — simula a ingestão multi-fonte de um ASPM real
# ─────────────────────────────────────────────
# O ASPM não substitui SAST/DAST/SCA/CSPM — ele conecta e centraliza o que
# essas ferramentas encontram. Como aqui o cadastro é manual, o analista
# marca de qual categoria de ferramenta o achado "veio".

ORIGENS_VALIDAS = (
    "Manual/Pentest",
    "SAST (código-fonte)",
    "DAST (aplicação em execução)",
    "SCA (dependências/bibliotecas)",
    "Container Scan",
    "CSPM (postura cloud)",
    "API Security",
    "Pipeline/IaC",
)

def correlacionar_por_ativo(conn, ativo, status_ignorados=("Isolada (Circuit Breaker)",)):
    """
    Correlação de risco por ATIVO: se o mesmo sistema/API/serviço já acumula
    várias vulnerabilidades em aberto, isso é sinal de um ativo crítico que
    concentra risco — não só "mais uma falha isolada".
    """
    if not ativo or not ativo.strip():
        return {"ocorrencias": 0, "alerta": False, "mensagem": None}

    placeholders = ",".join("?" for _ in status_ignorados)
    query = f"""
        SELECT COUNT(*) as c FROM vulnerabilidades
        WHERE ativo = ? AND status NOT IN ({placeholders})
    """
    cursor = conn.cursor()
    cursor.execute(query, (ativo, *status_ignorados))
    row = cursor.fetchone()

    try:
        ocorrencias = row["c"]
    except (TypeError, IndexError):
        ocorrencias = row[0]

    alerta = ocorrencias >= 2
    mensagem = None
    if alerta:
        mensagem = (
            f"Ativo concentrador de risco: '{ativo}' já acumula {ocorrencias} "
            "vulnerabilidade(s) em aberto. Considere priorizar esse ativo como um todo."
        )

    return {"ocorrencias": ocorrencias, "alerta": alerta, "mensagem": mensagem}

# ─────────────────────────────────────────────
# DREAD — framework de risco citado no briefing, derivado dos mesmos
# fatores de contexto já coletados (sem pedir dado novo ao analista).
# Cada dimensão vai de 0 a 10.
# ─────────────────────────────────────────────

def calcular_dread(gravidade, frequencia, fatores):
    fatores = fatores or {}

    damage = min(10, round(gravidade / 10
                           + (2 if fatores.get("dados_sensiveis") else 0)
                           + (2 if fatores.get("escalonamento_privilegio") else 0), 1))

    reproducibility = min(10, round(frequencia / 10
                                    + (2 if fatores.get("exploit_publico") else 0), 1))

    exploitability = min(10, 2
                        + (4 if fatores.get("exploit_publico") else 0)
                        + (2 if fatores.get("exposta_internet") else 0)
                        + (2 if fatores.get("ambiente_producao") else 0))

    affected_users = (5 if fatores.get("ambiente_producao") else 0) \
                    + (5 if fatores.get("exposta_internet") else 0)

    discoverability = (6 if fatores.get("exposta_internet") else 0) \
                     + (4 if fatores.get("exploit_publico") else 0)

    dimensoes = [damage, reproducibility, exploitability, affected_users, discoverability]
    media = round(sum(dimensoes) / len(dimensoes), 1)

    return {
        "damage": damage,
        "reproducibility": reproducibility,
        "exploitability": exploitability,
        "affected_users": affected_users,
        "discoverability": discoverability,
        "dread_medio": media,
        "dread_score_100": round(media * 10, 1),
    }

# ─────────────────────────────────────────────
# MONITORAMENTO CONTÍNUO (lite)
# ─────────────────────────────────────────────
# Um ASPM de verdade monitora novos ativos, drift de configuração e
# mudanças de pipeline em tempo real. Sem integrações reais, simulamos a
# parte que é possível com os dados que já temos: idade das vulnerabilidades
# em aberto e concentração de risco por ativo — e a IA age de forma
# PROATIVA gerando alertas sozinha, sem o analista precisar perguntar.

def gerar_alertas_monitoramento(conn, dias_limite=7, prioridade_minima=80):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT nome, data, prioridade, ativo FROM vulnerabilidades
        WHERE status = 'Aberta' AND prioridade >= ?
    """, (prioridade_minima,))
    linhas = cursor.fetchall()

    alertas = []
    agora = datetime.now()

    for linha in linhas:
        try:
            nome, data_str, prioridade, ativo = linha["nome"], linha["data"], linha["prioridade"], linha["ativo"]
        except (TypeError, IndexError):
            nome, data_str, prioridade, ativo = linha[0], linha[1], linha[2], linha[3]

        try:
            data_registro = datetime.strptime(data_str, "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            continue

        dias_aberta = (agora - data_registro).days
        if dias_aberta >= dias_limite:
            local = f" ({ativo})" if ativo else ""
            alertas.append(
                f"'{nome}'{local} está em aberto há {dias_aberta} dia(s) com prioridade "
                f"{prioridade:.0f} e ainda não foi validada nem contida."
            )

    # Concentração de risco por ativo (top 1)
    cursor.execute("""
        SELECT ativo, COUNT(*) as total FROM vulnerabilidades
        WHERE status != 'Isolada (Circuit Breaker)' AND ativo != ''
        GROUP BY ativo ORDER BY total DESC LIMIT 1
    """)
    top_ativo = cursor.fetchone()
    if top_ativo:
        try:
            nome_ativo, total = top_ativo["ativo"], top_ativo["total"]
        except (TypeError, IndexError):
            nome_ativo, total = top_ativo[0], top_ativo[1]

        if total >= 2:
            alertas.append(
                f"Ativo com maior concentração de risco: '{nome_ativo}' ({total} vulnerabilidades em aberto/validadas)."
            )

    return alertas

def aprender_com_historico(conn):
    """
    Lê o banco, pega vulnerabilidades validadas e calcula estatísticas usando numpy.
    Retorna médias, máximos, mínimos e risco médio geral calculado com a fórmula do Risk Index™.
    Achados por origem e alertas de monitoramento são calculados sempre,
    independente de já existir histórico validado ou não.
    """
    try:
        cursor = conn.cursor()

        # Achados por origem — visibilidade de "quantas ferramentas diferentes"
        # estão alimentando o painel (considera TODAS as vulnerabilidades,
        # não só as validadas, pra dar uma visão real de ingestão multi-fonte).
        cursor.execute("""
            SELECT origem, COUNT(*) as total FROM vulnerabilidades
            GROUP BY origem ORDER BY total DESC
        """)
        achados_por_origem = {}
        for linha_origem in cursor.fetchall():
            try:
                origem, total = linha_origem["origem"], linha_origem["total"]
            except (TypeError, IndexError):
                origem, total = linha_origem[0], linha_origem[1]
            achados_por_origem[origem or "Manual/Pentest"] = total

        # Monitoramento contínuo (proativo) olha vulnerabilidades ABERTAS,
        # então não depende de já existir histórico validado.
        alertas_monitoramento = gerar_alertas_monitoramento(conn)

        cursor.execute(
            "SELECT impacto, frequencia, gravidade, score FROM vulnerabilidades WHERE status = 'Validada'"
        )
        linhas = cursor.fetchall()

        if not linhas:
            return {
                "status": "sem_dados",
                "mensagem": "Histórico insuficiente para insights da IA.",
                "achados_por_origem": achados_por_origem,
                "alertas_monitoramento": alertas_monitoramento,
            }

        # Suporte a sqlite3.Row e tuplas
        def extrair(linha, chave, indice):
            try:
                return linha[chave]
            except (TypeError, IndexError):
                return linha[indice]

        impactos    = np.array([extrair(l, 'impacto', 0)    for l in linhas])
        frequencias = np.array([extrair(l, 'frequencia', 1) for l in linhas])
        gravidades  = np.array([extrair(l, 'gravidade', 2)  for l in linhas])
        scores      = np.array([extrair(l, 'score', 3)      for l in linhas])

        return {
            "status": "sucesso",
            "total_analisado": len(linhas),
            "media_impacto":    round(float(np.mean(impactos)), 1),
            "media_frequencia": round(float(np.mean(frequencias)), 1),
            "media_gravidade":  round(float(np.mean(gravidades)), 1),
            "risco_medio_geral": round(float(
                calcular_risk_index(
                    np.mean(impactos),
                    np.mean(frequencias),
                    np.mean(gravidades)
                )
            ), 1),
            "pior_risco":  round(float(np.max(scores)), 1),
            "melhor_risco": round(float(np.min(scores)), 1),
            "achados_por_origem": achados_por_origem,
            "alertas_monitoramento": alertas_monitoramento,
        }

    except Exception as e:
        return {"status": "erro", "mensagem": str(e)}