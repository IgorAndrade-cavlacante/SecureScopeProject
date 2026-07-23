# ANÁLISE CRÍTICA E PLANO DE APERFEIÇOAMENTO PROFISSIONAL
## SecureScope ASPM — Correlação com Pesquisa Acadêmica

**Projeto Analisado:** SecureScope ASPM  
**Base de Referência:** Pesquisa Acadêmica — Governança de Risco de Segurança de Aplicações e Gestão de Vulnerabilidades: Uma Análise Sistemática do Estado da Arte em ASPM (2024–2026)  
**Data da Análise:** Julho de 2026

---

## Sumário Executivo

O SecureScope ASPM é um projeto tecnicamente sólido que demonstra compreensão arquitetural avançada dos pilares de um ASPM real. O sistema implementa corretamente os conceitos de _ingestão multi-fonte_, _correlação por categoria e ativo_, _motor de priorização com explicabilidade_, _wizard conversacional_ e _monitoramento contínuo proativo_.

A análise identificou **7 áreas prioritárias de aperfeiçoamento** que, quando implementadas, elevarão o projeto ao nível de profissionalismo e conformidade esperado por plataformas líderes como Palo Alto Prisma Cloud, CrowdStrike Falcon ASPM e Microsoft Defender for Cloud — todas detalhadas na pesquisa de referência.

---

## Escala de Prioridade das Melhorias

| Código | Prioridade | Impacto |
| :--- | :--- | :--- |
| M1 | CRÍTICA | Modelo de priorização tripartido (CVSS + EPSS + KEV) |
| M2 | ALTA | Auditoria, SLAs e trilha de conformidade completa |
| M3 | ALTA | Sistema de autenticação e segurança da API |
| M4 | MÉDIA | Classificação de maturidade OWASP SAMM |
| M5 | MÉDIA | Relatório PDF enriquecido e com valor de governança |
| M6 | MÉDIA | Endpoint de métricas de KPIs de governança |
| M7 | BAIXA | Corrigir posicionamento CSS com valores absolutos em pixels |

---

## M1 — CRÍTICA: Migrar o Motor de Priorização para o Modelo Tripartido CVSS + EPSS + KEV

### Lacuna Identificada no Código

No arquivo `ia.py`, a função `calcular_prioridade()` (linhas 152 a 170) calcula o _Priority Score_ partindo de um _Risk Index™_ interno baseado em pesos próprios de Impacto, Frequência e Gravidade. O campo `exploit_publico` é um booleano binário que adiciona apenas 10 pontos fixos.

```python
# CÓDIGO ATUAL (ia.py, linha 97-103) — limitação:
PESOS_FATORES_CONTEXTO = {
    "exposta_internet":         (8,  "Ativo exposto diretamente na internet"),
    "exploit_publico":          (10, "Exploit público disponível para a falha"),
    ...
}
```

### Justificativa com Base na Pesquisa

A pesquisa acadêmica de referência — Seção 8 — documenta que o **modelo de priorização moderno e defensável** exige a combinação de três sinais distintos:

- **CVSS v4.0**: Severidade técnica teórica (base estática).
- **EPSS v3** (FIRST): Probabilidade de exploração nos próximos 30 dias (dinâmico, atualizado diariamente por ML).
- **CISA KEV**: Exploração ativa e confirmada em produção (sinal binário de urgência máxima).

> "Estudos operacionais indicam que apenas 2% a 5% das vulnerabilidades divulgadas são efetivamente exploradas em ataques reais. O CVSS isolado torna todas igualmente urgentes — paralisia operacional."  
> — Seção 8, Pesquisa de Referência

Plataformas como o **CrowdStrike Falcon ASPM** e o **Palo Alto Prisma Cloud** (Seção 6 da pesquisa) constroem seus motores de priorização exatamente sobre essa tríade, com adição de contexto de runtime.

### Proposta de Implementação

**1. Adicionar campos CVSS, EPSS e KEV ao banco de dados:**

```sql
-- Adicionar via ALTER TABLE (idempotente, no banco.py):
ALTER TABLE vulnerabilidades ADD COLUMN cvss_score REAL DEFAULT 0.0;
ALTER TABLE vulnerabilidades ADD COLUMN epss_score REAL DEFAULT 0.0;
ALTER TABLE vulnerabilidades ADD COLUMN cve_id TEXT DEFAULT '';
ALTER TABLE vulnerabilidades ADD COLUMN no_kev INTEGER DEFAULT 0;
ALTER TABLE vulnerabilidades ADD COLUMN sla_prazo_dias INTEGER DEFAULT 90;
ALTER TABLE vulnerabilidades ADD COLUMN sla_prioridade TEXT DEFAULT 'P3';
```

**2. Substituir a fórmula linear por modelo ponderado multivariado em `ia.py`:**

```python
# NOVA FÓRMULA — ia.py (substituir calcular_prioridade)
PESOS_SLA = {
    "P0": 1,  # 24-72 horas (KEV + ativo crítico + internet)
    "P1": 15, # 15 dias
    "P2": 30, # 30 dias
    "P3": 90, # 90 dias
    "P4": 180 # 180 dias ou aceite de risco
}

def calcular_prioridade_v2(cvss, epss, no_kev, fatores, criticidade_ativo=1.0):
    """
    Motor de priorização tripartido:
      Rp = [(CVSS × 0.30) + (EPSS × 100 × 0.70)] × C_ativo × E_fator × KEV_modifier
    """
    # KEV Override — se na lista CISA, prioridade máxima automática
    if no_kev:
        return 100.0, "P0", PESOS_SLA["P0"], [
            "KEV Override: vulnerabilidade com exploração ativa confirmada (CISA).",
            f"CVSS: {cvss} | EPSS: {epss:.2%} | Ativo Crítico: {'Sim' if criticidade_ativo > 1 else 'Não'}"
        ]

    # Score base ponderado
    score_base = (cvss * 0.30) + (epss * 100 * 0.70)

    # Fator de exposição
    e_fator = 2.0 if fatores.get("exposta_internet") else 1.0

    # Fator de criticidade do ativo (Tier 0=3.0, Tier 1=2.0, Tier 2=1.0)
    rp = round(min(score_base * criticidade_ativo * e_fator, 100.0), 1)

    # Determinar SLA
    if rp >= 90 or (cvss >= 8.0 and epss >= 0.30):
        nivel = "P1"
    elif rp >= 70:
        nivel = "P2"
    elif rp >= 40:
        nivel = "P3"
    else:
        nivel = "P4"

    explicacao = [
        f"CVSS: {cvss} (peso 30%)",
        f"EPSS: {epss:.2%} → {epss*100:.1f} pts (peso 70%)",
        f"Score Base: {score_base:.1f}",
        f"Fator de Exposição: {e_fator}x",
        f"Fator de Criticidade do Ativo: {criticidade_ativo}x",
        f"Priority Score Final: {rp} → Nível {nivel} (SLA: {PESOS_SLA[nivel]} dias)"
    ]

    return rp, nivel, PESOS_SLA[nivel], explicacao
```

**3. Atualizar o formulário frontend para receber CVE ID, CVSS e EPSS:**

```html
<!-- Adicionar ao index.html dentro do form-grid -->
<div class="form-group">
    <label>CVE ID (opcional)</label>
    <input type="text" id="cve_id" placeholder="Ex: CVE-2024-12345" />
</div>
<div class="form-group">
    <label>CVSS Score (0-10)</label>
    <input type="number" id="cvss_score" min="0" max="10" step="0.1" value="0" />
</div>
<div class="form-group">
    <label>EPSS Score (0.00 a 1.00)</label>
    <input type="number" id="epss_score" min="0" max="1" step="0.001" value="0" />
</div>
```

> **Impacto Esperado:** O painel passará a comunicar ao analista e ao board não apenas "o quão grave é" a vulnerabilidade, mas "qual a probabilidade real de ela ser explorada esta semana", alinhando-se diretamente ao que Gartner e FIRST recomendam como estado da arte em 2025.

---

## M2 — ALTA: Implementar Trilha de Auditoria Completa e SLAs Formais

### Lacuna Identificada no Código

A tabela `historico` em `banco.py` (linhas 31-40) registra ações, mas de forma incompleta para fins de auditoria regulatória. O `responsavel` é preenchido como string estática (`"API System"`, `"Analista Blue Team"`), sem identificação real do usuário. Não existe rastreamento de prazos de remediação (SLA) nem alerta quando um SLA é violado.

A função `registrar_historico()` em `app.py` (linhas 20-28) é chamada em apenas 3 momentos (criação, validação e circuit breaker), deixando as alterações de status sem registro granular.

### Justificativa com Base na Pesquisa

A pesquisa de referência — Seção 5.1 — cita explicitamente o controle **NIST SP 800-53 SI-2(2)** (_Automated Flaw Remediation Status_) que exige rastreamento automatizado do status de correção de falhas, e o **CA-7** (_Continuous Monitoring_), que demanda evidências auditáveis de monitoramento.

A **ISO/IEC 27001:2022, Controle A.8.8** (Seção 5.2 da pesquisa) determina que "medidas apropriadas devem ser tomadas de acordo com o risco associado", subentendendo que a tomada de decisão deve ser rastreável e temporizada.

Plataformas como **GitHub Advanced Security** e **GitLab Ultimate** (Seção 6 da pesquisa) fazem do "audit trail unificado" um diferencial competitivo central, especialmente para setores regulados.

### Proposta de Implementação

**1. Enriquecer o schema da tabela historico:**

```sql
-- No banco.py, adicionar colunas à tabela historico:
ALTER TABLE historico ADD COLUMN ip_origem TEXT DEFAULT '';
ALTER TABLE historico ADD COLUMN dados_anteriores TEXT DEFAULT '';
ALTER TABLE historico ADD COLUMN dados_novos TEXT DEFAULT '';
```

**2. Adicionar tabela de SLAs:**

```sql
CREATE TABLE IF NOT EXISTS sla_vulnerabilidades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerabilidade_id INTEGER NOT NULL,
    nivel_sla TEXT NOT NULL,         -- P0, P1, P2, P3, P4
    prazo_dias INTEGER NOT NULL,
    data_inicio TEXT NOT NULL,
    data_prazo TEXT NOT NULL,
    data_resolucao TEXT,             -- NULL se ainda em aberto
    status_sla TEXT DEFAULT 'Em Prazo',  -- 'Em Prazo', 'Em Risco', 'Violado', 'Cumprido'
    FOREIGN KEY(vulnerabilidade_id) REFERENCES vulnerabilidades(id)
);
```

**3. Endpoint de status de SLAs — novo em `app.py`:**

```python
@app.route('/sla/status', methods=['GET'])
def status_slas():
    """Retorna todas as vulnerabilidades com status de SLA calculado em tempo real."""
    conn = get_db_connection()
    agora = datetime.now()
    
    vulns = conn.execute(
        "SELECT id, nome, sla_prioridade, sla_prazo_dias, data, status FROM vulnerabilidades "
        "WHERE status NOT IN ('Isolada (Circuit Breaker)')"
    ).fetchall()
    
    resultados = []
    for v in vulns:
        data_registro = datetime.strptime(v["data"], "%Y-%m-%d %H:%M:%S")
        prazo = data_registro + timedelta(days=v["sla_prazo_dias"])
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
            "nivel": v["sla_prioridade"],
            "prazo_dias": v["sla_prazo_dias"],
            "dias_restantes": dias_restantes,
            "status_sla": status_sla
        })
    
    conn.close()
    return jsonify(resultados), 200
```

**4. Novo bloco no painel de Insights da IA (index.html) — Widget de SLAs:**

```html
<div class="ia-stat-box sla-widget" id="sla-status-box">
    SLAs em Risco / Violados
    <strong id="sla-criticos">--</strong>
    <small id="sla-lista"></small>
</div>
```

> **Impacto Esperado:** O sistema passará a ter uma trilha de auditoria defensável perante ISO 27001 e NIST, com SLAs formais por nível de prioridade — exatamente o que o painel executivo (CISO/Board) precisa para reportar conformidade ao conselho de administração.

---

## M3 — ALTA: Adicionar Autenticação e Segurança à API

### Lacuna Identificada no Código

Em `app.py`, linha 9, a configuração `CORS(app)` aceita requisições de qualquer origem (`*`). Não há nenhuma camada de autenticação nos endpoints da API. Qualquer pessoa com acesso à rede pode ler, criar, validar ou acionar o circuit breaker de qualquer vulnerabilidade sem qualquer credencial.

A Home Page (`Home.html`, linhas 89-95) possui botões de "Criar Conta" e "Login" que redirecionam para `#` — sem implementação real.

### Justificativa com Base na Pesquisa

A pesquisa de referência — Seção 8.3 — cita o framework DREAD justamente como mecanismo para avaliar _Discoverability_ (facilidade de descoberta). Uma API aberta sem autenticação maximiza o score DREAD de qualquer vulnerabilidade interna.

O **NIST SP 800-53, Controle RA-5(4)** (Seção 5.1 da pesquisa) exige controle sobre _"Discoverable Information"_, evitando que a superfície de ataque seja exposta acidentalmente.

Adicionalmente, a **ISO/IEC 27001:2022, Controle A.8.3** exige controle de acesso à informação baseado em identidade verificada.

### Proposta de Implementação

**1. Instalar Flask-JWT-Extended:**

```bash
pip install flask-jwt-extended
```

**2. Implementar autenticação por token em `app.py`:**

```python
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET", "securescope-dev-key-troque-em-prod")
jwt = JWTManager(app)

# Usuários (em produção: migrar para banco com senha hashed)
USUARIOS = {
    "admin": {"senha": "hash_aqui", "role": "admin"},
    "analista": {"senha": "hash_aqui", "role": "analyst"}
}

@app.route('/auth/login', methods=['POST'])
def login():
    dados = request.get_json()
    usuario = dados.get("usuario", "")
    senha = dados.get("senha", "")
    
    if usuario in USUARIOS and check_password_hash(USUARIOS[usuario]["senha"], senha):
        token = create_access_token(identity={"usuario": usuario, "role": USUARIOS[usuario]["role"]})
        return jsonify({"access_token": token}), 200
    
    return jsonify({"erro": "Credenciais inválidas."}), 401

# Proteger rotas críticas:
@app.route('/vulnerabilidades', methods=['POST'])
@jwt_required()
def adicionar_vulnerabilidade():
    # ... código existente mantido
```

**3. CORS restritivo:**

```python
# Substituir CORS(app) por:
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5500", "http://127.0.0.1:5500"]}})
```

> **Impacto Esperado:** O sistema passará a ter controle de acesso mínimo viável, transformando a aplicação de um protótipo em um sistema com postura de segurança adequada para ambientes reais. Este ponto é especialmente importante para a apresentação acadêmica — demonstra maturidade arquitetural.

---

## M4 — MÉDIA: Implementar Endpoint de Score de Maturidade OWASP SAMM

### Lacuna Identificada no Código

O sistema não possui um mecanismo para medir ou reportar a maturidade do próprio programa de segurança de aplicações que ele gerencia. O painel atual mostra métricas técnicas (Risk Index™, DREAD, Prioridade), mas não oferece uma visão de maturidade do processo ao longo do tempo.

### Justificativa com Base na Pesquisa

A pesquisa de referência — Seção 5.3 — documenta o **OWASP SAMM v2** como o _"gold standard para avaliar e melhorar o programa de software assurance"_, estruturado em 5 funções de negócio com níveis 0 a 3.

A pesquisa também cita como KPI de governança (Seção 9.1) o **SAMM Maturity Score**, definindo-o como a "percentagem de aplicações ou features que passaram por modelagem formal de ameaças".

Plataformas como **ArmorCode** e **Checkmarx One** (Seção 6) exibem scores de maturidade de programa como diferenciais competitivos em seus dashboards executivos.

### Proposta de Implementação

**Novo endpoint em `app.py`:**

```python
@app.route('/governance/maturity', methods=['GET'])
def calcular_maturidade_samm():
    """
    Calcula um Score de Maturidade SAMM simplificado com base nos dados disponíveis.
    Nível 0 = Inexistente | Nível 1 = Básico | Nível 2 = Gerenciado | Nível 3 = Otimizado
    """
    conn = get_db_connection()
    total = conn.execute("SELECT COUNT(*) FROM vulnerabilidades").fetchone()[0]
    validadas = conn.execute("SELECT COUNT(*) FROM vulnerabilidades WHERE status='Validada'").fetchone()[0]
    com_sla = conn.execute("SELECT COUNT(*) FROM vulnerabilidades WHERE sla_prioridade IS NOT NULL AND sla_prioridade != ''").fetchone()[0]
    com_ativo = conn.execute("SELECT COUNT(*) FROM vulnerabilidades WHERE ativo != ''").fetchone()[0]
    origens_distintas = conn.execute("SELECT COUNT(DISTINCT origem) FROM vulnerabilidades").fetchone()[0]
    conn.close()

    if total == 0:
        return jsonify({"nivel": 0, "descricao": "Sem dados suficientes para avaliação."}), 200

    score = 0
    detalhes = []

    # Nível 1: Processo básico — vulnerabilidades sendo registradas
    if total > 0:
        score += 1
        detalhes.append("Nível 1 atingido: registro de vulnerabilidades ativo.")

    # Nível 2: Processo gerenciado — validação e múltiplas origens
    taxa_validacao = validadas / total
    if taxa_validacao >= 0.5 and origens_distintas >= 2:
        score += 1
        detalhes.append(f"Nível 2 atingido: {taxa_validacao:.0%} de validação | {origens_distintas} origens distintas.")

    # Nível 3: Processo otimizado — SLAs, ativos mapeados e correlação ativa
    taxa_com_ativo = com_ativo / total
    taxa_com_sla = com_sla / total
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
        "origens_distintas": origens_distintas
    }), 200
```

> **Impacto Esperado:** O painel ganha um KPI de alto valor executivo — "em que nível de maturidade de segurança nossa organização está?" — exatamente o que CISOs apresentam ao board de administração, conforme documentado na Seção 3 da pesquisa.

---

## M5 — MÉDIA: Enriquecer o Relatório PDF com Dados de Governança

### Lacuna Identificada no Código

A função `gerarRelatorio()` em `script.js` (linhas 435-482) gera um PDF com apenas 6 colunas básicas: Nome, Impacto, Frequência, Gravidade, Risk Index™ e Status. Toda a riqueza do motor de IA (DREAD, Prioridade, SLA, Origem, Ativo, Explicação) é descartada do relatório.

### Justificativa com Base na Pesquisa

A pesquisa de referência — Seção 8.3 — define que um relatório de governança de alto nível deve obrigatoriamente conter:

- Distribuição de risco por severidade e nível de SLA
- Status de conformidade por framework (pelo menos referência ao CVSS/EPSS)
- Análise de ativos concentradores de risco (_Crown Jewels_)

A pesquisa também cita (Seção 8.3) que painéis como **Mend.io** e **OpenText** automatizam geração de _audit-ready reports_ que demonstram progresso de remediação para stakeholders, indo muito além de uma simples tabela de vulnerabilidades.

### Proposta de Implementação

**Substituir a função `gerarRelatorio()` em `script.js`:**

```javascript
async function gerarRelatorio() {
    try {
        const [resVulns, resInsights, resSlas] = await Promise.all([
            fetch(`${API_URL}/relatorio`),
            fetch(`${API_URL}/ia/insights`),
            fetch(`${API_URL}/sla/status`)
        ]);

        const dados = await resVulns.json();
        const insights = await resInsights.json();
        const slas = await resSlas.json();

        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        const dataGeracao = new Date().toLocaleString('pt-BR');

        // --- CAPA ---
        doc.setFontSize(20);
        doc.setTextColor(44, 62, 80);
        doc.text('SecureScope ASPM', 14, 20);
        doc.setFontSize(14);
        doc.text('Relatório de Governança de Risco', 14, 30);
        doc.setFontSize(10);
        doc.setTextColor(100);
        doc.text(`Gerado em: ${dataGeracao}`, 14, 38);

        // --- RESUMO EXECUTIVO ---
        doc.setFontSize(12);
        doc.setTextColor(44, 62, 80);
        doc.text('Resumo Executivo', 14, 50);

        const totalVulns = dados.length;
        const criticas = dados.filter(v => (v.prioridade || v.score) >= 90).length;
        const slaViolados = slas.filter(s => s.status_sla === 'Violado').length;
        const slaEmRisco = slas.filter(s => s.status_sla === 'Em Risco').length;

        doc.setFontSize(10);
        doc.setTextColor(60);
        doc.text(`Total de Vulnerabilidades Registradas: ${totalVulns}`, 14, 58);
        doc.text(`Vulnerabilidades com Prioridade Crítica (≥90): ${criticas}`, 14, 64);
        doc.text(`SLAs Violados: ${slaViolados} | Em Risco: ${slaEmRisco}`, 14, 70);

        if (insights.status === 'sucesso') {
            doc.text(`Risco Médio Geral: ${insights.risco_medio_geral} | Pior Risco: ${insights.pior_risco}`, 14, 76);
        }

        // --- TABELA PRINCIPAL ENRIQUECIDA ---
        const linhas = dados.map(v => [
            v.nome.substring(0, 30),
            v.ativo || '—',
            parseFloat(v.score).toFixed(1),
            parseFloat(v.prioridade || v.score).toFixed(1),
            v.sla_prioridade || '—',
            v.categoria || '—',
            v.origem || '—',
            v.status
        ]);

        doc.autoTable({
            startY: 85,
            head: [['Nome', 'Ativo', 'Risk Index', 'Prioridade', 'SLA', 'Categoria', 'Origem', 'Status']],
            body: linhas,
            headStyles: { fillColor: [44, 62, 80], fontSize: 8 },
            styles: { fontSize: 7.5 },
            columnStyles: { 0: { cellWidth: 40 } }
        });

        // --- TABELA DE STATUS DE SLAs ---
        const finalY = doc.lastAutoTable.finalY + 10;
        doc.setFontSize(12);
        doc.setTextColor(44, 62, 80);
        doc.text('Status de SLAs de Remediação', 14, finalY);

        const linhasSla = slas.map(s => [
            s.nome.substring(0, 30),
            s.nivel,
            `${s.prazo_dias} dias`,
            `${s.dias_restantes} dias`,
            s.status_sla
        ]);

        doc.autoTable({
            startY: finalY + 6,
            head: [['Vulnerabilidade', 'Nível', 'Prazo', 'Dias Restantes', 'Status SLA']],
            body: linhasSla,
            headStyles: { fillColor: [123, 46, 255], fontSize: 8 },
            styles: { fontSize: 8 }
        });

        doc.save(`relatorio-securescope-${new Date().toISOString().slice(0, 10)}.pdf`);
        mostrarToast('Relatório PDF enriquecido gerado com sucesso!', '#28a745');

    } catch (error) {
        mostrarToast('Erro ao gerar relatório PDF.', '#dc3545');
    }
}
```

> **Impacto Esperado:** O PDF gerado passará a ser um documento de governança real — com resumo executivo, análise de SLAs e categorização de risco — em vez de uma simples exportação de tabela. Este nível de relatório é o que diferencia uma ferramenta de apresentação de uma ferramenta de governança profissional.

---

## M6 — MÉDIA: Endpoint de Dashboard de KPIs de Governança

### Lacuna Identificada no Código

O endpoint `/ia/insights` retorna estatísticas de vulnerabilidades validadas (médias e extremos), mas não fornece os KPIs operacionais de governança que são padrão de mercado: MTTR, MTTD, Taxa de Violação de SLA e Scan Coverage Rate.

### Justificativa com Base na Pesquisa

A pesquisa de referência — Seção 9 — define explicitamente os seguintes KPIs como obrigatórios para um programa de governança maduro:

| KPI | Definição |
|-----|-----------|
| MTTR | Mean Time to Remediate — tempo médio de remediação por severidade |
| MTTD | Mean Time to Detect — tempo entre introdução e detecção |
| Scan Coverage Rate | Percentual de ativos cobertos por scanning |
| SLA Breach Rate | Percentual de vulns que ultrapassaram o SLA |
| KEV Remediation Rate | Taxa de remediação de CVEs no catálogo CISA KEV |

### Proposta de Implementação

**Novo endpoint em `app.py`:**

```python
from datetime import timedelta

@app.route('/governance/kpis', methods=['GET'])
def kpis_governanca():
    conn = get_db_connection()
    agora = datetime.now()

    # MTTR — Tempo médio de remediação (vulns Isoladas como proxy de "remediadas")
    resolvidas = conn.execute(
        "SELECT data FROM vulnerabilidades WHERE status = 'Isolada (Circuit Breaker)'"
    ).fetchall()
    
    # SLA Breach Rate
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
            except:
                pass

    sla_breach_rate = round((violados / total_aberto * 100), 1) if total_aberto > 0 else 0

    # Scan Coverage — % de vulns com ativo mapeado (proxy de asset coverage)
    com_ativo = conn.execute(
        "SELECT COUNT(*) FROM vulnerabilidades WHERE ativo != '' AND ativo IS NOT NULL"
    ).fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM vulnerabilidades").fetchone()[0]
    scan_coverage = round((com_ativo / total * 100), 1) if total > 0 else 0

    # Distribuição por categoria de Origem
    origens = conn.execute(
        "SELECT origem, COUNT(*) as c FROM vulnerabilidades GROUP BY origem ORDER BY c DESC"
    ).fetchall()

    conn.close()

    return jsonify({
        "total_vulnerabilidades": total,
        "sla_breach_rate_percent": sla_breach_rate,
        "sla_violados": violados,
        "scan_coverage_rate_percent": scan_coverage,
        "distribuicao_por_origem": {o["origem"]: o["c"] for o in origens},
        "timestamp": agora.strftime("%Y-%m-%d %H:%M:%S")
    }), 200
```

> **Impacto Esperado:** O painel executivo passa a exibir os KPIs que qualquer CISO ou gestor de risco espera encontrar em um sistema de governança de vulnerabilidades — os mesmos listados em frameworks como NIST e medidos por plataformas como Microsoft Defender for Cloud (Seção 6 da pesquisa).

---

## M7 — BAIXA: Corrigir Posicionamento CSS Absoluto em Pixels

### Lacuna Identificada no Código

No arquivo `painel.css`, o posicionamento da barra de navegação e da barra de pesquisa utiliza valores absolutos em pixels que dependem de uma resolução de tela específica:

```css
/* PROBLEMÁTICO — painel.css, linhas 507-508 e 468 */
.search {
    top: -94px;
    left: 1494px;  /* Quebra em qualquer tela diferente da de desenvolvimento */
}
.navbar {
    top: -145px;
    margin-left: 281px;  /* Posicionamento frágil */
}
```

### Justificativa com Base na Pesquisa

A pesquisa de referência — Seção 5 — descreve que dashboards de governança modernos devem suportar _multi-cloud_ e _dynamic environments_ (wording de Wiz e Orca Security na Seção 6). No nível de interface, isso se traduz em suporte a múltiplos dispositivos e resoluções.

### Proposta de Implementação

```css
/* SUBSTITUIR o bloco .header por: */
.header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 24px;
    position: relative;
}

/* SUBSTITUIR .search por: */
.search {
    display: flex;
    align-items: center;
    gap: 11px;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.08);
    padding: 6px 16px;
    border-radius: 14px;
}

/* SUBSTITUIR .navbar por: */
.navbar {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 40px;
    padding: 16px 24px;
    backdrop-filter: blur(10px);
    border-radius: 40px;
    margin: 0 24px 16px;
    border-top: 1px solid rgba(255, 255, 255, 0.05);
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}

/* Adicionar responsividade */
@media (max-width: 768px) {
    .navbar {
        flex-wrap: wrap;
        gap: 16px;
        border-radius: 12px;
    }
    .search {
        width: 100%;
        max-width: 280px;
    }
}
```

---

## Roadmap de Implementação Sugerido

```
SPRINT 1 (Impacto Técnico e Acadêmico)
├── M1: Motor de Priorização CVSS + EPSS + KEV
│   ├── Atualizar banco.py (colunas cvss_score, epss_score, cve_id, no_kev)
│   ├── Reescrever calcular_prioridade_v2() em ia.py
│   └── Atualizar formulário frontend com campos CVE/CVSS/EPSS
└── M2: SLAs Formais e Trilha de Auditoria
    ├── Criar tabela sla_vulnerabilidades no banco
    ├── Adicionar endpoint /sla/status em app.py
    └── Exibir widget SLA no painel IA

SPRINT 2 (Segurança e Governança Executiva)
├── M3: Autenticação JWT na API
│   ├── Instalar flask-jwt-extended
│   ├── Criar endpoint /auth/login
│   └── Proteger rotas POST/PUT com @jwt_required()
├── M4: Score de Maturidade OWASP SAMM
│   └── Endpoint /governance/maturity em app.py
└── M6: KPIs de Governança
    └── Endpoint /governance/kpis em app.py

SPRINT 3 (Apresentação e Experiência)
├── M5: PDF Enriquecido com Resumo Executivo e SLAs
└── M7: Refatoração CSS com Flexbox responsivo
```

---

## Mapeamento de Conformidade — Antes e Depois

| Framework / Controle | Estado Atual | Após Melhorias |
| :--- | :--- | :--- |
| **NIST SP 800-53 RA-5** | Parcial (scoring básico) | Completo (CVSS + EPSS + KEV) |
| **NIST SP 800-53 SI-2(2)** | Inexistente | Implementado (SLA tracking) |
| **NIST SP 800-53 CA-7** | Parcial (alertas proativos) | Completo (KPI contínuo) |
| **ISO 27001 A.8.8** | Parcial (sem SLA formal) | Completo (SLA + evidência auditável) |
| **OWASP SAMM Nível 1** | Atingido | Atingido |
| **OWASP SAMM Nível 2** | Parcial | Atingido (múltiplas origens + validação) |
| **OWASP SAMM Nível 3** | Não atingido | Atingido (SLA + ativos + rastreabilidade) |
| **DREAD Framework** | Implementado (completo) | Mantido e enriquecido |
| **Segurança da API (Auth)** | Inexistente | JWT implementado |
| **Relatório de Governança** | Básico (6 colunas) | Completo (sumário executivo + SLAs) |

---

*Análise produzida com base na leitura integral de todos os arquivos do projeto SecureScope e correlação sistemática com o relatório acadêmico "Governança de Risco de Segurança de Aplicações e Gestão de Vulnerabilidades: Uma Análise Sistemática do Estado da Arte em ASPM (2024–2026)".*
