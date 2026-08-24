# scanner.py
# ─────────────────────────────────────────────────────────────────────────────
# Fase 1 — SCA (Software Composition Analysis)
# Fase 2 — SAST (Static Application Security Testing) com Bandit
# Fase 4 — DAST (Dynamic Application Security Testing) com OWASP ZAP
#
# Fase 1 — SCA:
#   1. parsear_requirements()   — extrai lista de (pacote, versão) de um
#                                 requirements.txt enviado pelo usuário.
#   2. consultar_osv_em_lote()  — consulta a API pública do OSV.dev em uma
#                                 única requisição HTTP em lote (querybatch).
#   3. processar_achados_osv()  — converte a resposta bruta do OSV em achados
#                                 normalizados prontos para o banco.
#   4. executar_sca()           — orquestra o pipeline completo.
#
# Fase 2 — SAST:
#   5. _salvar_arquivos_temp()  — grava .py em diretório temporário isolado;
#                                 o código enviado NUNCA é executado.
#   6. executar_bandit()        — chama `bandit -r <dir> -f json` via
#                                 subprocess (shell=False, timeout=60s).
#   7. processar_achados_bandit() — normaliza saída JSON do Bandit.
#   8. executar_sast()          — entry point para arquivo .py único.
#   9. executar_sast_zip()      — entry point para .zip com múltiplos .py.
#
# Fase 3 — Triagem Multi-LLM será chamada após os achados desta fase.
#
# Pode ser testado de forma isolada sem o Flask rodando.
# ─────────────────────────────────────────────────────────────────────────────

import ipaddress
import os
import re
import json
import logging
import shutil
import socket
# Uso restrito a `python -m bandit`, com argumentos separados e sem shell.
import subprocess  # nosec B404
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import requests

from triagem_llm import MotorTriagem
logger = logging.getLogger(__name__)
motor_triagem = MotorTriagem()

def aplicar_triagem_llm(achados: list) -> tuple[list, int, bool]:
    """Aplica a triagem multi-LLM na lista de achados e retorna (achados_filtrados, qtd_descartados, triagem_aplicada)."""
    achados_filtrados = []
    descartados = 0
    triagem_aplicada = len(motor_triagem.provedores) > 0
    
    for a in achados:
        resultado = motor_triagem.aplicar_triagem(a)
        if resultado["veredito"] == "descartar":
            descartados += 1
            continue
            
        a["confianca_ia"] = resultado["confianca_ia"]
        achados_filtrados.append(a)
        
    return achados_filtrados, descartados, triagem_aplicada

# URL da API pública do OSV.dev — sem autenticação necessária.
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Timeout em segundos para a chamada ao OSV.dev.
OSV_TIMEOUT_SEGUNDOS = 30

# Ecossistema PyPI para consulta ao OSV.dev.
# O OSV.dev aceita outros ecossistemas (npm, Go, Maven, etc.) — futuras
# extensões podem iterar sobre múltiplos ecossistemas.
OSV_ECOSISTEMA = "PyPI"


# ─────────────────────────────────────────────
# 1. PARSE DE requirements.txt
# ─────────────────────────────────────────────

def parsear_requirements(conteudo_txt: str) -> list[dict]:
    """Extrai pacotes e versões de um requirements.txt.

    Retorna uma lista de dicionários no formato:
        [{"pacote": "flask", "versao": "3.0.0"}, ...]

    Regras:
    - Linhas em branco e comentários (#) são ignorados.
    - Suporta os operadores mais comuns: ==, >=, <=, ~=, !=, >.
    - Pacotes sem versão explícita são incluídos com versao="".
    - Extras e marcadores de ambiente (ex: flask[async]; python_version>='3.8')
      são removidos para simplificar a consulta.
    """
    pacotes = []
    for linha in conteudo_txt.splitlines():
        linha = linha.strip()

        # Ignora comentários e linhas vazias
        if not linha or linha.startswith("#"):
            continue

        # Remove opções de linha de comando (ex: -r, -i, --index-url)
        if linha.startswith("-"):
            continue

        # Remove marcadores de ambiente (ex: ; python_version >= '3.8')
        linha = re.split(r";", linha)[0].strip()

        # Remove extras entre colchetes (ex: flask[async] → flask)
        linha = re.sub(r"\[.*?\]", "", linha)

        # Extrai pacote e versão com operador ==, >=, <=, ~=, !=, >
        match = re.match(
            r"^([A-Za-z0-9_.\-]+)\s*([><=!~]{1,2})\s*([A-Za-z0-9_.+\-]*)$",
            linha
        )
        if match:
            pacote = match.group(1).strip()
            operador = match.group(2).strip()
            versao = match.group(3).strip()
            # Para o OSV.dev, só usamos a versão exata (==) ou a primeira
            # versão especificada para outros operadores. Versões sem '=='
            # podem gerar resultados menos precisos, mas ainda são úteis.
            pacotes.append({
                "pacote": pacote,
                "versao": versao,
                "operador": operador,
            })
        else:
            # Pacote sem versão especificada
            pacote = re.match(r"^([A-Za-z0-9_.\-]+)", linha)
            if pacote:
                pacotes.append({
                    "pacote": pacote.group(1).strip(),
                    "versao": "",
                    "operador": "",
                })

    return pacotes


# ─────────────────────────────────────────────
# 2. CONSULTA AO OSV.dev EM LOTE
# ─────────────────────────────────────────────

def consultar_osv_em_lote(pacotes: list[dict]) -> dict:
    """Faz uma única requisição POST para o endpoint /v1/querybatch do OSV.dev.

    Cada item da lista 'pacotes' gera uma entrada em 'queries'. Quando a versão
    é fornecida, a API retorna apenas as vulnerabilidades que afetam aquela
    versão específica. Sem versão, retorna todos os CVEs conhecidos para o pacote.

    Retorna o JSON bruto da resposta (dict com chave 'results').
    Lança RuntimeError em caso de falha de rede ou resposta inválida.
    """
    if not pacotes:
        return {"results": []}

    queries = []
    for item in pacotes:
        query: dict = {
            "package": {
                "name": item["pacote"],
                "ecosystem": OSV_ECOSISTEMA,
            }
        }
        # Inclui versão apenas quando disponível — aumenta a precisão da consulta.
        if item.get("versao"):
            query["version"] = item["versao"]
        queries.append(query)

    payload = {"queries": queries}

    try:
        resposta = requests.post(
            OSV_BATCH_URL,
            json=payload,
            timeout=OSV_TIMEOUT_SEGUNDOS,
            headers={"Content-Type": "application/json"},
        )
        resposta.raise_for_status()
        return resposta.json()
    except requests.exceptions.Timeout:
        raise RuntimeError(
            f"Timeout após {OSV_TIMEOUT_SEGUNDOS}s ao consultar o OSV.dev. "
            "Verifique a conectividade e tente novamente."
        )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Erro ao consultar OSV.dev: {e}")


# ─────────────────────────────────────────────
# 3. NORMALIZAÇÃO DOS ACHADOS
# ─────────────────────────────────────────────

def _extrair_cvss(vuln_osv: dict) -> float:
    """Extrai o score CVSS mais alto disponível em um objeto de vulnerabilidade
    do OSV.dev. Tenta CVSS v3.1 > v3.0 > v2.0 nessa ordem de preferência."""
    severity = vuln_osv.get("severity", [])
    melhor_score = 0.0

    preferencia = ["CVSS_V3", "CVSS_V2"]
    for pref in preferencia:
        for sev in severity:
            if sev.get("type") == pref:
                try:
                    score = float(sev.get("score", 0))
                    melhor_score = max(melhor_score, score)
                except (ValueError, TypeError):
                    pass

    # Fallback: tenta database_specific do GitHub Advisory
    if melhor_score == 0.0:
        db_specific = vuln_osv.get("database_specific", {})
        try:
            melhor_score = float(db_specific.get("cvss_score", 0) or 0)
        except (ValueError, TypeError):
            pass

    return round(melhor_score, 1)


def _extrair_cve_id(vuln_osv: dict) -> str:
    """Extrai o CVE-ID de um objeto de vulnerabilidade do OSV.dev.
    Procura nos aliases (ex: CVE-2023-XXXXX) antes de retornar o OSV ID."""
    aliases = vuln_osv.get("aliases", [])
    for alias in aliases:
        if alias.upper().startswith("CVE-"):
            return alias.upper()
    return vuln_osv.get("id", "")


def _extrair_versao_corrigida(vuln_osv: dict, nome_pacote: str) -> str:
    """Tenta extrair a primeira versão corrigida (fixed) para o pacote
    dentro dos 'affected' do OSV. Retorna string vazia se não encontrado."""
    for afetado in vuln_osv.get("affected", []):
        pkg = afetado.get("package", {})
        if pkg.get("name", "").lower() != nome_pacote.lower():
            continue
        for ranges in afetado.get("ranges", []):
            for evento in ranges.get("events", []):
                if "fixed" in evento:
                    return evento["fixed"]
    return ""


def processar_achados_osv(resposta_osv: dict, pacotes: list[dict]) -> list[dict]:
    """Converte a resposta bruta do OSV.dev em uma lista de achados normalizados.

    Cada achado é um dicionário compatível com a tabela 'vulnerabilidades',
    com os campos mínimos necessários para a inserção via app.py.

    Um único pacote pode gerar múltiplos achados se tiver mais de um CVE.
    Pacotes sem vulnerabilidades conhecidas são silenciosamente ignorados.
    """
    achados = []
    resultados = resposta_osv.get("results", [])

    for i, resultado in enumerate(resultados):
        if i >= len(pacotes):
            break

        pacote_info = pacotes[i]
        nome_pacote = pacote_info["pacote"]
        versao_pacote = pacote_info.get("versao", "")

        vulns = resultado.get("vulns", [])
        if not vulns:
            continue  # Pacote sem vulnerabilidades conhecidas — OK

        for vuln in vulns:
            cvss = _extrair_cvss(vuln)
            cve_id = _extrair_cve_id(vuln)
            versao_corrigida = _extrair_versao_corrigida(vuln, nome_pacote)

            # Título legível para o campo 'nome' na tabela vulnerabilidades
            titulo_osv = vuln.get("summary", "") or vuln.get("id", nome_pacote)
            nome_vuln = f"[SCA] {nome_pacote} {versao_pacote} — {titulo_osv}"[:200]

            # Severidade textual baseada no CVSS
            if cvss >= 9.0:
                gravidade_texto = "Crítica"
                gravidade_val = 100.0
            elif cvss >= 7.0:
                gravidade_texto = "Alta"
                gravidade_val = 80.0
            elif cvss >= 4.0:
                gravidade_texto = "Média"
                gravidade_val = 50.0
            elif cvss > 0:
                gravidade_texto = "Baixa"
                gravidade_val = 20.0
            else:
                gravidade_texto = "Desconhecida"
                gravidade_val = 30.0  # Assume risco baixo quando CVSS não disponível

            # Monta o achado no formato esperado pelo pipeline de inserção do app.py
            achado = {
                # Identificação
                "nome": nome_vuln,
                "cve_id": cve_id,
                "cvss_score": cvss,
                "epss_score": 0.0,   # Fase 3 — será preenchido pela triagem IA
                "no_kev": False,     # Fase 3 — será verificado pela triagem IA

                # Métricas de risco base (legado SecureScope)
                # Usamos valores simétricos quando CVSS está disponível
                "impacto": gravidade_val,
                "frequencia": 50.0,   # Neutro — não temos dados de frequência real
                "gravidade": gravidade_val,

                # Contexto de segurança (conservador por padrão para achados SCA)
                "exposta_internet": False,
                "exploit_publico": False,
                "dados_sensiveis": False,
                "escalonamento_privilegio": False,
                "ambiente_producao": False,

                # Rastreabilidade
                "origem": "Scanner Automatizado",
                "ativo": nome_pacote,

                # Metadados extras (úteis para exibição futura)
                "_versao_afetada": versao_pacote,
                "_versao_corrigida": versao_corrigida,
                "_gravidade_texto": gravidade_texto,
                "_osv_id": vuln.get("id", ""),
                "_descricao": (vuln.get("details", "") or "")[:500],
            }

            achados.append(achado)

    return achados


# ─────────────────────────────────────────────
# 4. PIPELINE COMPLETO SCA
# ─────────────────────────────────────────────

def executar_sca(conteudo_txt: str) -> dict:
    """Ponto de entrada principal do módulo SCA.

    Recebe o conteúdo de um requirements.txt como string e retorna um
    dicionário com:
        - 'achados': lista de vulnerabilidades normalizadas
        - 'total_pacotes': quantos pacotes foram analisados
        - 'total_achados': quantas vulnerabilidades foram encontradas
        - 'pacotes_sem_vuln': lista de pacotes limpos (sem CVEs conhecidos)
        - 'erro': None se tudo correu bem, ou mensagem de erro string

    Nunca lança exceção ao chamador — erros são capturados e retornados
    no campo 'erro' para que a rota Flask possa responder de forma adequada.
    """
    resultado = {
        "achados": [],
        "total_pacotes": 0,
        "total_achados": 0,
        "pacotes_sem_vuln": [],
        "erro": None,
    }

    try:
        # Etapa 1 — Parse
        pacotes = parsear_requirements(conteudo_txt)
        resultado["total_pacotes"] = len(pacotes)

        if not pacotes:
            resultado["erro"] = (
                "Nenhum pacote encontrado no arquivo. "
                "Verifique se o arquivo é um requirements.txt válido."
            )
            return resultado

        # Etapa 2 — Consulta OSV.dev em lote
        resposta_osv = consultar_osv_em_lote(pacotes)

        # Etapa 3 — Normalização
        achados = processar_achados_osv(resposta_osv, pacotes)
        achados_filtrados, descartados, triagem_aplicada = aplicar_triagem_llm(achados)
        resultado["achados"] = achados_filtrados
        resultado["total_achados"] = len(achados_filtrados)
        resultado["achados_descartados"] = descartados
        resultado["triagem_aplicada"] = triagem_aplicada

        # Identifica pacotes limpos (sem CVE)
        pacotes_com_vuln = {
            a["ativo"].lower() for a in achados
        }
        resultado["pacotes_sem_vuln"] = [
            p["pacote"] for p in pacotes
            if p["pacote"].lower() not in pacotes_com_vuln
        ]

    except RuntimeError as e:
        logger.error("Falha operacional no SCA (%s)", type(e).__name__)
        resultado["erro"] = "Servico de analise SCA indisponivel."
    except Exception:
        logger.exception("Falha inesperada durante o SCA")
        resultado["erro"] = "Erro interno inesperado durante o SCA."

    return resultado


# ═════════════════════════════════════════════
# FASE 2 — SAST (Static Application Security Testing)
# ═════════════════════════════════════════════

# Timeout em segundos para a execução do Bandit.
BANDIT_TIMEOUT_SEGUNDOS = 60

# Tamanho máximo de um ZIP aceito (10 MB descompactado por arquivo).
MAX_ARQUIVO_PY_BYTES = 10 * 1024 * 1024  # 10 MB

# Mapeamento de severidade Bandit → CVSS aproximado e valor numérico de risco.
_BANDIT_SEVERIDADE = {
    "HIGH":   {"cvss": 8.0, "gravidade": 90.0, "texto": "Alta"},
    "MEDIUM": {"cvss": 5.0, "gravidade": 55.0, "texto": "Média"},
    "LOW":    {"cvss": 2.0, "gravidade": 20.0, "texto": "Baixa"},
}

# Mapeamento de confiança Bandit → fator de ajuste de impacto.
_BANDIT_CONFIANCA = {
    "HIGH":   1.0,
    "MEDIUM": 0.75,
    "LOW":    0.5,
}


# ─────────────────────────────────────────────
# 5. DIRETÓRIO TEMPORÁRIO SEGURO
# ─────────────────────────────────────────────

def _salvar_arquivos_temp(arquivos: list[dict]) -> str:
    """Grava os arquivos .py recebidos em um diretório temporário isolado.

    Parâmetro:
        arquivos: lista de {'nome': str, 'conteudo': bytes}

    Retorna o caminho absoluto do diretório temporário criado.
    O chamador é responsável por remover o diretório após o uso
    (via shutil.rmtree) — independentemente de sucesso ou erro.

    Garante:
    - Nomes de arquivo são sanitizados (apenas basename, sem path traversal).
    - Apenas arquivos .py são gravados.
    - O conteúdo é escrito em disco mas NUNCA importado ou executado.
    """
    dir_temp = tempfile.mkdtemp(prefix="securescope_sast_")

    for arq in arquivos:
        # Sanitiza o nome: pega apenas o basename para evitar path traversal
        nome_seguro = Path(arq["nome"]).name
        if not nome_seguro.endswith(".py"):
            continue  # Ignora silenciosamente arquivos não-Python

        caminho = Path(dir_temp) / nome_seguro
        caminho.write_bytes(arq["conteudo"])

    return dir_temp


# ─────────────────────────────────────────────
# 6. EXECUÇÃO DO BANDIT
# ─────────────────────────────────────────────

def executar_bandit(caminho_dir: str) -> dict:
    """Executa o Bandit sobre o diretório informado via subprocess.

    Usa `sys.executable -m bandit` para garantir que o mesmo ambiente
    Python/virtualenv da aplicação seja usado — sem depender de PATH.

    Flags:
        -r          análise recursiva no diretório
        -f json     saída em JSON estruturado
        -q          suprime progresso (apenas erros e resultados)
        --exit-zero sempre retorna código 0, mesmo com achados
                    (sem isso, subprocess interpreta achados como erro)

    Retorna o dict JSON da saída do Bandit.
    Lança RuntimeError em caso de falha real (timeout, binário não encontrado).
    """
    cmd = [
        sys.executable, "-m", "bandit",
        "-r", caminho_dir,
        "-f", "json",
        "-q",
        "--exit-zero",
    ]

    try:
        proc = subprocess.run(  # nosec B603
            cmd,
            capture_output=True,
            text=True,
            timeout=BANDIT_TIMEOUT_SEGUNDOS,
            shell=False,  # Segurança: sem shell expansion
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Bandit excedeu o timeout de {BANDIT_TIMEOUT_SEGUNDOS}s. "
            "O arquivo pode ser muito grande."
        )
    except FileNotFoundError:
        raise RuntimeError(
            "Bandit não encontrado. Execute: pip install bandit>=1.7.9"
        )

    # stderr pode conter avisos não-fatais do Bandit — logamos mas não falhamos
    if proc.returncode not in (0, 1):  # Bandit usa 1 para achados com -exit-zero
        raise RuntimeError(
            f"Bandit terminou com código {proc.returncode}. "
            f"Stderr: {proc.stderr[:500]}"
        )

    saida = proc.stdout.strip()
    if not saida:
        # Sem saída = sem achados (arquivo vazio ou só comentários)
        return {"results": [], "errors": []}

    try:
        return json.loads(saida)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Saída do Bandit não é JSON válido: {e}")


# ─────────────────────────────────────────────
# 7. NORMALIZAÇÃO DOS ACHADOS BANDIT
# ─────────────────────────────────────────────

def processar_achados_bandit(saida_bandit: dict, prefixo_remover: str = "") -> list[dict]:
    """Converte a saída JSON do Bandit em lista de achados normalizados.

    Cada resultado do Bandit gera um achado compatível com a tabela
    'vulnerabilidades'. Achados de confiança LOW são incluídos mas
    recebem impacto reduzido — o analista pode validar ou descartar.

    Parâmetro 'prefixo_remover': caminho do dir temporário para remover
    dos nomes de arquivo nos achados (mantém apenas o caminho relativo).
    """
    achados = []
    resultados = saida_bandit.get("results", [])

    for r in resultados:
        severidade_str = r.get("issue_severity", "LOW").upper()
        confianca_str  = r.get("issue_confidence", "LOW").upper()

        sev  = _BANDIT_SEVERIDADE.get(severidade_str, _BANDIT_SEVERIDADE["LOW"])
        conf = _BANDIT_CONFIANCA.get(confianca_str, 0.5)

        # Nome do arquivo relativo (sem o path do dir temporário)
        filename = r.get("filename", "desconhecido")
        if prefixo_remover and filename.startswith(prefixo_remover):
            filename = filename[len(prefixo_remover):].lstrip("/\\\"\'")

        linha      = r.get("line_number", 0)
        test_id    = r.get("test_id", "")     # Ex: B105
        test_name  = r.get("test_name", "")   # Ex: hardcoded_password_string
        descricao  = r.get("issue_text", "")  # Descrição humana
        cwe_node   = r.get("issue_cwe", {})
        cwe_id     = cwe_node.get("id", "") if isinstance(cwe_node, dict) else ""
        cwe_link   = cwe_node.get("link", "") if isinstance(cwe_node, dict) else ""
        codigo_trecho = (r.get("code", "") or "").strip()[:300]

        # CVE-ID preenchido como CWE quando disponível (sem CVE real no SAST)
        cve_id_campo = f"CWE-{cwe_id}" if cwe_id else test_id

        # Impacto ajustado pela confiança do Bandit
        impacto_ajustado = round(sev["gravidade"] * conf, 1)

        nome_vuln = (
            f"[SAST] {filename}:{linha} — {test_name} ({test_id})"
        )[:200]

        achado = {
            # Identificação
            "nome":      nome_vuln,
            "cve_id":    cve_id_campo,
            "cvss_score": sev["cvss"],
            "epss_score": 0.0,
            "no_kev":    False,

            # Métricas de risco
            "impacto":    impacto_ajustado,
            "frequencia": 50.0,
            "gravidade":  sev["gravidade"],

            # Contexto (conservador — analista deve revisar)
            "exposta_internet":         False,
            "exploit_publico":          False,
            "dados_sensiveis":          False,
            "escalonamento_privilegio": False,
            "ambiente_producao":        False,

            # Rastreabilidade
            "origem": "Scanner Automatizado",
            "ativo":  filename,

            # Metadados extras (prefixo _ = não vão para o banco diretamente)
            "_gravidade_texto": sev["texto"],
            "_test_id":         test_id,
            "_test_name":       test_name,
            "_descricao":       descricao,
            "_cwe_id":          str(cwe_id),
            "_cwe_link":        cwe_link,
            "_linha":           linha,
            "_codigo_trecho":   codigo_trecho,
            "_confianca":       confianca_str,
            "_osv_id":          "",  # Compatibilidade com histórico da Fase 1
        }
        achados.append(achado)

    return achados


# ─────────────────────────────────────────────
# 8. ENTRY POINT — arquivo .py único
# ─────────────────────────────────────────────

def executar_sast(conteudo_py: bytes, nome_arquivo: str) -> dict:
    """Ponto de entrada SAST para um único arquivo .py.

    Retorna dicionário com o mesmo contrato de executar_sca():
        - 'achados': lista de vulnerabilidades normalizadas
        - 'total_arquivos': quantos arquivos foram analisados
        - 'total_achados': quantas vulnerabilidades foram encontradas
        - 'erro': None se OK, ou mensagem de erro
    """
    resultado = {
        "achados": [],
        "total_arquivos": 0,
        "total_achados": 0,
        "erro": None,
    }

    if len(conteudo_py) > MAX_ARQUIVO_PY_BYTES:
        resultado["erro"] = (
            f"Arquivo muito grande ({len(conteudo_py) // 1024} KB). "
            f"Limite: {MAX_ARQUIVO_PY_BYTES // (1024*1024)} MB."
        )
        return resultado

    dir_temp = None
    try:
        dir_temp = _salvar_arquivos_temp([{"nome": nome_arquivo, "conteudo": conteudo_py}])
        saida_bandit = executar_bandit(dir_temp)
        achados = processar_achados_bandit(saida_bandit, prefixo_remover=dir_temp)

        achados_filtrados, descartados, triagem_aplicada = aplicar_triagem_llm(achados)
        resultado["achados"] = achados_filtrados
        resultado["total_arquivos"] = 1
        resultado["total_achados"] = len(achados_filtrados)
        resultado["achados_descartados"] = descartados
        resultado["triagem_aplicada"] = triagem_aplicada

    except RuntimeError as e:
        logger.error("Falha operacional no SAST (%s)", type(e).__name__)
        resultado["erro"] = "Ferramenta SAST indisponivel."
    except Exception:
        logger.exception("Falha inesperada durante o SAST")
        resultado["erro"] = "Erro interno inesperado durante o SAST."
    finally:
        # Garante limpeza do diretório temporário em qualquer cenário
        if dir_temp and Path(dir_temp).exists():
            shutil.rmtree(dir_temp, ignore_errors=True)

    return resultado


# ─────────────────────────────────────────────
# 9. ENTRY POINT — arquivo .zip com múltiplos .py
# ─────────────────────────────────────────────

def executar_sast_zip(conteudo_zip: bytes) -> dict:
    """Ponto de entrada SAST para um arquivo .zip contendo arquivos .py.

    Apenas os arquivos .py dentro do ZIP são extraídos e analisados.
    Todos os outros tipos de arquivo são ignorados silenciosamente.
    O ZIP é inspecionado antes da extração para evitar zip-bomb e
    path traversal (nomes com '..' são descartados).

    Retorna dicionário com o mesmo contrato de executar_sca().
    """
    resultado = {
        "achados": [],
        "total_arquivos": 0,
        "total_achados": 0,
        "erro": None,
    }

    dir_temp = None
    try:
        # Inspeciona o ZIP sem extrair ainda
        import io
        with zipfile.ZipFile(io.BytesIO(conteudo_zip), 'r') as zf:
            membros_py = [
                m for m in zf.infolist()
                if m.filename.endswith(".py")
                and ".." not in m.filename          # anti path traversal
                and not m.filename.startswith("/")  # anti path absoluto
                and m.file_size <= MAX_ARQUIVO_PY_BYTES  # anti zip-bomb
            ]

            if not membros_py:
                resultado["erro"] = (
                    "Nenhum arquivo .py encontrado no ZIP. "
                    "Verifique o conteúdo do arquivo enviado."
                )
                return resultado

            # Monta lista de arquivos para gravação temporária
            arquivos = []
            for m in membros_py:
                arquivos.append({
                    "nome": Path(m.filename).name,  # Só o basename
                    "conteudo": zf.read(m.filename),
                })

        dir_temp = _salvar_arquivos_temp(arquivos)
        saida_bandit = executar_bandit(dir_temp)
        achados = processar_achados_bandit(saida_bandit, prefixo_remover=dir_temp)

        achados_filtrados, descartados, triagem_aplicada = aplicar_triagem_llm(achados)
        resultado["achados"] = achados_filtrados
        resultado["total_arquivos"] = len(membros_py)
        resultado["total_achados"] = len(achados_filtrados)
        resultado["achados_descartados"] = descartados
        resultado["triagem_aplicada"] = triagem_aplicada

    except zipfile.BadZipFile:
        resultado["erro"] = "Arquivo ZIP inválido ou corrompido."
    except RuntimeError as e:
        logger.error("Falha operacional no SAST ZIP (%s)", type(e).__name__)
        resultado["erro"] = "Ferramenta SAST indisponivel."
    except Exception:
        logger.exception("Falha inesperada durante o SAST ZIP")
        resultado["erro"] = "Erro interno inesperado durante o SAST ZIP."
    finally:
        if dir_temp and Path(dir_temp).exists():
            shutil.rmtree(dir_temp, ignore_errors=True)

    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# FASE 4 — DAST (Dynamic Application Security Testing) via OWASP ZAP
# ─────────────────────────────────────────────────────────────────────────────
#   10. _zap_disponivel()        — checa se o daemon do ZAP está no ar.
#   11. _executar_zap_real()     — Spider + Active Scan reais via API do ZAP.
#   12. _gerar_alertas_mock()    — fallback simulado (mesmo formato do ZAP)
#                                  usado quando o daemon não está instalado.
#   13. processar_achados_zap()  — normaliza os alertas (reais ou mock).
#   14. executar_dast(url)       — orquestra o pipeline completo.
# ─────────────────────────────────────────────────────────────────────────────

# Endereço do daemon local do OWASP ZAP (modo Daemon/Servidor, porta padrão 8080)
ZAP_API_URL = os.environ.get("ZAP_API_URL", "http://localhost:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")

ZAP_TIMEOUT_SEGUNDOS   = 8    # timeout de conexão para checar/chamar a API do ZAP
ZAP_SPIDER_MAX_ESPERA  = 90   # segundos máx. aguardando o Spider terminar
ZAP_SCAN_MAX_ESPERA    = 150  # segundos máx. aguardando o Active Scan terminar
ZAP_POLL_INTERVALO     = 2    # segundos entre verificações de status

# Mapa de severidade do ZAP ("risk") -> métricas do Risk Index™ (mesmo
# espírito do _BANDIT_SEVERIDADE já usado na Fase 2).
_ZAP_RISCO = {
    "High":          {"cvss": 8.5, "gravidade": 90.0, "texto": "Alta"},
    "Medium":        {"cvss": 5.5, "gravidade": 60.0, "texto": "Média"},
    "Low":           {"cvss": 2.5, "gravidade": 25.0, "texto": "Baixa"},
    "Informational": {"cvss": 0.5, "gravidade": 10.0, "texto": "Informativa"},
}

# Mapa de confiança do ZAP ("confidence") -> peso usado para ajustar o impacto.
_ZAP_CONFIANCA = {
    "High": 1.0,
    "Medium": 0.75,
    "Low": 0.5,
    "Confirmed": 1.0,
    "User Confirmed": 1.0,
}


# ─────────────────────────────────────────────
# 10. DISPONIBILIDADE DO DAEMON ZAP
# ─────────────────────────────────────────────

def _zap_disponivel() -> bool:
    """Verifica rapidamente se o daemon do OWASP ZAP está rodando localmente
    (porta 8080 por padrão). Não levanta exceção — apenas retorna bool."""
    try:
        params = {"apikey": ZAP_API_KEY} if ZAP_API_KEY else {}
        resp = requests.get(
            f"{ZAP_API_URL}/JSON/core/view/version/",
            params=params,
            timeout=ZAP_TIMEOUT_SEGUNDOS,
        )
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False


# ─────────────────────────────────────────────
# 11. VARREDURA REAL (Spider + Active Scan)
# ─────────────────────────────────────────────

def _zap_params(extra: dict) -> dict:
    params = dict(extra)
    if ZAP_API_KEY:
        params["apikey"] = ZAP_API_KEY
    return params


def _zap_spider(url: str) -> None:
    """Dispara o Spider do ZAP (mapeamento de páginas/endpoints) e aguarda
    até 100% de progresso ou até estourar ZAP_SPIDER_MAX_ESPERA."""
    resp = requests.get(
        f"{ZAP_API_URL}/JSON/spider/action/scan/",
        params=_zap_params({"url": url}),
        timeout=ZAP_TIMEOUT_SEGUNDOS,
    )
    resp.raise_for_status()
    scan_id = resp.json().get("scan")

    decorrido = 0
    while decorrido < ZAP_SPIDER_MAX_ESPERA:
        time.sleep(ZAP_POLL_INTERVALO)
        decorrido += ZAP_POLL_INTERVALO
        status_resp = requests.get(
            f"{ZAP_API_URL}/JSON/spider/view/status/",
            params=_zap_params({"scanId": scan_id}),
            timeout=ZAP_TIMEOUT_SEGUNDOS,
        )
        status_resp.raise_for_status()
        if int(status_resp.json().get("status", 0)) >= 100:
            return
    # Estourou o tempo máximo: segue para o Active Scan mesmo assim, usando
    # o que já foi mapeado até aqui — melhor achar algo do que travar o scan.


def _zap_active_scan(url: str) -> None:
    """Dispara o Active Scan do ZAP (ataques ativos contra os endpoints
    mapeados pelo Spider) e aguarda até 100% ou até estourar o tempo máximo."""
    resp = requests.get(
        f"{ZAP_API_URL}/JSON/ascan/action/scan/",
        params=_zap_params({"url": url, "recurse": "true"}),
        timeout=ZAP_TIMEOUT_SEGUNDOS,
    )
    resp.raise_for_status()
    scan_id = resp.json().get("scan")

    decorrido = 0
    while decorrido < ZAP_SCAN_MAX_ESPERA:
        time.sleep(ZAP_POLL_INTERVALO)
        decorrido += ZAP_POLL_INTERVALO
        status_resp = requests.get(
            f"{ZAP_API_URL}/JSON/ascan/view/status/",
            params=_zap_params({"scanId": scan_id}),
            timeout=ZAP_TIMEOUT_SEGUNDOS,
        )
        status_resp.raise_for_status()
        if int(status_resp.json().get("status", 0)) >= 100:
            return
    # Mesma lógica de degradação graciosa do spider: segue com o que houver.


def _zap_obter_alertas(url: str) -> list[dict]:
    resp = requests.get(
        f"{ZAP_API_URL}/JSON/core/view/alerts/",
        params=_zap_params({"baseurl": url}),
        timeout=ZAP_TIMEOUT_SEGUNDOS,
    )
    resp.raise_for_status()
    return resp.json().get("alerts", [])


def _executar_zap_real(url: str) -> list[dict]:
    """Orquestra Spider -> Active Scan -> coleta de alertas contra o daemon
    real do ZAP. Propaga RuntimeError em caso de falha de comunicação."""
    try:
        _zap_spider(url)
        _zap_active_scan(url)
        return _zap_obter_alertas(url)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Erro ao comunicar com o OWASP ZAP em {ZAP_API_URL}: {e}")


# ─────────────────────────────────────────────
# 12. FALLBACK MOCK (ZAP não instalado localmente)
# ─────────────────────────────────────────────

def _gerar_alertas_mock(url: str) -> list[dict]:
    """Gera alertas simulados no MESMO formato de resposta da API do ZAP
    (campos 'alert', 'risk', 'confidence', 'cweid', etc.), permitindo que
    processar_achados_zap() trate achados reais e simulados de forma
    idêntica. Usado apenas quando o daemon do ZAP não está rodando
    localmente na porta 8080 — mantém a interface e o pipeline (triagem
    Multi-LLM, gravação no banco) totalmente testáveis sem a ferramenta."""
    return [
        {
            "alert": "Content Security Policy (CSP) Header Not Set",
            "risk": "Medium",
            "confidence": "High",
            "cweid": "693",
            "description": "O cabeçalho Content-Security-Policy não foi encontrado na resposta HTTP, deixando a aplicação mais vulnerável a ataques de XSS e injeção de dados.",
            "solution": "Configure uma política CSP restritiva no servidor web ou na aplicação Flask (ex: via flask-talisman).",
            "evidence": "",
            "url": url,
        },
        {
            "alert": "X-Frame-Options Header Not Set",
            "risk": "Medium",
            "confidence": "Medium",
            "cweid": "1021",
            "description": "A resposta não define o cabeçalho X-Frame-Options, permitindo que a página seja incorporada em um iframe malicioso (clickjacking).",
            "solution": "Defina X-Frame-Options: DENY ou SAMEORIGIN em todas as respostas.",
            "evidence": "",
            "url": url,
        },
        {
            "alert": "Cookie No HttpOnly Flag",
            "risk": "Low",
            "confidence": "Medium",
            "cweid": "1004",
            "description": "Um cookie foi definido sem a flag HttpOnly, permitindo que seja lido via JavaScript no navegador (aumenta o risco de roubo de sessão via XSS).",
            "solution": "Defina a flag HttpOnly em todos os cookies de sessão/autenticação.",
            "evidence": "Set-Cookie: session=...",
            "url": url,
        },
        {
            "alert": "Server Leaks Version Information via 'Server' HTTP Response Header",
            "risk": "Informational",
            "confidence": "High",
            "cweid": "200",
            "description": "O cabeçalho 'Server' da resposta HTTP expõe a versão exata do software rodando no servidor, facilitando o reconhecimento por um atacante.",
            "solution": "Remova ou ofusque o cabeçalho 'Server' na configuração do servidor web/WSGI.",
            "evidence": "Server: Werkzeug/3.0.1 Python/3.11",
            "url": url,
        },
    ]


# ─────────────────────────────────────────────
# 13. NORMALIZAÇÃO DOS ALERTAS ZAP
# ─────────────────────────────────────────────

def processar_achados_zap(alertas: list[dict], url_alvo: str) -> list[dict]:
    """Converte alertas do ZAP (reais ou mock) em achados normalizados,
    no mesmo contrato usado por processar_achados_bandit() e
    processar_achados_osv() — compatível com a tabela 'vulnerabilidades'."""
    achados = []

    for a in alertas:
        risco_str = (a.get("risk") or "Informational").strip()
        conf_str  = (a.get("confidence") or "Low").strip()

        risco = _ZAP_RISCO.get(risco_str, _ZAP_RISCO["Informational"])
        conf  = _ZAP_CONFIANCA.get(conf_str, 0.5)

        nome_alerta = a.get("alert") or a.get("name") or "Alerta ZAP desconhecido"
        cwe_id      = a.get("cweid", "")
        descricao   = re.sub(r"<[^>]+>", "", a.get("description", "") or "").strip()[:500]
        solucao     = re.sub(r"<[^>]+>", "", a.get("solution", "") or "").strip()[:500]
        evidencia   = (a.get("evidence", "") or "")[:200]
        url_afetada = a.get("url") or url_alvo

        cve_id_campo = f"CWE-{cwe_id}" if cwe_id else "ZAP-ALERT"
        impacto_ajustado = round(risco["gravidade"] * conf, 1)

        nome_vuln = f"[DAST] {nome_alerta} — {url_afetada}"[:200]

        achado = {
            # Identificação
            "nome":       nome_vuln,
            "cve_id":     cve_id_campo,
            "cvss_score": risco["cvss"],
            "epss_score": 0.0,
            "no_kev":     False,

            # Métricas de risco
            "impacto":    impacto_ajustado,
            "frequencia": 50.0,
            "gravidade":  risco["gravidade"],

            # Contexto — via DAST o alvo já é, por definição, uma aplicação
            # em execução alcançável pela URL informada (exposta_internet=True);
            # os demais fatores seguem conservadores, para revisão do analista.
            "exposta_internet":         True,
            "exploit_publico":          False,
            "dados_sensiveis":          False,
            "escalonamento_privilegio": False,
            "ambiente_producao":        False,

            # Rastreabilidade
            "origem": "Scanner Automatizado",
            "ativo":  url_afetada,

            # Metadados extras (prefixo _ = não vão direto para o banco)
            "_gravidade_texto": risco["texto"],
            "_descricao":       descricao,
            "_solucao":         solucao,
            "_cwe_id":          str(cwe_id),
            "_evidencia":       evidencia,
            "_confianca":       conf_str,
            "_osv_id":          "",  # Compatibilidade com histórico da Fase 1
        }
        achados.append(achado)

    return achados


# ─────────────────────────────────────────────
# 13b. PROTEÇÃO CONTRA SSRF
# ─────────────────────────────────────────────

# Por padrão, o DAST recusa alvos que resolvam para rede interna/loopback/
# link-local (isso inclui 127.0.0.1, 169.254.169.254 — endpoint de metadata
# de nuvem em AWS/GCP/Azure — e faixas RFC 1918 como 10.x/172.16.x/192.168.x).
# Sem essa checagem, um usuário autenticado poderia usar o próprio scanner
# como proxy para varrer a rede interna do servidor (SSRF).
#
# Para testes controlados em ambiente de desenvolvimento (ex: apontar o DAST
# para um homólogo rodando em localhost), defina explicitamente:
#   DAST_PERMITIR_REDE_INTERNA=true
# Nunca habilite essa flag em produção.
DAST_PERMITIR_REDE_INTERNA = os.environ.get(
    "DAST_PERMITIR_REDE_INTERNA", "false"
).strip().lower() in ("1", "true", "yes")


def _validar_alvo_dast(url: str) -> tuple[bool, str]:
    """Resolve o hostname da URL e garante que nenhum IP resultante aponta
    para rede interna, loopback, link-local ou outra faixa reservada.

    Retorna (True, "") se o alvo é seguro para varredura, ou
    (False, motivo) caso deva ser bloqueado.
    """
    if DAST_PERMITIR_REDE_INTERNA:
        return True, ""

    try:
        partes = urlparse(url)
    except ValueError:
        return False, "URL malformada."

    hostname = partes.hostname
    if not hostname:
        return False, "Não foi possível identificar o host da URL."

    try:
        # Resolve TODOS os endereços associados ao hostname — um domínio
        # pode ter múltiplos registros A/AAAA, e todos precisam ser seguros.
        enderecos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, f"Não foi possível resolver o host '{hostname}'."

    for familia, _, _, _, sockaddr in enderecos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Endereço IP inválido resolvido para '{hostname}'."

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False, (
                f"Alvo bloqueado: '{hostname}' resolve para {ip_str}, "
                "um endereço de rede interna/reservado. O DAST só varre "
                "sistemas alcançáveis publicamente (ex: ambiente de "
                "homologação com URL pública)."
            )

    return True, ""


# ─────────────────────────────────────────────
# 14. ENTRY POINT — DAST via URL
# ─────────────────────────────────────────────

def executar_dast(url: str) -> dict:
    """Ponto de entrada DAST: recebe a URL de um sistema alvo, executa
    Spider + Active Scan via OWASP ZAP (ou usa alertas simulados caso o
    daemon não esteja disponível localmente) e retorna achados normalizados
    já filtrados pela triagem Multi-LLM (Fase 3).

    Retorna dicionário:
        - 'achados': lista de vulnerabilidades normalizadas
        - 'total_alertas': quantos alertas brutos o ZAP (ou o mock) retornou
        - 'total_achados': quantos sobreviveram à triagem Multi-LLM
        - 'achados_descartados': quantos foram descartados pela triagem
        - 'triagem_aplicada': se a triagem multi-LLM estava configurada
        - 'mock_usado': True se o ZAP não estava disponível e o fallback
          simulado foi usado
        - 'url_alvo': a URL analisada
        - 'erro': None se OK, ou mensagem de erro
    """
    resultado = {
        "achados": [],
        "total_alertas": 0,
        "total_achados": 0,
        "achados_descartados": 0,
        "triagem_aplicada": False,
        "mock_usado": False,
        "url_alvo": url,
        "erro": None,
    }

    url = (url or "").strip()
    if not url:
        resultado["erro"] = "Informe a URL do sistema alvo."
        return resultado

    if not re.match(r"^https?://", url, re.IGNORECASE):
        resultado["erro"] = "URL inválida. Utilize o formato http(s)://dominio.com"
        return resultado

    # Proteção contra SSRF — recusa alvos em rede interna/loopback/reservada
    # antes de repassar a URL ao ZAP (real ou mock).
    alvo_seguro, motivo_bloqueio = _validar_alvo_dast(url)
    if not alvo_seguro:
        resultado["erro"] = motivo_bloqueio
        return resultado

    try:
        if _zap_disponivel():
            alertas = _executar_zap_real(url)
            resultado["mock_usado"] = False
        else:
            alertas = _gerar_alertas_mock(url)
            resultado["mock_usado"] = True

        resultado["total_alertas"] = len(alertas)

        achados = processar_achados_zap(alertas, url)
        achados_filtrados, descartados, triagem_aplicada = aplicar_triagem_llm(achados)

        resultado["achados"] = achados_filtrados
        resultado["total_achados"] = len(achados_filtrados)
        resultado["achados_descartados"] = descartados
        resultado["triagem_aplicada"] = triagem_aplicada

    except RuntimeError as e:
        logger.error("Falha operacional no DAST (%s)", type(e).__name__)
        resultado["erro"] = "Servico DAST indisponivel."
    except Exception:
        logger.exception("Falha inesperada durante o DAST")
        resultado["erro"] = "Erro interno inesperado durante o DAST."

    return resultado
