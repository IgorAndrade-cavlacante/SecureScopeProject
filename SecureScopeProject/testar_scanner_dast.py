import requests
import json
import os

print("Autenticando na API do SecureScope...")
# Tenta registrar um usuário de teste (pode dar erro se já existir, mas ignoramos)
email_teste = os.environ.get("SCANNER_TEST_EMAIL", "scanner-test@example.invalid")
senha_teste = os.environ.get("SCANNER_TEST_PASSWORD", "SenhaLocalTemporaria123")
auth_url = "http://127.0.0.1:5000/auth/register"
auth_data = {"email": email_teste, "senha": senha_teste, "nome": "Testador Scanner"}
requests.post(auth_url, json=auth_data)

# Loga para pegar o JWT
login_url = "http://127.0.0.1:5000/auth/login"
resp_login = requests.post(login_url, json={"email": email_teste, "senha": senha_teste})
if resp_login.status_code != 200:
    print("Erro ao tentar logar:", resp_login.text)
    exit(1)

token = resp_login.json().get("access_token")
headers = {"Authorization": f"Bearer {token}"}

url_scanner = "http://127.0.0.1:5000/scanner/analisar-url"

# ─────────────────────────────────────────────
# Teste 1 — Proteção contra SSRF
# Confirma que o scanner recusa varrer alvos internos (rede local, loopback,
# metadata de nuvem etc.) antes mesmo de tentar falar com o ZAP.
# ─────────────────────────────────────────────
print("--- Teste 1: proteção contra SSRF (alvo interno deve ser bloqueado) ---")
alvos_internos = [
    "http://127.0.0.1:5000/painel",
    "http://169.254.169.254/latest/meta-data/",
]
for alvo in alvos_internos:
    resp = requests.post(url_scanner, json={"url": alvo}, headers=headers)
    bloqueado = resp.status_code == 400 and "bloqueado" in resp.json().get("erro", "").lower()
    status_txt = "OK (bloqueado)" if bloqueado else "FALHOU (deveria ter bloqueado)"
    print(f" [{status_txt}] {alvo} -> HTTP {resp.status_code} | {resp.json().get('erro')}")

# ─────────────────────────────────────────────
# Teste 2 — Varredura DAST real/mock contra um alvo público de teste
#
# testphp.vulnweb.com é um alvo mantido pela Acunetix especificamente para
# testes legais de scanners de segurança (usado nos próprios tutoriais do
# OWASP ZAP). Se você tiver um ambiente de homologação próprio com permissão
# para varrer, defina a variável de ambiente DAST_TESTE_URL antes de rodar
# este script para usá-lo no lugar.
# ─────────────────────────────────────────────
url_alvo = os.environ.get("DAST_TESTE_URL", "http://testphp.vulnweb.com")

print(f"\n--- Teste 2: varredura DAST contra alvo público de teste ({url_alvo}) ---")
print("Aguarde (Spider + Active Scan via ZAP real, ou fallback simulado se o daemon não estiver rodando)...\n")

response = requests.post(url_scanner, json={"url": url_alvo}, headers=headers)

print(f"Status da Resposta: {response.status_code}")
if response.status_code == 201:
    dados = response.json()
    print("\n--- RESULTADO DA VARREDURA DAST/MULTI-LLM ---")
    print(f"Scan ID: {dados.get('scan_id')}")
    print(f"URL alvo: {dados.get('url_alvo')}")
    print(f"ZAP simulado (mock)? {'Sim' if dados.get('zap_mock_usado') else 'Não (ZAP real)'}")
    print(f"Alertas brutos do ZAP: {dados.get('total_alertas_zap')}")
    print(f"Vulnerabilidades Confirmadas: {dados.get('total_vulnerabilidades_encontradas')}")
    print(f"Achados Descartados pela IA: {dados.get('achados_descartados')}")
    print(f"Triagem Aplicada? {'Sim (Ativa!)' if dados.get('triagem_aplicada') else 'Não (Modo Degradado)'}")
    print("\nDetalhes das Vulnerabilidades Confirmadas (inseridas no Banco de Dados):")

    for vuln in dados.get("vulnerabilidades", []):
        print(
            f" - {vuln.get('url', '')} [{vuln.get('cwe', '')}] "
            f"| Gravidade: {vuln.get('gravidade', '')} "
            f"| SLA: {vuln.get('sla_prioridade', '')} "
            f"| Confiança ZAP/IA: {vuln.get('confianca_zap', '')}"
        )
else:
    print("Erro:", response.text)

print("\nVocê também pode ver os resultados no painel: http://127.0.0.1:5000/painel")
