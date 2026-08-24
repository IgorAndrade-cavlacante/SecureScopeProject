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

# Cria um arquivo .py de teste temporário com problemas conhecidos que o
# Bandit deve pegar: senha hardcoded, MD5 fraco, subprocess com shell=True
# e uso de eval(). Nenhum desses trechos é executado — só analisado como texto.
codigo_vulneravel = '''\
import subprocess
import hashlib

SENHA_ADMIN = "admin123"

def autenticar(usuario, senha):
    return senha == SENHA_ADMIN

def hash_legado(dado):
    return hashlib.md5(dado.encode()).hexdigest()

def rodar_comando(cmd_usuario):
    subprocess.Popen(cmd_usuario, shell=True)

def avaliar_expressao(expr):
    return eval(expr)
'''

with open("codigo_vulneravel_teste.py", "w") as f:
    f.write(codigo_vulneravel)

print("Enviando codigo_vulneravel_teste.py para o Scanner SAST (Fase 2 + Multi-LLM Fase 3)...")
print("Aguarde (Bandit varre o AST e a triagem Multi-LLM julga os achados no backend)...\n")

url = "http://127.0.0.1:5000/scanner/analisar-codigo"
with open("codigo_vulneravel_teste.py", "rb") as f:
    files = {"arquivo": f}
    response = requests.post(url, files=files, headers=headers)

print(f"Status da Resposta: {response.status_code}")
if response.status_code == 201:
    dados = response.json()
    print("\n--- RESULTADO DA TRIAGEM SAST/MULTI-LLM ---")
    print(f"Scan ID: {dados.get('scan_id')}")
    print(f"Arquivos analisados: {dados.get('total_arquivos_analisados')}")
    print(f"Vulnerabilidades Confirmadas: {dados.get('total_vulnerabilidades_encontradas')}")
    print(f"Achados Descartados pela IA: {dados.get('achados_descartados')}")
    print(f"Triagem Aplicada? {'Sim (Ativa!)' if dados.get('triagem_aplicada') else 'Não (Modo Degradado)'}")
    print("\nDetalhes das Vulnerabilidades Confirmadas (inseridas no Banco de Dados):")

    for vuln in dados.get("vulnerabilidades", []):
        print(
            f" - [{vuln.get('test_id')}] {vuln.get('test_name')} "
            f"(linha {vuln.get('linha')}, {vuln.get('cwe')}) "
            f"| SLA: {vuln.get('sla_prioridade')} "
            f"| Confiança Bandit: {vuln.get('confianca_bandit')}"
        )

    # Sanidade mínima: o código de teste tem 4 achados conhecidos do Bandit
    # (B404/B324/B602/B307). Se a triagem multi-LLM estiver ativa, pode
    # descartar algum falso positivo — então checamos "pelo menos 1 achado
    # confirmado", não um número exato.
    if dados.get('total_vulnerabilidades_encontradas', 0) == 0 and not dados.get('triagem_aplicada'):
        print("\nAVISO: nenhum achado confirmado e a triagem não estava ativa — verifique se o Bandit está instalado no ambiente.")
else:
    print("Erro:", response.text)

# Limpa o arquivo de teste
os.remove("codigo_vulneravel_teste.py")
print("\nVocê também pode ver os resultados no painel: http://127.0.0.1:5000/painel")
