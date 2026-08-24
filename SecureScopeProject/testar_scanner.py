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

# Cria um arquivo requirements.txt de teste temporário
with open("requirements_teste.txt", "w") as f:
    f.write("requests==2.20.0\n")
    f.write("flask==0.12.2\n")

print("Enviando arquivo requirements_teste.txt para o Scanner Multi-LLM (Fase 3)...")
print("Aguarde (a IA do Groq e do Gemini estão julgando os achados no backend)...\n")

url = "http://127.0.0.1:5000/scanner/analisar"
with open("requirements_teste.txt", "rb") as f:
    files = {"arquivo": f}
    response = requests.post(url, files=files, headers=headers)

print(f"Status da Resposta: {response.status_code}")
if response.status_code == 201:
    dados = response.json()
    print("\n--- RESULTADO DA TRIAGEM MULTI-LLM ---")
    print(f"Arquivo analisado: {dados.get('nome_arquivo')}")
    print(f"Vulnerabilidades Totais (brutas): {dados.get('total_vulnerabilidades_encontradas')}")
    print(f"Achados Descartados pela IA: {dados.get('achados_descartados')}")
    print(f"Triagem Aplicada? {'Sim (Ativa!)' if dados.get('triagem_aplicada') else 'Não (Modo Degradado)'}")
    print("\nDetalhes das Vulnerabilidades Confirmadas (inseridas no Banco de Dados):")
    
    for vuln in dados.get("vulnerabilidades_confirmadas", dados.get("vulnerabilidades", [])):
        orig = vuln.get('origem_scan', vuln.get('origem', 'SCA/Scanner'))
        ativo = vuln.get('ativo', vuln.get('nome', ''))
        osv = vuln.get('_osv_id', '')
        conf = vuln.get('confianca_ia', 0.0)
        print(f" - [{orig}] {ativo}: {osv} | Confiança da IA: {conf}")
else:
    print("Erro:", response.text)

# Limpa o arquivo de teste
os.remove("requirements_teste.txt")
print("\nVocê também pode ver os resultados no painel: http://127.0.0.1:5000/painel")
