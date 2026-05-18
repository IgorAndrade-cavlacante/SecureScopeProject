import numpy as np


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

def calcular_risk_index(impacto, frequencia, gravidade):
    """Calcula o Risk Index™ usando a mesma fórmula do sistema."""
    return round((impacto * 0.4) + (frequencia * 0.3) + (gravidade * 0.3), 2)

def analisar_nome(nome):
    
    #Vai ver o nome que foi digitado e comparar com as palavra chave lá em cima
    
    if not nome:
        return VALORES_PADRAO

    nome_lower = nome.lower()
    melhor_categoria = None
    maior_matches = 0

    for categoria, dados in REGRAS_CATEGORIAS.items():
        matches = sum(1 for kw in dados["keywords"] if kw in nome_lower)
        if matches > maior_matches:
            maior_matches = matches
            melhor_categoria = categoria

    if melhor_categoria:
        dados = REGRAS_CATEGORIAS[melhor_categoria]
        return {
            "categoria": melhor_categoria,
            "impacto": dados["impacto"],
            "frequencia": dados["frequencia"],
            "gravidade": dados["gravidade"],
            "risk_index_sugerido": calcular_risk_index(
                dados["impacto"], dados["frequencia"], dados["gravidade"]
            )
        }

    return VALORES_PADRAO

def aprender_com_historico(conn):
    """
    Lê o banco, pega vulnerabilidades validadas e calcula estatísticas usando numpy.
    Retorna médias, máximos, mínimos e risco médio geral calculado com a fórmula do Risk Index™.
    """
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT impacto, frequencia, gravidade, score FROM vulnerabilidades WHERE status = 'Validada'"
        )
        linhas = cursor.fetchall()

        if not linhas:
            return {
                "status": "sem_dados",
                "mensagem": "Histórico insuficiente para insights da IA."
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
            "melhor_risco": round(float(np.min(scores)), 1)
        }

    except Exception as e:
        return {"status": "erro", "mensagem": str(e)}