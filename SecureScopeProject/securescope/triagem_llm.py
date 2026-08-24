import os
import json
import logging
from abc import ABC, abstractmethod

# Log configuration
logger = logging.getLogger(__name__)

class ProvedorLLM(ABC):
    """
    Interface base para todos os provedores de IA que farão a triagem.
    """
    @abstractmethod
    def triar_achado(self, achado: dict) -> dict:
        """
        Recebe um dicionário com o achado bruto (de SCA ou SAST).
        Deve retornar um dicionário com:
        - veredito: "confirmar", "descartar" ou "revisar_manual"
        - severidade_ajustada: float (0.0 a 10.0)
        - justificativa: str
        - confianca: float (0.0 a 1.0)
        """
        pass

def criar_prompt(achado: dict) -> str:
    # Formata os dados do achado para uma representação amigável para o LLM
    dados_achado = json.dumps(achado, indent=2, ensure_ascii=False)
    
    prompt = f"""Você é um especialista em segurança da informação (AppSec) analisando uma possível vulnerabilidade encontrada em um projeto Python/Flask.
    
Seu objetivo é analisar o achado abaixo, que foi identificado por uma ferramenta de segurança automatizada (SCA ou SAST), e determinar se ele é um Falso Positivo ou se é um risco real que precisa de atenção.

DADOS DO ACHADO:
{dados_achado}

Responda EXCLUSIVAMENTE em formato JSON com a seguinte estrutura:
{{
  "veredito": "confirmar" | "descartar" | "revisar_manual",
  "severidade_ajustada": <float de 0.0 a 10.0>,
  "justificativa": "<texto explicando o motivo do veredito>",
  "confianca": <float de 0.0 a 1.0>
}}

Use "descartar" se for claramente um falso positivo.
Use "confirmar" se for uma vulnerabilidade real.
Use "revisar_manual" se houver incerteza.
A resposta DEVE ser apenas o JSON, sem markdown ou explicações adicionais fora do JSON.
"""
    return prompt

class ProvedorGemini(ProvedorLLM):
    def __init__(self, api_key: str):
        from google import genai
        self.client = genai.Client(api_key=api_key)
        self.model_name = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        
    def triar_achado(self, achado: dict) -> dict:
        try:
            prompt = criar_prompt(achado)
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config={"response_mime_type": "application/json"},
            )
            resultado = json.loads(response.text or "{}")
            
            # Validação básica
            if "veredito" not in resultado:
                raise ValueError("JSON de resposta incompleto")
                
            return {
                "veredito": resultado.get("veredito", "revisar_manual"),
                "severidade_ajustada": float(resultado.get("severidade_ajustada", 5.0)),
                "justificativa": resultado.get("justificativa", ""),
                "confianca": float(resultado.get("confianca", 0.5)),
                "erro": False
            }
        except Exception as e:
            logger.error("Falha no Gemini (%s)", type(e).__name__)
            return {
                "veredito": "revisar_manual",
                "severidade_ajustada": 5.0,
                "justificativa": "A analise automatica falhou; revise o achado manualmente.",
                "confianca": 0.0,
                "erro": True
            }

class ProvedorGroq(ProvedorLLM):
    def __init__(self, api_key: str):
        from groq import Groq
        self.client = Groq(api_key=api_key)
        # Using llama-3.3-70b-versatile for high capability
        self.model_name = "llama-3.3-70b-versatile"
        
    def triar_achado(self, achado: dict) -> dict:
        try:
            prompt = criar_prompt(achado)
            
            completion = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "Você é um especialista em segurança de aplicações. Responda apenas com JSON válido."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"}
            )
            
            resposta_texto = completion.choices[0].message.content
            resultado = json.loads(resposta_texto)
            
            return {
                "veredito": resultado.get("veredito", "revisar_manual"),
                "severidade_ajustada": float(resultado.get("severidade_ajustada", 5.0)),
                "justificativa": resultado.get("justificativa", ""),
                "confianca": float(resultado.get("confianca", 0.5)),
                "erro": False
            }
        except Exception as e:
            logger.error("Falha no Groq (%s)", type(e).__name__)
            return {
                "veredito": "revisar_manual",
                "severidade_ajustada": 5.0,
                "justificativa": "A analise automatica falhou; revise o achado manualmente.",
                "confianca": 0.0,
                "erro": True
            }

class MotorTriagem:
    def __init__(self):
        self.provedores = []
        
        # Iniciar Gemini se a chave existir
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if gemini_key:
            try:
                self.provedores.append(("Gemini", ProvedorGemini(gemini_key)))
                logger.info("Provedor Gemini inicializado.")
            except ImportError:
                logger.warning("SDK do Gemini não instalado. Ignorando.")
                
        # Iniciar Groq se a chave existir
        groq_key = os.environ.get("GROQ_API_KEY")
        if groq_key:
            try:
                self.provedores.append(("Groq", ProvedorGroq(groq_key)))
                logger.info("Provedor Groq inicializado.")
            except ImportError:
                logger.warning("SDK do Groq não instalado. Ignorando.")

    def aplicar_triagem(self, achado: dict) -> dict:
        """
        Recebe um achado e submete a todos os provedores configurados.
        Retorna o dicionário consolidado do veredito.
        """
        num_provedores = len(self.provedores)
        
        # Modo degradado: sem IA, aceita tudo
        if num_provedores == 0:
            return {
                "veredito": "confirmar",
                "severidade_ajustada": float(achado.get("cvss_score", 5.0)),
                "justificativa": "Sem IA configurada (modo degradado).",
                "confianca_ia": 0.0
            }
            
        resultados = []
        for nome_provedor, provedor in self.provedores:
            res = provedor.triar_achado(achado)
            res['provedor'] = nome_provedor
            resultados.append(res)
            
        return self._calcular_consenso(resultados)
        
    def _calcular_consenso(self, resultados: list) -> dict:
        # Um provedor que falhou (timeout, rate limit, erro de rede) não deve
        # contar como um voto real — ele simplesmente não opinou. Contar o
        # fallback de erro como "revisar_manual" distorceria o consenso e
        # forçaria empates artificiais sempre que um provedor cair.
        justificativas_erro = [
            f"[{res.get('provedor', 'IA')}]: {res['justificativa']}"
            for res in resultados if res.get("erro", False)
        ]
        resultados_validos = [res for res in resultados if not res.get("erro", False)]

        # Todos os provedores falharam — não há voto real para consolidar.
        if not resultados_validos:
            return {
                "veredito": "revisar_manual",
                "severidade_ajustada": 5.0,
                "justificativa": "Todos os provedores de IA falharam. " + " | ".join(justificativas_erro),
                "confianca_ia": 0.0,
                "detalhes_votos": {"confirmar": 0, "descartar": 0, "revisar_manual": 0},
                "provedores_com_erro": len(justificativas_erro),
            }

        votos = {"confirmar": 0, "descartar": 0, "revisar_manual": 0}
        severidades = []
        confiancas = []
        justificativas = list(justificativas_erro)  # erros entram no relato, não na votação

        for res in resultados_validos:
            veredito = res["veredito"]
            if veredito in votos:
                votos[veredito] += 1
            else:
                votos["revisar_manual"] += 1

            severidades.append(res["severidade_ajustada"])
            confiancas.append(res["confianca"])
            justificativas.append(f"[{res.get('provedor', 'IA')}]: {res['justificativa']}")

        # Determina o veredito vencedor (maioria) entre quem de fato respondeu
        veredito_final = max(votos, key=votos.get)

        # Empate real entre provedores que responderam (ex: 2 válidos, 1 diz
        # descartar, 1 diz confirmar) — cai para revisar_manual por precaução.
        if list(votos.values()).count(votos[veredito_final]) > 1:
            veredito_final = "revisar_manual"

        severidade_final = sum(severidades) / len(severidades)

        # Confiança de consenso calculada só sobre quem respondeu de verdade.
        # Se os modelos concordam, a confiança é alta. Se discordam, é mais baixa.
        pct_concordancia = votos[veredito_final] / len(resultados_validos)
        media_confianca = sum(confiancas) / len(confiancas)
        confianca_final = pct_concordancia * media_confianca

        return {
            "veredito": veredito_final,
            "severidade_ajustada": severidade_final,
            "justificativa": " | ".join(justificativas),
            "confianca_ia": confianca_final,
            "detalhes_votos": votos,
            "provedores_com_erro": len(justificativas_erro),
        }
