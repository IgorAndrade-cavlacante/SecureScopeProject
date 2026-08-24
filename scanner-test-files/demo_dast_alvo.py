"""Alvo local e deliberadamente limitado para a demonstração do DAST.

Ele contém somente dois sinais observáveis esperados:
1. cookie de demonstração com nome de sessão sem HttpOnly;
2. versão do servidor de desenvolvimento no cabeçalho Server.

Não publique este arquivo como aplicação de produção.
"""

from flask import Flask, make_response


app = Flask(__name__)


@app.get("/")
def inicio():
    resposta = make_response(
        "<h1>SecureScope — alvo controlado para demonstração DAST</h1>"
    )
    resposta.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'"
    )
    resposta.headers["X-Frame-Options"] = "DENY"
    resposta.headers["X-Content-Type-Options"] = "nosniff"
    resposta.set_cookie(
        "session_demo",
        "valor-publico-sem-dados-reais",
        httponly=False,
        samesite="Lax",
    )
    return resposta


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=False)
