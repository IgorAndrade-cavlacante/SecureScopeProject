import hashlib


def gerar_identificador_legado(valor: str) -> str:
    """Exemplo curto para a demonstração do achado Bandit B324."""
    return hashlib.md5(valor.encode()).hexdigest()
