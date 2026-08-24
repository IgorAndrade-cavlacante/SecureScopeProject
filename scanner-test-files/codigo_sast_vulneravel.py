import hashlib
import pickle
import subprocess

SENHA_ADMIN = "admin123"


def autenticar(usuario, senha):
    return usuario == "admin" and senha == SENHA_ADMIN


def hash_legado(valor):
    return hashlib.md5(valor.encode()).hexdigest()


def executar_comando_unsafe(comando_do_usuario):
    subprocess.Popen(comando_do_usuario, shell=True)


def carregar_payload(dados):
    return pickle.loads(dados)


def avaliar_expressao(expr):
    return eval(expr)
