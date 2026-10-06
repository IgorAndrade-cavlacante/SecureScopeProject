"""Fila persistida no banco, snapshots e consolidação transacional de scans."""
import base64
import hashlib
import json
import logging
import os
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from werkzeug.exceptions import BadRequest, NotFound, Conflict, TooManyRequests
from werkzeug.utils import secure_filename
import scanner
import ia
from gestao import conexao, uid, agora, inteiro, auditar

bp = Blueprint('scan_jobs', __name__)
_thread = None
_lock = threading.Lock()
_serializer = None
MAX_JOB_SECONDS = 1800


def configurar(serializer):
    global _serializer
    _serializer = serializer


def identidade_achado(tipo, alvo, achado):
    # Inclui o alvo lógico para não fundir dois projetos que usam o mesmo pacote.
    regra = (achado.get('_test_id') if tipo == 'sast' else
             (achado.get('cve_id') or achado.get('_osv_id')) if tipo == 'sca' else
             (achado.get('_plugin_id') or achado.get('_titulo') or achado.get('nome')))
    fields = [tipo, alvo, achado.get('ativo', ''), regra or achado.get('nome', '')]
    if tipo == 'sast':
        fields.append(str(achado.get('_linha', '')))
    if tipo == 'dast':
        fields.append(achado.get('_parametro', ''))
    return hashlib.sha256(json.dumps(fields, ensure_ascii=False).encode()).hexdigest()


def receber(tipo):
    """Rotas antigas continuam síncronas; o painel pede segundo_plano=1."""
    body = request.get_json(silent=True) if tipo == 'dast' else request.form
    if body is None or (tipo == 'dast' and not isinstance(body, dict)):
        raise BadRequest('Envie um objeto JSON.')
    if tipo == 'dast':
        url = body.get('url', '')
        if not isinstance(url, str) or not url.strip() or len(url) > 2048:
            raise BadRequest('Informe uma URL válida.')
        url = url.strip()
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError()
            parsed.port
        except ValueError:
            raise BadRequest('URL inválida. Use http ou https, sem credenciais.')
        # A validação SSRF completa também ocorre no scanner, no momento de uso.
        name = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or '/', parsed.query, ''))
        payload = {'url': name}
    else:
        upload = request.files.get('arquivo')
        if not upload or not upload.filename:
            raise BadRequest('Selecione um arquivo.')
        name = secure_filename(upload.filename)
        extension = name.rsplit('.', 1)[-1].lower()
        if extension not in (('txt',) if tipo == 'sca' else ('py', 'zip')):
            raise BadRequest('Use .txt para SCA ou .py/.zip para SAST.')
        content = upload.read(10 * 1024 * 1024 + 1)
        if not content or len(content) > 10 * 1024 * 1024:
            raise BadRequest('Envie um arquivo não vazio de até 10 MB.')
        if tipo == 'sca':
            try:
                content.decode('utf-8')
            except UnicodeDecodeError:
                raise BadRequest('Use UTF-8 no arquivo de dependências.')
        payload = {'conteudo': base64.b64encode(content).decode(), 'extensao': extension}
    target = body.get('alvo', '')
    if not isinstance(target, str) or len(target.strip()) > 200:
        raise BadRequest('Identifique o projeto com até 200 caracteres.')
    target = name if tipo == 'dast' else (target.strip() or name)
    background = str(body.get('segundo_plano', '0')).lower() in ('1', 'true')
    with conexao() as conn:
        # Serializa admissões da mesma conta, inclusive com vários workers web.
        conn.execute('UPDATE usuarios SET alerta_sla_dias = alerta_sla_dias WHERE id = ?', (uid(),))
        count = conn.execute("SELECT COUNT(*) AS n FROM scans WHERE usuario_id = ? AND status IN ('na_fila','em_progresso')", (uid(),)).fetchone()['n']
        if count >= 3:
            raise TooManyRequests('Você já tem três scans pendentes. Aguarde uma conclusão.')
        sid = conn.execute('''INSERT INTO scans (usuario_id, nome_arquivo, status, data_inicio,
            tipo, alvo, payload, etapa) VALUES (?, ?, 'na_fila', ?, ?, ?, ?, 'Aguardando processamento') RETURNING id''',
            (uid(), name, agora(), tipo, target, json.dumps(payload))).fetchone()['id']
    if background:
        return jsonify(scan_id=sid, status='na_fila', message='Scan enfileirado. Acompanhe no histórico.'), 202
    claim = reservar(sid)
    if not claim:
        # Um worker pode ter assumido o job após o commit.
        return jsonify(scan_id=sid, status='em_progresso'), 202
    result, code = executar(claim)
    return jsonify(result), code


def reservar(sid=None):
    with conexao() as conn:
        cutoff = (datetime.now() - timedelta(seconds=MAX_JOB_SECONDS)).strftime('%Y-%m-%d %H:%M:%S')
        conn.execute('''UPDATE scans SET status = 'erro', erro = 'Execução interrompida ou tempo limite excedido. Execute novamente.',
            etapa = 'Interrompido', payload = NULL, token_execucao = NULL, data_fim = ?
            WHERE status = 'em_progresso' AND (iniciado_worker_em < ? OR
                (iniciado_worker_em IS NULL AND data_inicio < ?))''', (agora(), cutoff, cutoff))
        token = secrets.token_hex(24)
        where = 'id = ?' if sid is not None else "id = (SELECT id FROM scans WHERE status = 'na_fila' ORDER BY id LIMIT 1)"
        args = (token, agora()) + ((sid,) if sid is not None else ())
        return conn.execute(f'''UPDATE scans SET status = 'em_progresso', token_execucao = ?,
            iniciado_worker_em = ?, progresso = 15, etapa = 'Analisando o alvo'
            WHERE {where} AND status = 'na_fila' RETURNING *''', args).fetchone()


def _resultado_base(job, result):
    return dict(scan_id=job['id'], status='concluido', nome_arquivo=job['nome_arquivo'],
                url_alvo=job['nome_arquivo'] if job['tipo'] == 'dast' else '',
                tipo=job['tipo'], alvo=job['alvo'], modo_scan=result.get('modo_scan', ''),
                total_pacotes_analisados=result.get('total_pacotes', 0),
                total_arquivos_analisados=result.get('total_arquivos', 0),
                total_alertas_zap=result.get('total_alertas', 0),
                pacotes_sem_vuln=result.get('pacotes_sem_vuln', []),
                achados_descartados=result.get('achados_descartados', 0),
                triagem_aplicada=result.get('triagem_aplicada', False),
                data_inicio=job['data_inicio'], data_fim=agora(), vulnerabilidades=[])


def _consolidar(job, result):
    summary = _resultado_base(job, result)
    novos, repetidos, seen = 0, 0, set()
    with conexao() as conn:
        # Adquire trava de escrita antes de ler achados: SQLite e PostgreSQL.
        active = conn.execute('''UPDATE scans SET progresso = 85, etapa = 'Salvando resultados'
            WHERE id = ? AND token_execucao = ? AND status = 'em_progresso' RETURNING id''',
            (job['id'], job['token_execucao'])).fetchone()
        if not active:
            raise Conflict('A execução foi encerrada por outro worker.')
        for a in result['achados']:
            fingerprint = identidade_achado(job['tipo'], job['alvo'], a)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            score = ia.calcular_risk_index(a['impacto'], a['frequencia'], a['gravidade'])
            fatores = {k: bool(a.get(k)) for k in ('exposta_internet', 'exploit_publico', 'dados_sensiveis',
                       'escalonamento_privilegio', 'ambiente_producao')}
            cvss = a.get('cvss_score', 0)
            if cvss > 0 or a.get('no_kev'):
                prioridade, nivel, prazo, explicacao = ia.calcular_prioridade_v2(
                    cvss, a.get('epss_score', 0), a.get('no_kev', False), fatores,
                    risk_index_base=score, epss_disponivel=a.get('_epss_disponivel', False))
            else:
                prioridade, explicacao = ia.calcular_prioridade(score, fatores)
                nivel, prazo = ia.classificar_sla(prioridade)
            data = dict(nome=a['nome'], impacto=a['impacto'], frequencia=a['frequencia'], gravidade=a['gravidade'],
                        score=score, status='Aberta', data=agora(), categoria=ia.detectar_categoria(a['nome']),
                        prioridade=prioridade, explicacao=' | '.join(explicacao), origem=a.get('origem', 'Scanner Automatizado'),
                        ativo=a.get('ativo', ''), cvss_score=cvss, epss_score=a.get('epss_score', 0),
                        cve_id=a.get('cve_id', ''), no_kev=int(a.get('no_kev', False)), sla_prazo_dias=prazo,
                        sla_prioridade=nivel, usuario_id=job['usuario_id'], origem_scan=job['id'],
                        confianca_ia=a.get('confianca_ia', 0), detalhes_scanner=_serializer(a, job['tipo']),
                        fingerprint=fingerprint, **{k: int(v) for k, v in fatores.items()})
            cols = ','.join(data)
            inserted = conn.execute(f'''INSERT INTO vulnerabilidades ({cols}) VALUES ({','.join('?' for _ in data)})
                ON CONFLICT(usuario_id, fingerprint) DO NOTHING RETURNING id''', tuple(data.values())).fetchone()
            if inserted:
                vid = inserted['id']; novos += 1
                auditar(conn, vid, 'Scanner', f'Detectada em scan #{job["id"]} ({job["tipo"].upper()})')
            else:
                v = conn.execute('SELECT id, status FROM vulnerabilidades WHERE usuario_id = ? AND fingerprint = ?',
                                 (job['usuario_id'], fingerprint)).fetchone()
                vid = v['id']; repetidos += 1
                # Não sobrescreve decisões humanas. A recorrência fica explícita no histórico.
                auditar(conn, vid, 'Scanner', f'Redetectada no scan #{job["id"]}; status preservado: {v["status"]}')
            snapshot = dict(vuln_id=vid, nome=a.get('_titulo') or a['nome'], arquivo=a.get('ativo', ''),
                            linha=a.get('_linha', ''), test_id=a.get('_test_id', ''), cwe=a.get('_cwe_id', ''),
                            pacote=a.get('ativo', ''), url=a.get('ativo', ''), cve_id=a.get('cve_id', ''),
                            cvss_score=cvss, prioridade=prioridade, sla_prioridade=nivel,
                            gravidade=a.get('_gravidade_texto', ''), detalhes=json.loads(data['detalhes_scanner']))
            conn.execute('INSERT INTO scan_achados VALUES (?, ?, ?, ?)',
                         (job['id'], vid, fingerprint, json.dumps(snapshot, ensure_ascii=False)))
            summary['vulnerabilidades'].append(snapshot)
        summary.update(total_vulnerabilidades_encontradas=len(seen), novos_achados=novos, achados_repetidos=repetidos)
        conn.execute('''UPDATE scans SET status = 'concluido', progresso = 100, etapa = 'Concluído',
            total_achados = ?, data_fim = ?, resultado = ?, payload = NULL, token_execucao = NULL, modo_scan = ? WHERE id = ?''',
            (len(seen), agora(), json.dumps(summary, ensure_ascii=False), result.get('modo_scan', ''), job['id']))
    return summary


def executar(job):
    """Nenhum achado parcial é publicado: consolidação e snapshots são atômicos."""
    try:
        payload = json.loads(job['payload'])
        tipo = job['tipo']
        if tipo == 'dast':
            result = scanner.executar_dast(payload['url'])
        else:
            content = base64.b64decode(payload['conteudo'])
            if tipo == 'sca':
                result = scanner.executar_sca(content.decode('utf-8'))
            elif payload['extensao'] == 'zip':
                result = scanner.executar_sast_zip(content)
            else:
                result = scanner.executar_sast(content, job['nome_arquivo'])
        if result.get('erro'):
            error = str(result['erro'])
            code = 400 if result.get('erro_codigo') in ('REQUIREMENTS_INVALIDO', 'LIMITE_PACOTES_EXCEDIDO') or any(
                t in error for t in ('URL inválida', 'Alvo bloqueado', 'Não foi possível resolver', 'URL malformada')) else 502
            response = dict(scan_id=job['id'], status='erro', erro=error, erro_codigo=result.get('erro_codigo'))
        else:
            return _consolidar(job, result), 201
    except Exception:
        logging.exception('Erro no scan %s', job['id'])
        response, code = dict(scan_id=job['id'], status='erro', erro='Falha interna durante o scan. Execute novamente.'), 500
    with conexao() as conn:
        conn.execute('''UPDATE scans SET status = 'erro', erro = ?, etapa = 'Erro', data_fim = ?,
            payload = NULL, resultado = ?, token_execucao = NULL WHERE id = ? AND token_execucao = ?''',
            (response['erro'], agora(), json.dumps(response), job['id'], job['token_execucao']))
    return response, code


def processar_um(isolar=False):
    job = reservar()
    if job:
        if not isolar:
            executar(job)
        else:
            # Processo separado limita o tempo inclusive de SDKs externos que
            # travem. O web server continua respondendo durante todo o scan.
            try:
                subprocess.run([sys.executable, str(Path(__file__).with_name('worker.py')),
                                '--scan', str(job['id']), '--token', job['token_execucao']],
                               timeout=MAX_JOB_SECONDS, check=True)
                failure = 'O processador terminou sem finalizar o scan.'
            except subprocess.TimeoutExpired:
                failure = 'Tempo limite de 30 minutos excedido. Execute novamente.'
            except (subprocess.CalledProcessError, OSError):
                logging.exception('Falha ao executar processo do scan %s', job['id'])
                failure = 'Processador interrompido. Execute novamente.'
            with conexao() as conn:
                conn.execute('''UPDATE scans SET status = 'erro', erro = ?, etapa = 'Interrompido',
                    data_fim = ?, payload = NULL, token_execucao = NULL
                    WHERE id = ? AND token_execucao = ? AND status = 'em_progresso' ''',
                    (failure, agora(), job['id'], job['token_execucao']))
    return bool(job)


def loop_worker():
    while True:
        try:
            if not processar_um(isolar=True):
                time.sleep(2)
        except Exception:
            logging.exception('Falha no worker; nova tentativa em 5 segundos')
            time.sleep(5)


def iniciar_embutido():
    global _thread
    enabled = os.environ.get('SCAN_WORKER_EMBUTIDO', '1' if os.environ.get('APP_ENV', 'development') == 'development' else '0')
    if enabled.lower() not in ('1', 'true'):
        return
    with _lock:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=loop_worker, name='securescope-scanner', daemon=True)
            _thread.start()


def ler_scan(conn, sid, usuario):
    row = conn.execute('''SELECT id, tipo, alvo, nome_arquivo, status, total_achados, data_inicio,
        data_fim, progresso, etapa, erro, resultado, modo_scan FROM scans WHERE id = ? AND usuario_id = ?''',
        (sid, usuario)).fetchone()
    if not row:
        raise NotFound('Scan não encontrado.')
    return dict(row)


@bp.get('/scans')
@jwt_required()
def listar():
    page = inteiro(request.args.get('pagina', 1), 'Página')
    with conexao() as conn:
        count = conn.execute('SELECT COUNT(*) AS n FROM scans WHERE usuario_id = ?', (uid(),)).fetchone()['n']
        rows = conn.execute('''SELECT id, tipo, alvo, nome_arquivo, status, total_achados,
            data_inicio, data_fim, progresso, etapa, erro FROM scans WHERE usuario_id = ?
            ORDER BY id DESC LIMIT 20 OFFSET ?''', (uid(), (page-1)*20)).fetchall()
    return jsonify(scans=rows, total=count, pagina=page, por_pagina=20)


@bp.get('/scans/<int:sid>')
@jwt_required()
def detalhe(sid):
    with conexao() as conn:
        row = ler_scan(conn, sid, uid())
        row['resultado'] = json.loads(row['resultado']) if row['resultado'] else None
        return jsonify(row)


@bp.get('/scans/comparar')
@jwt_required()
def comparar():
    before = inteiro(request.args.get('antes'), 'Scan anterior')
    after = inteiro(request.args.get('depois'), 'Scan posterior')
    if before >= after:
        raise BadRequest('Escolha duas execuções diferentes, da mais antiga para a mais recente.')
    with conexao() as conn:
        a, b = ler_scan(conn, before, uid()), ler_scan(conn, after, uid())
        if a['status'] != 'concluido' or b['status'] != 'concluido':
            raise Conflict('Compare apenas scans concluídos.')
        if not a['tipo'] or not a['resultado'] or not b['resultado']:
            raise Conflict('Scans antigos sem snapshots não podem ser comparados. Execute novamente.')
        if (a['tipo'], a['alvo'], a['modo_scan']) != (b['tipo'], b['alvo'], b['modo_scan']):
            raise BadRequest('Os scans precisam ter o mesmo tipo, projeto/alvo e modo de análise.')
        def snapshots(sid):
            return {r['fingerprint']: json.loads(r['snapshot']) for r in conn.execute(
                'SELECT fingerprint, snapshot FROM scan_achados WHERE scan_id = ?', (sid,)).fetchall()}
        old, new = snapshots(before), snapshots(after)
        return jsonify(novos=[new[k] for k in sorted(new.keys()-old.keys())],
                       persistentes=[new[k] for k in sorted(new.keys() & old.keys())],
                       nao_detectados=[old[k] for k in sorted(old.keys()-new.keys())],
                       aviso='Não detectado novamente não significa corrigido.')
