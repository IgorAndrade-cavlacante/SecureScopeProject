"""Filtros, colaboração, ciclo de correção e alertas internos autenticados."""
import csv
import io
import json
from contextlib import contextmanager
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, Response
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.exceptions import BadRequest, NotFound, Forbidden, Conflict
import db

bp = Blueprint('gestao', __name__)
FECHADOS = ('Corrigida', 'Isolada (Circuit Breaker)')
STATUS = ('Aberta', 'Validada', 'Isolada (Circuit Breaker)', 'Corrigida')


def agora():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


@contextmanager
def conexao():
    conn = db.get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def uid():
    try:
        return int(get_jwt_identity())
    except (ValueError, TypeError):
        raise Forbidden('Sessão inválida.')


def dados_json():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise BadRequest('Envie um objeto JSON.')
    return data


def texto(data, campo, maximo, obrigatorio=True):
    value = data.get(campo, '')
    if not isinstance(value, str) or len(value.strip()) > maximo:
        raise BadRequest(f'{campo}: use texto com até {maximo} caracteres.')
    value = value.strip()
    if obrigatorio and not value:
        raise BadRequest(f'Preencha {campo}.')
    return value


def inteiro(value, nome, minimo=1, maximo=2147483647):
    if isinstance(value, bool):
        raise BadRequest(f'{nome} inválido.')
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        raise BadRequest(f'{nome} inválido.')
    if not minimo <= number <= maximo:
        raise BadRequest(f'{nome} deve estar entre {minimo} e {maximo}.')
    return number


def membro(conn, equipe, usuario, escrita=False, gestor=False):
    row = conn.execute('SELECT papel FROM equipe_membros WHERE equipe_id = ? AND usuario_id = ?',
                       (equipe, usuario)).fetchone()
    if not row:
        raise NotFound('Equipe não encontrada.')
    if (gestor and row['papel'] != 'gestor') or (escrita and row['papel'] == 'leitor'):
        raise Forbidden('Seu papel não permite essa alteração.')
    return row['papel']


def obter_vulnerabilidade(conn, vid, usuario, escrita=False):
    row = conn.execute('SELECT * FROM vulnerabilidades WHERE id = ?', (vid,)).fetchone()
    if not row:
        raise NotFound('Vulnerabilidade não encontrada.')
    if row['usuario_id'] != usuario:
        if not row.get('equipe_id'):
            raise NotFound('Vulnerabilidade não encontrada.')
        membro(conn, row['equipe_id'], usuario, escrita=escrita)
    return dict(row)


def auditar(conn, vid, usuario, acao, antes='', depois=''):
    conn.execute('''INSERT INTO historico
        (vulnerabilidade_id, acao, responsavel, data, dados_anteriores, dados_novos)
        VALUES (?, ?, ?, ?, ?, ?)''',
        (vid, acao, str(usuario), agora(), str(antes), str(depois)))


def mudar_status(conn, vid, usuario, destino, justificativa):
    v = obter_vulnerabilidade(conn, vid, usuario, escrita=True)
    if destino not in STATUS:
        raise BadRequest('Status inválido.')
    if v['status'] == destino:
        raise Conflict('O achado já possui esse status.')
    if v['status'] == 'Corrigida' and destino != 'Aberta':
        raise Conflict('Reabra o achado antes de validar ou isolar.')
    if destino == 'Aberta' and v['status'] not in FECHADOS:
        raise Conflict('Só é possível reabrir um achado corrigido ou isolado.')
    if not justificativa.strip():
        raise BadRequest('Informe a justificativa.')
    instante = agora()
    conn.execute('UPDATE vulnerabilidades SET status = ?, corrigida_em = ? WHERE id = ?',
                 (destino, instante if destino == 'Corrigida' else None, vid))
    # Reabertura conserva o prazo original: não oculta violações passadas.
    prazo = (datetime.strptime(v['data'], '%Y-%m-%d %H:%M:%S') +
             timedelta(days=v['sla_prazo_dias'] or 90)).strftime('%Y-%m-%d %H:%M:%S')
    sla = 'Resolvido' if destino in FECHADOS else ('Violado' if prazo < instante else 'Em Prazo')
    if not conn.execute('SELECT id FROM sla_vulnerabilidades WHERE vulnerabilidade_id = ?', (vid,)).fetchone():
        conn.execute('''INSERT INTO sla_vulnerabilidades
            (vulnerabilidade_id, nivel_sla, prazo_dias, data_inicio, data_prazo)
            VALUES (?, ?, ?, ?, ?)''', (vid, v['sla_prioridade'], v['sla_prazo_dias'], v['data'], prazo))
    conn.execute('''UPDATE sla_vulnerabilidades SET data_resolucao = ?, status_sla = ?
        WHERE vulnerabilidade_id = ?''', (instante if destino in FECHADOS else None, sla, vid))
    auditar(conn, vid, usuario, f'{v["status"]} → {destino}: {justificativa}', v['status'], destino)


def filtrar(conn, usuario, args):
    clauses, values = [], []
    equipe = args.get('equipe_id')
    if equipe:
        equipe = inteiro(equipe, 'Equipe')
        membro(conn, equipe, usuario)
        clauses.append('v.equipe_id = ?'); values.append(equipe)
    else:
        clauses.append('v.usuario_id = ?'); values.append(usuario)
    for key in ('nome', 'ativo'):
        value = args.get(key, '').strip()
        if len(value) > 200:
            raise BadRequest('Filtro muito longo.')
        if value:
            value = value.lower().replace('!', '!!').replace('%', '!%').replace('_', '!_')
            clauses.append(f"LOWER(v.{key}) LIKE ? ESCAPE '!'"); values.append(f'%{value}%')
    for key in ('status', 'origem'):
        if args.get(key):
            if key == 'status' and args[key] not in STATUS:
                raise BadRequest('Status inválido.')
            clauses.append(f'v.{key} = ?'); values.append(args[key])
    priority = args.get('prioridade')
    if priority:
        levels = {'critica': (90, 101), 'alta': (70, 90), 'media': (40, 70), 'baixa': (0, 40)}
        if priority not in levels:
            raise BadRequest('Prioridade inválida.')
        clauses.append('v.prioridade >= ? AND v.prioridade < ?'); values.extend(levels[priority])
    return [dict(r) for r in conn.execute('''SELECT v.*, u.nome AS responsavel_nome,
        e.nome AS equipe_nome FROM vulnerabilidades v
        LEFT JOIN usuarios u ON u.id = v.responsavel_id LEFT JOIN equipes e ON e.id = v.equipe_id
        WHERE ''' + ' AND '.join(clauses) + ' ORDER BY v.prioridade DESC, v.id DESC', tuple(values)).fetchall()]


@bp.get('/gestao/vulnerabilidades')
@jwt_required()
def listar():
    with conexao() as conn:
        return jsonify(filtrar(conn, uid(), request.args))


@bp.get('/gestao/exportar/<formato>')
@jwt_required()
def exportar(formato):
    if formato not in ('csv', 'json'):
        raise BadRequest('Use csv ou json.')
    with conexao() as conn:
        rows = filtrar(conn, uid(), request.args)
    fields = ('id', 'nome', 'ativo', 'origem', 'prioridade', 'status', 'data',
              'sla_prioridade', 'sla_prazo_dias', 'cve_id', 'equipe_nome', 'responsavel_nome', 'corrigida_em')
    rows = [{key: row.get(key) for key in fields} for row in rows]
    if formato == 'json':
        data, mime = json.dumps(rows, ensure_ascii=False, indent=2), 'application/json'
    else:
        output = io.StringIO(newline='')
        writer = csv.DictWriter(output, fields, delimiter=';', quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            # Planilhas podem ignorar espaços/control characters antes de uma fórmula.
            writer.writerow({key: ("'" + val if isinstance(val, str) and
                (val.lstrip().startswith(('=', '+', '-', '@')) or val.startswith(('\t', '\r', '\n')))
                else val) for key, val in row.items()})
        data, mime = '\ufeff' + output.getvalue(), 'text/csv; charset=utf-8'
    return Response(data, content_type=mime, headers={
        'Content-Disposition': f'attachment; filename="securescope.{formato}"', 'Cache-Control': 'no-store'})


@bp.put('/gestao/vulnerabilidades/<int:vid>/status')
@jwt_required()
def status(vid):
    data = dados_json()
    with conexao() as conn:
        mudar_status(conn, vid, uid(), texto(data, 'status', 40), texto(data, 'justificativa', 1000))
    return jsonify(message='Status atualizado.')


@bp.get('/gestao/vulnerabilidades/<int:vid>')
@jwt_required()
def detalhe(vid):
    with conexao() as conn:
        v = obter_vulnerabilidade(conn, vid, uid())
        comentarios = conn.execute('''SELECT c.id, c.texto, c.criado_em, u.nome AS autor
            FROM comentarios c JOIN usuarios u ON u.id = c.usuario_id
            WHERE c.vulnerabilidade_id = ? ORDER BY c.id''', (vid,)).fetchall()
        historico = conn.execute('''SELECT h.*, u.nome AS autor FROM historico h
            LEFT JOIN usuarios u ON CAST(u.id AS TEXT) = h.responsavel
            WHERE vulnerabilidade_id = ? ORDER BY h.id''', (vid,)).fetchall()
        membros = []
        if v.get('equipe_id'):
            membros = conn.execute('''SELECT u.id, u.nome, m.papel FROM equipe_membros m
                JOIN usuarios u ON u.id = m.usuario_id WHERE m.equipe_id = ? ORDER BY u.nome''',
                (v['equipe_id'],)).fetchall()
        papel = 'dono' if v['usuario_id'] == uid() else membro(conn, v['equipe_id'], uid())
        return jsonify(vulnerabilidade=v, comentarios=comentarios, historico=historico,
                       membros=membros, papel=papel)


@bp.post('/gestao/vulnerabilidades/<int:vid>/comentarios')
@jwt_required()
def comentar(vid):
    value = texto(dados_json(), 'texto', 2000)
    with conexao() as conn:
        obter_vulnerabilidade(conn, vid, uid(), escrita=True)
        conn.execute('INSERT INTO comentarios (vulnerabilidade_id, usuario_id, texto, criado_em) VALUES (?, ?, ?, ?)',
                     (vid, uid(), value, agora()))
        auditar(conn, vid, uid(), 'Comentário adicionado')
    return jsonify(message='Comentário registrado.'), 201


@bp.put('/gestao/vulnerabilidades/<int:vid>/colaboracao')
@jwt_required()
def colaborar(vid):
    data = dados_json()
    with conexao() as conn:
        v = obter_vulnerabilidade(conn, vid, uid(), escrita=True)
        equipe = v.get('equipe_id')
        if 'equipe_id' in data:
            if v['usuario_id'] != uid():
                raise Forbidden('Somente o dono do achado pode alterar o compartilhamento.')
            equipe = inteiro(data['equipe_id'], 'Equipe') if data['equipe_id'] is not None else None
            if equipe:
                membro(conn, equipe, uid(), escrita=True)
            conn.execute('UPDATE vulnerabilidades SET equipe_id = ?, responsavel_id = NULL WHERE id = ?', (equipe, vid))
            auditar(conn, vid, uid(), 'Compartilhamento atualizado', v.get('equipe_id'), equipe)
        if 'responsavel_id' in data:
            responsavel = inteiro(data['responsavel_id'], 'Responsável') if data['responsavel_id'] is not None else None
            if responsavel is not None:
                if equipe:
                    membro(conn, equipe, responsavel, escrita=True)
                elif responsavel != v['usuario_id']:
                    raise BadRequest('Compartilhe com uma equipe antes de atribuir outro responsável.')
            conn.execute('UPDATE vulnerabilidades SET responsavel_id = ? WHERE id = ?', (responsavel, vid))
            auditar(conn, vid, uid(), 'Responsável atualizado', v.get('responsavel_id'), responsavel)
    return jsonify(message='Colaboração atualizada.')


@bp.route('/equipes', methods=['GET', 'POST'])
@jwt_required()
def equipes():
    with conexao() as conn:
        if request.method == 'GET':
            return jsonify(conn.execute('''SELECT e.*, m.papel FROM equipes e
                JOIN equipe_membros m ON m.equipe_id = e.id WHERE m.usuario_id = ? ORDER BY e.nome''', (uid(),)).fetchall())
        nome = texto(dados_json(), 'nome', 80)
        eid = conn.execute('INSERT INTO equipes (nome, dono_id, criado_em) VALUES (?, ?, ?) RETURNING id',
                           (nome, uid(), agora())).fetchone()['id']
        conn.execute("INSERT INTO equipe_membros VALUES (?, ?, 'gestor')", (eid, uid()))
    return jsonify(id=eid, nome=nome), 201


@bp.route('/equipes/<int:eid>/membros', methods=['GET', 'POST'])
@jwt_required()
def membros(eid):
    with conexao() as conn:
        membro(conn, eid, uid(), gestor=request.method == 'POST')
        if request.method == 'GET':
            return jsonify(conn.execute('''SELECT u.id, u.nome, u.email, m.papel FROM equipe_membros m
                JOIN usuarios u ON u.id = m.usuario_id WHERE m.equipe_id = ? ORDER BY u.nome''', (eid,)).fetchall())
        data = dados_json()
        email = texto(data, 'email', 254).lower()
        papel = data.get('papel', 'analista')
        if papel not in ('leitor', 'analista'):
            raise BadRequest('Use leitor ou analista. O criador permanece gestor.')
        user = conn.execute('SELECT id FROM usuarios WHERE email = ?', (email,)).fetchone()
        if not user:
            raise BadRequest('Esse e-mail precisa ter uma conta cadastrada.')
        if conn.execute('SELECT id FROM equipes WHERE id = ? AND dono_id = ?', (eid, user['id'])).fetchone():
            raise BadRequest('O papel do gestor não pode ser alterado.')
        conn.execute('''INSERT INTO equipe_membros VALUES (?, ?, ?)
            ON CONFLICT(equipe_id, usuario_id) DO UPDATE SET papel = excluded.papel''', (eid, user['id'], papel))
        if papel == 'leitor':
            conn.execute('UPDATE vulnerabilidades SET responsavel_id = NULL WHERE equipe_id = ? AND responsavel_id = ?',
                         (eid, user['id']))
    return jsonify(message='Membro atualizado.'), 201


@bp.delete('/equipes/<int:eid>/membros/<int:user>')
@jwt_required()
def remover_membro(eid, user):
    with conexao() as conn:
        membro(conn, eid, uid(), gestor=True)
        if conn.execute('SELECT id FROM equipes WHERE id = ? AND dono_id = ?', (eid, user)).fetchone():
            raise BadRequest('O gestor não pode ser removido.')
        proprios = conn.execute('SELECT id FROM vulnerabilidades WHERE equipe_id = ? AND usuario_id = ?', (eid, user)).fetchall()
        for v in proprios:
            auditar(conn, v['id'], uid(), 'Compartilhamento encerrado ao remover o dono da equipe', eid, '')
        conn.execute('UPDATE vulnerabilidades SET equipe_id = NULL, responsavel_id = NULL WHERE equipe_id = ? AND usuario_id = ?',
                     (eid, user))
        conn.execute('DELETE FROM equipe_membros WHERE equipe_id = ? AND usuario_id = ?', (eid, user))
        conn.execute('UPDATE vulnerabilidades SET responsavel_id = NULL WHERE equipe_id = ? AND responsavel_id = ?', (eid, user))
    return jsonify(message='Acesso à equipe removido.')


@bp.route('/preferencias/alertas', methods=['GET', 'PUT'])
@jwt_required()
def preferencias():
    with conexao() as conn:
        if request.method == 'PUT':
            days = inteiro(dados_json().get('dias'), 'Antecedência', 0, 90)
            conn.execute('UPDATE usuarios SET alerta_sla_dias = ? WHERE id = ?', (days, uid()))
        row = conn.execute('SELECT alerta_sla_dias AS dias FROM usuarios WHERE id = ?', (uid(),)).fetchone()
        if not row:
            raise NotFound('Usuário não encontrado.')
        return jsonify(row)


def alertas(conn, usuario):
    days = conn.execute('SELECT alerta_sla_dias FROM usuarios WHERE id = ?', (usuario,)).fetchone()
    if not days:
        return []
    rows = conn.execute('''SELECT v.* FROM vulnerabilidades v WHERE v.usuario_id = ? OR EXISTS (
        SELECT 1 FROM equipe_membros m WHERE m.equipe_id = v.equipe_id AND m.usuario_id = ?)''', (usuario, usuario)).fetchall()
    result = []
    for v in rows:
        if v['status'] in FECHADOS:
            continue
        deadline = datetime.strptime(v['data'], '%Y-%m-%d %H:%M:%S') + timedelta(days=v['sla_prazo_dias'] or 90)
        remaining = (deadline - datetime.now()).total_seconds() / 86400
        if remaining > days['alerta_sla_dias']:
            continue
        level = 'Violado' if remaining < 0 else 'Em Risco'
        key = deadline.isoformat() + ':' + level
        read = conn.execute('SELECT 1 FROM alertas_lidos WHERE usuario_id = ? AND vulnerabilidade_id = ? AND chave = ?',
                            (usuario, v['id'], key)).fetchone()
        result.append(dict(id=v['id'], nome=v['nome'], prazo=deadline.isoformat(), nivel=level,
                           chave=key, lido=bool(read), dias_restantes=int(remaining)))
    return sorted(result, key=lambda r: (r['prazo'], r['id']))


@bp.get('/alertas')
@jwt_required()
def listar_alertas():
    with conexao() as conn:
        return jsonify(alertas(conn, uid()))


@bp.post('/alertas/<int:vid>/ler')
@jwt_required()
def ler_alerta(vid):
    with conexao() as conn:
        obter_vulnerabilidade(conn, vid, uid())
        item = next((a for a in alertas(conn, uid()) if a['id'] == vid), None)
        if not item:
            raise NotFound('Alerta não encontrado.')
        conn.execute('''INSERT INTO alertas_lidos VALUES (?, ?, ?, ?)
            ON CONFLICT(usuario_id, vulnerabilidade_id, chave) DO NOTHING''', (uid(), vid, item['chave'], agora()))
    return jsonify(message='Alerta marcado como lido.')
