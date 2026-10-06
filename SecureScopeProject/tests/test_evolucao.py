"""Contratos de acesso, transações, fila e fluxos das funcionalidades novas.

Reutiliza o ambiente SQLite temporário da suíte de segurança (sem serviços
externos e sem executar o worker automático).
"""
import csv
import io
import json
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import test_security
import scan_jobs
import gestao

app_module = test_security.securescope_app


def achado(nome='Hash inseguro', linha=4):
    return dict(nome=nome, impacto=80, frequencia=50, gravidade=80, cvss_score=8,
                ativo='codigo.py', origem='Scanner Automatizado', _test_id='B324',
                _linha=linha, _titulo=nome, _descricao='Weak MD5 hash', _codigo_trecho='hashlib.md5(valor)',
                _gravidade_texto='Alta', cve_id='', epss_score=0, no_kev=False)


def resultado(*achados):
    return dict(erro=None, achados=list(achados), total_arquivos=1, triagem_aplicada=False)


class EvolucaoTest(unittest.TestCase):
    def setUp(self):
        test_security.SecurityControlsTest.setUp(self)
        self.a, self.aid = self.conta('alice')
        self.b, self.bid = self.conta('bruno')
        self.c, self.cid = self.conta('carla')

    def conta(self, name):
        client = app_module.app.test_client()
        response = client.post('/auth/register', json=dict(nome=name, email=f'{name}@example.test', senha='SenhaTeste12345'))
        self.assertEqual(response.status_code, 201, response.json)
        self.assertEqual(client.post('/auth/login', json=dict(email=f'{name}@example.test', senha='SenhaTeste12345')).status_code, 200)
        return client, client.get('/auth/me').json['id']

    def request(self, client, method, path, **kwargs):
        return getattr(client, method)(path, headers={'X-CSRF-TOKEN': client.get_cookie('csrf_access_token').value}, **kwargs)

    def manual(self, client=None, name='SQL Injection', ativo='API principal'):
        response = self.request(client or self.a, 'post', '/vulnerabilidades', json=dict(
            nome=name, impacto=90, frequencia=80, gravidade=90, ativo=ativo))
        self.assertEqual(response.status_code, 201, response.json)
        return response.json['id']

    def equipe(self, papel='analista'):
        team = self.request(self.a, 'post', '/equipes', json={'nome': 'Segurança'}).json['id']
        response = self.request(self.a, 'post', f'/equipes/{team}/membros', json={'email': 'bruno@example.test', 'papel': papel})
        self.assertEqual(response.status_code, 201)
        return team

    def share(self, vid, team):
        response = self.request(self.a, 'put', f'/gestao/vulnerabilidades/{vid}/colaboracao', json={'equipe_id': team})
        self.assertEqual(response.status_code, 200, response.json)

    def scan(self, result, client=None, background=False, target='API A'):
        with patch('scanner.executar_sast', return_value=result):
            response = self.request(client or self.a, 'post', '/scanner/analisar-codigo', data={
                'arquivo': (io.BytesIO(b'import hashlib'), 'codigo.py'), 'alvo': target,
                'segundo_plano': '1' if background else '0'}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 202 if background else 201, response.json)
        return response.json

    def test_filter_combinations_are_literal_and_tenant_scoped(self):
        vid = self.manual(name='Falha 100%_literal', ativo='Produção')
        self.manual(self.b, name='Falha 100%_literal', ativo='Produção')
        self.manual(name='Outra falha', ativo='Homologação')
        rows = self.a.get('/gestao/vulnerabilidades', query_string={'nome': '%_literal', 'ativo': 'Produ', 'status': 'Aberta'}).json
        self.assertEqual([r['id'] for r in rows], [vid])
        self.assertEqual(self.a.get('/gestao/vulnerabilidades?nome=%27%20OR%201%3D1').json, [])
        self.assertEqual(self.a.get('/gestao/vulnerabilidades?prioridade=desconhecida').status_code, 400)
        self.assertEqual(self.c.get(f'/gestao/vulnerabilidades/{vid}').status_code, 404)

    def test_export_matches_filters_unicode_and_protects_formulas(self):
        self.manual(name='  =HYPERLINK("malicioso")', ativo='Produção')
        self.manual(name='Outro', ativo='Teste')
        response = self.a.get('/gestao/exportar/csv?ativo=Produ')
        rows = list(csv.DictReader(io.StringIO(response.data.decode('utf-8-sig')), delimiter=';'))
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]['nome'].startswith("'"))
        self.assertEqual(rows[0]['ativo'], 'Produção')
        exported = self.a.get('/gestao/exportar/json?ativo=Produ').json
        self.assertEqual(len(exported), 1)
        self.assertEqual(self.c.get('/gestao/exportar/json').json, [])
        self.assertEqual(self.a.get('/gestao/exportar/xml').status_code, 400)

    def test_status_audit_resolution_kpis_reopen_and_required_reason(self):
        vid = self.manual()
        original = self.a.get(f'/gestao/vulnerabilidades/{vid}').json['vulnerabilidade']
        path = f'/gestao/vulnerabilidades/{vid}/status'
        self.assertEqual(self.request(self.a, 'put', path, json={'status': 'Corrigida', 'justificativa': ''}).status_code, 400)
        self.assertEqual(self.request(self.b, 'put', path, json={'status': 'Corrigida', 'justificativa': 'Não autorizado'}).status_code, 404)
        self.assertEqual(self.request(self.a, 'put', path, json={'status': 'Corrigida', 'justificativa': 'Patch aplicado e revisado'}).status_code, 200)
        detail = self.a.get(f'/gestao/vulnerabilidades/{vid}').json
        self.assertIsNotNone(detail['vulnerabilidade']['corrigida_em'])
        self.assertEqual(detail['historico'][-1]['responsavel'], str(self.aid))
        self.assertEqual(self.a.get('/sla/status').json, [])
        self.assertEqual(self.a.get('/governance/kpis').json['vulnerabilidades_em_aberto'], 0)
        self.assertEqual(self.request(self.a, 'put', f'/vulnerabilidades/{vid}/validar', json={}).status_code, 409)
        self.assertEqual(self.request(self.a, 'put', path, json={'status': 'Aberta', 'justificativa': 'Recorrência confirmada'}).status_code, 200)
        detail = self.a.get(f'/gestao/vulnerabilidades/{vid}').json['vulnerabilidade']
        self.assertIsNone(detail['corrigida_em'])
        self.assertEqual(detail['data'], original['data'])
        self.assertEqual(self.a.get('/governance/kpis').json['vulnerabilidades_em_aberto'], 1)

    def test_team_permissions_assignment_comments_and_revocation(self):
        vid = self.manual(); team = self.equipe('leitor'); self.share(vid, team)
        rows = self.b.get(f'/gestao/vulnerabilidades?equipe_id={team}').json
        self.assertEqual([r['id'] for r in rows], [vid])
        self.assertEqual(self.b.get('/gestao/vulnerabilidades').json, [])
        self.assertEqual(self.b.get(f'/vulnerabilidades/{vid}/analise').status_code, 200)
        self.assertEqual(self.c.get(f'/gestao/vulnerabilidades?equipe_id={team}').status_code, 404)
        self.assertEqual(self.request(self.b, 'post', f'/gestao/vulnerabilidades/{vid}/comentarios', json={'texto': 'Teste'}).status_code, 403)
        self.assertEqual(self.request(self.b, 'post', f'/equipes/{team}/membros', json={'email': 'carla@example.test'}).status_code, 403)
        self.request(self.a, 'post', f'/equipes/{team}/membros', json={'email': 'bruno@example.test', 'papel': 'analista'})
        self.assertEqual(self.request(self.b, 'post', f'/gestao/vulnerabilidades/{vid}/comentarios', json={'texto': '<script>texto não executável</script>'}).status_code, 201)
        path = f'/gestao/vulnerabilidades/{vid}/colaboracao'
        self.assertEqual(self.request(self.b, 'put', path, json={'responsavel_id': self.cid}).status_code, 404)
        self.assertEqual(self.request(self.b, 'put', path, json={'responsavel_id': self.bid}).status_code, 200)
        self.assertEqual(self.request(self.b, 'put', path, json={'equipe_id': None}).status_code, 403)
        self.assertEqual(self.request(self.a, 'delete', f'/equipes/{team}/membros/{self.aid}').status_code, 400)
        self.assertEqual(self.request(self.a, 'delete', f'/equipes/{team}/membros/{self.bid}').status_code, 200)
        self.assertEqual(self.b.get(f'/gestao/vulnerabilidades/{vid}').status_code, 404)
        self.assertIsNone(self.a.get(f'/gestao/vulnerabilidades/{vid}').json['vulnerabilidade']['responsavel_id'])

    def test_sla_alert_dedup_ack_and_new_breach_phase(self):
        vid = self.manual()
        with gestao.conexao() as conn:
            conn.execute("UPDATE vulnerabilidades SET data = datetime('now', '-14 days'), sla_prazo_dias = 15 WHERE id = ?", (vid,))
        first = self.a.get('/alertas').json
        self.assertEqual(len(first), 1); self.assertFalse(first[0]['lido'])
        for _ in range(2):
            self.assertEqual(self.request(self.a, 'post', f'/alertas/{vid}/ler', json={}).status_code, 200)
        self.assertTrue(self.a.get('/alertas').json[0]['lido'])
        self.assertEqual(self.c.get('/alertas').json, [])
        with gestao.conexao() as conn:
            conn.execute("UPDATE vulnerabilidades SET data = datetime('now', '-16 days') WHERE id = ?", (vid,))
        breached = self.a.get('/alertas').json[0]
        self.assertEqual(breached['nivel'], 'Violado'); self.assertFalse(breached['lido'])
        self.assertEqual(self.request(self.a, 'put', '/preferencias/alertas', json={'dias': 91}).status_code, 400)
        self.assertEqual(self.request(self.a, 'put', '/preferencias/alertas', json={'dias': 0}).status_code, 200)
        self.request(self.a, 'put', f'/gestao/vulnerabilidades/{vid}/status', json={'status': 'Corrigida', 'justificativa': 'Resolvida'})
        self.assertEqual(self.a.get('/alertas').json, [])

    def test_duplicate_scans_keep_snapshots_status_and_account_isolation(self):
        first = self.scan(resultado(achado()))
        vid = first['vulnerabilidades'][0]['vuln_id']
        self.request(self.a, 'put', f'/gestao/vulnerabilidades/{vid}/status', json={'status': 'Corrigida', 'justificativa': 'Corrigida'})
        second = self.scan(resultado(achado('Título revisado'), achado('Outro achado', linha=20)))
        self.assertEqual(second['achados_repetidos'], 1)
        self.assertEqual(second['novos_achados'], 1)
        self.assertEqual(second['vulnerabilidades'][0]['vuln_id'], vid)
        self.assertEqual(self.a.get(f'/vulnerabilidades/{vid}').json['status'], 'Corrigida')
        snapshot = self.a.get(f'/scans/{first["scan_id"]}').json['resultado']['vulnerabilidades'][0]
        self.assertEqual(snapshot['nome'], 'Hash inseguro')
        compare = self.a.get(f'/scans/comparar?antes={first["scan_id"]}&depois={second["scan_id"]}').json
        self.assertEqual(len(compare['novos']), 1); self.assertEqual(len(compare['persistentes']), 1)
        self.assertEqual(compare['nao_detectados'], [])
        another = self.scan(resultado(achado()), client=self.b)
        self.assertNotEqual(another['vulnerabilidades'][0]['vuln_id'], vid)
        self.assertEqual(self.b.get(f'/scans/{first["scan_id"]}').status_code, 404)
        self.assertEqual(self.b.get(f'/scans/comparar?antes={first["scan_id"]}&depois={second["scan_id"]}').status_code, 404)

    def test_compare_disappearance_not_correction_and_incompatible_targets(self):
        first = self.scan(resultado(achado()))
        second = self.scan(resultado())
        third = self.scan(resultado(), target='API B')
        compare = self.a.get(f'/scans/comparar?antes={first["scan_id"]}&depois={second["scan_id"]}').json
        self.assertEqual(len(compare['nao_detectados']), 1)
        vid = first['vulnerabilidades'][0]['vuln_id']
        self.assertEqual(self.a.get(f'/vulnerabilidades/{vid}').json['status'], 'Aberta')
        self.assertEqual(self.a.get(f'/scans/comparar?antes={first["scan_id"]}&depois={third["scan_id"]}').status_code, 400)

    def test_persistent_queue_claim_once_and_payload_cleanup(self):
        job = self.scan(resultado(), background=True)
        sid = job['scan_id']
        detail = self.a.get(f'/scans/{sid}').json
        self.assertEqual(detail['status'], 'na_fila'); self.assertNotIn('payload', detail)
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(lambda _: scan_jobs.reservar(sid), range(2)))
        self.assertEqual(sum(c is not None for c in claims), 1)
        with patch('scanner.executar_sast', return_value=resultado(achado())):
            scan_jobs.executar(next(c for c in claims if c))
        self.assertEqual(self.a.get(f'/scans/{sid}').json['status'], 'concluido')
        with gestao.conexao() as conn:
            self.assertIsNone(conn.execute('SELECT payload FROM scans WHERE id = ?', (sid,)).fetchone()['payload'])

    def test_failure_rolls_back_all_findings_and_releases_payload(self):
        with patch('scanner.executar_sast', return_value=resultado(achado(), {'nome': 'inválido'})):
            response = self.request(self.a, 'post', '/scanner/analisar-codigo', data={
                'arquivo': (io.BytesIO(b'x=1'), 'a.py')}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 500)
        self.assertEqual(self.a.get('/gestao/vulnerabilidades').json, [])
        with gestao.conexao() as conn:
            row = conn.execute('SELECT status, payload FROM scans WHERE id = ?', (response.json['scan_id'],)).fetchone()
            self.assertEqual(row['status'], 'erro'); self.assertIsNone(row['payload'])
            self.assertEqual(conn.execute('SELECT COUNT(*) AS n FROM scan_achados').fetchone()['n'], 0)

    def test_pending_limit_stale_job_recovery_and_no_late_commit(self):
        jobs = [self.scan(resultado(), background=True)['scan_id'] for _ in range(3)]
        response = self.request(self.a, 'post', '/scanner/analisar-codigo', data={
            'arquivo': (io.BytesIO(b'x=1'), 'a.py'), 'segundo_plano': '1'}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 429)
        claim = scan_jobs.reservar(jobs[0])
        with gestao.conexao() as conn:
            conn.execute("UPDATE scans SET iniciado_worker_em = '2000-01-01 00:00:00' WHERE id = ?", (jobs[0],))
        scan_jobs.reservar(jobs[1])
        self.assertEqual(self.a.get(f'/scans/{jobs[0]}').json['status'], 'erro')
        with patch('scanner.executar_sast', return_value=resultado(achado())):
            scan_jobs.executar(claim)
        self.assertEqual(self.a.get('/gestao/vulnerabilidades').json, [])

    def test_new_routes_require_auth_and_csrf(self):
        anonymous = app_module.app.test_client()
        for path in ('/scans', '/gestao/vulnerabilidades', '/equipes', '/alertas', '/preferencias/alertas', '/gestao/exportar/csv'):
            self.assertEqual(anonymous.get(path).status_code, 401, path)
        self.assertEqual(self.a.post('/equipes', json={'nome': 'Sem CSRF'}).status_code, 401)

    def test_dast_rules_with_same_cwe_are_not_merged(self):
        findings = app_module.scanner.processar_achados_zap([
            {'alert': 'CSP ausente', 'cweid': '693', 'url': 'https://example.test/'},
            {'alert': 'Clickjacking', 'cweid': '693', 'url': 'https://example.test/'},
        ], 'https://example.test/', 'passivo_http')
        self.assertNotEqual(scan_jobs.identidade_achado('dast', 'site', findings[0]),
                            scan_jobs.identidade_achado('dast', 'site', findings[1]))

    def test_zip_preserves_same_filename_in_different_directories(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as z:
            for name in ('api/main.py', 'worker/main.py'):
                z.writestr(name, 'import hashlib\nhashlib.md5(b"example").hexdigest()\n')
        result = app_module.scanner.executar_sast_zip(archive.getvalue())
        self.assertIsNone(result['erro'])
        paths = {a['ativo'].replace('\\', '/') for a in result['achados']}
        self.assertEqual(paths, {'api/main.py', 'worker/main.py'})

    def test_worker_timeout_marks_error_without_leaking_input(self):
        import subprocess
        job = self.scan(resultado(), background=True)
        with patch('scan_jobs.subprocess.run', side_effect=subprocess.TimeoutExpired('worker', 1800)):
            self.assertTrue(scan_jobs.processar_um(isolar=True))
        row = self.a.get(f'/scans/{job["scan_id"]}').json
        self.assertEqual(row['status'], 'erro')
        self.assertIn('Tempo limite', row['erro'])
        with gestao.conexao() as conn:
            self.assertIsNone(conn.execute('SELECT payload FROM scans WHERE id = ?', (job['scan_id'],)).fetchone()['payload'])

    def test_two_concurrent_scans_consolidate_one_vulnerability(self):
        ids = [self.scan(resultado(), background=True)['scan_id'] for _ in range(2)]
        jobs = [scan_jobs.reservar(sid) for sid in ids]
        with patch('scanner.executar_sast', return_value=resultado(achado())):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(scan_jobs.executar, jobs))
        self.assertTrue(all(code == 201 for _, code in results))
        self.assertEqual(len(self.a.get('/gestao/vulnerabilidades').json), 1)
        self.assertEqual(sum(r['novos_achados'] for r, _ in results), 1)


if __name__ == '__main__':
    unittest.main()
