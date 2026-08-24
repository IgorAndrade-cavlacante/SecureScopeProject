import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


TESTS_DIR = Path(__file__).resolve().parent
APP_DIR = TESTS_DIR.parent / "securescope"
sys.path.insert(0, str(APP_DIR))

import ia  # noqa: E402
import scanner  # noqa: E402


class PriorityRegressionTest(unittest.TestCase):
    def test_cvss_eight_is_not_reduced_to_two_point_four(self):
        prioridade, nivel, prazo, explicacao = ia.calcular_prioridade_v2(
            8.0,
            0.0,
            False,
            {},
            risk_index_base=78.0,
            epss_disponivel=False,
        )

        self.assertEqual(prioridade, 78.8)
        self.assertEqual((nivel, prazo), ("P2", 30))
        self.assertGreaterEqual(prioridade, 78.0)
        self.assertTrue(any("normalizado: 80/100" in item for item in explicacao))

    def test_priority_never_falls_below_observed_risk(self):
        prioridade, _, _, _ = ia.calcular_prioridade_v2(
            2.0,
            0.0,
            False,
            {},
            risk_index_base=65.0,
            epss_disponivel=False,
        )
        self.assertEqual(prioridade, 65.0)


class SCARegressionTest(unittest.TestCase):
    def test_cvss_vector_is_converted_to_numeric_base_score(self):
        vuln = {
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }]
        }
        self.assertEqual(scanner._extrair_cvss(vuln), 9.8)

    def test_full_osv_records_are_deduplicated_and_keep_details(self):
        registro = {
            "id": "GHSA-aaaa-bbbb-cccc",
            "aliases": ["CVE-2026-1234", "PYSEC-2026-12"],
            "summary": "Falha crítica na dependência",
            "details": "Descrição técnica completa.",
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }],
            "references": [{"type": "ADVISORY", "url": "https://example.test/advisory"}],
            "affected": [{
                "package": {"name": "demo", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }],
        }
        alias = dict(registro, id="PYSEC-2026-12", aliases=["CVE-2026-1234"])
        resposta = {"results": [{"vulns": [registro, alias]}]}

        achados = scanner.processar_achados_osv(
            resposta,
            [{"pacote": "demo", "versao": "1.0.0", "operador": "=="}],
        )

        self.assertEqual(len(achados), 1)
        self.assertEqual(achados[0]["cvss_score"], 9.8)
        self.assertEqual(achados[0]["_versao_corrigida"], "2.0.0")
        self.assertEqual(achados[0]["_descricao"], "Descrição técnica completa.")
        self.assertEqual(achados[0]["_referencias"], ["https://example.test/advisory"])

    @patch("scanner.requests.post")
    def test_package_query_uses_endpoint_that_returns_full_records(self, post):
        response = Mock()
        response.status_code = 200
        response.json.return_value = {"vulns": [{"id": "GHSA-test", "summary": "Detalhe"}]}
        response.raise_for_status.return_value = None
        post.return_value = response

        resultado = scanner.consultar_osv_em_lote([
            {"pacote": "demo", "versao": "1.0.0", "operador": "=="}
        ])

        self.assertEqual(resultado["results"][0]["vulns"][0]["summary"], "Detalhe")
        self.assertEqual(post.call_args.args[0], scanner.OSV_QUERY_URL)


class SASTDetailsRegressionTest(unittest.TestCase):
    def test_bandit_result_keeps_code_and_specific_remediation(self):
        saida = {
            "results": [{
                "filename": "codigo.py",
                "line_number": 13,
                "test_id": "B324",
                "test_name": "hashlib",
                "issue_text": "Use of weak MD5 hash for security.",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 327, "link": "https://cwe.mitre.org/data/definitions/327.html"},
                "code": "13 return hashlib.md5(valor.encode()).hexdigest()",
            }]
        }

        achado = scanner.processar_achados_bandit(saida)[0]

        self.assertEqual(achado["_linha"], 13)
        self.assertIn("hashlib.md5", achado["_codigo_trecho"])
        self.assertEqual(achado["_titulo"], "Hash criptográfico fraco (MD5)")
        self.assertGreaterEqual(len(achado["_remediacao"]), 3)


if __name__ == "__main__":
    unittest.main()
