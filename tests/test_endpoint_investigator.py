"""Testes do Endpoint Investigator.

Executar:  python3 -m unittest discover -s tests -v

Sem dependencias externas: apenas ``unittest`` da biblioteca padrao.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from endpoint_investigator.collectors import DatasetCollector  # noqa: E402
from endpoint_investigator.correlation import ALL_RULES, CorrelationEngine  # noqa: E402
from endpoint_investigator.model import (  # noqa: E402
    Confidence, Evidence, FileRecord, Finding, Severity, SourceRef,
)
from endpoint_investigator.normalize import (  # noqa: E402
    analyze_command, classify_address, enrich_file, parse_log_line, parse_mode,
)
from endpoint_investigator.pipeline import investigate  # noqa: E402
from endpoint_investigator.scoring import compute_confidence  # noqa: E402

DATASETS = RAIZ / "datasets"
DS_NORMAL = DATASETS / "01-normal"
DS_PERM = DATASETS / "02-permissao-ampla"
DS_SERVICO = DATASETS / "03-servico-root"
DS_CORR = DATASETS / "04-correlacao"
DS_AMBIGUO = DATASETS / "05-ambiguo"


def run(dataset: Path):
    return investigate(DatasetCollector(dataset), CorrelationEngine())


def ids(bundle) -> set:
    return {f.rule_id for f in bundle.findings}


# --------------------------------------------------------------------------- #
class TestNormalizacao(unittest.TestCase):
    def test_modo_octal_e_simbolico(self):
        self.assertEqual(parse_mode("0777"), 0o777)
        self.assertEqual(parse_mode("4755"), 0o4755)
        self.assertEqual(parse_mode("rwxr-xr-x"), 0o755)
        self.assertEqual(parse_mode(""), 0)

    def test_flags_de_permissao(self):
        f = enrich_file(FileRecord(path="/x", mode="4757"))
        self.assertTrue(f.setuid)
        self.assertTrue(f.world_writable)
        self.assertFalse(f.setgid)

    def test_link_simbolico_nao_e_gravavel(self):
        """Modo 0777 de um symlink nao e aplicado pelo kernel Linux."""
        f = enrich_file(FileRecord(path="/usr/bin/python3", ftype="link", mode="0777"))
        self.assertFalse(f.world_writable)
        self.assertFalse(f.group_writable)

    def test_decomposicao_de_comando(self):
        _argv, exe, interp, script, _alvos = analyze_command("/bin/bash /opt/b/run.sh")
        self.assertEqual((exe, interp, script), ("/bin/bash", "bash", "/opt/b/run.sh"))

    def test_wrapper_env_e_ignorado(self):
        _argv, _exe, interp, script, _a = analyze_command("/usr/bin/env python3 /opt/a.py")
        self.assertEqual((interp, script), ("python3", "/opt/a.py"))

    def test_url_em_argumento_e_extraida(self):
        _argv, exe, _i, _s, alvos = analyze_command("/usr/bin/curl -fsS https://a.example/x")
        self.assertEqual(exe, "/usr/bin/curl")
        self.assertIn("a.example", alvos)

    def test_classificacao_de_endereco(self):
        # RFC 5737: faixas de documentacao, que o ipaddress do Python marca como
        # privadas. A ferramenta nao pode herdar esse engano.
        self.assertEqual(classify_address("198.51.100.4"), "documentacao")
        self.assertEqual(classify_address("8.8.8.8"), "externo")
        self.assertEqual(classify_address("10.0.0.1"), "privado")
        self.assertEqual(classify_address("127.0.0.1"), "loopback")

    def test_parse_de_log_syslog(self):
        p = parse_log_line("Sep 14 09:00:08 srv sshd[1204]: Accepted publickey for "
                           "aluno from 10.20.30.44 port 51518 ssh2")
        self.assertEqual(p["program"], "sshd")
        self.assertEqual(p["pid"], 1204)
        self.assertIn("Accepted", p["message"])


# --------------------------------------------------------------------------- #
class TestColeta(unittest.TestCase):
    def test_le_as_tres_dimensoes_obrigatorias(self):
        snap = DatasetCollector(DS_CORR).collect()
        self.assertTrue(snap.processes, "processos nao coletados")
        self.assertTrue(snap.files, "permissoes nao coletadas")
        self.assertTrue(snap.services, "servicos nao coletados")

    def test_toda_entidade_tem_proveniencia(self):
        snap = DatasetCollector(DS_CORR).collect()
        for grupo in (snap.processes, snap.files, snap.services, snap.logs):
            for item in grupo:
                self.assertIsNotNone(item.source, f"sem SourceRef: {item}")
                self.assertTrue(item.source.artifact)

    def test_servicos_parseados_corretamente(self):
        snap = DatasetCollector(DS_CORR).collect()
        unidades = {s.unit: s for s in snap.services}
        self.assertIn("backup-agent.service", unidades)
        svc = unidades["backup-agent.service"]
        self.assertEqual(svc.user, "root")
        self.assertEqual(svc.exec_start, "/bin/bash /opt/backup/backup.sh")

    def test_respostas_didaticas_do_gerador_nao_sao_lidas(self):
        """O motor usa so os artefatos observacionais, nunca metadata/README."""
        snap = DatasetCollector(DS_CORR).collect()
        texto = json.dumps([p.cmdline for p in snap.processes]
                           + [f.path for f in snap.files]
                           + [s.unit for s in snap.services]
                           + [l.raw for l in snap.logs])
        self.assertNotIn("scenario", texto)
        self.assertNotIn("Nota didatica", texto)


# --------------------------------------------------------------------------- #
class TestGrafo(unittest.TestCase):
    def setUp(self):
        self.bundle, self.snap, self.graph = run(DS_CORR)

    def test_grafo_liga_as_dimensoes(self):
        rels = {k for k in self.graph.stats() if k.startswith("edge_")}
        self.assertIn("edge_executa-como", rels)
        self.assertIn("edge_pai-de", rels)
        self.assertIn("edge_gerencia", rels)

    def test_servico_casa_com_processo_certo(self):
        procs = self.graph.processes_of_service("backup-agent.service")
        self.assertEqual([p.pid for p in procs], [2417])

    def test_interpretador_nao_captura_shell_alheio(self):
        """'/bin/bash script.sh' nao pode casar com todo /bin/bash do host."""
        pids = {p.pid for p in self.graph.processes_of_service("backup-agent.service")}
        self.assertNotIn(2638, pids, "shell do usuario pareado com o servico")

    def test_caminho_entre_servico_e_arquivo(self):
        caminhos = self.graph.paths_between("service:backup-agent.service",
                                            "file:/opt/backup/backup.sh")
        self.assertTrue(caminhos, "grafo nao liga servico ao recurso executado")


# --------------------------------------------------------------------------- #
class TestCorrelacao(unittest.TestCase):
    def test_as_quatro_correlacoes_do_enunciado_existem(self):
        esperadas = {
            "EI-R01": "servico + permissao + usuario",       # servico + arquivo + usuario
            "EI-R02": "processo + permissao + usuario",      # processo + servico + permissao
            "EI-R07": "processo + PPID + usuario",           # contexto de execucao
            "EI-R14": "log + processo + usuario",            # reconstrucao temporal
        }
        por_id = {r.id: r.correlation for r in ALL_RULES}
        for rid, correlacao in esperadas.items():
            self.assertEqual(por_id.get(rid), correlacao)

    def test_cenario_de_correlacao_gera_achado_alto(self):
        bundle, _, _ = run(DS_CORR)
        self.assertIn("EI-R01", ids(bundle))
        alto = next(f for f in bundle.findings if f.rule_id == "EI-R01")
        self.assertEqual(alto.severity, Severity.HIGH)
        self.assertEqual(alto.confidence, Confidence.HIGH)
        self.assertGreaterEqual(alto.risk_score, 70)

    def test_cenario_normal_nao_gera_achado_alto(self):
        """Uma boa ferramenta nao inventa risco onde nao ha correlacao."""
        bundle, _, _ = run(DS_NORMAL)
        altos = [f for f in bundle.findings if f.severity.rank >= Severity.HIGH.rank]
        self.assertEqual(altos, [], f"falso positivo em cenario normal: {altos}")

    def test_servico_root_sozinho_nao_e_vulnerabilidade(self):
        """O cenario privileged_service tem script 0700: nao deve virar achado alto."""
        bundle, _, _ = run(DS_SERVICO)
        altos = [f for f in bundle.findings if f.severity.rank >= Severity.HIGH.rank]
        self.assertEqual(altos, [], f"servico root tratado como vulneravel: {altos}")

    def test_permissao_ampla_sem_execucao_nao_vira_achado_grave(self):
        """Configuracao inadequada != relacao de privilegio demonstrada."""
        bundle, _, _ = run(DS_PERM)
        self.assertIn("EI-R04", ids(bundle))
        f = next(x for x in bundle.findings if x.rule_id == "EI-R04")
        self.assertEqual(f.severity, Severity.LOW)
        self.assertNotIn("EI-R01", ids(bundle))

    def test_url_em_contexto_root_nao_vira_malware(self):
        """Cenario ambiguo: saida de rede de agente root nao e rotulada como C2."""
        bundle, _, _ = run(DS_AMBIGUO)
        f = next((x for x in bundle.findings if x.rule_id == "EI-R13"), None)
        self.assertIsNotNone(f)
        self.assertLess(f.severity.rank, Severity.HIGH.rank)
        self.assertIn("NAO classifica", f.hypothesis)

    def test_todo_achado_tem_os_quatro_elementos(self):
        for ds in (DS_NORMAL, DS_PERM, DS_SERVICO, DS_CORR, DS_AMBIGUO):
            bundle, _, _ = run(ds)
            for f in bundle.findings:
                self.assertTrue(f.evidence, f"{f.rule_id} sem evidencia")
                self.assertTrue(f.interpretation.strip(), f"{f.rule_id} sem interpretacao")
                self.assertTrue(f.hypothesis.strip(), f"{f.rule_id} sem hipotese")
                self.assertTrue(f.missing_evidence, f"{f.rule_id} sem evidencia ausente")
                self.assertTrue(f.correlation.strip(), f"{f.rule_id} sem correlacao")

    def test_toda_evidencia_e_rastreavel(self):
        bundle, _, _ = run(DS_CORR)
        for f in bundle.findings:
            for e in f.evidence:
                self.assertTrue(e.source.collector)
                self.assertTrue(e.source.artifact)

    def test_regras_declaram_pelo_menos_duas_dimensoes(self):
        for r in ALL_RULES:
            self.assertGreaterEqual(
                len(r.correlation.split("+")), 2,
                f"{r.id} nao declara correlacao entre dimensoes")

    def test_regras_sem_dimensao_sao_puladas_com_motivo(self):
        """Degradacao controlada quando falta uma fonte de dados."""
        bundle, _, _ = run(DS_NORMAL)
        for pulada in bundle.coverage["rules_skipped"]:
            self.assertTrue(pulada["reason"])
        self.assertFalse(bundle.coverage["engine_errors"])

    def test_nenhum_achado_afirma_exploracao(self):
        for ds in (DS_NORMAL, DS_PERM, DS_CORR, DS_AMBIGUO):
            bundle, _, _ = run(ds)
            for f in bundle.findings:
                self.assertFalse(f.exploracao_comprovada,
                                 f"{f.rule_id} afirma exploracao comprovada")


# --------------------------------------------------------------------------- #
class TestScoring(unittest.TestCase):
    @staticmethod
    def _finding(kinds):
        ev = [Evidence(kind=k, observed="x", source=SourceRef("c", f"art-{k}"))
              for k in kinds]
        return Finding(rule_id="T", title="t", severity=Severity.HIGH,
                       category="c", correlation="a + b", evidence=ev)

    def test_confianca_cresce_com_as_dimensoes(self):
        self.assertEqual(compute_confidence(self._finding(["file"]))[0], Confidence.LOW)
        self.assertEqual(compute_confidence(self._finding(["file", "service"]))[0],
                         Confidence.MEDIUM)
        self.assertEqual(compute_confidence(self._finding(["file", "service", "log"]))[0],
                         Confidence.HIGH)

    def test_fonte_unica_limita_a_confianca(self):
        ev = [Evidence(kind=k, observed="x", source=SourceRef("c", "mesma-fonte"))
              for k in ("file", "service", "log")]
        f = Finding(rule_id="T", title="t", severity=Severity.HIGH, category="c",
                    correlation="a + b", evidence=ev)
        self.assertEqual(compute_confidence(f)[0], Confidence.MEDIUM)


# --------------------------------------------------------------------------- #
class TestGeradorCorrigido(unittest.TestCase):
    """Correcoes na copia do gerador (docs/correcoes-no-gerador.md)."""

    @staticmethod
    def _gerador():
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "gerador", RAIZ / "tools" / "generate_dataset.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_cenario_aleatorio_nao_quebra(self):
        """A versao recebida levantava ValueError ao reaproveitar a saida de build()."""
        from datetime import datetime
        dados = self._gerador().random_noise(datetime(2026, 9, 14, 9, 0), 42)
        self.assertEqual(dados["kind"], "random")
        self.assertTrue(dados["processes"])

    def test_todos_os_cenarios_sao_alcancaveis_por_nome(self):
        from datetime import datetime
        g = self._gerador()
        for nome in ("normal", "permission", "privileged_service", "correlation",
                     "ambiguous", "random"):
            self.assertTrue(g.CENARIOS[nome](datetime(2026, 9, 14, 9, 0))["processes"],
                            f"cenario {nome} sem processos")

    def test_cenario_permission_tem_rotulo_proprio(self):
        from datetime import datetime
        self.assertEqual(
            self._gerador().scenario_permission(datetime(2026, 9, 14, 9, 0))["kind"],
            "permission")

    def test_csv_e_journal_usam_o_mesmo_instante(self):
        """iso() rotulava -03:00 sobre um horario UTC, adiantando os CSV em 3h."""
        from datetime import datetime
        base = datetime(2026, 9, 14, 9, 0)
        self.assertTrue(self._gerador().iso(base).startswith("2026-09-14T09:00:00"))
        self.assertEqual(base.strftime("%H:%M:%S"), "09:00:00")


# --------------------------------------------------------------------------- #
class TestRelatorios(unittest.TestCase):
    def setUp(self):
        self.bundle, _, _ = run(DS_CORR)

    def test_json_e_serializavel_e_versionado(self):
        from endpoint_investigator.reporting import render_json
        data = json.loads(render_json(self.bundle))
        self.assertEqual(data["schema_version"], "ei-evidence-bundle/1.0")
        self.assertIn("findings", data)
        self.assertIn("limitations", data)

    def test_html_mostra_os_quatro_elementos(self):
        from endpoint_investigator.reporting import render_html
        html = render_html(self.bundle)
        for bloco in ("Evidencia", "Interpretacao", "Hipotese", "Evidencia ausente"):
            self.assertIn(bloco, html)

    def test_limitacoes_sao_declaradas(self):
        self.assertGreaterEqual(len(self.bundle.limitations), 5)
        texto = " ".join(self.bundle.limitations)
        self.assertIn("Escopo adotado", texto)
        self.assertIn("falso", texto.lower() + " falso")   # falsos positivos no README


if __name__ == "__main__":
    unittest.main(verbosity=2)
