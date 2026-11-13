"""Monitoring stack as tests (R-10). Static: Prometheus, Alertmanager and Grafana do not run here.

promtool was not available when this was written, so rule syntax is checked by structure only.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MON = ROOT / "monitoring"
SERVICES = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]
PROM = yaml.safe_load((MON / "prometheus.yml").read_text())
RULES = yaml.safe_load((MON / "rules" / "lab.yml").read_text())
NAMES = ("prometheus", "alertmanager", "blackbox", "grafana")


def test_monitoring_services_exist_and_use_the_profile() -> None:
    for name in NAMES:
        assert SERVICES[name]["profiles"] == ["monitoring"], name


def test_monitoring_images_use_digest_form_and_a_tag_comment() -> None:
    text = (ROOT / "compose.yaml").read_text()
    for name in NAMES:
        repo = SERVICES[name]["image"].split("@")[0]
        assert re.search(rf"image: {re.escape(repo)}@sha256:[0-9a-f]{{64}}  # \S+", text), name


def test_host_ports_come_from_env_and_bind_loopback() -> None:
    env = (ROOT / ".env.example").read_text()
    for name, var in (("prometheus", "PROMETHEUS_PORT"), ("alertmanager", "ALERTMANAGER_PORT"), ("grafana", "GRAFANA_PORT")):
        (port,) = SERVICES[name]["ports"]
        assert port.startswith("127.0.0.1:${" + var + "}:"), port
        assert re.search(rf"^{var}=\d+$", env, re.M)
    assert "ports" not in SERVICES["blackbox"]


def test_grafana_password_is_a_variable_not_a_literal() -> None:
    env = SERVICES["grafana"]["environment"]
    assert "GF_SECURITY_ADMIN_PASSWORD=${GF_SECURITY_ADMIN_PASSWORD}" in env
    assert "GF_AUTH_ANONYMOUS_ENABLED=false" in env
    assert "GF_SECURITY_ADMIN_PASSWORD" not in (ROOT / ".env.example").read_text()


def test_monitoring_containers_drop_capabilities() -> None:
    for name in NAMES:
        assert SERVICES[name]["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in SERVICES[name]["security_opt"], name


def test_prometheus_sends_alerts_and_loads_rules() -> None:
    assert "/etc/prometheus/rules/*.yml" in PROM["rule_files"]
    assert PROM["alerting"]["alertmanagers"][0]["static_configs"][0]["targets"] == ["alertmanager:9093"]
    mounts = SERVICES["prometheus"]["volumes"]
    assert "./monitoring/rules:/etc/prometheus/rules:ro" in mounts


def test_lab_services_are_probed_through_blackbox() -> None:
    job = next(j for j in PROM["scrape_configs"] if j["job_name"] == "lab-services")
    assert job["metrics_path"] == "/probe" and job["params"]["module"] == ["tcp_connect"]
    assert {"opensearch:9200", "opensearch-dashboards:5601"} <= set(job["static_configs"][0]["targets"])
    assert any(r.get("replacement") == "blackbox:9115" for r in job["relabel_configs"])
    modules = yaml.safe_load((MON / "blackbox.yml").read_text())["modules"]
    assert modules["tcp_connect"]["prober"] == "tcp"


def test_stopping_a_container_alert_exists() -> None:
    rules = {r["alert"]: r for g in RULES["groups"] for r in g["rules"]}
    down = rules["LabServiceDown"]
    assert down["expr"] == 'probe_success{job="lab-services"} == 0'
    assert down["for"] == "30s"
    assert down["labels"]["severity"] == "critical"
    assert "MonitoringComponentDown" in rules


def test_alertmanager_has_a_route_to_a_defined_receiver() -> None:
    conf = yaml.safe_load((MON / "alertmanager.yml").read_text())
    assert conf["route"]["receiver"] in {r["name"] for r in conf["receivers"]}


def test_grafana_datasources_point_at_the_stack() -> None:
    sources = yaml.safe_load((MON / "grafana/provisioning/datasources/datasources.yml").read_text())["datasources"]
    kinds = {s["type"]: s["url"] for s in sources}
    assert kinds == {"prometheus": "http://prometheus:9090", "alertmanager": "http://alertmanager:9093"}
    assert next(s for s in sources if s["type"] == "alertmanager")["jsonData"]["implementation"] == "prometheus"


def test_makefile_enables_the_profile_only_with_the_secret_and_cleans_up() -> None:
    make = (ROOT / "Makefile").read_text()
    assert "secrets/grafana.enc.yaml" in make and "--profile monitoring" in make
    assert "rm -f .env.secrets" in make
