# Monitoring runbook (Session 7)

Risk: R-10 (exposure and availability of the lab go unwatched). The row stays `Open` until the three evidence files at the end exist.

## What is here

| Path | Purpose |
|---|---|
| `compose.yaml` | Four services under the profile `monitoring`: `prometheus`, `alertmanager`, `blackbox`, `grafana`. Host ports come from `.env` and bind to loopback. |
| `monitoring/prometheus.yml` | Scrapes itself, Alertmanager and Grafana, and TCP-probes `opensearch:9200` and `opensearch-dashboards:5601` through the blackbox exporter. |
| `monitoring/rules/lab.yml` | `LabServiceDown` (probe fails for 30 s, critical) and `MonitoringComponentDown`. |
| `monitoring/alertmanager.yml` | One receiver with no integration. The alert shows in the Alertmanager UI and in Grafana. |
| `monitoring/grafana/provisioning/` | Prometheus and Alertmanager data sources. |
| `tests/test_monitoring.py` | Static checks on all of the above. |

Container-internal addresses in `monitoring/` (for example `opensearch:9200`) are the fixed ports of the images, the same as in `nginx/`. Only host-facing ports come from `.env`.

## Why a TCP probe and not cAdvisor

cAdvisor needs the Docker socket, `/sys` and `/var/lib/docker` mounted into a container. That widens the attack surface of a stack whose point is to reduce it. A TCP probe from inside the Compose network needs no mounts and still turns a stopped container into an alert. The cost: it sees a closed port, not the container state, so a hung process with an open port is not caught.

## What is not verified

- Nothing here was run. The sandbox has no Docker, no registry access and no `promtool`.
- The four image digests in `compose.yaml` are zero placeholders. `STRICT_DIGESTS=1` tests fail until `make pin-digests` replaces them. The tags (`v3.16.0`, `v0.35.0`, `v0.29.1`, `13.3.1`) come from the upstream git tags; whether the matching image tags exist on Docker Hub is checked by `make pin-digests`, which stops if one is missing.
- The Alertmanager data source (`implementation: prometheus`) and the Grafana alert view are written from the Grafana documentation as I remember it and are unchecked.
- R-10 also asked for an alert on a new port or banner. That is not built. `exposure_check.py` exits 1 on a finding, but nothing feeds that into Prometheus yet.

## Run it

```bash
make pin-digests                                   # once; commit compose.yaml
bash scripts/add-secret.sh grafana GF_SECURITY_ADMIN_PASSWORD
git add secrets/grafana.enc.yaml
make up                                            # enables the monitoring profile
```

Open Grafana at `http://localhost:<GRAFANA_PORT>`, user `admin`. Prometheus Targets at `http://localhost:<PROMETHEUS_PORT>/targets` must show `lab-services` up.

## Trigger the alert

```bash
docker compose --env-file .env --env-file .env.secrets stop opensearch-dashboards
# wait about 60 s: 15 s scrape, 30 s `for`, then Alertmanager grouping
```

Look for `LabServiceDown` in Prometheus Alerts (state `Firing`), the Alertmanager UI, and Grafana under Alerting, Alert rules. Then `docker compose ... start opensearch-dashboards` and watch it resolve.

## Evidence

| File | How to produce it | Risk |
|---|---|---|
| `s6-shodan-exposure.txt` | `make exposure-check` | R-10 |
| `s7-alert-firing.png` | Prometheus Alerts page or Alertmanager UI with `LabServiceDown` firing for `opensearch-dashboards:5601` | R-10 |
| `s7-grafana-alert.png` | The same alert visible in Grafana, Alerting, Alert rules | R-10 |
