# Threat intelligence runbook (Session 6)

Risks: R-09 (known-malicious sources go unflagged), R-10 (unwatched exposure on the lab's public IP). Both stay `Open` until the screenshots in the last section exist.

## What is here

| Path | Purpose |
|---|---|
| `threatintel/misp_lookup.py` | Pulls `ip-src` and `ip-dst` attributes from MISP with PyMISP (`to_ids`, published, warninglist enforced, last 30 days) and writes the Logstash dictionary. Private ranges and invalid values are dropped. |
| `pipelines/eve/30-enrich.conf` | `translate` filter on `source.ip`. On a hit it adds `threat.indicator.provider` and `threat.indicator.matched`. It adds fields only and skips `_parse_failure` lines. |
| `pipelines/eve/dictionaries/misp_ip.yml` | The dictionary. The committed file holds one documentation address as a seed; `make misp-dictionary` overwrites it from MISP. |
| `detections/enrich.py` | Reference of the enrich stage, compared with the conf by `tests/test_enrich.py`. |
| `detections/sigma/web_alert_from_misp_source.yml` | Fires on any IDS alert whose source is listed. Needs the enrichment field. |
| `scripts/enrichment_demo.py` | Prints the verdict of every rule before and after enrichment. Output is `docs/evidence/s6-enrichment-outcome.txt`. |
| `scripts/exposure_check.py`, `make exposure-check` | Asks Shodan which ports it sees on `SHODAN_TARGET_IP`. Exit 1 on an unexpected port or a known vulnerability. |
| `scripts/add-secret.sh` | Stores an API key as SOPS/age ciphertext from a hidden prompt. |

## What is not verified

- Logstash has not run. The conf is checked statically against the reference, not by Logstash.
- MISP is not in `compose.yaml`. Run it from the official `misp-docker` repository. The commands below follow its template and have not been run here.
- The Shodan response shape in the fixtures comes from memory of the host API. Check it with one live call (below) before trusting the test.
- `sops` was not available where this was written. `add-secret.sh` and the two Make targets are untested end to end.

## Run it

1. Store the keys (hidden prompt, nothing on the command line):

   ```bash
   bash scripts/add-secret.sh shodan SHODAN_API_KEY
   bash scripts/add-secret.sh misp MISP_KEY
   ```

   Commit only `secrets/shodan.enc.yaml` and `secrets/misp.enc.yaml`. Check with `git show --stat HEAD` that no `.env.secrets` is staged.

2. MISP, in a separate folder:

   ```bash
   git clone --depth 1 https://github.com/MISP/misp-docker.git ~/misp-docker
   cd ~/misp-docker && cp template.env .env
   ```

   Edit `.env`: `BASE_URL`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_KEY`. Pick an HTTPS port that is not 8443 (step-ca uses it). Then `docker compose up -d`. Sign in, enable one OSINT feed under Sync Actions, List Feeds, fetch it, and publish an event with a few `ip-src` attributes marked "For Intrusion Detection System". The `ADMIN_KEY` you set is the value for `MISP_KEY`.

3. Set `MISP_URL` in `.env` to that instance, then:

   ```bash
   make misp-dictionary
   git diff --stat pipelines/eve/dictionaries/misp_ip.yml
   ```

4. Exposure, once, from the lab host:

   ```bash
   make exposure-check | tee docs/evidence/s6-shodan-exposure.txt
   ```

   Set `SHODAN_TARGET_IP` and `SHODAN_EXPECTED_PORTS` in `.env` first. A free Shodan account gets HTTP 403 on the host lookup. For that case set `SHODAN_MODE=internetdb` and `SHODAN_API_HOST=internetdb.shodan.io`: the check then uses the free keyless InternetDB service, and the output names its `source`. InternetDB data is coarser (ports, vulnerabilities, tags) and its response shape was read from a sample, not tested live. Exit code 1 is a finding, not a failure of the tool. Session 7 turns it into an Alertmanager rule.

## Evidence

| File | How to produce it | Risk |
|---|---|---|
| `s6-enrichment-outcome.txt` | `python3 scripts/enrichment_demo.py` (already committed) | R-09 |
| `s6-misp-event.png` | MISP event with the listed `ip-src`, to_ids on | R-09 |
| `s6-dashboards-misp-hit.png` | Discover on `eve-lab-samples`, query `threat.indicator.matched:true` after `make load-samples` | R-09 |
| `s6-shodan-exposure.txt` | `make exposure-check` | R-10 |
