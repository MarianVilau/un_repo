# pipelines/CLAUDE.md

Rules for Logstash pipelines. They add to the root `CLAUDE.md` and never loosen it.

- One pipeline per source (`snort-alerts`, `eve`), one file per stage: input, normalise, enrich, output.
- Normalise to Elastic Common Schema first. Enrichment reads ECS fields only: `source.ip`, `destination.ip`, `event.dataset`, `rule.id`.
- Ports, hosts and file paths come from environment variables (`${LOGSTASH_BEATS_PORT}`), never literals.
- A line that fails parsing gets the tag `_parse_failure` and is kept, not dropped. Silent drops make detections blind (R-07).
- Enrichment adds fields (`threat.indicator.matched`, `threat.indicator.provider`). It never overwrites source fields.
- Every filter change comes with a positive and a negative sample in `tests/` and a test that runs in CI.
