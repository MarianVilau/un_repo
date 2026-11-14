# Detection runbook (Session 5)

Risk: R-07 (a malformed or oversized line makes detections blind). Related: R-09 and R-10 use the same fields in Session 6.

## What is here

| Path | Purpose |
|---|---|
| `detections/sigma/*.yml` | Two Sigma rules: SQL injection pattern (ATT&CK T1190) and scanner user agent (T1595.002). Fields are ECS. |
| `tests/samples/eve/` | One positive and one negative raw EVE sample per rule, plus `malformed_line.txt`. Addresses are from the documentation ranges (RFC 5737). |
| `pipelines/eve/` | Logstash stages: `10-input`, `20-normalise`, `90-output`. `30-enrich` is Session 6, see `docs/threatintel-runbook.md`. |
| `detections/ecs_eve.py` | Reference mapping EVE to ECS. The tests compare it with `20-normalise.conf`. |
| `detections/sigma_match.py` | Small Sigma evaluator so pytest can assert match and no-match. Unsupported syntax raises an error. |
| `detections/opensearch/eve-lab-template.json` | Index template: matching fields are keywords with a lowercase normalizer, so Sigma's case-insensitive match works in Lucene. |
| `scripts/sigma_query.py`, `make sigma-query` | The OpenSearch query pySigma generates from each rule. |
| `scripts/load-samples.sh`, `make load-samples` | Loads the ECS-normalised samples into the running stack for the Dashboards evidence. |

## What the tests prove

`pytest -q` checks, for each rule: ATT&CK technique and tactic tags, a unique ID, ECS field names the pipeline produces, a match on its positive sample, no match on its negative sample and on the other rule's sample. It also checks that pySigma converts the rule to an OpenSearch query.

For the pipeline it checks: one file per stage, no literal ports, hosts or IPs, every variable documented in `.env.example`, the tag `_parse_failure` present and no `drop`, and that the rename block equals the reference mapping.

## Evidence for the Dashboards hit

With the stack running (`make up`):

```bash
make -s sigma-query | tee docs/evidence/s5-sigma-query.txt
make load-samples
```

`load-samples` prints `errors: False documents: 5`. Then in Dashboards:

1. Stack Management, Index patterns, create `eve-lab*` with `@timestamp` as the time field.
2. Discover, pick `eve-lab*`, time range Last 15 minutes.
3. Paste the SQL injection query from `s5-sigma-query.txt` into the search bar. One document must match, `sqli_positive.json`.
4. Screenshot as `docs/evidence/s5-dashboards-hit.png`. Do the same with the scanner query if you want a second one.

## Known limits

- Logstash did not run for this session. The conf files are checked statically and against the reference mapping. Whether Logstash accepts them is untested until a Logstash service joins the stack in Session 6, with a digest pinned by `make pin-digests`.
- The Dashboards hit uses documents loaded by `load-samples`, not documents that came through Logstash.
- Discover starts in DQL, which rejects the escaped spaces in the generated query (`DQLSyntaxError`). Switch the language to Lucene with the DQL button next to the search bar. With that, the SQL injection query returned exactly one document on 2026-11-14 (`s5-dashboards-hit.png`). If it matches nothing, check that the index was created from the template (`GET eve-lab-samples/_mapping`).
- `sigma_match.py` is not Sigma. It supports `contains`, `startswith`, `endswith`, `re`, field lists and `and`, `or`, `not` with parentheses. A rule that needs more fails the tests.
- Keyword fields have a 32 KB term limit. `EVE_MAX_LINE_BYTES` defaults to 16 KB, below it.
- The output stage turns certificate verification off because the lab OpenSearch uses the image's demo certificate.
