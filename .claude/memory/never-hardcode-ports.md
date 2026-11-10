---
name: never-hardcode-ports
type: correction
---

Ports are never written into Compose, nginx or pipeline files.

**Why:** the first generated `compose.yaml` published `9200:9200` literally. Two stacks on one laptop then collided and the fix touched four files.

**How to apply:** put each port in `.env` (`OPENSEARCH_PORT=9200`) and reference `${OPENSEARCH_PORT}`. Inside a container network the service name replaces the host.
