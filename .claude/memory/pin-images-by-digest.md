---
name: pin-images-by-digest
type: correction
---

Container images are pinned by digest, with the readable tag kept as a comment.

**Why:** a tag can be repointed, so the same Compose file may pull different bits tomorrow. That is a supply-chain risk (R-06) and it breaks repeatable deploys.

**How to apply:** `image: opensearchproject/opensearch@sha256:<digest>  # 2.19.1`. Read the digest with `docker inspect --format '{{index .RepoDigests 0}}' <image>`. Never type a digest from memory.
