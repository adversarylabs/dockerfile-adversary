# container/dockerfile

**container/dockerfile** reviews Dockerfile-style files for **container build and runtime security**: unpinned bases, secrets in build args/env, broad build context copies, root runtime users, and dangerous shell patterns.

It is a **Dockerfile domain reviewer**, not a general image scanner (no registry pulls, no CVE DB of base layers). When it reports, the build can leak secrets or produce an unsafe runtime image.

## What it does

1. **Discovers** Dockerfile and `*.dockerfile` candidates (and related ignore files).
2. **Runs deterministic detectors** with stable rule ids.
3. **Synthesizes a review** through the SDK.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)** — the audit surface for “what does this adversary look for?”

Highlights:

| Area | Examples |
| --- | --- |
| Base images | FROM without digest pin |
| Secrets | ARG/ENV holding secret material; secrets removed only in later layers |
| Context | Broad COPY/ADD of `.`; missing .dockerignore pairing |
| Runtime | USER root in final stage |
| Shell | curl|bash install patterns; remote ADD URLs |

### Ownership boundaries

Other official adversaries own adjacent classes so findings stay non-duplicative:

| Concern | Owned by |
| --- | --- |
| Committed secrets outside Dockerfiles | [`security/secrets`](https://github.com/adversarylabs/secrets-adversary) |
| CI workflow supply chain | [`ci/github-actions`](https://github.com/adversarylabs/githubactions-adversary) |
| Go module graph integrity | [`go/modules`](https://github.com/adversarylabs/go-modules-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire where graded fixtures exist.
- Prefer missing a weak signal over a false positive on normal production code.
