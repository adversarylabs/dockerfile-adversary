# Checks — what container/dockerfile detects

This file is the **public audit list** of detectors. If a rule id appears here, it is part of the product surface: it should fire on a vulnerable pattern, stay quiet on the documented clean case, and produce file:line evidence where applicable.

Runtime source of truth: [`src/rules.ts`](src/rules.ts).
Regression entry: package tests under `test/`.

**Scope:** Dockerfile, Dockerfile.*, *.dockerfile, and adjacent .dockerignore context.

---

## High

### `dockerfile.secret.arg-env`

| | |
| --- | --- |
| **What** | Secret material in ARG/ENV |
| **Why** | Build args and env leak via history and runtime |
| **Looks for** | password/token/secret-like ARG or ENV |
| **Stays quiet when** | BuildKit secrets / runtime secret injection |
| **Remediation** | Never bake secrets into image config |

### `dockerfile.secret.rm-later-layer`

| | |
| --- | --- |
| **What** | Secret removed only in a later layer |
| **Why** | Layer history retains secret files |
| **Looks for** | COPY secret then later RUN rm |
| **Stays quiet when** | Multi-stage without secret in final; BuildKit secret mounts |
| **Remediation** | Secrets must never enter committed layers |

### `dockerfile.runtime.root-user`

| | |
| --- | --- |
| **What** | Final stage runs as root |
| **Why** | Container breakout impact amplified |
| **Looks for** | No USER or USER root in final stage |
| **Stays quiet when** | Non-root USER before ENTRYPOINT/CMD |
| **Remediation** | Run as non-root |

### `dockerfile.shell.curl-bash`

| | |
| --- | --- |
| **What** | curl|bash (or similar) install pattern |
| **Why** | Remote script execution at build |
| **Looks for** | curl/wget piped to shell |
| **Stays quiet when** | Pinned artifacts with checksums |
| **Remediation** | Verify checksums; avoid pipe-to-shell |

### `dockerfile.add.remote-url`

| | |
| --- | --- |
| **What** | ADD from remote URL |
| **Why** | Opaque remote content in build |
| **Looks for** | ADD https://… |
| **Stays quiet when** | COPY local verified artifacts |
| **Remediation** | Prefer COPY of pinned local inputs |

## Medium

### `dockerfile.base-image.unpinned-digest`

| | |
| --- | --- |
| **What** | Base image not pinned by digest |
| **Why** | Tags move under you |
| **Looks for** | FROM image:tag without @sha256 |
| **Stays quiet when** | FROM image:tag@sha256:… |
| **Remediation** | Pin production bases by digest |

### `dockerfile.external-artifact.mutable`

| | |
| --- | --- |
| **What** | Direct artifact download uses a moving or unversioned URL |
| **Why** | Rebuilds can consume different external content without a Dockerfile change |
| **Looks for** | `curl`/`wget` URLs with `latest`, moving branches, or unversioned artifact filenames |
| **Stays quiet when** | The URL contains a stable version/commit or the same `RUN` verifies a checksum/signature |
| **Remediation** | Select a stable artifact and verify its integrity before use |

### `dockerfile.copy.broad-context`

| | |
| --- | --- |
| **What** | Broad COPY/ADD of build context |
| **Why** | Secrets and junk enter context/image |
| **Looks for** | COPY . / or similar with weak dockerignore |
| **Stays quiet when** | Narrow COPY + strong .dockerignore |
| **Remediation** | Copy only required build inputs |

### `dockerfile.ignore.missing`

| | |
| --- | --- |
| **What** | Missing .dockerignore with broad copy risk |
| **Why** | Accidental context upload |
| **Looks for** | Dockerfile present without dockerignore when broad copies exist |
| **Stays quiet when** | .dockerignore for VCS, secrets, caches |
| **Remediation** | Add .dockerignore |
