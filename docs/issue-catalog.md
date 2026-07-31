# container/dockerfile — issue catalog

This document is the **issue catalog** for this adversary: the classes of defects we aim to find, how we detect them (static vs LLM), public pattern references, and staff priority (P0 / P1 / LLM-only / Cut).

It is documentation and roadmap for contributors — not a runtime contract. Implemented detectors live in `src/` with fixtures under `fixtures/`; the **Review verdicts** section records what ships first.

Public examples cited below illustrate bad patterns only. Do not scrape secrets from them or copy copyrighted code into fixtures.

**Catalog id:** `container/dockerfile`  
**Status:** public OSS documentation of the issue classes this adversary targets  
**Goal:** trusted, high-precision detections. Prefer missing a weak signal over a false positive.

## Mission
Catch container build and runtime foot-guns that lead to supply-chain risk, secret leakage into layers, and over-privileged production images.

## LLM strategy (required for world-class)
**Enhance:** interpret multi-stage graphs, decide if a root USER is intentional, judge .dockerignore adequacy.
**Discover:** novel secret-in-layer patterns, weird privilege escalations across stages.

### Division of labor
| Layer | Responsibility |
| --- | --- |
| **Static / structural** | Precise, deterministic signals with line-level evidence. |
| **LLM enhancement** | Impact, multi-file stories, ranking, FP suppression when context proves safe. |
| **LLM discovery** | Novel issues only with concrete file:line evidence; no invented vulns. |

### Trust / anti-FP rules
1. Evidence required: file + line + snippet (or explicit multi-file list).
2. LLM-only findings default medium/low confidence until backed by a static rule.
3. One finding per remediation story; skip vendor/generated noise.
4. When unsure, do not report.

## Review verdicts (staff pass)

- **P0 implement:** `secret.arg`, `user.root-runtime`, `add.remote-url`, `shell.curl-bash`, `copy.dot`, `ignore.missing`, `secret.rm-later-layer`
- **P1:** `base.unpinned-digest` (low), `add.tar-autoextract`, `apt.no-clean`, `pkg.unpinned` (low), `sudo`, `privileged-hint`, `healthcheck.missing`, `multistage.missing`, `workdir.root`, `exposed.admin-port`, `env.secrets-file`, `setuid`, `writable-etc`, `from.latest`, `user.uid0-named`, `os-package.recommends`, `cmd.shell-form`
- **LLM-only:** none — everything here has a static backbone.
- **Cut:** `zypper-or-apk.no-pin` — merged into `pkg.unpinned` (one rule across package managers).
- **Precision notes:** `base.unpinned-digest` and `pkg.unpinned` downgraded to low — both flag the majority of real-world Dockerfiles and must be scoped to release images to stay trustworthy.

## Issue catalog

---
### 1. `dockerfile.user.root-runtime` — Runtime image runs as root

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Final stage lacks USER or sets USER root, expanding blast radius of RCE.

**Static detection.** Parse Dockerfile stages; check final stage USER instruction.

**LLM role.** Note if image is intentionally a build toolkit; still warn for app images.

**False-positive guards.** Base images that are distroless with nonroot by default; FROM scratch static binaries.

**Public examples of the bad pattern:**
  - https://github.com/dockersamples/example-voting-app — vote/Dockerfile historically root-centric teaching images
  - https://github.com/jessfraz/dockerfiles — mixed desktop containers (good FP corpus)
  - https://github.com/docker-library/docs — official image best practices on USER

---
### 2. `dockerfile.base.unpinned-digest` — Base image not pinned by digest

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | high |

**What it is.** FROM image:tag without sha256 digest enables silent base swaps.

**Static detection.** Detect FROM without @sha256:; ignore multi-stage build stages named as aliases.

**LLM role.** Recommend digests for production release Dockerfiles only — this pattern is the majority of real-world Dockerfiles, so report only when CI pushes the image to a registry or the LLM classifies it as a release image.

**False-positive guards.** Local dev Dockerfiles; ARG-parameterized tags with CI pin elsewhere.

**Public examples of the bad pattern:**
  - https://github.com/docker-library/official-images — pinning guidance
  - https://github.com/aquasecurity/trivy — image pin findings in wild reports
  - https://github.com/GoogleContainerTools/distroless — digest usage examples

---
### 3. `dockerfile.secret.arg` — Secret passed via ARG/ENV

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** ARG/ENV names like TOKEN/PASSWORD/SECRET persist in image history.

**Static detection.** Keyword match on ARG/ENV keys + values that look like secrets.

**LLM role.** Prefer BuildKit secret mounts; flag history leak risk.

**False-positive guards.** ARG VERSION, ARG TARGETARCH; empty ARGs for multi-arch.

**Public examples of the bad pattern:**
  - https://docs.docker.com/build/building/secrets/ — correct secret mounts
  - https://github.com/moby/buildkit — secret mount design
  - https://stackoverflow.com/questions/23391839/clone-private-git-repo-with-dockerfile — common ARG token anti-pattern

---
### 4. `dockerfile.copy.dot` — COPY . copies entire build context

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** COPY . /app without tight .dockerignore risks secrets and bloat.

**Static detection.** Detect COPY/ADD of `.` or wide globs; check for .dockerignore existence.

**LLM role.** LLM: is .dockerignore adequate for this project type?

**False-positive guards.** Scratch/examples where context is intentionally tiny.

**Public examples of the bad pattern:**
  - https://github.com/docker-library/official-images — COPY specificity guidance
  - https://github.com/dockersamples/example-voting-app
  - https://docs.docker.com/build/building/context/#dockerignore-files

---
### 5. `dockerfile.add.remote-url` — ADD remote URL

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** ADD https://... fetches mutable remote content into image.

**Static detection.** Detect ADD with http(s) URLs.

**LLM role.** Suggest COPY of vendored artifacts or verified digests.

**False-positive guards.** Legacy Docker docs samples.

**Public examples of the bad pattern:**
  - https://docs.docker.com/reference/dockerfile/#add — warns about remote ADD
  - https://github.com/hadolint/hadolint — DL3020 rule corpus
  - https://github.com/docker/dockerfile — reference examples

---
### 6. `dockerfile.add.tar-autoextract` — ADD local archive auto-extract

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | high |

**What it is.** ADD archive.tar confuses layer intent vs COPY.

**Static detection.** Detect ADD of .tar/.tar.gz/.zip.

**LLM role.** Prefer COPY + RUN tar for clarity.

**False-positive guards.** Intentional rootfs tarball images.

**Public examples of the bad pattern:**
  - https://github.com/hadolint/hadolint — DL3010
  - https://docs.docker.com/reference/dockerfile/#add
  - https://github.com/docker-library/busybox — rootfs patterns

---
### 7. `dockerfile.apt.no-clean` — Package install without clean

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | high |

**What it is.** apt-get install without rm -rf /var/lib/apt/lists inflates image.

**Static detection.** Shell parse of RUN apt-get.

**LLM role.** Minor for multi-stage builder stages.

**False-positive guards.** Builder stages discarded later.

**Public examples of the bad pattern:**
  - https://github.com/hadolint/hadolint — DL3009
  - https://docs.docker.com/build/building/best-practices/
  - https://github.com/docker-library/python — clean patterns

---
### 8. `dockerfile.pkg.unpinned` — Unpinned OS packages (apt/apk/yum/dnf)

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | medium |

**What it is.** Unversioned installs hurt reproducibility (absorbs the former apk/yum rule). Reality check: hadolint DL3008/DL3018 are among the most-disabled rules in the wild because pins go stale and break builds — default severity low.

**Static detection.** Parse RUN apt-get/apk/yum/dnf/microdnf install lines for unversioned packages.

**LLM role.** Balance with distroless/minimal images.

**False-positive guards.** Meta-packages; security update intentional floating.

**Public examples of the bad pattern:**
  - https://github.com/hadolint/hadolint — DL3008
  - https://github.com/docker-library/official-images
  - https://docs.docker.com/build/building/best-practices/

---
### 9. `dockerfile.sudo` — sudo installed or used

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** sudo in container usually means privilege model is wrong.

**Static detection.** Detect sudo package or sudo in RUN/CMD.

**LLM role.** Rare legitimate admin containers.

**False-positive guards.** Build stages only.

**Public examples of the bad pattern:**
  - https://github.com/hadolint/hadolint — DL3004
  - https://github.com/jessfraz/dockerfiles
  - https://docs.docker.com/engine/security/

---
### 10. `dockerfile.privileged-hint` — Capabilities / privileged hints in comments or compose

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Dockerfile/compose suggesting --privileged or CAP_SYS_ADMIN.

**Static detection.** Scan adjacent compose/k8s files for privileged: true / cap_add: SYS_ADMIN and scripts for docker run --privileged; do not scan comments (FP-prone).

**LLM role.** LLM: is this a nested docker builder?

**False-positive guards.** DinD official examples.

**Public examples of the bad pattern:**
  - https://github.com/docker-library/docker — dind Dockerfiles
  - https://github.com/hadolint/hadolint
  - https://docs.docker.com/engine/security/userns-remap/

---
### 11. `dockerfile.healthcheck.missing` — No HEALTHCHECK for long-running service

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | medium |

**What it is.** Service images without HEALTHCHECK.

**Static detection.** Detect CMD/ENTRYPOINT server patterns without HEALTHCHECK.

**LLM role.** Skip CLI tools and one-shot jobs.

**False-positive guards.** Kubernetes-only health probes.

**Public examples of the bad pattern:**
  - https://docs.docker.com/reference/dockerfile/#healthcheck
  - https://github.com/docker-library/docs
  - https://github.com/hadolint/hadolint

---
### 12. `dockerfile.multistage.missing` — Single-stage build ships toolchain

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Compiler/tooling left in final image.

**Static detection.** Detect go build/npm install/maven in final stage without AS builder.

**LLM role.** LLM: is multi-stage feasible?

**False-positive guards.** Tiny C static builds; scratch FROM with only binary.

**Public examples of the bad pattern:**
  - https://docs.docker.com/build/building/multi-stage/
  - https://github.com/docker-library/golang
  - https://github.com/GoogleContainerTools/distroless

---
### 13. `dockerfile.workdir.root` — WORKDIR is /

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | high |

**What it is.** WORKDIR / is sloppy and risky for relative COPY.

**Static detection.** Detect WORKDIR /.

**LLM role.** None.

**False-positive guards.** Init containers.

**Public examples of the bad pattern:**
  - https://github.com/hadolint/hadolint — DL3000
  - https://docs.docker.com/reference/dockerfile/#workdir
  - https://github.com/docker-library/official-images

---
### 14. `dockerfile.exposed.admin-port` — Exposes admin/debug ports

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** EXPOSE 2375/9229/5005/6060 etc.

**Static detection.** Port allow/deny lists (2375, 9229, 5005, 6060 — and 22: sshd inside a container is its own smell).

**LLM role.** LLM: is service intentionally a debugger image?

**False-positive guards.** Devcontainer Dockerfiles.

**Public examples of the bad pattern:**
  - https://github.com/microsoft/vscode-dev-containers
  - https://github.com/hadolint/hadolint
  - https://docs.docker.com/reference/dockerfile/#expose

---
### 15. `dockerfile.env.secrets-file` — ENV points to secret files in image

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** ENV GOOGLE_APPLICATION_CREDENTIALS=/secrets/key.json copied into image.

**Static detection.** ENV path + COPY of json key files.

**LLM role.** Suggest runtime mounts.

**False-positive guards.** Public dummy credentials for demos.

**Public examples of the bad pattern:**
  - https://docs.docker.com/build/building/secrets/
  - https://github.com/GoogleCloudPlatform/python-docs-samples — credential patterns
  - https://github.com/hadolint/hadolint

---
### 16. `dockerfile.shell.curl-bash` — curl | bash installers

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** curl ... | sh in RUN without checksum.

**Static detection.** Detect pipe-to-shell patterns.

**LLM role.** Require checksum/signature verification.

**False-positive guards.** Well-known get.docker.com in docs (still warn).

**Public examples of the bad pattern:**
  - https://github.com/hadolint/hadolint — DL4006/pipefail related
  - https://docs.docker.com/engine/install/
  - https://blog.yossarian.net/2020/05/21/Dont-curl-bash-what-you-found-on-the-internet

---
### 17. `dockerfile.setuid` — chmod u+s or setuid binaries

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Creating setuid binaries in image.

**Static detection.** Detect chmod u+s / 4755.

**LLM role.** Rare specialized images.

**False-positive guards.** None usually.

**Public examples of the bad pattern:**
  - https://github.com/hadolint/hadolint
  - https://docs.docker.com/engine/security/
  - https://github.com/docker/docker-bench-security

---
### 18. `dockerfile.writable-etc` — chmod 777 on system paths

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** chmod -R 777 /app or /etc.

**Static detection.** Detect world-writable chmod.

**LLM role.** tmp only exceptions.

**False-positive guards.** Build cache dirs cleaned later.

**Public examples of the bad pattern:**
  - https://github.com/hadolint/hadolint
  - https://github.com/docker/docker-bench-security
  - https://docs.docker.com/engine/security/

---
### 19. `dockerfile.from.latest` — FROM …:latest

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** Floating latest tag.

**Static detection.** Detect :latest or untagged Docker Hub official short names resolving latest.

**LLM role.** Dev-only suppress. Cross-ref `dockerfile.base.unpinned-digest`: :latest/no tag = medium (this rule); tagged-but-no-digest = low (that rule).

**False-positive guards.** Scratch.

**Public examples of the bad pattern:**
  - https://github.com/hadolint/hadolint — DL3007
  - https://docs.docker.com/build/building/best-practices/
  - https://github.com/docker-library/official-images

---
### 20. `dockerfile.user.uid0-named` — USER with uid 0 alias

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** USER 0 or USER root after nonroot.

**Static detection.** Parse USER args.

**LLM role.** None.

**False-positive guards.** Root required package managers in intermediate stages.

**Public examples of the bad pattern:**
  - https://docs.docker.com/reference/dockerfile/#user
  - https://github.com/GoogleContainerTools/distroless — nonroot user
  - https://github.com/hadolint/hadolint

---
### 21. `dockerfile.os-package.recommends` — apt without --no-install-recommends

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | high |

**What it is.** Bloated images from recommended packages.

**Static detection.** Detect apt-get install without flag.

**LLM role.** Low priority.

**False-positive guards.** Builder stages.

**Public examples of the bad pattern:**
  - https://github.com/hadolint/hadolint — DL3015
  - https://docs.docker.com/build/building/best-practices/
  - https://github.com/docker-library/python

---
### 22. `dockerfile.cmd.shell-form` — CMD/ENTRYPOINT shell form

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | medium |

**What it is.** Shell form hurts signals (PID1).

**Static detection.** Detect shell vs exec form JSON arrays.

**LLM role.** LLM: is shell needed for env expansion?

**False-positive guards.** Complex shell entrypoints with explicit tini.

**Public examples of the bad pattern:**
  - https://docs.docker.com/reference/dockerfile/#cmd
  - https://github.com/hadolint/hadolint — DL3025
  - https://github.com/krallin/tini

---
### 23. `dockerfile.ignore.missing` — Missing .dockerignore

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** No .dockerignore with COPY .

**Static detection.** File existence check.

**LLM role.** Generate suggested ignore for language.

**False-positive guards.** Context is single file.

**Public examples of the bad pattern:**
  - https://docs.docker.com/build/building/context/#dockerignore-files
  - https://github.com/github/gitignore
  - https://github.com/dockersamples/example-voting-app

---
### 24. `dockerfile.secret.rm-later-layer` — Secret added then removed in a later layer

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** COPY id_rsa … followed by a later RUN rm does not remove it from the earlier layer — the secret ships in image history. Same for RUN steps that write a credential and delete it in a *different* RUN.

**Static detection.** Pair COPY/ADD of credential-looking files (id_rsa, *.pem, .npmrc, .netrc, service-account*.json) with a later rm of the same path across instructions.

**LLM role.** Recommend BuildKit --mount=type=secret; suppress when the file only ever exists in a discarded builder stage.

**False-positive guards.** Multi-stage builds where the file lives only in a discarded stage; obvious dummy fixtures.

**Public examples of the bad pattern:**
  - https://docs.docker.com/build/building/secrets/ — the correct pattern
  - https://github.com/moby/buildkit — secret mounts
  - https://github.com/OWASP/wrongsecrets — layer-history challenges

---

## Implementation roadmap (after approval)
1. Ship P0 static rules with vulnerable+clean fixtures.
2. Feed static signals into LLM review for enhancement (not re-detection).
3. Add discovery prompts constrained to evidence.
4. Precision bake-off on popular public repos; FP budget is a release gate.

**P0 priorities:** secret ARG/ENV, root runtime, remote ADD, curl|bash, COPY . without dockerignore, secret-then-rm layers.
