# Dockerfile Checks

This adversary reviews Dockerfile-style files for container build and runtime security issues.

Current implementation status:

- Implemented: `dockerfile.discovered`
- Planned: all other checks listed below

The planned checks are intentionally conservative. They should produce deterministic findings, include line-level evidence where possible, and avoid findings that require knowing the application runtime contract.

Recommended implementation priority:

- `dockerfile.context.sensitive-file-not-ignored`
- `dockerfile.copy.from-external-unpinned`
- `dockerfile.pkg.apt-version-unpinned`
- `dockerfile.pkg.pip-version-unpinned`
- `dockerfile.pkg.npm-version-unpinned`
- `dockerfile.pkg.gem-version-unpinned`
- `dockerfile.workdir.missing`
- `dockerfile.cmd.multiple`
- `dockerfile.entrypoint.multiple`
- `dockerfile.expose.port-out-of-range`
- `dockerfile.stopsignal.sigkill`

## Sources

- Docker Build best practices: https://docs.docker.com/build/building/best-practices/
- Dockerfile reference: https://docs.docker.com/reference/dockerfile/
- Docker Build checks reference: https://docs.docker.com/reference/build-checks/
- Hadolint rules reference: https://github.com/hadolint/hadolint#rules

## Discovery

### `dockerfile.discovered`

- Status: implemented
- Severity: low
- Check: discover Dockerfile-style files named `Dockerfile`, `Dockerfile.*`, or `*.dockerfile`.
- Finding: emit one informational finding per discovered file so reviewers know where Docker image definitions exist.
- Recommendation: review base image pinning, secret handling, user privileges, package installation, and exposed ports.

## Base Images

### `dockerfile.base.latest-tag`

- Status: planned
- Severity: medium
- Check: flag `FROM` images that use `latest` or omit an explicit tag.
- Rationale: mutable tags reduce reproducibility and can introduce unexpected changes.
- Recommendation: pin to an explicit version tag, and for high assurance pin by digest.

### `dockerfile.base.unpinned-digest`

- Status: planned
- Severity: low
- Check: flag `FROM` images that use a tag but do not include an image digest.
- Rationale: tags are mutable even when they look versioned.
- Recommendation: use `image:tag@sha256:<digest>` when reproducible builds or auditability matter.

### `dockerfile.base.scratch-or-minimal-runtime`

- Status: planned
- Severity: low
- Check: when a Dockerfile has build tooling but only one stage, suggest multi-stage builds or a smaller runtime image.
- Rationale: separating build and runtime stages reduces final image size and attack surface.
- Recommendation: use multi-stage builds and copy only runtime artifacts into the final stage.

### `dockerfile.base.remote-platform-constant`

- Status: planned
- Severity: low
- Check: flag `FROM --platform=<constant>` when the platform is hard-coded.
- Rationale: Docker Build includes a `FromPlatformFlagConstDisallowed` check because hard-coded platform values can break multi-platform builds.
- Recommendation: remove the constant platform or use a build argument when platform selection is intentional.

## Build Context

### `dockerfile.context.missing-dockerignore`

- Status: planned
- Severity: medium
- Check: flag repositories that contain Dockerfile-style files but no `.dockerignore` adjacent to the build context.
- Rationale: large or sensitive files can be sent to the build context accidentally.
- Recommendation: add `.dockerignore` entries for secrets, VCS metadata, dependency caches, build outputs, test artifacts, and local configuration.

### `dockerfile.context.copy-all`

- Status: planned
- Severity: low
- Check: flag broad `COPY . ...` or `ADD . ...` instructions.
- Rationale: broad copies make image contents depend on the entire build context and increase the chance of copying sensitive or unnecessary files.
- Recommendation: copy only required manifests and source paths, and use `.dockerignore` to exclude everything else.

### `dockerfile.context.copy-ignored-file`

- Status: planned
- Severity: medium
- Check: flag `COPY` or `ADD` references that are excluded by `.dockerignore`.
- Rationale: Docker Build has a `CopyIgnoredFile` check because these instructions do not behave as authors often expect.
- Recommendation: remove the ignore entry or stop copying the ignored path.

### `dockerfile.context.sensitive-file-not-ignored`

- Status: planned
- Severity: high
- Check: flag obvious sensitive files in the build context that are not excluded by `.dockerignore`, such as `.env`, `.aws/`, `.kube/`, `id_rsa`, `.npmrc`, `.pypirc`, `*.pem`, and `*.key`.
- Rationale: sensitive files can be sent to the Docker build context and accidentally copied into layers.
- Recommendation: add `.dockerignore` entries for local secrets and credential files, and keep build credentials outside the context.

## Secrets

### `dockerfile.secrets.arg-env`

- Status: planned
- Severity: high
- Check: flag `ARG` or `ENV` names that appear to hold secrets, such as `TOKEN`, `SECRET`, `PASSWORD`, `PRIVATE_KEY`, `API_KEY`, `AWS_SECRET_ACCESS_KEY`, or similar names.
- Rationale: Docker Build includes a `SecretsUsedInArgOrEnv` check; ARG and ENV values can persist in metadata or image history.
- Recommendation: pass secrets with BuildKit secret mounts instead of `ARG` or `ENV`.

### `dockerfile.secrets.inline-value`

- Status: planned
- Severity: high
- Check: flag obvious inline secret assignments in `RUN`, `ENV`, `ARG`, `LABEL`, `COPY`, or `ADD` instructions.
- Rationale: secrets committed to Dockerfiles are usually baked into images, layers, metadata, or source history.
- Recommendation: remove the value, rotate the secret, and pass it through a secret manager or BuildKit `RUN --mount=type=secret`.

### `dockerfile.secrets.ssh-material`

- Status: planned
- Severity: high
- Check: flag copying SSH keys, `.netrc`, cloud credentials, kubeconfigs, npm tokens, pip credentials, or other credential files into the image.
- Rationale: credential files copied into an image can remain recoverable even if later deleted.
- Recommendation: use BuildKit `RUN --mount=type=ssh` or `RUN --mount=type=secret`.

### `dockerfile.secrets.credential-download-without-secret-mount`

- Status: planned
- Severity: medium
- Check: flag likely private dependency or credentialed download flows that do not use BuildKit secret or SSH mounts, such as copying `.npmrc` before `npm install`, using credential environment variables before `pip install`, or cloning private Git repositories without `--mount=type=ssh`.
- Rationale: credentialed build steps often need temporary secrets, and secret mounts avoid persisting those secrets in image layers or metadata.
- Recommendation: use `RUN --mount=type=secret` for token files and `RUN --mount=type=ssh` for private Git access.

## Users And Privileges

### `dockerfile.user.missing-nonroot`

- Status: planned
- Severity: medium
- Check: flag final stages that do not set `USER`, or set `USER root`.
- Rationale: Docker recommends using `USER` to switch to a non-root user when the service can run without privileges.
- Recommendation: create a dedicated user/group and switch to it before the final runtime command.

### `dockerfile.user.switches-back-to-root`

- Status: planned
- Severity: medium
- Check: flag Dockerfiles that switch from a non-root user back to `root` in the final stage.
- Rationale: frequent user switching increases complexity, and ending as root weakens runtime isolation.
- Recommendation: perform privileged setup earlier, then switch once to the runtime user.

### `dockerfile.user.sudo-installed`

- Status: planned
- Severity: medium
- Check: flag installation or use of `sudo`.
- Rationale: Docker recommends avoiding `sudo` in containers because it can introduce signal and TTY behavior problems and is rarely needed in images.
- Recommendation: perform privileged steps during build, then run the application as a non-root user.

### `dockerfile.user.missing-group`

- Status: planned
- Severity: low
- Check: flag final-stage `USER` values that specify a user without an explicit group.
- Rationale: Docker warns that if the user has no primary group, the image may run with the root group.
- Recommendation: specify both user and group, such as `USER app:app` or `USER 10001:10001`.

## Package Installation

### `dockerfile.pkg.apt-used`

- Status: planned
- Severity: low
- Check: flag use of `apt` in `RUN` instructions.
- Rationale: `apt` is intended for interactive end-user workflows; `apt-get` is more stable for scripts and Dockerfiles.
- Recommendation: use `apt-get` in Dockerfile build steps.

### `dockerfile.pkg.apt-update-without-install`

- Status: planned
- Severity: medium
- Check: flag `RUN apt-get update` when it is not combined with `apt-get install` in the same `RUN`.
- Rationale: separate update/install layers can reuse stale package indexes from cache.
- Recommendation: combine `apt-get update && apt-get install -y --no-install-recommends ...` in one `RUN`.

### `dockerfile.pkg.apt-install-recommends`

- Status: planned
- Severity: low
- Check: flag `apt-get install` commands that omit `--no-install-recommends`.
- Rationale: recommended packages can increase image size and dependency surface.
- Recommendation: include `--no-install-recommends` unless the extra packages are explicitly needed.

### `dockerfile.pkg.install-missing-assume-yes`

- Status: planned
- Severity: medium
- Check: flag non-interactive package install commands that omit assume-yes flags, such as `apt-get install` without `-y`, `yum install` without `-y`, `dnf install` without `-y`, or `zypper install` without `-y`.
- Rationale: missing assume-yes flags can make Docker builds hang or depend on interactive prompts.
- Recommendation: include the package manager's non-interactive assume-yes flag in Dockerfile install commands.

### `dockerfile.pkg.apt-version-unpinned`

- Status: planned
- Severity: low
- Check: flag `apt-get install` package arguments that do not pin a package version with `=`.
- Rationale: Hadolint checks apt version pinning because unpinned package installs reduce reproducibility.
- Recommendation: pin packages to explicit versions where reproducibility matters, such as `package=1.2.3-1`.

### `dockerfile.pkg.pip-version-unpinned`

- Status: planned
- Severity: low
- Check: flag `pip install` package arguments that do not pin versions with `==`, constraints, or a lock/requirements file.
- Rationale: Hadolint checks pip version pinning because unpinned package installs can change over time.
- Recommendation: install from a locked requirements file or pin direct package arguments.

### `dockerfile.pkg.npm-version-unpinned`

- Status: planned
- Severity: low
- Check: flag global or direct `npm install` package arguments that do not pin versions with `@<version>`.
- Rationale: Hadolint checks npm version pinning because mutable dependency resolution reduces reproducibility.
- Recommendation: use lockfiles for project installs and pin direct/global package versions.

### `dockerfile.pkg.gem-version-unpinned`

- Status: planned
- Severity: low
- Check: flag `gem install` package arguments that do not pin versions with `--version`, `-v`, or a lockfile-driven install.
- Rationale: Hadolint checks gem version pinning because unpinned package installs can drift.
- Recommendation: use Bundler with a lockfile or pin direct gem installs.

### `dockerfile.pkg.apt-lists-not-removed`

- Status: planned
- Severity: low
- Check: flag `apt-get install` commands that do not remove `/var/lib/apt/lists/*` in the same `RUN`.
- Rationale: package indexes left in layers increase image size.
- Recommendation: append `rm -rf /var/lib/apt/lists/*` in the same `RUN`.

### `dockerfile.pkg.apk-no-cache-missing`

- Status: planned
- Severity: low
- Check: flag `apk add` commands that omit `--no-cache`.
- Rationale: Alpine package indexes do not need to persist in the final image.
- Recommendation: use `apk add --no-cache ...`.

### `dockerfile.pkg.package-manager-upgrade`

- Status: planned
- Severity: medium
- Check: flag full system upgrades such as `apt-get upgrade`, `apt-get dist-upgrade`, `apk upgrade`, `yum update`, or `dnf upgrade`.
- Rationale: broad upgrades make builds less reproducible and can conflict with the base image maintainer's patching model.
- Recommendation: rebuild from an updated base image and install only required packages.

### `dockerfile.pkg.unnecessary-tools`

- Status: planned
- Severity: low
- Check: flag common debug/build tools in final stages, such as compilers, shells added only for debugging, editors, curl/wget, git, openssh-client, or package managers when not needed at runtime.
- Rationale: Docker recommends avoiding unnecessary packages to reduce complexity, size, and vulnerability surface.
- Recommendation: keep build tools in builder stages and copy only runtime artifacts into the final stage.

## Remote Downloads And Shell

### `dockerfile.download.pipe-shell`

- Status: planned
- Severity: high
- Check: flag `curl ... | sh`, `wget ... | sh`, `bash <(curl ...)`, and equivalent remote script execution.
- Rationale: remote script execution bypasses integrity review and can make builds non-reproducible.
- Recommendation: download pinned artifacts, verify checksums or signatures, then execute trusted local files.

### `dockerfile.download.no-integrity-check`

- Status: planned
- Severity: medium
- Check: flag `curl`, `wget`, `ADD <url>`, or similar remote downloads that are not followed by checksum or signature verification.
- Rationale: unauthenticated or unverified downloads can compromise the build.
- Recommendation: verify SHA256 checksums, signatures, or use package manager repositories with trusted metadata.

### `dockerfile.add.remote-url`

- Status: planned
- Severity: medium
- Check: flag `ADD` instructions that fetch remote URLs.
- Rationale: `ADD` can fetch remote HTTPS and Git URLs, but explicit download and verification is easier to review.
- Recommendation: prefer `COPY` for local files; for remote artifacts, use explicit download plus verification.

### `dockerfile.add.git-unpinned`

- Status: planned
- Severity: medium
- Check: flag `ADD` instructions that fetch Git repositories without an immutable commit reference.
- Rationale: Docker supports Git URLs in `ADD`, and branch or default references are mutable.
- Recommendation: pin Git `ADD` sources to a commit SHA, or fetch explicitly and verify the expected revision.

### `dockerfile.add.local-file`

- Status: planned
- Severity: low
- Check: flag local `ADD` instructions that are not using automatic tar extraction.
- Rationale: `COPY` is clearer for local files and directories when `ADD` features are not needed.
- Recommendation: use `COPY` unless relying on `ADD` for local tar extraction, remote URLs, or Git sources.

### `dockerfile.copy.from-external-unpinned`

- Status: planned
- Severity: medium
- Check: flag `COPY --from=<image>` references to external images that use mutable tags or omit digests.
- Rationale: external images used as copy sources can drift just like `FROM` base images.
- Recommendation: pin external copy sources with explicit tags and digests.

## Runtime Metadata

### `dockerfile.cmd.shell-form`

- Status: planned
- Severity: low
- Check: flag shell-form `CMD` for service images.
- Rationale: Docker recommends exec-form `CMD ["executable", "param"]` for service-based images.
- Recommendation: use JSON exec form so the main process receives signals predictably.

### `dockerfile.cmd.multiple`

- Status: planned
- Severity: low
- Check: flag Dockerfiles with multiple `CMD` instructions in a single stage.
- Rationale: Docker only uses the last `CMD`, so earlier values are dead configuration.
- Recommendation: keep one final `CMD` per stage.

### `dockerfile.entrypoint.shell-form`

- Status: planned
- Severity: medium
- Check: flag shell-form `ENTRYPOINT`.
- Rationale: shell-form entrypoints can interfere with signal handling and PID 1 behavior.
- Recommendation: use JSON exec form and ensure wrapper scripts end with `exec "$@"`.

### `dockerfile.entrypoint.multiple`

- Status: planned
- Severity: low
- Check: flag Dockerfiles with multiple `ENTRYPOINT` instructions in a single stage.
- Rationale: Docker only uses the last `ENTRYPOINT`, so earlier values are dead configuration.
- Recommendation: keep one final `ENTRYPOINT` per stage.

### `dockerfile.healthcheck.missing`

- Status: planned
- Severity: low
- Check: flag service-like images with exposed ports but no `HEALTHCHECK`.
- Rationale: health checks let orchestrators and operators detect unhealthy containers.
- Recommendation: add a lightweight `HEALTHCHECK`, or document why health is handled outside the image.

### `dockerfile.healthcheck.multiple`

- Status: planned
- Severity: low
- Check: flag Dockerfiles with multiple `HEALTHCHECK` instructions in a single stage.
- Rationale: Docker only uses the last `HEALTHCHECK`, so earlier values are dead configuration.
- Recommendation: keep one final `HEALTHCHECK` per stage, or use `HEALTHCHECK NONE` intentionally.

### `dockerfile.expose.invalid`

- Status: planned
- Severity: low
- Check: flag invalid `EXPOSE` values, protocol casing issues, or host-port mappings in `EXPOSE`.
- Rationale: Docker Build includes `ExposeInvalidFormat` and `ExposeProtoCasing` checks.
- Recommendation: use container ports only, such as `EXPOSE 8080` or `EXPOSE 8080/tcp`.

### `dockerfile.expose.port-out-of-range`

- Status: planned
- Severity: medium
- Check: flag `EXPOSE` ports outside the valid TCP/UDP port range of 0 through 65535.
- Rationale: out-of-range ports are invalid and indicate a likely configuration error.
- Recommendation: use a valid container port number between 0 and 65535.

### `dockerfile.workdir.relative`

- Status: planned
- Severity: low
- Check: flag relative `WORKDIR` values.
- Rationale: Docker recommends absolute `WORKDIR` paths for clarity and reliability, and Docker Build includes `WorkdirRelativePath`.
- Recommendation: use an absolute path such as `/app`.

### `dockerfile.workdir.missing`

- Status: planned
- Severity: low
- Check: flag stages that copy application files or run application setup commands without first setting an explicit `WORKDIR`.
- Rationale: Docker notes that the default working directory can come from the base image and recommends setting it explicitly.
- Recommendation: set an absolute `WORKDIR` before application `COPY`, `ADD`, `RUN`, `CMD`, or `ENTRYPOINT` instructions.

### `dockerfile.stopsignal.invalid`

- Status: planned
- Severity: medium
- Check: flag invalid `STOPSIGNAL` values that are not valid signal names or numbers.
- Rationale: invalid stop signals can break container shutdown behavior.
- Recommendation: use a valid signal such as `SIGTERM` unless the image has a documented need for another signal.

### `dockerfile.stopsignal.sigkill`

- Status: planned
- Severity: medium
- Check: flag `STOPSIGNAL SIGKILL` or numeric signal `9`.
- Rationale: `SIGKILL` prevents graceful shutdown and cleanup.
- Recommendation: prefer `SIGTERM` or another graceful signal handled by the process.

## Instruction Hygiene

### `dockerfile.shell.override`

- Status: planned
- Severity: low
- Check: flag `SHELL` instructions.
- Rationale: overriding the shell changes how later shell-form `RUN`, `CMD`, and `ENTRYPOINT` instructions are interpreted.
- Recommendation: use `SHELL` only when intentional, and prefer exec-form runtime instructions where possible.

### `dockerfile.syntax.missing-modern-syntax`

- Status: planned
- Severity: low
- Check: flag Dockerfiles using BuildKit-only features without a `# syntax=docker/dockerfile:...` directive.
- Rationale: syntax directives make feature availability explicit.
- Recommendation: add an appropriate `# syntax=docker/dockerfile:1` directive.

### `dockerfile.syntax.maintainer-deprecated`

- Status: planned
- Severity: low
- Check: flag `MAINTAINER`.
- Rationale: Docker Build includes a `MaintainerDeprecated` check.
- Recommendation: use OCI labels, such as `LABEL org.opencontainers.image.authors=...`.

### `dockerfile.syntax.legacy-key-value`

- Status: planned
- Severity: low
- Check: flag legacy `ENV key value` and `ARG key value` style where `key=value` is expected.
- Rationale: Docker Build includes a `LegacyKeyValueFormat` check.
- Recommendation: use `ENV key=value` and `ARG key=value`.

### `dockerfile.syntax.inconsistent-instruction-casing`

- Status: planned
- Severity: low
- Check: flag mixed Dockerfile instruction casing.
- Rationale: consistent instruction casing improves readability, and Docker Build includes `ConsistentInstructionCasing`.
- Recommendation: use uppercase instructions consistently.

### `dockerfile.syntax.no-empty-continuation`

- Status: planned
- Severity: low
- Check: flag empty continuation lines in multi-line instructions.
- Rationale: Docker Build includes a `NoEmptyContinuation` check.
- Recommendation: remove empty continuation lines or convert the block to a heredoc.

### `dockerfile.stage.duplicate-name`

- Status: planned
- Severity: medium
- Check: flag duplicate stage aliases.
- Rationale: Docker Build includes `DuplicateStageName`.
- Recommendation: give each build stage a unique alias.

### `dockerfile.stage.reserved-name`

- Status: planned
- Severity: low
- Check: flag reserved or confusing stage names.
- Rationale: Docker Build includes `ReservedStageName`.
- Recommendation: use descriptive stage aliases such as `build`, `test`, or `runtime`.

### `dockerfile.arg.undefined-in-from`

- Status: planned
- Severity: medium
- Check: flag `FROM` instructions that reference undefined build arguments.
- Rationale: Docker Build includes `UndefinedArgInFrom`.
- Recommendation: define the `ARG` before the `FROM` that uses it.

### `dockerfile.var.undefined`

- Status: planned
- Severity: medium
- Check: flag variable references that are not defined by `ARG`, `ENV`, or Docker's automatic build args.
- Rationale: Docker Build includes `UndefinedVar`.
- Recommendation: define the variable or remove the reference.

## Risky Instructions

### `dockerfile.shell.service-command`

- Status: planned
- Severity: medium
- Check: flag service-management or interactive/debug commands in `RUN`, `CMD`, or `ENTRYPOINT`, such as `service`, `systemctl`, `shutdown`, `mount`, `ssh`, `vim`, `top`, and similar commands.
- Rationale: Hadolint has a similar rule because these commands usually indicate a VM-style workflow or interactive tooling inside a container image.
- Recommendation: run one foreground process, avoid host/service management inside the image, and keep interactive tools out of runtime images.

### `dockerfile.onbuild.copy-add`

- Status: planned
- Severity: medium
- Check: flag `ONBUILD ADD` or `ONBUILD COPY`.
- Rationale: Docker warns that `ADD` or `COPY` in `ONBUILD` can fail child builds when the expected context is absent.
- Recommendation: avoid `ONBUILD` for context-sensitive file operations, or publish a clearly named `-onbuild` tag.

### `dockerfile.volume.sensitive-path`

- Status: planned
- Severity: low
- Check: flag `VOLUME` declarations for sensitive system paths such as `/`, `/etc`, `/usr`, `/var/run/docker.sock`, or application code directories.
- Rationale: volumes alter runtime persistence and can obscure image contents.
- Recommendation: expose only mutable data, configuration, or user-serviceable paths.

### `dockerfile.labels.missing-oci-metadata`

- Status: planned
- Severity: low
- Check: optionally flag production images with no OCI image labels.
- Rationale: labels help record source, version, license, authorship, and automation metadata.
- Recommendation: add relevant `org.opencontainers.image.*` labels.

## Deliberately Out Of Scope For Initial Rules

- Vulnerability database matching for base images or installed packages.
- Verifying that a version tag is the latest secure patch.
- Determining whether an exposed port is correct for the application.
- Determining whether a missing `HEALTHCHECK` is acceptable because orchestration handles health externally.
- Flagging every broad shell anti-pattern when there is no clear Docker-specific risk.
