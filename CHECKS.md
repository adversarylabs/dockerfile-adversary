# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `dockerfile.add.remote-url` | High | ADD from remote URL |
| `dockerfile.base-image.unpinned-digest` | Medium | Base image not pinned by digest |
| `dockerfile.build-arg.missing` | Medium | A version build variable is used without a stage-visible declaration |
| `dockerfile.copy.broad-context` | Medium | Broad COPY/ADD of build context |
| `dockerfile.external-artifact.mutable` | Medium | Direct artifact download uses a moving or unversioned URL |
| `dockerfile.ignore.missing` | Medium | Missing .dockerignore with broad copy risk |
| `dockerfile.runtime.root-user` | High | Final stage runs as root |
| `dockerfile.secret.arg-env` | High | Secret material in ARG/ENV |
| `dockerfile.secret.rm-later-layer` | High | Secret removed only in a later layer |
| `dockerfile.shell.curl-bash` | High | curl\|bash (or similar) install pattern |
