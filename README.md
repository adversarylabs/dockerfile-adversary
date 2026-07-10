# dockerfile

Inspects Dockerfile-style files and reports structured review observations through the Adversary SDK.

## Build

```sh
npm install
npm run build
```

## Run

```sh
adversary run . --repo /path/to/repository
```

## Test

```sh
npm test
```

## Layout

- `adversary.yaml` declares the adversary manifest.
- `AGENTS.md` gives AI coding agents repository-specific engineering guidance.
- `src/index.ts` contains the TypeScript SDK adversary.
- `dist/index.js` is prebuilt so `adversary run . --repo ...` works immediately.
- `test/index.test.ts` demonstrates testing rules with fixtures.
- `fixtures/clean` should produce no findings.
- `fixtures/vulnerable` should produce actionable Dockerfile findings.
- `Dockerfile` packages the compiled adversary for the CLI.
