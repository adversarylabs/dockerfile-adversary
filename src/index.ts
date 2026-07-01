#!/usr/bin/env node

import { Adversary, Finding, Severity, log } from "@adversary/sdk";

export function createApp(): Adversary {
  const app = new Adversary({
    name: "local/dockerfile-adversary",
  });

  app.rule("dockerfile.discovered", async (ctx) => {
    log.info("Searching for Dockerfile-style files...");

    const dockerfiles = Array.from(
      new Set([...(await ctx.rglob("Dockerfile")), ...(await ctx.rglob("Dockerfile.*")), ...(await ctx.rglob("*.dockerfile"))]),
    ).sort();

    ctx.summary.files_scanned = dockerfiles.length;

    if (dockerfiles.length === 0) {
      log.info("No Dockerfile-style files were found.");
      return [];
    }

    log.info(`Found ${dockerfiles.length} Dockerfile-style file(s).`);
    return dockerfiles.map(
      (dockerfile) =>
        new Finding({
          ruleId: "dockerfile.discovered",
          severity: Severity.Low,
          title: "Dockerfile was found",
          message: "Review this Dockerfile for image build and runtime security concerns.",
          path: dockerfile,
          recommendation:
            "Check base image pinning, secret handling, user privileges, package installation, and exposed ports.",
        }),
    );
  });

  return app;
}

if (process.argv[1] !== undefined && import.meta.url === new URL(process.argv[1], "file:").href) {
  await createApp().run();
}
