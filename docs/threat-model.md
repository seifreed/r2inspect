# Threat Model

## Assets

- Analyst workstation, CI runner, and container host.
- Files outside the requested sample/rule/output paths.
- Credentials and tokens present in the environment.
- Integrity of analysis reports, rules, plugins, and release artifacts.

## Adversary input

Samples, paths, YARA rules, plugin packages, radare2 output, archive contents,
and metadata are untrusted. A crafted binary may be extremely large, malformed,
cyclic, slow to analyze, or designed to exploit a parser.

## Trust boundaries

The CLI validates user paths before opening them. r2inspect crosses a process
boundary when it invokes radare2 and a code-execution boundary when Python entry
point plugins are installed. Plugins therefore have the same privileges as the
r2inspect process and are not a sandbox.

## Controls

- Bounded reads, output sizes, worker counts, retries, and timeouts.
- Input and output path validation.
- Non-root minimal container runtime.
- Pinned fixture/backend inputs, dependency audit, container scanning, SBOM,
  provenance, and signed published images.
- Explicit error outcomes instead of trusted clean defaults.

## Residual risk

radare2 and optional native libraries parse attacker-controlled bytes outside a
sandbox. Analyze hostile samples in an isolated, disposable environment with no
secrets or sensitive mounts. Resource bounds reduce denial-of-service risk but
cannot eliminate parser vulnerabilities or all worst-case analysis time.
