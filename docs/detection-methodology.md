# Detection Methodology

r2inspect treats raw matches as observations, groups relevant observations into
evidence, and only then produces findings or a detector verdict.

## Rules

1. `ERROR`, `UNKNOWN`, and `UNSUPPORTED` are not `ABSENT` or `CLEAN`.
2. A single common API, string, opcode, or high-entropy section is weak evidence.
3. High-confidence findings require a signature or a contextual combination of
   independent evidence.
4. Every finding records its analyzer, method, evidence, and location when the
   backend provides one.
5. Format and architecture checks precede instruction-specific detection.
6. Resource limits and timeouts produce explicit incomplete outcomes.

The packer detector currently combines signature, entropy, suspicious-section,
and import-count evidence using transparent weights. Import extraction failure
is unknown and contributes no low-import score. Those weights are heuristics,
not calibrated probabilities, until the benchmark publishes measured precision
and recall.

YARA matches retain rule-level evidence. Generic suspicious API matches are
triage signals and must not be interpreted as proof of malicious behavior.

Changes to a detector require labeled positive and benign negative cases plus a
malformed/error case. Threshold changes require benchmark evidence rather than
coverage-only tests.
