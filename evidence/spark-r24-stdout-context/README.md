# Spark R24 Stdout/Log Context Evidence

## Before

`before-spark-r24-stdout-log-context.png` is a genuine screenshot from a Spark Telegram
conversation captured on 2026-06-04 at 16:36:05 Europe/Budapest.

The user asked: "show the Codex stdout/log for this run".

Spark answered with a Mission Control URL and a diagnostic notes path instead of the requested
stdout/log artifact. This demonstrates the R24 context-misunderstanding failure.

## After Contract

The `spark-runtime-log-context-advisor` chip adds a bounded response contract for stdout, stderr,
service logs, and diagnostic notes. It requires Spark to identify the requested artifact, separate
Mission Control URLs from log or diagnostic locations, and state missing context rather than
inventing or substituting a false answer.
