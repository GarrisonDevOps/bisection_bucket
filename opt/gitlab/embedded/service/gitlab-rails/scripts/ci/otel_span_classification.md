# CI span classification

Operation metadata describes the work being performed. Failure categories describe
observed results, not infrastructure root causes.

## Usage

```shell
otel_span [--kind KIND] [--operation NAME] [--attempt NUMBER] \
  [--rspec-report PATH] [--rspec-report-count COUNT] [NAME] -- COMMAND [ARGS...]
```

Existing invocations remain compatible. Metadata options precede the span name
and command separator. Command arguments after the separator remain unchanged,
and commands continue to run in the current shell.

## Attributes

| Attribute | Values |
| --- | --- |
| `gitlab.cicd.operation.kind` | `test`, `dependency_install`, `build`, `lint`, `deploy`, `readiness` |
| `gitlab.cicd.operation.name` | Identifier matching `[a-z][a-z0-9_-]{0,63}` |
| `gitlab.cicd.operation.attempt` | Integer from 1 to 999 |
| `gitlab.cicd.failure.category` | `user:test:failure`, `user:test:framework_error`, `user:unknown` |
| `gitlab.cicd.failure.source` | `rspec_report` for classified results, otherwise `exit_code` |

Successful spans have no failure attributes. Unsupported metadata is omitted
without changing the command result or ordinary span export.

## Category namespaces

Every failure category has the form `<namespace>:<name>`, and the name can have
more `:` segments, for example `user:test:failure`. Segments match `[a-z0-9_]+`.

- `platform:` is reserved for GitLab product code, such as Rails, Runner and
  helper binaries.
- `user:` is for classifications emitted by CI job scripts. These scripts are
  user code, so every category in this document is `user:`.

The prefix is a convention. A job script can send any string to the endpoint, so
consumers must not treat a `platform:` value as trusted without a producer
attribute.

## RSpec evidence

The wrapper and exporter accept `--rspec-report-count COUNT`, which defaults to
1 and supports at most 64 reports. A literal `%{worker}` in the report path is
replaced with worker indexes from 1 through `COUNT`. There is no glob discovery.

All expected reports must be regular files modified at or after span start.
The total 8 MiB size budget is divided equally among the expected files. Each
JSON report must contain nonnegative integer `summary.failure_count` and
`summary.errors_outside_of_examples_count` values. Classification uses their
combined counts:

- Exit 1, failures greater than zero, no outside-example errors: `user:test:failure`.
- Exit 2, outside-example errors greater than zero: `user:test:framework_error`,
  including mixed example failures and outside-example errors.
- For operation `e2e`, exit 1 also permits `user:test:framework_error` when
  outside-example errors are greater than zero, because QA aborts with exit 1.
- Other combinations: `user:unknown`.

If any expected report is missing, malformed, stale, oversized, or inconsistent,
classification falls back to `user:unknown` with source `exit_code`. Invalid report
counts also fall back to `user:unknown`. Report contents and paths are not exported.
Classification uses the existing exporter process without extra Ruby launches.

The shared RSpec helpers consume initial and retry reports before merging them,
using operation `rspec` and attempts 1 and 2. E2E uses operation `e2e` with the
same attempt numbers and these reports:

| Attempt | Report path | Count |
| --- | --- | --- |
| Initial, sequential | `tmp/rspec-${CI_JOB_ID}-retried-false.json` | 1 |
| Initial, `QA_RUN_IN_PARALLEL=true` | `tmp/rspec-${CI_JOB_ID}-retried-false-%{worker}.json` | `QA_PARALLEL_PROCESSES` |
| Retry | `tmp/rspec-${CI_JOB_ID}-retried-true.json` | 1 |

An unset parallel count becomes 0, producing `user:unknown`. QA can reduce the actual
worker count below the configured count. Missing reports then produce `user:unknown`.
Dynamic worker counts require an exact report manifest and are not supported.

## Interpretation

Failures from other tools remain `user:unknown`. Dependency installation and deployment
failures do not by themselves establish an infrastructure problem. There is no
log parsing or inference of cancellation, timeout, or OOM from exit codes.

Recovery can be derived by joining job ID and operation name across attempts:
initial `ERROR`, retry `OK`, job `OK`. A successful retry alone does not establish
test flakiness. Earlier failed spans retain their original status and category.
