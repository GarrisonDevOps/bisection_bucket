# gitlab-ai-principles-distiller

Tooling that keeps `.ai/principles/distilled/*.md` in sync with the SSOT
documentation under `doc/development/`. It powers the scheduled weekly job in
`.gitlab/ci/sync-principles.gitlab-ci.yml`; see
[`.ai/principles/README.md`](../../.ai/principles/README.md) in the consuming
repository for the full operator-facing flow.

## Binaries

- `gitlab-ai-principles-distiller-sync` — the orchestrator. Detects per-principle
  drift via the existing checksum frontmatter, triggers one Duo Workflow per
  affected principle, polls each until terminal state, writes the result back,
   and (with `distill --push`) opens an MR via the REST API. Each per-team MR pings the
  people who changed the SSOT docs since the last distillation (resolved via a
  GraphQL `commits` query, so private and secondary emails match too), assigns
  up to four of the most recent contributors as reviewers, and falls back to one available `owner_team`
  member when no author resolves. Approval still routes to `owner_team` via
  CODEOWNERS. Each per-team MR opens as Draft and requests a GitLab Duo
  review, since automatic review skips drafts.
- `gitlab-ai-principles-distiller-provision-flow` — idempotent provisioner for
  the AI Catalog Flow that the orchestrator drives. Runs before `sync` so prompt
  edits in git automatically propagate to the catalog. The read-only
  `--print-consumer-id` flag prints only the numeric ItemConsumer ID.

## Subcommands

Use `distill` to scan, distill every affected principle (four at a time), and
optionally publish. This is the local and dry-run path.

Scheduled CI instead splits those stages across jobs, so each principle gets its
own CI job with its own timeout:

| Subcommand | Stage | Description |
|------------|-------|-------------|
| `distill [--push]` | local | Scans, distills, and optionally publishes affected principles. |
| `generate-pipeline` | generate | Scans for drift and writes the child-pipeline YAML. Distills nothing. |
| `distill-one NAME` | distill (one job per principle) | Distills exactly that principle and records the outcome as an artifact. Publishes nothing. |
| `collect NAMES [--push]` | collect | Fans the artifacts back in and publishes only with `--push`. Distills nothing. |
| `check-fences [--warn-stale]` | guard | Reports stale, malformed, or orphaned Duo review instruction fences. |
| `reconcile-fences [--push]` | reconcile | Regenerates Duo review instruction fences and optionally opens a reconcile MR. |

`distill --only NAMES` limits drift detection to the named principles.
It skips principles whose checksums match unless you also pass `--force`.
`distill-one NAME` runs after `generate-pipeline` has already selected a
principle, so it does not repeat drift detection.
It writes an artifact for `collect` and is intended for the generated CI
pipeline, not local use.

The split exists because all principles previously shared a single 2 h job
budget. A principle that fails with invalid content burns roughly 20 minutes of
retry backoff, and that time was charged to every other principle: on
2026-07-30 the job timed out and discarded 19 successfully distilled principles
because the publish step was never reached.

Publishing stays a single job. It groups principles by owning team and builds
each team's branch against one shared working tree, so it cannot be split the
way distillation can.

When reusing an open sync MR, publishing skips the branch if any MR commit
has an author or committer email different from the configured Git author.
Checking the committer also catches a reviewer who amends a generated commit.
It also skips the branch if commit ownership cannot be verified. This preserves
reviewer fixes without opening a replacement MR or closing the existing one.
Publication stops if account or MR discovery fails.

Every push uses an explicit force-with-lease, so commits pushed after the
ownership check are never overwritten:

- An adopted branch is leased at the MR head verified during discovery.
- A missing branch gets a create-only lease.
- An existing branch without an open MR, such as the reconcile branch after its
  MR closes or a dated branch left behind by a failed run, is replaced only if
  every commit beyond the default branch was authored and committed by the
  distiller account. Otherwise publication of that branch fails and the branch
  is preserved for a human to inspect.

When regeneration produces no changes, the existing MR stays open for a human
to close: its remote branch might contain a concurrent reviewer fix.

For adopted team, tooling, and metadata MRs, the distiller posts a notice when
publication is frozen or regeneration produces no publishable changes.
The notice asks a human to review and merge the existing changes or close the
MR if obsolete. Only one notice is posted per MR, even if the reason changes later.
The distiller checks every page of notes for its own notice marker;
note lookup or posting failures warn without changing publication behavior.
The notice mentions assigned reviewers except the distiller account and Duo.
MRs without reviewers, including tooling MRs, still receive a notice but may
have no human notification recipients unless someone is subscribed.
An ownership-check failure only pauses the current run; later runs verify
ownership again and may resume publication.
The collect job uses a shared resource group to prevent overlapping CI runs
from posting duplicate notices. Serialize manual publication runs with collectors
too: the notes API does not provide an atomic check-and-create operation.

The date-free reconcile branch uses the existing-branch ownership check even
when its MR is open. If it contains human commits and needs another fence
update, publication fails with `ERROR: reconcile push failed` and preserves
the branch. Subsequent runs continue to fail until the branch is resolved.
Review and merge the fixes, or preserve any needed changes elsewhere before
closing the MR and deleting its source branch. Closing the MR alone does not
unblock publication while the branch still contains unmerged human commits.

### Artifact contract

Each `distill-one` job writes its files under `tmp/ai-principles-distilled/`:
`<name>.status` (always), `<name>.md` (only when the status is `updated`), and
`<name>.checkpoint.json` (only when the status is `unchanged`).
`collect` reads them against the expected principle list and sorts each
principle into one of four states:

| Artifact | State |
|----------|-------|
| status `updated` + content | Publish it. |
| status `unchanged` + checkpoint | Ran cleanly, no meaningful diff. Publish only the new `source_checksum` and `distilled_at_sha`. |
| status `failed` | Failed after retries. Reported, and the run exits non-zero. |
| no status file | The job never completed. Reported separately, and the run exits zero. |

The last two states are deliberately distinct. A principle whose job never ran
has not been shown to be undistillable, so reporting it as a distillation
failure would send an operator chasing a defect that does not exist. Either way
the principle keeps its committed checksum, so the next scheduled run
re-attempts it.

Checkpoints are published together in one `metadata` MR, which each run reuses.
That MR changes only the frontmatter, so the next scan skips the principle
until its sources change again. A checkpoint is dropped when the distilled file
on the default branch no longer matches the file that was evaluated.

## Workspace

Both binaries operate on the consumer repository's working tree. The path is
discovered, in order:

1. `--workspace PATH` CLI flag.
2. `CI_PROJECT_DIR` environment variable.
3. Otherwise the script aborts with an explicit error.

## Required environment variables

| Variable | Purpose |
|----------|---------|
| `GITLAB_TOKEN` | Duo Workflow API and GraphQL polling. |
| `GITLAB_API_TOKEN` | Auto-MR creation through the REST API. Required for `distill --push`. |
| `AGENT_PRINCIPLES_CATALOG_PROJECT` | Project that owns the AI Catalog flow. |
| `AGENT_PRINCIPLES_CATALOG_ITEM_CONSUMER_ID` | Numeric ID of the catalog `ItemConsumer` that binds the distillation flow to the project. |
| `CI_DEFAULT_BRANCH` | Default branch used to resolve the workflow source branch. |
| `CI_PROJECT_ID` | Numeric ID of the consumer project. Required for `distill --push`. |

Before distillation, the sync preflights all required variables together. If
configuration is missing, the error provides copy-pasteable `export` lines.

The CI job in `.gitlab/ci/sync-principles.gitlab-ci.yml` documents how these are
sourced from project CI/CD variables.
