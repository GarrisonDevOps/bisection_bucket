---
stage: Data Access
group: Database
info: Any user with at least the Maintainer role can merge updates to this content. For details, see <https://docs.gitlab.com/development/development_processes/#development-guidelines-review>.
title: clickhouse:migrate:multi-version-upgrade job
---

This job runs ClickHouse migrations the way a real GitLab upgrade runs them, so
that migrations are exercised against populated tables. It is the ClickHouse
counterpart of [`db:migrate:multi-version-upgrade`](../dbmigrate_multi_version_upgrade_job.md)
for PostgreSQL.

The existing `clickhouse:check-schema` job runs every migration from scratch
against an empty database in a single pass. That cannot reproduce three
conditions that real upgrades have:

1. The schema starts at an older [required upgrade stop](../../../update/upgrade_paths.md),
   not at the current version.
1. Post-deployment migrations run after newer regular migrations have already
   changed a table. Omnibus and Helm upgrades run migrations in these two
   phases.
1. Tables already contain rows, so a swap, a projection rebuild or a column
   drop has parts on disk to rewrite.

Issue [#593129](https://gitlab.com/gitlab-org/gitlab/-/issues/593129) needed all
three at once and reached a customer because no job covered them.

## What the job does

`scripts/click_house/multi_version_upgrade.sh`:

1. Resolves the latest required upgrade stop with `Gitlab::Utils::UpgradePath`,
   then picks that release's highest patch tag.
1. Loads the ClickHouse schema as it was at that tag. `db/click_house/main.sql`
   and `db/click_house/schema_migrations/` are committed, so this is a
   `git checkout` of two paths and needs no database dump.
1. Seeds 10 rows into every MergeTree table except `AggregatingMergeTree`
   tables, with the ClickHouse `generateRandom` table function, which takes its
   structure from the table. Integer columns are kept small, like real IDs,
   because batched data migrations walk ID ranges in fixed steps.
   `AggregatingMergeTree` tables get their rows from their materialized views,
   the way they do in production. An aggregated table stays empty when random
   source rows do not pass its view's `WHERE` filter.
1. Runs regular migrations with `SKIP_POST_DEPLOYMENT_MIGRATIONS=true` in one
   log section, then the post-deployment migrations in a second.
1. Runs `scripts/validate_clickhouse_schema.rb`, the same check as
   `clickhouse:check-schema`, to confirm the dumped schema, the schema cache
   and the migration marker files all match what is committed.

Seeding is derived from the schema rather than from hand-written fixtures on
purpose. The migrations in the tested window change every release, so a fixed
fixture set would drift away from the tables that actually get migrated.

## When it runs

On merge request pipelines that change `config/upgrade_path.yml`, `VERSION`,
`db/click_house/**`, `db/siphon/**`, `lib/click_house/**`,
`lib/tasks/gitlab/click_house/**`, `scripts/click_house/**`, or the job
definition itself. It is skipped on
forks, on merge requests targeting stable branches, and on expedited pipelines.

The job is allowed to fail while it proves stable, so a failure does not block
the merge. Issue [635169](https://gitlab.com/gitlab-org/gitlab/-/work_items/635169)
tracks making it required.

Apply `~"pipeline:run-all-rspec"` to force it to run.

## Troubleshooting

### The job is red on an unrelated merge request

Check which step failed:

- Resolving the upgrade stop: A `git ls-remote` or `git fetch` failure is
  usually transient. The error includes the output from Git. Retry the job.
- Seeding: A `WARNING: could not seed <table>` line includes the ClickHouse
  error. The job skips that table and continues, and only fails if no rows were
  seeded at all. A warning from a materialized view fed by the table is
  expected, because the view can reject random values.
- Migrating: This is a real migration failure against populated tables and
  is what the job exists to catch. The two log sections show whether it failed
  in the regular or the post-deployment phase. Reproduce it locally with the
  steps below.
- Verifying: The schema drifted from `db/click_house/main.sql`. For a
  confirmed false positive, the `~"pipeline:skip-check-clickhouse-schema"`
  label also applies here, the same way it does for `clickhouse:check-schema`.

To disable the job while a fix is prepared, set
`DISABLE_CLICKHOUSE_MULTI_VERSION_UPGRADE` to `true` in the project CI/CD
settings, and announce it in `#master-broken`.

### Running it locally

Point the `test` ClickHouse configuration at a throwaway database, then:

```shell
CLICKHOUSE_URL=http://localhost:8123 \
  CLICKHOUSE_DATABASE=gitlab_clickhouse_upgrade_test \
  RAILS_ENV=test DISABLE_WEBMOCK=true ENABLE_CLICKHOUSE_DB_DUMP=true \
  bash scripts/click_house/multi_version_upgrade.sh
```

The script restores the branch's `main.sql` and marker files on exit, so an
interrupted run does not leave the worktree on the upgrade stop's schema. It
fetches the stop tag with `--depth 1` only on CI, because a shallow fetch into
a full local clone marks that clone as shallow.
