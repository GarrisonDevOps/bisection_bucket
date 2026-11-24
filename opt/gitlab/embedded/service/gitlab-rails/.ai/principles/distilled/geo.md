---
source_checksum: 4b25e08e2a052368
distilled_at_sha: 2019a7ae51d6a06150b080b619b0d33e1f8d50ac
---
<!-- Auto-generated from docs.gitlab.com by gitlab-ai-principles-distiller — do not edit manually -->

# Geo Principles

## Checklist

### Geo Support for New Features

- Ensure new data stored outside the main and CI PostgreSQL databases (not a plain table or column) is replicated and verified by Geo; Geo support is part of the definition of done.
- DO NOT add Geo work for new tables or fields in the main or CI databases; PostgreSQL streaming replication already covers them.
- Subclass `AttachmentUploader` for new blobs when possible: it tracks blobs in the `Upload` model, so Geo support already exists. Exception: when blobs are tracked in a new table, add the blob replicator strategy.
- Add Geo support (repository replicator strategy) for any new feature backed by Git repositories.
- Ensure every `Uploader` has a corresponding `Replicator`; `ee/spec/uploaders/every_gitlab_uploader_spec.rb` fails otherwise.
- Handle each kind of data in a multi-data feature separately; reuse existing replicators (LFS objects, `Upload`) and add Geo support only for the kinds not yet covered.
- DO NOT replicate Redis data between sites; sessions and caches are not shared between primary and secondary.

### Adding or Changing Replicables (Self-Service Framework)

- Use the SSF generators for new replicables: `rails g geo:blob_replicator` for CarrierWave-backed blobs, `rails g geo:repository_replicator` for Git repository types; DO NOT hand-roll replication. The generator produces the replicator, registry and state models, finder, GraphQL type/resolver, ops feature flags, migrations for both databases, dictionaries, factories, and specs.
- Every replicable has a replicator (`ee/app/replicators/geo/`), a registry model (`ee/app/models/geo/`), a verification state, a registry finder (`ee/app/finders/geo/`), and GraphQL wiring; follow the full checklist in the `Geo Replicate a new blob type` or `Geo Replicate a new Git repository type` issue template in `.gitlab/issue_templates/`.
- Replicators inherit from `Gitlab::Geo::Replicator` and include either `::Geo::BlobReplicatorStrategy` or `::Geo::RepositoryReplicatorStrategy`; the model includes `::Geo::ReplicableModel` and declares `with_replicator Geo::<Name>Replicator`.
- Registry models inherit from `Geo::BaseRegistry` and include `::Geo::ReplicableRegistry` (plus `::Geo::VerifiableRegistry` when the data type is verified); the registry state machine and sync logic come from those concerns.
- Geo feature flags follow `geo_<data_type>_replication` and `geo_<data_type>_force_primary_checksumming` naming; the SSF generators create them as type `ops` in `ee/config/feature_flags/ops/`. Flags for features still under test use `beta` or `wip` instead.
- New replicables must be added to `doc/administration/geo/replication/datatypes.md`.
- Define a separate replicator for each resource to replicate, even when several resources share one model; keep the class name unique, because the registry table name derives from it (`PackageFileReplicator` → `package_file_registry`).
- Give every blob file and every Git repository its own primary ID and model; treat each as a first-class citizen to simplify tracking replication and verification state.
- Put small Geo utility methods in `ee/lib/gitlab/geo.rb`.

### Database

- Registry tables live in the Geo tracking database (`gitlab_geo` schema); their migrations go in `ee/db/geo/migrate` (or `ee/db/geo/post_migrate` for post-deployment migrations), never `db/migrate` or `db/post_migrate`.
- Verification state tables (`*_states`) live in the same database and schema as their model table — `gitlab_main*` for most, `gitlab_ci` for CI data types (`ci_job_artifact_states`, `ci_secure_file_states`, `p_ci_pipeline_artifact_states`) — never in the tracking database. Their migrations go in `db/migrate` with sharding keys, `db/docs` entries, and the usual review process.
- DO NOT add foreign keys, joins, or transactions that span the main database and the tracking database; they are separate databases on separate servers.
- On postgres.ai snapshots, model tables (for example `projects`, `uploads`) hold production-scale data and are good for query plans; `*_states` tables exist but are near-empty and need seeding; registry tables do not exist at all (Geo does not run on GitLab.com) — create them via DDL first, then seed.
- Generate tracking database migrations with `rails g migration [args] [options] --database geo` and apply them with `bundle exec rake db:migrate:geo`.
- Use `Gitlab::Geo.geo_database_configured?` for initialization-time checks of the tracking database (it exists only on secondaries); this avoids bootstrapping race conditions.

### Primary/Secondary Semantics

- Secondaries are read-only against the main database; secondary-side code writes only to the tracking database. DO NOT add main-database writes to code paths that run on secondaries.
- On the primary, replication events are published through the replicator: `geo_handle_after_create/update/destroy` → `Replicator#publish` → `create_event_with`, which writes `Geo::Event` + `Geo::EventLog`; the Log Cursor on the secondary consumes them. `Geo::EventStore` is the legacy mechanism; DO NOT use it for new code, and DO NOT emit Geo events from secondary-side code.
- Log Cursor delivery is at-least-once: event consumption on the secondary must be idempotent. The same event can be processed twice.
- Use the `Gitlab::Geo.enabled?` / `.primary?` / `.secondary?` / `.current_node` helpers for site checks — they are cached; DO NOT query `GeoNode` directly in hot paths.
- Workhorse on a secondary proxies nearly every HTTP request to the primary, reads included. Only the `geoLocalRoutes` allowlist in `workhorse/internal/upstream/routes.go` reaches the secondary's Rails: Geo admin and API routes, `/api/v4/internal`, health checks, assets, and Git/LFS reads (Rails decides whether to proxy those based on push/pull and freshness). DO NOT add secondary-only behavior to a proxied controller or endpoint, because it runs on the primary; a new route the secondary must serve itself needs an entry in that allowlist (`doc/development/geo/proxying.md`).
- Account for `.primary?` and `.secondary?` both returning `false` when no Geo site exists or the current site's name (`geo.node_name`, defaulting to the external URL) matches no Geo site; an expired license does not change them.
- Use `Gitlab::Geo.license_allows?` to check that the license includes Geo; DO NOT rely on `Gitlab::Geo.enabled?` for that, because it only checks that a Geo site exists and keeps its value after the license expires.
- Guard write actions that are disallowed on secondaries with `Gitlab::Database.read_only?` or `Gitlab::Database.read_write?`, not `Gitlab::Geo.secondary?`.

### Replication Mechanics

- Secondaries download blobs via `GET /api/v4/geo/retrieve/:replicable_name/:replicable_id` authenticated with a `TransferRequest` JWT, and fetch repositories over Git HTTP (`fetch_as_mirror`) authenticated with a `RepoSyncRequest` JWT (`doc/development/geo/blob_replication.md`, `doc/development/geo/repository_sync.md`); DO NOT invent new transfer endpoints.
- Blob code paths must handle both local storage and object storage; object-storage replication depends on the site's `sync_object_storage` setting.
- Every replicable model must implement `selective_sync_scope(node, **params)`; the default raises `NotImplementedError`. Scope records owned by a project or group to the node's selective-sync settings. Return all records only for instance-wide data with no owning project, group, or organization, and add a comment explaining why.
- DO NOT filter registry finders or counters by selective sync. The framework enforces it through `replicables_for_current_secondary`: the registry consistency worker creates registries only for in-scope records and deletes the rest, and event consumers skip out-of-scope records with `in_replicables_for_current_secondary?`.
- Include identifying data in the JWT payload of file and Git transfer requests (for example the replicable name and database ID for blobs, the `scope` for Git repositories) so the secondary downloads the right data for the right database ID. The framework builds the blob payload in `Gitlab::Geo::Replicator#replicable_params`; DO NOT add custom payload fields in a new blob replicator.
- Run repository syncs through `Geo::FrameworkRepositorySyncService`, which takes the exclusive lease `geo_sync_ssf_service:{replicable_name}:{model_record_id}`; DO NOT bypass it, so concurrent syncs of one repository are serialized. `ExclusiveLeaseGuard#try_obtain_lease` releases the lease after the sync, also when it raises an error.
- Rely on `Geo::RepositoryReplicatorStrategy#consume_event_updated` to set the registry to `pending` before a repository sync (mutable repository types only); DO NOT add per-replicator code for it. This prevents a running sync from marking the registry `synced` and missing the latest change.

### Workers and State

- Event-driven Geo workers include the `GeoQueue` concern; Geo cron workers use `CronjobQueue` instead. Only scheduler-style workers (`Geo::Scheduler::SchedulerWorker` subclasses) also include `GeoBackoffDelay` for backoff between runs.
- `GeoQueue` sets `feature_category :geo_replication`; workers without it must declare the feature category themselves.
- Geo cron workers must be registered in `Gitlab::Geo::CronManager` (`COMMON_GEO_JOBS`, `PRIMARY_GEO_JOBS`, or `SECONDARY_GEO_JOBS`) so the right site roles run them.
- Record sync and verification failures on the registry (`failed` state + error message) so retry/backoff works; an unhandled exception must not strand a registry in `started`.
- Guard bulk state transitions against concurrent changes: `update_all`/`upsert_all` must include the expected current state in the `WHERE` clause, and upserts must explicitly list updated columns.
- For multi-step state transitions, verify a crash between steps cannot strand records in an intermediate state forever.
- Registry state is a `state_machine` over an integer column, not a Rails enum; use the named state-machine events for single records. In `update_all`/`upsert_all`, use `Geo::ReplicableRegistry::STATE_VALUES[:synced]`-style constants (or `Model.enums[:value]` for actual enums) — bulk operations bypass both the state machine and ActiveRecord casting.

### Verification

- Use the `Geo::VerifiableModel` / `Geo::VerifiableReplicator` concerns; the primary checksums, the secondary compares. DO NOT implement bespoke checksum logic.
- A checksum mismatch must lead to re-sync, not a silent state overwrite.

### Testing

- Use the EE Geo helpers: `stub_current_geo_node`, `stub_primary_site`, `stub_secondary_site`, `stub_proxied_site`; DO NOT stub `Gitlab::Geo` methods directly.
- Use the SSF shared examples instead of re-testing framework behavior per replicable: `'a replicator'`, `'a blob replicator'`, `'a repository replicator'`, `'a verifiable replicator'`, `'a replicable model'`, `'a verifiable model for verification state'`.
- Use the `Geo::DummyReplicator` helpers (`stub_dummy_replicator_class`, `create_dummy_model_table`) when testing framework changes rather than coupling specs to a real replicable.
- Add QA tests for new Geo functionality, and ensure the `qa-geo` job passes in a triggered `GET:Geo` pipeline when changing Geo features.

### EE Gating

- Geo application code (replicators, registries, workers, finders) is EE-only and lives under `ee/`; the exceptions are verification state table migrations (`db/migrate`, `db/docs`) and Workhorse proxy routes. Behavior must degrade cleanly when Geo is disabled or unlicensed.

## Authoritative sources

For the full picture, see:

- doc/development/geo.md
- doc/development/geo/framework.md
- doc/development/geo/blob_replication.md
- doc/development/geo/repository_sync.md
- doc/development/geo/api.md
- doc/development/geo/proxying.md

