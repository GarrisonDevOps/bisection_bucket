### Adding or Changing Replicables (Self-Service Framework)

- Use the SSF generators for new replicables: `rails g geo:blob_replicator` for CarrierWave-backed blobs, `rails g geo:repository_replicator` for Git repository types; DO NOT hand-roll replication. The generator produces the replicator, registry and state models, finder, GraphQL type/resolver, ops feature flags, migrations for both databases, dictionaries, factories, and specs.
- Every replicable has a replicator (`ee/app/replicators/geo/`), a registry model (`ee/app/models/geo/`), a verification state, a registry finder (`ee/app/finders/geo/`), and GraphQL wiring; follow the full checklist in the `Geo Replicate a new blob type` or `Geo Replicate a new Git repository type` issue template in `.gitlab/issue_templates/`.
- Replicators inherit from `Gitlab::Geo::Replicator` and include either `::Geo::BlobReplicatorStrategy` or `::Geo::RepositoryReplicatorStrategy`; the model includes `::Geo::ReplicableModel` and declares `with_replicator Geo::<Name>Replicator`.
- Registry models inherit from `Geo::BaseRegistry` and include `::Geo::ReplicableRegistry` (plus `::Geo::VerifiableRegistry` when the data type is verified); the registry state machine and sync logic come from those concerns.
- Geo feature flags follow `geo_<data_type>_replication` and `geo_<data_type>_force_primary_checksumming` naming; the SSF generators create them as type `ops` in `ee/config/feature_flags/ops/`. Flags for features still under test use `beta` or `wip` instead.
- New replicables must be added to `doc/administration/geo/replication/datatypes.md`.

### Database

- Registry tables live in the Geo tracking database (`gitlab_geo` schema); their migrations go in `ee/db/geo/migrate` (or `ee/db/geo/post_migrate` for post-deployment migrations), never `db/migrate` or `db/post_migrate`.
- Verification state tables (`*_states`) live in the same database and schema as their model table — `gitlab_main*` for most, `gitlab_ci` for CI data types (`ci_job_artifact_states`, `ci_secure_file_states`, `p_ci_pipeline_artifact_states`) — never in the tracking database. Their migrations go in `db/migrate` with sharding keys, `db/docs` entries, and the usual review process.
- DO NOT add foreign keys, joins, or transactions that span the main database and the tracking database; they are separate databases on separate servers.
- On postgres.ai snapshots, model tables (for example `projects`, `uploads`) hold production-scale data and are good for query plans; `*_states` tables exist but are near-empty and need seeding; registry tables do not exist at all (Geo does not run on GitLab.com) — create them via DDL first, then seed.

### Primary/Secondary Semantics

- Secondaries are read-only against the main database; secondary-side code writes only to the tracking database. DO NOT add main-database writes to code paths that run on secondaries.
- On the primary, replication events are published through the replicator: `geo_handle_after_create/update/destroy` → `Replicator#publish` → `create_event_with`, which writes `Geo::Event` + `Geo::EventLog`; the Log Cursor on the secondary consumes them. `Geo::EventStore` is the legacy mechanism; DO NOT use it for new code, and DO NOT emit Geo events from secondary-side code.
- Log Cursor delivery is at-least-once: event consumption on the secondary must be idempotent. The same event can be processed twice.
- Use the `Gitlab::Geo.enabled?` / `.primary?` / `.secondary?` / `.current_node` helpers for site checks — they are cached; DO NOT query `GeoNode` directly in hot paths.
- Workhorse on a secondary proxies nearly every HTTP request to the primary, reads included. Only the `geoLocalRoutes` allowlist in `workhorse/internal/upstream/routes.go` reaches the secondary's Rails: Geo admin and API routes, `/api/v4/internal`, health checks, assets, and Git/LFS reads (Rails decides whether to proxy those based on push/pull and freshness). DO NOT add secondary-only behavior to a proxied controller or endpoint, because it runs on the primary; a new route the secondary must serve itself needs an entry in that allowlist (`doc/development/geo/proxying.md`).

### Replication Mechanics

- Secondaries download blobs via `GET /api/v4/geo/retrieve/:replicable_name/:replicable_id` authenticated with a `TransferRequest` JWT, and fetch repositories over Git HTTP (`fetch_as_mirror`) authenticated with a `RepoSyncRequest` JWT (`doc/development/geo/blob_replication.md`, `doc/development/geo/repository_sync.md`); DO NOT invent new transfer endpoints.
- Blob code paths must handle both local storage and object storage; object-storage replication depends on the site's `sync_object_storage` setting.
- Every replicable model must implement `selective_sync_scope(node, **params)`; the default raises `NotImplementedError`. Scope records owned by a project or group to the node's selective-sync settings. Return all records only for instance-wide data with no owning project, group, or organization, and add a comment explaining why.
- DO NOT filter registry finders or counters by selective sync. The framework enforces it through `replicables_for_current_secondary`: the registry consistency worker creates registries only for in-scope records and deletes the rest, and event consumers skip out-of-scope records with `in_replicables_for_current_secondary?`.

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

### EE Gating

- Geo application code (replicators, registries, workers, finders) is EE-only and lives under `ee/`; the exceptions are verification state table migrations (`db/migrate`, `db/docs`) and Workhorse proxy routes. Behavior must degrade cleanly when Geo is disabled or unlicensed.
