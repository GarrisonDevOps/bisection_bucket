---
stage: Developer Experience
group: Application Lifecycle
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: GitLab 19 upgrade notes
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab Self-Managed

{{< /details >}}

This page contains upgrade information for minor and patch versions of GitLab 19.
Ensure you review these instructions for:

- Your installation type.
- All versions between your current version and your target version.

If you also plan to upgrade GitLab Runner alongside GitLab, review the GitLab Runner [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/main/CHANGELOG.md) for changes that might affect your setup.

For additional information for Helm chart installations, see
[the Helm chart 10.0 upgrade notes](https://docs.gitlab.com/charts/releases/10_0/).

## Required upgrade stops

To provide a predictable upgrade schedule for instance administrators,
required upgrade stops occur at versions:

- `19.2`
- `19.5`
- `19.8`
- `19.11`

## Upgrade notes reference

The following is a reference list of upgrade notes for each minor GitLab version.
Each list item points to a specific section that holds more information.

Items marked with an installation method, like `(Geo)` or `(Linux package)`,
apply only to that method. All other items apply to all installation methods.

### Upgrade to 19.6

Before upgrading to GitLab 19.6, review the following:

- [19.6.0] - [Geo upload replication by upload type enabled by default](#geo-upload-replication-by-upload-type-enabled-by-default) (Geo)
- [19.6.0] - [OpenBao policy for GitLab Secrets Manager](#openbao-policy-for-gitlab-secrets-manager) (Linux package, Helm chart)
- [19.6.0] - [NGINX update might break custom NGINX configuration](#nginx-update-might-break-custom-nginx-configuration) (Linux package, Docker)
- [19.6.0] - [Geo secondary sites store the location of synced files](#geo-secondary-sites-store-the-location-of-synced-files) (Geo)
- [19.6.0] - [Service Ping internal API secret on multi-node installations](#service-ping-internal-api-secret-on-multi-node-installations) (Linux package)

Also review the [GitLab 19.6 release notes](../../releases/19/gitlab-19-6-released/index.md)
and the [deprecations and removals for GitLab 19.6](../deprecations.md#gitlab-196).

### Upgrade to 19.5

> [!note]
> Required upgrade stop. You must upgrade to this version before upgrading to later
> versions. See [required upgrade stops](../upgrade_paths.md#required-upgrade-stops).

Before upgrading to GitLab 19.5, review the following:

- [19.5.0] - [Agent for Kubernetes address defaults to native gRPC](#agent-for-kubernetes-address-defaults-to-native-grpc) (Linux package, Helm chart)
- [19.5.0] - [Duo Agent Platform checkpoint migration](#duo-agent-platform-checkpoint-migration)
- [19.5.0] - [Geo upload checksumming by upload type enabled by default](#geo-upload-checksumming-by-upload-type-enabled-by-default) (Geo)

Also review the [GitLab 19.5 release notes](../../releases/19/gitlab-19-5-released/index.md)
and the [deprecations and removals for GitLab 19.5](../deprecations.md#gitlab-195).

### Upgrade to 19.4

Before upgrading to GitLab 19.4, review the following:

- [19.4.0] - [Geo SSH proxying enabled by default](#geo-ssh-proxying-enabled-by-default)
- [19.4.0] - [Restores that use `SKIP_REPOSITORIES_PATHS` keep existing repositories](#restores-that-use-skip_repositories_paths-keep-existing-repositories)
- [19.4.0] - [Untrusted group SAML identities are restored to trusted](#untrusted-group-saml-identities-are-restored-to-trusted)
- [19.4.0 - 19.4.3] - [Audit event streaming jobs fill Redis for CI/CD job token requests](#audit-event-streaming-jobs-fill-redis-for-cicd-job-token-requests)

Also review the [GitLab 19.4 release notes](../../releases/19/gitlab-19-4-released/index.md).

### Upgrade to 19.3

Before upgrading to GitLab 19.3, review the following:

- [19.3.0 - 19.3.1] - [New groups require SHA parameter for merge requests API calls](#new-groups-require-sha-parameter-for-merge-requests-api-calls)
- [19.3.0] - [Geo verification concurrency limit applied as a global total](#geo-verification-concurrency-limit-applied-as-a-global-total)
- [19.3.0] - [Dry run mode no longer logs to `auth.log`](#dry-run-mode-no-longer-logs-to-authlog)
- [19.3.0] - [Requests from allowlisted users not marked with `throttle_user_allowlist`](#requests-from-allowlisted-users-not-marked-with-throttle_user_allowlist)
- [19.3.0 - 19.3.7] - [Audit event streaming jobs fill Redis for CI/CD job token requests](#audit-event-streaming-jobs-fill-redis-for-cicd-job-token-requests)

Also review the [GitLab 19.3 release notes](../../releases/19/gitlab-19-3-released/index.md)
and the [deprecations and removals for GitLab 19.3](../deprecations.md#gitlab-193).

### Upgrade to 19.2

> [!note]
> Required upgrade stop. You must upgrade to this version before upgrading to later
> versions. See [required upgrade stops](../upgrade_paths.md#required-upgrade-stops).

Before upgrading to GitLab 19.2, review the following:

- [19.2.0] - [GitLab Duo Self-Hosted AI Gateway URLs cleared after upgrade](#gitlab-duo-self-hosted-ai-gateway-urls-cleared-after-upgrade) (Linux package)
- [19.2.0 - 19.2.5] - [New groups require SHA parameter for merge requests API calls](#new-groups-require-sha-parameter-for-merge-requests-api-calls)

Also review the [GitLab 19.2 release notes](../../releases/19/gitlab-19-2-released/index.md)
and the [deprecations and removals for GitLab 19.2](../deprecations.md#gitlab-192).

### Upgrade to 19.0

Before upgrading to GitLab 19.0, review the following:

- [19.0.0 - 19.0.1] - [Container registry metadata database enabled by default in prefer mode](#container-registry-metadata-database-enabled-by-default-in-prefer-mode) (Linux package, self-compiled)
- [19.0.0] - [Container registry S3 storage driver replaced by s3_v2](#container-registry-s3-storage-driver-replaced-by-s3_v2) (Linux package, self-compiled)
- [19.0.0 - 19.1.0] - [Orphaned `.agents` and `.claude` directories on Linux package RPM installs](#orphaned-agents-and-claude-directories-on-linux-package-rpm-installs) (Linux package)
- [19.0.0] - [PostgreSQL 17 minimum requirement](#postgresql-17-minimum-requirement)
- [19.0.0] - [Webhook payload timestamps changed to ISO 8601 format](#webhook-payload-timestamps-changed-to-iso-8601-format)
- [19.0.0] - [Linux package support for Ubuntu 20.04 discontinued](#linux-package-support-for-ubuntu-2004-discontinued) (Linux package)
- [19.0.0] - [Redis 6 support removed](#redis-6-support-removed) (Linux package)
- [19.0.0] - [Mattermost removed from the Linux package](#mattermost-removed-from-the-linux-package) (Linux package)
- [19.0.0] - [Linux package support for SUSE distributions discontinued](#linux-package-support-for-suse-distributions-discontinued) (Linux package)
- [19.0.0] - [Spamcheck removed from Linux package and GitLab Helm chart](#spamcheck-removed-from-linux-package-and-gitlab-helm-chart) (Linux package, Helm chart)
- [19.0.0] - [NGINX Ingress replaced by Gateway API with Envoy Gateway](#nginx-ingress-replaced-by-gateway-api-with-envoy-gateway) (Helm chart)
- [19.0.0] - [Bundled PostgreSQL, Redis, and MinIO removed from GitLab Helm chart](#bundled-postgresql-redis-and-minio-removed-from-gitlab-helm-chart) (Helm chart)
- [19.0.0 - 19.0.1] - [Geo container repository sync silently skips OCI image index tags](#geo-container-repository-sync-silently-skips-oci-image-index-tags) (Geo)
- [16.0.0 - 19.0.1] - [Geo design management replication `NoMethodError` when project is `nil`](#geo-design-management-replication-nomethoderror-when-project-is-nil) (Geo)

Also review the [GitLab 19.0 release notes](../../releases/19/gitlab-19-0-released/index.md)
and the [deprecations and removals for GitLab 19.0](../deprecations.md#gitlab-190).

## Upgrade notes

Specific upgrade notes for GitLab 19.

### Geo upload replication by upload type enabled by default

{{< details >}}

- Tier: Premium, Ultimate

{{< /details >}}

- Affects: Geo
- Affected versions: 19.6.0

In GitLab 19.6, Geo replicates and verifies uploads through the upload data types added in GitLab 19.5,
for example project uploads and group uploads.
The `geo_upload_replication` and `geo_upload_force_primary_checksumming` feature flags of the legacy
uploads data type are disabled by default.
If you set either flag explicitly, the new default does not apply.
To use the default, remove the stored values in a Rails console on the primary site:

```ruby
Feature.remove(:geo_upload_replication)
Feature.remove(:geo_upload_force_primary_checksumming)
```

#### Before you upgrade

Wait until the primary site finishes the checksumming that started in GitLab 19.5.
To check the progress, run the following command in a
[Rails console](../../administration/operations/rails_console.md#starting-a-rails-console-session) on the primary site:

```ruby
lines = Gitlab::Geo::REPLICATOR_CLASSES.select { |r| r.model < ::Upload }.map do |r|
  name = r.replicable_name.delete_suffix('_upload')
  next format('%-45s disabled', name) unless r.replication_enabled?

  done = r.checksummed_count + r.checksum_failed_count
  total = r.primary_total_count
  format('%-45s %10d / %-10d %s', name, done, total, done == total ? 'done' : 'pending')
end

puts lines
```

Checksumming is done when every upload data type shows `done`.
If an upload data type shows `disabled`, its `geo_<name>_upload_replication` feature flag is off,
where `<name>` is the name in the output.
Geo does not replicate that data type after the upgrade.
To replicate it, turn on the feature flag before you upgrade, then run the command again.

If you upgrade before checksumming finishes, no data is lost.
Secondary sites verify the remaining uploads as the primary site checksums them.
Until then, verification alerts can fire.
Before a planned failover, wait until uploads are verified.

#### After you upgrade

On each secondary site, Geo starts tracking every upload in the new data types:

- Sidekiq runs one sync job for each upload, so expect a temporary increase in Sidekiq jobs
  proportional to the number of uploads.
- Uploads that the legacy data type already verified on the secondary site are not downloaded again.
  Geo downloads and checksums all other uploads.
- The first verification of each upload reuses the primary site's checksum.
  After that, each reverification reads the file on both sites,
  at the reverification interval of the primary site.

Other changes:

- The **Geo Sites** page shows one **Uploads** row for each site, which you can expand to show each
  upload data type.
  On secondary sites, progress starts at 0% and increases as the uploads sync.
- In the [Geo site status](../../api/geo_sites.md#retrieve-a-geo-site-status), the `gitlab:geo:status`
  Rake task, and [Prometheus](../../administration/monitoring/prometheus/gitlab_metrics.md#geo-metrics),
  the `uploads_*` fields and `geo_uploads_*` metrics report the sum of all upload data types, so
  existing dashboards and alerts keep working.
  The `<name>_uploads_*` fields and `geo_<name>_uploads_*` metrics report each upload data type.
- The **Uploads** replication details page of each site and the **Uploads** page in **Data management**
  list the upload data types, with a link to each one.
- In the GraphQL API, the [`uploadRegistries`](../../api/graphql/reference/objects.md#geonode)
  field returns the registries of all upload data types:
  - The `id` of each registry changes to the upload ID, the same value as `fileId`.
    Registry IDs saved before the upgrade no longer match the same uploads.
  - The experimental `geoRegistriesUpdate` and `geoRegistriesBulkUpdate` mutations return an
    error for `UPLOAD_REGISTRY`.
    Use the registry class of each upload data type instead, such as `PROJECT_UPLOAD_REGISTRY`.

To return to the legacy uploads data type,
[enable both feature flags](../../administration/feature_flags/_index.md#how-to-enable-and-disable-features-behind-flags):

```ruby
Feature.enable(:geo_upload_replication)
Feature.enable(:geo_upload_force_primary_checksumming)
```

Secondary sites then resume the legacy data type
and catch up on uploads created while the flags were disabled.

### OpenBao policy for GitLab Secrets Manager

{{< details >}}

- Tier: Premium, Ultimate

{{< /details >}}

- Affects: Linux package, Helm chart
- Affected versions: 19.6.0 and later

GitLab 19.6 includes a restricted `secrets_manager` OpenBao policy.
This policy controls what GitLab can do in OpenBao when GitLab provisions secrets managers.
The restricted policy grants access only to the paths that GitLab uses.
Upgrading GitLab does not change the policy on an existing OpenBao installation, because OpenBao
creates the policy only when OpenBao initializes for the first time.

After you upgrade, apply the restricted policy with the
`gitlab:secrets_management:openbao:secrets_manager_policy:update` Rake task.
For more information, see
[update the OpenBao policy for GitLab](../../administration/secrets_manager/maintenance.md#update-the-openbao-policy-for-gitlab).

### NGINX update might break custom NGINX configuration

- Affects: Linux package, Docker
- Affected versions: 19.6.0 and later

GitLab 19.6 updates the NGINX version bundled in the Linux package from 1.31.4 to 1.31.7.
The update fixes five security issues: CVE-2026-15176, CVE-2026-93479, CVE-2026-95101,
CVE-2026-97629, and CVE-2026-97205.

The NGINX configuration that the Linux package generates is not affected by these changes.
You are affected only if:

- You added your own NGINX configuration, for example with
  `nginx['custom_gitlab_server_config']` or `nginx['custom_nginx_config']`.
- You use hand-written NGINX configuration files.

The two changes that can break customized configuration:

- NGINX now rejects zero-size buffers.
  Setting any `*_buffer_size` directive to `0`, for example `proxy_buffer_size 0;`, is now a configuration error.
  NGINX 1.31.4 accepted it, but a zero-size buffer never worked.
  NGINX 1.31.7 rejects the configuration, and `nginx -t` reports an error.
  To fix this issue, you must remove the directive or set it to a positive size.
- NGINX now verifies certificates by IP address more strictly.
  When `proxy_ssl_verify` is `on` and `proxy_pass` or `proxy_ssl_name` uses an IP address,
  NGINX now matches the certificate only against IP subject alternative name (SAN) entries.
  Certificates that have the IP address only in the common name or in a DNS SAN passed before and now fail verification.
  NGINX returns a `502` error for these certificates.
  Certificates with an IP SAN now pass.
  The Linux package does not turn on `proxy_ssl_verify`.
  To fix this issue, you must add the IP address as an IP SAN in the backend certificate,
  or use a hostname in `proxy_ssl_name` that matches the certificate.

Before you upgrade:

1. Check whether your instance uses either setting. For example, search the rendered NGINX
   configuration:

   ```shell
   sudo grep -rnE '_buffer_size[[:space:]]+0[[:space:]]*;|proxy_ssl_verify[[:space:]]+on' /var/opt/gitlab/nginx/conf/
   ```

1. Check any additional NGINX configuration files that you include with `custom_nginx_config`.
1. If you locate configuration impacted by the upgrade, make the required changes to the
   configuration.

After you upgrade:

1. Run `sudo gitlab-ctl reconfigure`.
1. Confirm that NGINX is running by running `sudo gitlab-ctl status nginx`.

This change does not affect the GitLab Helm chart, because the Helm chart does not use the NGINX bundled in the Linux package.

### Geo secondary sites store the location of synced files

{{< details >}}

- Tier: Premium, Ultimate

{{< /details >}}

- Affects: Geo
- Affected versions: 19.6.0

In GitLab 19.6 and later, Geo secondary sites store the location of each file they sync.
After the upgrade, background jobs on each secondary site store the location of files that were synced earlier.
The jobs process each data type once, then stop.

The jobs read the GitLab database and write to the Geo tracking database, but do not read or transfer files.
They run in addition to file sync jobs, up to half the {{< ui text="Geo|File synchronization concurrency limit" >}} at a time.
If database load on a secondary site is too high while the jobs run, you can lower that limit.
For more information, see [tuning Geo](../../administration/geo/replication/tuning.md#changing-the-syncverification-concurrency-values).

### Service Ping internal API secret on multi-node installations

- Affects: Linux package
- Affected versions: 19.6.0 and later

In GitLab 19.6, `gitlab-ctl reconfigure` generates a shared secret for the Service Ping internal API
when `gitlab_rails['service_ping_secret']` is not set in `/etc/gitlab/gitlab.rb`.
The secret is stored in `/etc/gitlab/gitlab-secrets.json` and written to
`/var/opt/gitlab/gitlab-rails/etc/gitlab_service_ping_secret`.
Services that report Service Ping on behalf of the instance, such as the Service Ping exporter,
authenticate with this secret.

On a multi-node installation, each node that runs Puma or Sidekiq generates its own secret
the first time you reconfigure the node on 19.6.
The secret must be the same on every node, otherwise requests to the
Service Ping internal API fail with `401 Unauthorized`
when the node that receives the request has a different secret.
No stored data depends on this secret, so a mismatch does not affect existing data.

Helm chart installations are not affected, because the chart generates one Kubernetes Secret that
all pods share.

To give every node the same secret, set the secret before you upgrade, or repair the secret after the upgrade.
Reconfigure restarts Puma and Sidekiq when the secret file changes, so no separate restart is needed.
To rotate the secret later, see
[Set or rotate the Service Ping internal API secret](../../administration/settings/usage_statistics.md#set-or-rotate-the-service-ping-internal-api-secret).

#### Set the secret before you upgrade

Before you upgrade, on every node that runs Puma or Sidekiq:

1. Edit `/etc/gitlab/gitlab.rb` and set the same value on every node.
   The value must be a Base64-encoded 32-byte string.
   For example, use the output of `openssl rand -base64 32`:

   ```ruby
   gitlab_rails['service_ping_secret'] = '<base64-encoded 32-byte value>'
   ```

1. Upgrade the nodes as usual.

#### Repair the secret after the upgrade

If you already upgraded every node and the secrets differ:

1. Select one node that runs Puma or Sidekiq as the reference node.
1. On every other node that runs Puma or Sidekiq, back up the existing configuration:

   ```shell
   sudo gitlab-ctl backup-etc
   ```

1. Copy `/etc/gitlab/gitlab-secrets.json` from the reference node to every other node, and replace the
   file of the same name.
1. Reconfigure every node that received the file:

   ```shell
   sudo gitlab-ctl reconfigure
   ```

### Agent for Kubernetes address defaults to native gRPC

- Affects: Linux package, Helm chart
- Affected versions: 19.5.0 and later

In GitLab 19.5, the Linux package and the GitLab Helm chart advertise a native gRPC address
to the agent for Kubernetes by default, instead of a WebSocket address. The address is shown
in the agent installation instructions and stored in `gitlab_kas.external_url`.

- Linux package: `grpcs://gitlab.example.com` instead of `wss://gitlab.example.com/-/kubernetes-agent/`,
  when `external_url` uses HTTPS without a relative URL root and the bundled NGINX terminates TLS with HTTP/2.
- Helm chart: `grpcs://kas.example.com` instead of `wss://kas.example.com`, with Gateway API or
  with the NGINX Ingress provider.

In other configurations, the WebSocket address is kept. Agents that are already connected over
WebSocket are not affected, because GitLab Relay (KAS) serves both protocols on the same port.
Agents installed after the upgrade connect over gRPC, which needs HTTP/2 end to end. If a proxy
between your clusters and GitLab does not pass HTTP/2, new agents fail to connect and the error
looks like a network problem. For example, a WAF or a TLS-inspecting proxy might connect to GitLab
over HTTP/1.1. In that case, keep advertising WebSocket by setting the address explicitly:

- Linux package: `gitlab_rails['gitlab_kas_external_url']` in `/etc/gitlab/gitlab.rb`.
- Helm chart: `global.appConfig.gitlab_kas.externalUrl`.

For more information, see [GitLab Relay (KAS)](../../administration/clusters/kas.md) and the
[KAS chart documentation](https://docs.gitlab.com/charts/charts/gitlab/kas/#agent-connection-protocol).

### Duo Agent Platform checkpoint migration

{{< details >}}

- Tier: Premium, Ultimate

{{< /details >}}

- Affects: All installation methods
- Affected versions: 19.5.0

GitLab 19.5 queues a batched background migration named `BackfillDuoWorkflowsCheckpointHeadersAndBlobs`.
It copies GitLab Duo Agent Platform session checkpoints from the table
`p_duo_workflows_checkpoints` into the tables `p_duo_workflows_checkpoint_headers` and
`p_duo_workflows_checkpoint_blobs`. This is the storage format the application now writes and reads.

The migration runs in the background after the upgrade. It only processes rows that are not
already stored in the new format, and it skips sessions older than 30 days because their data
is past the retention period.

Sessions created before the upgrade remain readable while the migration runs. A later GitLab
version removes the code that reads the old table, so this migration must finish before that
upgrade. Before you upgrade past 19.5, check the migration status on the **Admin area** >
**Background migrations** page (`/admin/background_migrations`). For more information on how
to check the status and how to finish the migration manually, see
[background migrations](../background_migrations.md).

The time the migration takes depends on how many sessions the instance stored in the last 30
days. Each processed checkpoint can be several megabytes.

The migration copies data and does not delete rows from `p_duo_workflows_checkpoints`, so
PostgreSQL disk usage increases while the migration runs. The space used by the old table is
freed only when its daily partitions pass the 30-day retention period and are dropped.
On instances with many sessions, disk usage can increase by several gigabytes an hour.

Before you upgrade to GitLab 19.5:

1. Check the size of the old table. In a PostgreSQL console, for example `sudo gitlab-psql`
   on Linux package installations, run:

   ```sql
   SELECT pg_size_pretty(sum(pg_total_relation_size(relid)))
   FROM pg_partition_tree('p_duo_workflows_checkpoints')
   WHERE isleaf;
   ```

1. Ensure the PostgreSQL data volume has at least this much free space, plus room for the
   write-ahead log (WAL) that the migration generates. If you use database replicas or
   WAL archiving, check the free space on those volumes as well.

If disk space runs low while the migration runs, [pause the migration](../background_migrations.md#pause-a-migration),
add disk space, then resume the migration. You can also pause and resume the migration with the
[batched background migrations API](../../api/admin/batched_background_migrations.md).
You can pause only migrations with an `active` status.

### Geo upload checksumming by upload type enabled by default

{{< details >}}

- Tier: Premium, Ultimate

{{< /details >}}

- Affects: Geo
- Affected versions: 19.5.0

In GitLab 19.5, Geo adds 23 new data types for uploads, one for each kind of upload, for example project uploads and group uploads.
Only the primary site uses the new data types, and it checksums the uploads for each one in the background. The secondary sites
keep replicating and verifying uploads through the existing uploads data type.

On the primary, most uploads reuse the checksum from the existing uploads data type, so GitLab reads only the files that
do not have a successful checksum yet.
Checksumming shares the **Verification concurrency limit** of the primary site with all other data types.
On sites with millions of uploads, checksumming can take several days at a limit of `1`, which many sites upgraded from earlier versions use.
You can raise the limit while checksumming runs, monitor database load, and restore the previous value afterward.
In GitLab testing, raising the limit from `1` to `10` made upload checksumming about eight times faster, with little extra database load.
For more information, see [tuning Geo](../../administration/geo/replication/tuning.md#changing-the-syncverification-concurrency-values).

To stop checksumming for one data type, you must
[disable both of its feature flags](../../administration/feature_flags/_index.md#how-to-enable-and-disable-features-behind-flags):
`geo_<name>_upload_replication` and `geo_<name>_upload_force_primary_checksumming`, where `<name>` is, for example, `project` or `group`.
Disabling only the `_replication` flag does not stop checksumming.

### Geo SSH proxying enabled by default

{{< details >}}

- Tier: Premium, Ultimate

{{< /details >}}

- Affects: Helm charts
- Affected versions: 19.4.0

In GitLab 19.4 and later, the following feature flags are enabled by default:

- `geo_proxy_fetch_ssh_to_primary`
- `geo_proxy_push_ssh_to_primary`

Because of this change, Cloud Native GitLab deployments using the bundled NGINX Ingress must either:

- upgrade to use the [Gateway API with Envoy Gateway](#nginx-ingress-replaced-by-gateway-api-with-envoy-gateway) before this rollout, or
- disable both feature flags after the rollout.

Otherwise, SSH fetches and pushes through Geo secondaries may hang or time out.

See the [Geo troubleshooting documentation](../../administration/geo/replication/troubleshooting/ssh_proxying.md) for SSH proxying for more information.

### Restores that use `SKIP_REPOSITORIES_PATHS` keep existing repositories

- Affects: All installation methods
- Affected versions: 19.4.0

In GitLab 19.4 and later, a restore keeps the repositories that are already on the instance when
`SKIP_REPOSITORIES_PATHS` excludes repositories from that restore. This applies both when you
specify the option for the restore and when the backup was created with it, including backups
created on earlier versions, because the restore also reads the excluded paths from the backup
manifest (`backup_information.yml`).

Previously, in both cases, and unless `REPOSITORIES_PATHS` was also specified, the restore first
removed all repositories in the storages it restored to. The excluded repositories were removed with
them, and because they were also left out of the restore itself, that backup could not bring them
back.

A full restore, where neither `REPOSITORIES_PATHS` nor `SKIP_REPOSITORIES_PATHS` applies, still
removes repositories that are not part of the backup.

If your restore process relies on the previous behavior to clear repositories, run a full restore
instead, or remove those repositories before the restore.

For more information, see
[restore specific repositories](../../administration/backup_restore/restore_gitlab.md#restore-specific-repositories)
and [issue 610910](https://gitlab.com/gitlab-org/gitlab/-/issues/610910).

### Untrusted group SAML identities are restored to trusted

- Affects: All installation methods
- Affected versions: 19.4.0

In GitLab 18.10, 18.11, 19.0, 19.1, 19.2, and 19.3, updating the `extern_uid` of a group SAML identity with the
[SAML identities API](../../api/saml.md) marked that identity as untrusted, and the affected user
could not sign in with SAML single sign-on until they linked their identity again.

GitLab 19.4 reverts this behavior. A group Owner controls the group identity provider, so a group
Owner can already assert any `NameID` through the identity provider. A post-deployment migration
sets `trusted_extern_uid` back to `true` for every group SAML identity, so affected users can sign
in with SAML single sign-on again.

For more information, see [issue 608236](https://gitlab.com/gitlab-org/gitlab/-/issues/608236).

### Audit event streaming jobs fill Redis for CI/CD job token requests

{{< details >}}

- Tier: Ultimate

{{< /details >}}

- Affects: All installation methods
- Affected versions:

  | Release | Affected patch releases | Fixed patch level |
  | ------- | ----------------------- | ----------------- |
  | 19.3    | 19.3.0 - 19.3.7         | 19.3.8            |
  | 19.4    | 19.4.0 - 19.4.3         | 19.4.5            |

GitLab 19.3 turns on a new rate limiter by default.
For each request that authenticates with a [CI/CD job token](../../ci/jobs/ci_job_token.md),
the rate limiter identifies the user before the endpoint does.
Each identification creates a `user_authenticated_using_job_token` audit event,
so GitLab streams this event more than once for each request.
If an administrator turned on the authenticated or unauthenticated [API rate limits](../../administration/settings/user_and_ip_rate_limits.md),
the `Rack::Attack` rate limiter also creates these events, also in versions before 19.3.

An instance is affected if an active [streaming destination](../../administration/compliance/audit_event_streaming.md)
of the instance or of a top-level group streams the `user_authenticated_using_job_token` event type.
A destination with no event type filter streams all event types.
On an affected instance, every running CI/CD job adds many `AuditEvents::AuditEventStreamingWorker`
jobs to Sidekiq, because the runner uses the job token to send the job log.
If the jobs are queued faster than Sidekiq processes them, Redis memory grows until Redis is full,
and GitLab stops working.

To fix this issue, upgrade to GitLab 19.3.8 or later, or GitLab 19.4.5 or later.

If you cannot upgrade, do one of the following on every active streaming destination:

- Set an event type filter that lists the event types you need, without
  `user_authenticated_using_job_token`.
  For more information, see
  [update event filters for an instance](../../administration/compliance/audit_event_streaming.md#update-event-filters)
  or [for a top-level group](../../user/compliance/audit_event_streaming.md#update-event-filters).
- Deactivate the streaming destination for an
  [instance](../../administration/compliance/audit_event_streaming.md#deactivate-a-streaming-destination)
  or for a [top-level group](../../user/compliance/audit_event_streaming.md#deactivate-a-streaming-destination).

An event type filter is an allowlist.
A filter that contains only `user_authenticated_using_job_token` streams only that event type,
and does not fix this issue.
A denylist entry on a group destination also does not fix this issue,
because GitLab queues the streaming job before it checks the denylist.

For more information, see [issue 631338](https://gitlab.com/gitlab-org/gitlab/-/work_items/631338).

### GitLab Duo Self-Hosted AI Gateway URLs cleared after upgrade

- Affects: Linux package
- Affected versions: 19.2.0
- Fixed versions: 19.2.1

When upgrading an instance directly to GitLab 19.2.0,
the GitLab Duo Self-Hosted service endpoint settings can be cleared.
The following fields under **Admin area** > **GitLab Duo** > **Configuration** > **Service endpoints** may
become empty after the upgrade:

- **Local AI Gateway URL**
- **Local URL for the GitLab Duo Agent Platform service**

Other related settings may also revert to their defaults.
GitLab Duo Self-Hosted features stop working until the URLs are manually re-entered.

This issue does not occur when upgrading to GitLab 19.2.1 or later.

If you have already upgraded to 19.2.0 and are affected, restore the correct
AI Gateway endpoint URLs in **Admin area** > **GitLab Duo** > **Configuration** > **Service endpoints**
and save the changes.
For more information, see [issue 606458](https://gitlab.com/gitlab-org/gitlab/-/work_items/606458).

### New groups require SHA parameter for merge requests API calls

- Affects: All installation methods
- Affected versions:

  | Release | Affected patch releases | Fixed patch level |
  | ------- | ----------------------- | ----------------- |
  | 19.2    | 19.2.0 - 19.2.5         | 19.2.6            |
  | 19.3    | 19.3.0 - 19.3.1         | 19.3.2            |

GitLab 19.2 introduces the `require_sha_for_merge` setting at the group and instance level.
When enabled, the [merge a merge request](../../api/merge_requests.md#merge-a-merge-request)
API endpoint rejects calls that do not include a valid commit `sha` parameter.

Groups created after upgrading to GitLab 19.2 and 19.3 have `require_sha_for_merge` enabled by
default, unless the setting is locked by the instance or an ancestor group using `lock_require_sha_for_merge`. If the setting is locked, the new group inherits the
locked value instead. Existing groups are not affected.

After you update to 19.2 or 19.3, if your automation or API clients call the merge endpoint without a `sha` parameter, those
clients will fail for all new groups unless you disable the requirement and lock the setting.

To disable this
requirement for all new groups, set `require_sha_for_merge` to `false` and enable
`lock_require_sha_for_merge`
through the [application settings API](../../api/settings.md#available-settings).

This setting was changed to disabled by default in GitLab 19.2.6 and GitLab 19.3.2.

### Container registry metadata database enabled by default in prefer mode

- Affects: Linux package, self-compiled
- Affected versions: 19.0.0, 19.0.1

In GitLab 19.0, the container registry metadata database defaults to `prefer` mode for
existing installations that do not have `registry['database']['enabled']` explicitly set
in `/etc/gitlab/gitlab.rb`. In prefer mode, the registry attempts to use the metadata
database. If the existing registry data has not been imported into the database, the
registry falls back to legacy filesystem metadata at startup.

Due to a bug ([issue 600955](https://gitlab.com/gitlab-org/gitlab/-/work_items/600955)),
the registry router was initialized before the prefer-fallback detection ran. This caused
nil pointer dereference panics on all `/gitlab/v1/` routes, resulting in `HTTP 500` errors
when the registry UI polls for group-level storage size. The actual Docker push and pull
protocol (`/v2/`) is not affected by this bug.

The bug is fixed in GitLab 19.0.2, which includes container registry `v4.40.1-gitlab`.

If you are running 19.0.0 or 19.0.1 and see repeated
`runtime error: invalid memory address or nil pointer dereference` panics in
`/var/log/gitlab/registry/current` at `handlers.(*repositoryHandler).HandleGetRepository`,
apply the following workaround:

1. Add the following to `/etc/gitlab/gitlab.rb`:

   ```ruby
   registry['database'] = {
     'enabled' => false
   }
   ```

1. Reconfigure and restart the registry:

   ```shell
   sudo gitlab-ctl reconfigure
   sudo gitlab-ctl restart registry
   ```

After upgrading to 19.0.2 or later, remove the override and reconfigure again to restore
default behavior.

For more information, see
[the container registry metadata database documentation](../../administration/packages/container_registry_metadata_database.md).

### Container registry S3 storage driver replaced by s3_v2

- Affects: Linux package, self-compiled
- Affected versions:

  | Change                                                                  | Release        | Affected patch releases | Fixed patch level        |
  | ----------------------------------------------------------------------- | -------------- | ----------------------- | ------------------------ |
  | `s3` driver replaced by `s3_v2`                                         | 19.0 and later | All patch releases      | N/A (intentional change) |
  | `checksum_disabled` does not remove the `DeleteObjects` checksum header | 19.0 - 19.1    | All patch releases      | 19.2.0                   |

In GitLab 19.0, the legacy `s3` container registry storage driver (AWS SDK v1) is removed.
The `s3` and `s3aws` driver names are now aliases for the `s3_v2` driver (AWS SDK v2).
Because the previous driver names continue to work, instances that were never reconfigured
also move to AWS SDK v2 when they upgrade.

This change affects two groups of installations:

- Installations that use S3-compatible object storage backends such as Ceph RGW, MinIO, or OVH S3.
- Installations that use AWS S3 and restrict outbound network traffic.
  For more information, see [presigned URL hostnames on AWS S3](#presigned-url-hostnames-on-aws-s3).

The `s3_v2` driver introduces two breaking changes for non-AWS S3-compatible backends:

- `regionendpoint` requires a full URI including scheme. The `s3_v2` driver requires
  `https://` (or `http://`) in the `regionendpoint` value. A bare hostname such as
  `storage.example.com` is no longer valid and causes a startup error:

  ```plaintext
  endpoint rule error, Custom endpoint `storage.example.com` was not a valid URI
  ```

  Update your configuration to include the scheme:

  ```ruby
  registry['storage'] = {
    's3_v2' => {
      'regionendpoint' => 'https://storage.example.com',
      # ...
    }
  }
  ```

- AWS SDK v2 sends enhanced checksums by default. The `s3_v2` driver sends
  `x-amz-content-sha256` and CRC64NVME checksums on uploads. Ceph RGW, older MinIO
  versions, OVH S3, and other S3-compatible backends may reject these with HTTP 400
  (`XAmzContentSHA256Mismatch`). Add `'checksum_disabled' => true` to disable this behavior.

  In GitLab 19.0 and 19.1, `checksum_disabled` does not remove the checksum header from `DeleteObjects` calls.
  On those versions, the registry sends a CRC32 checksum header on `DeleteObjects` calls
  even when `checksum_disabled` is `true`, and no `gitlab.rb` setting changes this.
  If your backend rejects this header, image pushes that trigger blob deletions fail
  with a `MissingContentMD5` or `InvalidRequest` error.

  GitLab 19.2.0 fixes this issue with container registry `v4.40.2-gitlab`.
  When `checksum_disabled` is `true`, the registry sends a `Content-MD5` header
  instead of a checksum header on `DeleteObjects` calls.

  To resolve this issue, set `checksum_disabled` to `true` and upgrade to GitLab 19.2.0 or later.
  On self-compiled installations, also upgrade the registry to `v4.40.2-gitlab` or later.
  If you cannot upgrade, upgrade your S3-compatible storage backend to a version that supports
  CRC32 checksum headers.
  For the minimum version, see your storage provider's documentation.
  For more information, see
  [issue 2309](https://gitlab.com/gitlab-org/container-registry/-/issues/2309).

For Ceph RGW and most S3-compatible backends, update your configuration as follows:

```ruby
registry['storage'] = {
  's3_v2' => {
    'accesskey' => '<your-access-key>',
    'secretkey' => '<your-secret-key>',
    'bucket' => '<your-bucket>',
    'region' => '<your-region>',
    'regionendpoint' => 'https://<your-s3-endpoint>',
    'pathstyle' => true,
    'checksum_disabled' => true
  }
}
```

For more information, see
[the container registry object storage documentation](../../administration/packages/container_registry.md#use-object-storage)
and the [deprecation notice](../deprecations.md#s3-storage-driver-aws-sdk-v1-for-the-container-registry).

#### Presigned URL hostnames on AWS S3

When the registry serves a blob, it redirects the client to a presigned S3 URL.
AWS SDK v2 resolves the S3 endpoint for the region in your registry configuration,
so these presigned URLs can use a regional hostname such as `s3.us-east-1.amazonaws.com`
instead of the global `s3.amazonaws.com` hostname that AWS SDK v1 could return.

The registry itself continues to work, but clients must be able to reach the new hostname.
In environments that filter outbound traffic with a proxy, firewall, or secure web gateway,
an allowlist that contains only `s3.amazonaws.com` blocks the redirect target.
Image pulls then fail with `403 Forbidden` responses returned by the filtering device rather than by S3.

Before you upgrade, add the regional hostname for your bucket region to the allowlist on any device
that filters outbound traffic from your container image clients.
Use the specific regional hostname for your region, such as `s3.eu-west-2.amazonaws.com`,
rather than a wildcard that covers all of Amazon S3.

If your instance uses an S3 VPC endpoint or another fixed endpoint, set `regionendpoint` to that
endpoint so that presigned URLs use a hostname you control.
For more information, see [use object storage](../../administration/packages/container_registry.md#use-object-storage).

To validate blob pulls after you upgrade:

1. Pull an image that is larger than a few megabytes, so that the pull is served by a blob redirect
   rather than from a cache:

   ```shell
   docker pull gitlab.example.com:5050/mygroup/myproject/myimage:latest
   ```

1. If the pull fails, request a blob directly to see the redirect target:

   ```shell
   curl --head "https://gitlab.example.com:5050/v2/mygroup/myproject/myimage/blobs/<digest>"
   ```

   Check the `location` response header for the hostname the client is redirected to,
   then confirm that hostname is allowed by your egress controls.

### Geo design management replication `NoMethodError` when project is `nil`

- Affects: Geo
- Affected versions: 16.0.0 - 19.0.1

On Geo secondary sites, a `NoMethodError` could occur during replication of
design management repositories when the associated project had been deleted,
leaving an orphaned `DesignManagement::Repository` record. GitLab 19.0.2 corrects
this issue.

For more information, see [issue 597049](https://gitlab.com/gitlab-org/gitlab/-/issues/597049).

### PostgreSQL 17 minimum requirement

- Affects: All installation methods
- Affected versions: 19.0.0

The minimum supported version of PostgreSQL is now version 17. Before installing GitLab 19.0:

- If you use the packaged PostgreSQL 16,
  [upgrade the packaged PostgreSQL server](https://docs.gitlab.com/omnibus/settings/database.html#upgrade-packaged-postgresql-server).
- If you use an [external PostgreSQL](../../administration/postgresql/external.md) instance,
  upgrade it to PostgreSQL 17.

For more information, see the [deprecation notice](../deprecations.md#support-for-postgresql-16).

### Webhook payload timestamps changed to ISO 8601 format

- Affects: All installation methods
- Affected versions: 19.0.0

Before GitLab 19.0, timestamp values in webhook payloads (for example `object_attributes.created_at`)
used the format `YYYY-MM-DD HH:MM:SS` followed by a time zone. For example, `2026-04-23 12:30:45 UTC`.
In GitLab 19.0 and later, these timestamps use ISO 8601 format with millisecond precision and a time zone
designator. For example, `2026-04-23T12:30:45.123Z`.

This change applies to all timestamps for project webhooks, group webhooks, and
custom webhook templates, with one exception. Pipeline events keep the previous format
for the `created_at`, `started_at`, and `finished_at` fields inside `builds[]` and `bridges[]`.

If your webhook receiver parses these timestamp fields, update it to accept ISO 8601 with
millisecond precision.
For the format of each field, see
[webhook events](../../user/project/integrations/webhook_events.md).

This change was introduced in
[merge request 233400](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/233400).
It is tracked in
[issue 622832](https://gitlab.com/gitlab-org/gitlab/-/work_items/622832).

### Geo container repository sync silently skips OCI image index tags

{{< details >}}

- Tier: Premium, Ultimate

{{< /details >}}

- Affects: Geo (container registry)
- Affected versions:

  | Release | Affected patch releases | Fixed patch level |
  | ------- | ----------------------- | ----------------- |
  | 19.0    | 19.0.0 - 19.0.1         | 19.0.2            |

On Geo secondary sites, container repository sync silently skipped tags whose
manifest is an OCI image index (`application/vnd.oci.image.index.v1+json`).
Multi-arch images and BuildKit cache tags commonly use this manifest type. No
error was raised and tag counts matched, but `docker pull` of an affected tag
from the secondary returned `manifest unknown`. The same root cause also left
orphan tags on the secondary that sync could not remove.

After you upgrade both the primary and secondary sites to a fixed version, newly
synced tags are correct. Previously affected repositories converge on their next
verification cycle, which can take up to the re-verification interval (90 days by
default). To repair affected repositories immediately,
[resync the container repositories on the secondary site](../../administration/geo/replication/container_registry.md#manually-trigger-a-container-registry-sync-event).

For more information, see [issue 600486](https://gitlab.com/gitlab-org/gitlab/-/work_items/600486).

### Geo verification concurrency limit applied as a global total

{{< details >}}

- Tier: Premium, Ultimate

{{< /details >}}

- Affects: Geo
- Affected versions: 19.3.0

The **Verification concurrency limit** Geo site setting is now applied as a single global
limit on the number of verification jobs that run concurrently on a site, across all data
types combined. Previously, the configured value was divided by the number of data types
before being applied, so the effective concurrency was lower and changed as data types were
added or consolidated.

To preserve the effective concurrency in use and avoid a spike in verification load, GitLab
19.3 automatically rescales each site's stored **Verification concurrency limit** to
`max(1, floor(previous_value / number_of_data_types))`. As a result, the value shown in the
Admin UI and returned by the API decreases. Review and re-tune the setting after upgrading.
If you manage this setting through the API or infrastructure-as-code, update your stored
value to match.

For more information, see [issue 596579](https://gitlab.com/gitlab-org/gitlab/-/work_items/596579).

### Dry run mode no longer logs to `auth.log`

- Affects: All installation methods
- Affected versions: 19.3.0 and later

In GitLab 19.3 and later, the LabKit rate limiter enforces [user and IP rate limits](../../administration/settings/user_and_ip_rate_limits.md)
instead of the `Rack::Attack` rate limiter. In [dry run mode](../../administration/settings/user_and_ip_rate_limits.md#try-out-throttling-settings-before-enforcing-them),
GitLab no longer writes a message with `env` set to `track` to `auth.log` or `auth_json.log`
when a request would hit a limit.

- In GitLab 19.3 and 19.4, only Prometheus metrics count these requests, without the user or IP address:
  `gitlab_labkit_rate_limiter_calls_total` with `action="log"` in GitLab 19.3,
  and `gitlab_labkit_rate_limiter_rule_evaluations_total` with `result="log"` in GitLab 19.4.
- In GitLab 19.5 and later, check the `rate_limit_state` field in the per-request structured logs.

For more information, see [issue 635754](https://gitlab.com/gitlab-org/gitlab/-/work_items/635754).

### Requests from allowlisted users not marked with `throttle_user_allowlist`

- Affects: All installation methods
- Affected versions: 19.3.0 and later

In GitLab 19.3 and later, requests from users in the [user allowlist](../../administration/settings/user_and_ip_rate_limits.md#allow-specific-users-to-bypass-authenticated-request-rate-limiting)
still bypass the rate limiter. However, `production_json.log` and `api_json.log` mark these requests with
`"throttle_safelist":"labkit_fully_enforced"`, the value most other requests also carry,
instead of `"throttle_safelist":"throttle_user_allowlist"`.

In GitLab 19.5 and later, the `rate_limit_state` field records these requests with a `skip` result
for the `user_allowlist` rule, for example `rack_request:user_allowlist:skip`.

For more information, see [issue 635759](https://gitlab.com/gitlab-org/gitlab/-/work_items/635759).

### Linux package support for Ubuntu 20.04 discontinued

- Affects: Linux package
- Affected versions: 19.0.0

Ubuntu 20.04 reached end of standard support in May 2025. From GitLab 19.0, Linux packages are no
longer provided for Ubuntu 20.04. GitLab 18.11 is the last release with packages for this
distribution. Before upgrading to GitLab 19.0, migrate to Ubuntu 22.04 or another
[supported operating system](../../install/package/_index.md#supported-platforms).

For more information, see the [deprecation notice](../deprecations.md#linux-package-support-for-ubuntu-2004).

### Redis 6 support removed

- Affects: Linux package
- Affected versions: 19.0.0

Support for Redis 6 is removed in GitLab 19.0. If you use an external Redis 6 deployment, migrate
to Redis 7.0 or higher, or Valkey 7.2, before upgrading. Redis 7.2 or Valkey 7.2 is recommended.
Redis 7.0 has reached end-of-life (EOL) upstream, but in some cases is actively maintained by
vendors, such as Amazon ElastiCache for Redis 7.1. The bundled Redis included with the Linux
package has used Redis 7 since GitLab 16.2 and is not affected.

For more information, see the [deprecation notice](../deprecations.md#support-for-redis-6).

### Mattermost removed from the Linux package

- Affects: Linux package
- Affected versions: 19.0.0

Bundled Mattermost is removed from the Linux package in GitLab 19.0. If you currently use the
bundled Mattermost, see
[Migrating from the Linux package to Mattermost Standalone](https://docs.mattermost.com/administration-guide/onboard/migrate-gitlab-omnibus.html)
for migration instructions. If you do not use the bundled Mattermost, you are not impacted.

Before upgrading to GitLab 19.0, remove or comment out all `mattermost[...]` settings from `/etc/gitlab/gitlab.rb`.
If any `mattermost[...]` keys remain, `gitlab-ctl reconfigure` aborts immediately after the package
is installed with:

```plaintext
RuntimeError: Removed configurations found in gitlab.rb. Aborting reconfigure.
```

> [!warning]
> The behavior when upgrading from certain 18.11.x versions differs:
>
> - 18.11.0 through 18.11.6: The upgrade does not detect stale Mattermost configuration,
>   so the upgrade proceeds without warning even if cleanup is incomplete.
>   Do not rely on `gitlab-ctl check-config --version 19.0.x` to validate
>   Mattermost key removal before upgrading ([issue 9916](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/9916)).
> - 18.11.7: The upgrade is blocked, even when all `mattermost[...]` keys have been
>   removed from `gitlab.rb`. The block is a false positive caused by stale Mattermost secrets
>   that GitLab generated unconditionally in the node cache.
>   To unblock the upgrade, use one of the following options:
>   - Upgrade to 18.11.9 or later before upgrading to 19.0.
>   - Apply the [manual workaround](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/10001#workaround).

For more information, see the [deprecation notice](../deprecations.md#mattermost-bundled-with-linux-package).

### Linux package support for SUSE distributions discontinued

- Affects: Linux package
- Affected versions: 19.0.0

Linux package support for SUSE distributions ends in GitLab 19.0, which affects openSUSE Leap 15.6,
SUSE Linux Enterprise Server 12.5, and SUSE Linux Enterprise Server 15.6. GitLab 18.11 is the last
version with Linux packages for these distributions. To continue to use SUSE distributions, migrate
to a [Docker deployment of GitLab](../../install/docker/installation.md).

For more information, see the [deprecation notice](../deprecations.md#linux-package-support-for-suse-distributions).

### Spamcheck removed from Linux package and GitLab Helm chart

- Affects: Linux package, Helm chart
- Affected versions: 19.0.0

[Spamcheck](../../administration/reporting/spamcheck.md) is removed from the Linux package and
GitLab Helm chart in GitLab 19.0. Customers not currently using Spamcheck are not impacted. If you
use the bundled Spamcheck, you can deploy it separately using
[Docker](https://gitlab.com/gitlab-org/gl-security/security-engineering/security-automation/spam/spamcheck).
No data migration is required.

For more information, see the [deprecation notice](../deprecations.md#spamcheck-support-in-the-linux-package-and-gitlab-helm-chart).

### NGINX Ingress replaced by Gateway API with Envoy Gateway

- Affects: Helm chart
- Affected versions: 19.0.0

Gateway API with Envoy Gateway becomes the default networking configuration in the GitLab Helm chart
in GitLab 19.0, replacing NGINX Ingress which reached end-of-life in March 2026. If migration to
Envoy Gateway is not immediately feasible, you can explicitly re-enable the bundled NGINX Ingress,
which remains available until its proposed removal in GitLab 20.0. This change does not impact the
NGINX used in the Linux package, or Helm chart instances using an externally managed Ingress or
Gateway API controller.

For detailed migration steps, see the
[Helm chart 10.0 upgrade notes](https://docs.gitlab.com/charts/releases/10_0/).

For more information, see the [deprecation notice](../deprecations.md#support-for-nginx-ingress).

### Bundled PostgreSQL, Redis, and MinIO removed from GitLab Helm chart

- Affects: Helm chart
- Affected versions: 19.0.0

The bundled Bitnami PostgreSQL, Bitnami Redis, and MinIO charts are removed from the GitLab Helm
chart and GitLab Operator in GitLab 19.0 with no replacement. These components were intended only
for proof-of-concept and test environments and are not recommended for production use. If you run an
instance with any of these bundled services, follow the
[migration guide](https://docs.gitlab.com/charts/installation/migration/bundled_chart_migration/)
to configure external services before upgrading to GitLab 19.0.

For more information, see the [deprecation notice](../deprecations.md#support-for-bundled-postgresql-redis-and-minio-in-gitlab-helm-chart).

### Orphaned `.agents` and `.claude` directories on Linux package RPM installs

- Affects: Linux package (RPM)
- Affected versions:

  | Release | Affected patch releases | Fixed patch level |
  |:--------|:------------------------|:------------------|
  | 19.0    | 19.0.0 - 19.0.2         | 19.0.3            |
  | 19.1    | 19.1.0                  | 19.1.1            |

Linux packages for the affected patch release mistakenly included two
directories under `/opt/gitlab/embedded/service/gitlab-rails/`:

- `.agents/`
- `.claude/`

These directories are excluded from the package payload starting with the fixed patch levels,
and by default in GitLab 19.2 and later. For more information, see
[issue 603547](https://gitlab.com/gitlab-org/gitlab/-/issues/603547).

On RPM-based distributions, RPM does not remove a directory it no longer owns
if the directory still contains files. Even after you upgrade a Linux
package RPM install past a fixed version, these directories can be left
behind on disk:

- `/opt/gitlab/embedded/service/gitlab-rails/.agents`
- `/opt/gitlab/embedded/service/gitlab-rails/.claude`

RPM does not remove these orphaned directories automatically. Check for these directories and,
if present, remove them manually:

1. Check whether the directories exist:

   ```shell
   ls -la /opt/gitlab/embedded/service/gitlab-rails/.agents \
          /opt/gitlab/embedded/service/gitlab-rails/.claude
   ```

1. If the directories are present, remove them:

   ```shell
   sudo rm -rf /opt/gitlab/embedded/service/gitlab-rails/.agents \
               /opt/gitlab/embedded/service/gitlab-rails/.claude
   ```

DEB-based distributions are not affected because `dpkg` removes directories
it no longer owns during the upgrade.
