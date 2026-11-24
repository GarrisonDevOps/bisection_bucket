---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
gitlab_dedicated: yes
description: Configure rate limits on Git HTTP, Git LFS, Git SSH, and Git push operations.
title: Git operations rate limits
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Common Git operations, like clones, fetches, and pushes, can generate many requests in a short time.
Rate limits on Git HTTP, Git LFS, Git SSH, and Git push operations protect the security and
durability of your GitLab instance.
Each of these limits works differently with the
[general user and IP rate limits](../administration/settings/user_and_ip_rate_limits.md).
Each section explains how.

## Git HTTP

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/147112) in GitLab 17.0.

{{< /history >}}

If you use Git HTTP in your repository, common Git operations can generate many Git HTTP requests.
GitLab can enforce rate limits on both authenticated and unauthenticated Git HTTP requests to improve
the security and durability of your web application.

> [!note]
> [General user and IP rate limits](../administration/settings/user_and_ip_rate_limits.md) aren't
> applied to Git HTTP requests.

### Git HTTP on GitLab.com

On GitLab.com, Git HTTP requests are subject to
[Git HTTPS request rate limits](../user/gitlab_com/rate_limits.md#current-rate-limits).

### Configure unauthenticated Git HTTP rate limits

{{< history >}}

- [Changed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/263309) in GitLab 19.6 to exclude requests authenticated with a CI/CD job token.

{{< /history >}}

GitLab disables rate limits on unauthenticated Git HTTP requests by default.

Git HTTP requests authenticated with a [CI/CD job token](../ci/jobs/ci_job_token.md) do not count toward this limit,
except [Git LFS object uploads and downloads](#configure-git-lfs-rate-limits).
To limit the other job token requests, enable the
[authenticated Git HTTP rate limit](#configure-authenticated-git-http-rate-limits).

Prerequisites:

- You must have administrator access.

To apply rate limits to Git HTTP requests that do not contain authentication
parameters, enable and configure these limits:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Git HTTP rate limits**.
1. Select **Enable unauthenticated Git HTTP request rate limit**.
1. Enter a value for **Max unauthenticated Git HTTP requests per period per user**.
1. Enter a value for **Unauthenticated Git HTTP rate limit period in seconds**.
1. Select **Save changes**.

### Configure authenticated Git HTTP rate limits

{{< history >}}

- Authenticated Git HTTP rate limits [introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/191552) in GitLab 18.1 [with a feature flag](../administration/feature_flags/_index.md) named `git_authenticated_http_limit`. Disabled by default.
- [Enabled on GitLab.com, GitLab Self-Managed, and GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/543768) in GitLab 18.3.
- [Generally available](https://gitlab.com/gitlab-org/gitlab/-/issues/561577) in GitLab 18.4. Feature flag `git_authenticated_http_limit` removed.
- [Changed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/263309) in GitLab 19.6 to count requests authenticated with a CI/CD job token.

{{< /history >}}

GitLab disables rate limits on authenticated Git HTTP requests by default.

Requests authenticated with a [CI/CD job token](../ci/jobs/ci_job_token.md) count toward the limit for the user
who runs the job.

Prerequisites:

- You must have administrator access.

To apply rate limits to Git HTTP requests that contain authentication
parameters, enable and configure these limits:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Git HTTP rate limits**.
1. Select **Enable authenticated Git HTTP request rate limit**.
1. Enter a value for **Max authenticated Git HTTP requests per period per user**.
1. Enter a value for **Authenticated Git HTTP rate limit period in seconds**.
1. Select **Save changes**.

If required, you can
[allow specific users to bypass authenticated request rate limiting](../administration/settings/user_and_ip_rate_limits.md#allow-specific-users-to-bypass-authenticated-request-rate-limiting).

### Override rate limits for a project

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/629903) in GitLab 19.6 [with a feature flag](../administration/feature_flags/_index.md) named `project_git_throttle_overrides`. Disabled by default.

{{< /history >}}

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.
> This feature is available for testing, but not ready for production use.

Some projects can generate too much repository traffic, including wiki and design
repository traffic. In these cases, instead of using instance-wide rate limit settings,
set a per-project limit for:

- Unauthenticated Git HTTP requests
- Authenticated Git HTTP requests
- Authenticated Git LFS requests

Per-project limits must be stricter than the instance limits they override, otherwise
the instance-wide limit still applies. Therefore, these settings cannot be used to
loosen rate limits for individual projects. The rate limit period always comes from
the instance-wide setting. A per-project limit applies only when the matching instance-wide limit is enabled.

Prerequisites:

- You must have the Owner role for the project.

To set a per-project limit:

1. In the top bar, select **Search or go to** and find your project.
1. Select **Settings** > **Repository**.
1. Expand **Git request rate limits**.
1. Enter a value for one or more of:
   - **Unauthenticated Git HTTP requests**
   - **Authenticated Git HTTP requests**
   - **Authenticated Git LFS requests**
1. Select **Save changes**.

Changes can take up to one minute to take effect because these values are cached.
Leave a field blank to use the instance-wide limit instead of a per-project override.
Because GitLab keeps serving Git requests sent to a project's previous paths after
a rename, the per-project limit applies to those paths too.

## Git LFS

[Git Large File Storage (LFS)](../topics/git/lfs/_index.md) is a Git extension for handling large
files.
Repositories that use Git LFS can generate a large number of LFS requests.
You can enforce
[general user and IP rate limits](../administration/settings/user_and_ip_rate_limits.md), but you can
also override the general setting to enforce additional limits on Git LFS requests. This
override can improve the security and durability of your web application.

### Git LFS on GitLab.com

On GitLab.com, Git LFS requests are subject to
[authenticated web request rate limits](../user/gitlab_com/rate_limits.md#current-rate-limits).
These limits are set to 1000 requests per minute per user.

Each Git LFS object uploaded or downloaded generates an HTTP request that counts toward
this limit.

> [!note]
> Projects with multiple large files may encounter an HTTP rate limit error.
> This error occurs during cloning or pulling, when performed from a single IP address in automated
> environments like CI/CD pipelines.

### Configure Git LFS rate limits

{{< history >}}

- [Changed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/263309) in GitLab 19.6 to count LFS batch and lock requests authenticated with a CI/CD job token.

{{< /history >}}

Git LFS rate limits are disabled by default on GitLab Self-Managed instances.
Administrators can configure dedicated rate limits specifically
for Git LFS traffic. When enabled, these dedicated LFS rate limits override the default
[user and IP rate limits](../administration/settings/user_and_ip_rate_limits.md).

LFS batch and lock requests authenticated with a CI/CD job token count toward the limit for the user
who runs the job.
LFS object uploads and downloads authenticated with a CI/CD job token do not count toward this limit.
They count toward the [unauthenticated Git HTTP rate limit](#configure-unauthenticated-git-http-rate-limits)
instead.

Prerequisites:

- You must be an administrator for the instance.

To configure Git LFS rate limits:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Git LFS Rate Limits**.
1. Select **Enable authenticated Git LFS request rate limit**.
1. Enter a value for **Max authenticated Git LFS requests per period per user**.
1. Enter a value for **Authenticated Git LFS rate limit period in seconds**.
1. Select **Save changes**.

## Git SSH operations

GitLab applies rate limits to Git operations that use SSH by user account and project. When a user
exceeds the rate limit, GitLab rejects further connection requests from that user for the project.

The rate limit applies at the Git command ([plumbing](https://git-scm.com/book/en/v2/Git-Internals-Plumbing-and-Porcelain)) level.
By default, each command has a rate limit of 600 per minute. For example:

- `git push` has a rate limit of 600 per minute.
- `git pull` has its own rate limit of 600 per minute.

The `git-upload-pack`, `git pull`, and `git clone` commands share a rate limit because they share commands.

> [!note]
> [General user and IP rate limits](../administration/settings/user_and_ip_rate_limits.md) are not
> applied to Git SSH operations. SSH traffic reaches GitLab through the internal API, so it counts
> only against the Git SSH operation limits.

### Limit for each user across all repositories

{{< details >}}

- Status: Beta

{{< /details >}}

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/267274) as a [beta](../policy/development_stages_support.md#beta) in GitLab 19.6 [with a feature flag](../administration/feature_flags/_index.md) named `rate_limit_gitlab_shell_operation_per_actor`. Disabled by default.

{{< /history >}}

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.

GitLab also limits the number of Git operations one user can perform across all repositories
and Git commands. The limit covers Git SSH operations, pushes over HTTP, and repository changes
in the UI or API.
By default, each user can perform 6,000 operations each minute.
This limit applies in addition to the limit for each project and Git command.

GitLab counts each deploy key separately from the user who created it.

GitLab checks a push over SSH twice: once when the connection is accepted, and once before the
changes are written. Each push over SSH counts as two operations.
GitLab checks pushes over HTTP and changes in the UI or API once, before the changes are written.
When a user is over the limit at that check, GitLab rejects the change after the data is uploaded.

### Git SSH operations on GitLab.com

On GitLab.com, Git SSH operations use the default rate limit of 600 operations each minute.
You cannot change this limit.

### Configure the GitLab Shell operation limits

By default, the limit for each user, project, and Git command is 600 operations each minute.
The limit across all repositories is 6,000 operations each minute.

Prerequisites:

- Administrator access.

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Git SSH operations rate limits**.
1. Enter values for these fields:
   - **Maximum number of Git operations per minute**: The limit for each user, project, and Git command.
   - **Maximum number of Git operations each user can perform every minute**: The limit for each user across
     all repositories.

   To disable a limit, set it to `0`.
1. Select **Save changes**.

## Git push operations

{{< details >}}

- Offering: GitLab.com, GitLab Self-Managed
- Status: Beta

{{< /details >}}

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/269867) as a [beta](../policy/development_stages_support.md#beta) in GitLab 19.6 [with a feature flag](../administration/feature_flags/_index.md) named `rate_limit_git_push_per_project`. Disabled by default.

{{< /history >}}

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.

GitLab limits the number of Git pushes to each project every minute.
The limit counts pushes from all users, over both HTTPS and SSH.
GitLab checks the limit before the client uploads the pushed data.
By default, each project accepts 600 pushes each minute.
This limit applies in addition to the Git HTTP and Git SSH rate limits.

When a project is over the limit, GitLab returns a `429 Too Many Requests` response
with a `Retry-After` header:

- Over HTTPS, the push fails and the Git client shows `The requested URL returned error: 429`.
- Over SSH, GitLab Shell waits 60 seconds and retries, up to two times.
  If every attempt is over the limit, the push fails with `Internal API unreachable`.

The limit counts Git pack uploads to project repositories.
It does not count:

- Pushes to wikis or snippets
- Commits made in the UI or API
- Pull mirroring
- Git LFS object uploads

Over HTTPS, a push larger than `http.postBuffer` (1 MiB by default) counts as two pushes,
because Git sends a probe request before the data.
Over SSH, a push that uploads Git LFS objects counts as two pushes,
because GitLab also counts the Git LFS authentication request.

GitLab counts pushes to a Geo secondary site on the primary site, which receives the data.

### Configure the Git push rate limit

Prerequisites:

- Administrator access.

To configure the Git push rate limit:

1. In the upper-right corner, select {{< ui text="Navigation|Admin" >}}.
1. In the left sidebar, select {{< ui text="Settings" >}} > {{< ui text="Network" >}}.
1. Expand {{< ui text="PushRateLimits|Git push rate limits" >}}.
1. Enter a value for {{< ui text="PushRateLimits|Maximum number of pushes every minute for each project" >}}.
   To disable the limit, set it to `0`.
1. Select {{< ui text="Save changes" >}}.

## Related topics

- [Rate limits](_index.md)
- [User and IP rate limits](../administration/settings/user_and_ip_rate_limits.md)
- [Non-configurable rate limits](non_configurable.md)
