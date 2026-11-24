---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Configure the rate limits on release creates, updates, and evidence collection.
title: Releases API rate limits
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/269134) in GitLab 19.6 [with feature flags](../../administration/feature_flags/_index.md) named `rate_limit_release_writes_per_user` and `rate_limit_release_writes_per_project`. Disabled by default.
- Release evidence collection rate limit [introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/269672) in GitLab 19.6 [with a feature flag](../../administration/feature_flags/_index.md) named `rate_limit_release_evidence_collections_per_user`. Disabled by default.

{{< /history >}}

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.

Repeated requests that create or update releases, or collect release evidence, can put significant load on your instance.
To protect against this, you can limit how often each user and project can write releases, and how often each user can collect evidence.

These rate limits apply to the [create a release](../../api/releases/_index.md#create-a-release)
and [update a release](../../api/releases/_index.md#update-a-release) REST API endpoints,
and to the GraphQL `releaseCreate` and `releaseUpdate` mutations, which the GitLab UI also uses.
Each create or update request counts toward both limits.

The rate limits:

- Apply per user and per project.
- Default to `600` requests each minute for each user, and `300` requests each minute for each project.
- Can be set to `0` to disable each rate limit.

A separate rate limit applies to the [collect release evidence](../../api/releases/_index.md#collect-release-evidence)
REST API endpoint.
It applies per user, defaults to `10` requests each minute, and can be set to `0` to disable it.
It does not apply to the evidence that GitLab collects when a release is created,
or on the release date of a scheduled release.

If a limit is exceeded, the REST API returns `429 Too Many Requests`,
and the GraphQL mutations return an error.
While a feature flag is disabled, requests over its limit are logged but not blocked.

## Change the rate limits

Prerequisites:

- Administrator access.

To change the rate limits:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Releases API rate limits**.
1. In the **Maximum release writes per minute per user**,
   **Maximum release writes per minute per project**, and
   **Maximum release evidence collections per minute per user** text boxes, enter values.
1. Select **Save changes**.
