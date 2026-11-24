---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Configure the rate limit on the rows that each user can delete with environments.
title: Environments API rate limits
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/269154) in GitLab 19.6 [with a feature flag](../../administration/feature_flags/_index.md) named `rate_limit_environment_delete_rows`. Applies only when the `environment_delete_in_batches` feature flag is also enabled. Disabled by default.

{{< /history >}}

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.

A single user who repeatedly deletes large environments can put significant load on your instance.
To protect against this, you can limit how many rows each user can delete with environments.

This rate limit applies to the [delete an environment](../../api/environments.md#delete-an-environment)
REST API endpoint, which the GitLab UI uses, and the GraphQL `environmentDelete` mutation.
Each request counts the deployment, job, and merge request link records it deletes with the environment.
Environments deleted automatically after they stop do not count toward the limit.

The rate limit:

- Applies per user.
- Defaults to `20000` rows each minute.
- Never stops the first 500 rows of a request, so a limit below `500` allows up to 500 rows each minute.
- Can be set to `0` to disable the rate limit.

If the limit is exceeded, the REST API returns `429 Too Many Requests` and
the GraphQL mutation returns an error.
A request that reaches the limit while deleting keeps the rows it deleted.

## Change the rate limit

Prerequisites:

- Administrator access.

To change the rate limit:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Environments API rate limits**.
1. In the **Maximum rows deleted with environments per minute per user** text box, enter a value.
1. Select **Save changes**.
