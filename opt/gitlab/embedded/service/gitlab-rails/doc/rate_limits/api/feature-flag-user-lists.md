---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Configure the rate limit on the size of feature flag user lists that each user can write.
title: Feature flag user lists API rate limits
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/269126) in GitLab 19.6 [with a feature flag](../../administration/feature_flags/_index.md) named `rate_limit_feature_flag_user_list_write_bytes`. Disabled by default.

{{< /history >}}

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.

A single user who repeatedly writes large user lists can put significant load on your instance.
To protect against this, you can limit how many bytes of user lists each user can write.

This rate limit applies to the [create a feature flag user list](../../api/feature_flag_user_lists.md#create-a-feature-flag-user-list)
and [update a feature flag user list](../../api/feature_flag_user_lists.md#update-a-feature-flag-user-list)
REST API endpoints, which the GitLab UI also uses.
Each request counts the size in bytes of its `user_xids` value.
A request that does not send user IDs, such as one that only renames a list, does not count toward the limit.

The rate limit:

- Applies per user.
- Defaults to `16777216` bytes (16 MiB) each minute.
- Can be set to `0` to disable the rate limit.

If the limit is exceeded, the REST API returns `429 Too Many Requests`.
A single request larger than the limit is blocked even if it is the user's first in that minute.

## Change the rate limit

Prerequisites:

- Administrator access.

To change the rate limit:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Feature flag user lists API rate limits**.
1. In the **Maximum bytes of user lists written per minute per user** text box, enter a value.
1. Select **Save changes**.
