---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Configure rate limits on issue, epic, note, and merge request creation, and on thread resolution.
title: Content creation rate limits
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab Self-Managed

{{< /details >}}

Rate limits control the pace at which users can create issues, epics, notes, and merge requests,
and resolve or unresolve threads.

## Issue and epic creation

The limit for [epic](../user/group/epics/_index.md) creation is the same limit applied to issue creation.

Prerequisites:

- Administrator access.

To limit the number of requests made to the issue and epic creation endpoints:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Issues Rate Limits**.
1. Under **Max requests per minute**, enter the new value.
1. Select **Save changes**.

The rate limit:

- Is applied independently per project and per user.
- Is not applied per IP address.
- Is disabled by default.
- Can be set to `0` to disable the rate limit.

Requests over the rate limit are logged into the `auth.log` file.

For example, if you set the limit to `300`, requests that exceed a rate of 300 per minute are blocked.
Access to the endpoint is available after one minute.

## Note creation

{{< history >}}

- [Extended](https://gitlab.com/gitlab-org/gitlab/-/work_items/635767) to notes created by email and chat slash commands in GitLab 19.6 [with a flag](../administration/feature_flags/_index.md) named `notes_create_rate_limit_email_and_chat`. Disabled by default.

{{< /history >}}

You can configure the rate limit for requests to the note creation endpoint.

Prerequisites:

- Administrator access.

To change the note creation rate limit:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Notes rate limit**.
1. In the **Maximum requests per minute** box, enter the new value.
1. Optional. In the **Users to exclude from the rate limit** box, list users allowed to exceed the limit.
1. Select **Save changes**.

The rate limit:

- Is applied independently per user.
- Is not applied per IP address.
- Defaults to `300`.
- Counts each comment published from a review, including reviews submitted with
  the `/submit_review` or `/approve` quick action.

Users that you list in **Users to exclude from the rate limit** are also excluded from the
[note edit rate limit](non_configurable.md).

Requests over the rate limit are logged into the `auth.log` file.

For example, if you set the limit to `300`, requests that exceed a rate of 300 per minute are blocked.
Access to the endpoint is available after one minute.

### Comments created by email and chat commands

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.

The note creation rate limit also applies to comments created
[by email](../user/discussions/_index.md#reply-to-a-comment-by-sending-email)
and with [Slack](../user/project/integrations/gitlab_slack_application.md) or
[Mattermost](../user/project/integrations/mattermost_slash_commands.md) slash commands.

[Service Desk](../user/project/service_desk/_index.md) replies are counted separately
for each sender email address in each project.
The **Users to exclude from the rate limit** setting does not apply to them.

When a comment sent by email is over the rate limit, GitLab does not create it
and sends a rejection email to the sender.
Each sender gets at most one of these rejection emails per minute.

## Draft note creation

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/636471) in GitLab 19.6.

{{< /history >}}

You can configure the rate limit for requests that create a draft note on a merge request.
The limit applies to the UI and the REST API.
Publishing draft notes counts against the [note creation](#note-creation) rate limit instead.

Prerequisites:

- Administrator access.

To change the draft note creation rate limit:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Notes rate limits**.
1. In the **Maximum draft note requests per minute** box, enter the new value.
1. Select **Save changes**.

The rate limit:

- Is applied independently per user.
- Defaults to `0`, which disables the rate limit. On GitLab.com, the limit is `300`.
- Does not apply to users in the **Users to exclude from the rate limit** box for note creation.

Requests over the rate limit return `429 Too Many Requests`.

## Thread resolution

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/606720) in GitLab 19.6.

{{< /history >}}

You can configure the rate limit for requests that resolve or unresolve a thread or a comment.
The limit applies to the UI, the REST API, and the GraphQL API.

Prerequisites:

- Administrator access.

To change the thread resolution rate limit:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Thread resolution rate limits**.
1. In the **Maximum requests per minute** box, enter the new value.
1. Select **Save changes**.

The rate limit:

- Is applied independently per user.
- Is not applied per IP address.
- Defaults to `120`.
- Can be set to `0` to disable the rate limit.
- Counts each resolve or unresolve request, including requests for a thread that is already
  resolved or unresolved.
  A GraphQL request with multiple mutations counts each mutation.
  When a GraphQL request exceeds the limit, the whole request returns an error,
  but the mutations that ran before the limit was reached are not reverted.

Requests over the rate limit return `429 Too Many Requests`.

## Merge request creation

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/606714) in GitLab 19.6.

{{< /history >}}

You can configure the rate limit for merge request creation.
The limit applies to the UI, the REST API, the GraphQL API, Git push options,
merge requests created from an issue, and merge requests created by email.

Prerequisites:

- Administrator access.

To change the merge request creation rate limit:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Merge request creation rate limits**.
1. In the **Maximum requests per minute** box, enter the new value.
1. Select **Save changes**.

The rate limit:

- Is applied independently per user.
- Is not applied per IP address.
- Defaults to `0`, which disables the rate limit. On GitLab.com, the limit is `150`.

Requests over the rate limit return `429 Too Many Requests`.

## Related topics

- [Rate limits](_index.md)
- [Non-configurable rate limits](non_configurable.md)
