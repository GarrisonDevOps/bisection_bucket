---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Organizations API rate limits
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab.com, GitLab Self-Managed
- Status: Experiment

{{< /details >}}

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/470613) in GitLab 17.5 with a [flag](../../administration/feature_flags/_index.md) named `allow_organization_creation`. Disabled by default. This feature is an [experiment](../../policy/development_stages_support.md).
- [Changed](https://gitlab.com/gitlab-org/gitlab/-/issues/549062) in GitLab 18.4. Feature flag `allow_organization_creation` consolidated and renamed to `organization_switching`.
- Feature flag [changed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249678) to `org_stage_experimental` in GitLab 19.4. Disabled by default. Feature flag `organization_switching` removed.

{{< /history >}}

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.

Requests over the rate limit are logged into the `auth.log` file.

For example, if you set a limit of 400 for `POST /organizations`, requests to the API endpoint that
exceed a rate of 400 within one minute are blocked. Access to the endpoint is restored after one minute.

You can configure the per minute rate limit per user for requests to the [POST /organizations API](../../api/organizations.md#create-an-organization). The default is 10.

## Organization user limits

The following organization user endpoints have fixed, per-minute rate limits for each authenticated user that you cannot change.
The limits apply to the user making the request, not to the user being added or removed:

| Endpoint | Limit |
|----------|-------|
| [`GET /organizations/:id/users`](../../api/organizations.md#list-organization-users) | 120 |
| [`POST /organizations/:id/users`](../../api/organizations.md#add-a-user-to-an-organization) | 20 |
| [`PUT /organizations/:id/users/:user_id`](../../api/organizations.md#update-an-organization-user) | 20 |
| [`DELETE /organizations/:id/users/:user_id`](../../api/organizations.md#remove-a-user-from-an-organization) | 20 |

## Change the rate limit

Prerequisites:

- Administrator access.

To change the rate limit:

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Settings** > **Network**.
1. Expand **Organizations API rate limits**.
1. Change the value of any rate limit. The rate limits are per minute per user.
   To disable a rate limit, set the value to `0`.
1. Select **Save changes**.
