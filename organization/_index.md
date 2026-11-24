---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 'Development Guidelines: learn about organization when developing GitLab.'
title: Organization
---

The [Organization initiative](../../user/organization/_index.md) focuses on reaching feature parity between
GitLab.com and GitLab Self-Managed.

## Guidance for feature teams

Use this section to understand what to consider before building a feature at the organization level.

The target milestone for launching Organizations as
[Beta](https://gitlab.com/groups/gitlab-org/-/work_items?state=opened&label_name%5B%5D=Organizations%3A%3ABeta&type%5B%5D=8)
is 19.4 (2026-09-11).

Previously, a feature implemented at the instance level for GitLab Self-Managed
had to be re-implemented for top-level groups on GitLab.com.
Organizations remove this duplication.
The new default is to build features at the organization level, which serves both.
For example, the Artifact Registry uses organizations as its
[anchor point](https://gitlab.com/gitlab-org/ops/artifact-registry/-/blob/main/docs/adr/001_organizations_as_anchor_point.md).

Not every feature needs organization-level scope, and because Organizations
has not yet launched as Beta, there are key considerations to be aware of.
Read the following sections for details.

Contact the team on Slack (`#g_organizations`) to discuss your use case before building.

### Determine if your feature needs organization-level scope

Not every feature belongs at the organization level.

Most features should continue to be anchored to the group, project, or user
level. This mirrors the old paradigm where most features did not target the
instance or TLG level.

Features that span multiple groups inside an organization should be scoped at
the group level, but with cross-group navigation. It is not a sufficient
justification to invent an organization-level version.

Only build a feature at the organization level when users have a clear need
for organization-level governance or configuration.

Consult the Organizations Charter
(`https://docs.google.com/document/d/1ldPftCifCDkdw3_3JKOnFjdwNHGIgbHIbW8HEc92i1Y/edit`, internal access required)
for more information.

### Plan roles specific to your organization-level feature

Organization-level roles are separate from group and project roles.
When designing your feature:

- Define what actions each organization role (Owner, User) can perform.
- Do not assume group-level roles map directly to organization-level roles.
- Consider whether your feature requires a new organization-level permission,
  or whether an existing role is sufficient.

For more information, see the [organization user documentation](../../user/organization/_index.md).

### Require the top-level group to transfer to its own organization (GitLab.com)

Features that depend on organization context require the TLG to be inside its own organization.
This is because the default organization on GitLab.com currently contains TLGs where the TLG
owners are not Organization Owners.

Do not enforce this with a check such as `organization.default?`. GitLab Self-Managed and GitLab
Dedicated legitimately run inside the default organization, so that check would also block them.

Instead, enforce this through authorization, using the organization-level permissions described in
[Plan roles specific to your organization-level feature](#plan-roles-specific-to-your-organization-level-feature).
Gate the feature behind a permission that only an Organization Owner can grant, for example through
the `organization_owner` and `organization_user` conditions in `Organizations::OrganizationPolicy`.

### Consider organization-based billing limitations

[Organization-based billing](https://gitlab.com/gitlab-org/customers-gitlab-com/-/merge_requests/15263)
is not yet available.

Do not build features that depend on billing or subscription entitlements at the organization level.

This is because billing and subscription entitlements are currently scoped to the top-level
group on GitLab.com, not to the organization.
Most paid customers only have one paid TLG on GitLab.com, so this rarely comes up.
If you create another TLG, that new TLG does not inherit the paid entitlements of your existing TLG.

Users are
[warned](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/organization/decisions/013_warn_on_tlg_creation/)
of this before they attempt to create another TLG on GitLab.com.

## Available and planned support for implementing organizations

The Organizations team is implementing changes which will automatically include support for:

- Application level Organization Isolation: There will be an ActiveRecord extension that will take care of [Organization Scoping](https://gitlab.com/groups/gitlab-org/-/work_items/19414). This is provisionally planned for availability and usage in early FY27-Q2.
- Sidekiq: there is no need to pass `organization_id` to Sidekiq worker parameters: Sidekiq workers will inherit the Current Organization from the scheduling context
- Events / Logging: similar to User, Project, or Namespace, Organization will be included
- Routing: Enabling / disabling organization based URLs (`/o/<organization>` prefix) will be available.
- Organization availability in tests

Teams do not need to implement these, unless there are specific reasons.

## Releasing organization features

Organization features ship behind an `organization flag` that moves through a fixed ladder of stages, from Experimental to generally available (GA).
A feature's audience only ever grows as its organization flag advances to a later stage, so an earlier stage's audience is never dropped.

For the engineering guide on gating a feature, registering an organization flag, and advancing it through the stages, see [Organizations release process](../organizations/release_process.md).
For the organization flags currently in the rollout process and their stage, see [Organizations platform release status](../organizations/release_status.md).

## Database table design

See the [sharding guidelines](sharding/_index.md).

## Using `Current.organization`

Ensure that `Current.organization` is set correctly at the request layer.
For the cases where this is not set automatically, follow the steps below.

Once `Current.organization` is set, the ActiveRecord extension
(`gitlab-database-data_isolation`) will use this
context to conditionally scope queries to that organization.

### Where `Current.organization` is available

`Current.organization` is set automatically in the following contexts:

- Controllers: `ApplicationController` includes a `before_action :set_current_organization` that runs for every request.
- GraphQL: `GraphqlController` inherits from `ApplicationController`, so the same `before_action` applies automatically.
- Grape API: a global `before_validation` hook in `lib/api/api.rb` runs for every endpoint.
  The hook resolves the organization from the `X-GitLab-Organization-ID` header, then from the
  organization of the authenticated user, and falls back to the default organization.
- Sidekiq: jobs get it from the organization context captured when the job is enqueued.
  Cron workers are the exception: the Sidekiq cron scheduler enqueues them with no context, so
  `Current.organization` is not set while they run. See [Cron workers](#cron-workers).

You must set `Current.organization` yourself in these cases:

- Grape API classes that opt out of the global hook with `skip_global_organization_setup!`.
  The global hook derives the organization from standard API authentication, such as personal
  access tokens. If your endpoint uses a custom authentication mechanism (for example, deploy
  tokens), the hook cannot resolve the correct organization. Opt out and derive the
  organization from the authenticated entity instead:

  ```ruby
  class MyAPI < ::API::Base
    skip_global_organization_setup!

    before do
      Current.organization = some_custom_method
    end
  end
  ```

- Code that runs outside a request or Sidekiq context, such as Rake tasks and the Rails console.

### Cron workers

Cron workers (workers that include `CronjobQueue`) are enqueued by the Sidekiq cron scheduler with no
application context. The job has no `organization_id`, so `Current.organization` is not set while the
worker runs.

A cron worker may read data of every organization. It may write to organization-owned tables (tables
whose `gitlab_schema` requires a sharding key) only inside an organization context.

Use `with_context(organization: organization) { ... }` (from `WorkerContext`) to set `Current.organization`
for the block. It restores the previous value afterwards. Jobs enqueued inside the block carry the
`organization_id`, so `Current.organization` is set when they run.

```ruby
with_context(namespace: group, user: user, organization: group.organization) do
  # ...
end
```

For Cells compatibility requirements for cron jobs, see
[Sidekiq Cells compatibility](../sidekiq/_index.md#cells-compatibility).

### Passing organization context

If there is application logic that needs the `Current.organization`, it should be passed from the request layer:

```ruby
# In controllers
def create
  @group = Groups::CreateService.new(
    current_user,
    group_params.with_defaults(organization_id: Current.organization.id)
  ).execute
end
```

### Scoping queries to organizations

An ActiveRecord extension (`gitlab-database-data_isolation`) scopes queries to the
current organization, dependent on the isolation state of the organization.
For more information, see [Organization data isolation](query_scoping.md).

## Organization routing

Organization-scoped routes use the `/o/:organization_path/` pattern (for example, `/o/my-org/projects`).
Pages that read the organization from the URL are organization-scoped.
These pages include the dashboard, explore, search, user settings, profile, help, import, uploads, snippets, `new` and `create` for groups and projects, root, invites, sign-in, and the organization admin area.
Each of these routes is drawn twice: once globally and once under `/o/:organization_path/`.

Routes for routable resources are drawn once and are not organization-scoped.
Routable resources are groups, projects, personal user profiles, ActivityPub, and the ID redirects such as `/-/g/:id` and `/-/p/:id`.
Git over HTTP is still organization-scoped, because its routes resolve no container and so cannot tell a prefixed repository path from a legacy one.
A group or project created in a non-default organization stores the organization prefix in its own route path, as `o/<organization-path>/<group>` in `routes.path`.
Its URL is therefore `/o/<organization-path>/<group>/<project>`, and `group_path` and `project_path` produce that URL without any organization context.
This prefix is planned in [work item 632163](https://gitlab.com/gitlab-org/gitlab/-/work_items/632163).

The URL helpers for organization-scoped pages exist so a feature's views and links work globally and inside an organization, without maintaining two versions.
Use regular, unscoped Rails URL helpers like `projects_path` and `project_issues_path(@project)`.
For organization-scoped pages, the routing layer decides at call time whether to nest the generated URL under an organization path, or return the plain global URL.
For groups, projects, and users, the record's own route path decides the URL.

```ruby
projects_path                    # /projects, or /o/my-org/projects if the request resolves to organization my-org
project_issues_path(@project)    # /namespace/project/-/issues, or /o/my-org/namespace/project/-/issues if the project's route path carries the prefix
```

Requests for a group, project, or user page in the former organization-scoped form, for example `/o/my-org/groups/my-group` or `/o/my-org/my-group/my-project`, redirect to the canonical URL: `GET` with status `302`, other methods with status `307` so that the method and body are kept.
The redirects are drawn by `redirect_organization_scoped` in `config/routes.rb`.

### Route pairing

The implementation lives in [`Routing::OrganizationsHelper::MappedHelpers`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/helpers/routing/organizations_helper.rb).
When routes load, it:

1. Scans the routes under `/o/:organization_path`, which no longer include groups, projects, and users.
1. Pairs each organization-scoped route with a global route of the same name, by stripping the `organization_` or `organizations_` prefix from the organization route's name. For example, `organization_projects_path` pairs with `projects_path`. Only names present on both sides are paired.
1. Overrides each paired global URL helper, both the `_path` and `_url` variant, so it can nest the generated URL or fall back to the plain global route.
1. Preserves the original `root_url`, `root_path`, `group_canonical_url`, and `group_canonical_path` helpers as `unscoped_root_url`, `unscoped_root_path`, `unscoped_group_canonical_url`, and `unscoped_group_canonical_path`.

Route pairing relies on name convention alone, not on matching controller and action.
As a result, an instance administrator whose home organization is isolated could get instance admin links incorrectly nested under their organization.
The plan is to keep instance administrators from being members of isolated organizations, avoiding this case entirely.

### `Current.data_context`

`Current.data_context` identifies the data-isolation boundary for the current request: the single organization or user whose data the request is confined to, if any.
It is set once per request by `CurrentDataContext#set_data_context` (`app/controllers/concerns/current_data_context.rb`).
It wraps a `Gitlab::Current::DataContext` (`lib/gitlab/current/data_context.rb`), built from `organization: Current.organization_resolver.from_request` and `user: current_user`.

`Current.organization` is always set, falling back to the default organization when none applies.
`Current.data_context` only resolves to an organization when that organization is actually isolated.

- `DataContext#type` returns `:organization` when an isolated organization applies, `:user` when a user is present but no organization is isolated, or `:nil` otherwise.
- A non-isolated organization is never treated as a boundary (`Organization#isolated?` must be true).
- If the current user's home organization is isolated, that organization is always the boundary, even when the request names a different organization.
- The request's own organization (the one it names, for example through the URL) only becomes the boundary when the user side does not already claim one: no current user exists, or the current user's home organization is not isolated.

For more information, see the [organization contexts design document](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/organization/contexts/).

### `Current.organization_resolver`

`Current.organization_resolver` is a `Gitlab::Current::Organization` (`lib/gitlab/current/organization.rb`), set once per request by `CurrentOrganization#set_current_organization` (`app/controllers/concerns/current_organization.rb`).

It exposes:

- `from_organization_params`: the organization named by the `/o/:organization_path` segment of the current request's URL, if any.
- `from_request`: `from_organization_params`, or the organization named by a group or project namespace in the URL parameters, or the organization named by the `X-GitLab-Organization-ID` header.
- `organization`: `from_request`, or the organization of the current user, or the default organization.

### Deciding which organization to nest under

This applies only to paired helpers.
Group, project, and user helpers are never paired.

For each paired helper call, the organization path to nest under is decided in this order, stopping at the first step that applies:

1. `Current.data_context`, if it resolves to organization context (its `type` is `:organization`). Use that organization's path.
   This step is checked, and returns, before either of the following steps run.
   It overrides even an explicit per-call override, because a user whose home organization is isolated, or an anchor organization that is itself isolated, has no existence outside that organization.
1. An explicit `organization_path:` keyword argument passed to the helper call, only reached when step 1 does not apply.
   Because this checks for the key's presence rather than its truthiness, passing `organization_path: nil` forces the plain global path, even though step 3 would otherwise nest it.
1. The organization named by the current request's own URL, checked through `Current.organization_resolver.from_organization_params`. This only applies if the request's path itself already contains an `/o/:organization_path` segment.

If none of these steps applies, the plain global route is used.

### Explicit organization helpers

Use explicit organization helpers outside the request layer, such as in services, workers, or Rake tasks, where the automatic resolution above does not apply.
Also use them when a caller needs an organization other than the one automatic resolution would pick:

```ruby
organization_projects_path(organization_path: 'my-org')                 # /o/my-org/projects
organization_dashboard_projects_path(organization_path: 'my-org')       # /o/my-org/dashboard/projects
projects_path(organization_path: nil)                                   # /projects, even inside an organization-scoped request
```

Group, project, and user helpers have no explicit organization variant.
The record's own path decides the URL.

### Routes that are not organization-scoped

Some routes are not available under the organization scope:

- **Routable resources (groups, projects, and users)** - These routes are drawn once. Their organization prefix lives in `routes.path` instead.
- **Pages that take a full group or project path as a parameter** - The profile notification settings' `groups/*id` scope is drawn once for the same reason. A cloned twin would repeat the organization, as in `/o/my-org/-/profile/groups/o/my-org/my-group/notifications`.
- **The Web IDE** - The whole `/-/ide` scope is drawn once. `BlobHelper#ide_edit_path` builds Web IDE links by joining onto `ide_path`, so a paired `/-/ide` prefixes them with the organization, and the IDE's single registered OAuth callback no longer matches the one derived from the page URL. See [work item 637683](https://gitlab.com/gitlab-org/gitlab/-/work_items/637683).
- **Devise OmniAuth callbacks** - Devise does not support scoping OmniAuth callbacks under a dynamic segment, so these remain at the global level
- **API routes** - API endpoints are not yet organization-scoped

## Testing organization isolation

Enable the following feature flags to test organizations:

- `ui_for_organizations`
- `org_stage_experimental`, which enables the Experimental-stage organization flags, such as `org_switcher`

For more information on organization flags, see the [organizations release process](../organizations/release_process.md).

When making features organization-aware, pay special attention to areas where cross-organization data leakage could occur.
Examples include:

- Group and project member invites
- User mentions in issues, merge requests, or comments
- User search and autocomplete results
- Issue, merge request, milestone, and label references across organizations
- Finder classes scoping results to the current organization

A helpful convention for manual testing in your development environment is to create an organization with an obvious
name and prefix all its associated data. This makes it easy to visually confirm whether data from other organizations
has accidentally been exposed.

Create an Organization named `Secret Tanuki` and prefix all its associated data with this name:

- Organization: `Secret Tanuki`
- Users: `Secret Tanuki User Bob`, `Secret Tanuki User Alice`
- Projects: `Secret Tanuki Project X`, `Secret Tanuki Project Y`
- Issues: `Secret Tanuki Issue #42`, `Secret Tanuki Issue #99`
- Groups: `Secret Tanuki Group`
- Merge Requests: `Secret Tanuki MR: Add feature`

When testing for data leaks, search your UI or API responses for `Secret Tanuki`. If you find it where it shouldn't be,
you've discovered a cross-organization data leak. This is particularly useful when:

- Testing search and autocomplete features
- Verifying member invitations don't leak across organizations
- Checking that mentions and references are properly scoped
- Reviewing API responses for unintended data exposure

### Automated testing

For automated testing strategies, see [Testing with Organizations](../testing_guide/testing_with_organizations.md).

## Frontend guidelines

### REST API and GraphQL requests

Providing the current organization context to REST API and GraphQL requests does not require any additional arguments. Behind the scenes the current organization is passed via the `X-GitLab-Organization-ID` header in [axios_utils.js#L15](https://gitlab.com/gitlab-org/gitlab/-/blob/3deab3ebc51cdbb14de4a593b35d3df2e26f34bc/app/assets/javascripts/lib/utils/axios_utils.js#L15) and [graphql.js#L183](https://gitlab.com/gitlab-org/gitlab/-/blob/3deab3ebc51cdbb14de4a593b35d3df2e26f34bc/app/assets/javascripts/lib/graphql.js#L183).

### URLs

Do not hardcode or construct URLs on the frontend as they will not support [organization routing](#organization-routing). See [URLs in GitLab](../urls_in_gitlab.md#frontend-guidelines) for guidelines on how to generate URLs on the frontend.

### Accessing the current organization

The current organization context is available on the frontend via `window.gon.current_organization`. Behind the scenes this is exposed to the frontend in [gon_helper.rb#L69](https://gitlab.com/gitlab-org/gitlab/-/blob/f8cdb7b281830854374686003edf7bb66b7a59fa/lib/gitlab/gon_helper.rb#L69).

## Related topics

- [Sharding guidelines](sharding/_index.md)
- [Organization user documentation](../../user/organization/_index.md)
- [Testing with Organizations](../testing_guide/testing_with_organizations.md)
- [Consolidating groups and projects](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/consolidating_groups_and_projects/) architecture documentation
