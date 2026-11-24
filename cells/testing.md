---
stage: Runtime
group: Cells Infrastructure
info: Any user with at least the Maintainer role can merge updates to this content. For details, see <https://docs.gitlab.com/development/development_processes/#development-guidelines-review>.
title: Test your changes against a cell
---

A cell differs from the legacy cell (the existing GitLab.com instance) in ways
that unit tests on a single-instance database do not exercise.
Test your feature against a cell to find these differences before your users do.

## Test locally

To run more than one cell on your workstation, use the
[cells rig in `gitlab-caproni`](https://gitlab.com/gitlab-org/gitlab-caproni/-/blob/main/docs/cells.md).
The rig runs each cell in its own local Kubernetes cluster and supports only macOS with `colima`.

If you use the GitLab Development Kit (GDK), see
[setting up Cells in GDK](https://gitlab.com/gitlab-org/gitlab-development-kit/-/blob/main/doc/howto/cells.md).

## Run end-to-end tests against a cell

The end-to-end test framework treats the environment as a cell when the `QA_RUNNING_ON_CELL`
environment variable is `true`.

Earlier, the `QA_COOKIES` environment variable set a `_gitlab_session` cookie with a value that starts with `cell-`.
This cookie marked the environment as a cell and routed requests to it.
The framework still accepts this cookie during the transition to `QA_RUNNING_ON_CELL`, but the cookie is no longer needed.
When this cookie is set, the framework refreshes the sign-in page before it enters the credentials.
The refresh replaces the cookie with a valid session cookie from the cell.

### How requests reach the cell

You do not need to route requests to the cell yourself.
The HTTP Router routes the requests of a test user to the cell of the user,
based on the Topology Service claims of the user:

- Sign-in: The framework uses the two-step sign-in flow.
  The HTTP Router routes the `/users/sign_in?login=<username>` request to the cell that claims the username.
  The cell then sets a `_gitlab_session` cookie with the prefix of the cell.
  The HTTP Router routes later browser requests by this prefix, also after the user signs out.
- API: The HTTP Router routes requests by the prefix of the access token, which the cell issues.
- Git over HTTP: The HTTP Router routes requests by the username in the HTTP Basic authentication header.

As a result, every user that the tests sign in with must exist on the target cell.
Each QA user environment variable, like `GITLAB_USERNAME`, `GITLAB_ADMIN_USERNAME`, and
`GITLAB_QA_USERNAME_1`, must name a user that was created on the target cell.
Users that the tests create with the administrator API are created on the same cell.
For the list of variables, see
[supported environment variables](https://gitlab.com/gitlab-org/gitlab-qa/blob/master/docs/what_tests_can_be_run.md#supported-gitlab-environment-variables).

Some requests reach the legacy cell instead of the target cell:

- A browser that never signs in.
  The HTTP Router cannot match an anonymous request to a cell, so the request goes to the legacy cell.
- Sign-up and registration flows, like trial registration.
  The new user does not exist yet, so the HTTP Router has no claim to route by.

### What changes on a cell

When the framework runs against a cell:

- The test runner (`bin/qa`) excludes tests tagged with `:skip_cells`.
- The check that waits for a resource created through the API fails the test
  when the resource is not available.
  On every environment, the check sends an authenticated `GET` request to the API path of the resource.
  If the resource has no API path, the check requests the web URL of the resource instead.
  If the response is not `200 OK` after five attempts, the check raises a `ResourceNotFoundError` on a cell.
  On other environments, the check gives up without an error.

If you add a resource to the framework, make sure the `GET` request for the resource includes every
required parameter.
To add a query parameter, override `query_parameters` in the resource.
A missing parameter fails the availability check on a cell, so the test fails,
even though the `POST` request created the resource.
For example, the file resource must pass `ref`.

## Skip a test that cannot pass on a cell

Use the `:skip_cells` tag only when a test cannot pass on a cell for an environmental reason.
For example:

- The test depends on infrastructure that a cell does not have, like a canary Gitaly storage.
- The test depends on fixture data that exists only on the legacy cell.

Do not use the tag to hide a product bug.
If a feature does not work on a cell, create an issue for the bug instead.

When you add the tag, add a comment with the reason and a link to the issue that tracks the gap:

```ruby
# Cells have no canary Gitaly storage: https://gitlab.com/gitlab-com/gl-infra/tenant-scale/cells-infrastructure/team/-/work_items/978
describe 'Git push to canary Gitaly node over HTTP', :skip_cells do
```

For how to run tagged tests against a cell anyway, see
[RSpec metadata for end-to-end tests](../testing_guide/end_to_end/best_practices/rspec_metadata_tests.md).

## Write code and tests that work on a cell

The following assumptions can fail on a cell.
The examples come from the first runs of the end-to-end test suite against a cell.
Check your feature for the same assumptions.

### IDs do not fit in 4 bytes

Database sequences are unique across all cells, so each cell allocates IDs from its own range.
For more information, see [database sequences](_index.md#database-sequences).
For example, IDs on staging Cell 9 start at about 9,000,000,000,000.
This value is far greater than 2,147,483,647, the largest 4-byte integer.
Code that works on the legacy cell can fail on a cell:

- Type casts that drop the column limit raise `ActiveModel::RangeError`.
  `Gitlab::Database::BulkUpdate` bound `bigint` columns as 4-byte integers, which broke issue boards.
  For more information, see
  [issue 981](https://gitlab.com/gitlab-com/gl-infra/tenant-scale/cells-infrastructure/team/-/work_items/981).
- `jsonb_accessor` attributes that store a record ID as `:integer` raise `ActiveModel::RangeError`.
- GraphQL fields that expose a record ID as `GraphQL::Types::Int`, which is a 32-bit type,
  raise `GraphQL::IntegerEncodingError` when they return the ID.
  Use a global ID type or `GraphQL::Types::BigInt` instead.
  For more information, see
  [issue 1051](https://gitlab.com/gitlab-com/gl-infra/tenant-scale/cells-infrastructure/team/-/work_items/1051).

When your code casts, serializes, or stores a record ID,
add a spec that uses an ID greater than 2,147,483,647.
Running the full test suite with large IDs is tracked in
[epic 19924](https://gitlab.com/groups/gitlab-org/-/epics/19924).

### A cell has no default organization

`Organizations::Organization.default_organization` returns `nil` on a cell.
Get the organization from the request or the record instead.
To get the organization from the request, see [using `Current.organization`](../organization/_index.md#using-currentorganization).
For example, an application setting that read the default organization caused the application settings API
to return a `500` error.
For more information, see
[issue 971](https://gitlab.com/gitlab-com/gl-infra/tenant-scale/cells-infrastructure/team/-/work_items/971).

### Claimed values are unique across all cells

A claimed attribute, like the fingerprint of a GPG key, can exist on only one cell in the cluster.
A test that creates the same fixed value on every run can fail on a cell
when another cell has already claimed the value.
Generate a new value for each test run instead.
For more information, see
[issue 975](https://gitlab.com/gitlab-com/gl-infra/tenant-scale/cells-infrastructure/team/-/work_items/975).

### Some tables and data exist only on the legacy cell

The database of a new cell is created from `db/structure.sql` and the production fixtures.
The database does not contain what only the history of GitLab.com added:

- Tables that are not in `db/structure.sql`.
  `Gitlab.com?` is true on a cell, not only on the legacy cell.
  A migration that runs only when `Gitlab.com?` is true still runs on a cell.
  For example, a batched background migration that reads from an archived table fails on a cell
  because the table does not exist.
  Make the migration do nothing when the table is missing.
  For more information, see
  [issue 973](https://gitlab.com/gitlab-com/gl-infra/tenant-scale/cells-infrastructure/team/-/work_items/973).
- Records that were created by data migrations that no longer exist.
  For example, the `plans` table on a new cell has rows only for the default and free plans.
  Code that reads a paid plan from this table finds no row.
  Use `GitlabSubscriptions::SystemDefined::Plan` to look up a plan instead.
  For more information, see
  [issue 977](https://gitlab.com/gitlab-com/gl-infra/tenant-scale/cells-infrastructure/team/-/work_items/977).

## Related topics

- [GitLab Cells development guidelines](_index.md)
- [HTTP Router](http_router.md)
- [Topology Service](topology_service.md)
- [Claiming an attribute for a cell](claims.md)
