---
name: Work items
external_docs: https://docs.gitlab.com/user/work_items/
---
Use this API to manage [work items](../../../../doc/user/work_items/_index.md) in a project, a group,
or a namespace. Work items are the core elements for planning and tracking work, and cover
[types](../../../../doc/user/work_items/_index.md#work-item-types) such as issues, tasks, and epics.

Alongside the work items themselves, you can retrieve their children, linked items, linked resources,
notes, discussions, emoji reactions, email participants, and the current user's to-do items.

By default, responses include only the `id`, `iid`, `global_id`, and `title` of each work item.
Use the `fields` and `features` parameters to request more attributes.

> [!note]
> The availability of these endpoints is controlled by the `work_item_rest_api` feature flag.
> They are available for testing, but not ready for production use. While the flag is disabled,
> every endpoint except the list endpoints returns `404 Not Found`.

## History

- Endpoints to list and get work items introduced in GitLab 18.10
  [with a feature flag](../../../../doc/administration/feature_flags/_index.md) named `work_item_rest_api`.
  Disabled by default.
- Endpoints to create and delete work items added in GitLab 18.11.
- Endpoint to update work items added in GitLab 19.0.
- Endpoint to list work items can also be enabled with the `work_item_rest_api_index` feature flag
  in GitLab 19.1. Disabled by default.
- Endpoints to list emoji reactions, children, email participants, linked items, linked resources,
  and notes added in GitLab 19.1.
- Endpoint to list work items no longer behind a feature flag in GitLab 19.2.
  Feature flag `work_item_rest_api_index` [removed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/243015).
- Endpoints to list the current user's to-do items and discussions added in GitLab 19.2.
- Endpoints to add a child, and to list closing and related merge requests, added in GitLab 19.3.
- Endpoints to remove and reorder children, get a discussion, get and create notes, and list related
  branches added in GitLab 19.4.
- Endpoints to create and resolve discussions, and to manage the notes in a discussion, added in GitLab 19.5.
- Endpoints to update and delete notes added in GitLab 19.6.
