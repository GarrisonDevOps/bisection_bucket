---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "A specific step in a work item's workflow ('In progress', 'Done', 'Won't do') that belongs to a category and maps to a binary state (open/closed)."
title: Status
---

{{< details >}}

- Tier: Premium, Ultimate
- Offering: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/543862) in GitLab 18.2 [with a feature flag](../../administration/feature_flags/_index.md) named `work_item_status_feature_flag`. Enabled by default.
- [Generally available](https://gitlab.com/gitlab-org/gitlab/-/issues/521286) in GitLab 18.4. Feature flag `work_item_status_feature_flag` removed.
- Status for epics [introduced](https://gitlab.com/groups/gitlab-org/-/work_items/17709) in GitLab 19.5 [with a feature flag](../../administration/feature_flags/_index.md) named `work_item_status_for_epics`. Disabled by default.
- Status for tickets [introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/580398) in GitLab 19.6 [with a feature flag](../../administration/feature_flags/_index.md) named
  `work_item_ticket_migration`. Enabled by default.

{{< /history >}}

> [!flag]
> The availability of status for epics and tickets is controlled by a feature flag.
> For more information, see the history.

<!-- Turn off the future tense test because of "won't do". -->
<!-- vale gitlab_base.FutureTense = NO -->

Work item status represents a specific step in a work item's workflow, such as **In progress**, **Done**, or **Won't do**.
Status gives more detail than the open and closed states that GitLab Free uses.

<i class="fa-youtube-play" aria-hidden="true"></i>
For a video overview, see [Configurable Status for Issues and Tasks - Complete Walkthrough (GitLab 18.2)](https://www.youtube.com/watch?v=oxN95MSo6UU).
<!-- Video published on 2025-07-11 -->

Use status in the following ways:

- Track work items through different stages of completion.
- Show the progress of work items more clearly.
- Standardize workflows across teams and projects.

Status is available for issues, tasks, epics, and Service Desk tickets.
For information on plans to add status to other work item types, see [epic 5099](https://gitlab.com/groups/gitlab-org/-/epics/5099).

## Default statuses

GitLab provides default statuses to get you started with work item tracking.
These statuses cannot be modified.

The default statuses are:

- **To do**: Work item is ready to be started.
- **In progress**: Work item is being actively worked on.
- **Done**: Work item has been completed.
- **Won't do**: Work item will not be completed.
- **Duplicate**: Work item is a duplicate of another item.

## Status categories

Status categories are logical groupings that determine how a status affects a work item's state and icon. Each status belongs to one of five categories:

- {{< ui text="WorkItem|Triage" >}}: For new or unprocessed work items.
- {{< ui text="WorkItem|To do" >}}: For work items ready to be started.
- {{< ui text="WorkItem|In progress" >}}: For work items being actively worked on.
- {{< ui text="WorkItem|Done" >}}: For completed work items.
- {{< ui text="WorkItem|Canceled" >}}: For work items that won't be completed.

Statuses in the {{< ui text="WorkItem|Done" >}} and {{< ui text="WorkItem|Canceled" >}} categories automatically set work items to closed state. All other categories maintain work items in open state.

<!-- vale gitlab_base.FutureTense = YES -->

## Status compared to scoped labels

[Scoped labels](../project/labels.md#scoped-labels), such as `workflow::in-review`, can also track
the workflow step of a work item.
Status and scoped labels are both available in the Premium and Ultimate tiers, but they work differently:

| Behavior               | Status | Scoped labels |
|------------------------|--------|---------------|
| Open and closed state  | A status in the {{< ui text="WorkItem\|Done" >}} or {{< ui text="WorkItem\|Canceled" >}} category closes the work item. A status in another category reopens it. | Adding or removing a label does not change the state. |
| Configuration          | Once, for the top-level group. Its subgroups and projects use the same statuses. | In any project or group. |
| Values for each item   | One status. | One label for each scope, with any number of scopes. |
| Supported types        | Issues, tasks, epics, and Service Desk tickets. | Merge requests and all work item types except requirements. |

Status and scoped labels are separate.
Setting a status does not add or remove labels.

Use status to track the workflow step of a work item, with the same statuses across a top-level group.
Use scoped labels to track other attributes that have one value at a time, such as priority or platform.
You can also use scoped labels to track the workflow of merge requests.

## Lifecycles

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/556113) in GitLab 18.5 [with a feature flag](../../administration/feature_flags/_index.md) named `work_item_status_mvc2`. Enabled by default.
- [Generally available](https://gitlab.com/gitlab-org/gitlab/-/issues/576610) in GitLab 18.6. Feature flag `work_item_status_mvc2` removed.

{{< /history >}}

A lifecycle is a collection of statuses that can be applied to a work item type. Lifecycles group statuses into meaningful workflows that can be reused consistently across work item types in a top-level group.

Each lifecycle defines default transition statuses:

- {{< ui text="WorkItem|Open default" >}}: Applied when a work item is created or reopened.
- {{< ui text="WorkItem|Closed default" >}}: Applied when a work item is closed.
- {{< ui text="WorkItem|Duplicate default" >}}: Applied when a work item is marked as a duplicate, moved, or promoted.

When status for epics is enabled for a top-level group that uses custom lifecycles, epics use the same lifecycle as issues.
If issues have no custom lifecycle, epics use the first custom lifecycle in the group.
In the {{< ui text="WorkItem|Statuses" >}} section of the group's {{< ui text="Settings" >}} > {{< ui text="Work items" >}} page, the epic type is listed after {{< ui text="WorkItem|Usage:" >}} for the issue lifecycle.
To give epics a different lifecycle, [change the lifecycle for the epic type](#change-lifecycle-for-a-work-item-type).
If you change the lifecycle for issues, epics keep their current lifecycle.

### Create a lifecycle

Prerequisites:

- You must have the Maintainer or Owner role for the group.
- This group must be at the top level.

To create a lifecycle:

1. In the top bar, select {{< ui text="Search or go to" >}} and find your group.
1. In the left sidebar, select {{< ui text="Settings" >}} > {{< ui text="Work items" >}}.
1. In the {{< ui text="WorkItem|Statuses" >}} section, select {{< ui text="WorkItem|Create lifecycle" >}}.
1. Enter a name, and choose whether to start from the default lifecycle or an existing lifecycle.
   The new lifecycle starts with the statuses of the lifecycle you choose, which you can edit later.
1. Select {{< ui text="Create" >}}.

### Rename a lifecycle

Prerequisites:

- You must have the Maintainer or Owner role for the group.
- This group must be at the top level.

To rename a lifecycle:

1. In the top bar, select {{< ui text="Search or go to" >}} and find your group.
1. In the left sidebar, select {{< ui text="Settings" >}} > {{< ui text="Work items" >}}.
1. In the {{< ui text="WorkItem|Statuses" >}} section, hover over the lifecycle detail view.
1. Select {{< ui text="Rename" >}}.
1. Rename the lifecycle and select {{< ui text="Save" >}}.

### Remove a lifecycle

Prerequisites:

- You must have the Maintainer or Owner role for the group.
- This group must be at the top level.
- The lifecycle must not be in use. It must not be associated with any work item type.

To remove a lifecycle:

1. In the top bar, select {{< ui text="Search or go to" >}} and find your group.
1. In the left sidebar, select {{< ui text="Settings" >}} > {{< ui text="Work items" >}}.
1. In the {{< ui text="WorkItem|Statuses" >}} section, select {{< ui text="WorkItem|Remove lifecycle" >}} for the lifecycle you want to remove.
1. In the confirmation dialog, select {{< ui text="WorkItem|Remove" >}}.

### Change lifecycle for a work item type

Prerequisites:

- You must have the Maintainer or Owner role for the group.
- This group must be at the top level.

To change the lifecycle for a work item type:

1. In the top bar, select {{< ui text="Search or go to" >}} and find your group.
1. In the left sidebar, select {{< ui text="Settings" >}} > {{< ui text="Work items" >}}.
1. In the {{< ui text="WorkItem|Statuses" >}} section, either:
   - Select {{< ui text="WorkItem|Change lifecycle" >}}.
   - If the lifecycle is used with more than one work item type, select it from the dropdown list.
1. Select a new lifecycle for the work item type. You can either choose an existing lifecycle or create a new lifecycle.
1. Select {{< ui text="Next" >}}.

   All current statuses show which new status from the new lifecycle they get.

1. Optional. To choose a different replacement status, select it from the dropdown list.
1. Select {{< ui text="Save" >}}.

## Custom statuses

Custom statuses are statuses that you define for a top-level group.
When you edit a lifecycle, custom statuses replace the default statuses for all subgroups and projects in that group.

Custom statuses have the following limits:

- A maximum of 70 statuses for each top-level group
- A maximum of 30 statuses for each lifecycle

### Status category changes

A status has one category, and that category applies to every lifecycle that uses the status.
You cannot change the category of a status when:

- The status is used in another lifecycle.
- The status is in use, and the new category would move the status between the open and closed states.
  A status is in use when work items are assigned to it, or when it is the replacement status for a status that was removed.

To use a different category, create a status with a different name and the category you want.

### Configure custom statuses for a top-level group

Configure custom statuses for top-level groups to make them available for work items in that group, its subgroups, and projects.

Prerequisites:

- You must have the Maintainer or Owner role for the group.
- This group must be at the top level.

To configure custom statuses:

1. In the top bar, select {{< ui text="Search or go to" >}} and find your group.
1. In the left sidebar, select {{< ui text="Settings" >}} > {{< ui text="Work items" >}}.
1. In the {{< ui text="WorkItem|Statuses" >}} section, select {{< ui text="WorkItem|Edit statuses" >}} for the lifecycle being used by the work item type.
1. Add, edit, or reorder statuses.
1. Select {{< ui text="Close" >}}.

### Set status for a work item

Prerequisites:

- You must have the Planner, Reporter, Developer, Maintainer, or Owner role for the work item's project or group, be the author of the work item, or be assigned to the work item.

To set a status for a work item:

1. Go to an issue, task, epic, or Service Desk ticket.
1. In the right sidebar, in the {{< ui text="Status" >}} section, select {{< ui text="Edit" >}}.
1. Select a status.
1. Select any area outside the dropdown list.

The work item's status updates immediately.
