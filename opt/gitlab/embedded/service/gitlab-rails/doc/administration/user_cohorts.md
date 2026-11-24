---
stage: Analytics
group: Optimize
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Analyze user retention and activity trends over time.
gitlab_dedicated: yes
title: User cohorts
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

A cohort is a group of users created in the same month.
User cohorts show how many users in each cohort continue to use GitLab in the
months after they were created.
Use this information to track user retention and adoption on your instance,
and to see how many users were created but never used GitLab.

The user cohorts table shows the users created in the last 12 months, including the
current month, grouped by the month they were created in.
Newer months have fewer **Month** columns filled in.
The table counts all users on the instance, including bots, service accounts, and blocked users.

The table has the following columns:

- Under {{< ui text="Cohorts|New users" >}}:
  - {{< ui text="Cohorts|Registration month" >}}: The month the users were created.
  - {{< ui text="Cohorts|Inactive users" >}}: The number of users who never had any activity on the instance.
  - {{< ui text="Cohorts|Active users" >}}: The number of users who had activity at least once.
- Under {{< ui text="Cohorts|Returning users" >}}:
  - **Month 1** to **Month 11**: The number and percentage of active users who had
    activity that many months after the registration month, or later.

GitLab stores only the date of each user's most recent activity.
A user counts as active in every month up to their most recent activity,
even if they had no activity in some of those months.

The table is cached, so it can be up to one day out of date.

GitLab considers a user active if:

- The user signs in.
- The user has Git activity (whether push or pull).
- The user visits pages related to dashboards, groups, projects, issues, or merge requests.
- The user uses the API.
- The user uses the GraphQL API.

## View user cohorts

### For the instance

{{< details >}}

- Offering: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Prerequisites:

- Administrator access.

To view user cohorts for the instance:

1. In the upper-right corner, select {{< ui text="Navigation|Admin" >}}.
1. In the left sidebar, select {{< ui text="Admin|Instance overview" >}} > {{< ui text="Users" >}}.
1. Select the {{< ui text="Cohorts" >}} tab.

### For an organization

{{< details >}}

- Offering: GitLab.com, GitLab Self-Managed
- Status: Beta

{{< /details >}}

In the {{< ui text="Organization Admin" >}} area, the table counts only users in that organization.

Prerequisites:

- [Organization administrator](../user/organization/_index.md#user-types-and-permissions) access.

To view user cohorts for an organization:

1. In the left sidebar, select {{< ui text="Organization|Organizations" >}}.
1. From the dropdown list, select the organization you want to go to.
1. In the left sidebar, select {{< ui text="Organization|Manage organization" >}}.
1. Select {{< ui text="Organization|Organization overview" >}} > {{< ui text="Users" >}}.
1. Select the {{< ui text="Cohorts" >}} tab.
