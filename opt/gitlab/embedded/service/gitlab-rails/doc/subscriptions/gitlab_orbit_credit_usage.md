---
stage: Orbit
group: Context Systems
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Understand how GitLab Orbit consumes GitLab Credits, which requests are free, and which group is billed.
title: GitLab Orbit credit usage
---

{{< details >}}

- Tier: Premium, Ultimate
- Offering: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab Orbit credit usage [introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259054) in GitLab 19.5.

{{< /history >}}

Every query sent through the REST API, the GitLab MCP server,
or the GitLab Orbit MCP endpoint consumes [GitLab Credits](gitlab_credits.md).

The client does not matter. Queries from GitLab Duo, your own agents,
the GitLab Orbit CLI, the GitLab Orbit dashboard, and code navigation in GitLab all consume credits.

Queries on the local graph, which the GitLab Orbit CLI builds on your computer, do not consume credits.
Requests that do not run a query, such as schema and status requests, do not consume credits.

## Credit rate

Queries consume credits at this rate:

| Usage                           | Rate        | Credits |
|---------------------------------|-------------|---------|
| Queries to the GitLab Orbit API | 100 queries | 3       |

### Monthly consumption estimate examples

Use these examples to estimate monthly consumption:

- A team of 10 developers that each run 500 queries a month through GitLab Duo or the GitLab Orbit CLI.
  - Queries: 5,000
  - Monthly total: 150 credits
- A group of 100 developers that each run 500 queries a month.
  - Queries: 50,000
  - Monthly total: 1,500 credits
- An agent that reviews 5,000 merge requests a month and runs 30 queries for each review.
  - Queries: 150,000
  - Monthly total: 4,500 credits

## Graph capacity

Graph capacity is the size of the GitLab Orbit graph for a top-level group, measured in GiB.
The included graph capacity limit on GitLab.com and GitLab Dedicated is:

- Premium: 2 GiB.
- Ultimate: 5 GiB.

## Billed group

Usage is billed to the user's default GitLab Orbit group.
If the user belongs to only one top-level group with GitLab Orbit, that group is the default.
If the user belongs to more than one, they must select a
[default group](../user/profile/preferences.md#choose-which-gitlab-duo-features-use-orbit).
On GitLab.com, their queries fail until they do.

## Trials and purchases

On GitLab.com, a user with the Owner role for a top-level group can start a free GitLab Orbit trial.
To buy GitLab Orbit, or to use it on GitLab Self-Managed or GitLab Dedicated,
[contact the Sales team](https://about.gitlab.com/sales/).

## Track usage

To track GitLab Orbit usage, see [GitLab Orbit usage](gitlab_credits_dashboard.md#gitlab-orbit-usage).
