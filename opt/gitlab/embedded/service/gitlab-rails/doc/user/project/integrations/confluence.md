---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Confluence Workspace
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Use a Confluence Cloud Workspace as your project wiki.

This integration adds a link to a Confluence wiki instead of the [GitLab wiki](../wiki/_index.md).
GitLab does not display your Confluence content.

When you turn on the integration:

- A new menu item is added to the left sidebar: {{< ui text="Navigation|Plan" >}} > {{< ui text="Confluence" >}}.
  It links to your Confluence wiki.
- The {{< ui text="Navigation|Plan" >}} > {{< ui text="Wiki" >}} menu item is hidden.

  To access the GitLab wiki for the project, use its URL:
  `<example_project_URL>/-/wikis/home`.
  To bring back the {{< ui text="Navigation|Plan" >}} > {{< ui text="Wiki" >}} menu item, turn off this integration.

Creating a more comprehensive integration with Confluence Cloud is tracked in
[epic 3629](https://gitlab.com/groups/gitlab-org/-/epics/3629).

## Set up the integration

This integration can be turned on for a project or for all projects in a group or instance.

### For your project or all projects in a group

Prerequisites:

- You must have the Maintainer or Owner role for the project.
- You must use a Confluence Cloud URL (`https://example.atlassian.net/wiki/`).

To set up the integration for your project or group:

1. In the top bar, select {{< ui text="Search or go to" >}} and find your project or group.
1. In the left sidebar, select {{< ui text="Settings" >}} > {{< ui text="Integrations" >}}.
1. Next to {{< ui text="ConfluenceService|Confluence Workspace" >}}, select {{< ui text="Configure" >}}.
1. Under {{< ui text="Enable integration" >}}, select the {{< ui text="Active" >}} checkbox.
1. In {{< ui text="Confluence Workspace URL" >}}, enter your Confluence Workspace URL.
1. Select {{< ui text="Save changes" >}}.

If the integration has been turned on for the group, you can still turn it off for individual projects.

### For all projects on the instance

{{< details >}}

- Offering: GitLab Self-Managed

{{< /details >}}

Prerequisites:

- You must have administrator access to the instance.
- You must use a Confluence Cloud URL (`https://example.atlassian.net/wiki/`).

To set up the integration for your instance:

1. In the upper-right corner, select {{< ui text="Navigation|Admin" >}}.
1. In the left sidebar, select {{< ui text="Admin|Settings" >}} > {{< ui text="Integrations" >}}.
1. Next to {{< ui text="ConfluenceService|Confluence Workspace" >}}, select {{< ui text="Configure" >}}.
1. Under {{< ui text="Enable integration" >}}, select the {{< ui text="Active" >}} checkbox.
1. In {{< ui text="Confluence Workspace URL" >}}, enter your Confluence Workspace URL.
1. Select {{< ui text="Save changes" >}}.

## Access your Confluence Workspace from GitLab

Prerequisites:

- You must set up the integration [for your project, group](#for-your-project-or-all-projects-in-a-group),
  or [for your instance](#for-all-projects-on-the-instance).

To access your Confluence Workspace from a GitLab project:

1. In the top bar, select {{< ui text="Search or go to" >}} and find your project.
1. In the left sidebar, select {{< ui text="Navigation|Plan" >}} > {{< ui text="Confluence" >}}.
1. Select {{< ui text="WikiEmpty|Go to Confluence" >}}.
