---
stage: Plan
group: Spec-Driven Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Capture the intent, approach, and steps for a unit of work in a structured workplan that GitLab Duo flows can run."
title: Workplan
---

{{< details >}}

- Tier: Premium, Ultimate
- Offering: GitLab.com, GitLab Self-Managed
- Status: Experiment

{{< /details >}}

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/240718) in GitLab 19.0 [with a feature flag](../../administration/feature_flags/_index.md) named `workplan`. Disabled by default.
- Workplan widget [changed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250010) in GitLab 19.4.
- **View** and **Implement** workplan actions in the GitLab Duo Agentic Chat empty state [introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252727) in GitLab 19.4.
- Workplan actions in the GitLab Duo Agentic Chat empty state [removed](https://gitlab.com/gitlab-org/gitlab/-/work_items/626672) in GitLab 19.5.

{{< /history >}}

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.
> This feature is available for testing, but not ready for production use.

A workplan is a structured Markdown document attached to a work item. It captures the intent,
approach, and steps for a unit of work.

A workplan provides GitLab Duo agents with an agreed specification and a human-reviewable artifact on the
work item. With this context, an agent has more to work from than a short prompt, so it can run the
work more accurately.

You create a workplan with GitLab Duo or write one manually. GitLab Duo drafts the workplan from the
work item context, and you refine it. Agents then use the workplan as the primary specification for
the work.

The workplan is part of the [GitLab Duo Agent Platform](../duo_agent_platform/_index.md) and the
specification-driven development workflow.

You can add a workplan to issues and tasks.

After you turn on planning for a work item, the {{< ui text="AgentPlan|Workplan" >}}
widget appears and shows the workplan status:

- {{< ui text="AgentPlan|Not yet created" >}}: The work item has no workplan, and you can create one.
- {{< ui text="AgentPlan|No workplan" >}}: The work item has no workplan, and you do not have permission to create one.
- {{< ui text="AgentPlan|Ready for review" >}}: The work item has a workplan.

## Set up workplan generation

Before you can [generate a workplan with GitLab Duo](#generate-a-workplan-with-gitlab-duo),
your project and top-level group must be set up to run the {{< ui text="FoundationalFlow|Generate Workplan" >}} flow.

Prerequisites:

- The work item must be an issue or a task in a project. You cannot generate a workplan
  for a work item in a group.
- [GitLab Duo turned on](../duo_agent_platform/turn_on_off.md#turn-gitlab-duo-on-or-off).
- Flow execution and foundational flows turned on for the top-level group, with the
  {{< ui text="FoundationalFlow|Generate Workplan" >}} flow selected. On GitLab Self-Managed, flow execution and
  foundational flows must also be turned on for the instance.
- The {{< ui text="DuoAgentPlatform|Allow flow execution" >}} and {{< ui text="DuoAgentPlatform|Allow foundational flows" >}} settings turned on
  for the project.

For the steps to change these settings, see
[turn foundational flows on or off](../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off).

## Benefits

A workplan separates intent from implementation:

- The work item description captures intent, or what you want and why.
  People read the description to understand the goal.
- The workplan captures implementation, or how to do the work.
  Agents follow the workplan to carry out the work.

This separation gives you three benefits:

- Intent protection: An agent iterates on the workplan in a field separate from the work item
  description, so your intent stays intact even as the plan changes across several runs.
- Plan review: An agent pauses after producing a workplan, so you can review, refine, and approve
  the plan before any work starts.
- Agent focus: Because the workplan is a dedicated field, an agent asked to plan work puts that
  context there instead of rewriting the description or other parts of the work item.

## When to use a workplan

Use a workplan when you plan to give work to an agent, either by selecting {{< ui text="DuoAgentPlatform|Implement" >}}
or by providing the plan to a coding agent yourself. A workplan adds the most value when an agent runs
the work.

You do not need a workplan for small or well-understood changes, where planning adds more effort than it saves.

## Turn on planning for a work item

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250010) in GitLab 19.4.
- {{< ui text="AgentPlan|Create workplan manually" >}} option [added](https://gitlab.com/gitlab-org/gitlab/-/work_items/632233) in GitLab 19.6.

{{< /history >}}

By default, the {{< ui text="AgentPlan|Workplan" >}} widget and the readiness level are hidden on a work item.
To show them, turn on planning for that work item.

Prerequisites:

- An issue or a task.
- Permission to edit the work item.

To turn on planning, on the work item, in the upper-right corner, use one of the following methods:

- To [generate a workplan with GitLab Duo](#generate-a-workplan-with-gitlab-duo), select {{< ui text="WorkItem|Plan" >}}.
  This option requires workplan generation to be [set up](#set-up-workplan-generation).
- To [write a workplan yourself](#create-a-workplan-manually), next to {{< ui text="WorkItem|Plan" >}},
  select the down arrow ({{< icon name="chevron-down" >}}) > {{< ui text="AgentPlan|Create workplan manually" >}}.
  The workplan editor opens.

The {{< ui text="AgentPlan|Workplan" >}} widget appears on the work item, and the {{< ui text="WorkItem|Plan" >}} button no longer appears.
After you turn on planning for a work item, you cannot turn it off.

## Create a workplan

Create a workplan to describe how to complete a unit of work.

Prerequisites:

- Planning turned on for the work item.
- Permission to edit the work item.

You can generate a workplan with GitLab Duo or write one manually.

### Generate a workplan with GitLab Duo

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248543) in GitLab 19.3 [with a feature flag](../../administration/feature_flags/_index.md) named `duo_workplan_async_flow`. Disabled by default.
- Generating a workplan in GitLab Duo Chat [removed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/260695) in GitLab 19.6. Feature flag `duo_workplan_async_flow` removed.

{{< /history >}}

GitLab Duo generates the workplan with the {{< ui text="FoundationalFlow|Generate Workplan" >}} flow, which runs in the background.
When you select {{< ui text="WorkItem|Plan" >}} to [turn on planning](#turn-on-planning-for-a-work-item) for a work item,
GitLab Duo starts to generate a workplan.

Prerequisites:

- Workplan generation [set up](#set-up-workplan-generation).

To generate a workplan with GitLab Duo:

1. On the work item, in the {{< ui text="AgentPlan|Workplan" >}} widget, select {{< ui text="AgentPlan|Generate" >}}.
1. If GitLab Duo asks questions, answer them in the comment threads on the work item.
   Then, in the {{< ui text="AgentPlan|Workplan" >}} widget, select {{< ui text="AgentPlan|Continue" >}}.

GitLab Duo writes the workplan to the {{< ui text="AgentPlan|Workplan" >}} widget, and the status changes to
{{< ui text="AgentPlan|Ready for review" >}}.

The flow runs in the background, so you can leave the page while GitLab Duo works.
When GitLab Duo needs your input, you receive a to-do item and an email.

If the generation fails, in the {{< ui text="AgentPlan|Workplan" >}} widget, select {{< ui text="AgentPlan|Try again" >}}.

### Create a workplan manually

To create a workplan manually:

1. On the work item, in the {{< ui text="AgentPlan|Workplan" >}} widget, select {{< ui text="AgentPlan|More options" >}} > {{< ui text="AgentPlan|Create manually" >}}.
1. Optional. From the template dropdown list, select a workplan template.
1. Enter the workplan content. To switch between editors, select {{< ui text="Switch to rich text editing" >}}
   or {{< ui text="Switch to plain text editing" >}}.
1. Select {{< ui text="Save changes" >}}.

Workplan templates are [description templates](../project/description_templates.md) with filenames
that end in `.plan`.

## View a workplan

To view a workplan:

1. Go to the work item.
1. In the {{< ui text="AgentPlan|Workplan" >}} widget, select {{< ui text="View" >}}.

The workplan opens in a panel and shows the rendered content.

## Edit a workplan

Prerequisites:

- Permission to edit the work item.

To edit a workplan:

1. On the work item, in the {{< ui text="AgentPlan|Workplan" >}} widget, select {{< ui text="View" >}}.
1. In the panel, select {{< ui text="AgentPlan|Edit" >}}.
1. Make your changes.
1. Select {{< ui text="Save changes" >}}.

To discard your changes, select {{< ui text="Cancel" >}}.

## Regenerate a workplan

Regenerate a workplan to replace its content with a new version from GitLab Duo.

Prerequisites:

- Permission to edit the work item.
- Workplan generation [set up](#set-up-workplan-generation).

To regenerate a workplan:

1. On the work item, in the {{< ui text="AgentPlan|Workplan" >}} widget, select {{< ui text="View" >}}.
1. In the panel, select {{< ui text="More actions" >}} ({{< icon name="ellipsis_v" >}}) > {{< ui text="AgentPlan|Regenerate workplan" >}}.
1. If GitLab Duo asks questions, answer them in the comment threads on the work item.
   Then, in the {{< ui text="AgentPlan|Workplan" >}} widget, select {{< ui text="AgentPlan|Continue" >}}.

GitLab Duo replaces the existing workplan with the new version.

## Delete a workplan

Prerequisites:

- Permission to edit the work item.

To delete a workplan:

1. On the work item, in the {{< ui text="AgentPlan|Workplan" >}} widget, select {{< ui text="View" >}}.
1. In the panel, select {{< ui text="More actions" >}} ({{< icon name="ellipsis_v" >}}) > {{< ui text="AgentPlan|Delete workplan" >}}.
1. In the confirmation dialog, select {{< ui text="Delete" >}}.

This action cannot be undone.

## Readiness

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248374) in GitLab 19.3 [with a feature flag](../../administration/feature_flags/_index.md) named `workplan_score`. Disabled by default.
- [Renamed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259555) from confidence score to readiness score in GitLab 19.5.
- Feature flag `workplan_score` [removed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/268375) and replaced by the `workplan` feature flag in GitLab 19.7.

{{< /history >}}

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.
> This feature is available for testing, but not ready for production use.

Readiness shows how ready a work item is for GitLab Duo to
[implement](#implement-a-workplan-with-gitlab-duo).
GitLab Duo evaluates how complete, clear, and well scoped the work item is,
and shows the result as a readiness level.

Prerequisites:

- Planning turned on for the work item.

In the {{< ui text="AgentPlan|Workplan" >}} widget on the work item, the readiness level appears as
{{< ui text="AgentPlan|Low" >}}, {{< ui text="AgentPlan|Medium" >}}, or {{< ui text="AgentPlan|High" >}}.
The readiness level appears only after GitLab Duo generates a workplan and
evaluates the work item.

To view feedback on how to improve readiness, select {{< ui text="AgentPlan|Readiness details" >}}
({{< icon name="information-o" >}}) next to the readiness level.
The feedback opens in a drawer and shows any suggested changes to the work item or its workplan.
To close the drawer, select {{< ui text="AgentPlan|Readiness details" >}} again.

To improve readiness, make the suggested changes.
For example, add requirements, acceptance criteria, and constraints to the work item
description and to the workplan steps.

## Decision log

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249268) in GitLab 19.3 [with a feature flag](../../administration/feature_flags/_index.md) named `decision_log`. Disabled by default.

{{< /history >}}

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.
> This feature is available for testing, but not ready for production use.

The decision log is a record of the decisions made about a work item. It keeps the reason for
each decision next to the work item, so the history is not lost in chat or in comment threads.

The decision log is available on issues and tasks, and on custom work item types based on issues or tasks.
A work item does not need a workplan to have a decision log.

GitLab Duo adds a decision to the log when it settles an open question while it plans the work.
You can also record a decision yourself at any time.

Prerequisites:

- The Planner, Reporter, Security Manager, Developer, Maintainer, or Owner role for the project.

To open the decision log:

- On the work item, in the header, select {{< ui text="WorkItemDecisionLog|Decision log" >}} ({{< icon name="log" >}}).

The button shows a count of the decisions on the work item.

### Record a decision manually

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254465) in GitLab 19.5 [with a feature flag](../../administration/feature_flags/_index.md) named `decision_log`. Disabled by default.

{{< /history >}}

To record a decision manually:

1. On the work item, in the header, select {{< ui text="WorkItemDecisionLog|Decision log" >}} ({{< icon name="log" >}}).
1. In the panel, select {{< ui text="WorkItemDecisionLog|New decision" >}}.
1. Complete the fields. The required fields are {{< ui text="WorkItemDecisionLog|Decision" >}}, {{< ui text="WorkItemDecisionLog|Decided by" >}}, and {{< ui text="WorkItemDecisionLog|Context" >}}.
1. Optional. In {{< ui text="WorkItemDecisionLog|Why" >}}, explain why you chose this option over other options.
1. Optional. In {{< ui text="WorkItemDecisionLog|Source link" >}}, add a link to where the discussion happened, such as Slack,
   Google Docs, or GitLab.
1. Select {{< ui text="WorkItemDecisionLog|Create decision" >}}.

## Implement a workplan with GitLab Duo

When a workplan exists, GitLab Duo can implement it in a merge request. GitLab Duo treats
the workplan as the primary specification and uses the work item description and comments only for
additional context.

Prerequisites:

- GitLab Duo Agent Platform remote flows turned on.
- [Developer Flow](../project/merge_requests/developer.md) turned on for the top-level
  group and the project. For more information, see
  [turn foundational flows on or off](../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off).

To implement a workplan with GitLab Duo, use one of the following methods:

- On the work item, in the {{< ui text="AgentPlan|Workplan" >}} widget, select {{< ui text="DuoAgentPlatform|Implement" >}}.
- Open the workplan, then implement it from the panel:
  1. On the work item, in the {{< ui text="AgentPlan|Workplan" >}} widget, select {{< ui text="View" >}}.
  1. In the panel, select {{< ui text="DuoAgentPlatform|Implement" >}}.

### Implement a work item without a workplan

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/632233) in GitLab 19.6.

{{< /history >}}

For a small or well-understood change, GitLab Duo can implement the work item without a workplan.
GitLab Duo starts the Developer Flow with the work item as context, and planning stays off.

Prerequisites:

- GitLab Duo Agent Platform remote flows turned on.
- [Developer Flow](../project/merge_requests/developer.md) turned on for the top-level
  group and the project. For more information, see
  [turn foundational flows on or off](../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off).

To implement a work item without a workplan:

- On a work item without planning turned on, next to {{< ui text="WorkItem|Plan" >}},
  select the down arrow ({{< icon name="chevron-down" >}}) > {{< ui text="DuoAgentPlatform|Implement" >}}.

## Related topics

- [GitLab Duo Agent Platform](../duo_agent_platform/_index.md)
- [Planner Agent](../duo_agent_platform/agents/foundational_agents/planner.md)
- [Description templates](../project/description_templates.md)
- [Work items](_index.md)
