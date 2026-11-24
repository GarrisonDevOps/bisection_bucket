---
stage: Plan
group: Planning Views
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Configure an issue board with workflow labels and lists so a team can track tasks during daily stand-ups.
title: 'Tutorial: Set up an issue board for a team stand-up'
---

<!-- vale gitlab_base.FutureTense = NO -->

This tutorial shows you how to create and configure an issue board that helps teams run effective stand-ups.
When you're done, you'll have a board that supports this workflow:

1. Before each stand-up:

   - Team members update the status of their assigned tasks.
   - Tasks flow through lists that show their current state: planning, in development, blocked, or complete.

1. During the stand-up:

   - Team members discuss in-progress work and share completion timelines.
   - Blocked tasks are identified and plans made to resolve them.
   - New tasks are added to the ready list.
   - Completed tasks are celebrated and moved to done.

The result: Your team leaves each stand-up aligned on sprint progress, with risks identified and plans to address them.

To set up an issue board for team stand-ups:

1. [Create a group](#create-a-group)
1. [Create a project](#create-a-project)
1. [Create labels](#create-labels)
1. [Create the team stand-up board](#create-the-team-stand-up-board)
1. [Configure your board lists](#configure-your-board-lists)
1. [Create issues for team tasks](#create-issues-for-team-tasks)

## Before you begin

- If you're using an existing group for this tutorial, make sure you have the Planner, Reporter, Developer, Maintainer, or Owner role for the group.
- If you're using an existing project for this tutorial, make sure you have the Planner, Reporter, Developer, Maintainer, or Owner role for the project.

## Create a group

Start by creating a group to manage one or more related projects.
Groups let you manage member access and share settings across projects.

To create a group:

1. In the upper-right corner, select {{< ui text="Create new" >}} ({{< icon name="plus" >}}) and {{< ui text="New group" >}}.
1. Select {{< ui text="GroupsNew|Create group" >}}.
1. Complete the fields:
   - In {{< ui text="Groups|Group name" >}}, enter `Paperclip Software Factory`.
1. Select {{< ui text="GroupsNew|Create group" >}}.

You've created an empty group.
Next, create a project to store your issues and code.

## Create a project

Projects store your code repositories and issues you'll use for planning.
All development work happens in projects.

To create a blank project:

1. In your group, in the upper-right corner, select {{< ui text="Create project" >}}.
1. Select {{< ui text="ProjectsNew|Create blank project" >}}.
1. Complete the fields:
   - In {{< ui text="Project name" >}}, enter `Paperclip Assistant`.
1. Select {{< ui text="Create project" >}}.

## Create labels

To track issue status during stand-ups, you need workflow labels.

Create these labels in your `Paperclip Software Factory` group rather than the project.
Group labels are available to all projects in the group, which helps establish consistent
workflows across teams.

To create a workflow label:

1. In the top bar, select {{< ui text="Search or go to" >}} and find your **Paperclip Software Factory** group.
1. Select {{< ui text="Navigation|Manage" >}} > {{< ui text="Labels" >}}.
1. Select {{< ui text="New label" >}}.
1. In the **Title** text box, enter the label name.
1. Optional. Select a background color or enter a hex color value.
1. Select {{< ui text="Create label" >}}.

Repeat these steps to create all the workflow labels:

- `workflow::planning breakdown`
- `workflow::ready for development`
- `workflow::in development`
- `workflow::ready for review`
- `workflow::in review`
- `workflow::blocked`
- `workflow::verification`
- `workflow::complete`

## Create the team stand-up board

Create your board in the group so you can manage issues from any project in the group.

To create a group issue board:

1. In the top bar, select {{< ui text="Search or go to" >}} and find your **Paperclip Software Factory** group.
1. Select {{< ui text="Navigation|Plan" >}} > {{< ui text="Issue boards" >}}.
1. In the upper-left corner, select the dropdown list with the current board name.
1. Select {{< ui text="Boards|Create new board" >}}.
1. Complete the fields:
   - In {{< ui text="Title" >}}, enter `Team stand-up`.
   - Select both {{< ui text="Show the Open list" >}} and {{< ui text="Show the Closed list" >}}.
1. Select {{< ui text="Boards|Create board" >}}.

### Add workflow lists to your board

1. In the upper-right corner, select {{< ui text="New list" >}} ({{< icon name="plus" >}}).
1. From {{< ui text="New list" >}}, select {{< ui text="Label" >}}.
1. From the {{< ui text="Value" >}} dropdown list, select a workflow label.
1. Select {{< ui text="Add to board" >}}.
1. Repeat steps 1-4 for each workflow label.

Your board now has lists for each workflow state, though they'll be empty until you add issues in later steps.

![Issue board called "Team stand-up" with workflow lists but no issues.](img/team_standup_board_with_workflow_lists_v17_8.png)

## Configure your board lists

You can customize your board by setting filters that apply to all lists.
For example, you can show issues only from the current iteration or with specific labels.

To configure your board:

1. On your team stand-up board, select {{< ui text="Boards|Configure board" >}} ({{< icon name="settings" >}}).
1. Complete any of these fields to filter issues:
   - {{< ui text="BoardScope|Milestone" >}}: to show issues from a specific milestone.
   - {{< ui text="BoardScope|Assignee" >}}: to show issues assigned to specific team members.
   - {{< ui text="BoardScope|Labels" >}}: to show issues with specific labels.
   - {{< ui text="BoardScope|Weight" >}}: to show issues with specific weight values.
   - {{< ui text="BoardScope|Iteration" >}}: to show issues from the current iteration.
1. Select {{< ui text="Save changes" >}}.

Your board now shows only issues that match your filters.
For example, if you select a milestone, only issues assigned to that milestone appear in the board lists.

![Issue board called "Team stand-up" with workflow lists.](img/team_standup_board_with_workflow_lists_v17_8.png)

## Create issues for team tasks

You can create issues directly from your board during the team stand-up.

To create an issue:

1. On your team stand-up board, in the `workflow::ready for development` list, select {{< ui text="Boards|Create new issue" >}} ({{< icon name="plus" >}}).
1. Complete the fields:
   - In {{< ui text="Title" >}}, enter `Redesign user profile page`
   - From the {{< ui text="BoardNewIssue|Projects" >}} dropdown list, select **Paperclip Software Factory / Paperclip Assistant**
1. Select {{< ui text="Create issue" >}}.

The issue is created with the `workflow::ready for development` label because you created it in that list.

### Add metadata to the issue

1. On the issue card, select anywhere except the title.
1. In the right sidebar, in the field you want to update, select {{< ui text="Edit" >}}.
1. Select your changes.
1. Select any area outside the field to save.

Congratulations!
You've set up a team stand-up board that helps track work and facilitate discussions.
Your team can now use this board to run effective stand-ups.

## Related topics

- [Plan and track work tutorials](../plan_and_track.md)
- [Tutorial: Facilitate stand-ups, retrospectives, and velocity tracking](../scrum_events/standups_retrospectives_velocity.md)
