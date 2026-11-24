---
title: "`/goal` command in GitLab Duo Agentic Chat"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_chat/agentic_chat/#start-a-long-running-task-with-the-goal-command"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23107
categories: [ Web Chat ]
level: secondary
weight: 50
---

Previously, GitLab Duo Agentic Chat in the GitLab UI answered one message at a time and waited for you to continue.
For a larger change, like fixing a set of failing tests, you had to keep prompting it.

Now you can start a long-running task with `/goal`.
Agentic Chat starts a Developer Flow session that keeps working until the task is done, so you don't have to prompt after each step.

The flow can commit, push, and create merge requests without asking you to approve each action.
Each goal also uses compute minutes.

To use `/goal`, open Agentic Chat in a project and turn on the Developer Flow for your top-level group.
