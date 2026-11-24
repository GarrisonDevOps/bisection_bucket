---
title: Workspace subagents are generally available
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/duo_agent_platform/customize/workspace_subagents/"
work_item: https://gitlab.com/groups/gitlab-org/modelops/applied-ml/code-suggestions/-/work_items/75
categories: [ Duo Developer, Flow Components ]
level: secondary
weight: 50
---

Workspace subagents, previously released as an experiment, are now generally available.

Use workspace subagents to keep the details of a task, like linter output, out of the context of the Developer Flow.
Or use them for a separate agent with its own instructions and limited tools.

Define subagents as Markdown files in the `.agents/agents/` directory at the root of your repository.
The Developer Flow decides when to delegate a task to one, and receives only the result.

In GitLab Duo CLI 10.2.0 or later, use `/agents` to list subagents and ask the Developer Flow to use one.
In an issue or merge request comment, mention the Developer Flow and ask it to list subagents or delegate a task to one.
