---
title: Fail flows when the sandbox is unavailable
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/duo_agent_platform/environment_sandbox/#require-flows-to-run-in-the-sandbox"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/607753
categories: [ AI Agents ]
level: secondary
weight: 50
---

In previous versions of GitLab, a GitLab Duo Agent Platform flow in a runner environment ran without isolation if the sandbox was unavailable, and you saw only a warning.
Now you can [make the job fail instead of running the flow without the sandbox](../../../user/duo_agent_platform/environment_sandbox.md#require-flows-to-run-in-the-sandbox).
