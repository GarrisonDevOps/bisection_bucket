---
title: Start flow sessions faster with a reference repository (Beta)
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/duo_agent_platform/flows/execution/#start-sessions-from-a-reference-repository"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/633571
categories: [ Runner Execution ]
level: secondary
weight: 50
---

In previous versions of GitLab, every flow session cloned your whole repository first, so large projects waited minutes before the agent started.
Now you can include a copy of your repository in the image used for GitLab Duo Agent Platform sessions, so each session fetches only recent commits and starts significantly faster.
