---
title: Work item types in MCP project details
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools/#get_project"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/606643
categories: [ Agent Tools ]
co_create: true
weight: 50
---

In previous versions of GitLab, your AI agents needed a separate request to learn which work item types a project supports.
Now your agents get a project's work item types and the fields each type supports in the same request as the [project details](../../../user/model_context_protocol/mcp_server_tools.md#get_project).

Thank you to [Aditya Parida](https://gitlab.com/adityaswarupparida) for this contribution!
