---
title: Read GitLab Pages content with the MCP server
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools/#get_pages_content"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/617718
categories: [ Agent Tools ]
co_create: true
weight: 50
---

In previous versions of GitLab, the GitLab MCP server could read a Pages site's source, but not
the site your pipeline built from it. With the `get_pages_content` tool, the GitLab MCP server reads the published content of a Pages URL for you,
including private Pages sites you have permission to view.

Thank you to [Mawueli](https://gitlab.com/mawueli) for this contribution!
