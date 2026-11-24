---
title: Audit events for MCP server tool calls
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: software_supply_chain_security
documentation_link: "../../../user/ai-governance/ai-audit-events/#audit-events-for-the-gitlab-mcp-server"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/22496
categories: [ AI Governance ]
level: primary
weight: 50
---

Every action an agent takes through the GitLab MCP server now creates an audit event. You get a record of agent activity without adding any client-side tracking.

Each event records who performed the action, what they did, which resource was affected, and when. Events are also marked as coming from the MCP server, so you can tell agent actions apart from actions people take directly.

To review these events, go to **AI** > **Governance** in your top-level group and select the **Audit events** tab. Security and compliance teams get a complete view of what external agents do in GitLab.
