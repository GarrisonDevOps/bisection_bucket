---
title: Outil de groupes du serveur MCP
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/607719
categories: [ Agent Tools ]
level: secondary
weight: 50
---

Auparavant, un agent se connectant à GitLab via MCP n'avait aucun moyen de découvrir les groupes et sous-groupes auxquels vous avez accès sans que vous ne codiez en dur des identifiants ou des chemins. Le nouvel outil `list_groups` permet à votre agent de parcourir la hiérarchie de groupes de votre organisation de manière autonome, afin de trouver le bon groupe avant d'agir plutôt que de deviner les identifiants.
