---
title: "Sélection de l'ensemble d'outils du serveur MCP"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server/#select-tool-groups-toolsets"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/607755
categories: [ Agent Tools ]
level: secondary
weight: 50
---

Vous pouvez désormais choisir quels ensembles d'outils le serveur MCP GitLab expose. Chaque outil supplémentaire non nécessaire gaspille de l'espace dans la fenêtre de contexte du LLM et risque de le perturber, en particulier si vous utilisez plusieurs serveurs MCP simultanément.
