---
title: Outils de serveur MCP pour les agents et flows GitLab Duo
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools/#start_duo_session"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/21395
categories: [ Agent Tools ]
level: secondary
weight: 50
---

Les nouveaux outils pour les agents et flows GitLab Duo vous permettent d'invoquer et de suivre des agents et des flows GitLab Duo depuis n'importe quel client MCP :

- `start_duo_session` démarre une session.
- `get_duo_session` lit l'état actuel d'une session.
- `list_duo_sessions` parcourt l'historique de vos sessions.
- `list_duo_agents_and_flows` répertorie les agents et flows GitLab Duo activés dans un projet.
