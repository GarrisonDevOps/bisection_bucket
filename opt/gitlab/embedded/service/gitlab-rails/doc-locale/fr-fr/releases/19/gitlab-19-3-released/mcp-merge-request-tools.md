---
title: Nouveaux outils MCP pour lire et rechercher des merge requests
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/605878
categories: [ Agent Tools ]
level: secondary
weight: 50
---

Vous pouvez désormais utiliser `get_merge_request` pour récupérer une merge request avec ses diffs, commits, notes, pipelines ou discussions en un seul appel, de sorte que votre agent d'IA n'a plus besoin d'enchaîner plusieurs requêtes pour obtenir une vue complète d'une MR.

Vous pouvez également utiliser le nouvel outil `list_merge_requests` pour rechercher et filtrer les merge requests par auteur, assigné, relecteur, état, labels ou requête en texte libre, ce qui vous permet de trouver facilement les MR qui vous intéressent sans quitter votre workflow.
