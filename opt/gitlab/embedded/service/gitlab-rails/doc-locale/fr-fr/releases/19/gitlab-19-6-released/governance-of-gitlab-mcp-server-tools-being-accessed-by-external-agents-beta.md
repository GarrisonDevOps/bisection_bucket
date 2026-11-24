---
title: "Gérer les outils du serveur MCP GitLab pour les agents d'IA"
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: software_supply_chain_security
documentation_link: "../../../user/ai-governance/tool-governance/#gitlab-mcp-server-tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/633490
categories: [ AI Governance ]
level: primary
weight: 50
---

Vous pouvez désormais contrôler quels outils du serveur MCP GitLab les agents d'IA peuvent utiliser, grâce à des règles que GitLab applique pour chaque client qui se connecte.

Les propriétaires d'un groupe principal définissent chaque outil sur :

- **Toujours refuser** : l'outil est entièrement bloqué et invisible pour l'agent.
- **Toujours demander** : l'utilisateur doit approuver l'outil avant son exécution.
- **Toujours autoriser** : l'outil s'exécute normalement.

Cette fonctionnalité est en version bêta. Pour transmettre vos commentaires, consultez le [ticket 633490](https://gitlab.com/gitlab-org/gitlab/-/work_items/633490).
