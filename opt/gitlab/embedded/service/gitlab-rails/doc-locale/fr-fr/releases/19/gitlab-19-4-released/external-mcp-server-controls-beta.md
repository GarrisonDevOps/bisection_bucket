---
title: "Restreindre l'accès aux serveurs MCP (version bêta)"
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: software_supply_chain_security
documentation_link: "../../../user/ai-governance/tool-governance/#block-model-context-protocol-mcp-servers"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/628378
categories: [ AI Governance ]
level: primary
weight: 50
---

Vous pouvez désormais restreindre l'accès aux serveurs MCP (Model Context Protocol) en autorisant ou en refusant l'accès à :

- Un serveur MCP externe dans son intégralité.
- Des outils individuels sur un serveur MCP.

Cette fonctionnalité vous garantit que les agents d'IA au sein de Duo Agent Platform opèrent dans des limites gouvernées et ne peuvent accéder qu'aux outils MCP relevant de leur portée pour exécuter leurs activités, sessions et tâches.

Ces contrôles s'appliquent de manière cohérente partout où les agents d'IA s'exécutent, notamment :

- Agentic Chat.
- Flows.
- Environnements IDE et interface de ligne de commande.

Cette fonctionnalité est actuellement en version bêta et nous accueillons vos retours dans le [ticket #628378](https://gitlab.com/gitlab-org/gitlab/-/issues/628378).
