---
title: Pré-enregistrer des applications OAuth MCP
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server#reuse-a-pre-registered-oauth-application"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/601437
categories: [ Agent Tools ]
level: secondary
weight: 50
---

Auparavant, la portée `mcp` était masquée dans le formulaire des applications OAuth de la zone **Admin**, ce qui vous empêchait de pré-enregistrer une application OAuth pour vos clients MCP sans recourir à l'enregistrement dynamique de client (DCR). Vous pouvez désormais créer une application OAuth partagée avec la portée `mcp` directement depuis la zone **Admin**, offrant à vos utilisateurs un ID client stable à réutiliser et vous aidant à éviter les limites de débit DCR sur les réseaux partagés.
