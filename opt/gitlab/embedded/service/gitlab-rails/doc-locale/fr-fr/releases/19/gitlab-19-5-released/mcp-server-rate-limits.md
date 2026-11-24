---
title: "Nouvelles limites de débit pour le serveur MCP de GitLab"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server/#rate-limits"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/22800
categories: [ Agent Tools ]
level: secondary
weight: 50
---

Si vous connectez un agent à GitLab via MCP aujourd'hui, rien ne l'empêche de se reconnecter ou de réessayer plus rapidement que votre workflow n'en a réellement besoin, et sur GitLab.com, cela a un coût. 

À partir du 15 octobre, le serveur MCP de GitLab sur GitLab.com limite chaque utilisateur à 60 requêtes par minute sur l'édition Gratuite et à 600 sur GitLab Premium et GitLab Ultimate. Chaque reconnexion et chaque nouvelle tentative sont comptabilisées dans votre limite de débit. Si votre agent commence à recevoir des erreurs de limite de débit (HTTP 429), vérifiez ses paramètres de reconnexion et de nouvelle tentative avant de passer à une édition supérieure.
