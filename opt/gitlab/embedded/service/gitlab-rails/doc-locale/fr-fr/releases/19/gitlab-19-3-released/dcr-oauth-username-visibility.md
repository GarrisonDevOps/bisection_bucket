---
title: Voir quel utilisateur a autorisé chaque application MCP OAuth
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/605884
categories: [ AI Agents ]
level: secondary
weight: 50
---

Auparavant, lorsque des clients MCP se connectaient à GitLab via l'enregistrement dynamique de clients OAuth (DCR), toutes les applications OAuth enregistrées dynamiquement apparaissaient dans la zone d'administration avec uniquement un nom de client générique, rendant impossible l'identification de l'utilisateur ayant autorisé une application donnée. Désormais, lorsque vous approuvez une connexion MCP OAuth, votre nom d'utilisateur est automatiquement ajouté au nom de l'application — par exemple, `[Unverified Dynamic Application] kiro — authorized by @username`. Vous pouvez rapidement identifier quel utilisateur se trouve derrière chaque application OAuth dynamique, directement depuis la zone d'administration, sans aucune configuration supplémentaire.
