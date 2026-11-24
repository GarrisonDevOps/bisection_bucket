---
title: "Validation d'agent personnalisé"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/duo_agent_platform/agents/custom"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/601986
categories: [ AI Catalog Creation ]
level: secondary
weight: 50
---

Auparavant, il était possible d'enregistrer un agent personnalisé dans le catalogue d'IA dont le prompt échouait à l'exécution. Par exemple, les prompts qui déclenchaient des règles de sécurité provoquaient l'inaction silencieuse de l'agent lors de son utilisation.

Désormais, lorsque vous créez ou mettez à jour un agent personnalisé, GitLab valide la configuration du prompt et vous signale toute erreur avant que vous n'enregistriez cet agent.
