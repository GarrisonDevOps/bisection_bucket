---
title: Déclencher des flows avec une API en disponibilité générale
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../api/duo_agent_platform_flows/#trigger-a-flow"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/607860
categories: [ Agent Tools ]
level: secondary
weight: 50
---

Dans les versions précédentes de GitLab, le point de terminaison de l'API que vous utilisez pour déclencher des flows GitLab Duo Agent Platform depuis des pipelines CI/CD, des scripts et d'autres automatisations était en version expérimentale, ce qui rendait difficile de savoir si vous pouviez vous y fier en production. Désormais, le [point de terminaison de déclenchement de flow](../../../api/duo_agent_platform_flows.md#trigger-a-flow) de l'API Flows est en disponibilité générale, ce qui vous permet de concevoir des automatisations de production en sachant qu'il suit la politique de changements incompatibles de l'API REST GitLab.
