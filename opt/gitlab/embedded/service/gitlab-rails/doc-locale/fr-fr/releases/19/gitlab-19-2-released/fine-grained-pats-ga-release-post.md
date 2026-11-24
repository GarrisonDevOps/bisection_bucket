---
title: "Disponibilité générale des autorisations affinées des jetons d'accès personnels (PAT)"
tier: [Free, Premium, Ultimate]
offering: [gitlab_com, self_managed, gitlab_dedicated]
stage: software_supply_chain_security
documentation_link: "../../../auth/tokens/fine_grained_access_tokens/"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/18554"
categories: [Permissions]
weight: 50
---

Les jetons d'accès personnels (PAT) à granularité fine sont désormais en disponibilité générale. Contrairement aux PAT classiques, qui accordent l'accès à l'ensemble des projets et des groupes auxquels vous appartenez, les PAT à granularité fine vous permettent de limiter chaque jeton à des ressources et des actions spécifiques. Cette approche facilite l'application du principe du moindre privilège à l'automatisation et aux intégrations, contribuant ainsi à réduire l'impact potentiel d'un jeton compromis ou divulgué.

Pour simplifier la configuration, utilisez la fonctionnalité **Ajouter des autorisations avec Duo** afin de sélectionner les autorisations appropriées lors de la création du jeton. Vos PAT classiques existants continuent de fonctionner comme auparavant. Pour les nouveaux jetons, GitLab recommande les PAT à granularité fine afin que chaque jeton soit limité uniquement aux ressources et aux actions dont il a besoin.

Avec la release en disponibilité générale, les PAT à granularité fine offrent désormais une couverture complète pour les endpoints de l'API REST, ainsi qu'une couverture des types et mutations GraphQL les plus couramment utilisés.
