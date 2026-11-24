---
title: Flow Code Review pour les sièges GitLab Duo Enterprise
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
tier: [ Premium, Ultimate ]
stage: ai_coding
documentation_link: "../../../user/project/merge_requests/duo_in_merge_requests/#turn-on-code-review-flow-for-gitlab-duo-enterprise-seats"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/22247
categories: [ DAP Code Review ]
---

Dans les versions précédentes de GitLab, lorsque des utilisateurs disposant de sièges GitLab Duo Enterprise demandaient une revue de code à GitLab Duo, GitLab Duo Code Review effectuait la revue. Cela se produisait même si le flow Code Review était activé pour le groupe. Il n'existait aucun moyen d'activer le flow agentique pour tous les utilisateurs.

Désormais, les propriétaires de groupe principal peuvent modifier ce comportement par défaut et configurer toutes les revues de code pour utiliser le flow Code Review à la place, quel que soit le siège de l'utilisateur. Toutes les revues consommeront des GitLab Credits.

Cette modification offre aux utilisateurs disposant de sièges GitLab Duo Enterprise la même prise en compte du contexte à l'échelle du dépôt, le même raisonnement en plusieurs étapes et les mêmes sessions de revue que les autres utilisateurs.
