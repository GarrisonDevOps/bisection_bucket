---
title: Recommander des relecteurs avec GitLab Duo
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
documentation_link: "../../../user/project/merge_requests/reviews/automatic_reviewer_assignment/#recommend-reviewers-flow"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/20711
categories: [ DAP Code Review ]
level: secondary
weight: 50
---

Dans les versions précédentes de GitLab, vous deviez vérifier chaque règle d'approbation et deviner qui avait le temps de relire votre merge request. Ou vous assigniez un groupe entier en espérant que quelqu'un s'en charge.

Vous pouvez désormais utiliser le Recommend Reviewers Flow pour suggérer des relecteurs. Le flow est en disponibilité générale.

Pour chaque règle d'approbation, il recommande le nombre minimum de relecteurs nécessaires, en fonction de la disponibilité, de la charge de travail, du fuseau horaire et de l'activité récente.

Les recommandations apparaissent dans la section **Recommandé** de la barre latérale de la merge request. Survolez un utilisateur pour voir pourquoi il a été recommandé.

Pour commencer, activez le flow pour votre groupe principal. Il s'exécute lors de la création d'une merge request, ou vous pouvez créer un déclencheur pour l'exécuter lorsqu'un brouillon est marqué comme prêt. Pour obtenir de nouvelles recommandations, sélectionnez **Actualiser**.
