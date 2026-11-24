---
title: "Annuler la fusion automatique depuis l'API REST"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
co_create: true
documentation_link: "../../../api/merge_requests/#cancel-auto-merge"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255702
categories: [ Code Review Workflow ]
level: secondary
weight: 20
---

Vous pouvez désormais annuler une fusion automatique active avec le point de terminaison d'API `cancel_auto_merge`. Si la merge request se trouve sur un merge train, l'appel la supprime également du train. L'ancien point de terminaison `cancel_merge_when_pipeline_succeeds` est désormais obsolète.

Par ailleurs, `git push -o merge_request.auto_merge` est désormais rejeté avec un message distant lorsque vous ne pouvez pas fusionner vers la branche cible. Dans les versions précédentes de GitLab, la fusion automatique était enregistrée et laissait la merge request dans un état non fusionnable jusqu'à son annulation.

Merci aux utilisateurs suivants pour leurs contributions !

- [José M. Requena Plens](https://gitlab.com/jmrp) ([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255702) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255704))
- [Bobby Nandigam](https://gitlab.com/bobby-nandigam) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251960))
