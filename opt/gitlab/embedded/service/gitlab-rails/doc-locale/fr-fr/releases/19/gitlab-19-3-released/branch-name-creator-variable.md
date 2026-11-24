---
title: Les noms de branche peuvent inclure le nom de la personne qui a créé la branche
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: create
co_create: true
documentation_link: "../../../user/project/repository/branches/#configure-default-pattern-for-branch-names-from-issues"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/247356
categories: [ Source Code Management ]
level: secondary
---

Vous pouvez inclure le créateur dans les modèles de noms de branche avec une nouvelle variable `%{branch_creator}`, afin qu'une branche créée à partir d'un ticket puisse identifier qui l'a créée plutôt que de recourir à un nom générique.

Merci à [Radek Antoniuk](https://gitlab.com/rantoniuk) pour cette contribution !
