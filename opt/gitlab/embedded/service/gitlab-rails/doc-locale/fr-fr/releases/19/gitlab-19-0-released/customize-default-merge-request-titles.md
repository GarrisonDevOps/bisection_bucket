---
title: Personnaliser les titres par défaut des merge requests
stage: create
level: secondary
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed ]
documentation_link: "../../../user/project/merge_requests/title_templates/"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/16080"
categories: [ Code Review Workflow ]
weight: 100
---

Dans les versions précédentes de GitLab, le titre par défaut d'une nouvelle merge request provenait de la branche source ou du premier commit, et vous ne pouviez pas imposer une convention de nommage cohérente dans votre projet.

Vous pouvez désormais configurer un template de titre de merge request par défaut par projet. Les templates prennent en charge des variables pour la branche source, la branche cible, le sujet du premier commit, l'identifiant du ticket lié, le titre du ticket et une version lisible par un humain du nom de la branche source. Par exemple, le template `Resolve %{issue_id} "%{issue_title}"` produit des titres tels que `Resolve 123 "Fix login bug"`. Vous pouvez toujours modifier le titre avant de créer la merge request.
