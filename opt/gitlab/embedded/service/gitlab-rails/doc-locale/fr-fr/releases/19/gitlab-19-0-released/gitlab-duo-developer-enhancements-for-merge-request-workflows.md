---
title: Améliorations de GitLab Duo Developer pour les workflows de merge request
stage: ai-powered
level: primary
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
documentation_link: "../../../user/project/merge_requests/developer/"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228817"
categories: [ Duo Developer ]
weight: 40
---

GitLab Duo Developer prend désormais en charge plusieurs méthodes de déclenchement : assignez-le à un ticket, sélectionnez **Générer une merge request**, ou utilisez `@mention` dans n'importe quel fil de discussion de ticket ou de merge request pour transformer les retours, les tâches de la liste des pense-bêtes et les questions de conception en modifications de code, merge requests de suivi ou résumés de recherche.

Avec `AGENTS.md` et `agent-config.yml` configurés, GitLab Duo Developer exécute vos tests et vérifications avant de faire un commit. Après qu'un administrateur de groupe principal ou d'instance active le flow Developer, GitLab ajoute automatiquement des déclencheurs de mention et d'assignation aux projets éligibles.
