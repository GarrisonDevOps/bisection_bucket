---
title: GitLab Runner 19.3
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
documentation_link: https://docs.gitlab.com/runner
work_item: https://gitlab.com/gitlab-org/gitlab-runner/-/issues/?milestone_title=19.3&state=closed
categories: [ GitLab Runner Core ]
level: secondary
---

Nous publions également GitLab Runner 19.3 aujourd'hui ! GitLab Runner est l'agent de build hautement évolutif qui exécute vos jobs CI/CD et envoie les résultats à une instance GitLab. GitLab Runner fonctionne en conjonction avec GitLab CI/CD, le service d'intégration continue open source inclus avec GitLab.

**Nouveautés**

- [Documenter la matrice de compatibilité des versions de Job Router](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39408)
- [Vérifier que Workhorse se trouve dans le chemin de requête de KAS vers Rails pour Job Router](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39383)

**Corrections de bugs**

- [`clear-docker-cache` supprime toutes les images inutilisées lorsque `IMAGE_FILTER_FLAGS` est vide](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39621)
- [La distribution en mode concret ignore les étapes où `When` n'est pas défini](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39539)
- [`PrintPodWarningEvents` ne fonctionne pas](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/38982)
- [L'exécuteur personnalisé échoue lorsque le dossier `.git` est corrompu](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/27540)

La liste de toutes les modifications se trouve dans le [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/19-3-stable/CHANGELOG.md) de GitLab Runner.
