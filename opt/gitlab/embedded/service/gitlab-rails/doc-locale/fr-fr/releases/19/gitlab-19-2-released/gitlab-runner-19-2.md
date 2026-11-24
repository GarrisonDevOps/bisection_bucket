---
title: GitLab Runner 19.2
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
documentation_link: https://docs.gitlab.com/runner
work_item: https://gitlab.com/gitlab-org/gitlab-runner/-/issues/?milestone_title=19.2&state=closed
categories: [ GitLab Runner Core ]
level: secondary
---

Nous publions également GitLab Runner 19.2 aujourd'hui ! GitLab Runner est l'agent de build hautement évolutif qui exécute vos jobs CI/CD et envoie les résultats à une instance GitLab. GitLab Runner fonctionne en conjonction avec GitLab CI/CD, le service d'intégration continue open source inclus avec GitLab.

**Nouveautés**

- [GitLab Runner émet désormais la clé d'environnement lors de la requête PUT de fin de job](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39463)
- [GitLab Runner inclut désormais un disjoncteur qui bascule automatiquement vers Rails lorsque les requêtes de job KAS échouent de manière consécutive](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39389)

**Corrections de bugs**

- [Les échecs de résolution de secrets sont mal classifiés en tant que `runner_system_failure`](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39573)
- [Les jobs échouent avec `context deadline exceeded` lors de la mise à jour de GitLab Runner vers la version 19.1.0](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39556)
- [Les jobs échouent de manière intermittente avec `context deadline exceeded` dans l'exécuteur Docker](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39555)
- [Les téléchargements d'artefacts échouent lorsque `FF_CONCRETE` est activé](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39475)
- [L'histogramme de latence `GetJob` du KAS Job Router n'affiche aucune donnée en staging](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39388)
- [La rotation automatique du token de runner entraîne l'élimination des instances actives par l'exécuteur Docker Autoscaler et l'échec des jobs en cours](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39380)

La liste de toutes les modifications se trouve dans le [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/19-2-stable/CHANGELOG.md) de GitLab Runner.
