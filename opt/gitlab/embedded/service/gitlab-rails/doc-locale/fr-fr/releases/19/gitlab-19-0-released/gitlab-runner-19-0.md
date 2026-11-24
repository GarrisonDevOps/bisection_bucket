---
title: GitLab Runner 19.0
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
documentation_link: "https://docs.gitlab.com/runner"
work_item: "https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/?milestone_title=19.0&state=closed"
categories: [ GitLab Runner Core ]
level: secondary
weight: 150
---

Nous lançons également GitLab Runner 19.0 aujourd'hui ! GitLab Runner est l'agent de build hautement évolutif qui exécute vos jobs CI/CD et envoie les résultats à une instance GitLab. GitLab Runner fonctionne en conjonction avec GitLab CI/CD, le service d'intégration continue open source inclus avec GitLab.

**Nouveautés**

- [Instrumentation du runner : négociation de fonctionnalités, client d'export OTLP et premier span `job_execution`](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39231)
- [Ajouter un délai d'expiration de l'étape de préparation configurable à la configuration du runner](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/26583)

**Corrections de bugs**

- [Corrections complètes pour l'implémentation du feature flag `FF_SCRIPTS_TO_STEPS`](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39403)
- [Erreur `SignatureDoesNotMatch` lors du téléchargement du cache S3](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39402)
- [Erreur d'exécution lorsque GitLab Runner s'exécute dans AWS avec le cache S3](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39386)
- [Liens de téléchargement RPM S3 corrompus pour `amd64`, `arm64`, `arm` et `armhf` dans GitLab Runner 18.9.0 et versions ultérieures](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39362)
- [Les codes de sortie négatifs sont signalés incorrectement sur Windows](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39292)
- [Documentation incorrecte sur le nommage des conteneurs de services de l'exécuteur Kubernetes](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39235)

La liste de toutes les modifications se trouve dans le [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/19-0-stable/CHANGELOG.md) de GitLab Runner.
