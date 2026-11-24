---
title: "Pushs inter-projets à l'aide de jetons de job CI/CD"
stage: verify
level: secondary
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
documentation_link: "../../../ci/jobs/ci_job_token/#allow-cross-project-git-push-requests-from-allowlisted-projects"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/issues/479907"
categories: [ Continuous Integration (CI) ]
weight: 120
---

Dans les versions précédentes de GitLab, vous ne pouviez utiliser un jeton de job CI/CD (`CI_JOB_TOKEN`) que pour effectuer un push vers le même dépôt où le pipeline s'exécute. Les pushs entre projets nécessitaient un jeton d'accès personnel ou un jeton de déploiement.

Vous pouvez désormais utiliser un jeton de job pour effectuer un push vers un autre projet lorsque :

1. Le projet cible l'accepte.
1. L'utilisateur qui démarre le pipeline dispose au moins du rôle Développeur dans le projet cible.

Cette fonctionnalité est protégée par le feature flag `allow_push_to_allowlisted_projects`, désactivé par défaut dans GitLab 19.0. Demandez à votre administrateur de l'activer.
