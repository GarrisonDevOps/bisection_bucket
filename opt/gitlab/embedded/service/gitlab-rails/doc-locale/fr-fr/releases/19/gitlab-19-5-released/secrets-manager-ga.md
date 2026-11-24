---
title: GitLab Secrets Manager est désormais disponible en version générale
tier: [ Premium, Ultimate ]
add_ons: ["GitLab Secrets Manager"]
offering: [ gitlab_com, self_managed ]
stage: software_supply_chain_security
documentation_link: "../../../ci/secrets/secrets_manager/"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/10723
categories: [ Secrets Management ]
level: primary
weight: 20
---

Sans store de secrets centralisé, les identifiants peuvent se retrouver dispersés dans des variables CI/CD trop larges en portée, des fichiers de configuration locaux et des coffres-forts isolés. Cela les rend plus difficiles à gérer, protéger et auditer.

GitLab Secrets Manager est désormais disponible en version générale sur GitLab.com et GitLab Self-Managed. Basé sur OpenBao, il utilise vos autorisations de groupe et de projet existantes, ce qui évite de devoir maintenir un modèle d'accès distinct. Chaque secret CI est limité en portée au job qui en a besoin, selon l'environnement, la branche et les règles de protection de branche. Des journaux d'audit sont générés pour chaque opération de création, lecture, mise à jour et suppression.

GitLab Secrets Manager consomme des GitLab Credits. [Commencer un essai gratuit de 30 jours](../../../ci/secrets/secrets_manager/credit_usage.md#start-a-trial) ou [l'activer pour votre groupe ou votre instance](../../../ci/secrets/secrets_manager/_index.md#enable-gitlab-secrets-manager).
