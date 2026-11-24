---
title: Les runners hébergés pour GitLab Dedicated sont désormais en disponibilité générale
tier: [ Ultimate ]
offering: [ gitlab_dedicated ]
stage: production_engineering
documentation_link: "../../../administration/dedicated/hosted_runners"
work_item: https://gitlab.com/gitlab-com/gl-infra/gitlab-dedicated/transistor/-/merge_requests/834
categories: [ GitLab Hosted Runners ]
level: secondary
weight: 50
---

Les runners hébergés pour GitLab Dedicated sont désormais en disponibilité générale. GitLab provisionne, corrige et adapte les runners pour vous, dans le même périmètre de sécurité et de conformité que votre instance GitLab Dedicated.

Les fonctionnalités clés incluent :

- Instances AWS EC2 dans la même région que votre instance GitLab Dedicated, s'exécutant dans des VM mono-locataires éphémères détruites après chaque job
- Connexion PrivateLink sortante sécurisée vers votre instance GitLab
- Runners Linux x86-64 et Arm64 en cinq tailles, de small à 2X-large
- SLA de disponibilité à 99,9 %, calculé séparément du SLA de votre instance GitLab Dedicated, pour garantir la stabilité, la résilience et la continuité de vos workflows

Vous créez et gérez vous-même les runners hébergés dans Switchboard, et ne payez que ce que vous utilisez, avec un suivi de l'utilisation dans le tableau de bord GitLab Credits. Pour commencer, contactez votre responsable du succès client ou votre représentant de compte.
