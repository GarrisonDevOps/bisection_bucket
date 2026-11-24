---
title: Le suivi des branches non par défaut est désormais généralement disponible
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/vulnerability_report/#tracking-vulnerabilities-across-contexts"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/3430
categories: [ Vulnerability Management ]
level: primary
weight: 50
---

Le suivi des branches non par défaut est désormais généralement disponible. Vous pouvez suivre les vulnérabilités sur des branches autres que la branche par défaut. Pour de meilleurs résultats, ciblez un petit nombre de branches de release à longue durée de vie, telles que des branches pour des environnements spécifiques (`project-qa`, `project-prod`) ou des plateformes de déploiement (`project-iOS`, `project-android`).

Ce release inclut les fonctionnalités suivantes :

- Suivez trois branches ou tags supplémentaires sur la page de configuration de la sécurité. Cela s'ajoute à la branche suivie par défaut.
- Filtrez par ref suivie dans le rapport de vulnérabilités.
- Filtrez par branche dans le tableau de bord de sécurité au niveau du projet.
- Mettez à jour le statut de vulnérabilité sur les branches suivies.
- Les politiques de gestion des vulnérabilités évaluent chaque branche suivie séparément et mettent à jour uniquement les vulnérabilités sur cette branche.

Sur GitLab Self-Managed, les filtres de ref et de branche suivies nécessitent la [gestion avancée des vulnérabilités](../../../user/application_security/vulnerability_report/_index.md#advanced-vulnerability-management).
