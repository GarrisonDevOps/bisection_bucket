---
title: Les flows personnalisés GitLab Duo sont désormais en disponibilité générale
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/duo_agent_platform/flows/custom"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/602415
categories: [ AI Catalog Creation ]
level: primary
weight: 10
---

Les flows personnalisés sont des workflows alimentés par l'IA que vous créez et configurez pour automatiser des tâches complexes à plusieurs étapes dans vos projets GitLab. Ils permettent aux équipes de définir les étapes du workflow, les composants et les déclencheurs afin que les tâches de développement et opérationnelles répétitives puissent s'exécuter automatiquement en réponse aux événements GitLab. Dans l'interface GitLab, les flows s'exécutent directement dans GitLab CI/CD, aidant les équipes à automatiser les tâches courantes sans quitter GitLab.

Les fonctionnalités clés incluent :

- Workflows définis en YAML et réutilisables pour l'automatisation spécifique aux équipes
- Orchestration multi-agents pour les tâches complexes et à plusieurs étapes
- Points de contrôle humain dans la boucle (HITL) définis par l'utilisateur pour l'approbation ou les retours aux étapes sensibles
- Déclencheurs GitLab natifs, incluant les mentions, les assignations, les événements de pipeline et les événements du cycle de vie des merge requests
- Création et gestion des flows depuis les projets ou le catalogue d'IA
- Contrôles de visibilité publique et privée
- Exécution sécurisée à l'aide de comptes de service et d'une identité composite
- Validation YAML pour détecter les problèmes de configuration avant l'exécution
