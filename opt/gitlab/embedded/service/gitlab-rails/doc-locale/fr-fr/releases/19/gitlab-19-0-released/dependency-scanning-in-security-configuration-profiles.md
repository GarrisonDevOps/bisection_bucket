---
title: Analyse des dépendances dans les profils de configuration de sécurité
stage: security_risk_management
level: secondary
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
documentation_link: "../../../user/application_security/configuration/security_configuration_profiles/"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/19952"
categories: [ Security Testing Configuration ]
weight: 20
---

GitLab 18.11 a introduit des profils de configuration de sécurité pour SAST et la détection des secrets. Désormais, l'analyse des dépendances est également disponible avec le profil **Analyse des dépendances – par défaut**. Ce profil vous offre une surface de contrôle unifiée pour appliquer une couverture SCA standardisée à tous vos projets sans modifier un seul fichier de configuration CI/CD.

Le profil active deux déclencheurs d'analyse :

- **Pipelines de merge request** : exécute automatiquement une analyse des dépendances à chaque fois que de nouveaux commits font l'objet d'un push vers une branche avec une merge request ouverte. Les résultats incluent uniquement les nouvelles vulnérabilités introduites par la merge request.
- **Pipelines de branche (branche par défaut uniquement)** :  s'exécute automatiquement lorsque des modifications sont fusionnées ou font l'objet d'un push vers la branche par défaut, offrant une vue complète de la posture des dépendances de votre branche par défaut.
