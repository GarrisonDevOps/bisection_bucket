---
title: Personnaliser les profils de configuration de sécurité
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/configuration/security_configuration_profiles/"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/20198
categories: [ Security Testing Configuration, Secret Detection, SAST, Software Composition Analysis ]
weight: 50
---

Vous pouvez désormais personnaliser les profils de détection des secrets et SAST dans l'interface utilisateur. Définissez une seule fois les options d'analyse, telles que les chemins exclus, les images d'analyseur personnalisées et les analyses complètes de l'historique Git pour un groupe, puis appliquez-les à tous ses projets.

Auparavant, un profil de configuration de sécurité activait un scanner avec ses paramètres par défaut. Toute configuration allant au-delà des paramètres par défaut nécessitait des modifications de `.gitlab-ci.yml` dans chaque projet. Désormais, le profil inclut également ces paramètres.

Actuellement, la personnalisation des profils d'analyse des dépendances n'est disponible que via l'API GraphQL. La personnalisation via l'interface utilisateur est prévue dans une prochaine release.
