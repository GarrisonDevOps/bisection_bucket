---
title: SAST avancé pour iOS en version bêta
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: application_security_testin
documentation_link: "../../../user/application_security/sast/gitlab_advanced_sast"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/22353"
categories: [ SAST ]
level: secondary
---

<!-- Category: SAST -->

GitLab Advanced SAST prend désormais en charge Objective-C et Swift, apportant la même analyse de contamination interprocédurale que pour les autres langages au développement iOS. La version bêta est disponible pour tous les clients GitLab Ultimate à partir de GitLab 19.3.

La version bêta détecte les principales classes de vulnérabilités du OWASP Mobile Top 10, notamment le stockage de données non sécurisé, la cryptographie défaillante, les communications non sécurisées ainsi que les failles d'authentification et d'autorisation. Lorsqu'une vulnérabilité débute dans un langage et atteint un point de collecte dans l'autre, Advanced SAST détecte le chemin de contamination complet, y compris les chemins qui traversent la frontière entre les langages Swift et Objective-C.

Pour activer la fonctionnalité, définissez `GITLAB_ADVANCED_SAST_ENABLED: 'true'` dans votre pipeline. Si votre projet contient des fichiers Objective-C ou Swift, le job `gitlab-advanced-sast-ext` s'exécute automatiquement. Pour obtenir les instructions de configuration complètes, consultez la [documentation Advanced SAST](../../../user/application_security/sast/gitlab_advanced_sast.md).

Partagez vos retours dans le [ticket de retours sur la version bêta](https://gitlab.com/gitlab-org/gitlab/-/work_items/607091).
