---
title: Business Logic Security Analyzer (version bêta fermée)
tier: [ Ultimate ]
offering: [ gitlab_com ]
stage: application_security_testing
documentation_link: "../../../user/application_security/business_logic_scanning/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/632352
categories: [ SAST ]
level: secondary
---

Business Logic Security Analyzer est un flow par défaut de la plateforme GitLab Duo Agent qui analyse ce que votre code est censé appliquer. Il détecte des vulnérabilités que les analyseurs basés sur des patterns manquent souvent : autorisation au niveau des objets non respectée, contrôles d'autorisation manquants et assignation de masse.

Lancez une analyse de l'ensemble du dépôt depuis GitLab Duo Chat ou l'API. Pour analyser les merge requests automatiquement, associez le profil d'analyse Business Logic à un projet. Les résultats apparaissent dans le rapport de vulnérabilités et le widget de sécurité de la merge request.

Business Logic Security Analyzer est en version bêta fermée pour les clients GitLab Ultimate sur GitLab.com. Pour demander un accès, contactez votre équipe de compte. Chaque analyse consomme des GitLab Credits. Pour les prérequis et la configuration, consultez [Analyse de la logique métier](../../../user/application_security/business_logic_scanning/_index.md).
