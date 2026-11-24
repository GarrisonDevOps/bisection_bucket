---
title: "Flows d'IA pris en charge sur les branches non par défaut"
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/vulnerability_report/#tracked-ref-filter"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23297
categories: [ Vulnerability Management ]
---

Dans les versions précédentes de GitLab, vous pouviez exécuter les flows Détection de faux positifs SAST, Résolution de vulnérabilités SAST et Détection de faux positifs dans les secrets uniquement sur les vulnérabilités de la branche par défaut.

Désormais, vous pouvez également exécuter ces flows sur les vulnérabilités d'autres branches suivies depuis le rapport de vulnérabilités, afin de les analyser et de les résoudre avant la fusion.
