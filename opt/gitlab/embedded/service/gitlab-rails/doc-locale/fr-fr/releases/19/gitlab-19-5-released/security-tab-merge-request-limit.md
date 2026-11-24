---
title: Comparaisons précises des rapports de sécurité des merge requests
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/project/merge_requests/reports/#security-scan-report"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/628421
categories: [ Vulnerability Management ]
---

Dans les versions précédentes de GitLab, si un scan comportait plus de 25 résultats d'une même gravité, le rapport de sécurité n'en comparait que 25 par pipeline. Des résultats inchangés pouvaient apparaître comme nouveaux ou corrigés.

Désormais, le rapport compare jusqu'à 1 000 résultats par gravité, ce qui améliore la précision des listes des nouveaux résultats et des résultats corrigés.
