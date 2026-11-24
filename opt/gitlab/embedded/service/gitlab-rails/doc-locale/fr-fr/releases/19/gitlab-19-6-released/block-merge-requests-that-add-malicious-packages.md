---
title: Bloquer les merge requests qui ajoutent des packages malveillants
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/policies/merge_request_approval_policies/#block-malicious-packages-with-the-malware-rule"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/19465
categories: [ Security Policy Management ]
level: secondary
---

Dans les versions précédentes de GitLab, les politiques d'approbation des merge requests traitaient les packages malveillants comme n'importe quelle autre vulnérabilité. Si un résultat était ignoré ou ne correspondait pas aux filtres de gravité d'une règle, un package conçu pour causer des dommages pouvait quand même être fusionné.

Vous pouvez désormais ajouter une règle de détection des malwares à vos politiques d'approbation des merge requests. Lorsque l'analyse des dépendances détecte un package répertorié dans les avis de malwares de GitLab, la merge request requiert une approbation, quelle que soit la gravité ou l'état du résultat. La règle de détection des malwares fonctionne en parallèle de vos règles de résultats d'analyse existantes, ce qui vous permet de l'ajouter aux politiques que vous avez déjà sans les reconstruire.

Pour utiliser la règle de détection des malwares, votre projet doit exécuter [l'analyse des dépendances à l'aide de SBOM](../../../user/application_security/dependency_scanning/dependency_scanning_sbom/_index.md#turn-on-dependency-scanning). Les avis de malwares couvrent les packages npm, PyPI, Maven, Go, NuGet, Cargo et RubyGems.
