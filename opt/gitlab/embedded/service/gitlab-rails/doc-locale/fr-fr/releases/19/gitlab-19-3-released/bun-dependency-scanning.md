---
title: "Prise en charge de l'analyse des dépendances pour Bun"
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: application_security_testing
documentation_link: "../../../user/application_security/dependency_scanning/dependency_scanning_sbom/#supported-languages-and-files"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/592701
categories: [ Software Composition Analysis ]
level: secondary
---

Dans les versions précédentes de GitLab, les projets utilisant le runtime JavaScript Bun et son gestionnaire de paquets ne bénéficiaient d'aucune couverture d'analyse des dépendances.

Désormais, l'analyse des dépendances GitLab analyse les projets Bun en parsant les fichiers `bun.lock` (le format JSONC texte introduit dans Bun 1.2).

Comme les paquets Bun proviennent du registre npm, la base de données d'avis de sécurité de GitLab couvre déjà ces dépendances sans aucune configuration supplémentaire requise. Les équipes utilisant Bun comme alternative à npm, yarn ou pnpm peuvent désormais analyser leurs projets à la recherche de vulnérabilités connues dans le cadre de leurs pipelines CI/CD standard. Les résultats éligibles sont également pris en charge par la remédiation automatique de l'analyse des dépendances.
