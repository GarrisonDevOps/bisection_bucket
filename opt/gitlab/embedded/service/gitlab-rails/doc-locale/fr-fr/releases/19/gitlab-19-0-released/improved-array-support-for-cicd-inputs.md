---
title: Amélioration de la prise en charge des tableaux pour les entrées CI/CD
stage: verify
level: secondary
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
documentation_link: "../../../ci/inputs/#access-individual-array-elements"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/issues/587657"
categories: [ Pipeline Composition ]
weight: 60
---

Les entrées CI/CD disposent désormais d'une meilleure prise en charge des tableaux. Utilisez l'opérateur d'index de tableau `[]` pour accéder à des éléments spécifiques dans les entrées CI/CD de type tableau. Cette amélioration offre des capacités d'interpolation d'entrées CI/CD plus flexibles et plus puissantes dans vos configurations de pipeline, vous permettant de référencer directement des éléments individuels d'un tableau sans étapes de traitement supplémentaires.
