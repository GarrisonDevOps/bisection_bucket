---
title: "Résolution des dépendances pour l'analyse SBOM Gradle"
stage: software_supply_chain_security
level: secondary
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
documentation_link: "../../../user/application_security/dependency_scanning/dependency_scanning_sbom/#dependency-resolution"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/590734"
categories: [ Software Composition Analysis ]
weight: 30
---

L'analyse des dépendances GitLab utilisant la SBOM génère désormais automatiquement un graphe de dépendances (`gradle.graph.txt`) pour les projets Gradle. Auparavant, l'analyse des dépendances Gradle nécessitait que vous génériez manuellement un graphe de dépendances dans le cadre de votre build. Désormais, lorsqu'un fichier de graphe n'est pas disponible, l'analyseur en génère un automatiquement, supprimant cette étape manuelle pour les projets Java et Kotlin utilisant Gradle.
