---
title: "Analyse détaillée de l'utilisation des composants du catalogue CI/CD"
stage: verify
level: secondary
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
documentation_link: "../../../ci/components/#view-component-usage-details"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/579460"
categories: [ Component Catalog ]
weight: 80
---

Lorsque vous gérez un composant CI/CD dans le catalogue CI/CD GitLab, les détails d'utilisation sont essentiels pour gérer les mises à niveau, appliquer la conformité et communiquer les changements cassants. Vous devez savoir quels projets utilisent vos composants CI/CD et quelles versions ils utilisent. Auparavant, ces informations n'étaient pas disponibles, ce qui rendait difficile la notification des bons Chargés de maintenance, la planification des dépréciations en toute sécurité ou la garantie que les projets restent à jour avec les derniers correctifs de sécurité.

La vue des détails d'utilisation des composants CI/CD dans la page des ressources du catalogue affiche désormais exactement quels projets utilisent chaque composant CI/CD, la version qu'ils exécutent et s'ils disposent de la dernière version ou d'une version obsolète. Les projets utilisant des versions plus anciennes sont mis en avant, afin que vous puissiez prioriser la communication, encourager l'adoption des correctifs de sécurité et assurer une mise à niveau en douceur dans toute votre organisation.
