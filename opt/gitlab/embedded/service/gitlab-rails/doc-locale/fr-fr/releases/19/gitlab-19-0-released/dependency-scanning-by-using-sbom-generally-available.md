---
title: "L'analyse des dépendances par SBOM est désormais en disponibilité générale"
stage: software_supply_chain_security
level: primary
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
documentation_link: "../../../user/application_security/dependency_scanning/dependency_scanning_sbom/"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/20456"
categories: [ Software Composition Analysis ]
weight: 50
---

L'analyseur des dépendances basé sur la nomenclature logicielle (SBOM) de GitLab est désormais en disponibilité générale. Les projets Maven, Gradle et Python disposent d'une visibilité complète sur les vulnérabilités dans l'ensemble de leur arbre de dépendances, y compris les paquets vulnérables introduits de manière transitive, et pas seulement ceux déclarés directement.

L'analyseur inclut désormais la résolution automatique des dépendances pour les projets Maven, Gradle et Python. Lorsqu'un fichier de verrouillage ou un graphe de dépendances résolu n'est pas présent, l'analyseur invoque automatiquement des outils pour résoudre le graphe de dépendances transitif complet avant l'analyse. La résolution des dépendances est activée par défaut et nécessite peu ou pas de configuration supplémentaire au-delà de l'inclusion du template Dependency Scanning v2.

Pour les projets où la résolution des dépendances n'est pas possible, l'analyseur bascule vers l'analyse des manifestes. Il analyse `pom.xml`, `requirements.txt`, `build.gradle` et `build.gradle.kts` pour identifier les dépendances directes. L'analyse des manifestes garantit que les équipes disposent toujours d'un point de départ pour la couverture des vulnérabilités, même pour les projets sans fichiers de verrouillage ou de build.

L'analyse des manifestes est activée par défaut et renvoie uniquement les dépendances directes. Pour une couverture transitive complète, activez la résolution des dépendances ou fournissez manuellement un fichier de verrouillage de dépendances ou un export de graphe.
