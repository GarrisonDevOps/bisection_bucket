---
title: Désactiver les modèles de projets intégrés
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
documentation_link: "../../../administration/project_templates#built-in-project-templates"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/21356
categories: [ Source Code Management ]
level: secondary
weight: 50
---

Lorsque les organisations s'appuient sur des modèles de projets personnalisés, les modèles intégrés des fournisseurs peuvent parasiter l'expérience de sélection des modèles et, dans certains cas, contourner les hooks côté serveur ou d'autres contrôles du dépôt.

Les administrateurs peuvent désormais désactiver les modèles de projets intégrés globalement depuis la zone **Admin**, ou au niveau du groupe pour les sous-groupes. Le paramètre se propage automatiquement, ce qui vous évite de le configurer pour chaque groupe individuellement. Les administrateurs peuvent imposer la valeur du paramètre afin de s'assurer que les groupes ou sous-groupes ne peuvent pas le remplacer. Les paramètres de l'instance et du groupe sont également gérables via les API REST et GraphQL. Sur GitLab.com, seul le paramètre au niveau du groupe est disponible.
