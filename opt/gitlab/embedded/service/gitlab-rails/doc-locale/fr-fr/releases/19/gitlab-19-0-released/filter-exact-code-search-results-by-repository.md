---
title: Filtrer les résultats de recherche de code exact par dépôt
stage: ai-powered
level: secondary
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed ]
documentation_link: "../../../user/search/exact_code_search/#syntax"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/488467"
categories: [ Global Search ]
weight: 20
---

Vous pouvez désormais filtrer les résultats de recherche de code exact par dépôt. Avec la syntaxe `repo:`, vous pouvez définir directement la portée de votre requête de recherche sur des dépôts ou des modèles de dépôts spécifiques sans avoir à accéder aux projets individuels.

Par exemple, rechercher `def authenticate repo:my-group/my-project` renvoie des résultats uniquement depuis ce dépôt. Vous pouvez également utiliser des chemins partiels ou des modèles pour correspondre à plusieurs dépôts.
