---
title: "Intégrer du code d'un dépôt dans Markdown"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: plan
documentation_link: "../../../user/markdown/#embed-code-from-a-repository"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/300855
categories: [ Markdown ]
level: secondary
weight: 50
---

Dans les versions précédentes de GitLab, les [permaliens](../../../user/project/repository/files/_index.md#create-permalinks) vers les lignes d'un fichier s'affichaient sous forme d'URL simples, ce qui vous obligeait à quitter la merge request, le ticket ou la page wiki pour consulter le code référencé.

Désormais, les permaliens s'affichent sous forme d'extrait de code avec coloration syntaxique, incluant le chemin du fichier et le commit, ce qui vous permet de lire le code sans quitter la page. Vous ne pouvez consulter les extraits de code intégrés que si vous disposez d'un accès en lecture au dépôt.
