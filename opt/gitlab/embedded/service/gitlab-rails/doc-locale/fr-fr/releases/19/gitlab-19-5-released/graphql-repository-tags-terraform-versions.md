---
title: Tags de dépôt et états Terraform dans GraphQL
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
co_create: true
documentation_link: "../../../api/graphql/reference/#repositorytags"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255229
categories: [ Source Code Management ]
level: secondary
weight: 40
---

GraphQL expose désormais `Repository.tags`, avec pagination en avant, recherche et un enum `TagSort` pour l'ordre par nom, mise à jour et version, avec jusqu'à 100 tags par page. `Repository.tags` est une version expérimentale dans GitLab 19.5. `TerraformState.versions` répertorie les versions d'un état, de la plus récente à la plus ancienne. L'API REST des merge requests renvoie désormais `author.bot` dans les réponses simples et en liste, afin qu'un client puisse distinguer les auteurs bots des auteurs comptes de service sans effectuer un deuxième appel à l'API Utilisateurs.

Merci aux utilisateurs suivants pour leurs contributions !

- [Jeston Singh](https://gitlab.com/sjestonsingh) ([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255229) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255230))
- [Ivane Gkomarteli](https://gitlab.com/ivane_gkomarteli) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256381))
