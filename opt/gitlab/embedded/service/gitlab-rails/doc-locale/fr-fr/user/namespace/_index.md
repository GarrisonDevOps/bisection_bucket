---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Espaces de nommage
description: "En savoir plus sur les différents types d'espaces de nommage."
---

Les espaces de nommage organisent les projets dans GitLab. Comme chaque espace de nommage est distinct, vous pouvez utiliser le même nom de projet dans plusieurs espaces de nommage.

Lorsque vous choisissez un nom pour votre espace de nommage, gardez à l'esprit :

- [Règles de nommage](../reserved_names.md#rules-for-usernames-project-and-group-names-and-slugs)
- [Noms de groupes réservés](../reserved_names.md#reserved-group-names)

> [!note]
> Les espaces de nommage contenant un point (`.`) causent des problèmes avec la validation du certificat SSL et le chemin source lors de la [publication de modules Terraform](../packages/terraform_module_registry/_index.md#publish-a-terraform-module).

## Types d'espaces de nommage {#types-of-namespaces}

GitLab dispose de deux types d'espaces de nommage :

- **Utilisateur ou utilisatrice** : votre espace de nommage personnel est basé sur votre nom d'utilisateur. Dans un espace de nommage personnel :
  - Vous ne pouvez pas créer de sous-groupes.
  - Les groupes auxquels vous appartenez n'héritent pas des autorisations ou des fonctionnalités de votre espace de nommage personnel.
  - Tous les projets que vous créez sont dans la portée de cet espace de nommage.
  - Les modifications apportées à votre nom d'utilisateur modifient également les URL des projets et des espaces de nommage. Avant de modifier votre nom d'utilisateur, renseignez-vous sur les [redirections de dépôt](../project/repository/_index.md#repository-path-changes).

- **Groupe** : un espace de nommage de groupe ou de sous-groupe est basé sur le nom du groupe ou du sous-groupe. Dans les espaces de nommage de groupe et de sous-groupe :
  - Vous pouvez créer plusieurs sous-groupes pour gérer plusieurs projets.
  - Les sous-groupes héritent de certains paramètres du groupe parent. Vous pouvez les consulter dans les **Paramètres** du sous-groupe.
  - Vous pouvez configurer les paramètres spécifiquement pour chaque sous-groupe et projet.
  - Vous pouvez gérer l'URL du groupe ou du sous-groupe indépendamment du nom.

## Déterminer le type d'espace de nommage dans lequel vous vous trouvez {#determine-which-type-of-namespace-youre-in}

Pour déterminer si vous vous trouvez dans un espace de nommage de groupe ou personnel, vous pouvez consulter l'URL. Par exemple :

| Espace de nommage pour | URL | Espace de nommage |
| ------------- | --- | --------- |
| Un utilisateur nommé `alex`. | `https://gitlab.example.com/alex` | `alex` |
| Un groupe nommé `alex-team`. | `https://gitlab.example.com/alex-team` | `alex-team` |
| Un groupe nommé `alex-team` avec un sous-groupe nommé `marketing`. |  `https://gitlab.example.com/alex-team/marketing` | `alex-team/marketing` |

## Déterminer l'ID d'espace de nommage {#determine-the-namespace-id}

L'ID d'espace de nommage est l'ID de groupe ou l'ID de projet. Utilisez l'ID de groupe pour interagir avec les groupes et l'ID de projet pour interagir avec les projets.

Vous pouvez trouver l'ID de groupe et l'ID de projet dans l'interface utilisateur :

- [Trouver l'ID de groupe](../group/_index.md#find-the-group-id).
- [Trouver l'ID de projet](../project/working_with_projects.md#find-the-project-id).
