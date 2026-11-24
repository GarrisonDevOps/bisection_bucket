---
stage: Analytics
group: Global Search
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Recherche dans GitLab
description: "Recherche de base, avancée, exacte, par portée et par SHA de commit."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Trouvez ce dont vous avez besoin dans une base de code en croissance ou une organisation en expansion. Gagnez du temps en recherchant du code spécifique, des éléments de travail, des merge requests et d'autres contenus dans vos projets. Choisissez parmi trois types de recherche selon vos besoins : **recherche de base**, [**recherche avancée**](advanced_search.md) et [**recherche de code spécifique**](exact_code_search.md).

Pour la recherche de code, GitLab utilise ces types dans cet ordre :

- **Recherche de code spécifique** : permet d'utiliser les modes de correspondance exacte et d'expression régulière.
- **Recherche avancée** : utilisée lorsque la recherche de code spécifique n'est pas disponible.
- **Recherche de base** : utilisée lorsque la recherche de code spécifique et la recherche avancée ne sont pas disponibles ou lorsque vous effectuez une recherche sur une branche non définie par défaut. Ce type ne prend pas en charge la recherche de groupe ou globale.

## Portées disponibles {#available-scopes}

{{< history >}}

- La portée Groupes a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249760) dans GitLab 19.4 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `elasticsearch_group_search`. Fonctionnalité désactivée par défaut.
- La portée Groupes est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/607018) dans GitLab 19.5. Le feature flag `elasticsearch_group_search` a été supprimé.

{{< /history >}}

Les portées décrivent le type de données que vous recherchez. Les portées suivantes sont disponibles pour la recherche de base :

| Portée          | Global[^disable-global-search-scopes] |    Groupe    | Projet |
|----------------|:-------------------:|:-----------:|:-------:|
| Code           |     {{< no >}}      | {{< no >}}  | {{< yes >}} |
| Commentaires       |     {{< no >}}      | {{< no >}}  | {{< yes >}} |
| Commits        |     {{< no >}}      | {{< no >}}  | {{< yes >}} |
| Groupes         |     {{< yes >}}     | {{< yes >}} | {{< no >}} |
| Éléments de travail     |     {{< yes >}}     | {{< yes >}} | {{< yes >}} |
| Les merge requests |     {{< yes >}}     | {{< yes >}} | {{< yes >}} |
| Jalons[^global-basic-search] |     {{< yes >}}     | {{< yes >}} | {{< yes >}} |
| Projets       |     {{< yes >}}     | {{< yes >}} | {{< no >}} |
| Utilisateurs          |     {{< yes >}}     | {{< yes >}} | {{< yes >}} |
| les wikis.          |     {{< no >}}      | {{< no >}}  | {{< yes >}} |

[^disable-global-search-scopes]: un administrateur peut [désactiver les portées de recherche globale](#disable-global-search-scopes). [^global-basic-search]: la recherche globale de base renvoie uniquement les jalons de projet, et non les jalons de groupe.

## Spécifier un type de recherche {#specify-a-search-type}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/161999) dans GitLab 17.4.

{{< /history >}}

Pour spécifier un type de recherche, définissez le paramètre d'URL `search_type` comme suit :

- `search_type=zoekt` pour la [recherche de code spécifique](exact_code_search.md)
- `search_type=advanced` pour la [recherche avancée](advanced_search.md)
- `search_type=basic` pour la recherche de base

`search_type` remplace le paramètre obsolète `basic_search`. Pour plus d'informations, consultez [l'issue 477333](https://gitlab.com/gitlab-org/gitlab/-/issues/477333).

## Restreindre l'accès à la recherche {#restrict-search-access}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

{{< history >}}

- La restriction de la recherche globale aux utilisateurs authentifiés a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/41041) dans GitLab 13.4 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `block_anonymous_global_searches`. Fonctionnalité désactivée par défaut.
- L'autorisation de la recherche pour les utilisateurs non authentifiés a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/138975) dans GitLab 16.7 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `allow_anonymous_searches`. Activés par défaut.
- La restriction de la recherche globale aux utilisateurs authentifiés est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/186727) dans GitLab 17.11. Le feature flag `block_anonymous_global_searches` a été supprimé.
- L'autorisation de la recherche pour les utilisateurs non authentifiés est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/190090) dans GitLab 18.0. Le feature flag `allow_anonymous_searches` a été supprimé.

{{< /history >}}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

Par défaut, les requêtes vers `/search` et la recherche globale sont disponibles pour les utilisateurs non authentifiés.

Pour restreindre `/search` aux utilisateurs authentifiés uniquement, effectuez l'une des opérations suivantes :

- [Restreindre les niveaux de visibilité](../../administration/settings/visibility_and_access_controls.md#restrict-visibility-levels) pour le projet ou le groupe. Si les projets publics sont restreints, la recherche globale anonyme est redirigée vers la page de connexion GitLab.
- Restreindre l'accès dans la zone **Admin** :

  1. Dans le coin supérieur droit, sélectionnez **Admin**.
  1. Sélectionnez **Paramètres** > **Rechercher**.
  1. Développez **Recherche avancée**.
  1. Décochez la case **Autoriser les utilisateurs et utilisatrices non authentifiés à utiliser la recherche**.
  1. Sélectionnez **Enregistrer les modifications**.

Pour restreindre la recherche globale aux utilisateurs authentifiés uniquement :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Rechercher**.
1. Développez **Contrôles de visibilité et d'accès**
1. Cochez la case **Restreindre la recherche globale aux utilisateurs et utilisatrices authentifiés uniquement**.
1. Sélectionnez **Enregistrer les modifications**.

## Désactiver les portées de recherche globale {#disable-global-search-scopes}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/179688) dans GitLab 17.9.

{{< /history >}}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

Pour améliorer les performances de la recherche globale de votre instance, vous pouvez désactiver une ou plusieurs portées de recherche. Toutes les portées de recherche globale sont activées par défaut sur les instances GitLab Self-Managed.

Pour désactiver une ou plusieurs portées de recherche globale :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Rechercher**.
1. Développez **Contrôles de visibilité et d'accès**.
1. Décochez les cases correspondant aux portées que vous souhaitez désactiver.
1. Sélectionnez **Enregistrer les modifications**.

## Configurer une portée de recherche par défaut {#configure-a-default-search-scope}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

Par défaut, lorsque les utilisateurs ne sélectionnent pas de portée de recherche, une portée est sélectionnée automatiquement en fonction du contexte et de la disponibilité. Pour configurer une portée de recherche par défaut à la place :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Rechercher**.
1. Développez **Contrôles de visibilité et d'accès**.
1. Dans la liste déroulante **Portée de recherche par défaut**, sélectionnez une portée. Pour une sélection automatique, sélectionnez **Valeur système par défaut (automatique)**.
1. Sélectionnez **Enregistrer les modifications**.

Les utilisateurs peuvent remplacer la portée par défaut en sélectionnant une autre portée. Si la portée par défaut n'est pas disponible (par exemple, le code dans la recherche globale), une portée est sélectionnée automatiquement.

## Validation de la recherche globale {#global-search-validation}

La recherche globale ignore et enregistre comme abusives toutes les recherches qui contiennent :

- Moins de deux caractères
- Un terme de plus de 100 caractères (les termes de recherche dans l'URL ne doivent pas dépasser 200 caractères)
- Uniquement un mot vide (par exemple, `the`, `and` ou `if`)
- Une `scope` inconnue
- `group_id` ou `project_id` qui n'est pas entièrement numérique
- `repository_ref` ou `project_ref` avec des caractères spéciaux non autorisés par [Git refname](https://git-scm.com/docs/git-check-ref-format)

La recherche globale signale uniquement avec une erreur toute recherche qui contient plus de :

- 4 096 caractères
- 64 termes

Les correspondances partielles ne sont pas prises en charge dans la recherche de tickets. Par exemple, lorsque vous recherchez des tickets avec `play`, la requête ne renvoie pas les tickets contenant `display`. Cependant, la requête correspond à toutes les variations possibles de la chaîne (par exemple, `plays`).

## Suggestions de saisie automatique {#autocomplete-suggestions}

{{< history >}}

- L'affichage des utilisateurs uniquement issus des projets et groupes autorisés a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/442091) dans GitLab 17.10 [avec des feature flags](../../administration/feature_flags/_index.md) nommés `users_search_scoped_to_authorized_namespaces_advanced_search`, `users_search_scoped_to_authorized_namespaces_basic_search` et `users_search_scoped_to_authorized_namespaces_basic_search_by_ids`. Fonctionnalité désactivée par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/185577) dans GitLab 17.11. Les feature flags `users_search_scoped_to_authorized_namespaces_advanced_search`, `users_search_scoped_to_authorized_namespaces_basic_search` et `users_search_scoped_to_authorized_namespaces_basic_search_by_ids` ont été supprimés.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par des feature flags. Pour plus d'informations, consultez l'historique.

Lorsque vous tapez dans la zone de recherche, des suggestions de saisie automatique s'affichent pour :

- Projets et groupes
- Utilisateurs des projets et groupes autorisés
- Pages d'aide
- Fonctionnalités de projet (par exemple, les jalons)
- Paramètres (par exemple, les paramètres utilisateur)
- Merge requests récemment consultées
- Éléments de travail récemment consultés
- [Références GitLab Flavored Markdown](../markdown.md#gitlab-specific-references) pour les éléments de travail dans un projet

## Rechercher dans tout GitLab {#search-in-all-gitlab}

Pour effectuer une recherche dans tout GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**.
1. Saisissez votre requête de recherche. Vous devez saisir au moins deux caractères.
1. Appuyez sur <kbd>Entrée</kbd> pour lancer la recherche, ou sélectionnez un élément dans la liste.

Les résultats s'affichent. Pour filtrer les résultats, dans la barre latérale gauche, sélectionnez un filtre.

## Rechercher dans un projet {#search-in-a-project}

Pour effectuer une recherche dans un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Sélectionnez à nouveau **Rechercher ou accéder à** et saisissez la chaîne que vous souhaitez rechercher.
1. Appuyez sur <kbd>Entrée</kbd> pour lancer la recherche, ou sélectionnez un élément dans la liste.

Les résultats s'affichent. Pour filtrer les résultats, dans la barre latérale gauche, sélectionnez un filtre.

## Inclure les projets archivés dans les résultats de recherche {#include-archived-projects-in-search-results}

Par défaut, les projets archivés sont exclus des résultats de recherche. Pour inclure les projets archivés dans les résultats de recherche :

1. Sur la page de recherche, dans la barre latérale gauche, cochez la case **Inclure les éléments archivés**.
1. Dans la barre latérale gauche, sélectionnez **Appliquer**.

## Rechercher du code {#search-for-code}

Pour rechercher du code dans un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Sélectionnez à nouveau **Rechercher ou accéder à** et saisissez le code que vous souhaitez rechercher.
1. Appuyez sur <kbd>Entrée</kbd> pour lancer la recherche, ou sélectionnez un élément dans la liste.

La recherche de code affiche uniquement le premier résultat dans le fichier. Pour rechercher du code dans tout GitLab, demandez à votre administrateur d'activer la [recherche avancée](advanced_search.md).

### Voir les annotations Git depuis la recherche de code {#view-git-blame-from-code-search}

Après avoir trouvé des résultats de recherche, vous pouvez voir qui a effectué la dernière modification sur la ligne où les résultats ont été trouvés.

1. Dans le résultat de la recherche de code, survolez le numéro de ligne.
1. À gauche, sélectionnez **Voir le blame**.

### Filtrer les résultats de recherche de code par langage {#filter-code-search-results-by-language}

Pour filtrer les résultats de recherche de code par un ou plusieurs langages :

1. Sur la page de recherche de code, dans la barre latérale gauche, sélectionnez un ou plusieurs langages.
1. Dans la barre latérale gauche, sélectionnez **Appliquer**.

## Rechercher un SHA de commit {#search-for-a-commit-sha}

Pour rechercher un SHA de commit :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Sélectionnez à nouveau **Rechercher ou accéder à** et saisissez le SHA de commit que vous souhaitez rechercher.
1. Appuyez sur <kbd>Entrée</kbd> pour lancer la recherche, ou sélectionnez un élément dans la liste.

Si un seul résultat est renvoyé, GitLab redirige vers le résultat du commit et vous offre la possibilité de revenir à la page des résultats de recherche.

## Syntaxe {#syntax}

La recherche de base utilise la correspondance exacte de sous-chaîne avec les options suivantes :

| Syntaxe       | Description                                     | Exemple |
|--------------|-------------------------------------------------|---------|
| `filename:`  | Nom de fichier                                        | `filename:*spec.rb` |
| `path:`      | Emplacement dans le dépôt (correspondances complètes ou partielles)   | `path:spec/workers/` |
| `extension:` | Extension de fichier sans `.` (correspondances exactes uniquement) | `extension:js` |

### Exemples {#examples}

| Requête                                 | Description |
|---------------------------------------|-------------|
| `rails -filename:gemfile.lock`        | Renvoie `rails` dans tous les fichiers sauf le fichier `gemfile.lock`. |
| `helper -extension:yml -extension:js` | Renvoie `helper` dans tous les fichiers sauf les fichiers avec une extension `.yml` ou `.js`. |
| `helper path:lib/git`                 | Renvoie `helper` dans tous les fichiers avec un chemin `lib/git*` (par exemple, `spec/lib/gitlab`). |
