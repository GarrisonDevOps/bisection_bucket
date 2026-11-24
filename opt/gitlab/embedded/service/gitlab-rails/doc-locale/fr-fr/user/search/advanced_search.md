---
stage: Analytics
group: Global Search
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Recherche avancée
description: "Utilisez la recherche avancée pour trouver du code, des commits, des éléments de travail et des merge requests dans l'ensemble de votre instance GitLab."
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Utilisez la recherche avancée pour trouver exactement ce dont vous avez besoin dans l'ensemble de votre instance GitLab.

Avec la recherche avancée :

- Identifiez les patterns de code dans tous les projets pour refactoriser les composants partagés plus efficacement.
- Localisez les vulnérabilités de sécurité dans l'ensemble du code source et des dépendances de votre organisation.
- Suivez l'utilisation des fonctions ou bibliothèques obsolètes dans l'ensemble des dépôts.
- Retrouvez les discussions enfouies dans les tickets, les merge requests ou les commentaires.
- Découvrez les solutions existantes plutôt que de réinventer des fonctionnalités qui existent déjà.

La recherche avancée fonctionne dans :

- Code
- Commentaires
- Commits
- Groupes
- Éléments de travail
- Les merge requests
- Les jalons
- Projets
- Utilisateurs
- les wikis.

## Utiliser la recherche avancée {#use-advanced-search}

Prérequis :

- La recherche avancée doit être activée :
  - Pour GitLab.com et GitLab Dedicated, la recherche avancée est activée par défaut dans les abonnements payants.
  - Pour GitLab Self-Managed, un administrateur doit [activer la recherche avancée](../../integration/advanced_search/elasticsearch.md#enable-advanced-search).

Pour utiliser la recherche avancée :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**.
1. Dans la zone de recherche, saisissez le terme à rechercher.

Vous pouvez également utiliser la recherche avancée dans un projet ou un groupe.

## Portées disponibles {#available-scopes}

{{< history >}}

- La recherche dans les commentaires des tickets a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/513146) dans GitLab 18.0 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `search_work_item_queries_notes`. Fonctionnalité désactivée par défaut.
- La recherche dans les commentaires des tickets a été [activée sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/536912) dans GitLab 18.1.
- La recherche dans les commentaires des tickets est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/191369) dans GitLab 18.6. Le feature flag `search_work_item_queries_notes` a été supprimé.
- La recherche dans les commentaires des merge requests a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/572590) dans GitLab 18.6 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `search_merge_request_queries_notes`. Fonctionnalité désactivée par défaut.
- La recherche dans les commentaires des merge requests est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/573750) dans GitLab 18.7. Le feature flag `search_merge_request_queries_notes` a été supprimé.
- La portée Groupes a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249760) dans GitLab 19.4 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `elasticsearch_group_search`. Fonctionnalité désactivée par défaut.
- La portée Groupes est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/607018) dans GitLab 19.5. Le feature flag `elasticsearch_group_search` a été supprimé.

{{< /history >}}

Les portées décrivent le type de données que vous recherchez. Les portées suivantes sont disponibles pour la recherche avancée :

| Portée                       | Global[^disable-global-search-scopes], [^global-search-saas] | Groupe       | Projet     |
|-----------------------------|----------------------------------|-------------|-------------|
| Code                        | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| Commentaires                    | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| Commits                     | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| Groupes[^group-search-returns]         | {{< yes >}}                      | {{< yes >}} | {{< no >}}  |
| Éléments de travail[^search-work-items]     | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| Merge requests[^search-work-items] | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| Jalons[^advanced-search-returns]     | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| Projets                    | {{< yes >}}                      | {{< yes >}} | {{< no >}}  |
| Utilisateurs                       | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| les wikis.                       | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |

[^disable-global-search-scopes]: Un administrateur peut [désactiver les portées de recherche globale](_index.md#disable-global-search-scopes). Sur GitLab Self-Managed, la recherche globale n'est pas disponible lorsque l'indexation limitée est activée par défaut. Un administrateur peut [activer la recherche globale pour l'indexation limitée](../../integration/advanced_search/elasticsearch.md#indexed-namespaces).
[^global-search-saas]: sur GitLab.com, la recherche globale n'est pas activée pour le code, les commits et les wikis.
[^search-work-items]: lorsque vous recherchez des éléments de travail et des merge requests, les résultats incluent les commentaires correspondant à votre terme de recherche.
[^advanced-search-returns]: la recherche avancée retourne uniquement les jalons de projet, car les jalons de groupe ne sont pas indexés dans Elasticsearch. Pour plus d'informations, consultez [l'issue 428589](https://gitlab.com/gitlab-org/gitlab/-/issues/428589).
[^group-search-returns]: la recherche dans un groupe retourne les sous-groupes du groupe dans lequel vous effectuez la recherche, et non le groupe lui-même. La migration de recherche avancée `backfill_groups_to_elasticsearch` doit être terminée avant que cette portée retourne des résultats.

## Syntaxe {#syntax}

<!-- Remember to also update the tables in `doc/drawers/advanced_search_syntax.md` -->

La recherche avancée utilise [`simple_query_string`](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-simple-query-string-query), qui prend en charge les requêtes exactes et approximatives.

Lorsque vous recherchez un utilisateur, la requête [`fuzzy`](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-fuzzy-query) est utilisée par défaut. Vous pouvez affiner la recherche d'utilisateurs avec `simple_query_string`.

| Syntaxe | Description      | Exemple |
|--------|------------------|---------|
| `"`    | Recherche exacte     | `"gem sidekiq"` |
| `~`    | Recherche approximative     | `J~ Doe` |
| `\|`   | Ou               | `display \| banner` |
| `+`    | Et              | `display +banner` |
| `-`    | Exclure          | `display -banner` |
| `*`    | Partiel          | `bug error 50*` |
| ` \ `  | Échapper           | `\*md`  |
| `#`    | ID du ticket         | `#23456` |
| `!`    | ID de la merge request | `!23456` |

### Recherche dans le code {#code-search}

| Syntaxe       | Description                                     | Exemple |
|--------------|-------------------------------------------------|---------|
| `filename:`  | Nom de fichier                                        | `filename:*spec.rb` |
| `path:`      | Emplacement dans le dépôt (correspondances complètes ou partielles)   | `path:spec/workers/` |
| `extension:` | Extension de fichier sans `.` (correspondances exactes uniquement) | `extension:js` |
| `blob:`      | ID d'objet Git (correspondances exactes uniquement)              | `blob:998707*` |

### Exemples {#examples}

| Requête                                 | Description |
|---------------------------------------|-------------|
| `rails -filename:gemfile.lock`        | Retourne `rails` dans tous les fichiers sauf le fichier `gemfile.lock`. |
| `RSpec.describe Resolvers -*builder`  | Retourne `RSpec.describe Resolvers` qui ne commence pas par `builder`. |
| `bug \| (display +banner)`            | Retourne `bug` ou à la fois `display` et `banner`. |
| `helper -extension:yml -extension:js` | Retourne `helper` dans tous les fichiers sauf les fichiers avec une extension `.yml` ou `.js`. |
| `helper path:lib/git`                 | Retourne `helper` dans tous les fichiers avec un chemin `lib/git*` (par exemple, `spec/lib/gitlab`). |

## Problèmes connus {#known-issues}

- Vous pouvez rechercher uniquement des fichiers inférieurs à 1 Mo. Pour GitLab Self-Managed, un administrateur peut définir une limite sur la [taille maximale de fichier indexée](../../administration/instance_limits.md#maximum-file-size-indexed).
- Vous pouvez utiliser la recherche avancée uniquement sur la branche par défaut d'un projet. Pour plus d'informations, consultez [l'issue 229966](https://gitlab.com/gitlab-org/gitlab/-/issues/229966).
- La requête de recherche ne doit contenir aucun des caractères suivants :

  ```plaintext
  . , : ; / ` ' = ? $ & ^ | < > ( ) { } [ ] @
  ```

- Les résultats de recherche affichent uniquement la première correspondance dans un fichier.

## Sujets connexes {#related-topics}

- [Localiser les vulnérabilités de sécurité](../application_security/vulnerability_report/_index.md#advanced-vulnerability-management)
