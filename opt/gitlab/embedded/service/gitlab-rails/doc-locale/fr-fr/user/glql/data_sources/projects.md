---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Projets
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Champ `avatarUrl` [ajouté](https://gitlab.com/gitlab-org/glql/-/merge_requests/361) dans GitLab 18.11.

{{< /history >}}

## Portées autorisées {#allowed-scopes}

| Portée       | Description                                                                              |
| ----------- | ---------------------------------------------------------------------------------------- |
| `namespace` | Interroge les projets dans un espace de nommage spécifique. Vous pouvez utiliser `group` comme alias pour `namespace`. |

Pour plus d'informations, consultez [les portées](_index.md#scopes).

## Filtres de requête {#query-filters}

Utilisez ces champs dans le paramètre `query` pour filtrer vos résultats.

| Champ                                                    | Nom (et alias)       | Opérateurs  |
| -------------------------------------------------------- | ---------------------- | ---------- |
| [Archivé uniquement](#project-archived-only)                  | `archivedOnly`         | `=`, `!=`  |
| [A une couverture de code](#project-has-code-coverage)          | `hasCodeCoverage`      | `=`, `!=`  |
| [A des vulnérabilités](#project-has-vulnerabilities)      | `hasVulnerabilities`   | `=`, `!=`  |
| [Inclure les archivés](#project-include-archived)            | `includeArchived`      | `=`, `!=`  |
| [Inclure les sous-groupes](#project-include-subgroups)          | `includeSubgroups`     | `=`, `!=`  |
| [Tickets activés](#project-issues-enabled)                | `issuesEnabled`        | `=`, `!=`  |
| [Merge requests activées](#project-merge-requests-enabled)| `mergeRequestsEnabled` | `=`, `!=`  |

### Archivé uniquement {#project-archived-only}

**Description** : filtre pour afficher uniquement les projets archivés.

**Types de valeurs autorisés** : `Boolean` (`true` ou `false`)

**Notes** :

- Ne peut pas être utilisé conjointement avec `includeArchived`.

### A une couverture de code {#project-has-code-coverage}

**Description** : filtre les projets selon qu'ils disposent ou non de rapports de couverture de code.

**Types de valeurs autorisés** : `Boolean` (`true` ou `false`)

### A des vulnérabilités {#project-has-vulnerabilities}

**Description** : filtre les projets selon qu'ils présentent ou non des vulnérabilités de sécurité.

**Types de valeurs autorisés** : `Boolean` (`true` ou `false`)

### Inclure les archivés {#project-include-archived}

**Description** : inclut les projets archivés dans les résultats.

**Types de valeurs autorisés** : `Boolean` (`true` ou `false`)

**Notes** :

- Ne peut pas être utilisé conjointement avec `archivedOnly`.
- Par défaut, les projets archivés ne sont pas inclus.

### Inclure les sous-groupes {#project-include-subgroups}

**Description** : indique si les projets des sous-groupes doivent être inclus.

**Types de valeurs autorisés** : `Boolean` (`true` ou `false`)

**Notes** :

- Ce champ ne peut être utilisé qu'avec une portée `namespace`.
- La valeur par défaut est `true` lorsqu'une portée `namespace` est spécifiée.

### Tickets activés {#project-issues-enabled}

**Description** : filtre les projets selon qu'ils ont ou non des tickets activés.

**Types de valeurs autorisés** : `Boolean` (`true` ou `false`)

### Merge requests activées {#project-merge-requests-enabled}

**Description** : filtre les projets selon qu'ils ont ou non des merge requests activées.

**Types de valeurs autorisés** : `Boolean` (`true` ou `false`)

## Champs d'affichage {#display-fields}

| Champ                            | Nom (et alias)                 | Description |
| -------------------------------- | -------------------------------- | ----------- |
| Archivé                         | `archived`                       | Indique si le projet est archivé |
| URL de l'avatar                       | `avatarUrl`                      | Affiche l'URL de l'avatar du projet |
| Fonctionnalités Duo activées             | `duoFeaturesEnabled`             | Indique si les fonctionnalités Duo sont activées |
| Dupliqué                           | `forked`                         | Indique si le projet est une duplication |
| Nombre de duplications                      | `forksCount`                     | Affiche le nombre de duplications |
| Chemin complet                        | `fullPath`                       | Affiche le chemin complet du projet |
| Groupe                            | `group`                          | Affiche le groupe auquel appartient le projet |
| ID                               | `id`                             | Affiche l'ID du projet |
| Tickets activés                   | `issuesEnabled`                  | Indique si les tickets sont activés |
| Dernière activité                    | `lastActivity`, `lastActivityAt` | Affiche la date de la dernière activité du projet |
| Merge requests activées           | `mergeRequestsEnabled`           | Indique si les merge requests sont activées |
| Nom                             | `name`                           | Affiche le nom du projet |
| Nombre de tickets ouverts                | `openIssuesCount`                | Affiche le nombre de tickets ouverts |
| Nombre de merge requests ouvertes        | `openMergeRequestsCount`         | Affiche le nombre de merge requests ouvertes |
| Chemin                             | `path`                           | Affiche le chemin du projet |
| Protection contre les push de secrets activée   | `secretPushProtectionEnabled`    | Indique si la protection contre les push de secrets est activée |
| Nombre d'étoiles                       | `starCount`                      | Affiche le nombre d'étoiles |
| Visibilité                       | `visibility`                     | Affiche le niveau de visibilité du projet |
| URL web                          | `webUrl`                         | Affiche l'URL web du projet |

## Champs de tri {#sort-fields}

| Champ         | Nom (et alias)                 | Description                    |
| ------------- | -------------------------------- | ------------------------------ |
| Chemin complet     | `fullPath`                       | Trie par chemin complet              |
| Dernière activité | `lastActivity`, `lastActivityAt` | Trie par date de dernière activité     |
| Chemin          | `path`                           | Trie par chemin                   |

**Notes** :

- `lastActivity` ne prend en charge que l'ordre de tri décroissant (`desc`).

## Exemples {#examples}

- Lister tous les projets du groupe `gitlab-org` triés par chemin :

  ````yaml
  ```glql
  display: table
  fields: name, fullPath, starCount, openIssuesCount
  sort: path asc
  query: type = Project and group = "gitlab-org"
  ```
  ````

- Lister tous les projets du groupe `gitlab-org` triés par activité la plus récente :

  ````yaml
  ```glql
  display: table
  fields: name, fullPath, lastActivity
  sort: lastActivity desc
  query: type = Project and group = "gitlab-org"
  ```
  ````
