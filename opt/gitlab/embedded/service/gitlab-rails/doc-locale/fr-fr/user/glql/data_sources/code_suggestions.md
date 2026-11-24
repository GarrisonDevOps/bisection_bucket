---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Suggestions de code
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/21212) dans GitLab 19.1.
- `daily`, `weekly` et les valeurs `granularity` à jour fixe pour `timestamp` [introduites](https://gitlab.com/gitlab-org/glql/-/merge_requests/528) dans GitLab 19.5.
- Les opérateurs `!=` et `not in` sur les filtres `ideName`, `language` et `user` [introduits](https://gitlab.com/gitlab-org/glql/-/merge_requests/537) dans GitLab 19.5.

{{< /history >}}

Les suggestions de code sont une source de données qui fournit des métriques agrégées sur l'utilisation de [GitLab Duo Code Suggestions](../../project/repository/code_suggestions/_index.md) dans votre projet ou groupe.

## Modes autorisés {#allowed-modes}

- [`analytics`](../_index.md#analytics-mode)

## Portées autorisées {#allowed-scopes}

| Portée     | Description                                                                 |
| --------- | --------------------------------------------------------------------------- |
| `project` | Interrogez les suggestions de code dans un projet spécifique.                               |
| `group`   | Interrogez les suggestions de code dans tous les projets d'un groupe, y compris les sous-groupes. |

Pour agréger les suggestions de code dans plusieurs groupes ou projets, utilisez une liste avec l'opérateur `in`. Pour plus d'informations, consultez [plusieurs groupes et projets](_index.md#multiple-groups-and-projects).

## Filtres de requête {#query-filters}

Utilisez ces champs dans le paramètre `query` pour filtrer vos résultats.

| Champ                                      | Nom (et alias) | Opérateurs                 |
| ------------------------------------------ | ---------------- | ------------------------- |
| [Nom de l'IDE](#cs-ide-name)                   | `ideName`        | `=`, `!=`, `in`, `not in` |
| [Langage](#cs-language)                    | `language`       | `=`, `!=`, `in`, `not in` |
| [Horodatage](#cs-timestamp)                 | `timestamp`      | `=`, `>`, `<`, `>=`, `<=` |
| [Utilisateur](#cs-user)                           | `user`           | `=`, `!=`, `in`, `not in` |

### Nom de l'IDE {#cs-ide-name}

**Description** : filtrez par l'IDE utilisé pour générer les suggestions.

**Types de valeurs autorisés** :

- `String`
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs valeurs)

### Langage {#cs-language}

**Description** : filtrez par le langage de programmation de la suggestion.

**Types de valeurs autorisés** :

- `String`
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs valeurs)

### Horodatage {#cs-timestamp}

**Description** : filtrez par la date de génération de la suggestion. Utilisez des opérateurs de plage pour définir une fenêtre temporelle.

**Types de valeurs autorisés** :

- `AbsoluteDate` (au format `YYYY-MM-DD`)
- `RelativeDate` (au format `<sign><digit><unit>`, où le signe est `+`, `-`, ou omis, le chiffre est un entier, et `unit` est l'une des valeurs suivantes : `d` (jours), `w` (semaines), `m` (mois) ou `y` (années))

### Utilisateur {#cs-user}

**Description** : filtrez par l'utilisateur qui a reçu la suggestion.

**Types de valeurs autorisés** :

- `Number` (ID utilisateur)
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs ID utilisateur)

> [!note]
> La prise en charge du filtrage par nom d'utilisateur est suivie dans le [ticket 599750](https://gitlab.com/gitlab-org/gitlab/-/work_items/599750).

## Dimensions {#dimensions}

Les dimensions suivantes sont prises en charge :

| Dimension | Nom (et alias) | Description                                          |
|-----------|------------------|------------------------------------------------------|
| Nom de l'IDE  | `ideName`        | Regroupez par IDE utilisé (par exemple, VSCode, JetBrains).  |
| Langage  | `language`       | Regroupez par langage de programmation.                       |
| Horodatage | `timestamp`      | Regroupez par date. Accepte un [paramètre `granularity`](../_index.md#field-parameters) avec les valeurs `daily`, `weekly`, `monthly`, ou un nombre de jours tel que `30d` (par défaut : `monthly`), ainsi qu'un `origin` facultatif. Par exemple, `timestamp(weekly)` ou `timestamp(granularity=30d, origin=2026-07-16)`. |
| Utilisateur      | `user`           | Regroupez par utilisateur (affiche l'avatar, le nom et le nom d'utilisateur). |

## Métriques {#metrics}

Les métriques suivantes sont prises en charge :

| Métrique              | Nom (et alias)    | Description                             |
|---------------------|---------------------|-----------------------------------------|
| Taux d'acceptation     | `acceptanceRate`    | Ratio des suggestions acceptées par rapport aux suggestions affichées. |
| Nombre de suggestions acceptées      | `acceptedCount`     | Nombre de suggestions acceptées.         |
| Nombre de suggestions rejetées      | `rejectedCount`     | Nombre de suggestions rejetées.         |
| Nombre de suggestions affichées         | `shownCount`        | Nombre de suggestions affichées aux utilisateurs.   |
| Somme des tailles de suggestions | `suggestionSizeSum` | Volume total des suggestions.            |
| Nombre total de suggestions         | `totalCount`        | Nombre total de suggestions.            |
| Nombre d'utilisateurs         | `usersCount`        | Nombre d'utilisateurs uniques.                 |

## Champs de tri {#sort-fields}

Triez par n'importe quel champ inclus dans vos dimensions ou métriques sélectionnées. Pour plus d'informations, consultez [le tri en mode analytique](../_index.md#sorting).

## Exemples {#examples}

- Taux d'acceptation par langage pour les 30 derniers jours :

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= -30d
  dimensions: language as "Language"
  metrics: totalCount as "Total", acceptanceRate as "Acceptance Rate"
  sort: acceptanceRate desc
  ```
  ````

- Utilisation par IDE :

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= -30d
  dimensions: ideName as "IDE"
  metrics: totalCount as "Total Suggestions", usersCount as "Active Users"
  sort: totalCount desc
  ```
  ````

- Métriques globales sans regroupement :

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= -30d
  metrics: totalCount as "Total", acceptedCount as "Accepted", rejectedCount as "Rejected", shownCount as "Shown", acceptanceRate as "Acceptance Rate"
  ```
  ````

- Suggestions par utilisateur pour un projet spécifique, filtrées sur Ruby :

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= -30d and language = "ruby"
  dimensions: user as "User"
  metrics: totalCount as "Total", acceptanceRate as "Acceptance Rate"
  sort: totalCount desc
  limit: 10
  ```
  ````

- Suggestions dans le temps par langage sur une plage de dates :

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= "2026-01-01" and timestamp <= "2026-03-31"
  dimensions: timestamp as "Date", language as "Language"
  metrics: totalCount as "Total", acceptanceRate as "Acceptance Rate"
  sort: timestamp desc
  ```
  ````

- Filtrez sur des IDE et des langages spécifiques :

  ````yaml
  ```glql
  display: table
  mode: analytics
  query: type = CodeSuggestion and timestamp >= -7d and ideName in ("Visual Studio Code", "RubyMine") and language in ("ruby", "python")
  dimensions: ideName as "IDE", language as "Language"
  metrics: totalCount as "Total", acceptanceRate as "Rate"
  sort: totalCount desc
  ```
  ````
