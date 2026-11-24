---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Événements d'utilisation de l'IA"
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/21216) dans GitLab 19.3.
- La sélection de `returningUsersCount` ou `previousPeriodUsersCount` sans la dimension `timestamp` a [été modifiée](https://gitlab.com/gitlab-org/glql/-/merge_requests/485) pour renvoyer une erreur dans GitLab 19.5.
- La dimension `group` a été [introduite](https://gitlab.com/gitlab-org/glql/-/merge_requests/530) dans GitLab 19.5.
- Les opérateurs `!=` et `not in` sur les filtres `event`, `feature` et `user` ont été [introduits](https://gitlab.com/gitlab-org/glql/-/merge_requests/537) dans GitLab 19.5.
- Le paramètre `event` sur `totalCount` a été [introduit](https://gitlab.com/gitlab-org/glql/-/merge_requests/541) dans GitLab 19.5.

{{< /history >}}

Les événements d'utilisation de l'IA constituent une source de données qui fournit des métriques agrégées sur l'utilisation des fonctionnalités GitLab Duo dans votre projet ou groupe.

## Modes autorisés {#allowed-modes}

- [`analytics`](../_index.md#analytics-mode)

## Portées autorisées {#allowed-scopes}

| Portée     | Description                                                                 |
| --------- | --------------------------------------------------------------------------- |
| `project` | Interrogez les événements d'utilisation de l'IA dans un projet spécifique.                                |
| `group`   | Interrogez les événements d'utilisation de l'IA dans tous les projets d'un groupe, y compris les sous-groupes.  |

Pour agréger les événements d'utilisation de l'IA dans plusieurs groupes ou projets, utilisez une liste avec l'opérateur `in`. Pour plus d'informations, consultez [plusieurs groupes et projets](_index.md#multiple-groups-and-projects).

## Filtres de requête {#query-filters}

Utilisez ces champs dans le paramètre `query` pour filtrer vos résultats.

| Champ                                | Nom            | Opérateurs                 |
| ------------------------------------ | --------------- | ------------------------- |
| [Événement](#event)                      | `event`         | `=`, `!=`, `in`, `not in` |
| [Fonctionnalité](#feature)                  | `feature`       | `=`, `!=`, `in`, `not in` |
| [Nombre de fonctionnalités](#features-count)    | `featuresCount` | `>`, `<`, `>=`, `<=`      |
| [Horodatage](#timestamp)              | `timestamp`     | `=`, `>`, `<`, `>=`, `<=` |
| [Utilisateur](#user)                        | `user`          | `=`, `!=`, `in`, `not in` |

### Événement {#event}

**Description** : filtrez par identifiant d'événement.

**Types de valeurs autorisés** :

- `String`
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs valeurs)

**Notes** :

- L'exclusion d'un identifiant d'événement que GitLab ne reconnaît pas n'exclut rien. La validation des identifiants d'événements est proposée dans le [ticket 629846](https://gitlab.com/gitlab-org/gitlab/-/issues/629846).

### Fonctionnalité {#feature}

**Description** : filtrez par la fonctionnalité GitLab Duo qui a généré l'événement. Par exemple, `code_suggestions` ou `chat`.

**Types de valeurs autorisés** :

- `String`
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs valeurs)

**Notes** :

- `!=` et `not in` ne renvoient que les événements dont la fonctionnalité est connue. Les événements que GitLab n'a pas pu associer à une fonctionnalité sont exclus, donc `feature != "chat"` n'est pas équivalent à tous les événements sauf chat.

### Nombre de fonctionnalités {#features-count}

**Description** : filtrez par le nombre de fonctionnalités uniques utilisées. Ce filtre n'est valide que lorsque la métrique `featuresCount` est également sélectionnée.

**Types de valeurs autorisés** : `Number`

### Horodatage {#timestamp}

**Description** : filtrez par date de survenue de l'événement. Utilisez des opérateurs de plage pour définir une fenêtre temporelle.

**Types de valeurs autorisés** :

- `AbsoluteDate` (au format `YYYY-MM-DD`)
- `RelativeDate` (au format `<sign><digit><unit>`, où le signe est `+`, `-` ou omis, le chiffre est un entier, et `unit` est l'un des suivants : `d` (jours), `w` (semaines), `m` (mois) ou `y` (années))

**Notes** :

- Pour l'opérateur `=`, la plage horaire est considérée de 00:00 à 23:59 dans le fuseau horaire de l'utilisateur.

### Utilisateur {#user}

**Description** : filtrez par l'utilisateur qui a déclenché l'événement.

**Types de valeurs autorisés** :

- `Number` (identifiant d'utilisateur)
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs identifiants d'utilisateurs)

> [!note]
> La prise en charge du filtrage par nom d'utilisateur est suivie dans le [ticket 599750](https://gitlab.com/gitlab-org/gitlab/-/work_items/599750).

## Dimensions {#dimensions}

| Dimension | Nom        | Description |
| --------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Événement     | `event`     | Regroupez par identifiant d'événement. |
| Fonctionnalité   | `feature`   | Regroupez par fonctionnalité GitLab Duo. |
| Groupe     | `group`     | Regroupez par groupe. Accepte un paramètre `depth` compté à partir du groupe principal, de `1` à `99` (par défaut : `1`), donc `group` renvoie les groupes principaux et `group(depth=2)` leurs sous-groupes. Les événements au-delà de cette profondeur, ou dans un projet à cette profondeur plutôt que dans un sous-groupe (par exemple, un projet directement sous le groupe principal lorsque `depth=2`), n'ont pas de groupe, et le résultat peut contenir plus d'une ligne sans groupe. |
| Horodatage | `timestamp` | Regroupez par date. Accepte un [paramètre `granularity`](../_index.md#field-parameters) parmi `daily`, `weekly`, `monthly`, ou un nombre de jours comme `30d` (par défaut : `weekly`), et une `origin` facultative. Par exemple, `timestamp(daily)` ou `timestamp(granularity=30d, origin=2026-07-16)`. |
| Utilisateur      | `user`      | Regroupez par utilisateur (affiche l'avatar, le nom et le nom d'utilisateur). |

## Métriques {#metrics}

| Métrique                      | Nom                      | Description                                             |
| --------------------------- | ------------------------- | ------------------------------------------------------- |
| Nombre de fonctionnalités              | `featuresCount`           | Nombre de fonctionnalités uniques utilisées.                         |
| Nombre d'utilisateurs de la période précédente | `previousPeriodUsersCount` | Nombre d'utilisateurs uniques au cours de la période précédente.         |
| Nombre d'utilisateurs récurrents       | `returningUsersCount`     | Nombre d'utilisateurs actifs à la fois au cours de la période actuelle et de la période précédente. |
| Nombre total                 | `totalCount`              | Nombre total d'événements, filtré optionnellement par événement. Accepte un paramètre `event` facultatif avec un ou plusieurs identifiants d'événements (les mêmes valeurs que le filtre `event`), par exemple `totalCount(event="publish_duo_code_review_comments")` ou `totalCount(event=["request_review_duo_code_review_on_mr_by_author", "request_review_duo_code_review_on_mr_by_non_author"])`. Sans le paramètre, ou avec `event=[]`, tous les événements sont comptabilisés. Un identifiant d'événement que GitLab ne reconnaît pas renvoie une erreur. |
| Nombre d'utilisateurs                 | `usersCount`              | Nombre d'utilisateurs uniques.                                 |

**Notes** :

- Les métriques `returningUsersCount` et `previousPeriodUsersCount` comparent chaque intervalle `timestamp` avec le précédent, donc la dimension `timestamp` doit également être sélectionnée. Sans elle, la requête renvoie une erreur. Un filtre `timestamp` seul ne suffit pas.

## Champs de tri {#sort-fields}

Triez par n'importe quel champ inclus dans vos dimensions ou métriques sélectionnées. Pour plus d'informations, consultez [le tri en mode analytique](../_index.md#sorting).

## Exemples {#examples}

- Adoption des fonctionnalités au cours des 30 derniers jours :

  ````yaml
  ```glql
  title: "GitLab Duo feature adoption (last 30 days)"
  display: table
  mode: analytics
  query: type = AiUsageEvent and group = "gitlab-org" and timestamp > -30d
  dimensions: feature as "Feature"
  metrics: totalCount as "Total events", usersCount as "Users"
  sort: usersCount desc
  ```
  ````

- Tendance d'utilisation hebdomadaire avec les utilisateurs récurrents :

  ````yaml
  ```glql
  title: "Weekly GitLab Duo usage trend"
  display: table
  mode: analytics
  query: type = AiUsageEvent and group = "gitlab-org" and timestamp > -30d
  dimensions: timestamp(weekly) as "Week"
  metrics: usersCount as "Users", returningUsersCount as "Returning users", previousPeriodUsersCount as "Previous period users"
  sort: timestamp desc
  ```
  ````

- Nombre de GitLab Duo Code Review hebdomadaires, un par groupe d'événements :

  ````yaml
  ```glql
  title: "Weekly GitLab Duo Code Review requests and reviews"
  display: table
  mode: analytics
  query: type = AiUsageEvent and group = "gitlab-org" and timestamp > -30d
  dimensions: timestamp(weekly) as "Week"
  metrics: totalCount(event=["request_review_duo_code_review_on_mr_by_author", "request_review_duo_code_review_on_mr_by_non_author"]) as "Requested", totalCount(event="publish_duo_code_review_comments") as "With comments", totalCount(event="find_no_issues_duo_code_review_after_review") as "Without comments"
  sort: timestamp desc
  ```
  ````

- Événements par utilisateur pour un projet spécifique :

  ````yaml
  ```glql
  title: "GitLab Duo events by user"
  display: table
  mode: analytics
  query: type = AiUsageEvent and project = "gitlab-org/gitlab" and timestamp > -30d
  dimensions: user as "User"
  metrics: totalCount as "Total events"
  sort: totalCount desc
  limit: 10
  ```
  ````

- Utilisateurs uniques globaux, sans regroupement :

  ````yaml
  ```glql
  title: "Unique GitLab Duo users (last 30 days)"
  display: table
  mode: analytics
  query: type = AiUsageEvent and group = "gitlab-org" and timestamp > -30d
  metrics: usersCount as "Users"
  ```
  ````
