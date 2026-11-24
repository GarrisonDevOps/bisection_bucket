---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Sessions de la plateforme d'agents"
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/592423) dans GitLab 19.4.
- `daily` et les valeurs `granularity` à jour fixe pour `created` [introduites](https://gitlab.com/gitlab-org/glql/-/merge_requests/528) dans GitLab 19.5.
- Les opérateurs `!=` et `not in` sur les filtres `flowType` et `user` [introduits](https://gitlab.com/gitlab-org/glql/-/merge_requests/537) dans GitLab 19.5.

{{< /history >}}

Cette source de données fournit des métriques agrégées sur l'utilisation des sessions de la plateforme d'agents GitLab Duo dans votre projet ou groupe.

## Modes autorisés {#allowed-modes}

- [`analytics`](../_index.md#analytics-mode)

## Portées autorisées {#allowed-scopes}

| Portée     | Description |
|-----------|-------------|
| `project` | Interroger les sessions de la plateforme d'agents GitLab Duo dans un projet spécifique. |
| `group`   | Interroger les sessions de la plateforme d'agents GitLab Duo dans tous les projets d'un groupe, y compris les sous-groupes. |

Pour agréger les sessions de la plateforme d'agents GitLab Duo sur plusieurs groupes ou projets, utilisez une liste avec l'opérateur `in`. Pour plus d'informations, consultez [les groupes et projets multiples](_index.md#multiple-groups-and-projects).

## Filtres de requête {#query-filters}

Utilisez ces champs dans le paramètre `query` pour filtrer vos résultats.

| Champ                   | Nom (et alias)                                | Opérateurs                 |
| ----------------------- | ----------------------------------------------- | ------------------------- |
| [Créé](#created)     | `created` (`opened`, `openedAt`, `createdAt`)   | `=`, `>`, `<`, `>=`, `<=` |
| [Type de flow](#flow-type) | `flowType`                                      | `=`, `!=`, `in`, `not in` |
| [Utilisateur](#user)           | `user`                                          | `=`, `!=`, `in`, `not in` |

### Créé {#created}

**Description** : filtrer par date de création de la session. Utilisez des opérateurs de plage pour définir une fenêtre temporelle.

**Types de valeurs autorisés** :

- `AbsoluteDate` (au format `YYYY-MM-DD`)
- `RelativeDate` (au format `<sign><digit><unit>`, où le signe est `+`, `-`, ou omis, le chiffre est un entier, et `unit` est l'un des suivants : `d` (jours), `w` (semaines), `m` (mois) ou `y` (années))

**Notes** :

- Pour l'opérateur `=`, la plage horaire est considérée de 00:00 à 23:59 dans le fuseau horaire de l'utilisateur.

### Type de flow {#flow-type}

**Description** : filtrer par type de flow de la session. Par exemple, `chat` ou `code_review/v1`.

**Types de valeurs autorisés** :

- `String`
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs valeurs)

### Utilisateur {#user}

**Description** : filtrer par l'utilisateur propriétaire de la session.

**Types de valeurs autorisés** :

- `Number` (identifiant utilisateur)
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs identifiants utilisateur)

> [!note]
> La prise en charge du filtrage par nom d'utilisateur est suivie dans le [ticket 599750](https://gitlab.com/gitlab-org/gitlab/-/work_items/599750).

## Dimensions {#dimensions}

| Dimension | Nom       | Description |
|-----------|------------|-------------|
| Créé   | `created`  | Regrouper par date. Accepte un [paramètre `granularity`](../_index.md#field-parameters) de valeur `daily`, `weekly`, `monthly`, ou un nombre de jours tel que `30d` (par défaut : `weekly`), ainsi qu'un `origin` facultatif. Par exemple, `created(monthly)` ou `created(granularity=30d, origin=2026-07-16)`. |
| Type de flow | `flowType` | Regrouper par type de flow de session. |
| Projet   | `project`  | Regrouper par projet. Les sessions qui ne sont pas associées à un projet sont regroupées dans une seule ligne sans projet. |
| Utilisateur      | `user`     | Regrouper par utilisateur (affiche l'avatar, le nom et le nom d'utilisateur). |

## Métriques {#metrics}

| Métrique            | Nom               | Description |
|-------------------|--------------------|-------------|
| Taux de complétion   | `completionRate`   | Proportion de sessions terminées, sous forme de valeur comprise entre 0 et 1. |
| Durée maximale      | `durationMax`      | Durée de la session terminée la plus longue, en secondes. |
| Durée moyenne     | `durationMean`     | Durée moyenne des sessions terminées, en secondes. |
| Durée minimale      | `durationMin`      | Durée de la session terminée la plus courte, en secondes. |
| Quantile de durée | `durationQuantile` | Durée des sessions terminées à un quantile donné, en secondes. Accepte un [paramètre `quantile`](../_index.md#field-parameters) compris entre `0.01` et `0.99` (par défaut : `0.5`). Par exemple, `durationQuantile(0.95)`. |
| Durée totale      | `durationSum`      | Durée totale des sessions terminées, en secondes. |
| Nombre de sessions terminées    | `finishedCount`    | Nombre de sessions terminées. |
| Nombre total       | `totalCount`       | Nombre total de sessions. |
| Nombre d'utilisateurs       | `usersCount`       | Nombre d'utilisateurs uniques. |

## Champs de tri {#sort-fields}

Trier par n'importe quelle dimension, ou par l'une de ces métriques :

- `totalCount`
- `finishedCount`
- `usersCount`
- `completionRate`
- `durationQuantile`
- `durationMean`
- `durationMin`
- `durationMax`
- `durationSum`

Pour plus d'informations, consultez [le tri en mode analytique](../_index.md#sorting).

## Exemples {#examples}

- Sessions par type de flow pour les 30 derniers jours :

  ````yaml
  ```glql
  title: "Agent Platform sessions by flow (last 30 days)"
  display: table
  mode: analytics
  query: type = AgentPlatformSession and group = "gitlab-org" and created > -30d
  dimensions: flowType as "Flow"
  metrics: totalCount as "Total", finishedCount as "Finished", completionRate as "Completion rate"
  sort: totalCount desc
  ```
  ````

- Tendance hebdomadaire des sessions :

  ````yaml
  ```glql
  title: "Weekly Agent Platform session trend"
  display: columnChart
  mode: analytics
  query: type = AgentPlatformSession and group = "gitlab-org" and created > -90d
  dimensions: created(weekly) as "Week"
  metrics: totalCount as "Total", usersCount as "Users"
  sort: created desc
  ```
  ````

- Sessions par utilisateur, avec durée moyenne :

  ````yaml
  ```glql
  title: "Agent Platform sessions by user"
  display: table
  mode: analytics
  query: type = AgentPlatformSession and group = "gitlab-org" and created > -30d
  dimensions: user as "User"
  metrics: totalCount as "Total", durationMean as "Avg duration"
  sort: totalCount desc
  limit: 10
  ```
  ````

- Taux de complétion global et durée médiane, sans regroupement :

  ````yaml
  ```glql
  title: "Agent Platform session completion (last 30 days)"
  display: table
  mode: analytics
  query: type = AgentPlatformSession and group = "gitlab-org" and created > -30d
  metrics: totalCount as "Total", completionRate as "Completion rate", durationQuantile(0.5) as "Median duration"
  ```
  ````
