---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Contributions
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/21212) dans GitLab 19.2.
- Paramètre `granularity` configurable [introduit](https://gitlab.com/gitlab-org/glql/-/issues/130) dans GitLab 19.3.
- Les opérateurs `!=` et `not in` sur le filtre `user` [introduits](https://gitlab.com/gitlab-org/glql/-/merge_requests/537) dans GitLab 19.5.

{{< /history >}}

Contributions est une source de données qui fournit des métriques agrégées sur l'activité de contribution (tels que les commits, les tickets et les merge requests) dans vos projets ou groupes.

## Modes autorisés {#allowed-modes}

- [`analytics`](../_index.md#analytics-mode)

## Portées autorisées {#allowed-scopes}

| Portée     | Description                                                              |
| --------- | ------------------------------------------------------------------------ |
| `project` | Interroger les contributions dans un projet spécifique.                               |
| `group`   | Interroger les contributions dans tous les projets d'un groupe, y compris les sous-groupes. |

Pour agréger les contributions de plusieurs groupes ou projets, utilisez une liste avec l'opérateur `in`. Pour plus d'informations, voir [plusieurs groupes et projets](_index.md#multiple-groups-and-projects).

## Filtres de requête {#query-filters}

Utilisez ces champs dans le paramètre `query` pour filtrer vos résultats.

| Champ                      | Nom      | Opérateurs                 |
| -------------------------- | --------- | ------------------------- |
| [Créé le](#created-at)  | `created` | `=`, `>`, `<`, `>=`, `<=` |
| [Utilisateur](#user)              | `user`    | `=`, `!=`, `in`, `not in` |

### Créé le {#created-at}

**Description** : filtrer les contributions par date de création.

**Types de valeurs autorisés** :

- `AbsoluteDate` (au format `YYYY-MM-DD`)
- `RelativeDate` (au format `<sign><digit><unit>`, où le signe est `+`, `-`, ou omis, le chiffre est un entier, et `unit` est l'un des éléments suivants : `d` (jours), `w` (semaines), `m` (mois) ou `y` (années))

**Notes** :

- Pour l'opérateur `=`, GLQL considère la plage horaire de 00:00 à 23:59 dans le fuseau horaire de l'utilisateur.

### Utilisateur {#user}

**Description** : filtrer par l'utilisateur ayant effectué les contributions.

**Types de valeurs autorisés** :

- `Number` (ID utilisateur)
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs ID utilisateur)

> [!note]
> La prise en charge du filtrage par nom d'utilisateur est suivie dans [GLQL issue 143](https://gitlab.com/gitlab-org/glql/-/work_items/143).

## Dimensions {#dimensions}

| Dimension  | Nom      | Description                                          |
| ---------- | --------- | ----------------------------------------------------- |
| Créé le | `created` | Regrouper par date de création des contributions. Accepte un [paramètre `granularity`](../_index.md#field-parameters) de `daily`, `weekly`, `monthly`, ou un nombre de jours tel que `30d` (par défaut : `monthly`), et un `origin` optionnel. Par exemple, `created(weekly)` ou `created(granularity=30d, origin=2026-07-16)`. |

## Métriques {#metrics}

| Métrique      | Nom         | Description                    |
| ----------- | ------------ | ------------------------------- |
| Nombre total | `totalCount` | Nombre total de contributions. |
| Nombre d'utilisateurs | `usersCount` | Nombre de contributeurs uniques. |

## Champs de tri {#sort-fields}

Triez par n'importe quel champ inclus dans vos dimensions ou métriques sélectionnées. Pour plus d'informations, voir [le tri en mode analytique](../_index.md#sorting).

## Exemples {#examples}

- Tendance mensuelle des contributions pour un projet :

  ````yaml
  ```glql
  title: "Monthly contributions"
  display: table
  mode: analytics
  query: type = Contribution and project = "gitlab-org/gitlab"
  dimensions: created as "Month"
  metrics: totalCount as "Total", usersCount as "Contributors"
  sort: created desc
  ```
  ````

- Tendance des contributions pour un ensemble d'utilisateurs :

  ````yaml
  ```glql
  title: "Contributions from a set of users"
  display: table
  mode: analytics
  query: type = Contribution and project = "gitlab-org/gitlab" and user in (1234567, 2345678) and created >= -90d
  dimensions: created as "Month"
  metrics: totalCount as "Total"
  sort: created desc
  ```
  ````

- Contributions d'un utilisateur spécifique au cours de la dernière année, par mois :

  ````yaml
  ```glql
  title: "User contribution history"
  display: table
  mode: analytics
  query: type = Contribution and group = "gitlab-org" and user = 1234567 and created >= -365d
  dimensions: created as "Month"
  metrics: totalCount as "Total"
  sort: created asc
  ```
  ````

- Métriques globales de contribution pour un groupe, sans regroupement :

  ````yaml
  ```glql
  title: "Overall contribution metrics"
  display: table
  mode: analytics
  query: type = Contribution and group = "gitlab-org" and created >= -90d
  metrics: totalCount as "Total", usersCount as "Contributors"
  ```
  ````
