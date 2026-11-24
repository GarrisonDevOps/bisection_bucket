---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Analyse des pipelines
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/21212) dans GitLab 19.1.
- [Modifié](https://gitlab.com/gitlab-org/glql/-/merge_requests/416) pour couvrir les pipelines dans tous les états, y compris les pipelines en cours, dans GitLab 19.2.
- Les paramètres `granularity` et `quantile` configurables ont été [introduits](https://gitlab.com/gitlab-org/glql/-/issues/130) dans GitLab 19.3.
- Les métriques `durationMin`, `durationMax`, `durationMean` et `durationSum` ont été [introduites](https://gitlab.com/gitlab-org/glql/-/merge_requests/507) dans GitLab 19.5.
- Les opérateurs `!=` et `not in` sur les filtres `ref`, `source` et `status` ont été [introduits](https://gitlab.com/gitlab-org/glql/-/merge_requests/537) dans GitLab 19.5.

{{< /history >}}

Le mode analytique retourne des métriques agrégées pour les pipelines dans tous les états, y compris les pipelines en cours, avec des données généralement disponibles dans un délai de dix minutes.

Pour interroger des enregistrements de pipeline individuels, utilisez [Pipelines](pipelines.md).

## Portées autorisées {#allowed-scopes}

| Portée     | Description                                                          |
| --------- | -------------------------------------------------------------------- |
| `project` | Interroger les pipelines dans un projet spécifique.                               |
| `group`   | Interroger les pipelines dans tous les projets d'un groupe, y compris les sous-groupes. |

Pour agréger des pipelines sur plusieurs groupes ou projets, utilisez une liste avec l'opérateur `in`. Pour plus d'informations, voir [plusieurs groupes et projets](_index.md#multiple-groups-and-projects).

## Filtres de requête {#query-filters}

Utilisez ces champs dans le paramètre `query` pour filtrer vos résultats.

| Champ                                  | Nom       | Opérateurs                 |
| -------------------------------------- | ---------- | ------------------------- |
| [Terminé le](#finished-at)         | `finished` | `=`, `>`, `<`, `>=`, `<=` |
| [Ref](#ref)                         | `ref`      | `=`, `!=`, `in`, `not in` |
| [Source](#source)                   | `source`   | `=`, `!=`, `in`, `not in` |
| [Démarré le](#started-at)           | `started`  | `=`, `>`, `<`, `>=`, `<=` |
| [Statut](#status)                   | `status`   | `=`, `!=`, `in`, `not in` |

### Terminé le {#finished-at}

**Description** : filtrer les pipelines par leur date de fin.

**Types de valeurs autorisés** :

- `AbsoluteDate` (au format `YYYY-MM-DD`)
- `RelativeDate` (au format `<sign><digit><unit>`, où le signe est `+`, `-`, ou omis, le chiffre est un entier, et `unit` est l'un des suivants : `d` (jours), `w` (semaines), `m` (mois) ou `y` (années))

**Notes** :

- Pour l'opérateur `=`, la plage horaire est considérée de 00 h 00 à 23 h 59 dans le fuseau horaire de l'utilisateur.

### Ref {#ref}

**Description** : filtrer les pipelines par la ref Git (nom de branche ou de tag) sur laquelle ils se sont exécutés.

**Types de valeurs autorisés** :

- `String`
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs valeurs)

**Notes** :

- `!=` et `not in` retournent uniquement les pipelines qui ont une ref. Les pipelines qui n'en ont pas sont exclus ; ainsi, `ref != "main"` n'est pas équivalent à tous les pipelines sauf ceux sur `main`.

### Source {#source}

**Description** : filtrer les pipelines par leur événement déclencheur.

**Types de valeurs autorisés** :

- `String`
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs valeurs)

**Notes** :

- `!=` et `not in` retournent uniquement les pipelines qui ont une source. Les pipelines qui n'en ont pas sont exclus.
- L'exclusion d'une source que GitLab ne reconnaît pas n'exclut rien. La validation des valeurs de source est proposée dans le [ticket 629846](https://gitlab.com/gitlab-org/gitlab/-/issues/629846).

### Démarré le {#started-at}

**Description** : filtrer les pipelines par leur date de début.

**Types de valeurs autorisés** :

- `AbsoluteDate` (au format `YYYY-MM-DD`)
- `RelativeDate` (au format `<sign><digit><unit>`, où le signe est `+`, `-`, ou omis, le chiffre est un entier, et `unit` est l'un des suivants : `d` (jours), `w` (semaines), `m` (mois) ou `y` (années))

**Notes** :

- Pour l'opérateur `=`, la plage horaire est considérée de 00 h 00 à 23 h 59 dans le fuseau horaire de l'utilisateur.

### Statut {#status}

**Description** : filtrer les pipelines par leur statut CI/CD.

**Types de valeurs autorisés** :

- `Enum`, l'un des suivants : `canceled`, `canceling`, `created`, `failed`, `manual`, `pending`, `preparing`, `running`, `scheduled`, `skipped`, `success`, `waiting_for_callback`, ou `waiting_for_resource`
- `List` (utilisez l'opérateur `in` ou `not in` pour plusieurs valeurs)

## Dimensions {#dimensions}

| Dimension   | Nom       | Description                              |
| ----------- | ---------- | ---------------------------------------- |
| Terminé le | `finished` | Regrouper par date de fin. Accepte un [paramètre `granularity`](../_index.md#field-parameters) parmi `daily`, `weekly`, `monthly`, ou un nombre de jours tel que `30d` (par défaut : `weekly`), et un `origin` facultatif. Par exemple, `finished(daily)` ou `finished(granularity=30d, origin=2026-07-16)`. |
| Projet     | `project`  | Regrouper par projet.                        |
| Ref         | `ref`      | Regrouper par ref Git (branche ou tag).        |
| Source      | `source`   | Regrouper par événement déclencheur du pipeline.    |
| Démarré le  | `started`  | Regrouper par date de début. Accepte un [paramètre `granularity`](../_index.md#field-parameters) parmi `daily`, `weekly`, `monthly`, ou un nombre de jours tel que `30d` (par défaut : `weekly`), et un `origin` facultatif. Par exemple, `started(daily)` ou `started(granularity=30d, origin=2026-07-16)`. |
| Statut      | `status`   | Regrouper par statut de pipeline.                |

## Métriques {#metrics}

Un pipeline est considéré comme terminé lorsqu'il a fini son traitement et atteint un état final : réussi, échoué, annulé ou ignoré.

| Métrique            | Nom               | Description                                            |
| ----------------- | ------------------ | ------------------------------------------------------ |
| Taux d'annulation     | `canceledRate`     | Ratio de pipelines annulés par rapport aux pipelines terminés.    |
| Durée maximale      | `durationMax`      | Durée de pipeline la plus longue, en secondes.                |
| Durée moyenne     | `durationMean`     | Durée moyenne des pipelines, en secondes.                |
| Durée minimale      | `durationMin`      | Durée de pipeline la plus courte, en secondes.               |
| Quantile de durée | `durationQuantile` | Quantile de durée des pipelines, en secondes. Accepte un [paramètre `quantile`](../_index.md#field-parameters) compris entre `0.01` et `0.99` (par défaut : `0.95`). Par exemple, `durationQuantile(0.5)`. |
| Somme des durées      | `durationSum`      | Durée totale de tous les pipelines, en secondes.          |
| Taux d'échec      | `failureRate`      | Ratio de pipelines échoués par rapport aux pipelines terminés.      |
| Taux d'omission      | `skippedRate`      | Ratio de pipelines ignorés par rapport aux pipelines terminés.     |
| Taux de réussite      | `successRate`      | Ratio de pipelines réussis par rapport aux pipelines terminés.  |
| Nombre total       | `totalCount`       | Nombre total de pipelines, y compris ceux en cours. |

## Champs de tri {#sort-fields}

Triez selon n'importe quel champ inclus dans les dimensions ou métriques sélectionnées. Pour plus d'informations, voir [tri en mode analytique](../_index.md#sorting).

## Exemples {#examples}

- Taux de réussite et d'échec des pipelines par ref pour les 30 derniers jours :

  ````yaml
  ```glql
  title: "Pipeline success and failure rates by branch (last 30 days)"
  display: table
  mode: analytics
  query: type = Pipeline and project = "gitlab-org/gitlab" and finished >= -30d
  dimensions: ref as "Ref"
  metrics: totalCount as "Total", successRate as "Success rate", failureRate as "Failure rate"
  sort: totalCount desc
  ```
  ````

- Pipelines avec un statut autre que `success`, hors des branches par défaut, pour les 30 derniers jours :

  ````yaml
  ```glql
  title: "Pipelines not successful, off the default branches (last 30 days)"
  display: table
  mode: analytics
  query: type = Pipeline and project = "gitlab-org/gitlab" and finished >= -30d and status != success and ref not in ("main", "master")
  dimensions: ref as "Ref"
  metrics: totalCount as "Pipelines", failureRate as "Failure rate"
  sort: totalCount desc
  limit: 10
  ```
  ````

- Tendance de durée des pipelines par semaine pour une ref spécifique :

  ````yaml
  ```glql
  title: "Weekly pipeline duration trend for master"
  display: table
  mode: analytics
  query: type = Pipeline and project = "gitlab-org/gitlab" and ref = "master" and finished >= -90d
  dimensions: finished as "Week"
  metrics: totalCount as "Total", durationQuantile as "p95 duration (s)"
  sort: finished desc
  ```
  ````

- Durée médiane et p95 des pipelines par semaine :

  ````yaml
  ```glql
  title: "Median and p95 pipeline duration by week"
  display: table
  mode: analytics
  query: type = Pipeline and project = "gitlab-org/gitlab" and finished >= -90d
  dimensions: finished(weekly) as "Week", status as "Status"
  metrics: durationQuantile(0.5) as "Median", durationQuantile(0.95) as "p95", totalCount as "Total"
  sort: Median desc
  ```
  ````

- Métriques globales des pipelines pour un groupe, sans regroupement :

  ````yaml
  ```glql
  title: "Overall pipeline metrics for gitlab-org"
  display: table
  mode: analytics
  query: type = Pipeline and group = "gitlab-org" and finished >= -7d
  metrics: totalCount as "Total", successRate as "Success rate", failureRate as "Failure rate", canceledRate as "Canceled rate"
  ```
  ````

- Pipelines regroupés par source et statut, filtrés sur une plage de dates :

  ````yaml
  ```glql
  title: "Pipelines by source and status (Q1 2026)"
  display: table
  mode: analytics
  query: type = Pipeline and project = "gitlab-org/gitlab" and finished >= "2026-01-01" and finished <= "2026-03-31"
  dimensions: source as "Source", status as "Status"
  metrics: totalCount as "Total"
  sort: totalCount desc
  ```
  ````

- Filtrer sur des refs et des statuts spécifiques à l'échelle d'un groupe :

  ````yaml
  ```glql
  title: "Default branch pipeline outcomes across gitlab-org"
  display: table
  mode: analytics
  query: type = Pipeline and group = "gitlab-org" and finished >= -14d and ref in ("master", "main") and status in ("success", "failed")
  dimensions: project as "Project", status as "Status"
  metrics: totalCount as "Total", successRate as "Success rate"
  sort: totalCount desc
  limit: 20
  ```
  ````
