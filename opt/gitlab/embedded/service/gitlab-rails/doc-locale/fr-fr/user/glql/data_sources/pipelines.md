---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Pipelines
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228521) dans GitLab 18.11.
- Les champs `commit`, `commitPath`, `refPath`, `stages` et `user` ont été [ajoutés](https://gitlab.com/gitlab-org/glql/-/merge_requests/361) dans GitLab 18.11.

{{< /history >}}

## Modes autorisés {#allowed-modes}

- Mode standard (par défaut) : interroger les enregistrements de pipeline.
- Mode Analytics : interroger les métriques de pipeline agrégées. Pour plus d'informations, voir [Analytique de pipeline](pipeline_analytics.md).

> [!note]
> Le mode standard ne prend pas en charge le tri.

## Portées autorisées {#allowed-scopes}

| Portée     | Description                              |
| --------- | ---------------------------------------- |
| `project` | Interroger les pipelines dans un projet spécifique.   |

Pour plus d'informations, voir [les portées](_index.md#scopes).

## Filtres de requête {#query-filters}

Utilisez ces champs dans le paramètre `query` pour filtrer vos résultats.

| Champ                                          | Nom (et alias)                             | Opérateurs                  |
| ---------------------------------------------- | -------------------------------------------- | -------------------------- |
| [Auteur](#pipeline-author)                     | `author`                                     | `=`                        |
| [Ref](#pipeline-ref)                           | `ref`                                        | `=`                        |
| [Portée](#pipeline-scope)                       | `scope`                                      | `=`                        |
| [SHA](#pipeline-sha)                           | `sha`                                        | `=`                        |
| [Source](#pipeline-source)                     | `source`                                     | `=`                        |
| [Statut](#pipeline-status)                     | `status`                                     | `=`                        |
| [Mis à jour le](#pipeline-updated-at)             | `updated`, `updatedAt`                       | `=`, `>`, `<`, `>=`, `<=`  |

### Auteur {#pipeline-author}

**Description** : filtrer les pipelines par l'utilisateur qui les a déclenchés.

**Types de valeurs autorisés** :

- `String`
- `User` (par exemple, `@username`)

### Ref {#pipeline-ref}

**Description** : filtrer les pipelines par la ref Git (nom de branche ou de tag) sur laquelle ils ont été exécutés.

**Types de valeurs autorisés** : `String`

### Portée {#pipeline-scope}

**Description** : filtrer les pipelines par leur portée.

**Types de valeurs autorisés** :

- `Enum`, l'une des valeurs suivantes : `branches`, `tags`, `finished`, `pending` ou `running`

### SHA {#pipeline-sha}

**Description** : filtrer les pipelines par le SHA du commit.

**Types de valeurs autorisés** : `String`

### Source {#pipeline-source}

**Description** : filtrer les pipelines par ce qui les a déclenchés.

**Types de valeurs autorisés** : `String`

### Statut {#pipeline-status}

**Description** : filtrer les pipelines par leur statut CI/CD.

**Types de valeurs autorisés** :

- `Enum`, l'une des valeurs suivantes : `canceled`, `canceling`, `created`, `failed`, `manual`, `pending`, `preparing`, `running`, `scheduled`, `skipped`, `success`, `waiting_for_callback` ou `waiting_for_resource`

### Mis à jour le {#pipeline-updated-at}

**Description** : filtrer les pipelines par date de dernière mise à jour.

**Types de valeurs autorisés** :

- `AbsoluteDate` (au format `YYYY-MM-DD`)
- `RelativeDate` (au format `<sign><digit><unit>`, où le signe est `+`, `-` ou omis, le chiffre est un entier, et `unit` est l'une des valeurs suivantes : `d` (jours), `w` (semaines), `m` (mois) ou `y` (années))

**Notes** :

- Pour l'opérateur `=`, la plage horaire est considérée de 00:00 à 23:59 dans le fuseau horaire de l'utilisateur.

## Champs d'affichage {#display-fields}

| Champ              | Nom (et alias)                   | Description |
| ------------------ | ---------------------------------- | ----------- |
| Actif             | `active`                           | Afficher si le pipeline est actif |
| Annulable         | `cancelable`                       | Afficher si le pipeline peut être annulé |
| Enfant              | `child`                            | Afficher s'il s'agit d'un pipeline enfant |
| Commit             | `commit`                           | Afficher les détails du commit (ID, ID court, titre, nom de l'auteur, URL web) |
| Chemin du commit        | `commitPath`                       | Afficher le chemin vers le commit qui a déclenché le pipeline |
| Commité le       | `committed`, `committedAt`         | Afficher l'horodatage du commit |
| Terminé           | `complete`                         | Afficher si le pipeline est terminé |
| Minutes de calcul    | `computeMinutes`                   | Afficher les minutes de calcul utilisées |
| Source de configuration      | `configSource`                     | Afficher la source de configuration du pipeline |
| Couverture           | `coverage`                         | Afficher le pourcentage de couverture du code |
| Créé le         | `created`, `createdAt`             | Afficher la date de création du pipeline |
| Durée           | `duration`                         | Afficher la durée du pipeline |
| Nombre de jobs échoués  | `failedJobsCount`                  | Afficher le nombre de jobs échoués |
| Raison de l'échec     | `failureReason`                    | Afficher la raison de l'échec du pipeline |
| Terminé le        | `finished`, `finishedAt`           | Afficher la date de fin du pipeline |
| ID                 | `id`                               | Afficher l'ID du pipeline |
| IID                | `iid`                              | Afficher l'ID interne du pipeline |
| Dernière version             | `latest`                           | Afficher s'il s'agit du dernier pipeline pour la ref |
| Nom               | `name`                             | Afficher le nom du pipeline |
| Chemin               | `path`                             | Afficher le chemin du pipeline |
| Ref                | `ref`                              | Afficher la ref Git (branche ou tag) |
| Chemin de la ref           | `refPath`                          | Afficher le chemin vers la ref qui a déclenché le pipeline |
| Réessayable          | `retryable`                        | Afficher si le pipeline peut être réessayé |
| SHA                | `sha`                              | Afficher le SHA du commit |
| Source             | `source`                           | Afficher ce qui a déclenché le pipeline |
| Étapes             | `stages`                           | Afficher les étapes du pipeline (nom et statut) |
| Démarré le         | `started`, `startedAt`             | Afficher la date de démarrage du pipeline |
| Statut             | `status`                           | Afficher le statut du pipeline |
| Bloqué              | `stuck`                            | Afficher si le pipeline est bloqué |
| Total des jobs         | `totalJobs`                        | Afficher le nombre total de jobs |
| Mis à jour le         | `updated`, `updatedAt`             | Afficher la date de dernière mise à jour du pipeline |
| Utilisateur               | `user`                             | Afficher l'utilisateur qui a déclenché le pipeline |
| Avertissements           | `warnings`                         | Afficher les avertissements du pipeline |
| Erreurs YAML        | `yamlErrors`                       | Afficher si le pipeline contient des erreurs YAML |
| Messages d'erreur YAML| `yamlErrorMessages`                | Afficher les messages d'erreur YAML |

## Problèmes connus {#known-issues}

- Les requêtes portant sur de grandes plages de dates peuvent provoquer des délais d'expiration.

## Exemples {#examples}

- Lister tous les pipelines du projet `gitlab-org/gitlab` ayant échoué aujourd'hui :

  ````yaml
  ```glql
  title: "Failed pipelines today"
  display: table
  fields: id, ref, status, startedAt
  query: type = Pipeline and project = "gitlab-org/gitlab" and status = failed and updated = today()
  ```
  ````

- Lister tous les pipelines de l'agent Duo dans le projet `gitlab-org/gitlab` :

  ````yaml
  ```glql
  title: "GitLab Duo agent pipelines"
  display: table
  fields: id, ref, status, source, startedAt
  query: type = Pipeline and project = "gitlab-org/gitlab" and source = "duo_workflow"
  ```
  ````
