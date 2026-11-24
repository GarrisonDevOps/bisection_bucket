---
stage: Data Access
group: Database Frameworks
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "API REST pour lister, récupérer, mettre en pause et reprendre les migrations en arrière-plan par lots."
title: API des migrations en arrière-plan par lots
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Utilisez cette API pour surveiller et gérer les [migrations en arrière-plan par lots](../../update/background_migrations.md).

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

## Lister les 20 dernières migrations en arrière-plan par lots {#list-the-last-20-batched-background-migrations}

Lister toutes les migrations en arrière-plan par lots.

```plaintext
GET /api/v4/admin/batched_background_migrations
```

Attributs pris en charge :

| Attribut        | Type   | Obligatoire | Description |
|------------------|--------|----------|-------------|
| `database`       | Chaîne | Non       | Nom de la base de données. Par défaut : `main`. |
| `job_class_name` | Chaîne | Non       | Filtrer les migrations par nom de classe de job. |

En cas de succès, renvoie [`200 OK`](../rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut                  | Type     | Description |
|----------------------------|----------|-------------|
| `column_name`              | Chaîne   | Nom de la colonne sur laquelle la migration itère. |
| `created_at`               | datetime | Horodatage de la création de la migration. |
| `estimated_time_remaining` | Chaîne   | Temps estimé avant la fin de la migration. Parfois null |
| `id`                       | Entier  | ID de la migration en arrière-plan par lots. |
| `job_class_name`           | Chaîne   | Nom de la classe de job de migration. |
| `progress`                 | float    | Pourcentage de progression de la migration. |
| `status`                   | Chaîne   | Statut de la migration. Peut être `paused`, `active`, `finished`, `failed`, `finalizing` ou `finalized`. |
| `table_name`               | Chaîne   | Nom de la table sur laquelle la migration itère. |

Exemple de requête :

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/admin/batched_background_migrations"
```

Exemple de réponse :

```json
[
  {
    "id": 1234,
    "job_class_name": "CopyColumnUsingBackgroundMigrationJob",
    "table_name": "events",
    "column_name": "id",
    "status": "active",
    "progress": 50.0,
    "created_at": "2022-11-28T16:26:39+02:00",
    "estimated_time_remaining": "1 day"
  }
]
```

## Récupérer une migration en arrière-plan par lots {#retrieve-a-batched-background-migration}

Récupérer une migration en arrière-plan par lots.

```plaintext
GET /api/v4/admin/batched_background_migrations/:id
```

Attributs pris en charge :

| Attribut  | Type    | Obligatoire | Description |
|------------|---------|----------|-------------|
| `id`       | Entier | Oui      | ID de la migration en arrière-plan par lots. |
| `database` | Chaîne  | Non       | Nom de la base de données. Par défaut : `main`. |

En cas de succès, renvoie [`200 OK`](../rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut                  | Type     | Description |
|----------------------------|----------|-------------|
| `column_name`              | Chaîne   | Nom de la colonne sur laquelle la migration itère. |
| `created_at`               | datetime | Horodatage de la création de la migration. |
| `estimated_time_remaining` | Chaîne   | Temps estimé avant la fin de la migration. |
| `id`                       | Entier  | ID de la migration en arrière-plan par lots. |
| `job_class_name`           | Chaîne   | Nom de la classe de job de migration. |
| `progress`                 | float    | Pourcentage de progression de la migration. |
| `status`                   | Chaîne   | Statut de la migration. Peut être `paused`, `active`, `finished`, `failed`, `finalizing` ou `finalized`. |
| `table_name`               | Chaîne   | Nom de la table sur laquelle la migration itère. |

Exemple de requête :

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/admin/batched_background_migrations/1234"
```

Exemple de réponse :

```json
{
  "id": 1234,
  "job_class_name": "CopyColumnUsingBackgroundMigrationJob",
  "table_name": "events",
  "column_name": "id",
  "status": "active",
  "progress": 50.0,
  "created_at": "2022-11-28T16:26:39+02:00",
  "estimated_time_remaining": "1 day"
}
```

## Mettre en pause une migration en arrière-plan par lots {#pause-a-batched-background-migration}

Mettre en pause une migration en arrière-plan par lots. Vous pouvez mettre en pause uniquement les migrations avec un statut `active`.

```plaintext
PUT /api/v4/admin/batched_background_migrations/:id/pause
```

Attributs pris en charge :

| Attribut  | Type    | Obligatoire | Description |
|------------|---------|----------|-------------|
| `id`       | Entier | Oui      | ID de la migration en arrière-plan par lots. |
| `database` | Chaîne  | Non       | Nom de la base de données. Par défaut : `main`. |

En cas de succès, renvoie [`200 OK`](../rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut                  | Type     | Description |
|----------------------------|----------|-------------|
| `column_name`              | Chaîne   | Nom de la colonne sur laquelle la migration itère. |
| `created_at`               | datetime | Horodatage de la création de la migration. |
| `estimated_time_remaining` | Chaîne   | Temps estimé avant la fin de la migration. |
| `id`                       | Entier  | ID de la migration en arrière-plan par lots. |
| `job_class_name`           | Chaîne   | Nom de la classe de job de migration. |
| `progress`                 | float    | Pourcentage de progression de la migration. |
| `status`                   | Chaîne   | Statut de la migration. Peut être `paused`, `active`, `finished`, `failed`, `finalizing` ou `finalized`. |
| `table_name`               | Chaîne   | Nom de la table sur laquelle la migration itère. |

Si la migration ne possède pas de statut `active`, retourne [`422 Unprocessable Entity`](../rest/troubleshooting.md#status-codes).

Exemple de requête :

```shell
curl --request PUT \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/admin/batched_background_migrations/1234/pause"
```

Exemple de réponse :

```json
{
  "id": 1234,
  "job_class_name": "CopyColumnUsingBackgroundMigrationJob",
  "table_name": "events",
  "column_name": "id",
  "status": "paused",
  "progress": 50.0,
  "created_at": "2022-11-28T16:26:39+02:00",
  "estimated_time_remaining": "1 day"
}
```

## Reprendre une migration en arrière-plan par lots {#resume-a-batched-background-migration}

Reprendre une migration en arrière-plan par lots. Vous pouvez reprendre uniquement les migrations avec un statut `paused`.

```plaintext
PUT /api/v4/admin/batched_background_migrations/:id/resume
```

Attributs pris en charge :

| Attribut  | Type    | Obligatoire | Description |
|------------|---------|----------|-------------|
| `id`       | Entier | Oui      | ID de la migration en arrière-plan par lots. |
| `database` | Chaîne  | Non       | Nom de la base de données. Par défaut : `main`. |

En cas de succès, renvoie [`200 OK`](../rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut                  | Type     | Description |
|----------------------------|----------|-------------|
| `column_name`              | Chaîne   | Nom de la colonne sur laquelle la migration itère. |
| `created_at`               | datetime | Horodatage de la création de la migration. |
| `estimated_time_remaining` | Chaîne   | Temps estimé avant la fin de la migration. |
| `id`                       | Entier  | ID de la migration en arrière-plan par lots. |
| `job_class_name`           | Chaîne   | Nom de la classe de job de migration. |
| `progress`                 | float    | Pourcentage de progression de la migration. |
| `status`                   | Chaîne   | Statut de la migration. Peut être `paused`, `active`, `finished`, `failed`, `finalizing` ou `finalized`. |
| `table_name`               | Chaîne   | Nom de la table sur laquelle la migration itère. |

Si la migration ne possède pas de statut `paused`, retourne [`422 Unprocessable Entity`](../rest/troubleshooting.md#status-codes).

Exemple de requête :

```shell
curl --request PUT \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/admin/batched_background_migrations/1234/resume"
```

Exemple de réponse :

```json
{
  "id": 1234,
  "job_class_name": "CopyColumnUsingBackgroundMigrationJob",
  "table_name": "events",
  "column_name": "id",
  "status": "active",
  "progress": 50.0,
  "created_at": "2022-11-28T16:26:39+02:00",
  "estimated_time_remaining": "1 day"
}
```
