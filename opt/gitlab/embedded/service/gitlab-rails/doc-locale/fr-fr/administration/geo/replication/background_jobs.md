---
stage: GitLab Dedicated
group: Geo
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Jobs en arrière-plan Geo
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Geo conserve toutes les intentions de synchronisation et de vérification dans des tables de registre de la base de données de suivi Geo, et non dans les arguments de job Sidekiq. Si un job est interrompu, l'enregistrement du registre conserve son état et les planificateurs basés sur cron remettent le travail en file d'attente. Cette conception rend Geo fondamentalement résistant aux pannes.

## États de synchronisation du registre {#registry-sync-states}

Chaque type de données réplicable dispose d'un enregistrement de registre sur le site secondaire qui suit l'état de synchronisation :

| État | Description |
|-------|-------------|
| `pending` | Nécessite une synchronisation. Pris en charge par le cron du planificateur de synchronisation. |
| `started` | Synchronisation en cours. Si le worker est interrompu, l'enregistrement reste dans cet état. |
| `synced` | Réplication réussie. |
| `failed` | Échec de la synchronisation. Possède un horodatage `retry_at` pour la nouvelle tentative avec backoff exponentiel. |

Si un job de synchronisation est interrompu, le registre reste dans l'état `started`. `Geo::SyncTimeoutCronWorker`, qui s'exécute toutes les 10 minutes, détecte l'état du job de synchronisation et marque le registre comme `failed` avec un backoff de nouvelle tentative. Le worker cron du planificateur de synchronisation remet ensuite le registre en file d'attente pour la synchronisation.

## Mécanismes de récupération {#recovery-mechanisms}

Les workers cron suivants assurent la récupération automatique. Leurs planifications sont définies dans [`ee/config/schedule.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/config/schedule.yml) et sont configurables.

Le nom du job cron correspond au nom affiché dans l'onglet **Cron** du tableau de bord Sidekiq dans la [zone **Admin**](../../admin_area.md#background-jobs).

| Mécanisme | Worker | Nom du job cron | Planification par défaut | Objectif |
|-----------|--------|---------------|------------------|---------|
| Récupération après expiration de la synchronisation | `Geo::SyncTimeoutCronWorker` | `geo_sync_timeout_cron_worker` | Toutes les 10 min (secondaire) | Marque les registres bloqués à l'état `started` comme `failed` avec un backoff de nouvelle tentative. |
| Planificateur de synchronisation des blobs | `Geo::RegistrySyncWorker` | `geo_registry_sync_worker` | Toutes les 1 min (secondaire) | Interroge les registres de blobs `pending` et `failed` et met en file d'attente `Geo::SyncWorker`. |
| Planificateur de synchronisation des dépôts | `Geo::RepositoryRegistrySyncWorker` | `geo_repository_registry_sync_worker` | Toutes les 1 min (secondaire) | Interroge les registres de dépôts `pending` et `failed` et met en file d'attente `Geo::SyncWorker`. |
| Cohérence du registre | `Geo::Secondary::RegistryConsistencyWorker` | `geo_secondary_registry_consistency_worker` | Toutes les 1 min (secondaire) | Crée les enregistrements de registre manquants pour les réplicables non suivis. Détecte les registres orphelins. |
| Expiration de la vérification | `Geo::VerificationTimeoutWorker` | Déclenché par `geo_verification_cron_worker` | Toutes les 1 min (primaire et secondaire) | Marque la vérification bloquée dans l'état `verification_started` comme `verification_failed`. |
| Planificateur de vérification | `Geo::VerificationCronWorker` | `geo_verification_cron_worker` | Toutes les 1 min (primaire et secondaire) | Déclenche les workers de lot de vérification, d'expiration, de re-vérification et de remplissage d'état. |

## Référence de sécurité des files d'attente {#queue-safety-reference}

Les sections suivantes fournissent des informations de sécurité par worker pour les files d'attente Sidekiq de Geo.

### Workers cron {#cron-workers}

Les workers cron sont planifiés automatiquement et se réexécutent au prochain tick cron si leur file d'attente est vidée. Toutes les files d'attente de workers cron peuvent être vidées en toute sécurité.

| Worker | Objectif | Vidage de file d'attente sécurisé | Conséquences négatives du vidage | Mécanisme de récupération |
|--------|-------------|:-------------------:|-----------------------------------|-------------------|
| `Geo::RegistrySyncWorker` | Interroge les registres de blobs en attente et en échec. Met en file d'attente `Geo::SyncWorker`. | Oui | La synchronisation est retardée jusqu'au prochain tick cron. | Se réexécute toutes les 1 min. |
| `Geo::RepositoryRegistrySyncWorker` | Interroge les registres de dépôts en attente et en échec. Met en file d'attente `Geo::SyncWorker`. | Oui | La synchronisation est retardée jusqu'au prochain tick cron. | Se réexécute toutes les 1 min. |
| `Geo::SyncTimeoutCronWorker` | Recherche les registres bloqués à l'état `started`. Les marque `failed` avec un backoff de nouvelle tentative. | Oui | Les registres bloqués dans l'état `started` ne sont pas transférés vers l'état `failed` avant le prochain tick. La synchronisation reprend après le prochain tick. | Se réexécute toutes les 10 min. |
| `Geo::Secondary::RegistryConsistencyWorker` | Analyse tous les types de registres. Crée les registres manquants. Détecte les registres orphelins et met en file d'attente `Geo::DestroyWorker`. | Oui | Les registres manquants ne sont pas créés et les registres orphelins ne sont pas nettoyés avant le prochain tick. | Se réexécute toutes les 1 min. |
| `Geo::VerificationCronWorker` | Déclenche tous les sous-workers de vérification. | Oui | La vérification est retardée jusqu'au prochain tick cron. | Se réexécute toutes les 1 min. |
| `Geo::VerificationTimeoutWorker` | Récupère les enregistrements bloqués dans l'état `verification_started`. | Oui | Les enregistrements bloqués dans l'état `verification_started` ne sont pas transférés avant le prochain tick. | Se réexécute toutes les 1 min. |
| `Geo::PruneEventLogWorker` | Supprime les anciennes entrées du journal d'événements que tous les sites secondaires ont consommées (site primaire uniquement). | Oui | Le journal d'événements s'agrandit jusqu'à la prochaine exécution du worker. Aucune perte de données. | Se réexécute toutes les 5 min. |
| `Geo::MetricsUpdateWorker` | Calcule le statut du nœud, met à jour les jauges Prometheus, envoie le statut au site primaire. | Oui | Les métriques deviennent obsolètes jusqu'à la prochaine exécution du worker. | Se réexécute toutes les 1 min. |
| `Geo::SidekiqCronConfigWorker` | Active et désactive les jobs cron en fonction du type de nœud (primaire ou secondaire). | Oui | La configuration des jobs cron peut être incorrecte jusqu'à la prochaine exécution du worker. | Se réexécute toutes les 1 min. |

### Workers de synchronisation (secondaire) {#sync-workers-secondary}

| Worker | Objectif | Vidage de file d'attente sécurisé | Conséquences négatives du vidage | Mécanisme de récupération |
|--------|-------------|:-------------------:|-----------------------------------|-------------------|
| `Geo::SyncWorker` | Télécharge un seul blob ou récupère un seul dépôt depuis le site primaire. | Oui | Les registres des jobs en cours restent dans l'état `started`. La synchronisation est retardée jusqu'à la récupération. | `SyncTimeoutCronWorker` transfère les registres bloqués vers l'état `failed`. Le planificateur de synchronisation remet en file d'attente. |
| `Geo::ContainerRepositorySyncWorker` | Synchronise un seul dépôt de conteneur depuis le site primaire. | Oui | Le registre conserve son état. La synchronisation est retardée jusqu'à la récupération. | Le planificateur de synchronisation remet en file d'attente. |
| `Geo::BulkRegistryResyncWorker` | Déclenche la re-synchronisation en masse d'une classe de registre. | Oui | La re-synchronisation en masse ne démarre pas. Les registres individuels conservent leur état. | L'appelant remet en file d'attente. |

### Workers d'événements (primaire et secondaire) {#event-workers-primary-and-secondary}

> [!warning]
> Lorsque vous videz les files d'attente des workers d'événements, les événements présents dans la file d'attente peuvent être perdus. Les événements perdus peuvent entraîner une obsolescence temporaire des données sur le site secondaire.

| Worker | Objectif | Vidage de file d'attente sécurisé | Conséquences négatives du vidage | Mécanisme de récupération |
|--------|-------------|:-------------------:|-----------------------------------|-------------------|
| `Geo::EventWorker` | Traite les événements de réplication Geo (`created`, `updated`, `deleted`) sur le site secondaire. | Utiliser avec précaution. | La perte d'événements `updated` peut laisser une ressource obsolète jusqu'à la re-vérification ou au prochain événement de mise à jour. La perte d'événements `deleted` peut laisser des fichiers orphelins sur le site secondaire (espace disque gaspillé, aucune perte de données). La perte d'événements `created` n'a aucun effet durable. Dispose de 3 nouvelles tentatives Sidekiq. | Même si toutes les nouvelles tentatives échouent, l'enregistrement du registre existe et le planificateur de synchronisation remet en file d'attente. `RegistryConsistencyWorker` détecte également les registres orphelins. |
| `Geo::BatchEventCreateWorker` | Insère en masse des événements Geo sur le site primaire. | Utiliser avec précaution. | Les événements présents dans la file d'attente sont perdus en cas de vidage. Les sites secondaires peuvent ne pas être informés des modifications jusqu'à la re-vérification. | `RegistryConsistencyWorker` sur le site secondaire détecte finalement les registres manquants (toutes les 1 min). |
| `Geo::CreateRepositoryUpdatedEventWorker` | Crée un événement Geo lorsqu'un dépôt est mis à jour sur le site primaire. | Utiliser avec précaution. | Identique à `Geo::BatchEventCreateWorker`. | Identique à `Geo::BatchEventCreateWorker`. |

### Workers de vérification (primaire et secondaire) {#verification-workers-primary-and-secondary}

| Worker | Objectif | Vidage de file d'attente sécurisé | Conséquences négatives du vidage | Mécanisme de récupération |
|--------|-------------|:-------------------:|-----------------------------------|-------------------|
| `Geo::VerificationBatchWorker` | Calcule les checksums de lots d'enregistrements. | Oui | La vérification est retardée. | Le cron remet en file d'attente. `VerificationTimeoutWorker` intercepte les enregistrements bloqués. |
| `Geo::ReverificationBatchWorker` | Marque les enregistrements déjà vérifiés pour une re-vérification périodique. | Oui | La re-vérification est retardée. | Le cron remet en file d'attente. |
| `Geo::VerificationStateBackfillWorker` | Remplit rétroactivement la table d'état de vérification pour les types réplicables. | Oui | Le remplissage rétroactif est retardé. Le bail exclusif expire dans 30 min. | Se remet lui-même en file d'attente. |
| `Geo::BulkPrimaryVerificationWorker` | Déclenche la vérification en masse d'une classe de modèle sur le site primaire. | Oui | La vérification en masse ne démarre pas. | L'appelant remet en file d'attente. |
| `Geo::BulkRegistryReverificationWorker` | Déclenche la re-vérification en masse d'une classe de registre sur le site secondaire. | Oui | La re-vérification en masse ne démarre pas. | L'appelant remet en file d'attente. |

### Workers de suppression (secondaire) {#destroy-workers-secondary}

> [!warning]
> Lorsque vous videz la file d'attente du worker de suppression, les jobs perdus peuvent laisser des fichiers ou des dépôts orphelins sur le site secondaire.

| Worker | Objectif | Vidage de file d'attente sécurisé | Conséquences négatives du vidage | Mécanisme de récupération |
|--------|-------------|:-------------------:|-----------------------------------|-------------------|
| `Geo::DestroyWorker` | Supprime un fichier ou un dépôt répliqué sur le site secondaire après la suppression sur le site primaire. | Utiliser avec précaution. | Les fichiers ou dépôts orphelins restent sur le site secondaire, gaspillant de l'espace disque. Aucune perte de données. Dispose de 3 nouvelles tentatives Sidekiq. | `RegistryConsistencyWorker` détecte les registres orphelins et remet en file d'attente `DestroyWorker`. |
