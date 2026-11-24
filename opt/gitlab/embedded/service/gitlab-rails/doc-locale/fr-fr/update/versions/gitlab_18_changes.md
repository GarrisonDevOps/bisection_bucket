---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Notes de mise à niveau GitLab 18
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Cette page contient des informations de mise à niveau pour les versions mineures et les correctifs de GitLab 18. Assurez-vous de consulter ces instructions pour :

- Votre type d'installation.
- Toutes les versions entre votre version actuelle et votre version cible.

Pour obtenir des informations supplémentaires sur les installations avec le chart Helm, consultez [les notes de mise à niveau du chart Helm 9.0](https://docs.gitlab.com/charts/releases/9_0/).

## Arrêts de mise à niveau obligatoires {#required-upgrade-stops}

Pour offrir un calendrier de mise à niveau prévisible aux administrateurs d'instance, des arrêts de mise à niveau obligatoires sont prévus aux versions suivantes :

- `18.2`
- `18.5`
- `18.8`
- `18.11`

## Référence des notes de mise à niveau {#upgrade-notes-reference}

Ce qui suit est une liste de référence des notes de mise à niveau pour chaque version mineure de GitLab. Chaque élément de la liste pointe vers une section spécifique contenant plus d'informations.

Les éléments marqués d'une méthode d'installation, comme `(Geo)` ou `(Linux package)`, s'appliquent uniquement à cette méthode. Tous les autres éléments s'appliquent à toutes les méthodes d'installation.

### Mise à niveau vers la version 18.11 {#upgrade-to-1811}

Avant de mettre à niveau GitLab vers la version 18.11, consultez les informations suivantes :

- [18.11.0 - 18.11.2] - [Échecs de synchronisation des blobs Geo avec NoMethodError `log_error` sur le stockage de fichiers](#geo-blob-sync-failures-with-log_error-nomethoderror-on-file-storage) (Geo)
- [18.11.0 - 18.11.4] - [La synchronisation des dépôts de conteneurs Geo ignore silencieusement les tags d'index d'images OCI](#geo-container-repository-sync-silently-skips-oci-image-index-tags) (Geo)
- [18.11.0 - 18.11.1] - [Régression du token de job CI lors de l'extraction d'images de conteneurs depuis des projets internes et publics](#ci-job-token-regression-pulling-container-images-from-internal-and-public-projects)
- [18.11.0] - [La mise à niveau vers la version 18.11 déclenche une mise à niveau de la version PostgreSQL 17.7](#postgresql-version-177-upgrade-on-gitlab-1811) (Package Linux, Docker, Geo)
- [18.11.0] - [Mattermost et Spamcheck supprimés des packages SLES 12.5](#mattermost-and-spamcheck-removed-from-sles-125-packages) (Package Linux)
- [18.11.0] - [Les métriques cgroup de Gitaly ont été modifiées et certaines ont été supprimées](#gitaly-cgroup-metrics-changed-and-some-were-removed)
- [18.11.0] - [La configuration compilée par job est soumise à une limite de taille de 1 Mio](#compiled-per-job-config-is-subject-to-a-1-mib-size-limit)

### Mise à niveau vers la version 18.10 {#upgrade-to-1810}

Avant de mettre à niveau GitLab vers la version 18.10, consultez les informations suivantes :

- [18.10.0 - 18.10.3] - [Échec d'installation du package RPM SLES 12.5](#sles-125-rpm-package-installation-failure) (Package Linux)
- [18.10.0 - 18.10.5] - [Échecs de synchronisation des blobs Geo avec NoMethodError `log_error` sur le stockage de fichiers](#geo-blob-sync-failures-with-log_error-nomethoderror-on-file-storage) (Geo)
- [18.10.0 - 18.10.7] - [La synchronisation des dépôts de conteneurs Geo ignore silencieusement les tags d'index d'images OCI](#geo-container-repository-sync-silently-skips-oci-image-index-tags) (Geo)
- [18.10.0 - 18.10.3] - [URL du site Geo bloquée lors de l'utilisation du filtrage sortant](#geo-site-url-blocked-when-using-outbound-filtering) (Geo)
- [18.10.0 - 18.10.4] - [Échecs de téléchargement des blobs Geo](#geo-blob-download-failures) (Geo)
- [18.10.0 - 18.10.3] - [Les jobs limités du site secondaire Geo ne se vident pas](#geo-secondary-throttled-jobs-not-draining) (Geo)
- [18.10.0 - 18.10.3] - [Le limiteur de concurrence Sidekiq entraîne des files d'attente de jobs sur les déploiements Helm chart et Operator](#sidekiq-concurrency-limiter-causes-job-backlogs-on-helm-chart-and-operator-deployments) (Helm chart, Operator)
- [18.10.0] - [La détection des faux positifs de Secret Detection activée par défaut sur tous les projets](#secret-detection-false-positive-detection-enabled-by-default-on-all-projects)
- [18.10.0] - [Le modèle de webhook personnalisé avec des espaces réservés non mis entre guillemets ne peut pas être enregistré](#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved)
- [18.10.0] - [Les variables Dotenv dans les politiques d'exécution de pipeline respectent `variables_override`](#dotenv-variables-in-pipeline-execution-policies-respect-variables_override)

### Mise à niveau vers la version 18.9 {#upgrade-to-189}

Avant de mettre à niveau GitLab vers la version 18.9, consultez les informations suivantes :

- [18.9.1 - 18.9.5] - [Échec d'installation du package RPM SLES 12.5](#sles-125-rpm-package-installation-failure) (Package Linux)
- [18.9.0 - 18.9.5] - [URL du site Geo bloquée lors de l'utilisation du filtrage sortant](#geo-site-url-blocked-when-using-outbound-filtering) (Geo)
- [18.9.0 - 18.9.5] - [Les jobs limités du site secondaire Geo ne se vident pas](#geo-secondary-throttled-jobs-not-draining) (Geo)
- [18.9.0 - 18.9.5] - [Le limiteur de concurrence Sidekiq entraîne des files d'attente de jobs sur les déploiements Helm chart et Operator](#sidekiq-concurrency-limiter-causes-job-backlogs-on-helm-chart-and-operator-deployments) (Helm chart, Operator)
- [18.9.0] - [La mise à niveau vers la version 18.9 échoue avec une CheckViolation PostgreSQL](#upgrade-to-189-fails-with-postgresql-checkviolation)
- [18.9.0] - [Le modèle de webhook personnalisé avec des espaces réservés non mis entre guillemets ne peut pas être enregistré](#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved)

### Mise à niveau vers la version 18.8 {#upgrade-to-188}

Avant de mettre à niveau GitLab vers la version 18.8, consultez les informations suivantes :

- [18.8.2] - [Clés de déploiement et jetons d'accès personnels pour les utilisateurs bloqués invalidés](#deploy-keys-and-personal-access-tokens-for-blocked-users-invalidated)
- [18.8.0] - [Migration en arrière-plan par lots pour les données de fusion des merge requests](#batched-background-migration-for-merge-request-merge-data)
- [18.8.0] - [Erreur de création du dictionnaire ClickHouse](#clickhouse-dictionary-creation-error)
- [18.8.0] - [Migration en arrière-plan par lots pour les données CI réintroduite](#batched-background-migration-for-ci-data-reintroduced)
- [18.8.0] - [Le modèle de webhook personnalisé avec des espaces réservés non mis entre guillemets ne peut pas être enregistré](#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved)

### Mise à niveau vers la version 18.7 {#upgrade-to-187}

Avant de mettre à niveau GitLab vers la version 18.7, consultez les informations suivantes :

- [18.7.2] - [Clés de déploiement et jetons d'accès personnels pour les utilisateurs bloqués invalidés](#deploy-keys-and-personal-access-tokens-for-blocked-users-invalidated)
- [18.7.0] - [Migration des métadonnées des builds CI](#ci-builds-metadata-migration)
- [18.7.0] - [Paramètre des origines autorisées ActionCable Geo](#geo-actioncable-allowed-origins-setting) (Geo)

### Mise à niveau vers la version 18.6 {#upgrade-to-186}

Avant de mettre à niveau GitLab vers la version 18.6, consultez les informations suivantes :

- [18.6.5] - [Correction des requêtes lentes de Geo VerificationStateBackfillWorker](#geo-verificationstatebackfillworker-slow-queries-fix) (Geo)
- [18.6.4] - [Clés de déploiement et jetons d'accès personnels pour les utilisateurs bloqués invalidés](#deploy-keys-and-personal-access-tokens-for-blocked-users-invalidated)
- [18.6.2] - [Limites de taille et de débit de l'API Commits et Files](#commits-and-files-api-size-and-rate-limits)
- [18.6.2] - [Restrictions des runners de la plateforme Duo Agent](#duo-agent-platform-runner-restrictions)

### Mise à niveau vers la version 18.5 {#upgrade-to-185}

Avant de mettre à niveau GitLab vers la version 18.5, consultez les informations suivantes :

- [18.5.4] - [Limites de taille et de débit de l'API Commits et Files](#commits-and-files-api-size-and-rate-limits)
- [18.5.0 - 18.5.1] - [Correction de la migration du curseur de log Geo](#geo-log-cursor-migration-fix) (Geo)
- [18.5.0] - [Finalisation du remplissage des designs de gestion de conception](#finalize-design-management-designs-backfill)
- [18.5.0] - [Les modifications de routage NGINX provoquent des erreurs 404](#nginx-routing-changes-cause-404-errors) (Package Linux)

### Mise à niveau vers la version 18.4 {#upgrade-to-184}

Avant de mettre à niveau GitLab vers la version 18.4, consultez les informations suivantes :

- [18.4.6] - [Limites de taille et de débit de l'API Commits et Files](#commits-and-files-api-size-and-rate-limits)
- [18.4.2 - 18.4.3] - [Erreur nil dans la migration en arrière-plan par lots](#batched-background-migration-nil-error)
- [18.4.1] - [Limites d'entrée JSON pour la prévention des attaques par déni de service](#json-input-limits-for-denial-of-service-prevention)
- [18.4.0 - 18.4.3] - [Correction de la migration du curseur de log Geo](#geo-log-cursor-migration-fix) (Geo)
- [18.4.0 - 18.4.1] - [TypeError de réplication Geo](#geo-replication-typeerror) (Geo)

### Mise à niveau vers la version 18.3 {#upgrade-to-183}

Avant de mettre à niveau GitLab vers la version 18.3, consultez les informations suivantes :

- [18.3.3] - [Limites d'entrée JSON pour la prévention des attaques par déni de service](#json-input-limits-for-denial-of-service-prevention)
- [18.3.0] - [LdapAddOnSeatSyncWorker supprime des sièges Duo](#ldapaddonseatsyncworker-removes-duo-seats)
- [18.3.0] - [Correction de la vérification Rake Geo](#geo-rake-check-fix) (Geo)
- [18.3.0 - 18.3.2] - [Correction du nom de fichier des Pages Geo](#geo-pages-filename-fix) (Geo)

### Mise à niveau vers la version 18.2 {#upgrade-to-182}

Avant de mettre à niveau GitLab vers la version 18.2, consultez les informations suivantes :

- [18.2.7] - [Limites d'entrée JSON pour la prévention des attaques par déni de service](#json-input-limits-for-denial-of-service-prevention)
- [18.2.0] - [Erreurs push lors de la mise à niveau sans interruption de service entre les versions 18.1 et 18.2](#zero-downtime-upgrade-push-errors-between-181-and-182)
- [18.2.0 - 18.2.1] - [Geo VerificationStateBackfillService `ci_job_artifact_states`](#geo-verificationstatebackfillservice-ci_job_artifact_states) (Geo)
- [18.2.0 - 18.2.6] - [Correction du nom de fichier des Pages Geo](#geo-pages-filename-fix) (Geo)

### Mise à niveau vers la version 18.1 {#upgrade-to-181}

Avant de mettre à niveau GitLab vers la version 18.1, consultez les informations suivantes :

- [18.1.0] - [Elasticsearch `strict_dynamic_mapping_exception`](#elasticsearch-strict_dynamic_mapping_exception)
- [18.1.0 - 18.1.1] - [Erreur PostgreSQL `ci_job_artifacts`](#postgresql-ci_job_artifacts-error)
- [18.1.0] - [Bug merge request presque prête](#merge-request-almost-ready-bug)
- [18.1.0] - [Erreurs proxy HTTP 500 Geo](#geo-http-500-proxy-errors) (Geo)
- [18.1.0 - 18.1.3] - [Geo VerificationStateBackfillService `ci_job_artifact_states`](#geo-verificationstatebackfillservice-ci_job_artifact_states) (Geo)
- [18.1.0] - [Correction du nom de fichier des Pages Geo](#geo-pages-filename-fix) (Geo)

### Mise à niveau vers la version 18.0 {#upgrade-to-180}

Avant de mettre à niveau GitLab vers la version 18.0, consultez les informations suivantes :

- [18.0.0] - [PostgreSQL 14 n'est pas pris en charge](#postgresql-14-not-supported)
- [18.0.0] - [Compatibilité binaire de `pg_dump`](#pg_dump-binary-compatibility)
- [18.0.0] - [Échecs de pipeline lors des mises à niveau sans interruption de service depuis la version 17.11](#pipeline-failures-during-zero-downtime-upgrades-from-1711)
- [18.0.0] - [Migrer la configuration Gitaly de `git_data_dirs` vers le stockage](#migrate-gitaly-configuration-from-git_data_dirs-to-storage) (Package Linux)
- [18.0.0 - 18.0.1] - [Erreurs de migration de rétablissement Geo CE vers EE](#geo-ce-to-ee-revert-migration-errors) (Geo)
- [18.0.0 - 18.0.2] - [Erreurs proxy HTTP 500 Geo](#geo-http-500-proxy-errors) (Geo)
- [18.0.0 - 18.0.5] - [Geo VerificationStateBackfillService `ci_job_artifact_states`](#geo-verificationstatebackfillservice-ci_job_artifact_states) (Geo)
- [18.0.0] - [Erreur PRNG non initialisé sur les installations Docker](#prng-is-not-seeded-error-on-docker-installations) (Docker)
- [17.11.0] - [Dépréciation des images Bitnami PostgreSQL et Redis](#bitnami-postgresql-and-redis-image-deprecation) (Helm chart)

## Notes de mise à niveau {#upgrade-notes}

Notes de mise à niveau spécifiques à GitLab 18.

### Les variables Dotenv dans les politiques d'exécution de pipeline respectent `variables_override` {#dotenv-variables-in-pipeline-execution-policies-respect-variables_override}

{{< details >}}

- Édition : GitLab Ultimate

{{< /details >}}

- Affecte : Politiques d'exécution de pipeline
- Versions affectées :

  | Release     | Correctifs affectés |
  | ----------- | ----------------------- |
  | 18.10       | 18.10.0 et ultérieur       |

Dans GitLab 18.10 et versions ultérieures, les variables issues des artefacts dotenv (`artifacts:reports:dotenv`) sont soumises aux mêmes règles `variables_override` que les autres variables d'une politique d'exécution de pipeline (sécurisé par défaut). Auparavant, les variables dotenv pouvaient contourner les restrictions `variables_override`, ce qui compromettait les contrôles de sécurité de la politique.

Si un pipeline s'appuyait sur des variables dotenv pour remplacer des variables définies par la politique, ce comportement ne fonctionne plus lorsque `variables_override.allowed: false` est défini. Pour restaurer le comportement précédent, définissez la nouvelle option `dotenv` sur `allow_override` :

```yaml
variables_override:
  allowed: false
  exceptions: []
  dotenv: allow_override
```

Pour plus d'informations, consultez [les politiques d'exécution de pipeline](../../user/application_security/policies/pipeline_execution_policies.md) et la [merge request 214991](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/214991).

### Échecs de synchronisation des blobs Geo avec NoMethodError `log_error` sur le stockage de fichiers {#geo-blob-sync-failures-with-log_error-nomethoderror-on-file-storage}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo (stockage de fichiers uniquement)
- Versions affectées :

  | Release           | Correctifs affectés | Niveau de correctif résolu |
  | ----------------- |-------------------------|-------------------|
  | 18.11             | 18.11.0 - 18.11.2       | 18.11.3           |
  | 18.10             | 18.10.0 - 18.10.5       | 18.10.6           |
  | 18.0 - 18.9       | Tous les correctifs      | Non corrigé         |

Sur les sites secondaires Geo qui stockent les blobs sur **le stockage de fichiers** (plutôt que sur le stockage d'objets), la réplication des blobs (tels que les artefacts de pipeline, les objets LFS, les téléversements et les artefacts de job) peut échouer avec une erreur trompeuse :

```plaintext
Error while attempting to sync: undefined method `log_error' for an instance of Gitlab::Geo::Replication::BlobDownloader
```

Pour plus d'informations, consultez [le ticket 598565](https://gitlab.com/gitlab-org/gitlab/-/work_items/598565).

### La synchronisation des dépôts de conteneurs Geo ignore silencieusement les tags d'index d'images OCI {#geo-container-repository-sync-silently-skips-oci-image-index-tags}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo (registre de conteneurs)
- Versions affectées :

  | Release     | Correctifs affectés | Niveau de correctif résolu |
  | ----------- | ----------------------- | ----------------- |
  | 18.11       | 18.11.0 - 18.11.4       | 18.11.5           |
  | 18.10       | 18.10.0 - 18.10.7       | 18.10.8           |
  | 18.0 - 18.9 | Tous les correctifs      | Non corrigé         |

Sur les sites secondaires Geo, la synchronisation des dépôts de conteneurs ignorait silencieusement les tags dont le manifeste est un index d'images OCI (`application/vnd.oci.image.index.v1+json`). Les images multi-architectures et les tags de cache BuildKit utilisent couramment ce type de manifeste. Aucune erreur n'était générée et le nombre de tags correspondait, mais `docker pull` d'un tag affecté depuis le site secondaire retournait `manifest unknown`. La même cause principale a également laissé des tags orphelins sur le site secondaire que la synchronisation ne pouvait pas supprimer.

Après avoir mis à niveau les sites principal et secondaire vers une version corrigée, les tags nouvellement synchronisés sont corrects. Les dépôts précédemment affectés convergent lors de leur prochain cycle de vérification, ce qui peut prendre jusqu'à l'intervalle de re-vérification (90 jours par défaut). Pour réparer immédiatement les dépôts affectés, [resynchronisez les dépôts de conteneurs sur le site secondaire](../../administration/geo/replication/container_registry.md#manually-trigger-a-container-registry-sync-event).

Pour plus d'informations, consultez [le ticket 600486](https://gitlab.com/gitlab-org/gitlab/-/work_items/600486).

### Régression du token de job CI lors de l'extraction d'images de conteneurs depuis des projets internes et publics {#ci-job-token-regression-pulling-container-images-from-internal-and-public-projects}

- Affecte : toutes les méthodes d'installation
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif résolu |
  | ------- | ----------------------- | ----------------- |
  | 18.11   | 18.11.0 - 18.11.1       | 18.11.2           |

> [!warning]
> Ne mettez pas à niveau vers GitLab 18.11.0 ou 18.11.1 si des jobs CI s'appuient sur `CI_JOB_TOKEN` pour extraire des images de conteneurs depuis des projets internes ou publics.

Une régression dans GitLab 18.11.0 empêche les jobs CI d'extraire des images de conteneurs depuis des projets internes ou publics en utilisant `CI_JOB_TOKEN`. Les pipelines affectés échouent avec `denied: requested access to the resource is denied`. Le correctif a été rétroporté vers `18-11-stable-ee` mais a été intégré après la création du tag 18.11.1, ce qui fait que les versions 18.11.0 et 18.11.1 sont toutes deux affectées.

Contournements disponibles pour les opérateurs ayant déjà effectué la mise à niveau :

1. Ajoutez chaque projet consommateur à la liste d'autorisation du token de job CI du projet source. Consultez [la sécurité des tokens de job CI/CD](../../ci/jobs/ci_job_token.md#gitlab-cicd-job-token-security).
1. Authentifiez l'extraction du conteneur avec un jeton d'accès personnel, de groupe ou de projet au lieu de `CI_JOB_TOKEN`.
1. Appliquez le commit de rétroportage [`e3c0f308`](https://gitlab.com/gitlab-org/gitlab/-/commit/e3c0f30800f803b8f519e9b937296b068d8f4cca) à l'instance GitLab.

Pour plus d'informations, consultez [le ticket 597223](https://gitlab.com/gitlab-org/gitlab/-/work_items/597223).

### Échec d'installation du package RPM SLES 12.5 {#sles-125-rpm-package-installation-failure}

- Affecte : Paquet Linux
- Versions affectées :

  | Release | Correctifs affectés          | Niveau de correctif installable |
  | ------- | -------------------------------- | ----------------------- |
  | 18.10   | 18.10.0 - 18.10.3                | 18.10.4 - 18.10.5       |
  | 18.9    | 18.9.1 - 18.9.5                  | 18.9.0, 18.9.6          |

> [!warning]
> Sur SLES 12.5, seuls GitLab 18.9.0, 18.10.4 et 18.11.2 peuvent être installés avec succès. Toutes les autres versions de correctifs dans la plage affectée échouent à l'installation.

Les packages Linux GitLab pour SLES 12.5 échouent à l'installation avec `error: install failed` lors de l'utilisation des commandes `rpm` ou `zypper`. La cause principale est une limitation de la taille des données d'en-tête RPM de 16 Mio (`HEADER_DATA_MAX`) dans RPM 4.11.2, qui est la version livrée avec SLES 12 SP5. À mesure que le nombre de fichiers dans le package GitLab a augmenté, l'en-tête RPM sérialisé a dépassé cette limite, ce qui a provoqué l'échec silencieux de la transaction de base de données RPM lors de l'installation.

Le problème a été résolu dans des correctifs spécifiques en réduisant le nombre de fichiers dans le package Linux (voir [la merge request 9215](https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/9215)). Cependant, des correctifs ultérieurs peuvent régresser si le nombre de fichiers augmente à nouveau. Pour installer GitLab sur SLES 12.5, utilisez uniquement les niveaux de correctifs installables répertoriés ci-dessus.

Les distributions SUSE sont [dépréciées dans GitLab 18.9 et leur suppression est prévue dans GitLab 19.0](../deprecations.md#linux-package-support-for-suse-distributions). Envisagez de migrer vers un système d'exploitation pris en charge.

Pour plus d'informations, consultez [le ticket 9647](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/9647).

### Mattermost et Spamcheck supprimés des packages SLES 12.5 {#mattermost-and-spamcheck-removed-from-sles-125-packages}

- Affecte : Paquet Linux
- Versions affectées : 18.11.0 et ultérieur

En raison des [contraintes de taille des packages RPM](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/9716), Mattermost et Spamcheck ont été supprimés des packages Linux SLES 12.5.

Les distributions SUSE sont [dépréciées dans GitLab 18.9 et leur suppression est prévue dans GitLab 19.0](../deprecations.md#linux-package-support-for-suse-distributions), et [Mattermost](../deprecations.md#mattermost-bundled-with-linux-package) ainsi que [Spamcheck](../deprecations.md#spamcheck-support-in-the-linux-package-and-gitlab-helm-chart) sont tous deux prévus pour être supprimés de toutes les distributions dans GitLab 19.0.

Si vous utilisez Mattermost sur SLES 12.5, vous pouvez [migrer Mattermost vers un déploiement autonome](https://docs.mattermost.com/administration-guide/onboard/migrate-gitlab-omnibus.html). Si vous utilisez Spamcheck sur SLES 12.5, vous pouvez [le déployer avec Docker](../../administration/reporting/spamcheck.md).

### Les métriques cgroup de Gitaly ont été modifiées et certaines ont été supprimées {#gitaly-cgroup-metrics-changed-and-some-were-removed}

- Affecte : toutes les méthodes d'installation
- Versions affectées :

  | Release      | Correctifs affectés | Niveau de correctif résolu |
  | ------------ | ------------------------ | ------------------ |
  | 18.11 - 19.2 | Tous les correctifs       | 19.3.0             |

Dans GitLab 18.11, les métriques cgroup de Gitaly ont été déplacées vers un nouveau composant `LoadMonitor` (voir [Gitaly!8639](https://gitlab.com/gitlab-org/gitaly/-/merge_requests/8639)). En conséquence :

- Les métriques sont désormais rapportées uniquement pour le cgroup Gitaly parent, et non plus par cgroup de dépôt.
- Le paramètre `metrics_enabled` sous `[cgroups]` n'a plus aucun effet.
- Les métriques suivantes ont été supprimées : `gitaly_cgroup_cpu_usage_total`, `gitaly_cgroup_procs_total`, `gitaly_cgroup_cpu_cfs_periods_total`, `gitaly_cgroup_cpu_cfs_throttled_periods_total`, `gitaly_cgroup_cpu_cfs_throttled_seconds_total`, `gitaly_cgroup_memory_reclaim_attempts_total`, `gitaly_cgroup_memory_events_oom_total`, `gitaly_cgroup_memory_pgfault_total` et `gitaly_cgroup_memory_pgmajfault_total`.

De plus, en raison du [ticket Gitaly 7280](https://gitlab.com/gitlab-org/gitaly/-/work_items/7280), aucune métrique cgroup Gitaly, quel que soit son type, n'a été exportée dans GitLab 18.11 à 19.2. Ce problème a été corrigé dans GitLab 19.3.

Si vous dépendez des métriques supprimées, utilisez un exportateur compatible cgroup tel que [cAdvisor](https://github.com/google/cadvisor). Pour la liste actuelle des métriques et une correspondance entre les métriques supprimées et leurs équivalents cAdvisor, consultez [Surveiller les cgroups Gitaly](../../administration/gitaly/monitoring.md#monitor-gitaly-cgroups).

### Les jobs limités du site secondaire Geo ne se vident pas {#geo-secondary-throttled-jobs-not-draining}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif résolu |
  | ------- | ----------------------- | ----------------- |
  | 18.10   | 18.10.0 - 18.10.3       | 18.10.4           |
  | 18.9    | 18.9.0 - 18.9.5         | 18.9.6            |

Les sites secondaires Geo ont désactivé `ConcurrencyLimit::ResumeWorker`, ce qui a entraîné l'accumulation dans Redis des jobs limités `Geo::EventWorker` et `Geo::SyncWorker` sans vidage. Cela pouvait bloquer la réplication Geo et augmenter l'utilisation de la mémoire Redis.

Pour plus d'informations, consultez [le ticket 595824](https://gitlab.com/gitlab-org/gitlab/-/work_items/595824).

### URL du site Geo bloquée lors de l'utilisation du filtrage sortant {#geo-site-url-blocked-when-using-outbound-filtering}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif résolu |
  | ------- | ----------------------- | ----------------- |
  | 18.10   | 18.10.0 - 18.10.3       | 18.10.4           |
  | 18.9    | 18.9.0 - 18.9.5         | 18.9.6            |

Lorsque le filtrage des requêtes sortantes est activé, les URL des sites Geo sont incorrectement bloquées. Cela entraîne des erreurs de validation lors de l'enregistrement des sites Geo avec des messages tels que `Url is blocked: Requests to hosts and IP addresses not on the Allow List are denied`.

Le problème survient car les URL des sites Geo ne sont pas automatiquement ajoutées à la liste d'autorisation des requêtes locales sortantes lorsque le filtrage sortant est configuré.

Pour plus d'informations, consultez [le ticket 544821](https://gitlab.com/gitlab-org/gitlab/-/issues/544821).

### Paramètre de délai d'expiration du téléchargement des blobs Geo {#geo-blob-download-timeout-setting}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées : 18.10.0

Le délai d'expiration codé en dur de 8 heures (28 800 secondes) pour le téléchargement des blobs Geo provoque des échecs de synchronisation pour les objets LFS très volumineux (5 Go et plus) qui nécessitent des temps de transfert plus longs, les laissant bloqués à l'état « démarré ». Un nouveau paramètre `blob_download_timeout` contrôle le délai d'expiration par site (en secondes) pour la réplication des blobs (objets LFS, téléversements, artefacts de job, etc.). Configurable via l'[API Geo Sites](../../api/geo_sites.md).

- Par défaut : `28800` (8 heures).
- Maximum : `86400` (24 heures).

### Échecs de téléchargement des blobs Geo {#geo-blob-download-failures}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif résolu |
  | ------- | ----------------------- | ----------------- |
  | 18.10   |  18.10.0 - 18.10.4      | 18.10.5           |

Tous les types de blobs Geo (téléversements, objets LFS, artefacts de job et autres) peuvent échouer de façon persistante à se synchroniser sur les sites secondaires. Contrairement aux erreurs réseau transitoires, ces échecs affectent tous les enregistrements de blobs et ne se rétablissent pas lors d'une nouvelle tentative. Les sites secondaires affectés affichent des blobs à l'état « failed », et les logs Sidekiq peuvent contenir des segfaults, des erreurs `HPE_USER Span callback error in on_header_field`, ou des codes de statut HTTP inattendus (par exemple, `status_code: 32` ou `status_code: 34`).

La cause principale est une collision de symboles entre `rugged` 1.9.0 (mis à niveau dans GitLab 18.10) et le gem `llhttp-ffi`. Les symboles `llhttp` liés statiquement dans `rugged.so` remplacent les callbacks `llhttp-ffi`, corrompant l'analyse des réponses HTTP. Pour plus d'informations, consultez [le ticket 598564](https://gitlab.com/gitlab-org/gitlab/-/issues/598564).

Dans GitLab 18.10.5, `rugged` est rétrogradé à la version 1.7.2, qui ne contient pas les symboles conflictuels. Aucune action n'est requise après la mise à niveau.

#### Contournement avec un feature flag pour GitLab 18.10.4 {#feature-flag-workaround-for-gitlab-18104}

Si vous utilisez GitLab 18.10.4 et ne pouvez pas mettre à niveau vers GitLab 18.10.5, activez le feature flag `geo_blob_download_with_gitlab_http`. Ce flag bascule les téléchargements de blobs pour utiliser `Gitlab::HTTP` (`Net::HTTP`) au lieu du gem `http` dépendant de FFI :

1. Activez le feature flag :

   ```shell
   sudo gitlab-rails console
   Feature.enable(:geo_blob_download_with_gitlab_http)
   exit
   ```

1. Redémarrez Sidekiq :

   ```shell
   sudo gitlab-ctl restart sidekiq
   ```

> [!note]
> Le contournement par feature flag présente des limitations connues :
>
> - Les transferts de blobs volumineux dépassant 60 secondes peuvent expirer ([ticket 598020](https://gitlab.com/gitlab-org/gitlab/-/issues/598020)).
> - La réplication du registre de conteneurs n'est pas couverte par ce flag.
> - Les environnements avec filtrage des requêtes sortantes (`deny_all_requests_except_allowed`) peuvent nécessiter une configuration supplémentaire ([ticket 598514](https://gitlab.com/gitlab-org/gitlab/-/issues/598514)).

Pour plus d'informations, consultez [le ticket 595139](https://gitlab.com/gitlab-org/gitlab/-/issues/595139).

### La mise à niveau vers la version 18.9 échoue avec une CheckViolation PostgreSQL {#upgrade-to-189-fails-with-postgresql-checkviolation}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.9.0, 18.9.1

Lors de la mise à niveau d'une instance GitLab Self-Managed vers GitLab 18.9.0 ou 18.9.1, la mise à niveau échoue pendant les migrations de base de données avec :

```plaintext
PG::CheckViolation: ERROR: check constraint "check_xxxxxxxx" of relation "tablename" is violated by some row
```

Ce problème a été causé par un bug corrigé dans GitLab 18.10 (voir [la merge request 224446](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224446)). Le correctif a également été rétroporté et devrait être inclus dans la prochaine version de correctif GitLab 18.9 (voir [la merge request 225026](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/225026)).

Cependant, le bug peut entraîner l'omission silencieuse des migrations en arrière-plan par lots en raison du bug d'enregistrement unique. Lors de la mise à niveau vers la v18.8, les migrations en arrière-plan par lots ciblant des tables avec un seul enregistrement ont été incorrectement marquées comme `finished` sans jamais être exécutées. Cela a laissé des données sans remplissage, provoquant des échecs de mise à niveau sur les instances GitLab Self-Managed.

Un correctif proposé (voir [la merge request 225461](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/225461)) réinitialise les migrations en arrière-plan par lots affectées de `finished`/`finalized` vers `paused` afin que le planificateur les réexécute. Il se limite aux migrations dont `queued_migration_version` est compris entre 18.5 et 18.8 où `min_value = max_value` ou `min_cursor = max_cursor`.

Vous avez deux options :

- Appliquez le contournement maintenant pour finaliser votre mise à niveau immédiatement.
- Attendez le correctif complet et effectuez la mise à niveau après qu'une release le contienne.

Les articles de la base de connaissances suivants décrivent des contournements pour cinq symptômes connus :

- [`PG::CheckViolation: ERROR: check constraint "check_96233d37c0" of relation "pool_repositories" is violated by some row`](https://support.gitlab.com/hc/en-us/articles/25929006135068-PG-CheckViolation-ERROR-check-constraint-check-96233d37c0-of-relation-pool-repositories-is-violated-by-some-row)
- [`PG::CheckViolation: ERROR: check constraint "check_f6590fe2c1" of relation "gpg_key_subkeys" is violated by some row`](https://support.gitlab.com/hc/en-us/articles/25756021007004-Upgrade-to-18-9-0-fails-with-PG-CheckViolation-on-gpg-key-subkeys)
- [`PG::CheckViolation: ERROR: check constraint "check_17a3a18e31" of relation "user_agent_details" is violated by some row`](https://support.gitlab.com/hc/en-us/articles/25994671144348-Upgrade-to-18-9-0-fails-with-PG-CheckViolation-on-user-agent-details)
- [`PG::CheckViolation: ERROR: check constraint "check_ddd6f289f4" of relation "commit_user_mentions" is violated by some row`](https://support.gitlab.com/hc/en-us/articles/25992549646364-Upgrade-to-18-9-0-fails-with-PG-CheckViolation-on-commit-user-mentions)
- [`PG::CheckViolation: ERROR: check constraint "check_e69372e45f" of relation "suggestions" is violated by some row`](https://support.gitlab.com/hc/en-us/articles/25771198648732-Upgrade-to-18-9-0-fails-with-PG-CheckViolation-on-suggestions)

### Clés de déploiement et jetons d'accès personnels pour les utilisateurs bloqués invalidés {#deploy-keys-and-personal-access-tokens-for-blocked-users-invalidated}

- Affecte : toutes les méthodes d'installation
- Versions affectées :

  | Release | Niveaux de correctifs affectés | Niveau de correctif résolu        |
  |---------|-----------------------|--------------------------|
  | 18.8    | 18.8.2 et ultérieur      | S/O (modification intentionnelle) |
  | 18.7    | 18.7.2 et ultérieur      | S/O (modification intentionnelle) |
  | 18.6    | 18.6.4 et ultérieur      | S/O (modification intentionnelle) |

GitLab 18.8.2, 18.7.2 et 18.6.4 rejettent désormais les requêtes API utilisant des clés de déploiement associées à des utilisateurs bloqués. Si vous disposez de clés de déploiement associées à des utilisateurs bloqués, celles-ci ne fonctionnent plus après la mise à niveau vers les versions susmentionnées. Il s'agit d'un correctif de sécurité visant à empêcher les utilisateurs bloqués d'accéder aux ressources GitLab via leurs clés et tokens.

Vous devez :

1. Identifier toutes les clés de déploiement ou jetons d'accès personnels appartenant à des utilisateurs bloqués.
1. Les réattribuer à des utilisateurs facturables, ou les supprimer et créer de nouvelles clés/tokens avec des utilisateurs facturables ou des comptes de service.

La requête suivante peut être utilisée pour identifier toutes les clés de déploiement associées à des comptes bloqués et utilisées au moins une fois au cours des 365 derniers jours :

```sql
SELECT
  k.id,
  k.user_id,
  u.username,
  u.state as user_state,
  k.title,
  k.fingerprint,
  k.fingerprint_sha256,
  k.usage_type,
  k.last_used_at,
  k.created_at,
  k.updated_at
FROM keys k
INNER JOIN users u ON k.user_id = u.id
WHERE u.state IN ('blocked', 'ldap_blocked', 'blocked_pending_approval', 'banned')
  AND k.type = 'DeployKey'
  AND k.last_used_at >= NOW() - INTERVAL '365 days'
ORDER BY u.state, u.username, k.last_used_at DESC;
```

### Erreur de création du dictionnaire ClickHouse {#clickhouse-dictionary-creation-error}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.8.0

Les clients GitLab Self-Managed avec l'[intégration ClickHouse](../../integration/clickhouse.md) activée peuvent rencontrer une erreur de migration de base de données ClickHouse pendant le processus de mise à niveau en raison d'une permission manquante (`DB::Exception: gitlab: Not enough privileges`). Pour résoudre cette erreur, consultez la [documentation de dépannage pour la prise en charge de la lecture du dictionnaire de base de données](../../integration/clickhouse.md#database-dictionary-read-support).

### Migration en arrière-plan par lots pour les données CI réintroduite {#batched-background-migration-for-ci-data-reintroduced}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.8.0

Les [migrations en arrière-plan par lots](../background_migrations.md) introduites dans la [migration des métadonnées des builds CI](#ci-builds-metadata-migration) ont dû être réintroduites pour gérer un cas limite dans la structure des données et garantir leur achèvement.

### Le modèle de webhook personnalisé avec des espaces réservés non mis entre guillemets ne peut pas être enregistré {#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved}

- Affecte : toutes les méthodes d'installation
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif résolu |
  | ------- | ----------------------- | ----------------- |
  | 18.10   | Tous les correctifs      | Non corrigé         |
  | 18.9    | Tous les correctifs      | Non corrigé         |
  | 18.8    | Tous les correctifs      | Non corrigé         |

Dans GitLab 18.8 à 18.10, les [modèles de webhook personnalisés](../../user/project/integrations/webhooks.md#custom-webhook-template) avec des champs de charge utile non mis entre guillemets ne peuvent pas être enregistrés. Ce problème a été résolu dans GitLab 18.11.

À titre de contournement, encadrez les champs avec des guillemets. Par exemple, `{"value": {{id}}}` deviendrait `{"value": "{{id}}"}`.

Les champs mis entre guillemets produisent des valeurs de type chaîne au lieu de valeurs numériques. Si cela est incompatible avec votre webhook, mettez à niveau vers GitLab 18.11 ou une version ultérieure.

Pour plus d'informations, consultez la [documentation de dépannage des webhooks](../../user/project/integrations/webhooks_troubleshooting.md#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved).

### Migration des métadonnées des builds CI {#ci-builds-metadata-migration}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.7.0

Une [migration post-déploiement](../../development/database/post_deployment_migrations.md) planifie des [migrations en arrière-plan](../background_migrations.md) par lots pour copier les métadonnées des builds CI vers de nouvelles tables optimisées (`p_ci_job_definitions`). Cette migration fait partie d'une initiative visant à réduire à terme la taille de la base de données CI (voir l'[epic 13886](https://gitlab.com/groups/gitlab-org/-/work_items/13886)). Si vous disposez d'une instance avec des millions de jobs et souhaitez accélérer la migration, vous pouvez [sélectionner les données à migrer](#ci-builds-metadata-migration-details).

### Paramètre des origines autorisées ActionCable Geo {#geo-actioncable-allowed-origins-setting}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées : 18.7.0

Ajout d'un nouveau paramètre `action_cable_allowed_origins` pour configurer les origines autorisées pour les requêtes WebSocket ActionCable. Spécifiez les URL autorisées lors de la configuration du site principal pour garantir une connectivité WebSocket inter-sites appropriée :

- [Documentation Geo pour le package Linux](../../administration/geo/replication/configuration.md#add-primary-and-secondary-urls-as-allowed-actioncable-origins)
- [Documentation Geo pour le chart Helm](https://docs.gitlab.com/charts/advanced/geo/#configure-primary-database)

### Correction des requêtes lentes de Geo VerificationStateBackfillWorker {#geo-verificationstatebackfillworker-slow-queries-fix}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées : 18.6.5

Correction du [ticket Geo 587407](https://gitlab.com/gitlab-org/gitlab/-/work_items/587407) où `Geo::VerificationStateBackfillWorker` générait de grandes requêtes lentes pour la table `merge_request_diff_details`.

### Limites de taille et de débit de l'API Commits et Files {#commits-and-files-api-size-and-rate-limits}

- Affecte : toutes les méthodes d'installation
- Versions affectées :

  | Release | Niveaux de correctifs affectés | Niveau de correctif résolu        |
  |---------|-----------------------|--------------------------|
  | 18.6    | 18.6.2 et ultérieur      | S/O (modification intentionnelle) |
  | 18.5    | 18.5.4 et ultérieur      | S/O (modification intentionnelle) |
  | 18.4    | 18.4.6 et ultérieur      | S/O (modification intentionnelle) |

GitLab 18.6.2, 18.5.4 et 18.4.6 ont introduit des limites de taille et de débit sur les requêtes effectuées aux endpoints suivants :

- `POST /projects/:id/repository/commits` : [créer un commit](../../api/commits.md#create-a-commit)
- `POST /projects/:id/repository/files/:file_path` : [créer un fichier dans un dépôt](../../api/repository_files.md#create-a-file-in-a-repository)
- `PUT /projects/:id/repository/files/:file_path` : [mettre à jour un fichier dans un dépôt](../../api/repository_files.md#update-a-file-in-a-repository)

GitLab répond aux requêtes dépassant la limite de taille avec un statut `413 Entity Too large`, et aux requêtes dépassant la limite de débit avec un statut `429 Too Many Requests`. Pour plus d'informations, consultez [les limites de l'API Commits et Files](../../administration/instance_limits.md#commits-and-files-api-limits)

### Restrictions des runners de la plateforme Duo Agent {#duo-agent-platform-runner-restrictions}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.6.2

Des [restrictions de runners](../../user/duo_agent_platform/flows/execution/_index.md#configure-runners-to-execute-flows) ont été introduites concernant les runners pouvant être utilisés avec la plateforme Duo Agent.

### Correction de la migration du curseur de log Geo {#geo-log-cursor-migration-fix}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif résolu |
  |---------|-------------------------|-------------------|
  | 18.5    | 18.5.0 - 18.5.1         | 18.5.2            |
  | 18.4    | 18.4.0 - 18.4.3         | 18.4.4            |

La [migration](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/210512) Geo manquante qui empêchait le démarrage du curseur de log Geo sur le site secondaire est corrigée.

### Finalisation du remplissage des designs de gestion de conception {#finalize-design-management-designs-backfill}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.5.0

Une [migration post-déploiement](../../development/database/post_deployment_migrations.md) `20250922202128_finalize_correct_design_management_designs_backfill` finalise une [migration en arrière-plan](../background_migrations.md) par lots planifiée dans la version 18.4. Si vous avez ignoré la version 18.4 dans le chemin de mise à niveau, la migration est entièrement exécutée lors de l'exécution des migrations post-déploiement. Le temps d'exécution est directement lié à la taille de votre table `design_management_designs`. Pour la plupart des instances, la migration ne devrait pas durer plus de 2 minutes, mais pour certaines instances plus grandes, elle pourrait prendre jusqu'à 10 minutes. Veuillez patienter et ne pas interrompre le processus de migration.

### Les modifications de routage NGINX provoquent des erreurs 404 {#nginx-routing-changes-cause-404-errors}

- Affecte : Paquet Linux
- Versions affectées : 18.5.0

Les modifications de routage NGINX introduites dans GitLab 18.5.0 peuvent rendre des services inaccessibles lors de l'utilisation de noms d'hôte non correspondants tels que `localhost` ou des noms de domaine alternatifs. Ce problème provoque :

- Les endpoints de vérification de l'état tels que `/-/health` retournent des erreurs `404` au lieu de réponses appropriées.
- L'interface web GitLab affiche des pages d'erreur `404` lorsqu'elle est accédée avec des noms d'hôte autres que le FQDN configuré.
- GitLab Pages reçoit potentiellement du trafic destiné à d'autres services.
- Problèmes avec toutes les requêtes utilisant des noms d'hôte alternatifs qui fonctionnaient auparavant.

Ce problème est résolu dans le package Linux par la [merge request 8805](https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/8805), et le correctif sera disponible dans GitLab 18.5.2 et 18.6.0.

Les opérations Git telles que le clone, le push et le pull ne sont pas affectées par ce problème.

### Erreur nil dans la migration en arrière-plan par lots {#batched-background-migration-nil-error}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.4.2, 18.4.3

Les mises à niveau vers `18.4.2` ou `18.4.3` peuvent échouer avec une erreur `no implicit conversion of nil into String` pour ces migrations en arrière-plan par lots :

- `FixIncompleteInstanceExternalAuditDestinations`
- `FinalizeAuditEventDestinationMigrations`

Pour résoudre ce problème, mettez à niveau vers la dernière version de correctif ou utilisez le [contournement décrit dans le ticket 578938](https://gitlab.com/gitlab-org/gitlab/-/issues/578938#workaround).

### TypeError de réplication Geo {#geo-replication-typeerror}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif résolu |
  |---------|-------------------------|-------------------|
  | 18.4    | 18.4.0 - 18.4.1         | 18.4.2            |

Sur les sites secondaires Geo, [un bug](https://gitlab.com/gitlab-org/gitlab/-/issues/571455) entraîne l'échec des événements de réplication avec le message d'erreur `no implicit conversion of String into Array (TypeError)`. Les redondances telles que la re-vérification garantissent la cohérence éventuelle, mais le RPO est considérablement augmenté.

### Limites d'entrée JSON pour la prévention des attaques par déni de service {#json-input-limits-for-denial-of-service-prevention}

- Affecte : toutes les méthodes d'installation
- Versions affectées :

  | Release | Niveaux de correctifs affectés | Niveau de correctif résolu        |
  |---------|-----------------------|--------------------------|
  | 18.4    | 18.4.1 et ultérieur      | S/O (modification intentionnelle) |
  | 18.3    | 18.3.3 et ultérieur      | S/O (modification intentionnelle) |
  | 18.2    | 18.2.7 et ultérieur      | S/O (modification intentionnelle) |

GitLab 18.4.1, 18.3.3 et 18.2.7 ont introduit des limites sur les entrées JSON pour prévenir les attaques par déni de service. GitLab répond aux requêtes HTTP dépassant ces limites avec un statut `400 Bad Request`. Pour plus d'informations, consultez [les limites des requêtes HTTP](../../administration/instance_limits.md#http-request-limits).

### LdapAddOnSeatSyncWorker supprime des sièges Duo {#ldapaddonseatsyncworker-removes-duo-seats}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.3.0

Un nouveau worker `LdapAddOnSeatSyncWorker` a été introduit, ce qui pouvait involontairement supprimer tous les utilisateurs des sièges GitLab Duo toutes les nuits lorsque LDAP est activé. Ce problème a été corrigé dans GitLab 18.4.0 et 18.3.2. Consultez le [ticket 565064](https://gitlab.com/gitlab-org/gitlab/-/issues/565064) pour plus de détails.

### Correction de la vérification Rake Geo {#geo-rake-check-fix}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées : 18.3.0

Le [ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/545533) qui causait un rapport d'échec incorrect de `rake gitlab:geo:check` lors de l'installation d'un site secondaire Geo a été corrigé dans la version 18.3.0.

### Correction du nom de fichier des Pages Geo {#geo-pages-filename-fix}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées :

  | Release | Niveaux de correctifs affectés  | Niveau de correctif résolu |
  |---------|------------------------|-------------------|
  | 18.3    | 18.3.0 - 18.3.2        | 18.3.3            |
  | 18.2    | 18.2.0 - 18.2.6        | 18.2.7            |
  | 18.1    | 18.1.0 et versions ultérieures       | Non corrigé dans la version 18.1 |

GitLab 18.3.3, 18.2.7 et versions ultérieures incluent un correctif pour [le ticket 559196](https://gitlab.com/gitlab-org/gitlab/-/issues/559196), où la vérification Geo pouvait échouer pour les déploiements Pages comportant des noms de fichiers longs. Le correctif empêche la troncature des noms de fichiers sur les sites secondaires Geo afin de maintenir la cohérence lors de la réplication et de la vérification.

### Erreurs push lors d'une mise à niveau sans interruption entre 18.1 et 18.2 {#zero-downtime-upgrade-push-errors-between-181-and-182}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.2.0

Les mises à niveau entre les versions 18.1.x et 18.2.x sont affectées par le [ticket connu 567543](https://gitlab.com/gitlab-org/gitlab/-/issues/567543), qui provoque des erreurs lors des opérations push vers des projets existants pendant une mise à niveau. Pour éviter toute interruption de service lors de la mise à niveau entre les versions 18.1.x et 18.2.x, effectuez une mise à niveau directement vers la version 18.2.6, qui inclut un correctif.

### Geo VerificationStateBackfillService `ci_job_artifact_states` {#geo-verificationstatebackfillservice-ci_job_artifact_states}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées :

  | Release | Niveaux de correctifs affectés | Niveau de correctif résolu |
  |---------|------------------------|-------------------|
  | 18.2    | 18.2.0 - 18.2.1        | 18.2.2            |
  | 18.1    | 18.1.0 - 18.1.3        | 18.1.4            |
  | 18.0    | 18.0.0 - 18.0.5        | 18.0.6            |

Les versions affectées présentent un problème connu qui survient lorsque `VerificationStateBackfillService` s'exécute en raison de modifications apportées à la clé primaire de `ci_job_artifact_states`. Pour résoudre ce problème, effectuez une mise à niveau vers une release contenant un correctif.

### Elasticsearch `strict_dynamic_mapping_exception` {#elasticsearch-strict_dynamic_mapping_exception}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.1.0

L'indexation Elasticsearch peut échouer avec des erreurs `strict_dynamic_mapping_exception` pour Elasticsearch version 7. Pour résoudre ce problème, consultez la section « Correctifs possibles » dans le [ticket 566413](https://gitlab.com/gitlab-org/gitlab/-/issues/566413).

### Erreur PostgreSQL `ci_job_artifacts` {#postgresql-ci_job_artifacts-error}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.1.0, 18.1.1

Les versions 18.1.0 et 18.1.1 de GitLab affichent des erreurs dans les journaux PostgreSQL, telles que `ERROR:  relation "ci_job_artifacts" does not exist at ...`. Ces erreurs dans les journaux peuvent être ignorées sans risque, mais elles pourraient déclencher des alertes de surveillance, y compris sur les sites Geo. Pour résoudre ce problème, mettez à jour vers GitLab 18.1.2 ou une version ultérieure.

### Bogue « Merge request presque prête » {#merge-request-almost-ready-bug}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.1.0

Les merge requests comportant des commits de certains utilisateurs peuvent ne pas progresser et afficher continuellement `Your merge request is almost ready`. Consultez le [ticket 554613](https://gitlab.com/gitlab-org/gitlab/-/issues/554613). De plus, [le journal `sidekiq/current`](../../administration/logs/_index.md#sidekiq-logs) affiche des erreurs `undefined method 'id' for nil:NilClass` pour `merge_request_diff_commit.rb`. Pour corriger ce problème :

1. Démarrez une [console de base de données](../../administration/troubleshooting/postgresql.md#start-a-database-console).
1. Exécutez la commande suivante :

   ```sql
   REINDEX TABLE CONCURRENTLY public.merge_request_diff_commit_users;
   ```

1. Fermez et rouvrez les merge requests affectées.

### Erreurs proxy HTTP 500 de Geo {#geo-http-500-proxy-errors}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif résolu |
  |---------|-------------------------|-------------------|
  | 18.1    | 18.1.0                  | 18.1.1            |
  | 18.0    | 18.0.0 - 18.0.2         | 18.0.3            |

Les versions de GitLab indiquées dans le tableau ci-dessus présentent un problème connu où les opérations Git proxysées depuis un site Geo secondaire échouent avec des erreurs HTTP 500. Pour résoudre ce problème, effectuez une mise à niveau vers une release contenant un correctif.

### PostgreSQL 14 non pris en charge {#postgresql-14-not-supported}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.0.0

[PostgreSQL 14 n'est plus pris en charge à partir de GitLab 18](../deprecations.md#postgresql-14-and-15-no-longer-supported). Mettez à niveau PostgreSQL vers au moins la version 16.5 avant de procéder à la mise à niveau vers GitLab 18.0 ou une version ultérieure. Pour plus d'informations, consultez les [prérequis d'installation](../../install/requirements.md#postgresql).

> [!warning]
> Les mises à niveau automatiques de version de base de données s'appliquent uniquement aux instances à nœud unique utilisant le package Linux. Dans tous les autres cas, comme les instances Geo, PostgreSQL avec haute disponibilité via le package Linux, ou l'utilisation d'une base de données PostgreSQL externe (comme Amazon RDS), vous devez mettre à niveau PostgreSQL manuellement. Consultez [la mise à niveau d'une instance Geo](https://docs.gitlab.com/omnibus/settings/database/#upgrading-a-geo-instance) pour des étapes détaillées.

### Compatibilité binaire de `pg_dump` {#pg_dump-binary-compatibility}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.0.0

GitLab intègre le binaire `pg_dump`. Lorsque vous utilisez un serveur PostgreSQL externe, assurez-vous que la version client de `pg_dump` est compatible avec le serveur PostgreSQL, aussi bien pour la création que pour la restauration des sauvegardes de la base de données GitLab.

### Dépréciation des images PostgreSQL et Redis de Bitnami {#bitnami-postgresql-and-redis-image-deprecation}

- Affecte : Graphique Helm
- Versions affectées : 17.11.0 et versions antérieures

À partir du 29 septembre 2025, Bitnami cessera de fournir des images PostgreSQL et Redis avec des tags. Si vous déployez GitLab 17.11 ou une version antérieure à l'aide du chart GitLab avec Redis ou Postgres intégré, vous devez mettre à jour manuellement vos valeurs pour utiliser le dépôt hérité afin d'éviter une interruption de service inattendue. Pour plus d'informations, consultez le [ticket 6089](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/6089).

### Échecs de pipeline lors des mises à niveau sans interruption depuis la version 17.11 {#pipeline-failures-during-zero-downtime-upgrades-from-1711}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.0.0

Le feature flag `ci_only_one_persistent_ref_creation` provoque des échecs de pipeline lors des mises à niveau sans interruption de service lorsque Rails est mis à niveau mais que Sidekiq reste sur la version 17.11 (voir les détails dans le [ticket 558808](https://gitlab.com/gitlab-org/gitlab/-/issues/558808)).

**Prévention :** Ouvrez la console Rails et activez le feature flag avant la mise à niveau :

```shell
$ sudo gitlab-rails console
Feature.enable(:ci_only_one_persistent_ref_creation)
```

**Si déjà affecté :** Exécutez cette commande et relancez les pipelines en échec :

```shell
$ sudo gitlab-rails console
Rails.cache.delete_matched("pipeline:*:create_persistent_ref_service")
```

### Migrer la configuration Gitaly de `git_data_dirs` vers le stockage {#migrate-gitaly-configuration-from-git_data_dirs-to-storage}

- Affecte : Paquet Linux
- Versions affectées : 18.0.0

Dans GitLab 18.0 et les versions ultérieures, vous ne pouvez plus utiliser le paramètre `git_data_dirs` pour configurer les emplacements de stockage Gitaly.

Si vous utilisez encore `git_data_dirs`, vous devez [migrer votre configuration Gitaly](https://docs.gitlab.com/omnibus/settings/configuration/#migrating-from-git_data_dirs) avant de procéder à la mise à niveau vers GitLab 18.0.

### Erreurs de migration lors du retour de Geo CE vers EE {#geo-ce-to-ee-revert-migration-errors}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

- Affecte : Geo
- Versions affectées : 18.0.0

Si vous avez déployé GitLab Enterprise Edition puis êtes revenu à GitLab Community Edition, votre schéma de base de données peut s'écarter du schéma attendu par l'application GitLab, ce qui entraîne des erreurs de migration. Quatre erreurs particulières peuvent survenir lors de la mise à niveau vers la version 18.0.0, car une migration ajoutée dans cette version modifie les valeurs par défaut de ces colonnes.

Les erreurs sont les suivantes :

- `No such column: geo_nodes.verification_max_capacity`
- `No such column: geo_nodes.minimum_reverification_interval`
- `No such column: geo_nodes.repos_max_capacity`
- `No such column: geo_nodes.container_repositories_max_capacity`

Cette migration a été corrigée dans GitLab 18.0.2 pour ajouter ces colonnes si elles sont manquantes. Consultez le [ticket #543146](https://gitlab.com/gitlab-org/gitlab/-/issues/543146).

**Releases affectées** :

| Releases mineures affectées | Correctifs affectés | Corrigé dans |
| ----------------------- | ----------------------- | -------- |
| 18.0                    |  18.0.0 - 18.0.1        | 18.0.2   |

### Erreur « PRNG is not seeded » sur les installations Docker {#prng-is-not-seeded-error-on-docker-installations}

- Affecte : Docker
- Versions affectées : 18.0.0

Si vous exécutez GitLab sur une installation Docker avec un hôte FIPS activé, il est possible que la génération de clé SSH ou le serveur OpenSSH (`sshd`) ne parvienne pas à démarrer avec le message d'erreur :

```plaintext
PRNG is not seeded
```

GitLab 18.0 [a mis à jour l'image de base d'Ubuntu 22.04 vers 24.04](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8928). Cette erreur survient car Ubuntu 24.04 ne [permet plus à un hôte FIPS d'utiliser un fournisseur OpenSSL non conforme FIPS](https://github.com/dotnet/dotnet-docker/issues/5849#issuecomment-2324943811).

Pour résoudre ce problème, plusieurs options s'offrent à vous :

- Désactiver FIPS sur le système hôte.
- Désactiver la détection automatique d'un noyau FIPS dans le conteneur Docker GitLab. Pour ce faire, définissez la variable d'environnement `OPENSSL_FORCE_FIPS_MODE=0` avec GitLab 18.0.2 ou une version ultérieure.
- Au lieu d'utiliser l'image Docker GitLab, installez un [package FIPS natif](https://packages.gitlab.com/ui/browse/gitlab/gitlab-fips) sur l'hôte.

La dernière option est celle recommandée pour satisfaire aux exigences FIPS. Pour les installations héritées, les deux premières options peuvent être utilisées comme solution provisoire.

### Détails de la migration des métadonnées des builds CI {#ci-builds-metadata-migration-details}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.7.0

> [!note]
> Depuis GitLab 18.6, les nouveaux pipelines écrivent les données exclusivement dans le nouveau format (voir le [ticket 552065](https://gitlab.com/gitlab-org/gitlab/-/issues/552065)). Cette migration copie uniquement les données existantes de l'ancien format vers le nouveau. Aucune donnée n'est supprimée.

Les données non migrées seront supprimées dans une future release (voir l'[epic 18271](https://gitlab.com/groups/gitlab-org/-/work_items/18271)).

La durée de la migration est directement proportionnelle au nombre total de jobs CI dans votre instance. Les jobs sont traités des partitions les plus récentes aux plus anciennes afin de prioriser les données récentes.

Vous pouvez réduire le nombre de jobs à migrer en activant le [nettoyage automatique des pipelines](../../ci/pipelines/settings.md#automatic-pipeline-cleanup) sur les projets les plus volumineux, afin de supprimer les anciens pipelines avant la mise à niveau.

La migration copie deux types de données :

- **Données de traitement des jobs** : la configuration d'exécution des jobs provenant de `.gitlab-ci.yml` (comme `script`, `variables`) est nécessaire uniquement pour les runners lors de l'exécution des jobs, et non pour l'interface utilisateur ou l'API.
- **Données des jobs visibles par les utilisateurs** : parmi toutes les données des jobs, cette migration n'impacte que la valeur de délai d'expiration du job, les valeurs de code de sortie du job, les [artefacts exposés](../../ci/jobs/job_artifacts.md#link-to-job-artifacts-in-the-merge-request-ui) et les [associations d'environnement](../../ci/yaml/_index.md#environment).

Pour les instances GitLab Self-Managed et GitLab Dedicated disposant de grands ensembles de données CI, vous pouvez accélérer la migration en réduisant la portée des données à migrer. Pour contrôler la portée, utilisez les paramètres définis ci-dessous.

#### Contrôle de la portée pour les données de traitement des jobs {#controlling-the-scope-for-jobs-processing-data}

Par défaut, la migration copie les données de traitement de tous les jobs existants. Vous pouvez réduire la portée en utilisant l'un des paramètres décrits ci-dessous.

La valeur du paramètre contrôle la quantité de données de traitement des jobs que vous souhaitez conserver. Par exemple, définissez-le sur `6mo` si vous prévoyez uniquement que des jobs créés au cours des 6 derniers mois seront exécutés (via des [nouvelles tentatives](../../ci/jobs/_index.md#retry-jobs), l'[exécution de jobs manuels](../../ci/jobs/job_control.md#create-a-job-that-must-be-run-manually), l'[arrêt automatique d'environnement](../../ci/environments/_index.md#stopping-an-environment)).

GitLab recherche le paramètre dans l'ordre de priorité suivant :

1. Paramètre d'[archivage des pipelines](../../administration/settings/continuous_integration.md#archive-pipelines) (bonne pratique recommandée). Les pipelines archivés indiquent que les jobs ne peuvent pas être relancés ou réexécutés manuellement. Si ce paramètre est activé, les données de traitement des jobs archivés n'ont pas besoin d'être migrées.

   > [!note]
   > Si la plage d'archivage des pipelines est ultérieurement étendue, les jobs sans données de traitement resteront inexécutables.
1. `GITLAB_DB_CI_JOBS_PROCESSING_DATA_CUTOFF` [variable d'environnement](../../administration/environment_variables.md), si l'archivage des pipelines n'est pas configuré ou doit être remplacé pour cette migration. Elle accepte des chaînes de durée telles que `1y` (1 an), `6mo` (6 mois), `90d` (90 jours).
1. Variable d'environnement `GITLAB_DB_CI_JOBS_MIGRATION_CUTOFF`, si aucun des éléments ci-dessus n'est défini. Elle accepte des chaînes de durée telles que `1y` (1 an), `6mo` (6 mois), `90d` (90 jours). Consultez [Contrôle de la portée pour les données des jobs visibles par les utilisateurs](#controlling-the-scope-for-job-data-visible-to-users).
1. Toutes les données sont copiées si aucune configuration n'est trouvée.

#### Contrôle de la portée pour les données des jobs visibles par les utilisateurs {#controlling-the-scope-for-job-data-visible-to-users}

La variable d'environnement `GITLAB_DB_CI_JOBS_MIGRATION_CUTOFF` contrôle les jobs dont les données visibles seront migrées.

Par exemple, `GITLAB_DB_CI_JOBS_MIGRATION_CUTOFF=1y` copie les données visibles affectées (valeur de délai d'expiration, environnement, codes de sortie et métadonnées des artefacts exposés) pour les jobs de l'année la plus récente.

Par défaut, il n'y a pas de date limite et les données de tous les jobs sont migrées.

#### Estimation de l'impact de la migration {#estimating-migration-impact}

À titre de référence, pour GitLab.com, nous prévoyons de migrer 400 millions de lignes en environ 2 mois.

Pour estimer l'impact de la migration sur votre instance, vous pouvez exécuter les requêtes suivantes dans la [console PostgreSQL](../../administration/troubleshooting/postgresql.md#start-a-database-console) :

{{< tabs >}}

{{< tab title="Taille de la table" >}}

```sql
SELECT n.nspname AS schema_name, c.relname AS partition_name,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size
FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_class p ON p.oid = i.inhparent
WHERE p.relname = 'p_ci_builds_metadata'
ORDER BY pg_total_relation_size(c.oid) DESC;
```

Les nouvelles tables nécessitent environ 20 % de cet espace.

{{< /tab >}}

{{< tab title="Estimation du nombre de jobs" >}}

Il s'agit d'une estimation issue de la table de statistiques PostgreSQL.

```sql
SELECT SUM(c.reltuples)::bigint AS estimated_jobs_count
FROM pg_class c
JOIN pg_inherits i ON c.oid = i.inhrelid
WHERE i.inhparent = 'p_ci_builds'::regclass;
```

{{< /tab >}}

{{< tab title="Jobs par période" >}}

Pour connaître le nombre de jobs créés dans une période donnée, nous devons interroger les tables :

```sql
SELECT COUNT(*) FROM p_ci_builds WHERE created_at >= now() - '1 year'::interval;
```

Si la requête expire, utilisez la [console Rails](../../administration/operations/rails_console.md) pour traiter les données par lots :

```ruby
counts = []
CommitStatus.each_batch(of: 25000) do |batch|
  counts << batch.where(created_at: 1.year.ago...).count
end
counts.sum
```

{{< /tab >}}

{{< /tabs >}}

### Migration en arrière-plan par lots pour les données de fusion des merge requests {#batched-background-migration-for-merge-request-merge-data}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.8.0

Une [migration en arrière-plan par lots](../background_migrations.md) copie les données liées à la fusion des merge requests depuis la table `merge_requests` vers une nouvelle table dédiée `merge_requests_merge_data`.

Cette migration fait partie d'une initiative d'optimisation du schéma de base de données visant à normaliser les attributs spécifiques à la fusion dans une table séparée, améliorant ainsi les performances des requêtes et la maintenabilité.

#### Données migrées {#what-data-is-migrated}

La migration copie les colonnes suivantes de `merge_requests` vers `merge_requests_merge_data` :

- `merge_commit_sha`
- `merged_commit_sha`
- `merge_ref_sha`
- `squash_commit_sha`
- `in_progress_merge_commit_sha`
- `merge_status`
- `auto_merge_enabled`
- `squash`
- `merge_user_id`
- `merge_params`
- `merge_error`
- `merge_jid`

La migration traite la table `merge_requests`, en copiant les données uniquement pour les merge requests qui ne disposent pas encore d'entrées correspondantes dans `merge_requests_merge_data`.

Depuis GitLab 18.7, les nouvelles merge requests écrivent les données dans les deux tables via des mécanismes de double écriture au niveau de l'application (voir le [ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/560933)). Cette migration copie uniquement les données existantes qui n'ont pas été créées ou modifiées après la mise en place de la double écriture.

Aucune donnée n'est supprimée de la table `merge_requests` pendant cette migration.

La migration devrait être finalisée dans GitLab 18.9. Pour plus d'informations, consultez le [ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/584459).

#### Estimation de la durée de migration {#estimating-migration-duration}

La durée de la migration est directement proportionnelle au nombre de merge requests dans votre instance.

Pour estimer l'impact :

**Requête PostgreSQL :**

```sql
-- Count total merge requests
SELECT COUNT(*) FROM merge_requests;

-- Estimate table size
SELECT pg_size_pretty(pg_total_relation_size('merge_requests')) AS table_size;
```

**Console Rails :**

```ruby
# Count total merge requests
MergeRequest.count

# Count remaining merge requests to migrate
MergeRequest.left_joins(:merge_data)
  .where(merge_requests_merge_data: { merge_request_id: nil })
  .count
```

La migration traite les merge requests par lots et devrait se terminer en quelques heures à quelques jours pour la plupart des instances.

### Mise à niveau vers PostgreSQL version 17.7 sur GitLab 18.11 {#postgresql-version-177-upgrade-on-gitlab-1811}

- Affecte : package Linux, Docker, Geo
- Versions affectées : 18.11.0

La mise à niveau vers GitLab 18.11 déclenche une mise à niveau automatique vers [PostgreSQL 17.7](../../administration/package_information/postgresql_versions.md) pour les installations sur package Linux à nœud unique.

> [!warning]
> Les mises à niveau automatiques de version de base de données s'appliquent uniquement aux instances à nœud unique utilisant le package Linux. Pour les déploiements Geo, les mises à niveau PostgreSQL doivent être [planifiées et programmées délibérément](../../administration/geo/replication/upgrading_the_geo_sites.md), car une mise à niveau de version majeure nécessite la réinitialisation de la réplication PostgreSQL vers les sites secondaires Geo. Cela peut entraîner une interruption de service plus longue que prévu.

### Le limiteur de concurrence Sidekiq entraîne des files d'attente de jobs sur les déploiements Helm chart et Operator {#sidekiq-concurrency-limiter-causes-job-backlogs-on-helm-chart-and-operator-deployments}

- Affecte : Helm chart, Operator
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif résolu |
  | ------- | ----------------------- | ----------------- |
  | 18.10   | 18.10.0 - 18.10.3      | 18.10.4           |
  | 18.9    | 18.9.0 - 18.9.5        | 18.9.6            |

Dans GitLab 18.9, le chart Helm de GitLab a commencé à définir `GITLAB_SIDEKIQ_MAX_REPLICAS` par défaut ([merge request 4348 de charts/GitLab](https://gitlab.com/gitlab-org/charts/gitlab/-/merge_requests/4348)). Sur les environnements GitLab Self-Managed et GitLab Dedicated qui n'utilisent pas la mise à l'échelle automatique basée sur KEDA, cela entraîne l'activation inattendue du limiteur de concurrence Sidekiq et le report des jobs dans des files d'attente limitées sauvegardées par Redis.

Cela peut entraîner :

- Des files d'attente de jobs Sidekiq.
- Une augmentation de la mémoire Redis.
- Un retard dans l'exécution des jobs.
- Un impact sur des workers tels que `WebHookWorker`, `AuditEvents::AuditEventStreamingWorker` et les workers de réplication Geo (`Geo::EventWorker`, `Geo::SyncWorker`).

Si vous êtes affecté, vous pouvez utiliser l'une des mesures d'atténuation temporaires suivantes jusqu'à la mise à niveau vers une version corrigée :

- Désactiver le limiteur de concurrence pour un worker spécifique en activant un feature flag. Ouvrez une console Rails en exécutant `exec` sur un pod Sidekiq :

  ```shell
  kubectl exec -it <sidekiq-pod-name> -- gitlab-rails console
  ```

  Activez ensuite le flag pour le worker affecté :

  ```ruby
  Feature.enable(:"disable_sidekiq_concurrency_limit_middleware_<WorkerClass>")
  ```

  Remplacez `<WorkerClass>` par le nom du worker affecté (par exemple, `WebHookWorker`).

- Désactivez toutes les limites de concurrence par défaut en définissant `GITLAB_SIDEKIQ_MAX_REPLICAS=0` dans la configuration d'environnement de votre pod Sidekiq. Cela désactive entièrement le calcul de la limite de concurrence par défaut.

> [!warning]
> Si vous utilisez Geo, les jobs déjà limités sur les sites secondaires peuvent ne pas se vider automatiquement, car `ConcurrencyLimit::ResumeWorker` ne s'exécute pas sur les sites secondaires Geo. Vous devrez peut-être intervenir manuellement pour vider les files d'attente limitées.

Un correctif conditionnant le calcul de la limite de concurrence par défaut à un feature flag a été fusionné dans la [merge request 230713](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/230713) et rétroporté vers 18.10.4 ([merge request 231085](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/231085)) et 18.9.6 ([merge request 231297](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/231297)).

### La détection des faux positifs de la détection des secrets activée par défaut sur tous les projets {#secret-detection-false-positive-detection-enabled-by-default-on-all-projects}

- Affecte : toutes les méthodes d'installation
- Versions affectées : 18.10.x

L'activation du flow de base pour la [détection des faux positifs de secrets](../../user/application_security/vulnerabilities/false_positive_detection.md) nécessite habituellement deux étapes :

1. Autoriser le flow par défaut pour un groupe.
1. Activer le flow par défaut pour des projets individuels.

Cependant, une mise à niveau vers n'importe quelle version de GitLab 18.10 active le flow de base pour la détection des faux positifs de secrets pour tous les projets. Une fois le flow par défaut autorisé pour un groupe, il est déjà activé pour tous les projets du groupe.

Vous devez vérifier les paramètres des projets d'un groupe avant d'autoriser le flow de base pour la détection des faux positifs de secrets pour ce groupe.

### La configuration compilée par job est soumise à une limite de taille de 1 Mio {#compiled-per-job-config-is-subject-to-a-1-mib-size-limit}

- Affecte : toutes les méthodes d'installation
- Versions affectées :

  | Release | Correctifs affectés | Niveau de correctif résolu |
  | ------- | ----------------------- | ----------------- |
  | 18.11   | 18.11.x                 | Non corrigé         |
  | 19.0    | 19.0.0 à 19.0.5         | 19.0.6            |
  | 19.1    | 19.1.0 à 19.1.3         | 19.1.4            |
  | 19.2    | 19.2.0 à 19.2.1         | 19.2.2            |

Une [modification visant à appliquer la validation du schéma JSON impose désormais également une limite de taille de 1 Mio pour la configuration compilée par job](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/218219). Lorsque la configuration compilée d'un job (ses options, variables YAML, jetons, secrets, etc.) dépasse cette limite, la création du pipeline échoue avec le message : `Failed to persist the pipeline: Validation failed: Config is too large. Maximum size allowed is 1 MiB`. La solution de contournement consiste à réduire la taille de la configuration du job à moins de 1 Mio.

Après la mise à niveau vers une version corrigée, [la limite de taille est configurable](../../administration/cicd/limits.md#maximum-size-of-the-entire-cicd-configuration) à l'aide du paramètre d'application `ci_max_total_yaml_size_bytes`.
