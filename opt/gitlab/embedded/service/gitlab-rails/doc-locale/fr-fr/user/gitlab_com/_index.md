---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Paramètres de GitLab.com
description: "Configuration de l'instance GitLab.com."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Ces paramètres sont utilisés sur GitLab.com et sont disponibles pour les clients de [GitLab.com](https://about.gitlab.com/pricing/).

Consultez certains de ces paramètres sur la [page de configuration de l'instance GitLab.com](https://gitlab.com/help/instance_configuration).

## Paramètres de compte et de limite {#account-and-limit-settings}

GitLab.com utilise ces limites de compte. Si un paramètre n'est pas répertorié, la valeur par défaut [est la même que pour les instances GitLab Self-Managed](../../administration/settings/account_and_limit_settings.md) :

| Paramètre                                                                                                                                                                                                            | Valeur par défaut sur GitLab.com |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| [Taille du dépôt, LFS inclus](../../administration/settings/account_and_limit_settings.md#repository-size-limit)                                                                                                 | 10 GB              |
| [Taille maximale d'importation](../project/settings/import_export.md#import-a-project-and-its-data)                                                                                                                          | 5 Gio              |
| [Taille maximale d'exportation](../project/settings/import_export.md#export-a-project-and-its-data)                                                                                                                          | 40 GiB             |
| [Taille maximale des fichiers distants pour les importations depuis des stockages d'objets externes](../../administration/settings/import_and_export_settings.md#maximum-remote-file-size-for-imports)                                             | 10 Gio             |
| [Taille maximale des fichiers téléchargés lors d'importations depuis des instances GitLab sources par transfert direct](../../administration/settings/import_and_export_settings.md#maximum-download-file-size-for-imports-by-direct-or-offline-transfer) | 5 Gio              |
| Taille maximale des pièces jointes                                                                                                                                                                                            | 100 MiB            |
| [Taille maximale des fichiers décompressés pour les archives importées](../../administration/settings/import_and_export_settings.md#maximum-decompressed-file-size-for-imported-archives)                                           | 25 GiB             |
| [Taille maximale des pushs](../../administration/settings/account_and_limit_settings.md#max-push-size)                                                                                                                     | 5 Gio              |

Si vous approchez ou dépassez la limite de taille du dépôt, vous pouvez :

- [Réduire la taille de votre dépôt avec Git](../project/repository/repository_size.md#methods-to-reduce-repository-size).
- [Acheter de l'espace de stockage supplémentaire](https://about.gitlab.com/pricing/licensing-faq/#can-i-buy-more-storage).

> [!note]
> `git push` et les importations de projets GitLab sont limitées à 5 GiB par requête via Cloudflare. Les importations autres qu'un téléversement de fichier ne sont pas affectées par cette limite. Les limites de dépôt s'appliquent aux projets publics et privés.

## Sauvegardes {#backups}

Pour sauvegarder un projet entier sur GitLab.com, vous pouvez l'exporter :

- [Via l'interface utilisateur](../project/settings/import_export.md).
- [Via l'API](../../api/project_import_export.md#export-a-project). Vous pouvez également utiliser l'API pour téléverser des exports vers une plateforme de stockage, telle qu'Amazon S3.

Lors des exportations, tenez compte de [ce qui est et n'est pas inclus](../project/settings/import_export.md#project-items-that-are-exported) dans un export de projet.

Pour sauvegarder le dépôt Git d'un projet ou d'un wiki, clonez-le sur un autre ordinateur. Tous les fichiers [téléversés dans un wiki après le 22 août 2020](../project/wiki/_index.md#create-a-new-wiki-page) sont inclus lorsque vous clonez un dépôt.

## CI/CD {#cicd}

GitLab.com utilise ces paramètres [GitLab CI/CD](../../ci/_index.md). Tous les paramètres ou limites de fonctionnalités non répertoriés ici utilisent les valeurs par défaut indiquées dans la documentation correspondante :

| Paramètre                                                                          | GitLab.com                                                                                                 | Valeur par défaut (GitLab Self-Managed) |
|----------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|-------------------------------|
| Taille maximale des artefacts (compressés)                                              | 1 Go                                                                                                       | Voir [Taille maximale des artefacts](../../administration/cicd/limits.md#maximum-artifacts-size). |
| Artefacts - [durée d'expiration](../../ci/yaml/_index.md#artifactsexpire_in)              | 30 jours sauf indication contraire                                                                         | Voir [Expiration des artefacts par défaut](../../administration/settings/continuous_integration.md#set-default-artifacts-expiration). Les artefacts créés avant le 22 juin 2020 n'ont pas de date d'expiration. |
| Conservation des [résultats](../application_security/detect/security_scanning_results.md) d'analyse de sécurité   | 30 jours                                                                                                    | Voir [Période de conservation des analyses de sécurité](../../administration/settings/security_and_compliance.md#security-scan-retention-period). |
| Cron de planification de pipeline                                                          | `*/5 * * * *`                                                                                              | Voir [Configuration avancée des planifications de pipeline](../../administration/cicd/limits.md#maximum-scheduled-pipeline-frequency). |
| Nombre maximum de jobs dans un seul pipeline                                                | `500` pour le niveau Gratuit, `1000` pour tous les niveaux d'évaluation, `1500` pour GitLab Premium et `2000` pour GitLab Ultimate.              | Voir [Nombre maximum de jobs dans un pipeline](../../administration/cicd/limits.md#maximum-number-of-jobs-in-a-pipeline). |
| Nombre maximum de jobs dans les pipelines actifs                                                 | `500` pour le niveau Gratuit, `1000` pour tous les niveaux d'évaluation, `20000` pour GitLab Premium et `60000` pour GitLab Ultimate.            | Voir [Nombre de jobs dans les pipelines actifs](../../administration/cicd/limits.md#number-of-jobs-in-active-pipelines). |
| Nombre maximum d'abonnements CI/CD à un projet                                         | `2`                                                                                                        | Voir [Nombre d'abonnements CI/CD à un projet](../../administration/cicd/limits.md#number-of-cicd-subscriptions-to-a-project). |
| Nombre maximum de déclencheurs de pipeline dans un projet                                 | `25000`                                                                                                    | Voir [Limiter le nombre de déclencheurs de pipeline](../../administration/cicd/limits.md#limit-the-number-of-pipeline-triggers). |
| Nombre maximum de planifications de pipeline dans les projets                                           | `10` pour le niveau Gratuit, `50` pour tous les niveaux payants                                                                | Voir [Nombre de planifications de pipeline](../../administration/cicd/limits.md#number-of-pipeline-schedules). |
| Nombre maximum de pipelines pour chaque planification                                              | `24` pour le niveau Gratuit, `288` pour tous les niveaux payants                                                               | Voir [Limiter le nombre de pipelines créés par une planification de pipeline chaque jour](../../administration/cicd/limits.md#limit-the-number-of-pipelines-created-by-a-pipeline-schedule-each-day). |
| Nombre maximum de règles de planification définies pour chaque projet de politique de sécurité        | Illimité pour tous les niveaux payants                                                                               | Voir [Nombre de règles de planification définies pour chaque projet de politique de sécurité](../../administration/cicd/limits.md#limit-the-number-of-schedule-rules-defined-for-security-policy-project). |
| [Archivage des pipelines](../../administration/settings/continuous_integration.md#archive-pipelines) | 1 an                                                                                       | Jamais. Les jobs créés avant le 22 juin 2020 ont été archivés après le 22 septembre 2020. |
| Nombre maximum de cas de test pour chaque [rapport de test unitaire](../../ci/testing/unit_test_reports.md) | `500000`                                                                                              | Illimité.                    |
| Nombre maximum de runners enregistrés                                                       | Niveau Gratuit : `50` pour chaque groupe et `50`pour chaque projet<br/>Tous les niveaux payants : `1000` pour chaque groupe et `1000` pour chaque projet | Voir [Nombre de runners enregistrés pour chaque portée](../../administration/cicd/limits.md#number-of-registered-runners-for-groups-and-projects). |
| Limite de variables dotenv                                                        | Niveau Gratuit : `50`<br>Niveau GitLab Premium : `100`<br>Niveau GitLab Ultimate : `150`                                             | Voir [Limiter les variables dotenv](../../administration/cicd/limits.md#limit-dotenv-variables). |
| Taux maximum de déclenchement de pipeline downstream (pour un projet, un utilisateur et un commit donnés) | `350` par minute                                                                                          | Voir [Taux maximum de déclenchement de pipeline downstream](../../administration/cicd/limits.md#limit-downstream-pipeline-trigger-rate). |
| Taux maximum d'annulation de pipeline par pipeline (pour un utilisateur donné) | `5` par minute   | Voir [Limites de débit d'annulation de pipeline](../../administration/cicd/limits.md#pipeline-cancellation-rate-limits). |
| Taux maximum d'annulation de pipeline par projet (pour un utilisateur donné)  | `120` par minute | Voir [Limites de débit d'annulation de pipeline](../../administration/cicd/limits.md#pipeline-cancellation-rate-limits). |
| Taux maximum de relance de pipeline par pipeline (pour un utilisateur donné) | `5` par minute   | Voir [Limites de débit de relance de pipeline](../../administration/cicd/limits.md#pipeline-retry-rate-limits). |
| Taux maximum de relance de pipeline par projet (pour un utilisateur donné)  | `200` par minute | Voir [Limites de débit de relance de pipeline](../../administration/cicd/limits.md#pipeline-retry-rate-limits). |
| Taux maximum de relance de job par job (pour un utilisateur donné)                                | `3` par minute                                                                                            | Voir [Limites de débit de relance de job et d'exécution manuelle de job](../../administration/cicd/limits.md#job-retry-and-manual-job-run-rate-limits). |
| Taux maximum de relance de job par projet (pour un utilisateur donné)                            | `320` par minute                                                                                          | Voir [Limites de débit de relance de job et d'exécution manuelle de job](../../administration/cicd/limits.md#job-retry-and-manual-job-run-rate-limits). |
| Taux maximum d'exécution manuelle de job par job (pour un utilisateur donné)                           | `3` par minute                                                                                            | Voir [Limites de débit de relance de job et d'exécution manuelle de job](../../administration/cicd/limits.md#job-retry-and-manual-job-run-rate-limits). |
| Taux maximum d'exécution manuelle de job par projet (pour un utilisateur donné)                       | `200` par minute                                                                                          | Voir [Limites de débit de relance de job et d'exécution manuelle de job](../../administration/cicd/limits.md#job-retry-and-manual-job-run-rate-limits). |
| Taux maximum de suppression de pipeline par pipeline (pour un utilisateur donné) | `5` par minute   | Voir [Limites de débit de suppression de pipeline](../../administration/cicd/limits.md#pipeline-deletion-rate-limits). |
| Taux maximum de suppression de pipeline par projet (pour un utilisateur donné)  | `400` par minute | Voir [Limites de débit de suppression de pipeline](../../administration/cicd/limits.md#pipeline-deletion-rate-limits). |
| Nombre maximum de pipelines downstream dans l'arborescence hiérarchique d'un pipeline            | `1000`                                                                                                     | Voir [Limiter la taille de la hiérarchie de pipeline](../../administration/cicd/limits.md#limit-pipeline-hierarchy-size). |
| Nombre maximum de demandes de création de pipeline par projet, commit et utilisateur (par minute) | `25`                                                                                                | Voir [Limites de débit de création de pipeline](../../administration/cicd/limits.md#pipeline-creation-rate-limits). |

## Registre de conteneurs {#container-registry}

| Paramètre                                | GitLab.com                       | GitLab Self-Managed |
|:---------------------------------------|:---------------------------------|------------------------|
| Nom de domaine                            | `registry.gitlab.com`            |                        |
| Adresse IP                             | `35.227.35.254`                  |                        |
| Nom de domaine CDN                        | `cdn.registry.gitlab-static.net` |                        |
| Adresse IP du CDN                         | `34.149.22.116`                  |                        |
| Durée du jeton d'autorisation (minutes) | `15`                             | Voir [Augmenter la durée du jeton du registre de conteneurs](../../administration/packages/container_registry.md#increase-token-duration). |

Pour utiliser le registre de conteneurs GitLab, les clients Docker doivent avoir accès aux éléments suivants :

- Le point de terminaison du registre et GitLab.com pour l'autorisation.
- Google Cloud Storage (voir [les plages d'IP que Google met à disposition des utilisateurs sur Internet](https://knowledge.workspace.google.com/admin/security/obtain-google-ip-address-ranges)) ou Google Cloud Content Delivery Network pour télécharger des images.

GitLab.com est protégé par Cloudflare. Pour les connexions entrantes vers GitLab.com, vous devez autoriser les blocs CIDR de Cloudflare ([IPv4](https://www.cloudflare.com/ips-v4/) et [IPv6](https://www.cloudflare.com/ips-v6/)).

## Limites d'affichage des diffs {#diff-display-limits}

Les paramètres d'affichage des fichiers de diff ne peuvent pas être modifiés sur GitLab.com. Ces limites s'appliquent à la fois à l'interface utilisateur GitLab et aux points de terminaison de l'API.

| Paramètre                 | Définition                                     | GitLab.com |
|-------------------------|------------------------------------------------|------------|
| Taille maximale du patch de diff | La taille totale de l'ensemble du diff.             | 200 KB |
| Nombre maximum de fichiers dans un diff      | Le nombre total de fichiers modifiés dans un diff.   | 3 000 |
| Nombre maximum de lignes dans un diff      | Le nombre total de lignes modifiées dans un diff.   | 100 000 |

[Les limites de diff peuvent être modifiées](../../administration/diff_limits.md#configure-diff-limits) dans GitLab Self-Managed.

## E-mail {#email}

Paramètres de configuration des e-mails, adresses IP et alias.

### Paramètres de confirmation {#confirmation-settings}

GitLab.com utilise ces paramètres de confirmation par e-mail :

- [`email_confirmation_setting`](../../administration/settings/sign_up_restrictions.md#confirm-user-email) est défini sur **Stricte**.
- [`unconfirmed_users_delete_after_days`](../../administration/moderate_users.md#automatically-delete-unconfirmed-users) est défini sur trois jours.

### Adresses IP {#ip-addresses}

GitLab.com utilise [Mailgun](https://www.mailgun.com/) pour envoyer des e-mails depuis le domaine `mg.gitlab.com` et dispose de ses propres adresses IP dédiées :

- `23.253.183.236`
- `69.72.35.190`
- `69.72.44.107`
- `159.135.226.146`
- `161.38.202.219`
- `192.237.158.143`
- `192.237.159.239`
- `198.61.254.136`
- `198.61.254.160`
- `209.61.151.122`

Les adresses IP pour `mg.gitlab.com` sont susceptibles d'être modifiées à tout moment.

### Alias Service Desk {#service-desk-alias}

GitLab.com dispose d'une boîte aux lettres configurée pour Service Desk avec l'adresse e-mail : `contact-project+%{key}@incoming.gitlab.com`. Pour utiliser cette boîte aux lettres, configurez le [suffixe personnalisé](../project/service_desk/configure.md#configure-a-suffix-for-service-desk-alias-email) dans les paramètres du projet.

## Limites de concurrence RPC Gitaly sur GitLab.com {#gitaly-rpc-concurrency-limits-on-gitlabcom}

Les limites de concurrence et de mise en file d'attente des RPC Gitaly par dépôt sont configurées pour différents types d'opérations Git, comme `git clone`. Lorsque ces limites sont dépassées, un message `fatal: remote error: GitLab is currently unable to handle this request due to load` est renvoyé au client.

Une opération de fetch ou de clone est concurrente lorsqu'elle démarre avant qu'une opération précédente ne se termine.

| Opération               | Limite sur GitLab.com         |
|:------------------------|:-------------------------|
| Fetches et clones HTTP | 60 opérations simultanées |
| Fetches et clones SSH  | 30 opérations simultanées |

Pour la documentation administrateur, voir [limiter la concurrence RPC](../../administration/gitaly/concurrency_limiting.md#limit-rpc-concurrency).

## GitLab Pages {#gitlab-pages}

Certains paramètres de [GitLab Pages](../project/pages/_index.md) diffèrent des [valeurs par défaut pour GitLab Self-Managed](../../administration/pages/_index.md) :

| Paramètre                                                | GitLab.com |
|--------------------------------------------------------|------------|
| Nom de domaine                                            | `gitlab.io` |
| Adresse IP                                             | `35.185.44.232` |
| Prise en charge des domaines personnalisés                             | {{< yes >}} |
| Prise en charge des certificats TLS                           | {{< yes >}} |
| Taille maximale du site                                      | 1 Go       |
| Nombre de domaines personnalisés pour chaque site GitLab Pages | 150        |

La taille maximale de votre site Pages dépend de la taille maximale des artefacts, qui fait partie des [paramètres GitLab CI/CD](#cicd).

[Des limites de débit](rate_limits.md#current-rate-limits) s'appliquent également à GitLab Pages.

## GitLab.com à grande échelle {#gitlabcom-at-scale}

En plus du package Linux GitLab Enterprise Edition, GitLab.com utilise les applications et paramètres suivants pour atteindre une grande échelle. Tous les paramètres sont accessibles publiquement, sous forme de [configuration Kubernetes](https://gitlab.com/gitlab-com/gl-infra/k8s-workloads/gitlab-com) ou de [cookbooks Chef](https://gitlab.com/gitlab-cookbooks).

### Consul {#consul}

Découverte de services :

- [`gitlab-cookbooks` / `gitlab_consul` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab_consul)

### Fluentd {#fluentd}

Nous utilisons Fluentd pour unifier nos logs GitLab :

- [`gitlab-cookbooks` / `gitlab_fluentd` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab_fluentd)

### Grafana {#grafana}

Pour la visualisation des données de monitoring :

- [`gitlab-cookbooks` / `gitlab-grafana` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab-grafana)

### HAProxy {#haproxy}

Équilibreur de charge TCP/HTTP haute performance :

- [`gitlab-cookbooks` / `gitlab-haproxy` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab-haproxy)

### Prometheus {#prometheus}

Prometheus complète notre stack de monitoring :

- [`gitlab-cookbooks` / `gitlab-prometheus` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab-prometheus)

### Sentry {#sentry}

Suivi des erreurs open source :

- [`gitlab-cookbooks` / `gitlab-sentry` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab-sentry)

## Runners hébergés par GitLab {#gitlab-hosted-runners}

Utilisez les runners hébergés par GitLab pour exécuter vos jobs CI/CD sur GitLab.com et GitLab Dedicated afin de créer, tester et déployer facilement votre application dans différents environnements.

Pour plus d'informations, voir [Runners hébergés par GitLab](../../ci/runners/_index.md).

## Liste des noms d'hôte {#hostname-list}

Ajoutez ces noms d'hôte lorsque vous configurez des listes d'autorisation dans des proxys HTTP(S) locaux ou d'autres logiciels de blocage web qui régissent les ordinateurs des utilisateurs finaux. Les pages de GitLab.com chargent du contenu depuis ces noms d'hôte :

- `gitlab.com`
- `*.gitlab.com`
- `*.gitlab-static.net`
- `*.gitlab.io`
- `*.gitlab.net`

La documentation et les pages de la société GitLab servies via `docs.gitlab.com` et `about.gitlab.com` chargent également certains contenus de page directement depuis des noms d'hôte CDN publics courants.

### Liste des noms d'hôte du registre de conteneurs {#container-registry-hostname-list}

Ajoutez ces noms d'hôte supplémentaires à vos listes d'autorisation si vous extrayez des images depuis `registry.gitlab.com` :

- `*.storage.googleapis.com`
- `*.cdn.registry.gitlab-static.net`

## Importations {#imports}

GitLab.com utilise des paramètres pour limiter l'importation de données dans GitLab.

### Sources d'importation par défaut {#default-import-sources}

Les [sources d'importation](../import/_index.md) (outils de migration) disponibles par défaut dépendent de la version de GitLab que vous utilisez :

- GitLab.com : toutes les sources d'importation disponibles sont activées par défaut.
- GitLab Self-Managed : aucune source d'importation n'est activée par défaut et doit être [activée](../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources).

### Limites des utilisateurs fictifs d'import {#import-placeholder-user-limits}

Les importations dans GitLab.com limitent le nombre d'[utilisateurs temporaires](../import/mapping/post_migration_mapping.md#placeholder-users) pour chaque groupe principal. Les limites varient en fonction de votre plan et du nombre de sièges. Pour plus d'informations, consultez le [tableau des limites d'utilisateurs temporaires pour GitLab.com](../import/mapping/post_migration_mapping.md#placeholder-user-limits).

## Plage d'IP {#ip-range}

GitLab.com utilise les plages d'IP `34.74.90.64/28` et `34.74.226.0/24` pour le trafic de sa flotte Web/API. L'ensemble de cette plage est exclusivement alloué à GitLab. Les connexions provenant des webhooks ou de la mise en miroir de dépôts proviennent de ces adresses IP. Vous devez autoriser ces connexions.

- Connexions entrantes - GitLab.com est protégé par Cloudflare. Pour les connexions entrantes vers GitLab.com, autorisez les blocs CIDR de Cloudflare ([IPv4](https://www.cloudflare.com/ips-v4/) et [IPv6](https://www.cloudflare.com/ips-v6/)).

- Connexions sortantes depuis les runners CI/CD - Nous ne fournissons pas d'adresses IP statiques pour les connexions sortantes depuis les runners CI/CD. Cependant, ces recommandations peuvent vous aider :
  - Les runners Linux avec GPU et les runners Linux Arm64 sont déployés dans Google Cloud, dans `us-central1`.
  - Les autres runners d'instance GitLab.com sont déployés dans Google Cloud dans `us-east1`.
  - Les runners macOS sont hébergés sur AWS dans la région `us-east-1`, avec des gestionnaires de runners hébergés sur Google Cloud.

Pour configurer un pare-feu basé sur les IP, vous devez autoriser à la fois les [plages d'adresses IP AWS](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html) et les [plages d'adresses IP Google Cloud](https://cloud.google.com/compute/docs/faq#find_ip_range).

Consultez la procédure de recherche des [plages d'adresses IP ou blocs CIDR pour GCP](https://cloud.google.com/compute/docs/faq#find_ip_range).

## Nombre maximum de relecteurs et d'assignés {#maximum-number-of-reviewers-and-assignees}

Les merge requests appliquent ces maximums :

- Nombre maximal d'assignés : 200
- Nombre maximal de relecteurs : 200

## Limites des merge requests {#merge-request-limits}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/521970) dans GitLab 17.10 [avec le feature flag](../../administration/feature_flags/_index.md) `merge_requests_diffs_limit`. Fonctionnalité désactivée par défaut.
- [Activée sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/521970) dans GitLab 17.10.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/537447) dans GitLab 19.0. Le feature flag `merge_requests_diffs_limit` a été supprimé.

{{< /history >}}

GitLab limite chaque merge request à 1 000 [versions de diff](../project/merge_requests/versions.md). Les merge requests qui atteignent cette limite ne peuvent plus être mises à jour. Au lieu de cela, fermez la merge request concernée et créez-en une nouvelle.

### Limite des commits de diff {#diff-commits-limit}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/527036) dans GitLab 17.11 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `merge_requests_diff_commits_limit`. Fonctionnalité désactivée par défaut.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/537446) dans GitLab 19.0. Le feature flag `merge_requests_diff_commits_limit` a été supprimé.

{{< /history >}}

GitLab limite chaque merge request à 1 000 000 (un million) de commits de diff. Les merge requests qui atteignent cette limite ne peuvent plus être mises à jour. Au lieu de cela, fermez la merge request concernée et créez-en une nouvelle.

## Exigences relatives aux mots de passe {#password-requirements}

GitLab.com définit ces exigences pour les mots de passe des nouveaux comptes et les modifications de mot de passe :

- Longueur minimale de 8 caractères.
- Longueur maximale de 128 caractères.
- Tous les caractères sont acceptés. Par exemple, `~`, `!`, `@`, `#`, `$`, `%`, `^`, `&`, `*`, `()`, `[]`, `_`, `+`, `=` et `-`.

## Création de groupes {#group-creation}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/506673) dans GitLab 18.0
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/560840) de l'exception pour les administrateurs GitLab SaaS dans GitLab 18.5

{{< /history >}}

Sur GitLab.com, la [création de groupes principaux](../../api/groups.md#create-a-group) n'est autorisée que via l'interface utilisateur. Seuls les administrateurs peuvent utiliser l'API pour créer des groupes principaux.

## Suppression de projets et de groupes {#project-and-group-deletion}

Paramètres relatifs à la suppression de projets et de groupes.

### Suppression différée de groupes {#delayed-group-deletion}

{{< history >}}

- [Déplacé](https://gitlab.com/groups/gitlab-org/-/work_items/17208) de GitLab Premium vers GitLab Free dans la version 18.0.
- [Période de suppression prolongée](https://gitlab.com/groups/gitlab-org/-/work_items/17375) de sept jours à 30 jours dans la version 18.0.2.

{{< /history >}}

Les groupes sont définitivement supprimés après un délai de 30 jours.

Découvrez comment [afficher et restaurer les groupes marqués pour suppression](../group/_index.md#restore-a-group).

### Suppression différée de projets {#delayed-project-deletion}

{{< history >}}

- [Déplacé](https://gitlab.com/groups/gitlab-org/-/work_items/17208) de GitLab Premium vers GitLab Free dans la version 18.0.
- [Période de suppression prolongée](https://gitlab.com/groups/gitlab-org/-/work_items/17375) de sept jours à 30 jours dans la version 18.0.2.

{{< /history >}}

Les projets sont définitivement supprimés après un délai de 30 jours.

Découvrez comment [afficher et restaurer les projets marqués pour suppression](../project/working_with_projects.md#restore-a-project).

### Suppression des projets dormants {#dormant-project-deletion}

La [suppression des projets dormants](../../administration/dormant_project_deletion.md) est désactivée sur GitLab.com.

## Limites du registre de paquets {#package-registry-limits}

La [taille maximale de fichier](../../administration/instance_limits.md#file-size-limits) pour un paquet téléversé dans le [registre de paquets GitLab](../packages/package_registry/_index.md) varie selon le format :

| Type de paquet           | GitLab.com                         |
|------------------------|------------------------------------|
| Conan                  | 5 Go                               |
| Generic                | 5 Go                               |
| Helm                   | 5 Mo                               |
| Modèle de machine learning | 10 GB (les téléversements sont limités à 5 GB) |
| Maven                  | 5 Go                               |
| npm                    | 5 Go                               |
| NuGet                  | 5 Go                               |
| PyPI                   | 5 Go                               |
| Terraform              | 1 Go                               |

## Puma {#puma}

GitLab.com utilise la valeur par défaut de 60 secondes pour les [délais d'expiration des requêtes Puma](../../administration/operations/puma.md#change-the-worker-timeout).

## Limites de débit sur GitLab.com {#rate-limits-on-gitlabcom}

Les limites de débit sur GitLab.com varient selon le plan d'abonnement et s'appliquent à la fois par utilisateur et par groupe principal. Chaque plan dispose d'une limite horaire qui régit votre utilisation et d'une limite de rafale par minute, la limite horaire ayant la priorité. Les requêtes authentifiées bénéficient de l'allocation complète de votre plan.

Pour connaître les limites de chaque plan, leur entrée en vigueur et la procédure à suivre pour gérer une réponse `429 Too Many Requests`, consultez [les limites de débit de GitLab.com](rate_limits.md).

## Sidekiq {#sidekiq}

GitLab.com exécute [Sidekiq](https://sidekiq.org) en tant que [processus externe](../../administration/sidekiq/_index.md) pour la planification des jobs Ruby.

Les paramètres actuels se trouvent dans la [configuration des pods Kubernetes de GitLab.com](https://gitlab.com/gitlab-com/gl-infra/k8s-workloads/gitlab-com/-/blob/master/releases/gitlab/values/gprd.yaml.gotmpl).

## Clés SSH et authentification {#ssh-keys-and-authentication}

Paramètres relatifs à l'authentification avec SSH. Pour plus d'informations sur le nombre maximum de connexions, voir [Nombre maximum de connexions SSH](rate_limits.md#ssh-maximum-number-of-connections).

### Port SSH alternatif {#alternative-ssh-port}

GitLab.com est accessible via un [port SSH différent](https://about.gitlab.com/blog/gitlab-dot-com-now-supports-an-alternate-git-plus-ssh-port/) pour `git+ssh`.

| Paramètre    | Valeur               |
|------------|---------------------|
| `Hostname` | `altssh.gitlab.com` |
| `Port`     | `443`               |

Voici un exemple de `~/.ssh/config` :

```plaintext
Host gitlab.com
  Hostname altssh.gitlab.com
  User git
  Port 443
  PreferredAuthentications publickey
  IdentityFile ~/.ssh/gitlab
```

### Empreintes des clés SSH de l'hôte {#ssh-host-keys-fingerprints}

Accédez à la configuration de l'instance actuelle pour consulter les empreintes des clés SSH de l'hôte sur GitLab.com.

1. Connectez-vous à GitLab.
1. Dans la barre latérale gauche, sélectionnez **Aide** ({{< icon name="question-o" >}}) > **Aide**.
1. Sur la page d'aide, sélectionnez **Vérifiez la configuration actuelle de l 'instance**.

Dans la configuration de l'instance, vous verrez les **Empreintes de la clé SSH de l'hôte** :

| Algorithme        | MD5 (obsolète) | SHA256  |
|------------------|------------------|---------|
| ECDSA            | `f1:d0:fb:46:73:7a:70:92:5a:ab:5d:ef:43:e2:1c:35` | `SHA256:HbW3g8zUjNSksFbqTiUWPWg2Bq1x8xdGUrliXFzSnUw` |
| ED25519          | `2e:65:6a:c8:cf:bf:b2:8b:9a:bd:6d:9f:11:5c:12:16` | `SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8` |
| RSA              | `b6:03:0e:39:97:9e:d0:e7:24:ce:a3:77:3e:01:42:09` | `SHA256:ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ` |

La première fois que vous vous connectez à un dépôt GitLab.com, l'une de ces clés s'affiche dans la sortie.

### Restrictions relatives aux clés SSH {#ssh-key-restrictions}

GitLab.com utilise les [restrictions de clés SSH](../../security/ssh_keys_restrictions.md) par défaut.

### Entrées SSH `known_hosts` {#ssh-known_hosts-entries}

Pour ignorer la confirmation manuelle des empreintes dans SSH, ajoutez ce qui suit à `.ssh/known_hosts` :

```plaintext
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf
gitlab.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9
gitlab.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=
```

## Paramètres de visibilité {#visibility-settings}

Les projets, groupes et extraits de code disposent du paramètre [Visibilité interne](../public_access.md#internal-projects-and-groups), [désactivé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/12388).

## Webhooks {#webhooks}

Les limites suivantes s'appliquent aux [webhooks](../project/integrations/webhooks.md).

### Limites de débit {#rate-limits}

Le nombre de fois par minute que les webhooks d'un groupe principal peuvent être appelés. Tous les webhooks de projet et de groupe dans l'espace de nommage partagent cette limite. La limite varie en fonction de votre plan et du nombre de sièges dans votre abonnement.

| Plan                                                   | Valeur par défaut sur GitLab.com |
|--------------------------------------------------------|------------------------|
| GitLab Free                                            | `500`                  |
| GitLab Premium, `99` sièges ou moins                    | `1,600`                |
| GitLab Premium, `100-399` sièges                        | `2,800`                |
| GitLab Premium, `400` sièges ou plus                    | `4,000`                |
| GitLab Ultimate et open source, `999` sièges ou moins  | `6,000`                |
| GitLab Ultimate et open source, `1,000-4,999` sièges   | `9,000`                |
| GitLab Ultimate et open source, `5,000` sièges ou plus | `13,000`               |

Lorsque la limite de débit est atteinte, tous les webhooks de l'espace de nommage sont temporairement désactivés et réactivés automatiquement à la minute suivante.

En cas de limitation de débit, un badge apparaît à côté du webhook dans la liste des webhooks. Sur la page de modification du webhook, un message indique combien de fois par minute la limite de l'espace de nommage a été dépassée et quand les webhooks sont réactivés.

### Limites des politiques de sécurité {#security-policy-limits}

Le nombre maximum de politiques que vous pouvez ajouter à un projet de politique de sécurité. Ces limites s'appliquent à chaque type de politique individuellement. Par exemple, vous pouvez avoir cinq politiques d'approbation de merge request et cinq politiques d'exécution d'analyse dans le même projet de politique de sécurité.

| Type de politique                                            | Limite par défaut                             |
|--------------------------------------------------------|-------------------------------------------|
| Politiques d'approbation de merge request                        | Cinq politiques par projet de politique de sécurité |
| Politiques d'exécution des scans                                | Cinq politiques par projet de politique de sécurité |
| Politiques d'exécution de pipeline                            | Cinq politiques par projet de politique de sécurité |
| Politiques de gestion des vulnérabilités                      | Cinq politiques par projet de politique de sécurité |

### Autres limites {#other-limits}

| Paramètre                                                             | Valeur par défaut sur GitLab.com |
|:--------------------------------------------------------------------|:-----------------------|
| Nombre de webhooks                                                  | 100 par projet, 50 par groupe (les webhooks des sous-groupes ne sont pas comptabilisés dans les limites du groupe parent) |
| Taille maximale du payload                                                | 25 Mo                  |
| Délai d'expiration                                                             | 10 secondes             |
| [Déploiements Pages parallèles](../project/pages/parallel_deployments.md#limits) | 100 déploiements supplémentaires (niveau GitLab Premium), 500 déploiements supplémentaires (niveau GitLab Ultimate) |

Pour les limites des instances GitLab Self-Managed, voir :

- [Limite de débit des webhooks](../../administration/instance_limits.md#webhook-rate-limit).
- [Nombre de webhooks](../../administration/instance_limits.md#number-of-webhooks).
- [Délai d'expiration des webhooks](../../administration/instance_limits.md#webhook-timeout).
- [Déploiements Pages parallèles](../../administration/instance_limits.md#number-of-parallel-pages-deployments).
