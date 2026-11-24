---
stage: Application Security Testing
group: Composition Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Base de données de métadonnées de paquets
description: "Ce que contient la base de données de métadonnées de paquets, comment GitLab la synchronise et quelle version du format de données chaque version de GitLab lit."
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

La base de données de métadonnées de paquets (PMDB) est un ensemble de données de licences et d'avis de sécurité pour les paquets open source, maintenu par GitLab. GitLab la synchronise dans la base de données de votre instance, où les fonctionnalités suivantes la lisent :

- [Analyse des conteneurs pour le registre](../container_scanning/_index.md#container-scanning-for-registry)
- [Scan continu des vulnérabilités](../continuous_vulnerability_scanning/_index.md)
- [Analyse des dépendances](../dependency_scanning/_index.md)
- [Analyse des licences dans les fichiers CycloneDX](../../compliance/license_scanning_of_cyclonedx_files/_index.md)

La base de données de métadonnées de paquets est sous licence [EE License](https://storage.googleapis.com/prod-export-license-bucket-1a6c642fc4de57d4/LICENSE).

## Jeux de données {#datasets}

{{< history >}}

- Les avis sur les malwares ont été [introduits](https://gitlab.com/groups/gitlab-org/-/epics/20876) en version [bêta](../../../policy/development_stages_support.md#beta) dans GitLab 19.3 [avec les feature flags](../../../administration/feature_flags/_index.md) nommés `sync_malware_advisories` et `ingest_malware_advisories`. Activés par défaut. Activés par défaut.
- Les données de licence v3 ont été [introduites](https://gitlab.com/groups/gitlab-org/-/epics/22880) dans GitLab 19.4 avec un feature flag nommé `sync_v3_license_expressions`. Activé par défaut. Activés par défaut.
- Les avis sur les malwares sont [généralement disponibles](https://gitlab.com/groups/gitlab-org/-/epics/20876) dans GitLab 19.5. Les feature flags `sync_malware_advisories` et `ingest_malware_advisories` ont été supprimés.

{{< /history >}}

La base de données de métadonnées de paquets contient quatre jeux de données :

| Jeu de données            | Contenu                                              | Utilisé par |
|--------------------|-------------------------------------------------------|---------|
| Licences           | Données de licence pour les versions de paquets.                    | Analyse des licences |
| Avis         | Avis de sécurité pour les versions de paquets.             | Analyse des dépendances, analyse continue des vulnérabilités et analyse des conteneurs pour le registre |
| Enrichissement CVE     | Le score EPSS et le statut KEV des vulnérabilités.     | [Données d'évaluation des risques liés aux vulnérabilités](../vulnerabilities/risk_assessment_data.md) |
| Avis sur les malwares | Paquets malveillants connus trouvés dans les registres de paquets. | Analyse des dépendances, analyse continue des vulnérabilités et politiques d'approbation des merge requests. Pour plus d'informations, consultez [Avis GitLab sur les malwares](../gitlab_advisory_database/_index.md#gitlab-advisories-for-malware). |

Par défaut, GitLab synchronise les données pour tous les types de registres de paquets. Pour synchroniser moins de données, désélectionnez les types de registres de paquets que vous n'utilisez pas dans les [paramètres d'administration](../../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync).

## Versions du format de données {#data-format-versions}

Chaque jeu de données est publié dans l'une des deux versions du format de données, v2 ou v3. Il s'agit de versions du format de données, et non de versions de GitLab.

| Version du format | Jeux de données | Distribué depuis |
|----------------|----------|------------------|
| v2             | Licences pour GitLab 19.3 et versions antérieures, avis et enrichissement CVE. | Buckets Google Cloud Storage publics, accessibles en lecture sans identifiants. |
| v3             | Licences pour GitLab 19.4 et versions ultérieures, et avis sur les malwares. | Le service de distribution de la base de données de métadonnées de paquets, un service GitLab authentifié. |

Les données de licence v3 contiennent des expressions de licence Software Package Data Exchange (SPDX) au lieu d'identifiants de licence uniques. Par exemple, `MIT OR Apache-2.0`.

Vous ne choisissez pas la version du format. Votre version de GitLab détermine laquelle est lue :

| Version de GitLab   | Licences | Avis | Enrichissement CVE | Avis sur les malwares |
|------------------|----------|------------|----------------|--------------------|
| 19.2 et versions antérieures | v2       | v2         | v2             | Non disponible      |
| 19.3             | v2       | v2         | v2             | v3                 |
| 19.4 et versions ultérieures   | v3       | v2         | v2             | v3                 |

## Synchronisation {#synchronization}

Les cron jobs dans Sidekiq synchronisent chaque jeu de données dans la base de données de votre instance. Chaque exécution reprend depuis le point de contrôle enregistré par l'exécution précédente, de sorte qu'elle n'importe que les données plus récentes que celles déjà présentes dans l'instance.

### Instances avec accès à Internet {#instances-with-internet-access}

Une instance avec accès à Internet télécharge les données v2 depuis les buckets publics et les données v3 depuis le service de distribution. Pour télécharger les données v2, l'instance a besoin d'un accès réseau sortant vers `storage.googleapis.com`.

### Instances hors ligne {#offline-instances}

Une instance hors ligne ne peut pas télécharger les données elle-même. À la place, vous les téléchargez sur une machine disposant d'un accès à Internet et les copiez dans le répertoire `vendor/package_metadata` de l'instance hors ligne. Le téléchargement des données v3 nécessite une licence hors ligne.

Lorsque le répertoire d'un jeu de données existe sous `vendor/package_metadata`, GitLab lit ce répertoire au lieu de télécharger les données. Il n'y a pas de repli vers le réseau ; ainsi, un répertoire contenant des données obsolètes sert des données obsolètes sans signaler d'erreur.

Pour les procédures de téléchargement et les détails sur les feature flags pour chaque jeu de données, consultez [Base de données de métadonnées de paquets pour les instances hors ligne](../../../topics/offline/package-metadata-database.md).

## Sujets connexes {#related-topics}

- [Environnements hors ligne](../offline_deployments/_index.md)
