---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
ignore_in_report: true
title: Cloud Seed
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/371332) dans GitLab 15.4 [avec un feature flag](../administration/feature_flags/_index.md) nommé `google_cloud`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab Self-Managed et GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/100545) dans GitLab 15.5.

{{< /history >}}

Cloud Seed est un programme open source dirigé par GitLab en collaboration avec [Google Cloud](https://cloud.google.com/).

Cloud Seed associe la facilité d'utilisation d'Heroku à la flexibilité du hyper-cloud. Pour ce faire, nous utilisons OAuth 2 pour provisionner des services sur un hyper-cloud, en nous appuyant sur Terraform et l'Infrastructure as Code afin d'activer les opérations de niveau 2.

## Objectif {#purpose}

Nous pensons qu'il devrait être simple de déployer des applications web (et d'autres charges de travail) depuis GitLab vers les principaux fournisseurs cloud.

Pour soutenir cet effort, Cloud Seed facilite et rend intuitif l'utilisation des services Google Cloud appropriés dans GitLab.

## Pourquoi Google Cloud {#why-google-cloud}

*ou Pourquoi pas AWS ou Azure ?*

Cloud Seed est un programme open source que tout le monde peut étendre, et nous serions ravis de collaborer avec tous les grands fournisseurs cloud. Nous avons choisi de travailler avec Google Cloud car leur équipe est accessible, disponible et collaborative dans cet effort.

En tant que projet open source, [tout le monde peut contribuer](#contribute-to-cloud-seed) et orienter notre direction.

## Déployer vers Google Cloud Run {#deploy-to-google-cloud-run}

Une fois votre application web dans un projet GitLab, suivez ces étapes pour déployer votre application depuis GitLab vers Google Cloud avec Cloud Seed :

1. [Configurer les identifiants de déploiement](#set-up-deployment-credentials)
1. (Facultatif) [Configurer votre région GCP préférée](#configure-your-preferred-gcp-region)
1. [Configurer le pipeline de déploiement Cloud Run](#configure-the-cloud-run-deployment-pipeline)

### Configurer les identifiants de déploiement {#set-up-deployment-credentials}

Cloud Seed fournit une interface permettant de créer des comptes de service Google Cloud Platform (GCP) depuis votre projet GitLab. Le projet GCP associé doit être sélectionné lors du workflow de création du compte de service. Ce processus génère un compte de service, des clés et des autorisations de déploiement.

Pour créer un compte de service :

1. Accédez à la page `Project :: Infrastructure :: Google Cloud`.
1. Sélectionnez **Créer un compte de service**.
1. Suivez le workflow Google OAuth 2 et autorisez GitLab.
1. Sélectionnez votre projet GCP.
1. Associez une référence Git (telle qu'une branche ou un tag) au projet GCP sélectionné.
1. Soumettez le formulaire pour créer le compte de service.

Le compte de service généré, la clé du compte de service et l'ID de projet GCP associé sont stockés dans GitLab en tant que variables CI du projet. Vous pouvez les consulter et les gérer depuis la page `Project :: Settings :: CI`.

Le compte de service généré possède les rôles suivants :

- `roles/iam.serviceAccountUser`
- `roles/artifactregistry.admin`
- `roles/cloudbuild.builds.builder`
- `roles/run.admin`
- `roles/storage.admin`
- `roles/cloudsql.client`
- `roles/browser`

Vous pouvez renforcer la sécurité en stockant les variables CI dans des gestionnaires de secrets. Pour plus d'informations, consultez [la gestion des secrets avec GitLab](../ci/secrets/_index.md).

### Configurer votre région GCP préférée {#configure-your-preferred-gcp-region}

Lorsque vous configurez des régions GCP pour vos déploiements, la liste des régions proposées est un sous-ensemble de toutes les régions GCP disponibles.

Pour configurer une région :

1. Accédez à la page `Project :: Infrastructure :: Google Cloud`.
1. Sélectionnez **Configurer la région GCP**.
1. Sélectionnez votre région GCP préférée.
1. Associez une référence Git (telle qu'une branche ou un tag) à la région GCP sélectionnée.
1. Soumettez le formulaire pour configurer la région GCP.

La région GCP configurée est stockée dans GitLab en tant que variable CI du projet. Vous pouvez les consulter et les gérer depuis la page `Project :: Settings :: CI`.

### Configurer le pipeline de déploiement Cloud Run {#configure-the-cloud-run-deployment-pipeline}

Vous pouvez configurer le job de déploiement Google Cloud Run dans votre pipeline. Un cas d'utilisation typique de ce type de pipeline est le déploiement continu de votre application web.

Le pipeline du projet lui-même pourrait avoir un objectif plus large couvrant plusieurs étapes, telles que la compilation, les tests et la sécurisation. Par conséquent, l'offre de déploiement Cloud Run se présente sous la forme d'un seul job qui s'intègre dans un pipeline bien plus large.

Pour configurer le pipeline de déploiement Cloud Run :

1. Accédez à la page `Project :: Infrastructure :: Google Cloud`.
1. Accédez à l'onglet `Deployments`.
1. Pour `Cloud Run`, sélectionnez **Configurer via une requête de fusion**.
1. Examinez les modifications et soumettez-les pour créer une merge request.

Cette action crée une nouvelle branche avec le pipeline de déploiement Cloud Run (ou l'injecte dans un pipeline existant) et crée une merge request associée permettant d'examiner les modifications et l'exécution du pipeline de déploiement, puis de les fusionner dans la branche principale.

## Provisionner des bases de données Cloud SQL {#provision-cloud-sql-databases}

Les instances de bases de données relationnelles peuvent être provisionnées depuis la page `Project :: Infrastructure :: Google Cloud`. Cloud SQL est le service Google Cloud sous-jacent utilisé pour provisionner les instances de base de données.

Les bases de données et versions suivantes sont prises en charge :

- PostgreSQL : 14, 13, 12, 11, 10 et 9.6
- MySQL : 8.0, 5.7 et 5.6
- SQL Server
  - 2019 : Standard, Enterprise, Express et Web
  - 2017 : Standard, Enterprise, Express et Web

Les tarifs Google Cloud s'appliquent. Consultez la [page de tarification de Cloud SQL](https://cloud.google.com/sql/pricing).

1. [Créer une instance de base de données](#create-a-database-instance)
1. [Configuration de la base de données via un worker en arrière-plan](#database-setup-through-a-background-worker)
1. [Se connecter à la base de données](#connect-to-the-database)
1. [Gestion de l'instance de base de données](#managing-the-database-instance)

### Créer une instance de base de données {#create-a-database-instance}

Depuis la page `Project :: Infrastructure :: Google Cloud`, sélectionnez l'onglet **Base de données**. Vous y trouverez trois boutons pour créer des instances de base de données Postgres, MySQL et SQL Server.

Le formulaire de création d'instance de base de données comporte des champs pour le projet GCP, la référence Git (branche ou tag), la version de la base de données et le type de machine. Après soumission, l'instance de base de données est créée et la configuration de la base de données est mise en file d'attente en tant que job en arrière-plan.

### Configuration de la base de données via un worker en arrière-plan {#database-setup-through-a-background-worker}

La création réussie de l'instance de base de données déclenche un worker en arrière-plan pour effectuer les tâches suivantes :

- Créer un utilisateur de base de données
- Créer un schéma de base de données
- Stocker les informations de la base de données dans les variables CI/CD du projet

### Se connecter à la base de données {#connect-to-the-database}

Une fois la configuration de l'instance de base de données terminée, les informations de connexion à la base de données sont disponibles en tant que variables du projet. Celles-ci peuvent être gérées depuis la page `Project :: Settings :: CI` et sont mises à disposition des pipelines s'exécutant dans l'environnement approprié.

### Gestion de l'instance de base de données {#managing-the-database-instance}

La liste des instances dans `Project :: Infrastructure :: Google Cloud :: Databases` renvoie vers la Google Cloud Console. Sélectionnez une instance pour afficher les détails et gérer l'instance.

## Contribuer à Cloud Seed {#contribute-to-cloud-seed}

Il existe plusieurs façons de contribuer à Cloud Seed :

- Utilisez Cloud Seed et [partagez vos retours](https://gitlab.com/gitlab-org/incubation-engineering/five-minute-production/feedback/-/issues/new?template=general_feedback).
- Si vous maîtrisez Ruby on Rails ou Vue.js, envisagez de contribuer à GitLab en tant que développeur ou développeuse.
  - Une grande partie de Cloud Seed est un module interne de la base de code GitLab.
- Si vous maîtrisez les pipelines GitLab, envisagez de contribuer au projet [Cloud Seed Library](https://gitlab.com/gitlab-org/incubation-engineering/five-minute-production/library).
