---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Personnaliser Auto DevOps
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez personnaliser les composants d'Auto DevOps selon vos besoins. Par exemple, vous pouvez :

- Ajouter des [buildpacks](#custom-buildpacks), des [Dockerfiles](#custom-dockerfiles) et des [charts Helm](#custom-helm-chart) personnalisés.
- Activer les déploiements de staging et canari avec une [configuration CI/CD](#customize-gitlab-ciyml) personnalisée.
- Étendre Auto DevOps avec l'[API GitLab](#extend-auto-devops-with-the-api).

## Buildpacks personnalisés {#custom-buildpacks}

Vous pouvez personnaliser vos buildpacks dans l'un ou l'autre des cas suivants :

- La détection automatique des buildpacks échoue pour votre projet.
- Vous avez besoin d'un contrôle plus précis sur votre build.

### Personnaliser les buildpacks avec Cloud Native Buildpacks {#customize-buildpacks-with-cloud-native-buildpacks}

Spécifiez l'un ou l'autre des éléments suivants :

- La variable CI/CD `BUILDPACK_URL` avec l'un des [formats de spécification d'URI de `pack`](https://buildpacks.io/docs/app-developer-guide/specify-buildpacks/).
- Un [descripteur de projet `project.toml`](https://buildpacks.io/docs/app-developer-guide/using-project-descriptor/) avec les buildpacks que vous souhaitez inclure.

### Plusieurs buildpacks {#multiple-buildpacks}

Étant donné qu'Auto Test ne peut pas utiliser le fichier `.buildpacks`, Auto DevOps ne prend pas en charge plusieurs buildpacks. Le buildpack [heroku-buildpack-multi](https://github.com/heroku/heroku-buildpack-multi/), utilisé en arrière-plan pour analyser le fichier `.buildpacks`, ne fournit pas les commandes nécessaires `bin/test-compile` et `bin/test`.

Pour n'utiliser qu'un seul buildpack personnalisé, vous devez fournir la variable CI/CD de projet `BUILDPACK_URL` à la place.

## Dockerfiles personnalisés {#custom-dockerfiles}

Si vous avez un Dockerfile à la racine de votre dépôt de projet, Auto DevOps crée une image Docker basée sur ce Dockerfile. Cette approche peut être plus rapide que l'utilisation d'un buildpack. Elle peut également générer des images plus légères, notamment si votre Dockerfile est basé sur [Alpine](https://hub.docker.com/_/alpine/).

Si vous définissez la variable CI/CD `DOCKERFILE_PATH`, Auto Build recherche un Dockerfile à cet emplacement à la place.

### Passer des arguments à `docker build` {#pass-arguments-to-docker-build}

Vous pouvez passer des arguments à `docker build` avec la variable CI/CD de projet `AUTO_DEVOPS_BUILD_IMAGE_EXTRA_ARGS`.

Par exemple, pour créer une image Docker basée sur `ruby:alpine` au lieu de la valeur par défaut `ruby:latest` :

1. Attribuez la valeur `--build-arg=RUBY_VERSION=alpine` à `AUTO_DEVOPS_BUILD_IMAGE_EXTRA_ARGS`.
1. Ajoutez les éléments suivants à un Dockerfile personnalisé :

   ```dockerfile
   ARG RUBY_VERSION=latest
   FROM ruby:$RUBY_VERSION

   # Include your content here
   ```

Pour passer des valeurs complexes telles que des espaces et des sauts de ligne, utilisez l'encodage Base64. Les valeurs complexes non encodées peuvent entraîner des problèmes lors de l'échappement des caractères.

> [!warning]
> Ne passez pas de secrets en tant qu'arguments de build Docker. Les secrets peuvent persister dans votre image. Pour plus d'informations, consultez [cette discussion sur les bonnes pratiques concernant les secrets](https://github.com/moby/moby/issues/13490).

## Image de conteneur personnalisée {#custom-container-image}

Par défaut, [Auto Deploy](stages.md#auto-deploy) déploie une image de conteneur créée et envoyée dans le registre GitLab par [Auto Build](stages.md#auto-build). Vous pouvez remplacer ce comportement en définissant des variables spécifiques :

| Entrée | Valeur par défaut | Peut être remplacé par |
| ----- | -----   | -----    |
| Chemin de l'image | `$CI_REGISTRY_IMAGE/$CI_COMMIT_REF_SLUG` pour les pipelines de branche. `$CI_REGISTRY_IMAGE` pour les pipelines de tag. | `$CI_APPLICATION_REPOSITORY` |
| Tag de l'image | `$CI_COMMIT_SHA` pour les pipelines de branche. `$CI_COMMIT_TAG` pour les pipelines de tag. | `$CI_APPLICATION_TAG` |

Ces variables affectent également Auto Build et l'analyse automatique des conteneurs. Si vous ne souhaitez pas créer et envoyer une image vers `$CI_APPLICATION_REPOSITORY:$CI_APPLICATION_TAG`, incluez uniquement `Jobs/Deploy.gitlab-ci.yml`, ou [ignorez les jobs `build`](cicd_variables.md#job-skipping-variables).

Si vous utilisez l'analyse automatique des conteneurs et définissez une valeur pour `$CI_APPLICATION_REPOSITORY`, vous devez également mettre à jour `$CS_DEFAULT_BRANCH_IMAGE`. Pour plus d'informations, consultez [Définir l'image de branche par défaut](../../user/application_security/container_scanning/_index.md#setting-the-default-branch-image).

Voici un exemple de configuration dans votre fichier `.gitlab-ci.yml` :

```yaml
variables:
  CI_APPLICATION_REPOSITORY: <your-image-repository>
  CI_APPLICATION_TAG: <the-tag>
```

## Étendre Auto DevOps avec l'API {#extend-auto-devops-with-the-api}

Vous pouvez étendre et gérer votre configuration Auto DevOps avec les API GitLab :

- [Utiliser des appels API pour accéder aux paramètres](../../api/settings.md#available-settings), notamment `auto_devops_enabled`, pour activer Auto DevOps sur les projets par défaut.
- [Créer un nouveau projet](../../api/projects.md#create-a-project).
- [Modifier des groupes](../../api/groups.md#update-group-attributes).
- [Modifier des projets](../../api/projects.md#update-a-project).

## Transmettre des variables CI/CD à l'environnement de build {#forward-cicd-variables-to-the-build-environment}

Pour transmettre des variables CI/CD à l'environnement de build, ajoutez les noms des variables que vous souhaitez transmettre à la variable CI/CD `AUTO_DEVOPS_BUILD_IMAGE_FORWARDED_CI_VARIABLES`. Séparez les variables multiples par des virgules.

Par exemple, pour transmettre les variables `CI_COMMIT_SHA` et `CI_ENVIRONMENT_NAME` :

```yaml
variables:
  AUTO_DEVOPS_BUILD_IMAGE_FORWARDED_CI_VARIABLES: CI_COMMIT_SHA,CI_ENVIRONMENT_NAME
```

Si vous utilisez des buildpacks, les variables transmises sont automatiquement disponibles en tant que variables d'environnement.

Si vous utilisez un Dockerfile :

1. Pour activer la syntaxe Dockerfile expérimentale, ajoutez les éléments suivants à votre Dockerfile :

   ```dockerfile
   # syntax = docker/dockerfile:experimental
   ```

1. Pour rendre les secrets disponibles dans tout `RUN $COMMAND` du `Dockerfile`, montez le fichier de secrets et sourcez-le avant d'exécuter `$COMMAND` :

   ```dockerfile
   RUN --mount=type=secret,id=auto-devops-build-secrets . /run/secrets/auto-devops-build-secrets && $COMMAND
   ```

Lorsque `AUTO_DEVOPS_BUILD_IMAGE_FORWARDED_CI_VARIABLES` est défini, Auto DevOps active la fonctionnalité expérimentale [Docker BuildKit](https://docs.docker.com/build/buildkit/) pour utiliser l'option `--secret`.

## Chart Helm personnalisé {#custom-helm-chart}

Auto DevOps utilise [Helm](https://helm.sh/) pour déployer votre application sur Kubernetes. Vous pouvez remplacer le chart Helm utilisé en intégrant un chart dans votre dépôt de projet ou en spécifiant une variable CI/CD de projet :

- **Chart intégré** \- Si votre projet contient un répertoire `./chart` avec un fichier `Chart.yaml`, Auto DevOps détecte le chart et l'utilise à la place du [chart par défaut](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app).
- **Variable de projet** \- Créez une [variable CI/CD de projet](../../ci/variables/_index.md) `AUTO_DEVOPS_CHART` avec l'URL d'un chart personnalisé. Vous pouvez également créer cinq variables de projet :

  - `AUTO_DEVOPS_CHART_REPOSITORY` - L'URL d'un dépôt de charts personnalisé.
  - `AUTO_DEVOPS_CHART` - Le chemin vers le chart.
  - `AUTO_DEVOPS_CHART_REPOSITORY_INSECURE` - Définissez cette variable sur une valeur non vide pour ajouter un argument `--insecure-skip-tls-verify` aux commandes Helm.
  - `AUTO_DEVOPS_CHART_CUSTOM_ONLY` - Définissez cette variable sur une valeur non vide pour n'utiliser qu'un chart personnalisé. Par défaut, le dernier chart est téléchargé depuis GitLab.
  - `AUTO_DEVOPS_CHART_VERSION` - La version du chart de déploiement.

### Personnaliser les valeurs du chart Helm {#customize-helm-chart-values}

Pour remplacer les valeurs par défaut dans le fichier `values.yaml` du [chart Helm par défaut](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app), procédez de l'une des façons suivantes :

- Ajoutez un fichier nommé `.gitlab/auto-deploy-values.yaml` à votre dépôt. Ce fichier est utilisé par défaut pour les mises à niveau Helm.
- Ajoutez un fichier avec un nom ou un chemin différent dans le dépôt. Définissez la [variable CI/CD](cicd_variables.md) `HELM_UPGRADE_VALUES_FILE` avec le chemin et le nom du fichier.

Certaines valeurs ne peuvent pas être remplacées avec les options précédentes, mais [ce ticket](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/issues/31) propose de modifier ce comportement. Pour remplacer des paramètres comme `replicaCount`, utilisez la variable CI/CD `REPLICAS` de [build et de déploiement](cicd_variables.md#build-and-deployment-variables).

### Personnaliser `helm upgrade` {#customize-helm-upgrade}

L'[auto-deploy-image](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image) utilise la commande `helm upgrade`. Pour personnaliser cette commande, passez-lui des options avec la variable CI/CD `HELM_UPGRADE_EXTRA_ARGS`.

Par exemple, pour désactiver les hooks pré- et post-mise à niveau lorsque `helm upgrade` s'exécute :

```yaml
variables:
  HELM_UPGRADE_EXTRA_ARGS: --no-hooks
```

Pour obtenir la liste complète des options, consultez [la documentation officielle de `helm upgrade`](https://helm.sh/docs/helm/helm_upgrade/).

### Limiter un chart Helm à un environnement {#limit-a-helm-chart-to-one-environment}

Pour limiter un chart personnalisé à un environnement, ajoutez la portée d'environnement à vos variables CI/CD. Pour plus d'informations, consultez [Limiter la portée d'environnement des variables CI/CD](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable).

## Personnaliser `.gitlab-ci.yml` {#customize-gitlab-ciyml}

Auto DevOps est hautement personnalisable car le [modèle Auto DevOps](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Auto-DevOps.gitlab-ci.yml) est une implémentation d'un fichier `.gitlab-ci.yml`. Le modèle n'utilise que les fonctionnalités disponibles pour toute implémentation de `.gitlab-ci.yml`.

Pour ajouter des comportements personnalisés au pipeline CI/CD utilisé par Auto DevOps :

1. À la racine de votre dépôt, ajoutez un fichier `.gitlab-ci.yml` avec le contenu suivant :

   ```yaml
   include:
     - template: Auto-DevOps.gitlab-ci.yml
   ```

1. Ajoutez vos modifications au fichier `.gitlab-ci.yml`. Vos modifications sont fusionnées avec le modèle Auto DevOps. Pour plus d'informations sur la façon dont `include` fusionne vos modifications, consultez [la documentation de `include`](../../ci/yaml/_index.md#include).

Pour supprimer des comportements du pipeline Auto DevOps :

1. Copiez le [modèle Auto DevOps](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Auto-DevOps.gitlab-ci.yml) dans votre projet.
1. Modifiez votre copie du modèle selon vos besoins.

### Utiliser des composants individuels d'Auto DevOps {#use-individual-components-of-auto-devops}

Si vous n'avez besoin que d'un sous-ensemble des fonctionnalités offertes par Auto DevOps, vous pouvez inclure des jobs Auto DevOps individuels dans votre propre fichier `.gitlab-ci.yml`. Veillez également à définir l'étape requise par chaque job dans votre fichier `.gitlab-ci.yml`.

Par exemple, pour utiliser [Auto Build](stages.md#auto-build), vous pouvez ajouter les éléments suivants à votre `.gitlab-ci.yml` :

```yaml
stages:
  - build

include:
  - template: Jobs/Build.gitlab-ci.yml
```

Pour obtenir la liste des jobs disponibles, consultez le [modèle Auto DevOps](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Auto-DevOps.gitlab-ci.yml).

## Utiliser plusieurs clusters Kubernetes {#use-multiple-kubernetes-clusters}

Consultez [Plusieurs clusters Kubernetes pour Auto DevOps](multiple_clusters_auto_devops.md).

## Personnalisation de l'espace de nommage Kubernetes {#customizing-the-kubernetes-namespace}

Vous pouviez auparavant utiliser `environment:kubernetes:namespace` pour spécifier un espace de nommage pour l'environnement. Toutefois, cette fonctionnalité a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8), ainsi que l'intégration basée sur les certificats.

Vous devez désormais utiliser la variable d'environnement `KUBE_NAMESPACE` et [limiter sa portée d'environnement](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable).

## Utiliser des images hébergées dans un registre Docker local {#use-images-hosted-in-a-local-docker-registry}

Vous pouvez configurer de nombreux jobs Auto DevOps pour s'exécuter dans un [environnement hors ligne](../../user/application_security/offline_deployments/_index.md) :

1. Copiez les images Docker Auto DevOps requises depuis Docker Hub et `registry.gitlab.com` vers leur registre de conteneurs GitLab local.
1. Une fois les images hébergées et disponibles dans un registre local, modifiez `.gitlab-ci.yml` pour pointer vers les images hébergées localement. Par exemple :

   ```yaml
   include:
     - template: Auto-DevOps.gitlab-ci.yml

   variables:
     REGISTRY_URL: "registry.gitlab.example"

   build:
     image: "$REGISTRY_URL/docker/auto-build-image:v0.6.0"
     services:
       - name: "$REGISTRY_URL/greg/docker/docker:20.10.16-dind"
         command: ['--tls=false', '--host=tcp://0.0.0.0:2375']
   ```

## Prise en charge de la base de données PostgreSQL {#postgresql-database-support}

> [!warning]
> La mise à disposition d'une base de données PostgreSQL par défaut a été [dépréciée](https://gitlab.com/gitlab-org/gitlab/-/issues/387766) et n'est plus le comportement par défaut. Pour activer la mise à disposition de la base de données, définissez la [variable CI/CD](cicd_variables.md#database-variables) associée.

Pour prendre en charge les applications nécessitant une base de données, [PostgreSQL](https://www.postgresql.org/) est mis à disposition par défaut. Les identifiants d'accès à la base de données sont préconfigurés.

Pour personnaliser les identifiants, définissez les [variables CI/CD](cicd_variables.md) associées. Vous pouvez également définir une `DATABASE_URL` personnalisée :

```yaml
postgres://user:password@postgres-host:postgres-port/postgres-database
```

### Mise à niveau de PostgreSQL {#upgrading-postgresql}

GitLab utilise la version 8.2.1 du chart pour mettre à disposition PostgreSQL par défaut. Vous pouvez définir la version de 0.7.1 à 8.2.1.

Si vous utilisez une version plus ancienne du chart, vous devez [migrer votre base de données](upgrading_postgresql.md) vers la version plus récente de PostgreSQL.

La variable CI/CD `AUTO_DEVOPS_POSTGRES_CHANNEL` qui contrôle la mise à disposition par défaut de PostgreSQL est définie sur `2`. Pour utiliser l'ancienne version de PostgreSQL, définissez la variable `AUTO_DEVOPS_POSTGRES_CHANNEL` sur `1`.

### Personnaliser les valeurs du chart Helm PostgreSQL {#customize-values-for-postgresql-helm-chart}

Pour définir des valeurs personnalisées, effectuez l'une des opérations suivantes :

- Ajoutez un fichier nommé `.gitlab/auto-deploy-postgres-values.yaml` à votre dépôt. Si ce fichier est trouvé, il est utilisé automatiquement. Ce fichier est utilisé par défaut pour les mises à niveau Helm de PostgreSQL.
- Ajoutez un fichier avec un nom ou un chemin différent dans le dépôt, et définissez la [variable d'environnement](cicd_variables.md#database-variables) `POSTGRES_HELM_UPGRADE_VALUES_FILE` avec le chemin et le nom.
- Définissez la [variable d'environnement](cicd_variables.md#database-variables) `POSTGRES_HELM_UPGRADE_EXTRA_ARGS`.

### Utiliser des fournisseurs de bases de données PostgreSQL externes {#use-external-postgresql-database-providers}

Auto DevOps fournit une prise en charge prête à l'emploi d'un conteneur PostgreSQL pour les environnements de production. Cependant, vous pouvez souhaiter utiliser un fournisseur géré externe tel qu'AWS Relational Database Service.

Pour utiliser un fournisseur géré externe :

1. Désactivez l'installation PostgreSQL intégrée pour les environnements requis avec des [variables CI/CD](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable) dont la portée est limitée à l'environnement. Étant donné que la configuration PostgreSQL intégrée pour les environnements éphémères et le staging est suffisante, il peut être nécessaire de désactiver l'installation uniquement pour `production`.

   ![Auto Metrics](img/disable_postgres_v12_4.png)
1. Définissez la variable `DATABASE_URL` comme variable dont la portée est limitée à l'environnement et disponible pour votre application. L'URL doit respecter le format suivant :

   ```yaml
   postgres://user:password@postgres-host:postgres-port/postgres-database
   ```

1. Assurez-vous que votre cluster Kubernetes dispose d'un accès réseau à l'emplacement où PostgreSQL est hébergé.
