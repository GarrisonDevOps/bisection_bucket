---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Gestion des artefacts Google
description: "Connectez un registre d'artefacts Google à votre projet GitLab pour afficher, pousser et tirer des images Docker et OCI."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/141127) dans GitLab 16.10 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `google_cloud_support_feature_flag`. Cette fonctionnalité est en [version bêta](../../../policy/development_stages_support.md).
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/150472) dans GitLab 17.1. Le feature flag `google_cloud_support_feature_flag` a été supprimé.

{{< /history >}}

Vous pouvez utiliser l'intégration Gestion des artefacts Google pour configurer et connecter un dépôt [Google Artifact Registry](https://docs.cloud.google.com/artifact-registry/docs) à votre projet GitLab.

Une fois le registre Google Artifact Registry connecté à votre projet, vous pouvez afficher, pousser et tirer des images Docker et [OCI](https://opencontainers.org/) dans un dépôt [Google Artifact Registry](https://docs.cloud.google.com/artifact-registry/docs).

## Configurer le registre Google Artifact Registry dans un projet GitLab {#set-up-the-google-artifact-registry-in-a-gitlab-project}

Prérequis :

- Vous devez disposer du rôle Maintainer ou Owner pour le projet GitLab.
- Vous devez disposer des [autorisations nécessaires](https://cloud.google.com/iam/docs/granting-changing-revoking-access#required-permissions) pour gérer l'accès au projet Google Cloud avec le dépôt Artifact Registry.
- Un pool et un fournisseur de [fédération d'identités de charge de travail](../../../integration/google_cloud_iam.md) (WLIF) doivent être configurés pour s'authentifier auprès de Google Cloud.
- Un [dépôt Google Artifact Registry](https://docs.cloud.google.com/artifact-registry/docs/repositories) avec la configuration suivante :
  - Format [Docker](https://docs.cloud.google.com/artifact-registry/docs/supported-formats).
  - Mode [Standard](https://docs.cloud.google.com/artifact-registry/docs/repositories/create-repos). Les autres formats et modes de dépôt ne sont pas pris en charge.

Pour connecter un dépôt Google Artifact Registry à un projet GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Gestion des artefacts Google**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Remplissez les champs :
   - **ID de projet Google Cloud** : L'[ID de projet Google Cloud](https://cloud.google.com/resource-manager/docs/creating-managing-projects#identifying_projects) dans lequel se trouve le dépôt Artifact Registry.
   - **Nom du dépôt** : le nom du dépôt Artifact Registry.
   - **Emplacement du dépôt** : l'[emplacement Google Cloud](https://cloud.google.com/about/locations) du dépôt Artifact Registry.
1. Suivez les instructions à l'écran pour configurer les politiques Google Cloud Identity and Access Management (IAM). Pour en savoir plus sur les types de politiques, consultez [Politiques IAM](#iam-policies).
1. Sélectionnez **Enregistrer les modifications**.

Une entrée **Registre d'artefacts Google** devrait maintenant apparaître dans la barre latérale, sous **Déployer**.

## Afficher les images stockées dans le registre Google Artifact Registry {#view-images-stored-in-the-google-artifact-registry}

Prérequis :

- Le registre Google Artifact Registry doit être [configuré](#set-up-the-google-artifact-registry-in-a-gitlab-project) dans le projet.

Pour afficher la liste des images dans le dépôt Artifact Registry connecté dans l'interface GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Registre d'artefacts Google**.
1. Pour afficher les détails d'une image, sélectionnez une image.
1. Pour afficher l'image dans la console Google Cloud, sélectionnez **Ouvrir dans Google Cloud**. Vous devez disposer des [autorisations requises](https://cloud.google.com/artifact-registry/docs/repositories/list-repos#required_roles) pour afficher ce dépôt Artifact Registry.

## CI/CD {#cicd}

### Variables prédéfinies {#predefined-variables}

Une fois l'intégration Artifact Registry activée, les variables d'environnement prédéfinies suivantes sont disponibles dans CI/CD. Vous pouvez utiliser ces variables d'environnement pour interagir avec Artifact Registry, par exemple pour tirer ou pousser une image vers le dépôt connecté.

| Variable                                       | GitLab | Runner | Description |
|------------------------------------------------|--------|--------|-------------|
| `GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID`          | 16.10  | 16.10  | L'ID de projet Google Cloud dans lequel se trouve le dépôt Artifact Registry. |
| `GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME`     | 16.10  | 16.10  | Le nom du dépôt Artifact Registry connecté. |
| `GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION` | 16.10  | 16.10  | L'emplacement Google Cloud du dépôt Artifact Registry connecté. |

### S'authentifier auprès du registre Google Artifact Registry {#authenticate-with-the-google-artifact-registry}

Vous pouvez configurer un pipeline pour qu'il s'authentifie auprès du registre Google Artifact Registry lors de son exécution. GitLab utilise les politiques IAM du [pool d'identités de charge de travail](../../../integration/google_cloud_iam.md) configuré et renseigne les identifiants d'environnement `GOOGLE_APPLICATION_CREDENTIALS` et `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE`. Ces identifiants d'environnement sont automatiquement détectés par les outils clients, comme [gcloud CLI](https://docs.cloud.google.com/sdk/gcloud) et [crane](https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md).

Pour vous authentifier auprès du registre Google Artifact Registry, dans le fichier `.gitlab-ci.yml` du projet, utilisez le mot-clé [`identity`](../../../ci/yaml/_index.md#identity) avec la valeur `google_cloud`.

#### Politiques IAM {#iam-policies}

Votre projet Google Cloud doit disposer de politiques IAM spécifiques pour utiliser l'intégration Gestion des artefacts Google. Lorsque vous [configurez cette intégration](#set-up-the-google-artifact-registry-in-a-gitlab-project), les instructions à l'écran indiquent les étapes pour créer les politiques IAM suivantes dans votre projet Google Cloud :

- Accordez le rôle [Artifact Registry Reader](https://cloud.google.com/iam/docs/understanding-roles#artifactregistry.reader) aux membres du projet GitLab disposant du rôle [Invité](../../permissions.md#roles) ou supérieur.
- Accordez le rôle [Artifact Registry Writer](https://cloud.google.com/iam/docs/understanding-roles#artifactregistry.writer) aux membres du projet GitLab disposant du rôle [Developer](../../permissions.md#roles) ou supérieur.

Pour créer ces politiques IAM manuellement, utilisez les commandes `gcloud` suivantes. Remplacez ces valeurs :

- `<your_google_cloud_project_id>` par l'[ID](https://cloud.google.com/resource-manager/docs/creating-managing-projects#identifying_projects) du projet Google Cloud dans lequel se trouve le dépôt Artifact Registry.
- `<your_workload_identity_pool_id>` par l'ID du pool d'identités de charge de travail. Il s'agit de la même valeur que celle utilisée pour l'[intégration Google Cloud IAM](../../../integration/google_cloud_iam.md).
- `<your_google_cloud_project_number>` par le [numéro](https://cloud.google.com/resource-manager/docs/creating-managing-projects#identifying_projects) du projet Google Cloud dans lequel se trouve le pool d'identités de charge de travail. Il s'agit de la même valeur que celle utilisée pour l'[intégration Google Cloud IAM](../../../integration/google_cloud_iam.md).

```shell
gcloud projects add-iam-policy-binding '<your_google_cloud_project_id>' \
  --member='principalSet://iam.googleapis.com/projects/<your_google_cloud_project_number>/locations/global/workloadIdentityPools/<your_workload_identity_pool_id>/attribute.guest_access/true' \
  --role='roles/artifactregistry.reader'

gcloud projects add-iam-policy-binding '<your_google_cloud_project_id>' \
  --member='principalSet://iam.googleapis.com/projects/<your_google_cloud_project_number>/locations/global/workloadIdentityPools/<your_workload_identity_pool_id>/attribute.developer_access/true' \
  --role='roles/artifactregistry.writer'
```

Pour obtenir la liste des claims disponibles, consultez [Claims personnalisés OIDC](../../../integration/google_cloud_iam.md#oidc-custom-claims).

### Exemples {#examples}

#### Utiliser gcloud CLI pour lister les images {#use-gcloud-cli-to-list-images}

```yaml
list-images:
  image: gcr.io/google.com/cloudsdktool/google-cloud-cli:466.0.0-alpine
  identity: google_cloud
  script:
    - gcloud artifacts docker images list $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/app
```

#### Utiliser crane pour lister les images {#use-crane-to-list-images}

```yaml
list-images:
  image:
    name: gcr.io/go-containerregistry/crane:debug
    entrypoint: [""]
  identity: google_cloud
  before_script:
    # Temporary workaround for https://github.com/google/go-containerregistry/issues/1886
    - wget -q "https://github.com/GoogleCloudPlatform/docker-credential-gcr/releases/download/v2.1.22/docker-credential-gcr_linux_amd64-2.1.22.tar.gz" -O - | tar xz -C /tmp && chmod +x /tmp/docker-credential-gcr && mv /tmp/docker-credential-gcr /usr/bin/
    - docker-credential-gcr configure-docker --registries=$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev
  script:
    - crane ls $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/app
```

#### Tirer une image avec Docker {#pull-an-image-with-docker}

L'exemple suivant montre comment configurer l'authentification pour Docker avec le [programme d'assistance autonome aux identifiants Docker](https://cloud.google.com/artifact-registry/docs/docker/authentication#standalone-helper) fourni par Google.

```yaml
pull-image:
  image: docker:24.0.5-cli
  identity: google_cloud
  services:
    - docker:24.0.5-dind
  variables:
    # The following two variables ensure that the DinD service starts in TLS
    # mode and that the Docker CLI is properly configured to communicate with
    # the API. More details about the importance of this can be found at
    # https://docs.gitlab.com/ci/docker/using_docker_build/#use-the-docker-executor-with-docker-in-docker
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_CERTDIR: "/certs"
  before_script:
    - wget -q "https://github.com/GoogleCloudPlatform/docker-credential-gcr/releases/download/v2.1.22/docker-credential-gcr_linux_amd64-2.1.22.tar.gz" -O - | tar xz -C /tmp && chmod +x /tmp/docker-credential-gcr && mv /tmp/docker-credential-gcr /usr/bin/
    - docker-credential-gcr configure-docker --registries=$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev
  script:
    - docker pull $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/app:v0.1.0
```

#### Copier une image à l'aide d'un composant CI/CD {#copy-an-image-by-using-a-cicd-component}

Google fournit le composant CI/CD [`upload-artifact-registry`](https://gitlab.com/explore/catalog/google-gitlab-components/artifact-registry), que vous pouvez utiliser pour copier une image du registre de conteneurs GitLab vers Artifact Registry.

Pour utiliser le composant `upload-artifact-registry`, ajoutez ce qui suit à votre `.gitlab-ci.yml` :

```yaml
include:
  - component: gitlab.com/google-gitlab-components/artifact-registry/upload-artifact-registry@main
    inputs:
      stage: deploy
      source: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
      target: $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/$CI_PROJECT_NAME:$CI_COMMIT_SHORT_SHA
```

Pour plus de détails, consultez [la documentation du composant](https://gitlab.com/explore/catalog/google-gitlab-components/artifact-registry).

L'utilisation du composant `upload-artifact-registry` simplifie la copie d'images vers Artifact Registry et constitue la méthode recommandée pour cette intégration. Si vous souhaitez utiliser Docker ou Crane, consultez les exemples suivants.

#### Copier une image à l'aide de Docker {#copy-an-image-by-using-docker}

Dans l'exemple suivant, l'interface de ligne de commande `gcloud` est utilisée pour configurer l'authentification Docker, comme alternative au [programme d'assistance autonome aux identifiants Docker](https://cloud.google.com/artifact-registry/docs/docker/authentication#standalone-helper).

```yaml
copy-image:
  image: gcr.io/google.com/cloudsdktool/google-cloud-cli:466.0.0-alpine
  identity: google_cloud
  services:
    - docker:24.0.5-dind
  variables:
    SOURCE_IMAGE: $CI_REGISTRY_IMAGE:v0.1.0
    TARGET_IMAGE: $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/app:v0.1.0
    DOCKER_HOST: tcp://docker:2375
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - gcloud auth configure-docker $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev
  script:
    - docker pull $SOURCE_IMAGE
    - docker tag $SOURCE_IMAGE $TARGET_IMAGE
    - docker push $TARGET_IMAGE
```

#### Copier une image à l'aide de Crane {#copy-an-image-by-using-crane}

```yaml
copy-image:
  image:
    name: gcr.io/go-containerregistry/crane:debug
    entrypoint: [""]
  identity: google_cloud
  variables:
    SOURCE_IMAGE: $CI_REGISTRY_IMAGE:v0.1.0
    TARGET_IMAGE: $GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev/$GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID/$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME/app:v0.1.0
  before_script:
    # Temporary workaround for https://github.com/google/go-containerregistry/issues/1886
    - wget -q "https://github.com/GoogleCloudPlatform/docker-credential-gcr/releases/download/v2.1.22/docker-credential-gcr_linux_amd64-2.1.22.tar.gz" -O - | tar xz -C /tmp && chmod +x /tmp/docker-credential-gcr && mv /tmp/docker-credential-gcr /usr/bin/
    - docker-credential-gcr configure-docker --registries=$GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION-docker.pkg.dev
  script:
    - crane auth login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - crane copy $SOURCE_IMAGE $TARGET_IMAGE
```
