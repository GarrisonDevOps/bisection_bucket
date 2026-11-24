---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 'Tutoriel : annoter des images de conteneurs avec des données de provenance de build'
description: Utilisez Cosign pour annoter et signer des images de conteneurs avec des données de provenance de build dans les pipelines CI/CD GitLab.
---

Les annotations fournissent des métadonnées précieuses sur le processus de build. Ces informations sont utilisées à des fins d'audit et de traçabilité. En cas d'incident de sécurité, la disponibilité de données de provenance détaillées peut accélérer considérablement le processus d'investigation et de remédiation.

Ce tutoriel explique comment configurer un pipeline GitLab pour automatiser le processus de build, de signature et d'annotation des images de conteneurs à l'aide de Cosign. Vous pouvez configurer votre fichier `.gitlab-ci.yml` pour builder, pousser et signer une image Docker, puis la pousser vers le registre de conteneurs GitLab.

Pour annoter des images de conteneurs :

1. [Définir une image et une image de service](#set-image-and-service-image).
1. [Définir les variables CI/CD](#define-cicd-variables).
1. [Préparer le jeton OIDC](#prepare-oidc-token).
1. [Préparer le conteneur](#prepare-the-container).
1. [Builder et pousser l'image](#build-and-push-the-image).
1. [Signer l'image avec Cosign](#sign-the-image-with-cosign).
1. [Vérifier la signature et les annotations](#verify-the-signature-and-annotations).

Une fois toutes les étapes combinées, votre `.gitlab-ci.yml` devrait ressembler à la [configuration d'exemple](#example-gitlab-ciyml-configuration) fournie à la fin de ce tutoriel.

## Avant de commencer {#before-you-begin}

Vous devez disposer de :

- Cosign v2.0 ou version ultérieure installé.
- Pour GitLab Self-Managed, le registre de conteneurs GitLab [configuré avec une base de données de métadonnées](../../../administration/packages/container_registry_metadata_database.md) pour afficher les signatures.

## Définir une image et une image de service {#set-image-and-service-image}

Dans le fichier `.gitlab-ci.yml`, utilisez l'image `docker:cli` et activez le service Docker-in-Docker pour autoriser l'exécution des commandes Docker dans le job CI/CD.

```yaml
build_and_sign:
  stage: build
  image: docker:cli
  services:
    - docker:dind  # Enable Docker-in-Docker service to allow Docker commands inside the container
```

## Définir les variables CI/CD {#define-cicd-variables}

Définissez des variables pour le tag et l'URI de l'image à l'aide des variables prédéfinies CI/CD de GitLab.

```yaml
variables:
  IMAGE_TAG: $CI_COMMIT_SHORT_SHA  # Use the commit short SHA as the image tag
  IMAGE_URI: $CI_REGISTRY_IMAGE:$IMAGE_TAG  # Construct the full image URI with the registry, project path, and tag
  COSIGN_YES: "true"  # Automatically confirm actions in Cosign without user interaction
  FF_SCRIPT_SECTIONS: "true"  # Enables GitLab's CI script sections for better multi-line script output
```

## Préparer le jeton OIDC {#prepare-oidc-token}

Configurez un jeton OIDC pour la signature sans clé avec Cosign.

```yaml
id_tokens:
  SIGSTORE_ID_TOKEN:
    aud: sigstore  # Provide an OIDC token for keyless signing with Cosign
```

## Préparer le conteneur {#prepare-the-container}

Dans la section `before_script` du fichier `.gitlab-ci.yml` :

- Installez Cosign et jq (pour le traitement JSON) : `apk add --no-cache cosign jq`
- Activez la connexion au registre de conteneurs GitLab à l'aide d'un jeton de job CI/CD : `docker login -u "gitlab-ci-token" -p "$CI_JOB_TOKEN" "$CI_REGISTRY"`

Le pipeline commence par la configuration de l'environnement nécessaire.

## Builder et pousser l'image {#build-and-push-the-image}

Dans la section `script` du fichier `.gitlab-ci.yml`, saisissez les commandes suivantes pour builder l'image Docker et la pousser vers le registre de conteneurs GitLab.

```yaml
- docker build --pull -t "$IMAGE_URI" .
- docker push "$IMAGE_URI"
```

Cette commande crée l'image à l'aide du Dockerfile du répertoire courant et la pousse vers le registre.

## Signer l'image avec Cosign {#sign-the-image-with-cosign}

Après avoir buildé et poussé l'image vers le registre de conteneurs GitLab, utilisez Cosign pour la signer.

Dans la section `script` du fichier `.gitlab-ci.yml`, saisissez les commandes suivantes :

```yaml
- IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE_URI")
- |
  cosign sign "$IMAGE_DIGEST" \
    --registry-referrers-mode oci-1-1 \
    --annotations "com.gitlab.ci.user.name=$GITLAB_USER_NAME" \
    --annotations "com.gitlab.ci.pipeline.id=$CI_PIPELINE_ID" \
    # Additional annotations removed for readability
    --annotations "tag=$IMAGE_TAG"
```

Cette étape récupère le condensé (digest) de l'image. Elle utilise ensuite Cosign pour signer l'image et ajouter plusieurs annotations.

## Vérifier la signature et les annotations {#verify-the-signature-and-annotations}

Après avoir signé l'image, il est essentiel de vérifier la signature et les annotations ajoutées.

Dans le fichier `.gitlab-ci.yml`, incluez une étape de vérification à l'aide de la commande `cosign verify` :

```yaml
- |
  cosign verify \
    --annotations "tag=$IMAGE_TAG" \
    --certificate-identity "$CI_PROJECT_URL//.gitlab-ci.yml@refs/heads/$CI_COMMIT_REF_NAME" \
    --certificate-oidc-issuer "$CI_SERVER_URL" \
    "$IMAGE_URI" | jq .
```

L'étape de vérification garantit que les données de provenance associées à l'image sont correctes et n'ont pas été altérées. La commande `cosign verify` vérifie la signature et contrôle les annotations. La sortie affiche toutes les annotations que vous avez ajoutées à l'image lors du processus de signature.

Dans la sortie, vous pouvez voir toutes les annotations ajoutées précédemment, notamment :

- Nom d'utilisateur GitLab
- ID et URL du pipeline
- ID et URL du job
- SHA du commit et nom de la référence
- Chemin du projet
- Source et révision de l'image

En vérifiant ces annotations, vous pouvez vous assurer que les données de provenance de l'image sont intactes et correspondent à ce que vous attendez en fonction de votre processus de build.

## Exemple de configuration `.gitlab-ci.yml` {#example-gitlab-ciyml-configuration}

Lorsque vous suivez toutes les étapes précédentes, le fichier `.gitlab-ci.yml` devrait ressembler à ceci :

```yaml
stages:
  - build

build_and_sign:
  stage: build
  image: docker:cli
  services:
    - docker:dind  # Enable Docker-in-Docker service to allow Docker commands inside the container
  variables:
    IMAGE_TAG: $CI_COMMIT_SHORT_SHA  # Use the commit short SHA as the image tag
    IMAGE_URI: $CI_REGISTRY_IMAGE:$IMAGE_TAG  # Construct the full image URI with the registry, project path, and tag
    COSIGN_YES: "true"  # Automatically confirm actions in Cosign without user interaction
    FF_SCRIPT_SECTIONS: "true"  # Enables GitLab's CI script sections for better multi-line script output
  id_tokens:
    SIGSTORE_ID_TOKEN:
      aud: sigstore  # Provide an OIDC token for keyless signing with Cosign
  before_script:
    - apk add --no-cache cosign jq  # Install Cosign (mandatory) and jq (optional)
    - docker login -u "gitlab-ci-token" -p "$CI_JOB_TOKEN" "$CI_REGISTRY"  # Log in to the Docker registry using GitLab CI token
  script:
    # Build the Docker image using the specified tag and push it to the registry
    - docker build --pull -t "$IMAGE_URI" .
    - docker push "$IMAGE_URI"

    # Retrieve the digest of the pushed image to use in the signing step
    - IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE_URI")

    # Sign the image using Cosign with annotations that provide metadata about the build and tag annotation to allow verifying
    # the tag->digest mapping (https://github.com/sigstore/cosign?tab=readme-ov-file#tag-signing)
    - |
      cosign sign "$IMAGE_DIGEST" \
        --registry-referrers-mode oci-1-1 \
        --annotations "com.gitlab.ci.user.name=$GITLAB_USER_NAME" \
        --annotations "com.gitlab.ci.pipeline.id=$CI_PIPELINE_ID" \
        --annotations "com.gitlab.ci.pipeline.url=$CI_PIPELINE_URL" \
        --annotations "com.gitlab.ci.job.id=$CI_JOB_ID" \
        --annotations "com.gitlab.ci.job.url=$CI_JOB_URL" \
        --annotations "com.gitlab.ci.commit.sha=$CI_COMMIT_SHA" \
        --annotations "com.gitlab.ci.commit.ref.name=$CI_COMMIT_REF_NAME" \
        --annotations "com.gitlab.ci.project.path=$CI_PROJECT_PATH" \
        --annotations "org.opencontainers.image.source=$CI_PROJECT_URL" \
        --annotations "org.opencontainers.image.revision=$CI_COMMIT_SHA" \
        --annotations "tag=$IMAGE_TAG"

    # Verify the image signature using Cosign to ensure it matches the expected annotations and certificate identity
    - |
      cosign verify \
        --annotations "tag=$IMAGE_TAG" \
        --certificate-identity "$CI_PROJECT_URL//.gitlab-ci.yml@refs/heads/$CI_COMMIT_REF_NAME" \
        --certificate-oidc-issuer "$CI_SERVER_URL" \
        "$IMAGE_URI" | jq .  # Use jq to format the verification output for easier readability
```
