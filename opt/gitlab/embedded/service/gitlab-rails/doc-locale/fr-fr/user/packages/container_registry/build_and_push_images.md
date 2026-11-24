---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Créer et envoyer des images de conteneurs vers le registre de conteneurs
description: "Créez des images de conteneurs et envoyez-les vers votre registre GitLab à l'aide de commandes Docker ou de pipelines CI/CD."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Avant de pouvoir créer et envoyer des images de conteneurs, vous devez [vous authentifier](authenticate_with_container_registry.md) auprès du registre de conteneurs.

## Utiliser les commandes Docker {#use-docker-commands}

Vous pouvez utiliser les commandes Docker pour créer et envoyer des images de conteneurs vers votre registre de conteneurs :

1. [Authentifiez-vous](authenticate_with_container_registry.md) auprès du registre de conteneurs.
1. Exécutez la commande Docker pour créer ou envoyer l'image. Par exemple :

   - Pour créer :

     ```shell
     docker build -t registry.example.com/group/project/image .
     ```

   - Pour envoyer :

     ```shell
     docker push registry.example.com/group/project/image
     ```

## Utiliser GitLab CI/CD {#use-gitlab-cicd}

Utilisez [GitLab CI/CD](../../../ci/_index.md) pour créer, envoyer, tester et déployer des images de conteneurs depuis le registre de conteneurs.

### Configurer votre fichier `.gitlab-ci.yml` {#configure-your-gitlab-ciyml-file}

Vous pouvez configurer votre fichier `.gitlab-ci.yml` pour créer et envoyer des images de conteneurs vers le registre de conteneurs.

- Si plusieurs jobs nécessitent une authentification, placez la commande d'authentification dans `before_script`.
- Avant de créer, utilisez `docker build --pull` pour récupérer les modifications apportées aux images de base. Cela prend légèrement plus de temps, mais cela garantit que votre image est à jour.
- Avant chaque `docker run`, effectuez un `docker pull` explicite pour récupérer l'image qui vient d'être créée. Cette étape est particulièrement importante si vous utilisez plusieurs runners qui mettent en cache les images localement.

  Si vous utilisez le SHA Git dans votre tag d'image, chaque job est unique et vous ne devriez jamais avoir d'image obsolète. Cependant, il est toujours possible d'avoir une image obsolète si vous recréez un commit donné après qu'une dépendance a changé.
- Ne créez pas directement vers le tag `latest`, car plusieurs jobs peuvent se dérouler simultanément.

### Utiliser une image de conteneur Docker-in-Docker {#use-a-docker-in-docker-container-image}

Vous pouvez utiliser vos propres images de conteneurs Docker-in-Docker (DinD) avec le registre de conteneurs ou le proxy de dépendances.

Utilisez DinD pour créer, tester et déployer des applications conteneurisées depuis votre pipeline CI/CD.

Prérequis :

- Configurez [Docker-in-Docker](../../../ci/docker/using_docker_build.md#use-docker-in-docker).

{{< tabs >}}

{{< tab title="Depuis le registre de conteneurs" >}}

Utilisez cette approche lorsque vous souhaitez utiliser des images stockées dans votre registre de conteneurs GitLab.

Dans votre fichier `.gitlab-ci.yml` :

- Mettez à jour `image` et `services` pour pointer vers votre registre.
- Ajoutez un [alias](../../../ci/services/_index.md#available-settings-for-services) de service.

Votre `.gitlab-ci.yml` devrait ressembler à ceci :

```yaml
build:
  image: $CI_REGISTRY/group/project/docker:24.0.5-cli
  services:
    - name: $CI_REGISTRY/group/project/docker:24.0.5-dind
      alias: docker
  stage: build
  script:
    - docker build -t my-docker-image .
    - docker run my-docker-image /script/to/run/tests
```

{{< /tab >}}

{{< tab title="Avec le proxy de dépendances" >}}

Utilisez cette approche pour mettre en cache des images provenant de registres externes comme Docker Hub afin d'accélérer les builds et d'éviter les limites de débit.

Dans votre fichier `.gitlab-ci.yml` :

- Mettez à jour `image` et `services` pour utiliser le préfixe du proxy de dépendances.
- Ajoutez un [alias](../../../ci/services/_index.md#available-settings-for-services) de service.

Votre `.gitlab-ci.yml` devrait ressembler à ceci :

```yaml
build:
  image: ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/docker:24.0.5-cli
  services:
    - name: ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/docker:24.0.5-dind
      alias: docker
  stage: build
  script:
    - docker build -t my-docker-image .
    - docker run my-docker-image /script/to/run/tests
```

{{< /tab >}}

{{< /tabs >}}

Si vous oubliez de définir l'alias de service, l'image de conteneur ne peut pas trouver le service `dind`, et une erreur semblable à celle-ci s'affiche :

```plaintext
error during connect: Get http://docker:2376/v1.39/info: dial tcp: lookup docker on 192.168.0.1:53: no such host
```

## Exemples de registre de conteneurs avec GitLab CI/CD {#container-registry-examples-with-gitlab-cicd}

Si vous utilisez DinD sur vos runners, votre fichier `.gitlab-ci.yml` devrait ressembler à ceci :

```yaml
build:
  image: docker:24.0.5-cli
  stage: build
  services:
    - docker:24.0.5-dind
  script:
    - echo "$CI_REGISTRY_PASSWORD" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin
    - docker build -t $CI_REGISTRY/group/project/image:latest .
    - docker push $CI_REGISTRY/group/project/image:latest
```

Vous pouvez utiliser des [variables CI/CD](../../../ci/variables/_index.md) dans votre fichier `.gitlab-ci.yml`. Par exemple :

```yaml
build:
  image: docker:24.0.5-cli
  stage: build
  services:
    - docker:24.0.5-dind
  variables:
    IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
  script:
    - echo "$CI_REGISTRY_PASSWORD" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin
    - docker build -t $IMAGE_TAG .
    - docker push $IMAGE_TAG
```

Dans l'exemple précédent :

- `$CI_REGISTRY_IMAGE` correspond à l'adresse du registre associé à ce projet.
- `$IMAGE_TAG` est une variable CI/CD personnalisée qui combine l'adresse du registre avec `$CI_COMMIT_REF_SLUG`, le tag de l'image. [La variable prédéfinie `$CI_COMMIT_REF_NAME`](../../../ci/variables/predefined_variables.md#predefined-variables) correspond au nom de la branche ou du tag et peut contenir des barres obliques. Les tags d'image ne peuvent pas contenir de barres obliques. Utilisez plutôt `$CI_COMMIT_REF_SLUG`.

L'exemple suivant divise les tâches CI/CD en quatre étapes de pipeline, dont deux tests exécutés en parallèle.

Le `build` est stocké dans le registre de conteneurs et utilisé par les étapes suivantes qui téléchargent l'image de conteneur selon les besoins. Lorsque vous envoyez des modifications vers la branche `main`, le pipeline tague l'image comme `latest` et la déploie à l'aide d'un script de déploiement spécifique à l'application :

```yaml
default:
  image: docker:24.0.5-cli
  services:
    - docker:24.0.5-dind
  before_script:
    - echo "$CI_REGISTRY_PASSWORD" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin

stages:
  - build
  - test
  - release
  - deploy

variables:
  # Use TLS https://docs.gitlab.com/ci/docker/using_docker_build/#use-docker-in-docker
  DOCKER_HOST: tcp://docker:2376
  DOCKER_TLS_CERTDIR: "/certs"
  CONTAINER_TEST_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
  CONTAINER_RELEASE_IMAGE: $CI_REGISTRY_IMAGE:latest

build:
  stage: build
  script:
    - docker build --pull -t $CONTAINER_TEST_IMAGE .
    - docker push $CONTAINER_TEST_IMAGE

test1:
  stage: test
  script:
    - docker pull $CONTAINER_TEST_IMAGE
    - docker run $CONTAINER_TEST_IMAGE /script/to/run/tests

test2:
  stage: test
  script:
    - docker pull $CONTAINER_TEST_IMAGE
    - docker run $CONTAINER_TEST_IMAGE /script/to/run/another/test

release-image:
  stage: release
  script:
    - docker pull $CONTAINER_TEST_IMAGE
    - docker tag $CONTAINER_TEST_IMAGE $CONTAINER_RELEASE_IMAGE
    - docker push $CONTAINER_RELEASE_IMAGE
  rules:
    - if: $CI_COMMIT_BRANCH == "main"

deploy:
  stage: deploy
  script:
    - ./deploy.sh
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  environment: production
```

> [!note]
> L'exemple précédent appelle explicitement `docker pull`. Si vous préférez extraire implicitement l'image de conteneur à l'aide de `image:`, et utiliser l'exécuteur [Docker](https://docs.gitlab.com/runner/executors/docker/) ou [Kubernetes](https://docs.gitlab.com/runner/executors/kubernetes/), assurez-vous que [`pull_policy`](https://docs.gitlab.com/runner/executors/docker/#set-the-always-pull-policy) est défini sur `always`.
