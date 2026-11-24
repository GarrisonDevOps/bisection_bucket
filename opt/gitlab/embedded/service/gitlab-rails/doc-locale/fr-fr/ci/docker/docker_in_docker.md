---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Utiliser Docker-in-Docker
description: "Configurez Docker-in-Docker pour les jobs GitLab CI/CD à l'aide de l'exécuteur Docker ou Kubernetes."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Docker-in-Docker (`dind`) signifie que votre runner enregistré utilise l'[exécuteur Docker](https://docs.gitlab.com/runner/executors/docker/) ou l'[exécuteur Kubernetes](https://docs.gitlab.com/runner/executors/kubernetes/). L'exécuteur utilise une [image de conteneur Docker](https://hub.docker.com/_/docker/), fournie par Docker, pour exécuter vos jobs CI/CD.

L'image Docker inclut tous les outils `docker` et peut exécuter le script du job dans le contexte de l'image en mode privilégié.

Épinglez toujours une version spécifique de l'image, comme `docker:24.0.5`. Si vous utilisez un tag tel que `docker:latest`, vous n'avez aucun contrôle sur la version utilisée. Cette action peut entraîner des problèmes d'incompatibilité lors de la publication de nouvelles versions.

## Utilisation avec l'exécuteur Docker {#use-with-docker-executor}

Vous pouvez utiliser l'exécuteur Docker pour exécuter des jobs dans un conteneur Docker.

### Docker-in-Docker avec TLS activé dans l'exécuteur Docker (recommandé) {#docker-in-docker-with-tls-enabled-in-the-docker-executor-recommended}

Le daemon Docker prend en charge les connexions via TLS. Utilisez TLS dans la mesure du possible. TLS est activé par défaut dans Docker 19.03.12 et versions ultérieures, et est pris en charge par les [runners d'instance GitLab.com](../runners/_index.md).

> [!warning]
> Cette tâche active `--docker-privileged`, ce qui désactive effectivement les mécanismes de sécurité du conteneur et expose votre hôte à une élévation de privilèges. Cette action peut provoquer une évasion de conteneur. Pour plus d'informations, consultez [les privilèges d'exécution et les capacités Linux](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities).

Pour utiliser Docker-in-Docker avec TLS activé :

1. Installez [GitLab Runner](https://docs.gitlab.com/runner/install/).
1. Enregistrez GitLab Runner depuis la ligne de commande. Utilisez le mode `docker` et `privileged` :

   ```shell
   sudo gitlab-runner register -n \
     --url "https://gitlab.com/" \
     --registration-token REGISTRATION_TOKEN \
     --executor docker \
     --description "My Docker Runner" \
     --tag-list "tls-docker-runner" \
     --docker-image "docker:24.0.5-cli" \
     --docker-privileged \
     --docker-volumes "/certs/client"
   ```

   - Cette commande enregistre un nouveau runner pour utiliser l'image `docker:24.0.5-cli` (si aucune n'est spécifiée au niveau du job). Pour démarrer les conteneurs de build et de service, elle utilise le mode `privileged`. Si vous souhaitez utiliser Docker-in-Docker, vous devez toujours utiliser `privileged = true` dans vos conteneurs Docker.
   - Cette commande monte `/certs/client` pour le conteneur de service et de build, ce qui est nécessaire pour que le client Docker utilise les certificats dans ce répertoire. Pour plus d'informations, consultez [la documentation de l'image Docker](https://hub.docker.com/_/docker/).

   La commande précédente crée une entrée `config.toml` similaire à l'exemple suivant :

   ```toml
   [[runners]]
     url = "https://gitlab.com/"
     token = TOKEN
     executor = "docker"
     [runners.docker]
       tls_verify = false
       image = "docker:24.0.5-cli"
       privileged = true
       disable_cache = false
       volumes = ["/certs/client", "/cache"]
     [runners.cache]
       [runners.cache.s3]
       [runners.cache.gcs]
   ```

1. Vous pouvez maintenant utiliser `docker` dans le script du job. Incluez le service `docker:24.0.5-dind` :

   ```yaml
   default:
     image: docker:24.0.5-cli
     services:
       - docker:24.0.5-dind
     before_script:
       - docker info

   variables:
     # When you use the dind service, you must instruct Docker to talk with
     # the daemon started inside of the service. The daemon is available
     # with a network connection instead of the default
     # /var/run/docker.sock socket. Docker 19.03 does this automatically
     # by setting the DOCKER_HOST in
     # https://github.com/docker-library/docker/blob/d45051476babc297257df490d22cbd806f1b11e4/19.03/docker-entrypoint.sh#L23-L29
     #
     # The 'docker' hostname is the alias of the service container as described at
     # https://docs.gitlab.com/ci/services/#accessing-the-services.
     #
     # Specify to Docker where to create the certificates. Docker
     # creates them automatically on boot, and creates
     # `/certs/client` to share between the service and job
     # container, thanks to volume mount from config.toml
     DOCKER_TLS_CERTDIR: "/certs"

   build:
     stage: build
     tags:
       - tls-docker-runner
     script:
       - docker build -t my-docker-image .
       - docker run my-docker-image /script/to/run/tests
   ```

### Docker-in-Docker avec TLS désactivé dans l'exécuteur Docker {#docker-in-docker-with-tls-disabled-in-the-docker-executor}

Il existe parfois des raisons légitimes de désactiver TLS. Par exemple, vous n'avez aucun contrôle sur la configuration de GitLab Runner que vous utilisez.

1. Enregistrez GitLab Runner depuis la ligne de commande. Utilisez le mode `docker` et `privileged` :

   ```shell
   sudo gitlab-runner register -n \
     --url "https://gitlab.com/" \
     --registration-token REGISTRATION_TOKEN \
     --executor docker \
     --description "My Docker Runner" \
     --tag-list "no-tls-docker-runner" \
     --docker-image "docker:24.0.5-cli" \
     --docker-privileged
   ```

   La commande précédente crée une entrée `config.toml` similaire à l'exemple suivant :

   ```toml
   [[runners]]
     url = "https://gitlab.com/"
     token = TOKEN
     executor = "docker"
     [runners.docker]
       tls_verify = false
       image = "docker:24.0.5-cli"
       privileged = true
       disable_cache = false
       volumes = ["/cache"]
     [runners.cache]
       [runners.cache.s3]
       [runners.cache.gcs]
   ```

1. Incluez le service `docker:24.0.5-dind` dans le script du job :

   ```yaml
   default:
     image: docker:24.0.5-cli
     services:
       - docker:24.0.5-dind
     before_script:
       - docker info

   variables:
     # When using dind service, you must instruct docker to talk with the
     # daemon started inside of the service. The daemon is available with
     # a network connection instead of the default /var/run/docker.sock socket.
     #
     # The 'docker' hostname is the alias of the service container as described at
     # https://docs.gitlab.com/ci/services/#accessing-the-services
     #
     DOCKER_HOST: tcp://docker:2375
     #
     # This instructs Docker not to start over TLS.
     DOCKER_TLS_CERTDIR: ""

   build:
     stage: build
     tags:
       - no-tls-docker-runner
     script:
       - docker build -t my-docker-image .
       - docker run my-docker-image /script/to/run/tests
   ```

### Utiliser un socket Unix sur un volume partagé entre Docker-in-Docker et le conteneur de build {#use-a-unix-socket-on-a-shared-volume-between-docker-in-docker-and-build-container}

Les répertoires définis dans `volumes = ["/certs/client", "/cache"]` dans l'approche [Docker-in-Docker avec TLS activé dans l'exécuteur Docker](#docker-in-docker-with-tls-enabled-in-the-docker-executor-recommended) sont [persistants entre les builds](https://docs.gitlab.com/runner/executors/docker/#persistent-storage). Si plusieurs jobs CI/CD utilisant un runner avec l'exécuteur Docker ont des services Docker-in-Docker activés, chaque job écrit dans le chemin du répertoire. Cette approche peut entraîner un conflit.

Pour résoudre ce conflit, utilisez un socket Unix sur un volume partagé entre le service Docker-in-Docker et le conteneur de build. Cette approche améliore les performances et établit une connexion sécurisée entre le service et le client.

Voici un exemple de fichier `config.toml` avec un volume temporaire partagé entre les conteneurs de build et de service :

```toml
[[runners]]
  url = "https://gitlab.com/"
  token = TOKEN
  executor = "docker"
  [runners.docker]
    image = "docker:24.0.5-cli"
    privileged = true
    volumes = ["/runner/services/docker"] # Temporary volume shared between build and service containers.
```

Le service Docker-in-Docker crée un `docker.sock`. Le client Docker se connecte à `docker.sock` via un volume de socket Unix Docker.

```yaml
job:
  variables:
    # This variable is shared by both the DinD service and Docker client.
    # For the service, it will instruct DinD to create `docker.sock` here.
    # For the client, it tells the Docker client which Docker Unix socket to connect to.
    DOCKER_HOST: "unix:///runner/services/docker/docker.sock"
  services:
    - docker:24.0.5-dind
  image: docker:24.0.5-cli
  script:
    - docker version
```

### Docker-in-Docker avec proxy activé dans l'exécuteur Docker {#docker-in-docker-with-proxy-enabled-in-the-docker-executor}

Vous devrez peut-être configurer les paramètres de proxy pour utiliser la commande `docker push`.

Pour plus d'informations, consultez [Paramètres de proxy lors de l'utilisation du service `dind`](https://docs.gitlab.com/runner/configuration/proxy/#proxy-settings-when-using-dind-service).

## Utilisation avec l'exécuteur Kubernetes {#use-with-kubernetes-executor}

Vous pouvez utiliser l'[exécuteur Kubernetes](https://docs.gitlab.com/runner/executors/kubernetes/) pour exécuter des jobs dans un conteneur Docker.

### Docker-in-Docker avec TLS activé dans Kubernetes (recommandé) {#docker-in-docker-with-tls-enabled-in-kubernetes-recommended}

Pour utiliser Docker-in-Docker avec TLS activé dans Kubernetes :

1. À l'aide du [chart Helm](https://docs.gitlab.com/runner/install/kubernetes/), mettez à jour le [fichier `values.yml`](https://gitlab.com/gitlab-org/charts/gitlab-runner/-/blob/00c1a2098f303dffb910714752e9a981e119f5b5/values.yaml#L133-137) pour spécifier un montage de volume.

   ```yaml
   runners:
     tags: "tls-dind-kubernetes-runner"
     config: |
       [[runners]]
         [runners.kubernetes]
           image = "ubuntu:20.04"
           privileged = true
         [[runners.kubernetes.volumes.empty_dir]]
           name = "docker-certs"
           mount_path = "/certs/client"
           medium = "Memory"
   ```

1. Incluez le service `docker:24.0.5-dind` dans le job :

   ```yaml
   default:
     image: docker:24.0.5-cli
     services:
       - name: docker:24.0.5-dind
         variables:
           HEALTHCHECK_TCP_PORT: "2376"
     before_script:
       - docker info

   variables:
     # When using dind service, you must instruct Docker to talk with
     # the daemon started inside of the service. The daemon is available
     # with a network connection instead of the default
     # /var/run/docker.sock socket.
     DOCKER_HOST: tcp://docker:2376
     #
     # The 'docker' hostname is the alias of the service container as described at
     # https://docs.gitlab.com/ci/services/#accessing-the-services.
     #
     # Specify to Docker where to create the certificates. Docker
     # creates them automatically on boot, and creates
     # `/certs/client` to share between the service and job
     # container, thanks to volume mount from config.toml
     DOCKER_TLS_CERTDIR: "/certs"
     # These are usually specified by the entrypoint, however the
     # Kubernetes executor doesn't run entrypoints
     # https://gitlab.com/gitlab-org/gitlab-runner/-/issues/4125
     DOCKER_TLS_VERIFY: 1
     DOCKER_CERT_PATH: "$DOCKER_TLS_CERTDIR/client"

   build:
     stage: build
     tags:
       - tls-dind-kubernetes-runner
     script:
       - docker build -t my-docker-image .
       - docker run my-docker-image /script/to/run/tests
   ```

### Docker-in-Docker avec TLS désactivé dans Kubernetes {#docker-in-docker-with-tls-disabled-in-kubernetes}

Pour utiliser Docker-in-Docker avec TLS désactivé dans Kubernetes, vous devez adapter l'exemple précédent de la manière suivante :

- Supprimez la section `[[runners.kubernetes.volumes.empty_dir]]` du fichier `values.yml`.
- Changez le port de `2376` en `2375` avec `DOCKER_HOST: tcp://docker:2375`.
- Indiquez à Docker de démarrer avec TLS désactivé en utilisant `DOCKER_TLS_CERTDIR: ""`.

Par exemple :

1. À l'aide du [chart Helm](https://docs.gitlab.com/runner/install/kubernetes/), mettez à jour le [fichier `values.yml`](https://gitlab.com/gitlab-org/charts/gitlab-runner/-/blob/00c1a2098f303dffb910714752e9a981e119f5b5/values.yaml#L133-137) :

   ```yaml
   runners:
     tags: "no-tls-dind-kubernetes-runner"
     config: |
       [[runners]]
         [runners.kubernetes]
           image = "ubuntu:20.04"
           privileged = true
   ```

1. Vous pouvez maintenant utiliser `docker` dans le script du job. Incluez le service `docker:24.0.5-dind` :

   ```yaml
   default:
     image: docker:24.0.5-cli
     services:
       - name: docker:24.0.5-dind
         variables:
           HEALTHCHECK_TCP_PORT: "2375"
     before_script:
       - docker info

   variables:
     # When using dind service, you must instruct Docker to talk with
     # the daemon started inside of the service. The daemon is available
     # with a network connection instead of the default
     # /var/run/docker.sock socket.
     DOCKER_HOST: tcp://docker:2375
     #
     # The 'docker' hostname is the alias of the service container as described at
     # https://docs.gitlab.com/ci/services/#accessing-the-services.
     #
     # This instructs Docker not to start over TLS.
     DOCKER_TLS_CERTDIR: ""
   build:
     stage: build
     tags:
       - no-tls-dind-kubernetes-runner
     script:
       - docker build -t my-docker-image .
       - docker run my-docker-image /script/to/run/tests
   ```

## Problèmes connus avec Docker-in-Docker {#known-issues-with-docker-in-docker}

Docker-in-Docker est la configuration recommandée, mais vous devez être conscient des problèmes suivants :

- Commande `docker-compose` : cette commande n'est pas disponible dans cette configuration par défaut. Pour utiliser `docker-compose` dans vos scripts de job, suivez les [instructions d'installation](https://docs.docker.com/compose/install/) de Docker Compose.
- Cache : chaque job s'exécute dans un nouvel environnement. Comme chaque build dispose de sa propre instance du moteur Docker, les jobs simultanés ne provoquent pas de conflits. Cependant, les jobs peuvent être plus lents car il n'y a pas de mise en cache des couches. Consultez [Docker layer caching](using_docker_build.md#docker-layer-caching).
- Pilotes de stockage : par défaut, les versions antérieures de Docker utilisent le pilote de stockage `vfs`, qui copie le système de fichiers pour chaque job. Docker 17.09 et versions ultérieures utilisent `--storage-driver overlay2`, qui est le pilote de stockage recommandé. Consultez [Utilisation du pilote OverlayFS](using_docker_build.md#use-the-overlayfs-driver) pour plus de détails.
- Système de fichiers racine : comme le conteneur `docker:24.0.5-dind` et le conteneur runner ne partagent pas leur système de fichiers racine, vous pouvez utiliser le répertoire de travail du job comme point de montage pour les conteneurs enfants. Par exemple, si vous avez des fichiers que vous souhaitez partager avec un conteneur enfant, vous pouvez créer un sous-répertoire sous `/builds/$CI_PROJECT_PATH` et l'utiliser comme point de montage. Pour une explication plus détaillée, consultez le [ticket #41227](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/41227).

  ```yaml
  variables:
    MOUNT_POINT: /builds/$CI_PROJECT_PATH/mnt
  script:
    - mkdir -p "$MOUNT_POINT"
    - docker run -v "$MOUNT_POINT:/mnt" my-docker-image
  ```
