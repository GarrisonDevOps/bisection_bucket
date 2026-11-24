---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Proxy de dépendance pour les images de conteneurs
description: "Pour réduire le transfert de données depuis les images de conteneurs en amont, configurez le Proxy de Dépendance GitLab pour vos images de conteneurs."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Le proxy de dépendances GitLab pour les images de conteneurs est un proxy local que vous pouvez utiliser pour vos images en amont fréquemment sollicitées.

Dans le cas de CI/CD, le proxy de dépendances reçoit une requête et renvoie l'image en amont depuis un registre, agissant comme un cache pull-through.

## Prérequis {#prerequisites}

Pour utiliser le proxy de dépendances pour les images de conteneurs, il doit être activé pour l'instance GitLab. Il est activé par défaut, mais [les administrateurs peuvent le désactiver](../../../administration/packages/dependency_proxy.md).

Sur GitLab Self-Managed, les administrateurs peuvent également configurer une limite de débit dédiée pour les requêtes authentifiées du proxy de dépendances. Pour plus d'informations, consultez [Limites de débit des utilisateurs et des adresses IP](../../../administration/settings/user_and_ip_rate_limits.md#enable-authenticated-dependency-proxy-request-rate-limit).

### Images et paquets pris en charge {#supported-images-and-packages}

Les images et paquets suivants sont pris en charge.

| Image/Paquet    | Version de GitLab |
| ---------------- | -------------- |
| Docker           | 14.0+         |

Pour obtenir la liste des ajouts prévus, consultez la [page de direction](https://about.gitlab.com/direction/package/#dependency-proxy).

## Activer ou désactiver le proxy de dépendances pour un groupe {#enable-or-turn-off-the-dependency-proxy-for-a-group}

{{< history >}}

- Le rôle requis est passé de Maintainer à Owner dans GitLab 17.0 ([modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/370471)).

{{< /history >}}

Pour activer ou désactiver le proxy de dépendances pour un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Développez la section **Proxy de dépendance**.
1. Pour activer le proxy, activez **Activer le proxy**. Pour le désactiver, désactivez le bouton bascule.

Ce paramètre n'affecte que le proxy de dépendances pour un groupe. Seul un administrateur peut [activer ou désactiver le proxy de dépendances](../../../administration/packages/dependency_proxy.md) pour l'ensemble de l'instance GitLab.

## Afficher le proxy de dépendances pour les images de conteneurs {#view-the-dependency-proxy-for-container-images}

Pour afficher le proxy de dépendances pour les images de conteneurs :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Opération** > **Proxy de dépendance**.

Le proxy de dépendances n'est pas disponible pour les projets.

## Utiliser le proxy de dépendances pour les images Docker {#use-the-dependency-proxy-for-docker-images}

Vous pouvez utiliser GitLab comme source pour vos images Docker.

Prérequis :

- Vos images doivent être stockées sur [Docker Hub](https://hub.docker.com/).

### S'authentifier auprès du proxy de dépendances pour les images de conteneurs {#authenticate-with-the-dependency-proxy-for-container-images}

{{< history >}}

- Les portées de jeton de déploiement `read_virtual_registry` et `write_virtual_registry` ont été [introduites](https://gitlab.com/gitlab-org/gitlab/-/issues/336800) dans GitLab 17.11 avec un flag nommé `dependency_proxy_read_write_scopes`. Fonctionnalité désactivée par défaut.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/517249) dans GitLab 18.0. Suppression du feature flag `dependency_proxy_read_write_scopes`.

{{< /history >}}

Le proxy de dépendances pour les images de conteneurs stockant les images Docker dans un espace associé à votre groupe, vous devez vous authentifier auprès de lui.

Suivez les [instructions pour utiliser des images depuis un registre privé](../../../ci/docker/using_docker_images.md#access-an-image-from-a-private-container-registry), mais au lieu d'utiliser `registry.example.com:5000`, utilisez votre domaine GitLab sans port `gitlab.example.com`.

> [!note]
> [Admin Mode](../../../administration/settings/sign_in_restrictions.md#admin-mode) ne s'applique pas lors de l'authentification auprès du proxy de dépendances pour les images de conteneurs. Si vous êtes un administrateur avec Admin Mode activé et que vous créez un jeton d'accès personnel sans la portée `admin_mode`, ce jeton fonctionne même si Admin Mode est activé.

Par exemple, pour vous connecter manuellement :

```shell
echo "$CONTAINER_REGISTRY_PASSWORD" | docker login gitlab.example.com --username my_username --password-stdin
```

Vous pouvez vous authentifier en utilisant :

- Votre nom d'utilisateur et mot de passe GitLab.
- La [CLI GitLab](https://docs.gitlab.com/cli/).
- Un [jeton d'accès personnel](../../profile/personal_access_tokens.md).
- Un [jeton de déploiement de groupe](../../project/deploy_tokens/_index.md).
- Un [jeton d'accès de groupe](../../group/settings/group_access_tokens.md) pour le groupe.

La portée du jeton doit être définie sur l'une des valeurs suivantes :

- `api` : accorde un accès complet à l'API.
- `read_registry` : accorde un accès en lecture seule au registre de conteneurs.
- `write_registry` : accorde un accès en lecture et en écriture au registre de conteneurs.
- `read_virtual_registry` : accorde un accès en lecture seule (pull) aux images de conteneurs via le Proxy de Dépendance au niveau du groupe. Disponible uniquement lorsque le Proxy de Dépendance est activé.
- `write_virtual_registry` : accorde un accès en écriture au cache du proxy de dépendances au niveau du groupe, notamment pour alimenter et purger les images en cache. Accorde également un accès pull via ce cache. N'accorde pas d'accès push ou de suppression au registre de conteneurs du projet. Disponible uniquement lorsque le Proxy de Dépendance est activé.

Lors de l'authentification auprès du Proxy de Dépendance pour les images de conteneurs, les jetons doivent inclure l'une des combinaisons de portées suivantes :

- Portées du registre de conteneurs : `read_registry` et `write_registry`.
- Portées du Proxy de Dépendance : `read_virtual_registry` et `write_virtual_registry`. Lorsque vous extrayez des images via le Proxy de Dépendance, GitLab écrit des données dans le cache du Proxy de Dépendance au niveau du groupe.

Les utilisateurs accédant au proxy de dépendances pour les images de conteneurs avec un jeton d'accès personnel ou un nom d'utilisateur et un mot de passe doivent disposer du rôle Invité, Planificateur, Reporter, Développeur, Maintainer ou Owner pour le groupe depuis lequel ils extraient des images.

Le proxy de dépendances pour les images de conteneurs suit le [flux d'authentification par jeton Docker v2](https://distribution.github.io/distribution/spec/auth/token/), émettant au client un JWT à utiliser pour les extractions. Le JWT émis à la suite de l'authentification expire après un certain temps. Lorsque le jeton expire, la plupart des clients Docker stockent vos identifiants et demandent automatiquement un nouveau jeton sans autre intervention.

Le délai d'expiration du jeton est un [paramètre configurable](../../../administration/packages/dependency_proxy.md#changing-the-jwt-expiration). Sur GitLab.com, le délai d'expiration est de 15 minutes.

#### SAML SSO {#saml-sso}

Lorsque [l'application SSO](../../group/saml_sso/_index.md#sso-enforcement) est activée, les utilisateurs doivent être connectés via SSO avant de pouvoir extraire des images via le proxy de dépendances pour les images de conteneurs.

L'application SSO affecte également [la fusion automatique](../../project/merge_requests/auto_merge.md). Si une session SSO expire avant le déclenchement de la fusion automatique, le pipeline de fusion ne parvient pas à extraire les images via le proxy de dépendances.

#### S'authentifier dans CI/CD {#authenticate-within-cicd}

Les runners se connectent automatiquement au proxy de dépendances pour les images de conteneurs. Pour extraire via le proxy de dépendances, utilisez l'une des [variables prédéfinies](../../../ci/variables/predefined_variables.md) :

- `CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX` extrait via le groupe principal.
- `CI_DEPENDENCY_PROXY_DIRECT_GROUP_IMAGE_PREFIX` extrait via le sous-groupe ou le groupe direct dans lequel le projet existe.

Exemple d'extraction de la dernière image alpine :

```yaml
# .gitlab-ci.yml
image: ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/alpine:latest
```

D'autres variables CI/CD prédéfinies sont également disponibles :

- `CI_DEPENDENCY_PROXY_USER` : un utilisateur CI/CD pour se connecter au proxy de dépendances.
- `CI_DEPENDENCY_PROXY_PASSWORD` : un mot de passe CI/CD pour se connecter au proxy de dépendances
- `CI_DEPENDENCY_PROXY_SERVER` : le serveur pour se connecter au proxy de dépendances.
- `CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX` : le préfixe d'image pour extraire des images via le proxy de dépendances depuis le groupe principal.
- `CI_DEPENDENCY_PROXY_DIRECT_GROUP_IMAGE_PREFIX` : le préfixe d'image pour extraire des images via le proxy de dépendances depuis le groupe direct ou le sous-groupe auquel appartient le projet.

`CI_DEPENDENCY_PROXY_SERVER`, `CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX` et `CI_DEPENDENCY_PROXY_DIRECT_GROUP_IMAGE_PREFIX` incluent le port du serveur. Si vous incluez explicitement le chemin du proxy de dépendances, le port doit être inclus, sauf si vous vous êtes connecté manuellement au proxy de dépendances sans inclure le port :

```shell
docker pull gitlab.example.com:443/my-group/dependency_proxy/containers/alpine:latest
```

Exemple lors de l'utilisation du proxy de dépendances pour construire une image :

```plaintext
# Dockerfile
FROM gitlab.example.com:443/my-group/dependency_proxy/containers/alpine:latest
```

```yaml
# .gitlab-ci.yml
image: docker:20.10.16

variables:
  DOCKER_HOST: tcp://docker:2375
  DOCKER_TLS_CERTDIR: ""

services:
  - docker:20.10.16-dind

build:
  image: docker:20.10.16-cli
  before_script:
    - echo "$CI_DEPENDENCY_PROXY_PASSWORD" | docker login $CI_DEPENDENCY_PROXY_SERVER -u $CI_DEPENDENCY_PROXY_USER --password-stdin
  script:
    - docker build -t test .
```

Vous pouvez également utiliser des [variables CI/CD personnalisées](../../../ci/variables/_index.md#for-a-project) pour stocker et accéder à votre jeton d'accès personnel ou à votre jeton de déploiement.

### S'authentifier auprès de Docker Hub {#authenticate-with-docker-hub}

{{< history >}}

- La prise en charge des identifiants Docker Hub a été [ajoutée](https://gitlab.com/gitlab-org/gitlab/-/issues/331741) dans GitLab 17.10.
- La prise en charge de l'interface utilisateur a été [ajoutée](https://gitlab.com/gitlab-org/gitlab/-/issues/521954) dans GitLab 17.11.

{{< /history >}}

Par défaut, le Proxy de Dépendance n'utilise pas d'identifiants lors de l'extraction d'images depuis Docker Hub. Vous pouvez configurer l'authentification Docker Hub en utilisant vos identifiants ou jetons Docker Hub.

Pour vous authentifier auprès de Docker Hub, vous pouvez utiliser :

- Votre nom d'utilisateur et mot de passe Docker Hub.
  - Cette méthode n'est pas compatible avec les organisations Docker Hub qui [appliquent l'authentification unique (SSO)](https://docs.docker.com/security/faqs/single-sign-on/enforcement-faqs/#does-docker-sso-support-authenticating-through-the-command-line).
- Un [jeton d'accès personnel](https://docs.docker.com/security/for-developers/access-tokens/) Docker Hub.
- Un [jeton d'accès d'organisation](https://docs.docker.com/security/for-admins/access-tokens/) Docker Hub.

#### Configurer les identifiants {#configure-credentials}

Pour définir les identifiants Docker Hub pour le proxy de dépendances d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Développez la section **Proxy de dépendance**.
1. Activez **Activer le proxy**.
1. Sous **Authentification sur Docker Hub**, saisissez vos identifiants :
   - **Identité** correspond à votre nom d'utilisateur (pour le mot de passe ou le jeton d'accès personnel) ou au nom de l'organisation (pour le jeton d'accès d'organisation).
   - **Secret** correspond à votre mot de passe, à votre jeton d'accès personnel ou à votre jeton d'accès d'organisation.

   Vous devez soit remplir les deux champs, soit les laisser tous les deux vides. Si vous laissez les deux champs vides, les requêtes vers Docker Hub restent non authentifiées.

#### Configurer les identifiants à l'aide de l'API GraphQL {#configure-credentials-using-the-graphql-api}

Pour définir les identifiants Docker Hub dans les paramètres du Proxy de Dépendance à l'aide de l'[API GraphQL](../../../api/graphql/_index.md) :

1. Accédez à GraphiQL :
   - Pour GitLab.com, utilisez <https://gitlab.com/-/graphql-explorer>.
   - Pour GitLab Self-Managed, utilisez `https://gitlab.example.com/-/graphql-explorer`.
1. Dans GraphiQL, saisissez cette mutation :

   ```graphql
   mutation {
     updateDependencyProxySettings(input: {
       enabled: true,
         identity: "<identity>",
         secret: "<secret>",
         groupPath: "<group path>"
     }) {
       dependencyProxySetting {
        enabled
        identity
       }
       errors
     }
   }
   ```

   Où :
   - `<identity>` est votre nom d'utilisateur (pour le mot de passe ou le jeton d'accès personnel) ou le nom de l'organisation (pour le jeton d'accès d'organisation).
   - `<secret>` est votre mot de passe, votre jeton d'accès personnel ou votre jeton d'accès d'organisation.
   - `<group path>` est le chemin du groupe où se trouve le Proxy de Dépendance.

1. Sélectionnez **Exécuter**.
1. Vérifiez la présence d'erreurs dans le panneau des résultats.

#### Vérifier vos identifiants {#verify-your-credentials}

Après vous être authentifié auprès du Proxy de Dépendance, vérifiez vos identifiants Docker Hub en extrayant une image Docker :

```shell
docker pull gitlab.example.com/groupname/dependency_proxy/containers/alpine:latest
```

Si l'authentification réussit, vous verrez de l'activité dans votre [tableau de bord d'utilisation Docker Hub](https://hub.docker.com/usage/pulls).

### Stocker une image Docker dans le cache du proxy de dépendances {#store-a-docker-image-in-dependency-proxy-cache}

Pour stocker une image Docker dans le stockage du proxy de dépendances :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Opération** > **Proxy de dépendance**.
1. Copiez le **Préfixe d'image du Proxy de Dépendance**.
1. Utilisez l'une de ces commandes. Dans ces exemples, l'image est `alpine:latest`.
1. Vous pouvez également extraire des images par condensat pour spécifier exactement quelle version d'une image extraire.

   - Extrayez une image par tag en ajoutant l'image à votre fichier [`.gitlab-ci.yml`](../../../ci/yaml/_index.md#image) :

     ```shell
     image: gitlab.example.com/groupname/dependency_proxy/containers/alpine:latest
     ```

   - Extrayez une image par condensat en ajoutant l'image à votre fichier [`.gitlab-ci.yml`](../../../ci/yaml/_index.md#image) :

     ```shell
     image: ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/alpine@sha256:c9375e662992791e3f39e919b26f510e5254b42792519c180aad254e6b38f4dc
     ```

   - Extrayez manuellement l'image Docker :

     ```shell
     docker pull gitlab.example.com/groupname/dependency_proxy/containers/alpine:latest
     ```

   - Ajoutez l'URL à un `Dockerfile` :

     ```shell
     FROM gitlab.example.com/groupname/dependency_proxy/containers/alpine:latest
     ```

GitLab extrait l'image Docker depuis Docker Hub et met en cache les blobs sur le serveur GitLab. La prochaine fois que vous extrayez la même image, GitLab récupère les dernières informations sur l'image depuis Docker Hub, mais sert les blobs existants depuis le serveur GitLab.

## Réduire l'utilisation du stockage {#reduce-storage-usage}

Pour plus d'informations sur la réduction de l'utilisation du stockage du proxy de dépendances pour les images de conteneurs, consultez [Réduire l'utilisation du stockage du proxy de dépendances](reduce_dependency_proxy_storage.md).

## Limites de débit Docker Hub et proxy de dépendances {#docker-hub-rate-limits-and-the-dependency-proxy}

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez comment [utiliser le proxy de dépendances pour éviter les limites de débit Docker Hub](https://youtu.be/Nc4nUo7Pq08).

Docker Hub applique des [limites de débit sur les extractions](https://docs.docker.com/docker-hub/usage/pulls/). Si votre [configuration CI/CD](../../../ci/_index.md) GitLab utilise une image depuis Docker Hub, chaque fois qu'un job s'exécute, cela peut être comptabilisé comme une extraction. Pour contourner cette limite, vous pouvez extraire votre image depuis le cache du proxy de dépendances à la place.

Lorsque vous extrayez une image (à l'aide d'une commande comme `docker pull` ou, dans un fichier `.gitlab-ci.yml`, `image: foo:latest`), le client Docker effectue un ensemble de requêtes :

1. Le manifeste de l'image est demandé. Le manifeste contient des informations sur la façon de construire l'image.
1. À partir du manifeste, le client Docker demande un ensemble de couches, également appelées blobs, une à la fois.

La limite de débit Docker Hub est basée sur le nombre de requêtes GET pour le manifeste. Le proxy de dépendances met en cache à la fois le manifeste et les blobs pour une image donnée, de sorte que lorsque vous le demandez à nouveau, Docker Hub n'a pas besoin d'être contacté.

### Comment GitLab sait-il si une image taguée mise en cache est obsolète ? {#how-does-gitlab-know-if-a-cached-tagged-image-is-stale}

Si vous utilisez un tag d'image comme `alpine:latest`, l'image évolue au fil du temps. À chaque modification, le manifeste contient des informations différentes sur les blobs à demander. Le proxy de dépendances n'extrait pas une nouvelle image à chaque modification du manifeste ; il effectue une vérification uniquement lorsque le manifeste devient obsolète.

Docker ne comptabilise pas les requêtes HEAD pour le manifeste d'image dans la limite de débit. Vous pouvez effectuer une requête HEAD pour `alpine:latest`, consulter la valeur du condensat (checksum) renvoyée dans l'en-tête, et déterminer si un manifeste a changé.

Le proxy de dépendances commence toutes les requêtes par une requête HEAD. Ce n'est que si le manifeste est devenu obsolète qu'une nouvelle image est extraite.

Par exemple, si votre pipeline extrait `node:latest` toutes les cinq minutes, le proxy de dépendances met en cache l'image entière et ne la met à jour que si `node:latest` change. Ainsi, au lieu d'avoir 360 requêtes pour l'image en six heures (ce qui dépasse la limite de débit Docker Hub), vous n'effectuez qu'une seule extraction, sauf si le manifeste a changé pendant cette période.

### Vérifier votre limite de débit Docker Hub {#check-your-docker-hub-rate-limit}

Si vous souhaitez savoir combien de requêtes vous avez effectuées vers Docker Hub et combien il en reste, vous pouvez exécuter ces commandes depuis votre runner, ou même dans un script CI/CD :

```shell
# Note, you must have jq installed to run this command
TOKEN=$(curl "https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull" | jq --raw-output .token) && curl --head --header "Authorization: Bearer $TOKEN" "https://registry-1.docker.io/v2/ratelimitpreview/test/manifests/latest" 2>&1 | grep --ignore-case RateLimit
...
```

Le résultat ressemble à ceci :

```shell
RateLimit-Limit: 100;w=21600
RateLimit-Remaining: 98;w=21600
```

Cet exemple montre la limite totale de 100 extractions en six heures, avec 98 extractions restantes.

#### Vérifier la limite de débit dans un job CI/CD {#check-the-rate-limit-in-a-cicd-job}

Cet exemple montre un job CI/CD GitLab qui utilise une image avec `jq` et `curl` installés :

```yaml
hub_docker_quota_check:
    stage: build
    image: alpine:latest
    tags:
        - <optional_runner_tag>
    before_script: apk add curl jq
    script:
      - |
        TOKEN=$(curl "https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull" | jq --raw-output .token) && curl --head --header "Authorization: Bearer $TOKEN" "https://registry-1.docker.io/v2/ratelimitpreview/test/manifests/latest" 2>&1
```

## Dépannage {#troubleshooting}

### Erreur d'authentification : `HTTP Basic: Access Denied` {#authentication-error-http-basic-access-denied}

Si vous recevez une erreur `HTTP Basic: Access denied` lors de l'authentification auprès du proxy de dépendances, consultez le [guide de dépannage de l'authentification à deux facteurs](../../profile/account/two_factor_authentication_troubleshooting.md).

### Échec de connexion au proxy de dépendances {#dependency-proxy-connection-failure}

Si aucun alias de service n'est défini, l'image `docker:20.10.16` ne parvient pas à trouver le service `dind`, et une erreur similaire à la suivante est générée :

```plaintext
error during connect: Get http://docker:2376/v1.39/info: dial tcp: lookup docker on 192.168.0.1:53: no such host
```

Cela peut être résolu en définissant un alias de service pour le service Docker :

```yaml
services:
    - name: ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/docker:18.09.7-dind
      alias: docker
```

### Problèmes lors de l'authentification auprès du proxy de dépendances depuis les jobs CI/CD {#issues-when-authenticating-to-the-dependency-proxy-from-cicd-jobs}

GitLab Runner s'authentifie automatiquement auprès du proxy de dépendances. Cependant, le moteur Docker sous-jacent est toujours soumis à son [processus de résolution des autorisations](https://docs.gitlab.com/runner/configuration/advanced-configuration/#precedence-of-docker-authorization-resolving).

Des erreurs de configuration dans le mécanisme d'authentification peuvent provoquer des erreurs `HTTP Basic: Access denied` et `403: Access forbidden`.

Vous pouvez utiliser les job logs pour afficher le mécanisme d'authentification utilisé pour s'authentifier auprès du proxy de dépendances :

```plaintext
Authenticating with credentials from $DOCKER_AUTH_CONFIG
```

```plaintext
Authenticating with credentials from /root/.docker/config.json
```

```plaintext
Authenticating with credentials from job payload (GitLab Registry)
```

Assurez-vous d'utiliser le mécanisme d'authentification attendu.

### Erreur `Not Found` ou `404` lors de l'extraction d'une image {#not-found-or-404-error-when-pulling-image}

Ces erreurs peuvent indiquer que l'utilisateur qui exécute le job ne dispose pas du rôle Invité au minimum pour le groupe du proxy de dépendances :

- ```plaintext
  ERROR: gitlab.example.com:443/group1/dependency_proxy/containers/alpine:latest: not found

  failed to solve with frontend dockerfile.v0: failed to create LLB definition: gitlab.example.com:443/group1/dependency_proxy/containers/alpine:latest: not found
  ```

- ```plaintext
  ERROR: Job failed: failed to pull image "gitlab.example.com:443/group1/dependency_proxy/containers/alpine:latest" with specified policies [always]:
  Error response from daemon: error parsing HTTP 404 response body: unexpected end of JSON input: "" (manager.go:237:1s)
  ```

Pour plus d'informations sur les travaux visant à améliorer les messages d'erreur dans des cas similaires à `Access denied`, consultez le [ticket 354826](https://gitlab.com/gitlab-org/gitlab/-/issues/354826).

### Erreurs `MissingFile` après la restauration d'une sauvegarde {#missingfile-errors-after-restoring-a-backup}

Si vous rencontrez des erreurs `MissingFile` ou `Cannot read file`, cela peut être dû au fait que les [archives de sauvegarde](../../../administration/backup_restore/backup_gitlab.md) n'incluent pas le contenu de `gitlab-rails/shared/dependency_proxy/`.

Pour résoudre ce [problème connu](https://gitlab.com/gitlab-org/gitlab/-/issues/354574), vous pouvez utiliser `rsync`, `scp` ou un outil similaire pour copier les fichiers concernés ou l'ensemble de la structure de dossiers `gitlab-rails/shared/dependency_proxy/` depuis l'instance GitLab qui était la source de la sauvegarde.

Si les données ne sont pas nécessaires, vous pouvez supprimer les entrées de la base de données avec :

```shell
gitlab-psql -c "DELETE FROM dependency_proxy_blobs; DELETE FROM dependency_proxy_blob_states; DELETE FROM dependency_proxy_manifest_states; DELETE FROM dependency_proxy_manifests;"
```
