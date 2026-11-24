---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Découvrez comment vous authentifier auprès du registre de conteneurs à l'aide de vos identifiants GitLab, d'un jeton ou de variables CI/CD telles qu'un jeton de job CI."
title: "S'authentifier auprès du registre de conteneurs"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour vous authentifier auprès du registre de conteneurs, vous pouvez utiliser :

- Nom d'utilisateur et mot de passe GitLab (non disponible si la 2FA est activée)
- [Jeton d'accès personnel](../../profile/personal_access_tokens.md)
- [Jeton de déploiement](../../project/deploy_tokens/_index.md)
- [Jeton d'accès au projet](../../project/settings/project_access_tokens.md)
- [Jeton d'accès au groupe](../../group/settings/group_access_tokens.md)
- L'[interface de ligne de commande GitLab](https://docs.gitlab.com/cli/)

Pour les méthodes d'authentification basées sur un jeton, la portée minimale requise :

- Pour l'accès en lecture (pull), doit être `read_registry`
- Pour l'accès en écriture (push), doit être `write_registry` et `read_registry`

> [!note]
> Le mode Admin ne s'applique pas lors de l'authentification auprès du registre de conteneurs. Si vous êtes un administrateur avec le mode Admin activé et que vous créez un jeton d'accès personnel sans la portée `admin_mode`, ce jeton fonctionne même si le mode Admin est activé. Pour plus d'informations, voir [Mode Admin](../../../administration/settings/sign_in_restrictions.md#admin-mode).

## S'authentifier avec un nom d'utilisateur et un mot de passe {#authenticate-with-username-and-password}

> [!note]
> Si vous avez activé l'[authentification à deux facteurs (2FA)](../../profile/account/two_factor_authentication.md) (y compris l'OTP par e-mail) sur votre compte, vous devez [vous authentifier avec un jeton](#authenticate-with-a-token).

Pour vous authentifier avec votre nom d'utilisateur et votre mot de passe, exécutez la commande `docker login` :

```shell
docker login registry.example.com -u <username> -p <password>
```

Pour des raisons de sécurité, il est recommandé d'utiliser l'indicateur `--password-stdin` plutôt que `-p` :

```shell
echo "<password>" | docker login registry.example.com -u <username> --password-stdin
```

## S'authentifier avec un jeton {#authenticate-with-a-token}

Pour vous authentifier avec un jeton, exécutez la commande `docker login` :

```shell
TOKEN=<token>
echo "$TOKEN" | docker login registry.example.com -u <username> --password-stdin
```

Après l'authentification, le client met en cache les identifiants. Les opérations ultérieures effectuent des requêtes d'autorisation qui renvoient des jetons JWT, autorisés à effectuer uniquement l'opération spécifiée. Les jetons restent valides :

- Pendant [5 minutes par défaut](../../../administration/packages/container_registry.md#increase-token-duration) sur GitLab Self-Managed
- Pendant [15 minutes](../../gitlab_com/_index.md#container-registry) sur GitLab.com

## Utiliser GitLab CI/CD pour s'authentifier {#use-gitlab-cicd-to-authenticate}

Pour utiliser CI/CD afin de vous authentifier auprès du registre de conteneurs, vous pouvez utiliser :

- Les variables CI/CD `CI_REGISTRY_USER` et `CI_REGISTRY_PASSWORD`.

  `CI_REGISTRY_USER` contient un utilisateur par job disposant d'un accès en lecture-écriture au registre de conteneurs, et `CI_REGISTRY_PASSWORD` contient son mot de passe créé automatiquement.

  ```shell
  echo "$CI_REGISTRY_PASSWORD" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin
  ```

- Un [jeton de job CI](../../../ci/jobs/ci_job_token.md).

  Ce jeton dispose d'un accès en lecture (pull) et en écriture (push) au registre de conteneurs du projet qui exécute le job. La [liste d'autorisation des jetons de job CI/CD](../../../ci/jobs/ci_job_token.md#control-job-token-access-to-your-project) contrôle l'accès aux registres des autres projets.

  ```shell
  echo "$CI_JOB_TOKEN" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin
  ```

  Vous pouvez également utiliser le schéma `gitlab-ci-token` :

  ```shell
  echo "$CI_JOB_TOKEN" | docker login $CI_REGISTRY -u gitlab-ci-token --password-stdin
  ```

- Un [jeton de déploiement GitLab](../../project/deploy_tokens/_index.md#gitlab-deploy-token) avec la portée minimale :
  - Pour l'accès en lecture (pull), `read_registry`.
  - Pour l'accès en écriture (push), `read_registry` et `write_registry`.

  ```shell
  echo "$CI_DEPLOY_PASSWORD" | docker login $CI_REGISTRY -u $CI_DEPLOY_USER --password-stdin
  ```

- Un jeton d'accès personnel avec la portée minimale :
  - Pour l'accès en lecture (pull), `read_registry`.
  - Pour l'accès en écriture (push), `read_registry` et `write_registry`.

  ```shell
  echo "<access_token>" | docker login $CI_REGISTRY -u <username> --password-stdin
  ```

## Dépannage {#troubleshooting}

### Erreur : la commande `docker login` échoue avec `access forbidden` {#error-docker-login-command-fails-with-access-forbidden}

Le registre de conteneurs renvoie l'URL de l'API GitLab au client Docker pour valider les identifiants. Le client Docker utilise l'authentification de base, de sorte que la requête contient l'en-tête `Authorization`. Si l'en-tête `Authorization` est absent de la requête vers le point de terminaison `/jwt/auth` configuré dans `token_realm` pour la configuration du registre, vous recevez un message d'erreur `access forbidden`.

Par exemple :

```plaintext
> docker login gitlab.example.com:4567

Username: user
Password:
Error response from daemon: Get "https://gitlab.company.com:4567/v2/": denied: access forbidden
```

Pour éviter cette erreur, vérifiez que l'en-tête `Authorization` n'est pas supprimé de la requête. Par exemple, un proxy devant GitLab pourrait rediriger vers le point de terminaison `/jwt/auth`.

Pour plus d'informations sur la validation des identifiants avec les clients Docker, voir [Architecture du registre de conteneurs](../../../administration/packages/container_registry.md#container-registry-architecture).

### Erreur : `docker login` échoue avec une erreur d'authentification {#error-docker-login-fails-with-an-authentication-error}

Lorsque GitLab rejette une requête `docker login`, le client Docker affiche une enveloppe d'erreur JSON contenant un code d'erreur et un message.

Pour résoudre l'erreur, identifiez le code d'erreur et suivez les instructions :

- `UNAUTHORIZED` (`401`) : GitLab n'a pas pu vérifier les identifiants. Pour résoudre le problème :
  - Vérifiez que le mot de passe ou le jeton est correct et qu'il n'est pas expiré.
  - Vérifiez qu'un jeton d'accès personnel ou un jeton de déploiement possède la portée `read_registry` pour l'accès en pull, ou les portées `read_registry` et `write_registry` pour l'accès en push.
  - Si le compte utilise l'authentification à deux facteurs, authentifiez-vous avec un jeton plutôt qu'un mot de passe. Pour plus d'informations, voir [s'authentifier avec un jeton](#authenticate-with-a-token).
- `DENIED` (`403`) : GitLab a refusé l'accès. Vérifiez le message :
  - `access forbidden` : les identifiants sont valides mais ne donnent pas accès au registre. Vérifiez que le jeton possède la portée `read_registry` (et `write_registry` pour l'accès en push), et que votre rôle autorise l'accès au registre du projet.
  - `Pushing to protected repository path forbidden` : le chemin cible est protégé par des règles de protection du registre de conteneurs.
  - `Access denied: too many failed authentication attempts from this network` : la protection contre les abus a bloqué votre réseau. Attendez l'expiration du blocage ou réessayez depuis un réseau différent.
  - `Access denied: too many distinct sources for this account` : le compte a été utilisé depuis trop d'adresses IP. Vérifiez où le compte est utilisé, puis regroupez ou échelonnez les requêtes.
- `UNSUPPORTED` (`404`) : GitLab ne reconnaît pas le service d'authentification demandé. Pour résoudre le problème :
  - Vérifiez que le service de jetons du registre est correctement configuré.

Si le client Docker signale plutôt `unexpected end of JSON input`, le corps de la réponse était vide ou contenait du JSON non valide :

### Erreur : `unexpected end of JSON input` {#error-unexpected-end-of-json-input}

Lorsqu'un proxy ou un équilibreur de charge devant GitLab supprime le corps de la réponse, vous pouvez recevoir l'erreur suivante :

```plaintext
Error response from daemon: error parsing HTTP <status> response body: unexpected end of JSON input: ""
```

Pour résoudre ce problème, vérifiez le chemin de la requête entre le client Docker et GitLab.

### Erreur : `unauthorized: authentication required` lors du push d'images volumineuses {#error-unauthorized-authentication-required-when-pushing-large-images}

Lors du push d'images volumineuses, vous pouvez rencontrer une erreur d'authentification telle que la suivante :

```shell
docker push gitlab.example.com/myproject/docs:latest
The push refers to a repository [gitlab.example.com/myproject/docs]
630816f32edb: Preparing
530d5553aec8: Preparing
...
4b0bab9ff599: Waiting
d1c800db26c7: Waiting
42755cf4ee95: Waiting
unauthorized: authentication required
```

Cette erreur se produit lorsque votre jeton d'authentification expire avant que le push de l'image soit terminé. Par défaut, les jetons du registre de conteneurs sur les instances GitLab Self-Managed expirent après cinq minutes. Sur GitLab.com, le délai d'expiration du jeton est de 15 minutes.
