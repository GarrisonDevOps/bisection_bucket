---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Publier des paquets avec Yarn
---

Vous pouvez publier et installer des paquets avec [Yarn 1 (Classic)](https://classic.yarnpkg.com) et [Yarn 2+](https://yarnpkg.com).

Pour trouver la version de Yarn utilisée dans le conteneur de déploiement, exécutez `yarn --version` dans le bloc `script` du bloc de job de script CI/CD responsable de l'appel de `yarn publish`. La version de Yarn est affichée dans la sortie du pipeline.

## Authentification auprès du registre de paquets {#authenticating-to-the-package-registry}

Vous avez besoin d'un jeton pour interagir avec le registre de paquets. Différents jetons sont disponibles selon ce que vous souhaitez accomplir. Pour plus d'informations, consultez le [guide sur les jetons](../package_registry/supported_functionality.md#authenticate-with-the-registry).

- Si votre organisation utilise l'authentification à deux facteurs (2FA), vous devez utiliser un [jeton d'accès personnel](../../profile/personal_access_tokens.md) avec la portée définie sur `api`.
- Si vous publiez un paquet avec des pipelines CI/CD, vous pouvez utiliser un [jeton de job CI/CD](../../../ci/jobs/ci_job_token.md) avec des runners privés. Vous pouvez également [enregistrer une variable](https://docs.gitlab.com/runner/register/#register-with-a-runner-authentication-token) pour les runners d'instance.

### Configurer Yarn pour la publication {#configure-yarn-for-publication}

Pour configurer Yarn afin de publier dans le registre de paquets, modifiez votre fichier `.yarnrc.yml`. Vous pouvez trouver ce fichier dans le répertoire racine de votre projet, au même endroit que le fichier `package.json`.

- Modifiez `.yarnrc.yml` et ajoutez la configuration suivante :

  ```yaml
  npmScopes:
    <my-org>:
      npmPublishRegistry: 'https://<domain>/api/v4/projects/<project_id>/packages/npm/'
      npmAlwaysAuth: true
      npmAuthToken: '<token>'
  ```

  Dans cette configuration :

  - Remplacez `<my-org>` par la portée de votre organisation. N'incluez pas le symbole `@`.
  - Remplacez `<domain>` par votre nom de domaine.
  - Remplacez `<project_id>` par l'ID de votre projet, que vous pouvez trouver sur la [page de présentation du projet](../../project/working_with_projects.md#find-the-project-id).
  - Remplacez `<token>` par un jeton de déploiement, un jeton d'accès au groupe, un jeton d'accès au projet ou un jeton d'accès personnel.

Dans Yarn Classic, les registres délimités par portée avec `publishConfig["@scope:registry"]` ne sont pas pris en charge. Consultez la [pull request Yarn 7829](https://github.com/yarnpkg/yarn/pull/7829) pour plus d'informations. À la place, définissez `publishConfig` sur `registry` dans votre fichier `package.json`.

## Publier un paquet {#publish-a-package}

Vous pouvez publier un paquet depuis la ligne de commande ou avec GitLab CI/CD.

### Avec la ligne de commande {#with-the-command-line}

Pour publier un paquet manuellement :

- Exécutez la commande suivante :

  ```shell
  # Yarn 1 (Classic)
  yarn publish

  # Yarn 2+
  yarn npm publish
  ```

### Avec CI/CD {#with-cicd}

Vous pouvez publier un paquet automatiquement avec des runners d'instance (par défaut) ou des runners privés (avancé). Vous pouvez utiliser des variables de pipeline lorsque vous publiez avec CI/CD.

{{< tabs >}}

{{< tab title="Runners d'instance" >}}

1. Créez un jeton d'authentification pour votre projet ou groupe :

   1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
   1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt** > **Jetons de déploiement**.
   1. Créez un jeton de déploiement avec les portées `read_package_registry` et `write_package_registry` et copiez le jeton généré.
   1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD** > **Variables**.
   1. Sélectionnez `Add variable` et utilisez les paramètres suivants :

   | Champ              | Valeur                        |
   |--------------------|------------------------------|
   | clé                | `NPM_AUTH_TOKEN`             |
   | valeur              | `<DEPLOY-TOKEN>` |
   | type               | Variable                     |
   | Variable protégée | `CHECKED`                    |
   | Masquer la variable      | `CHECKED`                    |
   | Développer la variable    | `CHECKED`                    |

1. Facultatif. Pour utiliser des variables protégées :

   1. Accédez au dépôt qui contient le code source du paquet Yarn.
   1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
      - Si vous compilez depuis des branches avec des étiquettes, sélectionnez **Étiquettes protégées** et ajoutez `v*` (caractère générique) pour la gestion sémantique de version.
      - Si vous compilez depuis des branches sans étiquettes, sélectionnez **Règles des branches**.

1. Ajoutez le `NPM_AUTH_TOKEN` que vous avez créé à la configuration `.yarnrc.yml` dans le répertoire racine de votre projet de paquet où se trouve `package.json` :

   ```yaml
   npmScopes:
     <my-org>:
       npmPublishRegistry: '${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/npm/'
       npmAlwaysAuth: true
       npmAuthToken: '${NPM_AUTH_TOKEN}'
   ```

   Dans cette configuration, remplacez `<my-org>` par la portée de votre organisation, en excluant le symbole `@`.

{{< /tab >}}

{{< tab title="Runners privés" >}}

1. Ajoutez votre `CI_JOB_TOKEN` à la configuration `.yarnrc.yml` dans le répertoire racine de votre projet de paquet, où se trouve `package.json` :

   ```yaml
   npmScopes:
     <my-org>:
       npmPublishRegistry: '${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/npm/'
       npmAlwaysAuth: true
       npmAuthToken: '${CI_JOB_TOKEN}'
   ```

   Dans cette configuration, remplacez `<my-org>` par la portée de votre organisation, en excluant le symbole `@`.

1. Dans le projet GitLab contenant votre `.yarnrc.yml`, modifiez ou créez un fichier `.gitlab-ci.yml`. Par exemple, pour déclencher uniquement lors d'un push de n'importe quelle étiquette :

   Dans Yarn 1 :

   ```yaml
   image: node:lts

   stages:
     - deploy

   rules:
   - if: $CI_COMMIT_TAG

   deploy:
     stage: deploy
     script:
       - yarn publish
   ```

   Dans Yarn 2 et versions ultérieures :

   ```yaml
   image: node:lts

   stages:
     - deploy

   rules:
     - if: $CI_COMMIT_TAG

   deploy:
     stage: deploy
     before_script:
       - corepack enable
       - yarn set version stable
     script:
       - yarn npm publish
   ```

Lorsque le pipeline s'exécute, votre paquet est ajouté au registre de paquets.

{{< /tab >}}

{{< /tabs >}}

## Installer un paquet {#install-a-package}

Vous pouvez installer depuis une instance ou un projet. Si plusieurs paquets ont le même nom et la même version, seul le paquet publié le plus récemment est récupéré lorsque vous installez un paquet.

### Noms de paquets délimités par portée {#scoped-package-names}

Pour installer depuis une instance, un paquet doit être nommé avec une [portée](https://docs.npmjs.com/misc/scope/). Vous pouvez configurer la portée de votre paquet dans le fichier `.yarnrc.yml` et avec l'option `publishConfig` dans le fichier `package.json`. Vous n'avez pas besoin de suivre les conventions de nommage des paquets si vous installez depuis un projet ou un groupe.

Une portée de paquet commence par `@` et suit le format `@owner/package-name` :

- Le `@owner` est le projet principal qui héberge les paquets, et non la racine du projet contenant le code source du paquet.
- Le nom du paquet peut être quelconque.

Par exemple :

| URL du projet                                                       | Registre de paquets     | Portée de l'organisation | Nom complet du paquet           |
|-------------------------------------------------------------------|----------------------|--------------------|-----------------------------|
| `https://gitlab.com/<my-org>/<group-name>/<package-name-example>` | Exemple de nom de paquet | `@my-org`          | `@my-org/package-name`      |
| `https://gitlab.com/<example-org>/<group-name>/<project-name>`    | Nom du projet         | `@example-org`     | `@example-org/project-name` |

### Installer depuis l'instance {#install-from-the-instance}

Si vous travaillez avec de nombreux paquets dans la même portée d'organisation, envisagez d'installer depuis l'instance.

1. Configurez la portée de votre organisation. Dans votre fichier `.yarnrc.yml`, ajoutez ce qui suit :

   ```yaml
   npmScopes:
    <my-org>:
      npmRegistryServer: 'https://<domain_name>/api/v4/packages/npm'
   ```

   - Remplacez `<my-org>` par le groupe de niveau racine du projet depuis lequel vous installez le paquet, en excluant le symbole `@`.
   - Remplacez `<domain_name>` par votre nom de domaine, par exemple `gitlab.com`.

1. Facultatif. Si votre paquet est privé, vous devez configurer l'accès au registre de paquets :

   ```yaml
   npmRegistries:
     //<domain_name>/api/v4/packages/npm:
       npmAlwaysAuth: true
       npmAuthToken: '<token>'
   ```

   - Remplacez `<domain_name>` par votre nom de domaine, par exemple `gitlab.com`.
   - Remplacez `<token>` par un jeton de déploiement (recommandé), un jeton d'accès au groupe, un jeton d'accès au projet ou un jeton d'accès personnel.

1. [Installez le paquet avec Yarn](#install-with-yarn).

### Installer depuis un groupe ou un projet {#install-from-a-group-or-project}

Si vous avez un paquet ponctuel, vous pouvez l'installer depuis un groupe ou un projet.

{{< tabs >}}

{{< tab title="Depuis un groupe" >}}

1. Configurez la portée du groupe. Dans votre fichier `.yarnrc.yml`, ajoutez ce qui suit :

   ```yaml
   npmScopes:
     <my-org>:
       npmRegistryServer: 'https://<domain_name>/api/v4/groups/<group_id>/-/packages/npm'
   ```

   - Remplacez `<my-org>` par le groupe principal qui contient le groupe depuis lequel vous souhaitez effectuer l'installation. Excluez le symbole `@`.
   - Remplacez `<domain_name>` par votre nom de domaine, par exemple `gitlab.com`.
   - Remplacez `<group_id>` par l'ID de votre groupe, disponible sur la [page de présentation du groupe](../../group/_index.md#find-the-group-id).

1. Facultatif. Si votre paquet est privé, vous devez configurer le registre :

   ```yaml
   npmRegistries:
     //<domain_name>/api/v4/groups/<group_id>/-/packages/npm:
       npmAlwaysAuth: true
       npmAuthToken: "<token>"
   ```

   - Remplacez `<domain_name>` par votre nom de domaine, par exemple `gitlab.com`.
   - Remplacez `<token>` par un jeton de déploiement (recommandé), un jeton d'accès au groupe, un jeton d'accès au projet ou un jeton d'accès personnel.
   - Remplacez `<group_id>` par l'ID de votre groupe, disponible sur la [page de présentation du groupe](../../group/_index.md#find-the-group-id).

1. [Installez le paquet avec Yarn](#install-with-yarn).

{{< /tab >}}

{{< tab title="Depuis un projet" >}}

1. Configurez la portée du projet. Dans votre fichier `.yarnrc.yml`, ajoutez ce qui suit :

   ```yaml
   npmScopes:
    <my-org>:
      npmRegistryServer: "https://<domain_name>/api/v4/projects/<project_id>/packages/npm"
   ```

   - Remplacez `<my-org>` par le groupe principal qui contient le projet depuis lequel vous souhaitez effectuer l'installation. Excluez le symbole `@`.
   - Remplacez `<domain_name>` par votre nom de domaine, par exemple `gitlab.com`.
   - Remplacez `<project_id>` par l'ID de votre projet, disponible sur la [page de présentation du projet](../../project/working_with_projects.md#find-the-project-id).

1. Facultatif. Si votre paquet est privé, vous devez configurer le registre :

   ```yaml
   npmRegistries:
     //<domain_name>/api/v4/projects/<project_id>/packages/npm:
       npmAlwaysAuth: true
       npmAuthToken: "<token>"
   ```

   - Remplacez `<domain_name>` par votre nom de domaine, par exemple `gitlab.com`.
   - Remplacez `<token>` par un jeton de déploiement (recommandé), un jeton d'accès au groupe, un jeton d'accès au projet ou un jeton d'accès personnel.
   - Remplacez `<project_id>` par l'ID de votre projet, disponible sur la [page de présentation du projet](../../project/working_with_projects.md#find-the-project-id).

1. [Installez le paquet avec Yarn](#install-with-yarn).

{{< /tab >}}

{{< /tabs >}}

### Installer avec Yarn {#install-with-yarn}

{{< tabs >}}

{{< tab title="Yarn 2 ou version ultérieure" >}}

- Exécutez `yarn add` depuis la ligne de commande ou depuis un pipeline CI/CD :

```shell
yarn add @scope/my-package
```

{{< /tab >}}

{{< tab title="Yarn Classic" >}}

Yarn Classic nécessite à la fois un fichier `.npmrc` et un fichier `.yarnrc`. Consultez le [ticket Yarn 4451](https://github.com/yarnpkg/yarn/issues/4451#issuecomment-753670295) pour plus d'informations.

1. Placez vos identifiants dans le fichier `.npmrc` et le registre délimité par portée dans le fichier `.yarnrc` :

   ```shell
   # .npmrc
   ## For the instance
   //<domain_name>/api/v4/packages/npm/:_authToken='<token>'
   ## For the group
   //<domain_name>/api/v4/groups/<group_id>/-/packages/npm/:_authToken='<token>'
   ## For the project
   //<domain_name>/api/v4/projects/<project_id>/packages/npm/:_authToken='<token>'

   # .yarnrc
   ## For the instance
   '@scope:registry' 'https://<domain_name>/api/v4/packages/npm/'
   ## For the group
   '@scope:registry' 'https://<domain_name>/api/v4/groups/<group_id>/-/packages/npm/'
   ## For the project
   '@scope:registry' 'https://<domain_name>/api/v4/projects/<project_id>/packages/npm/'
   ```

1. Exécutez `yarn add` depuis la ligne de commande ou depuis un pipeline CI/CD :

   ```shell
   yarn add @scope/my-package
   ```

{{< /tab >}}

{{< /tabs >}}

## Supprimer un paquet Yarn {#delete-a-yarn-package}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire.

Avant de supprimer un paquet, assurez-vous de bien comprendre les [risques de sécurité associés](../package_registry/supported_functionality.md#deleting-packages).

Pour supprimer un paquet, vous pouvez :

- [Utiliser l'interface utilisateur](../package_registry/reduce_package_registry_storage.md#delete-a-package).
- [Utiliser l'API](../../../api/packages.md#delete-a-project-package).

## Sujets connexes {#related-topics}

- [Documentation du registre de paquets npm](../npm_registry/_index.md#helpful-hints)
- [Guide de migration Yarn](https://yarnpkg.com/migration/guide)
- [Créer un paquet Yarn](../workflows/build_packages.md#yarn)

## Dépannage {#troubleshooting}

### Erreur lors de l'exécution de Yarn avec le registre de paquets pour le registre npm {#error-running-yarn-with-the-package-registry-for-the-npm-registry}

Si vous utilisez [Yarn](https://classic.yarnpkg.com/en/) avec le registre npm, vous pouvez obtenir un message d'erreur tel que :

```shell
yarn install v1.15.2
warning package.json: No license field
info No lockfile found.
warning XXX: No license field
[1/4] 🔍  Resolving packages...
[2/4] 🚚  Fetching packages...
error An unexpected error occurred: "https://gitlab.example.com/api/v4/projects/XXX/packages/npm/XXX/XXX/-/XXX/XXX-X.X.X.tgz: Request failed \"404 Not Found\"".
info If you think this is a bug, please open a bug report with the information provided in "/Users/XXX/gitlab-migration/module-util/yarn-error.log".
info Visit https://classic.yarnpkg.com/en/docs/cli/install for documentation about this command
```

Dans ce cas, les commandes suivantes créent un fichier appelé `.yarnrc` dans le répertoire courant. Assurez-vous de vous trouver dans votre répertoire personnel pour une configuration globale ou dans la racine de votre projet pour une configuration par projet :

```shell
yarn config set '//gitlab.example.com/api/v4/projects/<project_id>/packages/npm/:_authToken' '<token>'
yarn config set '//gitlab.example.com/api/v4/packages/npm/:_authToken' '<token>'
```

### Yarn Classic retourne `404 Not Found` lors de la récupération d'une archive depuis l'installation d'un groupe {#yarn-classic-returns-404-not-found-when-fetching-a-tarball-from-a-group-install}

Lorsque vous installez un paquet depuis un registre dans un groupe avec Yarn Classic, la résolution du paquet peut réussir mais le téléchargement de l'archive échoue avec une erreur `404 Not Found` :

```shell
[1/4] Resolving packages...
[2/4] Fetching packages...
error Error: https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/@scope/my-package/-/@scope/my-package-1.0.0.tgz: Request failed "404 Not Found"
```

Cette erreur se produit car les métadonnées du paquet renvoyées par le registre du groupe contiennent des URL de téléchargement d'archive qui pointent vers le point de terminaison du projet. Si votre fichier `.npmrc` ne contient qu'un jeton d'authentification pour le point de terminaison du groupe, la requête vers le point de terminaison du projet n'est pas authentifiée et renvoie un `404`.

Pour résoudre ce problème, ajoutez des jetons d'authentification pour les points de terminaison du groupe et du projet dans votre fichier `.npmrc` :

```ini
# .npmrc
//gitlab.example.com/api/v4/groups/<group_id>/-/packages/npm/:_authToken='<token>'
//gitlab.example.com/api/v4/projects/<project_id>/packages/npm/:_authToken='<token>'
```

### Yarn Classic retourne `401 Unauthorized` avec des chemins d'authentification raccourcis {#yarn-classic-returns-401-unauthorized-with-shortened-authentication-paths}

Lorsque vous utilisez Yarn Classic avec le registre de paquets GitLab, vous pouvez recevoir une erreur `401 Unauthorized` même si votre jeton d'authentification est valide. Le message d'erreur peut ressembler à :

```shell
error Couldn't find package "@scope/my-package" on the "npm" registry.
```

Avec l'indicateur `--verbose`, le journal affiche un code de statut `401` :

```shell
verbose Performing "GET" request to "https://gitlab.com/api/v4/groups/<group_id>/-/packages/npm/..."
verbose Request "https://gitlab.com/api/v4/groups/<group_id>/-/packages/npm/..." finished with status code 401.
```

Ce problème se produit lorsque l'entrée `_authToken` dans `.npmrc` utilise un chemin parent raccourci au lieu du chemin complet du point de terminaison. Par exemple :

```ini
# Does NOT work with Yarn Classic
//gitlab.com/api/v4/:_authToken='<token>'
```

Bien que npm version 8 et les versions ultérieures prennent en charge la correspondance d'authentification hiérarchique (un jeton défini sur un chemin parent s'applique à tous les sous-chemins), Yarn Classic exige une correspondance exacte du chemin entre l'entrée `_authToken` et l'URL du registre.

Pour résoudre ce problème, utilisez le chemin complet du point de terminaison pour chaque registre avec lequel vous vous authentifiez dans votre fichier `.npmrc`. Par exemple, lors d'une installation depuis un registre de groupe où le paquet est hébergé dans un projet spécifique :

```ini
# .npmrc
//gitlab.com/api/v4/groups/<group_id>/-/packages/npm/:_authToken='<token>'
//gitlab.com/api/v4/projects/<project_id>/packages/npm/:_authToken='<token>'
```

L'entrée du projet est requise car les métadonnées du paquet renvoyées par le point de terminaison du groupe contiennent des URL de téléchargement d'archive qui pointent vers le point de terminaison du projet.

### `yarn install` échoue à cloner le dépôt en tant que dépendance {#yarn-install-fails-to-clone-repository-as-a-dependency}

Si vous utilisez `yarn install` depuis un Dockerfile, lors de la compilation du Dockerfile vous pouvez obtenir une erreur de ce type :

```plaintext
...
#6 8.621 fatal: unable to access 'https://gitlab.com/path/to/project/': Problem with the SSL CA cert (path? access rights?)
#6 8.621 info Visit https://yarnpkg.com/en/docs/cli/install for documentation about this command.
#6 ...
```

Pour résoudre ce problème, [ajoutez un point d'exclamation (`!`)](https://docs.docker.com/build/building/context/#negating-matches) à chaque chemin lié à Yarn dans votre fichier [.dockerignore](https://docs.docker.com/build/building/context/#dockerignore-files).

```dockerfile
**

!./package.json
!./yarn.lock
...
```
