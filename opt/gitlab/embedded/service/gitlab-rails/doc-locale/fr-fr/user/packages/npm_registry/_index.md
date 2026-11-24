---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Paquets npm dans le registre de paquets
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Node Package Manager (npm) est le gestionnaire de paquets par défaut pour JavaScript et Node.js. Les développeurs utilisent npm pour partager et réutiliser du code, gérer les dépendances et simplifier les workflows de projet. Dans GitLab, les paquets npm jouent un rôle crucial dans le cycle de vie du développement logiciel.

Pour plus d'informations sur les endpoints npm, consultez [l'API](../../../api/packages/npm.md).

Regardez une [démonstration vidéo](https://youtu.be/yvLxtkvsFDA) sur la façon de publier des paquets npm dans le registre de paquets GitLab.

## S'authentifier auprès du registre de paquets {#authenticate-to-the-package-registry}

Vous devez vous authentifier auprès du registre de paquets pour publier ou installer un paquet depuis un projet privé ou un groupe privé. Vous n'avez pas besoin de vous authentifier si le projet ou le groupe est public. Si le projet est interne, vous devez être un utilisateur enregistré sur l'instance GitLab. Un utilisateur anonyme ne peut pas extraire des paquets d'un projet interne.

Pour vous authentifier, vous pouvez utiliser l'un des éléments suivants :

- L'un des jetons suivants, avec la portée définie sur `api` :
  - [Jeton d'accès personnel](../../profile/personal_access_tokens.md)
  - [Jeton d'accès de groupe](../../group/settings/group_access_tokens.md)
  - [Jeton d'accès au projet](../../project/settings/project_access_tokens.md)
- Un [jeton de déploiement](../../project/deploy_tokens/_index.md) avec la portée définie sur `read_package_registry`, `write_package_registry`, ou les deux.
- Un [jeton de job CI/CD](../../../ci/jobs/ci_job_token.md) si vous souhaitez publier des paquets avec un pipeline CI/CD.

Si votre organisation utilise l'authentification à deux facteurs (2FA), vous devez utiliser un jeton d'accès personnel avec la portée définie sur `api`. Pour plus d'informations, consultez les [recommandations sur les jetons](../package_registry/supported_functionality.md#authenticate-with-the-registry).

N'utilisez pas de méthodes d'authentification autres que celles documentées ici. Les méthodes d'authentification non documentées peuvent être supprimées à l'avenir.

### Avec le fichier `.npmrc` {#with-the-npmrc-file}

Créez ou modifiez le fichier `.npmrc` dans le même répertoire que votre `package.json`. Incluez les lignes suivantes dans le fichier `.npmrc` :

```shell
  //<domain_name>/api/v4/projects/<project_id>/packages/npm/:_authToken="${NPM_TOKEN}"
```

> [!warning]
> Ne codez jamais en dur des jetons GitLab (ou tout autre jeton) directement dans des fichiers `.npmrc` ou dans tout autre fichier pouvant être commis dans un dépôt.

Par exemple :

{{< tabs >}}

{{< tab title="Pour une instance" >}}

```shell
//<domain_name>/api/v4/packages/npm/:_authToken="${NPM_TOKEN}"
```

Remplacez `<domain_name>` par votre nom de domaine. Par exemple, `gitlab.com`.

{{< /tab >}}

{{< tab title="Pour un groupe" >}}

```shell
//<domain_name>/api/v4/groups/<group_id>/-/packages/npm/:_authToken="${NPM_TOKEN}"
```

Veillez à remplacer :

- `<domain_name>` par votre nom de domaine. Par exemple, `gitlab.com`.
- `<group_id>` par l'ID de groupe figurant sur la page d'accueil du groupe.

{{< /tab >}}

{{< tab title="Pour un projet" >}}

```shell
//<domain_name>/api/v4/projects/<project_id>/packages/npm/:_authToken="${NPM_TOKEN}"
```

Veillez à remplacer :

- `<domain_name>` par votre nom de domaine. Par exemple, `gitlab.com`.
- `<project_id>` par l'ID de projet figurant sur la [page d'aperçu du projet](../../project/working_with_projects.md#find-the-project-id).

{{< /tab >}}

{{< /tabs >}}

### Avec `npm config set` {#with-npm-config-set}

Pour cela :

```shell
npm config set -- //<domain_name>/:_authToken=<token>
```

En fonction de votre version de npm, vous devrez peut-être apporter des modifications à l'URL :

- Sur npm version 7 ou antérieure, utilisez l'URL complète vers l'endpoint.
- Sur la version 8 et ultérieure, pour le paramètre `_authToken`, vous pouvez utiliser un fragment URI au lieu d'une URL complète. Pour plus d'informations, consultez [la configuration liée à l'authentification](https://docs.npmjs.com/cli/v8/configuring-npm/npmrc/?v=true#auth-related-configuration).

> [!note]
> Si vous utilisez Yarn Classic 1.x, vous devez spécifier le chemin complet de l'endpoint lors de la définition des jetons d'authentification. Yarn Classic ne prend pas en charge la correspondance d'authentification hiérarchique. Ainsi, un jeton défini sur un chemin parent tel que `//gitlab.com/api/v4/` n'est pas appliqué aux sous-chemins tels que `//gitlab.com/api/v4/groups/<group_id>/-/packages/npm/`. Utilisez toujours le chemin complet du groupe ou du projet. Pour plus d'informations, consultez [Yarn Classic renvoie `401 Unauthorized` avec des chemins d'authentification raccourcis](../yarn_repository/_index.md#yarn-classic-returns-401-unauthorized-with-shortened-authentication-paths).

Par exemple :

{{< tabs >}}

{{< tab title="Pour une instance" >}}

```shell
npm config set -- //<domain_name>/api/v4/packages/npm/:_authToken=<token>
```

Veillez à remplacer :

- `<domain_name>` par votre nom de domaine. Par exemple, `gitlab.com`.
- `<token>` par votre jeton de déploiement, jeton d'accès de groupe, jeton d'accès au projet ou jeton d'accès personnel.

{{< /tab >}}

{{< tab title="Pour un groupe" >}}

```shell
npm config set -- //<domain_name>/api/v4/groups/<group_id>/-/packages/npm/:_authToken=<token>
```

Veillez à remplacer :

- `<domain_name>` par votre nom de domaine. Par exemple, `gitlab.com`.
- `<group_id>` par l'ID de groupe figurant sur la page d'accueil du groupe.
- `<token>` par votre jeton de déploiement, jeton d'accès de groupe, jeton d'accès au projet ou jeton d'accès personnel.

{{< /tab >}}

{{< tab title="Pour un projet" >}}

```shell
npm config set -- //<domain_name>/api/v4/projects/<project_id>/packages/npm/:_authToken=<token>
```

Veillez à remplacer :

- `<domain_name>` par votre nom de domaine. Par exemple, `gitlab.com`.
- `<project_id>` par l'ID du projet.
- `<token>` par votre jeton de déploiement, jeton d'accès de groupe, jeton d'accès au projet ou jeton d'accès personnel.

{{< /tab >}}

{{< /tabs >}}

## Configurer l'URL du registre {#set-up-the-registry-url}

Pour publier ou installer des paquets depuis le registre de paquets GitLab, vous devez configurer npm pour utiliser l'URL de registre correcte. La méthode de configuration et la structure de l'URL dépendent de si vous publiez ou installez des paquets.

Avant de configurer l'URL du registre, il est important de comprendre la portée des différentes méthodes de configuration :

- Fichier `.npmrc` : la configuration est locale au dossier contenant le fichier.
- Commande `npm config set` : cette opération modifie la configuration npm globale et affecte toutes les commandes npm exécutées sur votre système.
- `publishConfig` dans `package.json` : cette configuration est spécifique au paquet et s'applique uniquement lors de la publication de ce paquet.

> [!warning]
> L'exécution de `npm config set` modifie la configuration npm globale. La modification affecte toutes les commandes npm exécutées sur votre système, quel que soit le répertoire de travail actuel. Faites preuve de prudence lorsque vous utilisez cette méthode, en particulier sur des systèmes partagés.

### Pour la publication de paquets {#for-publishing-packages}

Lors de la publication de paquets, utilisez l'endpoint du projet :

```shell
https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/
```

Remplacez `gitlab.example.com` par le domaine de votre instance GitLab et `<project_id>` par l'ID de votre projet. Pour configurer cette URL, utilisez l'une de ces méthodes :

{{< tabs >}}

{{< tab title="Fichier `.npmrc`" >}}

Créez ou modifiez le fichier `.npmrc` à la racine de votre projet :

```plaintext
@scope:registry=https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/
//gitlab.example.com/api/v4/projects/<project_id>/packages/npm/:_authToken="${NPM_TOKEN}"
```

{{< /tab >}}

{{< tab title="`npm config`" >}}

Utilisez la commande `npm config set` :

```shell
npm config set @scope:registry=https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/
```

{{< /tab >}}

{{< tab title="`package.json`" >}}

Ajoutez une section `publishConfig` à votre `package.json` :

```shell
{
  "publishConfig": {
    "@scope:registry": "https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/"
  }
}
```

{{< /tab >}}

{{< /tabs >}}

Remplacez `@scope` par la portée de votre paquet.

### Pour l'installation de paquets {#for-installing-packages}

Lorsque vous installez des paquets, vous pouvez utiliser des endpoints de projet, de groupe ou d'instance. La structure de l'URL varie en conséquence. Pour configurer ces URL, utilisez l'une de ces méthodes :

{{< tabs >}}

{{< tab title="Fichier `.npmrc`" >}}

Créez ou modifiez le fichier `.npmrc` à la racine de votre projet. Utilisez l'URL appropriée en fonction de vos besoins :

- Pour un projet :

  ```shell
  @scope:registry=https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/
  ```

- Pour un groupe :

  ```shell
  @scope:registry=https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/npm/
  ```

- Pour une instance :

  ```shell
  @scope:registry=https://gitlab.example.com/api/v4/packages/npm/
  ```

{{< /tab >}}

{{< tab title="`npm config`" >}}

Utilisez la commande `npm config set` avec l'URL appropriée :

- Pour un projet :

  ```shell
  npm config set @scope:registry=https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/
  ```

- Pour un groupe :

  ```shell
  npm config set @scope:registry=https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/npm/
  ```

- Pour une instance :

  ```shell
  npm config set @scope:registry=https://gitlab.example.com/api/v4/packages/npm/
  ```

{{< /tab >}}

{{< /tabs >}}

Remplacez `gitlab.example.com`, `<project_id>`, `<group_id>` et `@scope` par les valeurs appropriées pour votre instance GitLab et votre paquet.

Une fois votre URL de registre configurée, vous pouvez vous authentifier auprès du registre de paquets.

## Publier dans le registre de paquets GitLab {#publish-to-gitlab-package-registry}

Pour publier un paquet npm dans le registre de paquets GitLab, vous devez être authentifié.

### Convention de nommage {#naming-convention}

Selon la façon dont le paquet est installé, vous devrez peut-être respecter la convention de nommage.

Vous pouvez utiliser l'un des trois endpoints API pour installer des paquets :

- Instance : à utiliser lorsque vous avez de nombreux paquets npm dans différents groupes GitLab ou dans leur propre espace de nommage.
- Groupe : à utiliser lorsque vous avez de nombreux paquets npm dans différents projets au sein du même groupe ou sous-groupe.
- Projet : à utiliser lorsque vous avez peu de paquets npm et qu'ils ne se trouvent pas dans le même groupe GitLab.

Si vous prévoyez d'installer un paquet depuis un projet ou un groupe, vous n'avez pas à respecter la convention de nommage.

Si vous prévoyez d'installer un paquet depuis une instance, vous devez nommer votre paquet avec une portée. Les paquets avec portée commencent par `@` et ont le format `@owner/package-name`. Vous pouvez configurer la portée de votre paquet dans le fichier `.npmrc` et en utilisant l'option `publishConfig` dans le `package.json`.

- La valeur utilisée pour `@scope` est la racine du projet qui héberge les paquets, et non la racine du projet contenant le code source du paquet lui-même. La portée doit être en minuscules.
- Le nom du paquet peut être ce que vous souhaitez.

Pour plus d'informations, consultez [Paquets avec portée](https://docs.npmjs.com/cli/v11/using-npm/scope/).

| URL du projet                                             | Registre de paquets dans | Portée     | Nom complet du paquet      |
| ------------------------------------------------------- | ------------------- | --------- | ---------------------- |
| `https://gitlab.com/my-org/engineering-group/analytics` | Analytics           | `@my-org` | `@my-org/package-name` |

Assurez-vous que le nom de votre paquet dans le fichier `package.json` correspond à cette convention :

```shell
"name": "@my-org/package-name"
```

### Publier un paquet avec la ligne de commande {#publish-a-package-with-the-command-line}

Une fois l'authentification configurée, publiez le paquet NPM avec :

```shell
npm publish
```

Si vous utilisez un fichier `.npmrc` pour l'authentification, définissez les variables d'environnement requises :

```shell
NPM_TOKEN=<token> npm publish
```

Si le paquet chargé contient plusieurs fichiers `package.json`, seul le premier trouvé est utilisé ; les autres sont ignorés.

### Publier un paquet avec un pipeline CI/CD {#publish-a-package-with-a-cicd-pipeline}

Lors de la publication via un pipeline CI/CD, vous pouvez utiliser les [variables prédéfinies](../../../ci/variables/predefined_variables.md) `${CI_PROJECT_ID}` et `${CI_JOB_TOKEN}` pour vous authentifier auprès du registre de paquets de votre projet. Vous pouvez utiliser ces variables pour créer un fichier `.npmrc` pour l'authentification lors de l'exécution de votre job CI/CD.

> [!note]
> Lorsque vous générez le fichier `.npmrc`, ne spécifiez pas le port après `${CI_SERVER_HOST}` s'il s'agit d'un port par défaut. Les URL `http` utilisent par défaut le port `80`, et les URL `https` utilisent par défaut le port `443`.

Dans le projet GitLab contenant votre `package.json`, modifiez ou créez un fichier `.gitlab-ci.yml`. Par exemple :

```yaml
default:
  image: node:latest

stages:
  - deploy

publish-npm:
  stage: deploy
  script:
    - echo "@scope:registry=https://${CI_SERVER_HOST}/api/v4/projects/${CI_PROJECT_ID}/packages/npm/" > .npmrc
    - echo "//${CI_SERVER_HOST}/api/v4/projects/${CI_PROJECT_ID}/packages/npm/:_authToken=${CI_JOB_TOKEN}" >> .npmrc
    - npm publish
```

Remplacez `@scope` par la [portée](https://docs.npmjs.com/cli/v10/using-npm/scope/) du paquet en cours de publication.

Votre paquet est publié dans le registre de paquets lorsque le job `publish-npm` de votre pipeline s'exécute.

## Installer un paquet {#install-a-package}

Si plusieurs paquets ont le même nom et la même version, c'est le paquet publié le plus récemment qui est récupéré lors de l'installation.

Vous pouvez installer un paquet depuis un projet, un groupe ou une instance GitLab :

- Instance : à utiliser lorsque vous avez de nombreux paquets npm dans différents groupes GitLab ou dans leur propre espace de nommage.
- Groupe : à utiliser lorsque vous avez de nombreux paquets npm dans différents projets du même groupe GitLab.
- Projet : à utiliser lorsque vous avez peu de paquets npm et qu'ils ne se trouvent pas dans le même groupe GitLab.

### Installer depuis une instance {#install-from-an-instance}

Prérequis :

- Le paquet a été publié conformément à la convention de nommage avec portée.

1. Authentifiez-vous auprès du registre de paquets.
1. Définissez le registre :

   ```shell
   npm config set @scope:registry https://<domain_name>.com/api/v4/packages/npm/
   ```

   - Remplacez `@scope` par le groupe principal du projet depuis lequel vous installez le paquet.
   - Remplacez `<domain_name>` par votre nom de domaine, par exemple `gitlab.com`.

1. Installez le paquet :

   ```shell
   npm install @scope/my-package
   ```

### Installer depuis un groupe {#install-from-a-group}

1. Authentifiez-vous auprès du registre de paquets.
1. Définissez le registre :

   ```shell
   npm config set @scope:registry=https://<domain_name>/api/v4/groups/<group_id>/-/packages/npm/
   ```

   - Remplacez `@scope` par le groupe principal du groupe depuis lequel vous installez le paquet.
   - Remplacez `<domain_name>` par votre nom de domaine, par exemple, `gitlab.com`.
   - Remplacez `<group_id>` par l'ID de votre groupe, disponible sur la page d'accueil du groupe.

1. Installez le paquet :

   ```shell
   npm install @scope/my-package
   ```

### Installer depuis un projet {#install-from-a-project}

1. Authentifiez-vous auprès du registre de paquets.
1. Définissez le registre :

   ```shell
   npm config set @scope:registry=https://<domain_name>/api/v4/projects/<project_id>/packages/npm/
   ```

   - Remplacez `@scope` par le [groupe principal](#naming-convention) du projet depuis lequel vous installez le paquet.
   - Remplacez `<domain_name>` par votre nom de domaine, par exemple, `gitlab.com`.
   - Remplacez `<project_id>` par l'ID de votre projet, disponible sur la [page d'aperçu du projet](../../project/working_with_projects.md#find-the-project-id).

1. Installez le paquet :

   ```shell
   npm install @scope/my-package
   ```

### Installer un paquet dans un pipeline CI/CD {#install-a-package-inside-a-cicd-pipeline}

Lors de l'installation d'un paquet dans un pipeline CI/CD, vous pouvez utiliser les variables prédéfinies `${CI_PROJECT_ID}` et `${CI_JOB_TOKEN}` pour vous authentifier auprès du registre de paquets de votre projet. Vous pouvez utiliser ces variables pour créer un fichier `.npmrc` pour l'authentification lors de l'exécution de votre job CI/CD.

> [!note]
> Lorsque vous générez le fichier `.npmrc`, ne spécifiez pas le port après `${CI_SERVER_HOST}` s'il s'agit d'un port par défaut. Les URL `http` utilisent par défaut le port `80`, et les URL `https` utilisent par défaut le port `443`.

Dans le projet GitLab contenant votre `package.json`, modifiez ou créez un fichier `.gitlab-ci.yml`. Par exemple :

```yaml
default:
  image: node:latest

stages:
  - deploy

publish-npm:
  stage: deploy
  script:
    - echo "@scope:registry=https://${CI_SERVER_HOST}/api/v4/projects/${CI_PROJECT_ID}/packages/npm/" > .npmrc
    - echo "//${CI_SERVER_HOST}/api/v4/projects/${CI_PROJECT_ID}/packages/npm/:_authToken=${CI_JOB_TOKEN}" >> .npmrc
    - npm install @scope/my-package
```

Remplacez `@scope` par la portée du paquet en cours d'installation, ainsi que par le nom du paquet.

L'exemple précédent utilise l'endpoint au niveau du projet. Pour utiliser un endpoint au niveau du groupe ou de l'instance, configurez le registre et les URL des jetons d'authentification comme décrit dans les sections « Installer depuis un groupe » ou « Installer depuis une instance ».

### Transfert de paquets vers npmjs.com {#package-forwarding-to-npmjscom}

{{< history >}}

- Le rôle requis est [passé](https://gitlab.com/gitlab-org/gitlab/-/issues/370471) de Maintainer à Owner dans GitLab 17.0.

{{< /history >}}

Lorsqu'un paquet npm est introuvable dans le registre de paquets, GitLab répond par une redirection HTTP afin que le client demandeur puisse renvoyer la requête vers `npmjs.com`.

Les administrateurs peuvent désactiver ce comportement dans les [paramètres d'intégration continue](../../../administration/settings/continuous_integration.md).

Les propriétaires de groupe peuvent désactiver ce comportement dans les paramètres **Paquets et registres** du groupe.

Les améliorations sont suivies dans l'[epic 3608](https://gitlab.com/groups/gitlab-org/-/epics/3608).

## Déprécier un paquet {#deprecate-a-package}

Vous pouvez déprécier un paquet afin qu'un avertissement de dépréciation s'affiche lors de la récupération du paquet.

Prérequis :

- Vous disposez des [autorisations](../../permissions.md) nécessaires pour supprimer un paquet.
- Vous êtes authentifié auprès du registre de paquets.

Depuis la ligne de commande, exécutez :

```shell
npm deprecate @scope/package "Deprecation message"
```

L'interface de ligne de commande accepte également des plages de versions pour `@scope/package`. Par exemple :

```shell
npm deprecate @scope/package "All package versions are deprecated"
npm deprecate @scope/package@1.0.1 "Only version 1.0.1 is deprecated"
npm deprecate @scope/package@"< 1.0.5" "All package versions less than 1.0.5 are deprecated"
```

Lorsqu'un paquet est déprécié, son statut est mis à jour vers `deprecated`.

### Supprimer l'avertissement de dépréciation {#remove-deprecation-warning}

Pour supprimer l'avertissement de dépréciation d'un paquet, spécifiez `""` (une chaîne vide) pour le message. Par exemple :

```shell
npm deprecate @scope/package ""
```

Lorsque l'avertissement de dépréciation d'un paquet est supprimé, son statut est mis à jour vers `default`.

## Supprimer un paquet {#delete-a-package}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire.

Avant de supprimer un paquet, assurez-vous de comprendre les [risques de sécurité associés](../package_registry/supported_functionality.md#deleting-packages).

Pour supprimer un paquet, vous pouvez :

- [Utiliser l'interface utilisateur](../package_registry/reduce_package_registry_storage.md#delete-a-package).
- [Utiliser l'API](../../../api/packages.md#delete-a-project-package).

## Conseils utiles {#helpful-hints}

### Installer des paquets npm depuis d'autres organisations {#install-npm-packages-from-other-organizations}

Vous pouvez acheminer les requêtes de paquets vers des organisations et des utilisateurs extérieurs à GitLab.

Pour ce faire, ajoutez des lignes à votre fichier `.npmrc`. Remplacez `@my-other-org` par l'espace de nommage ou le groupe propriétaire du dépôt de votre projet, et utilisez l'URL de votre organisation. Le nom est sensible à la casse et doit correspondre exactement au nom de votre groupe ou espace de nommage.

```shell
@scope:registry=https://my_domain_name.com/api/v4/packages/npm/
@my-other-org:registry=https://my_domain_name.example.com/api/v4/packages/npm/
```

### Métadonnées npm {#npm-metadata}

Le registre de paquets GitLab expose les attributs suivants au client npm :

- `name`
- `versions`
  - `name`
  - `version`
  - `deprecated`
  - `dependencies`
  - `devDependencies`
  - `bundleDependencies`
  - `peerDependencies`
  - `bin`
  - `directories`
  - `dist`
  - `engines`
  - `_hasShrinkwrap`
  - `hasInstallScript` : `true` (si cette version contient les scripts d'installation)

Pour plus d'informations, consultez [Abbreviated version object](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md#abbreviated-version-object).

### Ajouter des tags de distribution npm {#add-npm-distribution-tags}

Vous pouvez ajouter des [tags de distribution](https://docs.npmjs.com/cli/dist-tag/) aux paquets récemment publiés. Les tags sont facultatifs et ne peuvent être attribués qu'à un seul paquet à la fois.

Lorsque vous publiez un paquet sans tag, le tag `latest` est ajouté par défaut. Lorsque vous installez un paquet sans spécifier le tag ou la version, le tag `latest` est utilisé.

Exemples de commandes `dist-tag` prises en charge :

```shell
npm publish @scope/package --tag               # Publish a package with new tag
npm dist-tag add @scope/package@version my-tag # Add a tag to an existing package
npm dist-tag ls @scope/package                 # List all tags under the package
npm dist-tag rm @scope/package@version my-tag  # Delete a tag from the package
npm install @scope/package@my-tag              # Install a specific tag
```

#### Depuis CI/CD {#from-cicd}

Vous pouvez utiliser l'un des jetons suivants pour exécuter des commandes `npm dist-tag` dans un job GitLab CI/CD :

- [`CI_JOB_TOKEN`](../../../ci/jobs/ci_job_token.md)
- Jeton de déploiement

Prérequis :

- Vous disposez de npm version 6.9.1 ou ultérieure. Dans les versions antérieures, la suppression des tags de distribution échoue en raison d'un bug dans npm 6.9.0.

Par exemple :

```yaml
npm-deploy-job:
  script:
    - echo "//${CI_SERVER_HOST}/api/v4/projects/${CI_PROJECT_ID}/packages/npm/:_authToken=${CI_JOB_TOKEN}">.npmrc
    - npm dist-tag add @scope/package@version my-tag
```

### Auditer les paquets npm {#audit-npm-packages}

GitLab prend en charge les commandes `npm audit`, vous permettant de vérifier vos paquets pour détecter des vulnérabilités connues.

#### Utiliser `npm audit` {#use-npm-audit}

Prérequis :

- Configurez l'authentification auprès du registre de paquets.
- Configurez l'URL du registre.

Pour exécuter des audits de sécurité, vous pouvez exécuter la commande suivante :

```shell
npm audit --registry=https://gitlab.example.com/api/v4/packages/npm/
```

Ou, si vous avez déjà défini votre configuration de registre :

```shell
npm audit
```

La commande `npm audit` vérifie vos dépendances pour détecter des vulnérabilités connues et fournit un rapport.

#### Workflow `npm audit` {#npm-audit-workflow}

Lorsque vous exécutez `npm audit` contre le registre de paquets GitLab, l'un des deux scénarios suivants se produit :

1. Si le transfert de paquets est activé (comportement par défaut), GitLab transfère la requête d'audit vers `npmjs.com` pour récupérer les informations de vulnérabilité des paquets publics et privés.
1. Si le transfert de paquets est désactivé, GitLab renvoie un ensemble de résultats vide. GitLab n'analyse pas les paquets pour détecter des vulnérabilités de manière indépendante.

#### Considérations de sécurité importantes {#important-security-considerations}

Si vous ne spécifiez pas GitLab comme registre de paquets (soit avec l'indicateur `--registry`, soit en le définissant comme registre par défaut dans le fichier `.npmrc`), la requête d'audit est envoyée au registre npm public à la place.

Dans ce cas, le corps de la requête contient des informations sur tous les paquets de votre projet, y compris vos paquets GitLab privés.

Pour vous assurer que les informations de vos paquets privés restent dans GitLab, veillez toujours à spécifier le registre GitLab lors de l'exécution des commandes `npm audit`.

#### Problèmes connus {#known-issues}

- Les résultats de l'audit dépendent de l'activation du transfert de paquets. Si le transfert est désactivé par un administrateur ou un propriétaire de groupe, `npm audit` ne renvoie pas d'informations sur les vulnérabilités.
- La requête d'audit inclut des informations sur tous les paquets de votre projet, y compris les paquets privés.

### Commandes CLI prises en charge {#supported-cli-commands}

Le dépôt npm de GitLab prend en charge les commandes suivantes pour le CLI npm (`npm`) et le CLI yarn (`yarn`) :

- `npm install` : installer des paquets npm.
- `npm publish` : publier un paquet npm dans le registre.
- `npm dist-tag add` : ajouter un dist-tag à un paquet npm.
- `npm dist-tag ls` : lister les dist-tags d'un paquet.
- `npm dist-tag rm` : supprimer un dist-tag.
- `npm ci` : installer des paquets npm directement depuis votre fichier `package-lock.json`.
- `npm view` : afficher les métadonnées du paquet.
- `npm pack` : créer une archive tar à partir d'un paquet.
- `npm deprecate` : déprécier une version d'un paquet.
- `npm audit` : vérifier les vulnérabilités dans les dépendances de votre projet.

## Dépannage {#troubleshooting}

### Les journaux npm ne s'affichent pas correctement {#npm-logs-dont-display-correctly}

Vous pouvez rencontrer une erreur indiquant :

```shell
npm ERR! A complete log of this run can be found in: .npm/_logs/<date>-debug-0
```

Si le journal n'apparaît pas dans le répertoire `.npm/_logs/`, vous pouvez copier le journal dans votre répertoire racine et le consulter à cet emplacement :

```yaml
  script:
    - npm install --loglevel verbose
    - cp -r /root/.npm/_logs/ .
  artifacts:
    paths:
      - './_logs'
```

Le journal npm est copié dans `/root/.npm/_logs/` en tant qu'artefact.

### Des erreurs `404 Not Found` se produisent sur `npm install` ou `yarn` {#404-not-found-errors-are-happening-on-npm-install-or-yarn}

L'utilisation de `CI_JOB_TOKEN` pour installer des paquets npm avec des dépendances dans un autre projet génère des erreurs 404 Not Found. Vous devez vous authentifier avec un jeton ayant accès au paquet et à toutes ses dépendances.

Lorsque vous installez un paquet depuis un registre de groupe avec Yarn Classic, la résolution du paquet peut réussir mais le téléchargement de l'archive tar peut échouer avec une erreur `404 Not Found`. Cette erreur se produit car les métadonnées du paquet renvoyées par l'endpoint de groupe contiennent des URL d'archives tar qui pointent vers l'endpoint du projet. Vous devez configurer des jetons d'authentification pour les endpoints du groupe et du projet :

```ini
//gitlab.example.com/api/v4/groups/<group_id>/-/packages/npm/:_authToken=<token>
//gitlab.example.com/api/v4/projects/<project_id>/packages/npm/:_authToken=<token>
```

Pour plus d'informations, consultez [Yarn Classic renvoie `404 Not Found` lors de la récupération d'une archive tar depuis une installation de groupe](../yarn_repository/_index.md#yarn-classic-returns-404-not-found-when-fetching-a-tarball-from-a-group-install).

Si le paquet et ses dépendances se trouvent dans des projets distincts mais dans le même groupe, vous pouvez utiliser un [jeton de déploiement de groupe](../../project/deploy_tokens/_index.md#create-a-deploy-token) :

```ini
//gitlab.example.com/api/v4/packages/npm/:_authToken=<group-token>
@group-scope:registry=https://gitlab.example.com/api/v4/packages/npm/
```

Si le paquet et ses dépendances sont répartis sur plusieurs groupes, vous pouvez utiliser un jeton d'accès personnel d'un utilisateur ayant accès à tous les groupes ou projets individuels :

```ini
//gitlab.example.com/api/v4/packages/npm/:_authToken=<personal-access-token>
@group-1:registry=https://gitlab.example.com/api/v4/packages/npm/
@group-2:registry=https://gitlab.example.com/api/v4/packages/npm/
```

> [!warning]
> Les jetons d'accès personnels doivent être traités avec soin. Consultez nos [considérations de sécurité relatives aux jetons](../../../security/tokens/_index.md#security-considerations) pour obtenir des conseils sur la gestion des jetons d'accès personnels (par exemple, définir une courte durée d'expiration et utiliser des portées minimales).

### `npm publish` cible le registre npm par défaut (`registry.npmjs.org`) {#npm-publish-targets-default-npm-registry-registrynpmjsorg}

Assurez-vous que la portée de votre paquet est définie de manière cohérente dans vos fichiers `package.json` et `.npmrc`.

Par exemple, si le nom de votre projet dans GitLab est `@scope/my-package`, votre fichier `package.json` doit ressembler à :

```json
{
  "name": "@scope/my-package"
}
```

Et le fichier `.npmrc` doit ressembler à :

```shell
@scope:registry=https://your_domain_name/api/v4/projects/your_project_id/packages/npm/
//your_domain_name/api/v4/projects/your_project_id/packages/npm/:_authToken="${NPM_TOKEN}"
```

### `npm install` renvoie `npm ERR! 403 Forbidden` {#npm-install-returns-npm-err-403-forbidden}

Si vous obtenez cette erreur, vérifiez que :

- Le registre de paquets est activé dans les paramètres de votre projet. Bien que le registre de paquets soit activé par défaut, il est possible de [le désactiver](../package_registry/_index.md#turn-off-the-package-registry).
- Votre jeton n'est pas expiré et dispose des autorisations appropriées.
- Un paquet portant le même nom ou la même version n'existe pas déjà dans la portée donnée.
- L'URL des paquets avec portée inclut une barre oblique finale :
  - Correct : `//gitlab.example.com/api/v4/packages/npm/`
  - Incorrect : `//gitlab.example.com/api/v4/packages/npm`

### `npm publish` renvoie `npm ERR! 400 Bad Request` {#npm-publish-returns-npm-err-400-bad-request}

Si vous obtenez cette erreur, l'un des problèmes suivants pourrait en être la cause.

### Le nom du paquet ne respecte pas la convention de nommage {#package-name-does-not-meet-the-naming-convention}

Le nom de votre paquet peut ne pas respecter la convention de nommage de paquet `@scope/package-name`.

Assurez-vous que le nom respecte exactement la convention, y compris la casse. Essayez ensuite de publier à nouveau.

### Le paquet existe déjà {#package-already-exists}

Votre paquet a déjà été publié dans un autre projet du même espace de nommage racine et ne peut donc pas être publié à nouveau sous le même nom.

Cela est également vrai même si le paquet précédemment publié partage le même nom, mais pas la même version.

### Le fichier JSON du paquet est trop volumineux {#package-json-file-is-too-large}

Assurez-vous que votre fichier `package.json` ne dépasse pas `20,000` caractères.
