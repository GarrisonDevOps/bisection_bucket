---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Paquets NuGet dans le registre de paquets
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Publiez des paquets NuGet dans le registre de paquets de votre projet. Installez ensuite les paquets chaque fois que vous devez les utiliser comme dépendance.

Le registre de paquets fonctionne avec :

- [NuGet CLI](https://learn.microsoft.com/en-us/nuget/reference/nuget-exe-cli-reference)
- [.NET Core CLI](https://learn.microsoft.com/en-us/dotnet/core/tools/)
- [Visual Studio](https://visualstudio.microsoft.com/vs/)

Pour en savoir plus sur les endpoints d'API spécifiques utilisés par ces clients, consultez la [référence de l'API NuGet](../../../api/packages/nuget.md).

Apprenez comment [installer NuGet](../workflows/build_packages.md#nuget).

## S'authentifier auprès du registre de paquets {#authenticate-to-the-package-registry}

Vous avez besoin d'un jeton d'authentification pour accéder au registre de paquets GitLab. Différents jetons sont disponibles selon ce que vous essayez d'accomplir. Pour plus d'informations, consultez les [conseils sur les jetons](../package_registry/supported_functionality.md#authenticate-with-the-registry).

- Si votre organisation utilise l'authentification à deux facteurs (2FA), vous devez utiliser un [jeton d'accès personnel](../../profile/personal_access_tokens.md) avec la portée définie sur `api`.
- Si vous publiez un paquet avec des pipelines CI/CD, vous pouvez utiliser un [jeton de job CI/CD](../../../ci/jobs/ci_job_token.md) avec des runners privés. Vous pouvez également [enregistrer une variable](https://docs.gitlab.com/runner/register/#register-with-a-runner-authentication-token) pour les runners d'instance.

## Utiliser l'endpoint GitLab pour les paquets NuGet {#use-the-gitlab-endpoint-for-nuget-packages}

Vous pouvez utiliser un endpoint de projet ou de groupe pour interagir avec le registre de paquets GitLab :

- Endpoint de projet : à utiliser lorsque vous avez quelques paquets NuGet qui ne sont pas dans le même groupe.
- Endpoint de groupe : à utiliser lorsque vous avez de nombreux paquets NuGet dans différents projets sous le même groupe.

Certaines actions, comme la publication d'un paquet, sont uniquement disponibles sur l'endpoint de projet.

En raison de la façon dont NuGet gère les identifiants, le registre de paquets rejette les requêtes anonymes vers les groupes publics.

## Ajouter le registre de paquets comme source pour les paquets NuGet {#add-the-package-registry-as-a-source-for-nuget-packages}

Pour publier et installer des paquets dans le registre de paquets, vous devez ajouter le registre de paquets comme source pour vos paquets.

Prérequis :

- Votre nom d'utilisateur GitLab
- Un jeton d'authentification (les sections suivantes supposent l'utilisation d'un jeton d'accès personnel)
- Un nom pour votre source
- Un ID de projet ou de groupe

### Avec l'endpoint de projet {#with-the-project-endpoint}

{{< tabs >}}

{{< tab title="NuGet CLI" >}}

Pour ajouter le registre de paquets comme source avec NuGet CLI, exécutez la commande suivante :

```shell
nuget source Add -Name <source_name> -Source "https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/index.json" -UserName <gitlab_username> -Password <personal_access_token>
```

Remplacez :

- `<source_name>` par le nom de votre source
- `<project_id>` par l'ID de projet trouvé sur la [page de présentation du projet](../../project/working_with_projects.md#find-the-project-id)
- `<gitlab_username>` par votre nom d'utilisateur GitLab
- `<personal_access_token>` par votre jeton d'accès personnel

Par exemple :

```shell
nuget source Add -Name "GitLab" -Source "https://gitlab.example.com/api/v4/projects/10/packages/nuget/index.json" -UserName carol -Password <your_access_token>
```

{{< /tab >}}

{{< tab title=".NET CLI" >}}

Pour ajouter le registre de paquets comme source avec l'interface CLI .NET, exécutez la commande suivante :

```shell
dotnet nuget add source "https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/index.json" --name <source_name> --username <gitlab_username> --password <personal_access_token>
```

Remplacez :

- `<source_name>` par le nom de votre source
- `<project_id>` par l'ID de projet trouvé sur la [page de présentation du projet](../../project/working_with_projects.md#find-the-project-id)
- `<gitlab_username>` par votre nom d'utilisateur GitLab
- `<personal_access_token>` par votre jeton d'accès personnel

Selon votre système d'exploitation, vous devrez peut-être ajouter `--store-password-in-clear-text` à la commande.

Par exemple :

```shell
dotnet nuget add source "https://gitlab.example.com/api/v4/projects/10/packages/nuget/index.json" --name gitlab --username carol --password <your_access_token> --store-password-in-clear-text
```

{{< /tab >}}

{{< tab title="Chocolatey CLI" >}}

Vous pouvez ajouter le registre de paquets comme flux source avec la CLI Chocolatey. Si vous utilisez la CLI Chocolatey v1.X, vous ne pouvez ajouter qu'un flux source NuGet v2.

Pour ajouter le registre de paquets comme source pour Chocolatey, exécutez la commande suivante :

```shell
choco source add -n=<source_name> -s "'https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/v2'" -u=<gitlab_username> -p=<personal_access_token>
```

Remplacez :

- `<source_name>` par le nom de votre source
- `<project_id>` par l'ID de projet trouvé sur la [page de présentation du projet](../../project/working_with_projects.md#find-the-project-id)
- `<gitlab_username>` par votre nom d'utilisateur GitLab
- `<personal_access_token>` par votre jeton d'accès personnel

Par exemple :

```shell
choco source add -n=gitlab -s "'https://gitlab.example.com/api/v4/projects/10/packages/nuget/v2'" -u=carol -p=<your_access_token>
```

{{< /tab >}}

{{< tab title="Visual Studio" >}}

Pour ajouter le registre de paquets comme source avec Visual Studio :

1. Ouvrez [Visual Studio](https://visualstudio.microsoft.com/vs/).
1. Sous Windows, sélectionnez **Outils** > **Options**. Sous macOS, sélectionnez **Visual Studio** > **Préférences**.
1. Dans la section **NuGet**, sélectionnez **Sources** pour afficher la liste de toutes vos sources NuGet.
1. Sélectionnez **Ajouter**.
1. Remplissez les champs suivants :

   - **Nom** : nom de la source.
   - **Source** : `https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/index.json`, où `<project_id>` est l'ID de votre projet et `gitlab.example.com` est votre nom de domaine.

1. Sélectionnez **Enregistrer**.
1. Lorsque vous accédez au paquet, vous devez saisir votre **Nom d'utilisateur** et votre **Mot de passe** :

   - **Nom d'utilisateur** : votre nom d'utilisateur GitLab.
   - **Mot de passe** : votre jeton d'accès personnel.

La source s'affiche dans votre liste.

Si vous recevez un avertissement, vérifiez que la **Source**, le **Nom d'utilisateur** et le **Mot de passe** sont corrects.

{{< /tab >}}

{{< tab title="Fichier de configuration" >}}

Pour ajouter le registre de paquets comme source avec un fichier de configuration .NET :

1. À la racine de votre projet, créez un fichier nommé `nuget.config`.
1. Ajoutez la configuration suivante :

   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <configuration>
    <packageSources>
        <clear />
        <add key="gitlab" value="https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/index.json" />
    </packageSources>
    <packageSourceCredentials>
        <gitlab>
            <add key="Username" value="%GITLAB_PACKAGE_REGISTRY_USERNAME%" />
            <add key="ClearTextPassword" value="%GITLAB_PACKAGE_REGISTRY_PASSWORD%" />
        </gitlab>
    </packageSourceCredentials>
   </configuration>
   ```

1. Configurez les variables d'environnement nécessaires :

   ```shell
   export GITLAB_PACKAGE_REGISTRY_USERNAME=<gitlab_username>
   export GITLAB_PACKAGE_REGISTRY_PASSWORD=<personal_access_token>
   ```

{{< /tab >}}

{{< /tabs >}}

> [!note]
> Les exemples de commandes précédents ajoutent une source nommée `gitlab`. Les exemples de commandes suivants font référence au nom de la source (`gitlab`), et non à l'URL de la source.

### Avec l'endpoint de groupe {#with-the-group-endpoint}

{{< tabs >}}

{{< tab title="NuGet CLI" >}}

Pour ajouter le registre de paquets comme source avec la CLI NuGet :

```shell
nuget source Add -Name <source_name> -Source "https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/nuget/index.json" -UserName <gitlab_username> -Password <personal_access_token>
```

Remplacez :

- `<source_name>` par le nom de votre source
- `<group_id>` par l'ID de groupe trouvé sur la [page de présentation du groupe](../../group/_index.md#find-the-group-id)
- `<gitlab_username>` par votre nom d'utilisateur GitLab
- `<personal_access_token>` par votre jeton d'accès personnel

Par exemple :

```shell
nuget source Add -Name "GitLab" -Source "https://gitlab.example.com/api/v4/groups/23/-/packages/nuget/index.json" -UserName carol -Password <your_access_token>
```

{{< /tab >}}

{{< tab title=".NET CLI" >}}

Pour ajouter le registre de paquets comme source avec l'interface CLI .NET :

```shell
dotnet nuget add source "https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/nuget/index.json" --name <source_name> --username <gitlab_username> --password <personal_access_token>
```

Remplacez :

- `<source_name>` par le nom de votre source
- `<group_id>` par l'ID de groupe trouvé sur la [page de présentation du groupe](../../group/_index.md#find-the-group-id)
- `<gitlab_username>` par votre nom d'utilisateur GitLab
- `<personal_access_token>` par votre jeton d'accès personnel

L'option `--store-password-in-clear-text` peut être nécessaire selon votre système d'exploitation.

Par exemple :

```shell
dotnet nuget add source "https://gitlab.example.com/api/v4/groups/23/-/packages/nuget/index.json" --name gitlab --username carol --password <your_access_token> --store-password-in-clear-text
```

{{< /tab >}}

{{< tab title="Chocolatey CLI" >}}

La CLI Chocolatey est uniquement compatible avec l'[endpoint de projet](#with-the-project-endpoint).

{{< /tab >}}

{{< tab title="Visual Studio" >}}

Pour ajouter le registre de paquets comme source avec Visual Studio :

1. Ouvrez [Visual Studio](https://visualstudio.microsoft.com/vs/).
1. Sous Windows, sélectionnez **Outils** > **Options**. Sous macOS, sélectionnez **Visual Studio** > **Préférences**.
1. Dans la section **NuGet**, sélectionnez **Sources** pour afficher la liste de toutes vos sources NuGet.
1. Sélectionnez **Ajouter**.
1. Remplissez les champs suivants :

   - **Nom** : nom de la source.
   - **Source** : `https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/nuget/index.json`, où `<group_id>` est l'ID de votre groupe et `gitlab.example.com` est votre nom de domaine.

1. Sélectionnez **Enregistrer**.
1. Lorsque vous accédez au paquet, vous devez saisir votre **Nom d'utilisateur** et votre **Mot de passe**.

   - **Nom d'utilisateur** : votre nom d'utilisateur GitLab.
   - **Mot de passe** : votre jeton d'accès personnel.

La source s'affiche dans votre liste.

Si vous recevez un avertissement, vérifiez que la **Source**, le **Nom d'utilisateur** et le **Mot de passe** sont corrects.

{{< /tab >}}

{{< tab title="Fichier de configuration" >}}

Pour ajouter le registre de paquets comme source avec un fichier de configuration .NET :

1. À la racine de votre projet, créez un fichier nommé `nuget.config`.
1. Ajoutez la configuration suivante :

   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <configuration>
    <packageSources>
        <clear />
        <add key="gitlab" value="https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/nuget/index.json" />
    </packageSources>
    <packageSourceCredentials>
        <gitlab>
            <add key="Username" value="%GITLAB_PACKAGE_REGISTRY_USERNAME%" />
            <add key="ClearTextPassword" value="%GITLAB_PACKAGE_REGISTRY_PASSWORD%" />
        </gitlab>
    </packageSourceCredentials>
   </configuration>
   ```

1. Configurez les variables d'environnement nécessaires :

   ```shell
   export GITLAB_PACKAGE_REGISTRY_USERNAME=<gitlab_username>
   export GITLAB_PACKAGE_REGISTRY_PASSWORD=<personal_access_token>
   ```

{{< /tab >}}

{{< /tabs >}}

> [!note]
> Les exemples de commandes précédents ajoutent une source nommée `gitlab`. Les exemples de commandes suivants font référence au nom de la source (`gitlab`), et non à l'URL de la source.

## Publier un paquet {#publish-a-package}

Prérequis :

- Configurez le registre de paquets comme [source](#add-the-package-registry-as-a-source-for-nuget-packages).
- Configurez l'[endpoint de projet GitLab pour les paquets NuGet](#with-the-project-endpoint).

Lors de la publication de paquets :

- Vérifiez les limites de taille de fichier maximale pour votre instance GitLab :
  - Les [limites du registre de paquets sur les instances GitLab.com](../../gitlab_com/_index.md#package-registry-limits) varient selon le format de fichier et ne sont pas configurables.
  - Les [limites du registre de paquets sur les instances GitLab Self-Managed](../../../administration/instance_limits.md#file-size-limits) varient selon le format de fichier et sont configurables.
- Si les doublons sont autorisés et que vous publiez le même paquet avec la même version plusieurs fois, chaque importation consécutive est enregistrée en tant que fichier distinct. Lors de l'installation d'un paquet, GitLab sert le fichier le plus récent.
- La plupart des paquets importés doivent être immédiatement visibles dans la page **Registre de paquets**. Certains paquets peuvent nécessiter jusqu'à 10 minutes avant d'être visibles s'ils doivent être traités en arrière-plan.

### Avec NuGet CLI {#with-nuget-cli}

Prérequis :

- [Un paquet NuGet créé avec NuGet CLI](https://learn.microsoft.com/en-us/nuget/create-packages/creating-a-package).

Pour publier un paquet, exécutez la commande suivante :

```shell
nuget push <package_file> -Source <source_name>
```

Remplacez :

- `<package_file>` par le nom de fichier de votre paquet, se terminant par `.nupkg`.
- `<source_name>` par le nom de votre source.

Par exemple :

```shell
nuget push MyPackage.1.0.0.nupkg -Source gitlab
```

### Avec l'interface CLI .NET {#with-net-cli}

Prérequis :

- [Un paquet NuGet créé avec l'interface CLI .NET](https://learn.microsoft.com/en-us/nuget/create-packages/creating-a-package-dotnet-cli).

Pour publier un paquet, exécutez la commande suivante :

```shell
dotnet nuget push <package_file> --source <source_name>
```

Remplacez :

- `<package_file>` par le nom de fichier de votre paquet, se terminant par `.nupkg`.
- `<source_name>` par le nom de votre source.

Par exemple :

```shell
dotnet nuget push MyPackage.1.0.0.nupkg --source gitlab
```

Vous pouvez publier un paquet en utilisant l'option `--api-key` à la place de `username` et `password` :

```shell
dotnet nuget push <package_file> --source <source_url> --api-key <personal_access_token>
```

Remplacez :

- `<package_file>` par le nom de fichier de votre paquet, se terminant par `.nupkg`.
- `<source_url>` par l'URL du registre de paquets NuGet.

Par exemple :

```shell
dotnet nuget push MyPackage.1.0.0.nupkg --source https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/index.json --api-key <personal_access_token>
```

### Avec la CLI Chocolatey {#with-chocolatey-cli}

Prérequis :

- Une source utilisant un [endpoint de projet](#with-the-project-endpoint).

Pour publier un paquet avec la CLI Chocolatey, exécutez la commande suivante :

```shell
choco push <package_file> --source <source_url> --api-key <gitlab_personal_access_token, deploy_token or job token>
```

Remplacez :

- `<package_file>` par le nom de fichier de votre paquet, se terminant par `.nupkg`.
- `<source_url>` par l'URL du registre de paquets du flux NuGet v2.

Par exemple :

```shell
choco push MyPackage.1.0.0.nupkg --source "https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/v2" --api-key <personal_access_token>
```

### Avec un pipeline CI/CD {#with-a-cicd-pipeline}

Si vous publiez des paquets NuGet avec GitLab CI/CD, vous pouvez utiliser une [variable prédéfinie `CI_JOB_TOKEN`](../../../ci/jobs/ci_job_token.md) à la place d'un jeton d'accès personnel ou d'un jeton de déploiement. Le jeton de job hérite des permissions de l'utilisateur ou du membre qui génère le pipeline.

Les exemples des sections suivantes présentent les workflows de publication NuGet courants lors de l'utilisation d'un pipeline CI/CD.

#### Publier des paquets lors de la mise à jour de la branche par défaut {#publish-packages-when-the-default-branch-is-updated}

Pour publier de nouveaux paquets à chaque mise à jour de la branche `main` :

1. Dans le fichier `.gitlab-ci.yml` de votre projet, ajoutez le job `deploy` suivant :

   ```yaml
   default:
     # Updated to a more current SDK version
     image: mcr.microsoft.com/dotnet/sdk:7.0

   stages:
     - deploy

   deploy:
     stage: deploy
     script:
       # Build the package in Release configuration
       - dotnet pack -c Release
       # Configure GitLab package registry as a NuGet source
       - dotnet nuget add source "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/nuget/index.json" --name gitlab --username gitlab-ci-token --password $CI_JOB_TOKEN --store-password-in-clear-text
       # Push the package to the project's package registry
       - dotnet nuget push "bin/Release/*.nupkg" --source gitlab
     rules:
       - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH  # Only run on the main branch
     environment: production
   ```

1. Commitez les modifications et poussez-les vers votre dépôt GitLab pour déclencher un nouveau build CI/CD.

#### Publier des paquets versionnés avec des tags Git {#publish-versioned-packages-with-git-tags}

Pour publier des paquets NuGet versionnés avec des [tags Git](../../project/repository/tags/_index.md) :

1. Dans le fichier `.gitlab-ci.yml` de votre projet, ajoutez le job `deploy` suivant :

   ```yaml
   publish-tagged-version:
     stage: deploy
     script:
       # Use the Git tag as the package version
       - dotnet pack -c Release /p:Version=${CI_COMMIT_TAG} /p:PackageVersion=${CI_COMMIT_TAG}
       # Configure GitLab package registry as a NuGet source
       - dotnet nuget add source "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/nuget/index.json" --name gitlab --username gitlab-ci-token --password $CI_JOB_TOKEN --store-password-in-clear-text
       # Push the package to the project's package registry
       - dotnet nuget push "bin/Release/*.nupkg" --source gitlab
     rules:
       - if: $CI_COMMIT_TAG  # Only run when a tag is pushed
   ```

1. Commitez les modifications et poussez-les vers votre dépôt GitLab.
1. Poussez un tag Git pour déclencher un nouveau build CI/CD.

#### Publier de manière conditionnelle pour différents environnements {#publish-conditionally-for-different-environments}

Vous pouvez configurer le pipeline CI/CD pour publier conditionnellement des paquets NuGet dans différents environnements selon votre cas d'usage.

Pour publier conditionnellement des paquets NuGet pour les environnements `development` et `production` :

1. Dans le fichier `.gitlab-ci.yml` de votre projet, ajoutez les jobs `deploy` suivants :

   ```yaml
     # Publish development/preview packages
   publish-dev:
     stage: deploy
     script:
       # Create a development version with pipeline ID for uniqueness
       - VERSION="0.0.1-dev.${CI_PIPELINE_IID}"
       - dotnet pack -c Release /p:Version=$VERSION /p:PackageVersion=$VERSION
       # Configure GitLab package registry as a NuGet source
       - dotnet nuget add source "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/nuget/index.json" --name gitlab --username gitlab-ci-token --password $CI_JOB_TOKEN --store-password-in-clear-text
       # Push the package to the project's package registry
       - dotnet nuget push "bin/Release/*.nupkg" --source gitlab
     rules:
       - if: $CI_COMMIT_BRANCH == "develop"
     environment: development

     # Publish stable release packages
   publish-release:
     stage: deploy
     script:
       - dotnet pack -c Release
       # Configure GitLab package registry as a NuGet source
       - dotnet nuget add source "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/nuget/index.json" --name gitlab --username gitlab-ci-token --password $CI_JOB_TOKEN --store-password-in-clear-text
       # Push the package to the project's package registry
       - dotnet nuget push "bin/Release/*.nupkg" --source gitlab
     rules:
       - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
     environment: production
   ```

1. Commitez les modifications et poussez-les vers votre dépôt GitLab.

   Avec cette configuration CI/CD :

   - Le push de paquets NuGet vers la branche `develop` publie les paquets dans le registre de paquets de votre environnement `development`.
   - Le push de paquets NuGet vers la branche `main` publie les paquets NuGet dans le registre de paquets de votre environnement `production`.

### Désactiver les paquets NuGet en double {#turn-off-duplicate-nuget-packages}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/issues/370471) du rôle requis de Maintainer à Owner dans GitLab 17.0.

{{< /history >}}

Vous pouvez publier plusieurs paquets avec le même nom et la même version.

Pour empêcher les membres du groupe et les utilisateurs de publier des paquets NuGet en double, désactivez le paramètre **Autoriser les doublons** :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Dans la ligne **NuGet** du tableau **Paquets dupliqués**, désactivez le bouton bascule **Autoriser les doublons**.
1. Facultatif. Dans la zone de texte **Exception**, saisissez une expression régulière correspondant aux noms et versions des paquets à autoriser.

Vous pouvez également désactiver les paquets NuGet en double avec le paramètre `nuget_duplicates_allowed` dans l'[API GraphQL](../../../api/graphql/reference/_index.md#packagesettings).

> [!warning]
> Si le fichier `.nuspec` n'est pas situé à la racine du paquet ou au début de l'archive, le paquet peut ne pas être immédiatement reconnu comme un doublon. Lorsqu'il est inévitablement reconnu comme un doublon, une erreur s'affiche dans la page **Gestionnaire de paquets**.

## Installer un paquet {#install-a-package}

Le registre de paquets GitLab peut contenir plusieurs paquets avec le même nom et la même version. Si vous installez un paquet en double, le dernier paquet publié est récupéré.

Prérequis :

- Configurez le registre de paquets comme [source](#add-the-package-registry-as-a-source-for-nuget-packages).
- Configurez l'[endpoint GitLab pour les paquets NuGet](#use-the-gitlab-endpoint-for-nuget-packages).

### Depuis la ligne de commande {#from-the-command-line}

{{< tabs >}}

{{< tab title="NuGet CLI" >}}

Installez la dernière version d'un paquet en exécutant cette commande :

```shell
nuget install <package_id> -OutputDirectory <output_directory> \
  -Version <package_version> \
  -Source <source_name>
```

- `<package_id>` : L'ID du paquet.
- `<output_directory>` : le répertoire de sortie, où le paquet est installé.
- `<package_version>` : Facultatif. La version du paquet.
- `<source_name>` : Facultatif. Le nom de la source.
  - `nuget` recherche en premier le paquet demandé sur `nuget.org`. Si le registre de paquets GitLab contient un paquet NuGet avec le même nom qu'un paquet sur `nuget.org`, vous devez spécifier le nom de la source pour installer le bon paquet.

{{< /tab >}}

{{< tab title=".NET CLI" >}}

> [!note]
> Si le registre de paquets GitLab contient un paquet NuGet avec le même nom qu'un paquet dans une source différente, vérifiez l'ordre dans lequel `dotnet` consulte les sources lors de l'installation. Ce comportement est défini dans le fichier `nuget.config`.

Installez la dernière version d'un paquet en exécutant cette commande :

```shell
dotnet add package <package_id> \
       -v <package_version>
```

- `<package_id>` : L'ID du paquet.
- `<package_version>` : Facultatif. La version du paquet.

{{< /tab >}}

{{< /tabs >}}

### Avec le flux NuGet v2 {#with-nuget-v2-feed}

Prérequis :

- Une [source de flux v2](#with-the-project-endpoint) pour Chocolatey.
- Une version de paquet doit être fournie lors de l'installation ou de la mise à niveau d'un paquet avec le flux NuGet v2.

Pour installer un paquet avec la CLI Chocolatey :

```shell
choco install <package_id> -Source <source_url> -Version <package_version>
```

- `<package_id>` : L'ID du paquet.
- `<source_url>` : L'URL ou le nom du registre de paquets du flux NuGet v2.
- `<package_version>` : La version du paquet.

Par exemple :

```shell
choco install MyPackage -Source gitlab -Version 1.0.2

# or

choco install MyPackage -Source "https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/v2" -u <username> -p <personal_access_token> -Version 1.0.2
```

Pour mettre à niveau un paquet avec la CLI Chocolatey :

```shell
choco upgrade <package_id> -Source <source_url> -Version <package_version>
```

- `<package_id>` : L'ID du paquet.
- `<source_url>` : L'URL ou le nom du registre de paquets du flux NuGet v2.
- `<package_version>` : La version du paquet.

Par exemple :

```shell
choco upgrade MyPackage -Source gitlab -Version 1.0.3
```

## Supprimer un paquet {#delete-a-package}

> [!warning]
> La suppression d'un paquet est une action permanente qui ne peut pas être annulée.

Prérequis :

- Vous devez disposer au minimum du rôle [Maintainer](../../permissions.md#project-permissions) dans le projet.
- Vous devez disposer à la fois du nom et de la version du paquet.

Pour supprimer un paquet avec la CLI NuGet :

```shell
nuget delete <package_id> <package_version> -Source <source_name> -ApiKey <personal_access_token>
```

- `<package_id>` : L'ID du paquet.
- `<package_version>` : La version du paquet.
- `<source_name>` : Le nom de la source.

Par exemple :

```shell
nuget delete MyPackage 1.0.0 -Source gitlab -ApiKey <personal_access_token>
```

## Paquets de symboles {#symbol-packages}

GitLab peut consommer des fichiers de symboles depuis le registre de paquets NuGet. Vous pouvez utiliser le registre de paquets GitLab comme serveur de symboles pour déboguer vos paquets NuGet.

Chaque fois que vous publiez un fichier de paquet NuGet (`.nupkg`), les fichiers de paquet de symboles (`.snupkg`) sont automatiquement importés dans le registre de paquets NuGet.

Vous pouvez également les pousser manuellement :

```shell
nuget push My.Package.snupkg -Source <source_name>
```

### Utiliser l'endpoint GitLab pour les fichiers de symboles {#use-the-gitlab-endpoint-for-symbol-files}

Le registre de paquets GitLab fournit un endpoint spécial `symbolfiles` que vous pouvez configurer avec votre endpoint de projet ou de groupe :

- Endpoint de projet :

  ```plaintext
  https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/symbolfiles
  ```

  - Remplacez `<project_id>` par l'ID de projet.
- Endpoint de groupe :

  ```plaintext
  https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/nuget/symbolfiles
  ```

  - Remplacez `<group_id>` par l'ID de groupe.

L'endpoint `symbolfiles` est la source vers laquelle un débogueur configuré peut pousser des fichiers de symboles.

### Utiliser le registre de paquets comme serveur de symboles {#use-the-package-registry-as-a-symbol-server}

Pour utiliser le serveur de symboles :

1. Activez le paramètre d'espace de nommage `nuget_symbol_server_enabled` avec l'[API GraphQL](../../../api/graphql/reference/_index.md#packagesettings).
1. Configurez votre débogueur pour utiliser le serveur de symboles.

Par exemple, pour configurer Visual Studio comme débogueur :

1. Sélectionnez **Outils** > **Préférences**.
1. Sélectionnez **Débogueur** > **Sources de symboles**.
1. Sélectionnez **Ajouter**.
1. Saisissez l'URL du serveur de symboles.
1. Sélectionnez **Ajouter une source**.

Une fois le débogueur configuré, vous pouvez déboguer votre application normalement. Le débogueur télécharge automatiquement les fichiers PDB de symboles depuis le registre de paquets s'ils sont disponibles.

#### Consommer des paquets de symboles {#consume-symbol-packages}

Lorsque le débogueur est configuré pour consommer des paquets de symboles, il envoie les informations suivantes dans une requête :

- En-tête `Symbolchecksum` : la somme de contrôle SHA-256 du fichier de symboles.
- Paramètre de requête `file_name` : le nom du fichier de symboles. Par exemple, `mypackage.pdb`.
- Paramètre de requête `signature` : le GUID et l'âge du fichier PDB.

Le serveur GitLab fait correspondre ces informations à un fichier de symboles et le renvoie.

Gardez à l'esprit que :

- Seuls les fichiers PDB portables sont pris en charge.
- Étant donné que les débogueurs ne peuvent pas fournir de jetons d'authentification, l'endpoint du serveur de symboles ne prend pas en charge les méthodes d'authentification habituelles. Le serveur GitLab exige les paramètres `signature` et `Symbolchecksum` pour renvoyer le fichier de symboles correct.

## Commandes CLI prises en charge {#supported-cli-commands}

Le dépôt NuGet GitLab prend en charge les commandes suivantes pour la CLI NuGet (`nuget`) et la CLI .NET (`dotnet`) :

| NuGet | .NET | Description |
|-----------|----------|-------------|
| `nuget push` | `dotnet nuget push` | Importer un paquet dans le registre. |
| `nuget install` | `dotnet add` | Installer un paquet depuis le registre. |
| `nuget delete` | `dotnet nuget delete` | Supprimer un paquet du registre. |

## Dépannage {#troubleshooting}

Lorsque vous travaillez avec des paquets NuGet, vous pouvez rencontrer les problèmes suivants.

### Vider le cache NuGet {#clear-the-nuget-cache}

Pour améliorer les performances, NuGet met en cache les fichiers de paquets. Si vous rencontrez des problèmes de stockage, videz le cache avec la commande suivante :

```shell
nuget locals all -clear
```

### Erreurs lors de la publication de paquets NuGet dans une installation GitLab basée sur Docker {#errors-when-publishing-nuget-packages-in-a-docker-based-gitlab-installation}

Vous pouvez obtenir les messages d'erreur suivants lors de la publication de paquets NuGet :

- `Error publishing`
- `Invalid Package: Failed metadata extraction error`

Les requêtes webhook vers les adresses du réseau local sont bloquées pour prévenir l'exploitation des services web internes.

Pour résoudre ces erreurs, modifiez vos paramètres réseau afin d'[autoriser les requêtes de webhook et d'intégration vers le réseau local](../../../security/webhooks.md#allow-requests-to-the-local-network-from-webhooks-and-integrations).
