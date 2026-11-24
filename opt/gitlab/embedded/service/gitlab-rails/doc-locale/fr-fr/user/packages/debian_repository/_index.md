---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Paquets Debian dans le registre de paquets
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed
- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Déployé derrière un feature flag](../../../administration/feature_flags/list.md), désactivé par défaut.

{{< /history >}}

> [!warning]
> Le registre de paquets Debian pour GitLab est en cours de développement et n'est pas prêt pour une utilisation en production. Cet [epic](https://gitlab.com/groups/gitlab-org/-/work_items/6057) détaille les travaux restants et les délais pour le rendre prêt pour la production. La prise en charge des [paquets Debian est une version expérimentale](../package_registry/supported_functionality.md) et présente des vulnérabilités de sécurité connues.

Publiez des paquets Debian dans le registre de paquets de votre projet. Installez ensuite les paquets chaque fois que vous avez besoin de les utiliser comme dépendance.

Les paquets de projet et de groupe sont pris en charge.

Pour la documentation des endpoints d'API spécifiques utilisés par les clients du gestionnaire de paquets Debian, consultez la [documentation de l'API Debian](../../../api/packages/debian.md).

Prérequis :

- Le binaire `dpkg-deb` doit être installé sur l'instance GitLab. Ce binaire est généralement fourni par le [paquet `dpkg`](https://wiki.debian.org/Teams/Dpkg/Downstream), installé par défaut sur Debian et ses dérivées.
- Recommandé. Utilisez `dpkg-deb` 1.22.21 ou une version ultérieure. Dans `dpkg-deb` 1.22.20 et versions antérieures, le binaire ne peut pas supprimer les fichiers temporaires des archives contenant des répertoires non modifiables. Ces fichiers consomment de l'espace disque et peuvent provoquer une attaque par déni de service.
- La prise en charge de l'algorithme de compression ZStandard nécessite la version `dpkg >= 1.21.18` de Debian 12 Bookworm ou `dpkg >= 1.19.0.5ubuntu2` d'Ubuntu 18.04 Bionic Beaver.

## Activer l'API Debian {#enable-the-debian-api}

La prise en charge du dépôt Debian est encore en cours de développement. Elle est protégée par un feature flag désactivé par défaut. [Les administrateurs GitLab ayant accès à la console Rails de GitLab](../../../administration/feature_flags/_index.md) peuvent choisir de l'activer.

> [!warning]
> Découvrez les [risques de stabilité et de sécurité liés à l'activation de fonctionnalités encore en développement](../../../administration/feature_flags/_index.md#risks-when-enabling-features-still-in-development).

Pour l'activer :

```ruby
Feature.enable(:debian_packages)
```

Pour le désactiver :

```ruby
Feature.disable(:debian_packages)
```

## Activer l'API de groupe Debian {#enable-the-debian-group-api}

Le dépôt de groupe Debian est également protégé par un second feature flag désactivé par défaut.

> [!warning]
> Découvrez les [risques de stabilité et de sécurité liés à l'activation de fonctionnalités encore en développement](../../../administration/feature_flags/_index.md#risks-when-enabling-features-still-in-development).

Pour l'activer :

```ruby
Feature.enable(:debian_group_packages)
```

Pour le désactiver :

```ruby
Feature.disable(:debian_group_packages)
```

## Créer un paquet Debian {#build-a-debian-package}

La création d'un paquet Debian est documentée [sur le Wiki Debian](https://wiki.debian.org/Packaging).

## S'authentifier auprès des endpoints Debian {#authenticate-to-the-debian-endpoints}

Les méthodes d'authentification diffèrent entre les [API de distributions](#authenticate-to-the-debian-distributions-apis) et les [dépôts de paquets](#authenticate-to-the-debian-package-repositories).

### S'authentifier auprès des API de distributions Debian {#authenticate-to-the-debian-distributions-apis}

Pour créer, lire, mettre à jour ou supprimer une distribution, vous avez besoin de l'un des éléments suivants :

- [Jeton d'accès personnel](../../profile/personal_access_tokens.md), en utilisant `--header "PRIVATE-TOKEN: <personal_access_token>"`
- [Jeton de déploiement](../../project/deploy_tokens/_index.md) en utilisant `--header "Deploy-Token: <deploy_token>"`
- [Jeton de job CI/CD](../../../ci/jobs/ci_job_token.md) en utilisant `--header "Job-Token: <job_token>"`

### S'authentifier auprès des dépôts de paquets Debian {#authenticate-to-the-debian-package-repositories}

Pour publier un paquet ou installer un paquet privé, vous devez utiliser l'authentification de base avec l'un des éléments suivants :

- [Jeton d'accès personnel](../../profile/personal_access_tokens.md), en utilisant `<username>:<personal_access_token>`
- [Jeton de déploiement](../../project/deploy_tokens/_index.md) en utilisant `<deploy_token_name>:<deploy_token>`
- [Jeton de job CI/CD](../../../ci/jobs/ci_job_token.md) en utilisant `gitlab-ci-token:<job_token>`

## Créer une distribution {#create-a-distribution}

Au niveau du projet, les paquets Debian sont publiés avec des distributions Debian. Au niveau du groupe, les paquets Debian sont agrégés à partir des projets du groupe, à condition que :

- La visibilité du projet est définie sur `public`.
- Le `codename` Debian du groupe correspond au `codename` Debian du projet.

Pour créer une distribution au niveau du projet à l'aide d'un jeton d'accès personnel :

```shell
curl --fail-with-body --request POST --header "PRIVATE-TOKEN: <personal_access_token>" \
  "https://gitlab.example.com/api/v4/projects/<project_id>/debian_distributions?codename=<codename>"
```

Exemple de réponse avec `codename=sid` :

```json
{
  "id": 1,
  "codename": "sid",
  "suite": null,
  "origin": null,
  "label": null,
  "version": null,
  "description": null,
  "valid_time_duration_seconds": null,
  "components": [
    "main"
  ],
  "architectures": [
    "all",
    "amd64"
  ]
}
```

Plus d'informations sur les API de distributions Debian :

- [API des distributions de projet Debian](../../../api/packages/debian_project_distributions.md)
- [API des distributions de groupe Debian](../../../api/packages/debian_group_distributions.md)

## Publier un paquet {#publish-a-package}

Une fois la compilation terminée, plusieurs fichiers sont créés :

- Fichiers `.deb` : les paquets binaires
- Fichiers `.udeb` : fichiers .deb allégés, utilisés pour Debian-Installer (si nécessaire)
- Fichiers `.ddeb` : fichiers .deb de débogage Ubuntu (si nécessaire)
- Fichiers `.tar.{gz,bz2,xz,...}` : fichiers sources
- Fichier `.dsc` : métadonnées sources et liste des fichiers sources (avec hachages)
- Fichier `.buildinfo` : utilisé pour les builds reproductibles (optionnel)
- Fichier `.changes` : métadonnées d'import et liste des fichiers importés (tous les éléments ci-dessus)

Pour importer ces fichiers, vous pouvez utiliser `dput-ng >= 1.32` (Debian bullseye). `<username>` et `<password>` sont définis comme dans les [dépôts de paquets Debian](#authenticate-to-the-debian-package-repositories) :

```shell
cat <<EOF > dput.cf
[gitlab]
method = https
fqdn = <username>:<password>@gitlab.example.com
incoming = /api/v4/projects/<project_id>/packages/debian
EOF

dput --config=dput.cf --unchecked --no-upload-log gitlab <your_package>.changes
```

## Importer un paquet avec une distribution et un composant explicites {#upload-a-package-with-explicit-distribution-and-component}

Lorsque vous n'avez pas accès au fichier `.changes`, vous pouvez importer directement un fichier `.deb` en passant la distribution `codename` et le composant cible `component` comme paramètres avec vos [identifiants](#authenticate-to-the-debian-package-repositories). Par exemple, pour importer dans le composant `main` de la distribution `sid` à l'aide d'un jeton d'accès personnel :

```shell
curl --fail-with-body --request PUT --user "<username>:<personal_access_token>" \
  "https://gitlab.example.com/api/v4/projects/<project_id>/packages/debian/your.deb?distribution=sid&component=main" \
  --upload-file  /path/to/your.deb
```

## Installer un paquet {#install-a-package}

Pour installer un paquet :

1. Configurez le dépôt :

   Si vous utilisez un projet privé, ajoutez vos [identifiants](#authenticate-to-the-debian-package-repositories) à votre configuration apt :

   ```shell
   echo 'machine gitlab.example.com login <username> password <password>' \
     | sudo tee /etc/apt/auth.conf.d/gitlab_project.conf
   ```

   Téléchargez votre clé de distribution à l'aide de vos [identifiants](#authenticate-to-the-debian-distributions-apis) :

   ```shell
   sudo mkdir -p /etc/apt/keyrings
   sudo curl --fail --silent --show-error --header "PRIVATE-TOKEN: <your_access_token>" \
        --output /etc/apt/keyrings/<codename>-archive-keyring.asc \
        --url "https://gitlab.example.com/api/v4/projects/<project_id>/debian_distributions/<codename>/key.asc"
   ```

   Ajoutez votre projet comme source :

   ```shell
   echo 'deb [ signed-by=/etc/apt/keyrings/<codename>-archive-keyring.asc ] https://gitlab.example.com/api/v4/projects/<project_id>/packages/debian <codename> <component1> <component2>' |
       sudo tee /etc/apt/sources.list.d/gitlab_project.list
   sudo apt-get update
   ```

1. Installez le paquet :

   ```shell
   sudo apt-get -y install -t <codename> <package-name>
   ```

## Télécharger un paquet source {#download-a-source-package}

Pour télécharger un paquet source :

1. Configurez le dépôt :

   Si vous utilisez un projet privé, ajoutez vos [identifiants](#authenticate-to-the-debian-package-repositories) à votre configuration apt :

   ```shell
   echo 'machine gitlab.example.com login <username> password <password>' \
     | sudo tee /etc/apt/auth.conf.d/gitlab_project.conf
   ```

   Téléchargez votre clé de distribution à l'aide de vos [identifiants](#authenticate-to-the-debian-distributions-apis) :

   ```shell
   sudo mkdir -p /etc/apt/keyrings
   sudo curl --fail --silent --show-error --header "PRIVATE-TOKEN: <your_access_token>" \
        --output /etc/apt/keyrings/<codename>-archive-keyring.asc \
        --url "https://gitlab.example.com/api/v4/projects/<project_id>/debian_distributions/<codename>/key.asc"
   ```

   Ajoutez votre projet comme source :

   ```shell
   echo 'deb-src [ signed-by=/etc/apt/keyrings/<codename>-archive-keyring.asc ] https://gitlab.example.com/api/v4/projects/<project_id>/packages/debian <codename> <component1> <component2>' |
       sudo tee /etc/apt/sources.list.d/gitlab_project-sources.list
   sudo apt-get update
   ```

1. Téléchargez le paquet source :

   ```shell
   sudo apt-get source -t <codename> <package-name>
   ```

## Supprimer un paquet Debian {#delete-a-debian-package}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire.

Avant de supprimer un paquet, assurez-vous de bien comprendre les [risques de sécurité associés](../package_registry/supported_functionality.md#deleting-packages).

Pour supprimer un paquet, vous pouvez :

- [Utiliser l'interface utilisateur](../package_registry/reduce_package_registry_storage.md#delete-a-package).
- [Utiliser l'API](../../../api/packages.md#delete-a-project-package).
