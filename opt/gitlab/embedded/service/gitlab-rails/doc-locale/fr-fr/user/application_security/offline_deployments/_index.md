---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Environnements hors ligne
description: Analyse de sécurité hors ligne et résolution des vulnérabilités.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

> [!note]
> Pour configurer un environnement hors ligne, vous devez obtenir une [exemption d'opt-out de la licence cloud](https://about.gitlab.com/pricing/licensing-faq/cloud-licensing/#offline-cloud-licensing) avant l'achat. Pour plus de détails, contactez votre représentant commercial GitLab.

Il est possible d'exécuter la plupart des scanners de sécurité GitLab sans connexion à Internet.

Ce document décrit comment utiliser les catégories Secure (c'est-à-dire les types de scanners) dans un environnement hors ligne. Ces instructions s'appliquent également aux instances GitLab Self-Managed sécurisées, dotées de politiques de sécurité (par exemple, des politiques de pare-feu) ou dont l'accès à Internet est restreint. GitLab désigne ces environnements comme _environnements hors ligne_. Parmi les autres noms courants, on trouve :

- Environnements air-gapped
- Environnements à connectivité limitée
- Environnements de réseau local (LAN)
- Environnements intranet

Ces environnements sont dotés de barrières physiques ou de politiques de sécurité (par exemple, des pare-feux) qui empêchent ou limitent l'accès à Internet. Ces instructions sont conçues pour les réseaux physiquement déconnectés, mais peuvent également s'appliquer à ces autres cas d'utilisation.

## Définition des environnements hors ligne {#defining-offline-environments}

Dans un environnement hors ligne, l'instance GitLab peut être constituée d'un ou plusieurs serveurs et services capables de communiquer sur un réseau local, mais avec un accès à Internet inexistant ou très restreint. Partez du principe que tout ce qui se trouve dans l'instance GitLab et l'infrastructure de support (par exemple, un dépôt Maven privé) est accessible via une connexion réseau locale. Partez du principe que tous les fichiers provenant d'Internet doivent être apportés via des supports physiques (clé USB, disque dur, DVD enregistrable, etc.).

## Utiliser les scanners hors ligne {#use-offline-scanners}

Les scanners GitLab se connectent généralement à Internet pour télécharger les derniers ensembles de signatures, de règles et de correctifs. Quelques étapes supplémentaires sont nécessaires pour configurer les outils afin qu'ils fonctionnent correctement en utilisant les ressources disponibles sur votre réseau local.

### Registres de conteneurs et dépôts de paquets {#container-registries-and-package-repositories}

D'une manière générale, les analyseurs de sécurité sont fournis sous forme d'images Docker et peuvent exploiter divers dépôts de paquets. Lorsque vous exécutez un job sur une installation GitLab connectée à Internet, GitLab vérifie le registre de conteneurs hébergé sur GitLab.com pour s'assurer que vous disposez des dernières versions de ces images Docker et se connecte éventuellement aux dépôts de paquets pour installer les dépendances nécessaires.

Dans un environnement hors ligne, ces vérifications doivent être désactivées afin que GitLab.com ne soit pas interrogé. Le registre et les dépôts de GitLab.com n'étant pas disponibles, vous devez mettre à jour chacun des scanners pour référencer un registre différent hébergé en interne ou pour fournir un accès aux images individuelles des scanners.

Vous devez également vous assurer que votre application a accès aux dépôts de paquets courants qui ne sont pas hébergés sur GitLab.com, tels que npm, yarn ou les gems Ruby. Les paquets de ces dépôts peuvent être obtenus en se connectant temporairement à un réseau ou en effectuant une mise en miroir des paquets au sein de votre propre réseau hors ligne.

### Interaction avec les vulnérabilités {#interacting-with-the-vulnerabilities}

Une fois qu'une vulnérabilité est détectée, vous pouvez interagir avec elle. Pour en savoir plus sur la façon de [traiter les vulnérabilités](../vulnerabilities/_index.md).

Dans certains cas, les vulnérabilités signalées fournissent des métadonnées pouvant contenir des liens externes exposés dans l'interface utilisateur. Ces liens peuvent ne pas être accessibles dans un environnement hors ligne.

### Résolution des vulnérabilités {#resolving-vulnerabilities}

La fonctionnalité de [résolution des vulnérabilités](../vulnerabilities/_index.md#resolve-a-vulnerability) est disponible pour l'analyse des dépendances hors ligne et l'analyse des conteneurs, mais peut ne pas fonctionner selon la configuration de votre instance. GitLab peut suggérer des solutions (généralement des versions plus récentes avec correctifs) uniquement lorsqu'il peut accéder à des services de registre à jour hébergeant les dernières versions de la dépendance ou de l'image concernée.

### Mises à jour des signatures et des règles des scanners {#scanner-signature-and-rule-updates}

Lorsqu'ils sont connectés à Internet, certains scanners consultent des bases de données publiques pour obtenir les derniers ensembles de signatures et de règles à vérifier. Sans connectivité, cela n'est pas possible. En fonction du scanner, vous devez donc désactiver ces vérifications automatiques des mises à jour et soit utiliser les bases de données fournies avec le scanner en les mettant à jour manuellement, soit fournir l'accès à vos propres copies hébergées au sein de votre réseau.

## Instructions spécifiques aux scanners {#specific-scanner-instructions}

Chaque scanner peut différer légèrement des étapes décrites précédemment. Vous trouverez plus d'informations sur chacune des pages suivantes :

- [Instructions hors ligne pour l'analyse des conteneurs](../container_scanning/_index.md#offline-environment)
- [Instructions hors ligne pour SAST](../sast/_index.md#running-sast-in-an-offline-environment)
- [Instructions hors ligne pour la détection des secrets](../secret_detection/pipeline/configure.md#offline-configuration)
- [Instructions hors ligne pour DAST](../dast/browser/configuration/offline_configuration.md)
- [Instructions hors ligne pour le fuzzing d'API](../api_fuzzing/configuration/offline_configuration.md)
- [Instructions hors ligne pour l'analyse des licences](../../compliance/license_scanning_of_cyclonedx_files/_index.md#running-in-an-offline-environment)
- [Instructions hors ligne pour l'analyse des dépendances](../dependency_scanning/dependency_scanning_sbom/_index.md#offline-environment)
- [Instructions hors ligne pour l'analyse IaC](../iac_scanning/_index.md#offline-configuration)

### Base de données de métadonnées des paquets {#package-metadata-database}

[L'analyse des dépendances](../dependency_scanning/_index.md) et [l'analyse continue des vulnérabilités](../continuous_vulnerability_scanning/_index.md) lisent la base de données de métadonnées des paquets pour obtenir des données sur les licences, les avis et l'évaluation des risques de vulnérabilité. Cette base de données est un artefact de données, et non une image d'analyseur ; le chargement des images d'analyseur ne la fournit donc pas. Une instance hors ligne n'en contient aucune jusqu'à ce que vous copiiez les exports.

Pour la procédure, consultez [Activation de la base de données de métadonnées des paquets](../../../topics/offline/quick_start_guide.md#enabling-the-package-metadata-database).

## Chargement des images Docker sur votre hôte hors ligne {#loading-docker-images-onto-your-offline-host}

Pour utiliser de nombreuses fonctionnalités de GitLab, notamment les analyses de sécurité et [Auto DevOps](../../../topics/autodevops/_index.md), le runner doit pouvoir récupérer les images Docker appropriées.

Le processus permettant de rendre ces images disponibles sans accès direct à Internet public consiste à les télécharger, puis à les conditionner et à les transférer vers l'hôte hors ligne. Voici un exemple d'un tel transfert :

1. Télécharger les images Docker depuis Internet public.
1. Conditionner les images Docker sous forme d'archives tar.
1. Transférer les images vers l'environnement hors ligne.
1. Charger les images transférées dans le registre Docker hors ligne.

### Utiliser le modèle GitLab officiel {#using-the-official-gitlab-template}

GitLab fournit un [modèle vendorisé](../../../ci/yaml/_index.md#includetemplate) pour simplifier ce processus.

Ce modèle doit être utilisé dans un projet nouveau et vide, avec un fichier `.gitlab-ci.yml` contenant :

```yaml
include:
  - template: Security/Secure-Binaries.gitlab-ci.yml
```

Le pipeline télécharge les images Docker nécessaires aux scanners de sécurité et les enregistre sous forme d'[artefacts de job](../../../ci/jobs/job_artifacts.md) ou les pousse vers le [registre de conteneurs](../../packages/container_registry/_index.md) du projet où le pipeline est exécuté. Ces archives peuvent être transférées vers un autre emplacement et [chargées](https://docs.docker.com/reference/cli/docker/image/load/) dans un daemon Docker. Cette méthode nécessite un runner ayant accès à la fois à `gitlab.com` (y compris `registry.gitlab.com`) et à l'instance hors ligne locale. Ce runner doit s'exécuter en [mode privilégié](https://docs.gitlab.com/runner/executors/docker/#use-docker-in-docker-with-privileged-mode) pour pouvoir utiliser la commande `docker` à l'intérieur des jobs. Ce runner peut être installé dans une DMZ ou sur un bastion, et utilisé uniquement pour ce projet spécifique.

> [!warning]
> Ce modèle n'inclut pas les mises à jour pour l'analyseur d'analyse des conteneurs. Consultez [les instructions hors ligne pour l'analyse des conteneurs](../container_scanning/_index.md#offline-environment).

#### Planification des mises à jour {#scheduling-the-updates}

Par défaut, le pipeline de ce projet ne s'exécute qu'une seule fois, lors de l'ajout du fichier `.gitlab-ci.yml` au dépôt. Pour mettre à jour les scanners et les signatures de sécurité GitLab, il est nécessaire d'exécuter ce pipeline régulièrement. GitLab offre la possibilité de [planifier des pipelines](../../../ci/pipelines/schedules.md). Par exemple, vous pouvez configurer cela pour télécharger et stocker les images Docker chaque semaine.

#### Utiliser le bundle sécurisé créé {#using-the-secure-bundle-created}

Le projet utilisant le modèle `Secure-Binaries.gitlab-ci.yml` doit maintenant héberger toutes les images et ressources requises pour exécuter les fonctionnalités de sécurité GitLab.

Ensuite, vous devez indiquer à l'instance hors ligne d'utiliser ces ressources à la place des ressources par défaut sur GitLab.com. Pour ce faire, définissez la variable CI/CD `SECURE_ANALYZERS_PREFIX` avec l'URL du [registre de conteneurs](../../packages/container_registry/_index.md) du projet.

Vous pouvez définir cette variable dans le fichier `.gitlab-ci.yml` des projets, ou dans l'interface utilisateur GitLab au niveau du projet ou du groupe. Consultez la [page des variables CI/CD GitLab](../../../ci/variables/_index.md#define-a-cicd-variable-in-the-ui) pour plus d'informations.

#### Variables {#variables}

Le tableau suivant indique les variables CI/CD que vous pouvez utiliser avec le modèle `Secure-Binaries.gitlab-ci.yml` :

| Variable CI/CD                            | Description                                   | Valeur par défaut                     |
|-------------------------------------------|-----------------------------------------------|-----------------------------------|
| `SECURE_BINARIES_ANALYZERS`               | Liste séparée par des virgules des analyseurs à télécharger | `"bandit, brakeman, gosec, ..."` |
| `SECURE_BINARIES_DOWNLOAD_IMAGES`         | Utilisé pour désactiver les jobs                          | `"true"`                          |
| `SECURE_BINARIES_PUSH_IMAGES`             | Pousser les fichiers vers le registre du projet            | `"true"`                          |
| `SECURE_BINARIES_SAVE_ARTIFACTS`          | Enregistrer également les archives d'images en tant qu'artefacts         | `"false"`                         |
| `SECURE_BINARIES_ANALYZER_VERSION`        | Version par défaut de l'analyseur (tag Docker)         | `"2"`                             |

### Autre méthode sans le modèle officiel {#alternate-way-without-the-official-template}

S'il n'est pas possible de suivre la méthode précédente, les images peuvent être transférées manuellement à la place :

#### Exemple de script de conditionnement d'images {#example-image-packager-script}

```shell
#!/bin/bash
set -ux

# Specify needed analyzer images
analyzers=${SAST_ANALYZERS:-"bandit eslint gosec"}
gitlab=registry.gitlab.com/security-products/

for i in "${analyzers[@]}"
do
  tarname="${i}_2.tar"
  docker pull $gitlab$i:2
  docker save $gitlab$i:2 -o ./analyzers/${tarname}
  chmod +r ./analyzers/${tarname}
done
```

#### Exemple de script de chargement d'images {#example-image-loader-script}

Cet exemple charge les images depuis un hôte bastion vers un hôte hors ligne. Dans certaines configurations, un support physique peut être nécessaire pour un tel transfert :

```shell
#!/bin/bash
set -ux

# Specify needed analyzer images
analyzers=${SAST_ANALYZERS:-"bandit eslint gosec"}
registry=$GITLAB_HOST:4567

for i in "${analyzers[@]}"
do
  tarname="${i}_2.tar"
  scp ./analyzers/${tarname} ${GITLAB_HOST}:~/${tarname}
  ssh $GITLAB_HOST "sudo docker load -i ${tarname}"
  ssh $GITLAB_HOST "sudo docker tag $(sudo docker images | grep $i | awk '{print $3}') ${registry}/analyzers/${i}:2"
  ssh $GITLAB_HOST "sudo docker push ${registry}/analyzers/${i}:2"
done
```

### Utiliser GitLab Secure avec AutoDevOps dans un environnement hors ligne {#using-gitlab-secure-with-autodevops-in-an-offline-environment}

Vous pouvez utiliser GitLab AutoDevOps pour les analyses Secure dans un environnement hors ligne. Toutefois, vous devez d'abord effectuer les étapes suivantes :

1. Charger les images de conteneurs dans le registre local. GitLab Secure exploite des images de conteneurs d'analyseurs pour effectuer les différentes analyses. Ces images doivent être disponibles lors de l'exécution d'AutoDevOps. Avant d'exécuter AutoDevOps, suivez les étapes du [modèle GitLab officiel](#using-the-official-gitlab-template) pour charger ces images de conteneurs dans le registre de conteneurs local.

1. Définissez la variable CI/CD pour vous assurer qu'AutoDevOps recherche les images au bon endroit. Les modèles AutoDevOps exploitent la variable `SECURE_ANALYZERS_PREFIX` pour identifier l'emplacement des images d'analyseurs. Pour plus d'informations à ce sujet, consultez [Utiliser le bundle sécurisé créé](#using-the-secure-bundle-created). Assurez-vous de définir cette variable à la valeur correcte correspondant à l'emplacement où vous avez chargé les images d'analyseurs. Vous pouvez envisager de le faire avec une variable CI/CD de projet ou en [modifiant](../../../topics/autodevops/customize.md#customize-gitlab-ciyml) directement le fichier `.gitlab-ci.yml`.

Une fois ces étapes terminées, GitLab dispose de copies locales des analyseurs Secure et est configuré pour les utiliser à la place d'une image de conteneur hébergée sur Internet. Cela vous permet d'exécuter Secure dans AutoDevOps dans un environnement hors ligne.

Ces étapes sont spécifiques à GitLab Secure avec AutoDevOps. L'utilisation d'autres étapes avec AutoDevOps peut nécessiter d'autres démarches décrites dans la [documentation Auto DevOps](../../../topics/autodevops/_index.md).
