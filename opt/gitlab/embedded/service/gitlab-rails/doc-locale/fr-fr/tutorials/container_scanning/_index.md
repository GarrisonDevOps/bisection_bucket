---
stage: Application Security Testing
group: Composition Analysis
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments-to-other-projects-and-subjects>.
title: 'Tutoriel : scanner un conteneur Docker pour détecter des vulnérabilités'
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez utiliser [l'analyse des conteneurs](../../user/application_security/container_scanning/_index.md) pour détecter les vulnérabilités dans les images de conteneurs stockées dans le [registre de conteneurs](../../user/packages/container_registry/_index.md).

La configuration de l'analyse des conteneurs est ajoutée à la configuration du pipeline d'un projet. Dans ce tutoriel, vous allez :

1. Créer un [nouveau projet](#create-a-new-project).
1. [Ajouter un fichier `Dockerfile`](#add-a-dockerfile-to-new-project) au projet. Ce fichier `Dockerfile` contient la configuration minimale requise pour créer une image Docker.
1. Créer une [configuration de pipeline](#create-pipeline-configuration) pour le nouveau projet afin de créer une image Docker à partir du fichier `Dockerfile`, de construire et de pousser une image Docker vers le registre de conteneurs, puis d'analyser l'image Docker à la recherche de vulnérabilités.
1. Vérifier les [vulnérabilités signalées](#check-for-reported-vulnerabilities).
1. [Mettre à jour l'image Docker](#update-the-docker-image) et analyser l'image mise à jour.

## Créer un nouveau projet {#create-a-new-project}

Pour créer le nouveau projet

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer un projet vide**.
1. Dans **Nom du projet**, saisissez `Tutorial container scanning project`.
1. Dans **URL du projet**, sélectionnez un espace de nommage pour le projet.
1. Sélectionnez **Créer le projet**.

## Ajouter un fichier `Dockerfile` au nouveau projet {#add-a-dockerfile-to-new-project}

Pour fournir un élément sur lequel l'analyse des conteneurs peut travailler, créez un fichier `Dockerfile` avec une configuration très minimale :

1. Dans votre projet `Tutorial container scanning project`, sélectionnez {{< icon name="plus" >}} > **Nouveau fichier**.
1. Saisissez le nom de fichier `Dockerfile` et fournissez le contenu suivant pour le fichier :

   ```Dockerfile
   FROM hello-world:latest
   ```

Les images Docker créées à partir de ce fichier `Dockerfile` sont basées sur l'image Docker [`hello-world`](https://hub.docker.com/_/hello-world).

1. Sélectionnez **Valider les modifications**.

## Créer la configuration du pipeline {#create-pipeline-configuration}

Vous êtes maintenant prêt à créer la configuration du pipeline. La configuration du pipeline :

1. Construit une image Docker à partir du fichier `Dockerfile` et pousse l'image Docker vers le registre de conteneurs. Le job `build-image` utilise [Docker-in-Docker](../../ci/docker/using_docker_build.md) en tant que [service CI/CD](../../ci/services/_index.md) pour construire l'image Docker.
1. Inclut le template `Container-Scanning.gitlab-ci.yml` pour analyser l'image Docker stockée dans le registre de conteneurs.

Pour créer la configuration du pipeline :

1. Dans le répertoire racine de votre projet, sélectionnez {{< icon name="plus" >}} > **Nouveau fichier**.
1. Saisissez le nom de fichier `.gitlab-ci.yml` et fournissez le contenu suivant pour le fichier :

   ```yaml
   include:
     - template: Jobs/Container-Scanning.gitlab-ci.yml

   container_scanning:
     variables:
       CS_IMAGE: $CI_REGISTRY_IMAGE/tutorial-image

   build-image:
     image: docker:24.0.2-cli
     stage: build
     services:
       - docker:24.0.2-dind
     script:
       - docker build --tag $CI_REGISTRY_IMAGE/tutorial-image --file Dockerfile .
       - docker login --username gitlab-ci-token --password $CI_JOB_TOKEN $CI_REGISTRY
       - docker push $CI_REGISTRY_IMAGE/tutorial-image
   ```

1. Sélectionnez **Valider les modifications**.

Vous avez presque terminé. Une fois le fichier commité, un nouveau pipeline démarre avec cette configuration. Une fois terminé, vous pouvez vérifier les résultats de l'analyse.

## Vérifier les vulnérabilités signalées {#check-for-reported-vulnerabilities}

Les vulnérabilités d'une analyse sont situées sur le pipeline qui a exécuté l'analyse. Pour vérifier les vulnérabilités signalées :

1. Sélectionnez **CI/CD** > **Pipelines** et sélectionnez le pipeline le plus récent. Ce pipeline doit être composé d'un job appelé `container_scanning` dans l'étape `test`.
1. Si le job `container_scanning` a réussi, sélectionnez l'onglet **Sécurité**. Si des vulnérabilités ont été trouvées, elles sont répertoriées sur cette page.

## Mettre à jour l'image Docker {#update-the-docker-image}

Une image Docker basée sur `hello-world:latest` est peu susceptible d'afficher des vulnérabilités. Pour obtenir un exemple d'analyse signalant des vulnérabilités :

1. Dans le répertoire racine de votre projet, sélectionnez le fichier `Dockerfile` existant.
1. Sélectionner **Éditer**.
1. Remplacez `FROM hello-world:latest` par une image Docker différente pour l'instruction [`FROM`](https://docs.docker.com/reference/dockerfile/#from). Les meilleures images Docker pour illustrer l'analyse des conteneurs possèdent :
   - Des packages de système d'exploitation. Par exemple, provenant de Debian, Ubuntu, Alpine ou Red Hat.
   - Des packages de langage de programmation. Par exemple, des packages NPM ou des packages Python.
1. Sélectionnez **Valider les modifications**.

Une fois les modifications committées dans le fichier, un nouveau pipeline démarre avec ce fichier `Dockerfile` mis à jour. Une fois terminé, vous pouvez vérifier les résultats de la nouvelle analyse.
