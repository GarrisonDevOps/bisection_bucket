---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Supprimer des images de conteneurs du registre de conteneurs
description: Méthodes automatisées et manuelles pour supprimer des images de conteneurs dans GitLab.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez supprimer des images de conteneurs de votre registre de conteneurs.

Pour supprimer automatiquement des images de conteneurs selon des critères spécifiques, utilisez le [ramasse-miettes](#garbage-collection). Vous pouvez également utiliser un outil tiers pour [créer un job CI/CD](#use-gitlab-cicd) permettant de supprimer des images de conteneurs de projets spécifiques.

Pour supprimer des images de conteneurs spécifiques d'un projet ou d'un groupe, vous pouvez utiliser [l'interface utilisateur GitLab](#use-the-gitlab-ui) ou [l'API GitLab](#use-the-gitlab-api).

> [!warning]
> La suppression d'images de conteneurs est une action destructrice et irréversible. Pour restaurer une image de conteneur supprimée, vous devez la reconstruire et la téléverser à nouveau.

## Ramasse-miettes {#garbage-collection}

La suppression d'une image de conteneur sur des instances GitLab Self-Managed ne libère pas d'espace de stockage ; elle marque uniquement l'image comme éligible à la suppression. Pour supprimer réellement les images de conteneurs non référencées et récupérer de l'espace de stockage, les administrateurs d'instances GitLab Self-Managed doivent exécuter le [ramasse-miettes](../../../administration/packages/container_registry.md#container-registry-garbage-collection).

Le registre de conteneurs sur GitLab.com inclut un ramasse-miettes en ligne automatique. Avec le ramasse-miettes automatique, les éléments suivants sont automatiquement planifiés pour suppression dans les 24 heures s'ils ne sont pas référencés :

- Les couches qui ne sont référencées par aucun manifeste d'image.
- Les manifestes d'image qui n'ont pas d'étiquettes et ne sont pas référencés par un autre manifeste (comme les images multi-architecture).

Le ramasse-miettes en ligne est une fonctionnalité à l'échelle de l'instance et s'applique à tous les espaces de nommage.

## Utiliser l'interface utilisateur GitLab {#use-the-gitlab-ui}

Pour supprimer des images de conteneurs via l'interface utilisateur GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Pour :
   - Un groupe, sélectionnez **Opération** > **Container Registry**.
   - Un projet, sélectionnez **Déployer** > **Container Registry**.
1. Depuis la page **Container Registry**, vous pouvez sélectionner ce que vous souhaitez supprimer, en choisissant l'une des options suivantes :

   - Supprimer l'intégralité du dépôt et toutes les étiquettes qu'il contient, en sélectionnant l'icône rouge {{< icon name="remove" >}} **Corbeille**.
   - Accéder au dépôt et supprimer des étiquettes individuellement ou en masse en sélectionnant l'icône rouge {{< icon name="remove" >}} **Corbeille** à côté de l'étiquette que vous souhaitez supprimer.

1. Dans la boîte de dialogue, sélectionnez **Supprimer l'étiquette**.

Les dépôts de conteneurs qui [échouent à la suppression plus de 10 fois](../../../administration/packages/container_registry.md#max-retries-for-deleting-container-images) cessent automatiquement de tenter de supprimer des images.

## Utiliser l'API GitLab {#use-the-gitlab-api}

Vous pouvez utiliser l'API pour automatiser le processus de suppression des images de conteneurs. Pour plus d'informations, consultez les endpoints suivants :

- [Supprimer un dépôt du registre](../../../api/container_registry.md#delete-registry-repository)
- [Supprimer une étiquette individuelle d'un dépôt du registre](../../../api/container_registry.md#delete-a-registry-repository-tag)
- [Supprimer des étiquettes de dépôts du registre en masse](../../../api/container_registry.md#delete-registry-repository-tags-in-bulk)

## Utiliser GitLab CI/CD {#use-gitlab-cicd}

> [!note]
> GitLab CI/CD ne fournit pas de méthode intégrée pour supprimer vos images de conteneurs. Cet exemple utilise un outil tiers appelé [`regctl`](https://github.com/regclient/regclient) qui communique avec l'API du registre GitLab. Pour obtenir de l'aide concernant cet outil tiers, consultez [le suivi des tickets de regclient](https://github.com/regclient/regclient/issues).

L'exemple suivant définit deux étapes : `build` et `clean`. Le job `build_image` crée une image de conteneur pour la branche, et le job `delete_image` la supprime. L'exécutable `reg` est téléchargé et utilisé pour supprimer l'image de conteneur correspondant à la [variable CI/CD prédéfinie](../../../ci/variables/predefined_variables.md) `$CI_PROJECT_PATH:$CI_COMMIT_REF_SLUG`.

Pour utiliser cet exemple, modifiez la variable `IMAGE_TAG` selon vos besoins.

```yaml
stages:
  - build
  - clean

build_image:
  image: docker:20.10.16
  stage: build
  services:
    - docker:20.10.16-dind
  variables:
    IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker build -t $IMAGE_TAG .
    - docker push $IMAGE_TAG
  rules:
      - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
        when: never
      - if: $CI_COMMIT_BRANCH

delete_image:
  stage: clean
  variables:
    IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
    REGCTL_VERSION: v0.6.1
  rules:
      - if: $CI_COMMIT_REF_NAME != $CI_DEFAULT_BRANCH
  image: alpine:latest
  script:
    - apk update
    - apk add curl
    - curl --fail-with-body --location "https://github.com/regclient/regclient/releases/download/${REGCTL_VERSION}/regctl-linux-amd64" > /usr/bin/regctl
    - chmod 755 /usr/bin/regctl
    - regctl registry login ${CI_REGISTRY} -u ${CI_REGISTRY_USER} -p ${CI_REGISTRY_PASSWORD}
    - regctl tag rm $IMAGE
```

> [!note]
> Vous pouvez télécharger la dernière release de `regctl` depuis [la page des releases](https://github.com/regclient/regclient/releases), puis mettre à jour l'exemple de code en modifiant la variable `REGCTL_VERSION` définie dans le job `delete_image`.

## Utiliser une politique de nettoyage {#use-a-cleanup-policy}

Vous pouvez créer une [politique de nettoyage](reduce_container_registry_storage.md#cleanup-policy) par projet pour vous assurer que les étiquettes et images plus anciennes sont régulièrement supprimées du registre de conteneurs.
