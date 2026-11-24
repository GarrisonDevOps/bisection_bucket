---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Dépannage du registre de conteneurs GitLab
description: Conseils pour résoudre les erreurs courantes liées au registre de conteneurs GitLab.
---

Vous devez vous connecter à GitLab avec des droits d'administrateur pour résoudre la plupart des problèmes liés au registre de conteneurs GitLab.

Vous trouverez des [informations de dépannage supplémentaires](../../../administration/packages/container_registry_troubleshooting.md) dans la documentation d'administration du registre de conteneurs GitLab.

## Migration des images de conteneurs OCI vers le registre de conteneurs GitLab {#migrating-oci-container-images-to-gitlab-container-registry}

La migration des images de conteneurs vers le registre GitLab n'est pas prise en charge, mais l'[epic 5210](https://gitlab.com/groups/gitlab-org/-/epics/5210) propose de modifier ce comportement.

Vous pouvez utiliser des outils tiers pour migrer des images de conteneurs. Par exemple, [skopeo](https://github.com/containers/skopeo) peut [copier des images de conteneurs](https://github.com/containers/skopeo#copying-images) entre différents mécanismes de stockage. Vous pouvez utiliser skopeo pour copier des images depuis des registres de conteneurs, des backends de stockage de conteneurs, des répertoires locaux et des répertoires OCI-layout locaux vers le registre de conteneurs GitLab.

## Erreur de connexion Docker {#docker-connection-error}

Une erreur de connexion Docker peut survenir lorsque des caractères spéciaux sont présents dans le nom du groupe, du projet ou de la branche. Les caractères spéciaux incluent :

- Un tiret de soulignement en début de nom.
- Un trait d'union ou un tiret en fin de nom.

Pour résoudre cette erreur, vous pouvez modifier le [chemin du groupe](../../group/manage.md#change-a-groups-path), le [chemin du projet](../../project/working_with_projects.md#rename-a-repository) ou le nom de la branche.

Vous pouvez recevoir un message d'erreur `404 Not Found` ou `Unknown Manifest` si vous utilisez Docker Engine 17.11 ou une version antérieure. Les versions actuelles de Docker Engine utilisent l'[API v2](https://distribution.github.io/distribution/spec/manifest-v2-2/).

Les images de votre registre de conteneurs GitLab doivent utiliser l'API Docker v2. Pour savoir comment mettre à jour les images de la version 1 vers la version 2, consultez la [documentation Docker](https://distribution.github.io/distribution/spec/deprecated-schema-v1/).

## Erreur `Blob unknown to registry` lors de l'envoi d'une liste de manifestes {#blob-unknown-to-registry-error-when-pushing-a-manifest-list}

Lors de l'[envoi d'une liste de manifestes Docker](https://docs.docker.com/reference/cli/docker/manifest/#create-and-push-a-manifest-list) vers le registre de conteneurs GitLab, vous pouvez recevoir l'erreur `manifest blob unknown: blob unknown to registry`. Cette erreur est probablement due à la présence de plusieurs images avec des architectures différentes réparties sur plusieurs dépôts au lieu du même dépôt.

Par exemple, vous pouvez avoir deux images, chacune représentant une architecture :

- La plateforme `amd64`.
- La plateforme `arm64v8`.

Pour créer une image multi-architecture à partir de ces images, vous devez les envoyer vers le même dépôt que l'image multi-architecture.

Pour résoudre l'erreur `Blob unknown to registry`, incluez l'architecture dans le nom du tag des images individuelles. Par exemple, utilisez `mygroup/myapp:1.0.0-amd64` et `mygroup/myapp:1.0.0-arm64v8`. Vous pouvez ensuite associer le tag de la liste de manifestes avec `mygroup/myapp:1.0.0`.

## Impossible de modifier le chemin du projet ou de transférer un projet {#unable-to-change-project-path-or-transfer-a-project}

Si vous essayez de modifier le chemin d'un projet ou de transférer un projet vers un nouvel espace de nommage, vous pouvez recevoir l'une des erreurs suivantes :

- Le projet ne peut pas être transféré car des tags sont présents dans son registre de conteneurs.
- L'espace de nommage ne peut pas être déplacé car au moins un projet possède des tags dans le registre de conteneurs.

Cette erreur se produit lorsque le projet contient des images dans le registre de conteneurs. Vous devez supprimer ou déplacer ces images avant de modifier le chemin ou de transférer le projet.

La procédure suivante utilise ces exemples de noms de projet :

- Pour le projet actuel : `gitlab.example.com/org/build/sample_project/cr:v2.9.1`.
- Pour le nouveau projet : `gitlab.example.com/new_org/build/new_sample_project/cr:v2.9.1`.

1. Téléchargez les images Docker sur votre ordinateur :

   ```shell
   docker login gitlab.example.com
   docker pull gitlab.example.com/org/build/sample_project/cr:v2.9.1
   ```

   > [!note]
   > Utilisez un [jeton d'accès personnel](../../profile/personal_access_tokens.md) ou un [jeton de déploiement](../../project/deploy_tokens/_index.md) pour authentifier votre compte utilisateur.

1. Renommez les images pour qu'elles correspondent au nouveau nom de projet :

   ```shell
   docker tag gitlab.example.com/org/build/sample_project/cr:v2.9.1 gitlab.example.com/new_org/build/new_sample_project/cr:v2.9.1
   ```

1. Supprimez les images de l'ancien projet en utilisant l'[interface utilisateur](delete_container_registry_images.md) ou l'[API](../../../api/packages.md#delete-a-project-package). Un délai peut survenir pendant que les images sont mises en file d'attente et supprimées.
1. Modifiez le chemin ou transférez le projet :

   1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
   1. Sélectionnez **Paramètres** > **Généralités**.
   1. Développez la section **Paramètres avancés**.
   1. Dans la zone de texte **Changer le chemin**, modifiez le chemin.
   1. Sélectionnez **Changer le chemin**.

1. Restaurez les images :

   ```shell
   docker push gitlab.example.com/new_org/build/new_sample_project/cr:v2.9.1
   ```

Consultez ce [ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/18383) pour plus de détails.

## Messages `Failed to pull image` {#failed-to-pull-image-messages}

Vous pouvez recevoir un message d'erreur [`Failed to pull image`](../../../ci/debugging.md#failed-to-pull-image-messages) lorsqu'un job CI/CD ne parvient pas à extraire une image de conteneur depuis un projet avec une [portée de jeton de job CI/CD](../../../ci/jobs/ci_job_token.md#limit-job-token-scope-for-public-or-internal-projects) limitée.

## Erreur `OCI manifest found, but accept header does not support OCI manifests` {#oci-manifest-found-but-accept-header-does-not-support-oci-manifests-error}

Si vous ne parvenez pas à extraire une image, les journaux du registre peuvent contenir une erreur similaire à :

```plaintext
manifest unknown: OCI manifest found, but accept header does not support OCI manifests
```

Cette erreur se produit lorsqu'un client n'envoie pas l'en-tête `Accept: application/vnd.oci.image.manifest.v1+json` correct. Assurez-vous que la version de votre client Docker est à jour. Si vous utilisez un outil tiers, assurez-vous qu'il est capable de gérer les manifestes OCI.
