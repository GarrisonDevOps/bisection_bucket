---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Créez une image de workspace personnalisée pour prendre en charge n'importe quel workspace que vous créez dans GitLab."
title: 'Tutoriel : créer une image de workspace personnalisée prenant en charge les ID utilisateur arbitraires'
---

<!-- vale gitlab_base.FutureTense = NO -->

Ce tutoriel vous guide dans la création d'une image de workspace personnalisée qui répond aux besoins de votre projet. Une fois terminé, vous pouvez utiliser cette image personnalisée avec n'importe quel [workspace](_index.md) que vous créez dans GitLab.

Pour créer une image de workspace personnalisée prenant en charge les ID utilisateur arbitraires :

1. [Créer un Dockerfile](#create-a-dockerfile).
1. [Créer l'image de workspace personnalisée](#build-the-custom-workspace-image).
1. [Pousser l'image de workspace personnalisée vers le registre de conteneurs GitLab](#push-the-custom-workspace-image-to-the-gitlab-container-registry).
1. [Utiliser l'image de workspace personnalisée dans GitLab](#use-the-custom-workspace-image-in-gitlab).

## Avant de commencer {#before-you-begin}

Vous avez besoin des éléments suivants :

- Un compte GitLab avec l'autorisation de créer et de pousser des images de conteneurs vers le registre de conteneurs GitLab.
- Docker installé sur votre machine locale.

## Créer un Dockerfile {#create-a-dockerfile}

Créez un Dockerfile qui utilise l'[image de base de workspace](_index.md#workspace-base-image) (`registry.gitlab.com/gitlab-org/gitlab-build-images:workspaces-base`) du registre de conteneurs GitLab comme point de départ :

```Dockerfile
FROM registry.gitlab.com/gitlab-org/gitlab-build-images:workspaces-base

# Install additional tools your project needs
RUN sudo apt-get update && \
    sudo apt-get install -y tree && \
    sudo rm -rf /var/lib/apt/lists/*

# Install project-specific tools using mise
# For example, install Node.js version 20
RUN mise install node@20 && \
    mise use node@20

# Install global packages
RUN npm install -g @angular/cli

# Set up your project environment
ENV NODE_ENV=development

# Create project directories
RUN mkdir -p /home/gitlab-workspaces/projects
```

Personnalisez ces étapes en fonction des exigences spécifiques de votre projet. Ensuite, créez l'image de workspace personnalisée.

## Créer l'image de workspace personnalisée {#build-the-custom-workspace-image}

Votre Dockerfile étant prêt, vous pouvez maintenant créer votre image de workspace personnalisée :

1. Exécutez la commande suivante dans le répertoire où vous avez créé le Dockerfile :

   ```shell
   docker build -t my-gitlab-workspace .
   ```

   Cette opération peut prendre quelques minutes selon votre connexion Internet et la vitesse de votre système.

1. Une fois le processus de création terminé, testez l'image localement :

   ```shell
   docker run -ti my-gitlab-workspace sh
   ```

Vous devriez maintenant avoir l'autorisation d'exécuter des commandes en tant qu'utilisateur `gitlab-workspaces`. Parfait ! Votre image fonctionne localement. Ensuite, vous allez la rendre disponible dans GitLab.

## Pousser l'image de workspace personnalisée vers le registre de conteneurs GitLab {#push-the-custom-workspace-image-to-the-gitlab-container-registry}

Poussez votre image de workspace personnalisée vers le registre de conteneurs GitLab pour l'utiliser dans vos projets :

1. Connectez-vous à votre compte GitLab :

   ```shell
   docker login registry.gitlab.com
   ```

1. Taguez l'image avec l'URL du registre de conteneurs GitLab :

   ```shell
   docker tag my-gitlab-workspace registry.gitlab.com/your-namespace/my-gitlab-workspace:latest
   ```

   N'oubliez pas de remplacer `your-namespace` par votre espace de nommage GitLab réel.

1. Poussez l'image vers le registre de conteneurs GitLab :

   ```shell
   docker push registry.gitlab.com/your-namespace/my-gitlab-workspace:latest
   ```

   Ce chargement peut prendre un certain temps selon la vitesse de votre connexion Internet.

Bien joué ! Votre image de workspace personnalisée est maintenant stockée en toute sécurité dans le registre de conteneurs GitLab et prête à être utilisée.

## Utiliser l'image de workspace personnalisée dans GitLab {#use-the-custom-workspace-image-in-gitlab}

Pour la dernière étape, vous allez configurer votre projet pour utiliser votre image de workspace personnalisée :

1. Mettez à jour l'image de conteneur dans le fichier `.devfile.yaml` de votre projet :

   ```yaml
   schemaVersion: 2.2.0
   components:
     - name: tooling-container
       attributes:
         gl/inject-editor: true
       container:
         image: registry.gitlab.com/your-namespace/my-gitlab-workspace:latest
   ```

   N'oubliez pas de remplacer `your-namespace` par votre espace de nommage GitLab réel.

Félicitations ! Vous avez créé et configuré avec succès une image de workspace personnalisée prenant en charge les ID utilisateur arbitraires. Vous pouvez maintenant utiliser cette image personnalisée avec n'importe quel [workspace](_index.md) que vous créez dans GitLab.

## Sujets connexes {#related-topics}

- [Dépannage des workspaces](workspaces_troubleshooting.md)
