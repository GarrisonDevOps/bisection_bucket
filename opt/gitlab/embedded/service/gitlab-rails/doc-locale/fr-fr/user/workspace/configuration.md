---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Configurez vos workspaces GitLab pour gérer vos environnements de développement GitLab.
title: Configurer les workspaces
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez utiliser les [workspaces](_index.md) pour créer et gérer des environnements de développement isolés pour vos projets GitLab. Chaque workspace inclut son propre ensemble de dépendances, de bibliothèques et d'outils, que vous pouvez personnaliser pour répondre aux besoins spécifiques de chaque projet.

## Configurer l'infrastructure des workspaces {#set-up-workspace-infrastructure}

Avant de [créer un workspace](#create-a-workspace), vous devez configurer votre infrastructure une seule fois. Pour configurer l'infrastructure des workspaces, quel que soit le fournisseur cloud, vous devez :

1. Configurer un cluster Kubernetes pris en charge par l'[agent GitLab pour Kubernetes](../clusters/agent/_index.md). Consultez les [versions de Kubernetes prises en charge](../clusters/agent/_index.md#supported-kubernetes-versions-for-gitlab-features).
1. Vérifier que la mise à l'échelle automatique du cluster Kubernetes est activée.
1. Dans le cluster Kubernetes :
   1. Vérifier qu'une [classe de stockage par défaut](https://kubernetes.io/docs/concepts/storage/storage-classes/) est définie afin que les volumes puissent être provisionnés dynamiquement pour chaque workspace.
1. Effectuer toutes les étapes du [tutoriel de configuration de l'agent GitLab pour Kubernetes](set_up_gitlab_agent_and_proxies.md).
1. Facultatif. [Créer et exécuter des conteneurs dans un workspace](#build-and-run-containers-in-a-workspace).
1. Facultatif. [Configurer la prise en charge des registres de conteneurs privés](#configure-support-for-private-container-registries).
1. Facultatif. [Configurer l'accès sudo pour un workspace](#configure-sudo-access-for-a-workspace).

Si vous utilisez AWS, vous pouvez utiliser notre tutoriel OpenTofu. Pour plus d'informations, consultez le [tutoriel de configuration de l'infrastructure des workspaces sur AWS](set_up_infrastructure.md).

## Créer un workspace {#create-a-workspace}

{{< history >}}

- **Variables** [introduites](https://gitlab.com/gitlab-org/gitlab/-/issues/463514) dans GitLab 17.1.
- **Workspace automatically terminates after** [supprimé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/166065) dans GitLab 17.6.
- **Workspace can be created from Merge Request page** [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/187320) dans GitLab 18.0.

{{< /history >}}

> [!warning]
> Créez un workspace uniquement à partir de projets de confiance.

Prérequis :

- Vous devez [configurer l'infrastructure des workspaces](#set-up-workspace-infrastructure).
- Vous devez disposer du rôle Developer, Maintainer ou Owner pour les projets du workspace et de l'agent.

{{< tabs >}}

{{< tab title="Depuis un projet" >}}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Sur la page du projet, sélectionnez le menu déroulant **Code** dans le coin supérieur droit, puis dans la section **Espaces de travail**, sélectionnez **Nouvel espace de travail**.
1. Dans la liste déroulante **Agent de cluster**, sélectionnez un agent de cluster appartenant au groupe auquel le projet appartient.
1. Dans la liste déroulante **Git reference**, sélectionnez la branche, le tag ou le hash de commit que GitLab utilise pour créer le workspace. Par défaut, il s'agit de la branche que vous consultez.
1. Dans la liste déroulante **Devfile**, sélectionnez l'une des options suivantes :
   - [Devfile par défaut de GitLab](_index.md#gitlab-default-devfile).
   - [Devfile personnalisé](_index.md#custom-devfile).
1. Dans **Variables**, saisissez les clés et les valeurs des variables d'environnement que vous souhaitez injecter dans le workspace. Pour ajouter une nouvelle variable, sélectionnez **Ajouter une variable**.
1. Sélectionnez **Créer un espace de travail**.

{{< /tab >}}

{{< tab title="À partir d'une merge request" >}}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**.
1. Sélectionnez la merge request pour laquelle vous souhaitez créer un workspace.
1. Sélectionnez **Code** > **Ouvrir dans l'espace de travail**.
1. Dans la liste déroulante **Agent de cluster**, sélectionnez un agent de cluster appartenant au groupe auquel le projet appartient.
1. Dans la liste déroulante **Git reference**, sélectionnez la branche, le tag ou le hash de commit que GitLab utilise pour créer le workspace. Par défaut, il s'agit de la branche source de la merge request.
1. Dans la liste déroulante **Devfile**, sélectionnez l'une des options suivantes :
   - [Devfile par défaut de GitLab](_index.md#gitlab-default-devfile).
   - [Devfile personnalisé](_index.md#custom-devfile).
1. Dans **Variables**, saisissez les clés et les valeurs des variables d'environnement que vous souhaitez injecter dans le workspace. Pour ajouter une nouvelle variable, sélectionnez **Ajouter une variable**.
1. Sélectionnez **Créer un espace de travail**.

{{< /tab >}}

{{< /tabs >}}

Le démarrage du workspace peut prendre quelques minutes. Pour ouvrir le workspace, sous **Aperçu**, sélectionnez le workspace. Vous avez également accès au terminal et pouvez installer toutes les dépendances nécessaires.

### Surveiller la progression du démarrage du workspace {#monitor-workspace-startup-progress}

Lorsque vous démarrez un workspace, vous pouvez surveiller la progression des tâches d'initialisation et des événements `postStart` en consultant les journaux du workspace. Pour plus d'informations, consultez le [répertoire des journaux du workspace](_index.md#workspace-logs-directory).

## Compatibilité des plateformes {#platform-compatibility}

Les exigences de plateforme pour les workspaces dépendent de vos besoins en développement.

Pour les fonctionnalités de base des workspaces, ceux-ci s'exécutent sur tout cluster Kubernetes `linux/amd64` prenant en charge l'agent GitLab pour Kubernetes, quel que soit le système d'exploitation sous-jacent.

Pour choisir une méthode adaptée à vos exigences de plateforme, consultez [configurer l'accès sudo pour un workspace](#configure-sudo-access-for-a-workspace).

## Créer et exécuter des conteneurs dans un workspace {#build-and-run-containers-in-a-workspace}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/13983) dans GitLab 17.4.

{{< /history >}}

Les environnements de développement nécessitent souvent la création et l'exécution de conteneurs pour gérer et utiliser les dépendances lors de l'exécution. Pour créer et exécuter des conteneurs dans un workspace, consultez [configurer l'accès sudo pour un workspace](#configure-sudo-access-for-a-workspace).

## Configurer la prise en charge des registres de conteneurs privés {#configure-support-for-private-container-registries}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/14664) dans GitLab 17.6.

{{< /history >}}

Pour utiliser des images provenant de registres de conteneurs privés :

1. Créez un [secret d'extraction d'image dans Kubernetes](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/).
1. Ajoutez le `name` et le `namespace` de ce secret à la [configuration de l'agent GitLab pour Kubernetes](gitlab_agent_configuration.md).

Pour plus d'informations, consultez [`image_pull_secrets`](settings.md#image_pull_secrets).

## Configurer l'accès sudo pour un workspace {#configure-sudo-access-for-a-workspace}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/13983) dans GitLab 17.4.

{{< /history >}}

Les environnements de développement nécessitent souvent des permissions sudo pour installer, configurer et utiliser les dépendances lors de l'exécution. Choisissez la méthode qui correspond à vos exigences de plateforme :

| Méthode                                   | Exigences de plateforme                                                                                                                                                                                                                                                                     | Utilisation |
|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------|
| [Sysbox](#with-sysbox)                   | Pour obtenir des informations à jour, consultez la [matrice de compatibilité des distributions Sysbox](https://github.com/nestybox/sysbox/blob/master/docs/distro-compat.md).                                                                                                                                     | Améliore l'isolation des conteneurs et permet aux conteneurs d'exécuter les mêmes charges de travail que les machines virtuelles. |
| [Kata Containers](#with-kata-containers) | Pour obtenir des informations à jour, consultez les [guides d'installation de Kata Containers](https://github.com/kata-containers/kata-containers/tree/main/docs/install).                                                                                                                                     | Les machines virtuelles légères fonctionnent comme des conteneurs, mais offrent une isolation des charges de travail et une sécurité renforcées. |
| [Espaces de nommage utilisateur](#with-user-namespaces) | La version 1.33 de Kubernetes ou une version ultérieure dispose des espaces de nommage utilisateur activés derrière une fonctionnalité Kubernetes qui est activée par défaut. Pour obtenir des informations à jour, consultez les [Feature Gates de Kubernetes](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/). | Aucune installation de runtime supplémentaire n'est requise. Isole les utilisateurs des conteneurs des utilisateurs hôtes pour une sécurité améliorée. |

Prérequis :

- Vos images de conteneurs doivent prendre en charge les [identifiants utilisateur arbitraires](_index.md#arbitrary-user-ids). Même avec l'accès sudo configuré, les images de conteneurs utilisées dans un [devfile](_index.md#devfile) ne peuvent pas s'exécuter avec un identifiant utilisateur de `0`.

### Avec Sysbox {#with-sysbox}

[Sysbox](https://github.com/nestybox/sysbox) est un runtime de conteneurs qui améliore l'isolation des conteneurs et leur permet d'exécuter les mêmes charges de travail que les machines virtuelles.

Pour configurer l'accès sudo avec Sysbox :

1. Dans votre cluster Kubernetes, [installez Sysbox](https://github.com/nestybox/sysbox#installation).
1. Configurez l'agent GitLab pour Kubernetes :

   - Définissez la classe de runtime par défaut. Dans [`default_runtime_class`](settings.md#default_runtime_class), saisissez la classe de runtime pour Sysbox. Par exemple, `sysbox-runc`.
   - Activez l'élévation de privilèges. Définissez [`allow_privilege_escalation`](settings.md#allow_privilege_escalation) sur `true`.
   - Configurez les annotations requises par Sysbox. Définissez [`annotations`](settings.md#annotations) sur `{"io.kubernetes.cri-o.userns-mode": "auto:size=65536"}`.

### Avec Kata Containers {#with-kata-containers}

[Kata Containers](https://github.com/kata-containers/kata-containers) est une implémentation standard de machines virtuelles légères qui fonctionnent comme des conteneurs, mais offrent l'isolation des charges de travail et la sécurité des machines virtuelles.

Pour configurer l'accès sudo avec Kata Containers :

1. Dans votre cluster Kubernetes, [installez Kata Containers](https://github.com/kata-containers/kata-containers/tree/main/docs/install).
1. Configurez l'agent GitLab pour Kubernetes :

   - Définissez la classe de runtime par défaut. Dans [`default_runtime_class`](settings.md#default_runtime_class), saisissez la classe de runtime pour Kata Containers. Par exemple, `kata-qemu`.
   - Activez l'élévation de privilèges. Définissez [`allow_privilege_escalation`](settings.md#allow_privilege_escalation) sur `true`.

### Avec les espaces de nommage utilisateur {#with-user-namespaces}

Les [espaces de nommage utilisateur](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/) isolent les utilisateurs des conteneurs des utilisateurs hôtes.

Pour configurer l'accès sudo avec les espaces de nommage utilisateur :

1. Dans votre cluster Kubernetes, [configurez les espaces de nommage utilisateur](https://kubernetes.io/blog/2024/04/22/userns-beta/).
1. Configurez l'agent GitLab pour Kubernetes :

   - Définissez [`use_kubernetes_user_namespaces`](settings.md#use_kubernetes_user_namespaces) sur `true`.
   - Définissez [`allow_privilege_escalation`](settings.md#allow_privilege_escalation) sur `true`.

## Se connecter à un workspace via SSH {#connect-to-a-workspace-with-ssh}

Prérequis :

- Vous devez activer l'accès SSH pour les images spécifiées dans votre [devfile](_index.md#devfile). Pour plus d'informations, consultez [mettre à jour l'image de conteneur de votre workspace](#update-your-workspace-container-image).
- Vous devez configurer un équilibreur de charge TCP pointant vers le proxy des workspaces GitLab. Pour plus d'informations, consultez [mettre à jour vos enregistrements DNS](set_up_gitlab_agent_and_proxies.md#update-your-dns-records).

Pour vous connecter à un workspace avec un client SSH :

1. Obtenez l'adresse IP externe de votre service `gitlab-workspaces-proxy-ssh` :

   ```shell
   kubectl -n gitlab-workspaces get service gitlab-workspaces-proxy-ssh
   ```

1. Obtenez le nom du workspace :

   1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**.
   1. Sélectionnez **Votre travail**.
   1. Sélectionnez **Espaces de travail**.
   1. Copiez le nom du workspace auquel vous souhaitez vous connecter.

1. Exécutez cette commande :

   ```shell
   ssh <workspace_name>@<ssh_proxy_IP_address>
   ```

1. Pour le mot de passe, saisissez votre jeton d'accès personnel avec au moins la portée `read_api`.

Lorsque vous vous connectez à `gitlab-workspaces-proxy` via l'équilibreur de charge TCP, `gitlab-workspaces-proxy` examine le nom d'utilisateur (nom du workspace) et interagit avec GitLab pour vérifier :

- Le jeton d'accès personnel
- L'accès de l'utilisateur au workspace

### Mettre à jour l'image de conteneur de votre workspace {#update-your-workspace-container-image}

Vous pouvez mettre à jour vos images de workspace personnalisées de deux façons.

Si votre image de workspace est basée sur l'[image de base du workspace](_index.md#workspace-base-image), la prise en charge SSH est déjà configurée et prête à l'emploi. Cette approche garantit que votre image dispose de toutes les configurations de workspace nécessaires. Pour plus d'informations, consultez [créer une image de workspace personnalisée](create_image.md).

Si vous préférez ne pas utiliser l'image de base du workspace, vous pouvez créer votre propre image de base. Dans ce cas, configurez manuellement la prise en charge SSH dans vos images de runtime :

1. Installez [`sshd`](https://man.openbsd.org/sshd.8) dans vos images de runtime.
1. Créez un utilisateur nommé `gitlab-workspaces` pour permettre l'accès à votre conteneur sans mot de passe.

Voici un exemple de configuration SSH :

```dockerfile
FROM golang:1.20.5-bullseye

# Install `openssh-server` and other dependencies
RUN apt update \
    && apt upgrade -y \
    && apt install openssh-server sudo curl git wget software-properties-common apt-transport-https --yes \
    && rm -rf /var/lib/apt/lists/*

# Permit empty passwords
RUN sed -i 's/nullok_secure/nullok/' /etc/pam.d/common-auth
RUN echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config

# Generate a workspace host key
RUN ssh-keygen -A
RUN chmod 775 /etc/ssh/ssh_host_rsa_key && \
    chmod 775 /etc/ssh/ssh_host_ecdsa_key && \
    chmod 775 /etc/ssh/ssh_host_ed25519_key

# Create a `gitlab-workspaces` user
RUN useradd -l -u 5001 -G sudo -md /home/gitlab-workspaces -s /bin/bash gitlab-workspaces
RUN passwd -d gitlab-workspaces
ENV HOME=/home/gitlab-workspaces
WORKDIR $HOME
RUN mkdir -p /home/gitlab-workspaces && chgrp -R 0 /home && chmod -R g=u /etc/passwd /etc/group /home

# Allow sign-in access to `/etc/shadow`
RUN chmod 775 /etc/shadow

USER gitlab-workspaces
```

## Sujets connexes {#related-topics}

- [Tutoriel : configurer l'agent GitLab pour Kubernetes](set_up_gitlab_agent_and_proxies.md)
- [Paramètres des workspaces](settings.md)
- [Dépannage des workspaces](workspaces_troubleshooting.md)
- [Guide de démarrage rapide pour les workspaces de développement à distance GitLab](https://go.gitlab.com/AVKFvy)
- [Configurez votre infrastructure pour des environnements de développement cloud à la demande dans GitLab](https://go.gitlab.com/dp75xo)
