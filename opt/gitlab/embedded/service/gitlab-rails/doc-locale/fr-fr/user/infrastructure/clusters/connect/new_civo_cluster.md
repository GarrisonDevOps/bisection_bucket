---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Créer un cluster Kubernetes Civo
---

Chaque nouveau compte Civo reçoit [250 $ de crédit](https://dashboard.civo.com/signup) pour démarrer avec l'intégration GitLab avec Civo Kubernetes. Vous pouvez également utiliser une application marketplace pour installer GitLab sur votre cluster Kubernetes Civo.

Apprenez à créer un nouveau cluster sur Civo Kubernetes via [Infrastructure as Code (IaC)](../../_index.md). Ce processus utilise les fournisseurs Terraform Civo et Kubernetes pour créer des clusters Kubernetes Civo. Vous connectez les clusters à GitLab en utilisant l'agent GitLab pour Kubernetes.

**Avant de commencer** :

- Un [compte Civo](https://dashboard.civo.com/signup).
- [Un runner](https://docs.gitlab.com/runner/install/) que vous pouvez utiliser pour exécuter le pipeline CI/CD GitLab.

**Étapes** :

1. [Importer l'exemple de projet](#import-the-example-project).
1. [Enregistrer l'agent pour Kubernetes](#register-the-agent).
1. [Configurer votre projet](#configure-your-project).
1. [Provisionner votre cluster](#provision-your-cluster).

## Importer l'exemple de projet {#import-the-example-project}

Pour créer un cluster depuis GitLab à l'aide d'Infrastructure as Code, vous devez créer un projet à partir duquel gérer le cluster. Dans ce tutoriel, vous commencez avec un exemple de projet et le modifiez selon vos besoins.

Commencez par [importer l'exemple de projet par URL](../../../import/third_party_systems/repo_by_url.md).

Pour importer le projet :

1. Dans GitLab, dans la barre supérieure, sélectionnez **Rechercher ou accéder à**.
1. Sélectionnez **Voir tous mes projets**.
1. À droite de la page, sélectionnez **Nouveau projet**.
1. Sélectionnez **Importer un projet**.
1. Sélectionnez **Dépôt par URL**.
1. Pour l'**URL du dépôt Git**, saisissez `https://gitlab.com/civocloud/gitlab-terraform-civo.git`.
1. Renseignez les champs et sélectionnez **Créer le projet**.

Ce projet vous fournit :

- Un [cluster sur Civo](https://gitlab.com/civocloud/gitlab-terraform-civo/-/blob/master/civo.tf) avec des valeurs par défaut pour le nom, la région, le nombre de nœuds et la version de Kubernetes.
- L'[agent GitLab pour Kubernetes](https://gitlab.com/civocloud/gitlab-terraform-civo/-/blob/master/agent.tf) installé dans le cluster.

## Enregistrer l'agent {#register-the-agent}

Pour créer un agent GitLab pour Kubernetes :

1. Dans la barre latérale gauche, sélectionnez **Opération** > **Clusters Kubernetes**.
1. Sélectionnez **Connecter un cluster**.
1. Dans la liste déroulante **Sélectionner un agent**, sélectionnez `civo-agent` puis sélectionnez **S'inscrire**.
1. GitLab génère un jeton d'accès à l'agent pour l'agent. Stockez ce jeton secret de manière sécurisée, car vous en aurez besoin ultérieurement.
1. GitLab fournit une adresse pour le serveur d'agent (KAS), dont vous aurez également besoin ultérieurement.

## Configurer votre projet {#configure-your-project}

Utilisez des variables d'environnement CI/CD pour configurer votre projet.

**Configuration requise** :

1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD**.
1. Développez **Variables**.
1. Définissez la variable `CIVO_TOKEN` sur le jeton de votre compte Civo.
1. Définissez la variable `TF_VAR_agent_token` sur le jeton d'agent que vous avez reçu lors de la tâche précédente.
1. Définissez la variable `TF_VAR_kas_address` sur l'adresse du serveur d'agent de la tâche précédente.

![Configuration requise](img/variables_civo_v17_3.png)

**Configuration facultative** :

Le fichier [`variables.tf`](https://gitlab.com/civocloud/gitlab-terraform-civo/-/blob/master/variables.tf) contient d'autres variables que vous pouvez remplacer selon vos besoins :

- `TF_VAR_civo_region` : définissez la région de votre cluster.
- `TF_VAR_cluster_name` : définissez le nom de votre cluster.
- `TF_VAR_cluster_description` : définissez une description pour le cluster. Pour créer une référence à votre projet GitLab sur la page de détails de votre cluster Civo, définissez cette valeur sur `$CI_PROJECT_URL`. Cette valeur vous aide à déterminer quel projet était responsable du provisionnement du cluster visible dans le tableau de bord Civo.
- `TF_VAR_target_nodes_size` : définissez la taille des nœuds à utiliser pour le cluster.
- `TF_VAR_num_target_nodes` : définissez le nombre de nœuds Kubernetes.
- `TF_VAR_agent_version` : définissez la version de l'agent GitLab pour Kubernetes.
- `TF_VAR_agent_namespace` : définissez l'espace de nommage Kubernetes pour l'agent GitLab pour Kubernetes.

Consultez la documentation du [fournisseur Terraform Civo](https://registry.terraform.io/providers/civo/civo/latest/docs/resources/kubernetes_cluster) et du [fournisseur Terraform Kubernetes](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs) pour d'autres options de ressources.

## Provisionner votre cluster {#provision-your-cluster}

Après avoir configuré votre projet, déclenchez manuellement le provisionnement de votre cluster. Dans GitLab :

1. Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**.
1. Sélectionnez **Nouveau pipeline**.
1. Sélectionnez **Exécuter le pipeline**, puis sélectionnez le pipeline nouvellement créé dans la liste.
1. En regard du job **déploiement**, sélectionnez **Action manuelle** ({{< icon name="status_manual" >}}).

Lorsque le pipeline se termine avec succès, vous pouvez voir votre nouveau cluster :

- Dans le tableau de bord Civo : dans l'onglet Kubernetes.
- Dans GitLab : depuis la barre latérale de votre projet, sélectionnez **Opération** > **Clusters Kubernetes**.

Si vous n'avez pas défini la variable `TF_VAR_civo_region`, le cluster sera créé dans la région 'lon1'.

## Utiliser votre cluster {#use-your-cluster}

Une fois le cluster provisionné, il est connecté à GitLab et prêt pour les déploiements. Pour vérifier la connexion :

1. Dans la barre latérale gauche, sélectionnez **Opération** > **Clusters Kubernetes**.
1. Dans la liste, consultez la colonne **État de la connexion**.

Pour plus d'informations sur les capacités de la connexion, consultez [la documentation de l'agent GitLab pour Kubernetes](../_index.md).

## Supprimer le cluster {#remove-the-cluster}

Un job de nettoyage est inclus dans votre pipeline par défaut.

Pour supprimer toutes les ressources créées :

1. Dans la barre latérale gauche, sélectionnez **Version** > **Pipelines**, puis sélectionnez le pipeline le plus récent.
1. En regard du job **destroy-environment**, sélectionnez **Action manuelle** ({{< icon name="status_manual" >}}).

## Assistance Civo {#civo-support}

Cette intégration Civo est prise en charge par Civo. Envoyez vos demandes d'assistance à [l'assistance Civo](https://www.civo.com/contact).
