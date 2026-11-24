---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Créer un cluster Amazon EKS
---

Vous pouvez créer un cluster sur Amazon Elastic Kubernetes Service (EKS) via [Infrastructure as Code (IaC)](../../_index.md). Ce processus utilise les fournisseurs Terraform AWS et Kubernetes pour créer des clusters EKS. Vous connectez les clusters à GitLab en utilisant l'agent GitLab pour Kubernetes.

**Avant de commencer** :

- Un compte Amazon Web Services (AWS), avec un ensemble de [credentials de sécurité](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-prereqs.html) configurés.
- [Un runner](https://docs.gitlab.com/runner/install/) que vous pouvez utiliser pour exécuter le pipeline CI/CD GitLab.

**Étapes** :

1. [Importer l'exemple de projet](#import-the-example-project).
1. [Enregistrer l'agent pour Kubernetes](#register-the-agent).
1. [Configurer votre projet](#configure-your-project).
1. [Provisionner votre cluster](#provision-your-cluster).

## Importer l'exemple de projet {#import-the-example-project}

Pour créer un cluster depuis GitLab en utilisant l'Infrastructure as Code, vous devez créer un projet à partir duquel gérer le cluster. Dans ce tutoriel, vous commencez avec un exemple de projet et le modifiez selon vos besoins.

Commencez par [importer l'exemple de projet par URL](../../../import/third_party_systems/repo_by_url.md).

Pour importer le projet :

1. Dans GitLab, dans la barre supérieure, sélectionnez **Rechercher ou accéder à**.
1. Sélectionnez **Voir tous mes projets**.
1. Sur la droite de la page, sélectionnez **Nouveau projet**.
1. Sélectionnez **Importer un projet**.
1. Sélectionnez **Dépôt par URL**.
1. Pour l'**URL du dépôt Git**, saisissez `https://gitlab.com/gitlab-org/configure/examples/gitlab-terraform-eks.git`.
1. Complétez les champs et sélectionnez **Créer le projet**.

Ce projet vous fournit :

- Un Amazon [Virtual Private Cloud (VPC)](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-eks/-/blob/main/vpc.tf).
- Un cluster Amazon [Elastic Kubernetes Service (EKS)](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-eks/-/blob/main/eks.tf).
- L'[agent GitLab pour Kubernetes](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-eks/-/blob/main/agent.tf) installé dans le cluster.

## Enregistrer l'agent {#register-the-agent}

{{< history >}}

- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/81054) dans GitLab 14.9. Un [flag](../../../../administration/feature_flags/_index.md) nommé `certificate_based_clusters` a modifié le menu **Actions** pour se concentrer sur l'agent plutôt que sur les certificats. Fonctionnalité désactivée par défaut.

{{< /history >}}

Pour créer un agent GitLab pour Kubernetes :

1. Dans la barre latérale gauche, sélectionnez **Opération** > **Clusters Kubernetes**.
1. Sélectionnez **Connecter un cluster (agent)**.
1. Dans la liste déroulante **Sélectionner un agent**, sélectionnez `eks-agent` et sélectionnez **Enregistrer un agent**.
1. GitLab génère un jeton d'enregistrement pour l'agent. Stockez ce jeton secret de manière sécurisée, car vous en aurez besoin ultérieurement.
1. GitLab fournit une adresse pour le serveur d'agent (KAS), dont vous aurez également besoin ultérieurement.

## Configurer les credentials AWS {#set-up-aws-credentials}

Configurez vos credentials AWS lorsque vous souhaitez authentifier AWS avec GitLab.

1. Créez un [utilisateur IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html) ou un [rôle IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html).
1. Assurez-vous que votre utilisateur ou rôle IAM dispose des autorisations appropriées pour votre projet. Pour cet exemple de projet, vous devez disposer des autorisations répertoriées dans le bloc JSON suivant. Vous pouvez étendre ces autorisations lors de la configuration de votre propre projet.

   ```json
   // IAM custom Policy definition
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "VisualEditor0",
         "Effect": "Allow",
         "Action": [
           "ec2:*",
           "eks:*",
           "elasticloadbalancing:*",
           "autoscaling:*",
           "cloudwatch:*",
           "logs:*",
           "kms:DescribeKey",
           "kms:TagResource",
           "kms:UntagResource",
           "kms:ListResourceTags",
           "kms:CreateKey",
           "kms:CreateAlias",
           "kms:ListAliases",
           "kms:DeleteAlias",
           "iam:AddRoleToInstanceProfile",
           "iam:AttachRolePolicy",
           "iam:CreateInstanceProfile",
           "iam:CreateRole",
           "iam:CreateServiceLinkedRole",
           "iam:GetRole",
           "iam:ListAttachedRolePolicies",
           "iam:ListRolePolicies",
           "iam:ListRoles",
           "iam:PassRole",
           "iam:DetachRolePolicy",
           "iam:ListInstanceProfilesForRole",
           "iam:DeleteRole",
           "iam:CreateOpenIDConnectProvider",
           "iam:CreatePolicy",
           "iam:TagOpenIDConnectProvider",
           "iam:GetPolicy",
           "iam:GetPolicyVersion",
           "iam:GetOpenIDConnectProvider",
           "iam:DeleteOpenIDConnectProvider",
           "iam:ListPolicyVersions",
           "iam:DeletePolicy"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

1. [Créez une clé d'accès pour l'utilisateur ou le rôle](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html).
1. Enregistrez votre clé d'accès et votre secret. Vous en avez besoin pour authentifier AWS avec GitLab.

## Configurer votre projet {#configure-your-project}

Utilisez des variables d'environnement CI/CD pour configurer votre projet.

**Configuration requise** :

1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD**.
1. Développez **Variables**.
1. Définissez la variable `AWS_ACCESS_KEY_ID` sur votre ID de clé d'accès AWS.
1. Définissez la variable `AWS_SECRET_ACCESS_KEY` sur votre clé d'accès secrète AWS.
1. Définissez la variable `TF_VAR_agent_token` sur le jeton d'agent affiché dans la tâche précédente.
1. Définissez la variable `TF_VAR_kas_address` sur l'adresse du serveur d'agent affichée dans la tâche précédente.

**Configuration facultative** :

Le fichier [`variables.tf`](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-eks/-/blob/main/variables.tf) contient d'autres variables que vous pouvez remplacer selon vos besoins :

- `TF_VAR_region` : définissez la région de votre cluster.
- `TF_VAR_cluster_name` : définissez le nom de votre cluster.
- `TF_VAR_cluster_version` : définissez la version de Kubernetes.
- `TF_VAR_instance_type` : définissez le type d'instance pour les nœuds Kubernetes.
- `TF_VAR_instance_count` : définissez le nombre de nœuds Kubernetes.
- `TF_VAR_agent_namespace` : définissez l'espace de nommage Kubernetes pour l'agent GitLab pour Kubernetes.

Consultez la documentation du [fournisseur Terraform AWS](https://registry.terraform.io/providers/hashicorp/aws/latest/docs) et du [fournisseur Terraform Kubernetes](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs) pour d'autres options de ressources.

## Provisionner votre cluster {#provision-your-cluster}

Après avoir configuré votre projet, déclenchez manuellement le provisionnement de votre cluster. Dans GitLab :

1. Dans la barre latérale gauche, accédez à **Version** > **Pipelines**.
1. À côté de **Play** ({{< icon name="play" >}}), sélectionnez l'icône de liste déroulante ({{< icon name="chevron-lg-down" >}}).
1. Sélectionnez **Déployer** pour déclencher manuellement le job de déploiement.

Lorsque le pipeline se termine avec succès, vous pouvez afficher le nouveau cluster :

- Dans AWS : depuis la [console EKS](https://console.aws.amazon.com/eks/home), sélectionnez **Amazon EKS** > **Clusters**.
- Dans GitLab : Dans la barre latérale gauche, sélectionnez **Opération** > **Clusters Kubernetes**.

## Utiliser votre cluster {#use-your-cluster}

Une fois le cluster provisionné, il est connecté à GitLab et prêt pour les déploiements. Pour vérifier la connexion :

1. Dans la barre latérale gauche, sélectionnez **Opération** > **Clusters Kubernetes**.
1. Dans la liste, consultez la colonne **État de la connexion**.

Pour plus d'informations sur les fonctionnalités de la connexion, consultez [la documentation de l'agent GitLab pour Kubernetes](../_index.md).

## Supprimer le cluster {#remove-the-cluster}

Un job de nettoyage n'est pas inclus dans votre pipeline par défaut. Pour supprimer toutes les ressources créées, vous devez modifier votre modèle GitLab CI/CD avant d'exécuter le job de nettoyage.

Pour supprimer toutes les ressources :

1. Ajoutez ce qui suit à votre fichier `.gitlab-ci.yml` :

   ```yaml
   stages:
     - init
     - validate
     - test
     - build
     - deploy
     - cleanup

   destroy:
     extends: .terraform:destroy
     needs: []
   ```

1. Dans la barre latérale gauche, sélectionnez **Version** > **Pipelines** et sélectionnez le pipeline le plus récent.
1. Pour le job `destroy`, sélectionnez **Play** ({{< icon name="play" >}}).
