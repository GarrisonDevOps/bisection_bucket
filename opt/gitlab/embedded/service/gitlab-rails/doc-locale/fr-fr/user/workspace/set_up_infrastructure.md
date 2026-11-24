---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Créez l'infrastructure nécessaire pour prendre en charge les workspaces GitLab dans des environnements de développement cloud à la demande."
title: 'Tutoriel : configurer l''infrastructure des workspaces sur AWS'
---

<!-- vale gitlab_base.FutureTense = NO -->

Ce tutoriel vous guide dans la configuration de l'infrastructure des workspaces GitLab sur AWS à l'aide de [OpenTofu](https://opentofu.org/), un fork open source de Terraform via l'Infrastructure as Code (IaC).

## Avant de commencer {#before-you-begin}

Pour suivre ce tutoriel, vous devez disposer des éléments suivants :

- Un compte Amazon Web Services (AWS).
- Un nom de domaine pour votre environnement de workspaces.

Pour configurer l'infrastructure des workspaces GitLab :

1. [Dupliquer le dépôt](#fork-the-repository)
1. [Configurer les identifiants AWS](#set-up-aws-credentials)
1. [Préparer le domaine et les certificats](#prepare-domain-and-certificates)
1. [Créer les clés requises](#create-required-keys)
1. [Créer un token pour l'agent GitLab pour Kubernetes](#create-a-gitlab-agent-for-kubernetes-token)
1. [Configurer OAuth GitLab](#configure-gitlab-oauth)
1. [Configurer les variables CI/CD](#configure-cicd-variables)
1. [Mettre à jour la configuration de l'agent GitLab pour Kubernetes](#update-the-gitlab-agent-for-kubernetes-configuration)
1. [Exécuter le pipeline](#run-the-pipeline)
1. [Configurer les enregistrements DNS](#configure-dns-records)
1. [Autoriser l'agent](#authorize-the-agent)
1. [Créer un workspace et vérifier la configuration](#create-a-workspace-and-verify-setup)

## Dupliquer le dépôt {#fork-the-repository}

Tout d'abord, vous devez créer votre propre copie du dépôt de configuration de l'infrastructure afin de pouvoir le configurer pour votre environnement.

> [!note]
> Il n'est pas possible de créer des workspaces à partir de projets dans votre espace de nommage personnel. À la place, dupliquez le dépôt vers un groupe principal ou un sous-groupe.

Pour dupliquer le dépôt :

1. Accédez au dépôt [Workspaces Infrastructure Setup AWS](https://gitlab.com/gitlab-org/workspaces/examples/workspaces-infrastructure-setup-aws).
1. [Créez une duplication](../project/repository/forking_workflow.md#create-a-fork) du dépôt.

## Configurer les identifiants AWS {#set-up-aws-credentials}

Ensuite, configurez les autorisations nécessaires dans AWS afin que l'infrastructure puisse être correctement provisionnée.

Pour configurer les identifiants AWS :

1. Créez un [utilisateur IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html) ou un [rôle IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html).
1. Attribuez les autorisations suivantes :

   ```json
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

1. [Créez une clé d'accès](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) pour l'utilisateur ou le rôle.
1. Enregistrez votre identifiant de clé d'accès et votre clé d'accès secrète. Vous en aurez besoin lors de la configuration des variables CI/CD ultérieurement.

## Préparer le domaine et les certificats {#prepare-domain-and-certificates}

Pour que vos workspaces soient accessibles, vous aurez besoin d'un domaine et de certificats TLS pour sécuriser les connexions.

Pour préparer votre domaine et vos certificats :

1. Achetez un domaine ou utilisez un domaine existant pour votre environnement de workspaces.
1. Créez des certificats TLS pour :
   - Domaine du proxy GitLab Workspaces. Par exemple, `workspaces.example.dev`.
   - Domaine générique du proxy GitLab Workspaces. Par exemple, `*.workspaces.example.dev`.

Pour plus d'informations, consultez [générer des certificats TLS](set_up_gitlab_agent_and_proxies.md#generate-tls-certificates).

## Créer les clés requises {#create-required-keys}

Vous devez maintenant créer des clés de sécurité pour l'authentification et les connexions SSH.

Pour créer les clés requises :

1. Générez une clé de signature composée de lettres, de chiffres et de caractères spéciaux aléatoires. Par exemple, exécutez :

   ```shell
   openssl rand -base64 32
   ```

1. Générez une clé d'hôte SSH :

   ```shell
   ssh-keygen -f ssh-host-key -N '' -t rsa
   ```

## Créer un token pour l'agent GitLab pour Kubernetes {#create-a-gitlab-agent-for-kubernetes-token}

L'agent GitLab pour Kubernetes connecte votre cluster Kubernetes AWS à GitLab.

Pour créer un token pour l'agent :

1. Accédez à votre groupe.
1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Opération** > **Clusters Kubernetes**.
1. Sélectionnez **Connecter un cluster**.
1. Saisissez un nom pour votre agent et enregistrez-le pour une utilisation ultérieure. Par exemple, `gitlab-workspaces-agentk-eks`.
1. Sélectionnez **Créer et enregistrer**.
1. Enregistrez le token et l'adresse GitLab Relay (KAS) pour une utilisation ultérieure.
1. Sélectionnez **Continuer**.

## Configurer OAuth GitLab {#configure-gitlab-oauth}

Ensuite, configurez l'authentification OAuth pour accéder aux workspaces de manière sécurisée.

Pour configurer OAuth GitLab :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Applications**.
1. Faites défiler jusqu'à **Applications OAuth**.
1. Sélectionnez **Ajouter une nouvelle application**.
1. Mettez à jour les paramètres suivants :

   - Nom : GitLab Workspaces Proxy
   - URI de redirection : Par exemple, `https://workspaces.example.dev/auth/callback`. Remplacez par votre domaine défini par l'utilisateur.
   - Cochez la case **Confidentiel**.
   - Portées : `api`, `read_user`, `openid` et `profile`.

1. Sélectionnez **Enregistrer l'application**.
1. Enregistrez l'**Identifiant de l'application** et le **Secret** pour vos variables CI/CD.
1. Sélectionnez **Continuer**.

## Configurer les variables CI/CD {#configure-cicd-variables}

Vous devez maintenant ajouter les variables nécessaires à votre configuration CI/CD pour que le pipeline d'infrastructure puisse s'exécuter.

Pour configurer les variables CI/CD :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD**.
1. Développez **Variables**.
1. Dans la section **Variables de projet**, ajoutez les variables requises suivantes :

   | Variable                                       | Valeur |
   |------------------------------------------------|-------|
   | `AWS_ACCESS_KEY_ID`                            | Identifiant de clé d'accès AWS. |
   | `AWS_SECRET_ACCESS_KEY`                        | Clé d'accès secrète AWS. |
   | `TF_VAR_agent_token`                           | Token de l'agent GitLab pour Kubernetes. |
   | `TF_VAR_kas_address`                           | Adresse GitLab Relay (KAS). Requis si vous utilisez une instance GitLab Self-Managed. Par exemple, `grpcs://kas.gitlab.com`. |
   | `TF_VAR_workspaces_proxy_auth_client_id`       | Identifiant client de l'application OAuth. |
   | `TF_VAR_workspaces_proxy_auth_client_secret`   | Secret de l'application OAuth. |
   | `TF_VAR_workspaces_proxy_auth_redirect_uri`    | URL de rappel OAuth. Par exemple, `https://workspaces.example.dev/auth/callback`. |
   | `TF_VAR_workspaces_proxy_auth_signing_key`     | Votre clé de signature générée. |
   | `TF_VAR_workspaces_proxy_domain`               | Domaine pour le proxy des workspaces. |
   | `TF_VAR_workspaces_proxy_domain_cert`          | Certificat TLS pour le domaine du proxy. |
   | `TF_VAR_workspaces_proxy_domain_key`           | Clé TLS pour le domaine du proxy. |
   | `TF_VAR_workspaces_proxy_ssh_host_key`         | Votre clé d'hôte SSH générée. |
   | `TF_VAR_workspaces_proxy_wildcard_domain`      | Domaine générique pour les workspaces. |
   | `TF_VAR_workspaces_proxy_wildcard_domain_cert` | Certificat TLS pour le domaine générique. |
   | `TF_VAR_workspaces_proxy_wildcard_domain_key`  | Clé TLS pour le domaine générique. |

1. Facultatif. Ajoutez l'une de ces variables pour personnaliser votre déploiement :

   | Variable                                     | Valeur |
   |----------------------------------------------|-------|
   | `TF_VAR_region`                              | Région AWS. |
   | `TF_VAR_zones`                               | Zones de disponibilité AWS. |
   | `TF_VAR_name`                                | Préfixe de nom pour les ressources. |
   | `TF_VAR_cluster_endpoint_public_access`      | Accès public au point de terminaison du cluster. |
   | `TF_VAR_cluster_node_instance_type`          | Type d'instance EC2 pour les nœuds Kubernetes. |
   | `TF_VAR_cluster_node_count_min`              | Nombre minimal de nœuds de travail. |
   | `TF_VAR_cluster_node_count_max`              | Nombre maximal de nœuds de travail. |
   | `TF_VAR_cluster_node_count`                  | Nombre de nœuds de travail. |
   | `TF_VAR_cluster_node_labels`                 | Ensemble de labels à appliquer sur les nœuds du cluster. |
   | `TF_VAR_agent_namespace`                     | Espace de nommage Kubernetes pour l'agent. |
   | `TF_VAR_workspaces_proxy_namespace`          | Espace de nommage Kubernetes pour le proxy des workspaces. |
   | `TF_VAR_workspaces_proxy_ingress_class_name` | Nom de la classe Ingress. |
   | `TF_VAR_ingress_nginx_namespace`             | Espace de nommage Kubernetes pour Ingress-NGINX. |

Excellent travail ! Vous avez configuré toutes les variables nécessaires pour le déploiement de votre infrastructure.

## Mettre à jour la configuration de l'agent GitLab pour Kubernetes {#update-the-gitlab-agent-for-kubernetes-configuration}

Vous devez maintenant configurer l'agent GitLab pour Kubernetes afin de prendre en charge les workspaces.

Pour mettre à jour la configuration de l'agent :

1. Dans votre dépôt dupliqué, ouvrez le fichier `.gitlab/agents/gitlab-workspaces-agentk-eks/config.yaml`.

   > [!note]
   > Le répertoire contenant le fichier `config.yaml` doit correspondre au nom de l'agent que vous avez créé à l'étape [créer un token pour l'agent GitLab pour Kubernetes](#create-a-gitlab-agent-for-kubernetes-token).

1. Mettez à jour le fichier avec les champs requis suivants :

   ```yaml
   remote_development:
     enabled: true
     dns_zone: "workspaces.example.dev"  # Replace with your domain
   ```

   Pour plus d'options de configuration, consultez [les paramètres des workspaces](settings.md).

1. Committez et poussez ces modifications vers votre dépôt.

## Exécuter le pipeline {#run-the-pipeline}

Il est temps de déployer votre infrastructure. Vous allez exécuter le pipeline CI/CD pour créer toutes les ressources nécessaires dans AWS.

Pour exécuter le pipeline :

1. Créez un nouveau pipeline dans votre projet GitLab :
   1. Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**.
   1. Sélectionnez **Nouveau pipeline** et sélectionnez à nouveau **Nouveau pipeline** pour confirmer.
1. Vérifiez que le job `plan` réussit, puis déclenchez manuellement le job `apply`.

Lorsque le code OpenTofu s'exécute, il crée ces ressources dans AWS :

- Un Virtual Private Cloud (VPC).
- Un cluster Elastic Kubernetes Service (EKS).
- Une release Helm de l'agent GitLab pour Kubernetes.
- Une release Helm du proxy GitLab Workspaces.
- Une release Helm d'Ingress NGINX.

Excellent ! Votre infrastructure est en cours de déploiement. Cette opération peut prendre un certain temps.

## Configurer les enregistrements DNS {#configure-dns-records}

Maintenant que votre infrastructure est déployée, vous devez configurer les enregistrements DNS pour qu'ils pointent vers votre nouvel environnement.

Pour configurer les enregistrements DNS :

1. Obtenez l'adresse du load balancer Ingress-NGINX depuis la sortie du pipeline :

   ```shell
   kubectl get services -n ingress-nginx ingress-nginx-controller
   ```

1. Créez des enregistrements DNS qui font pointer vos domaines vers cette adresse. Par exemple :
   - `workspaces.example.dev` → Adresse IP du load balancer
   - `*.workspaces.example.dev` → Adresse IP du load balancer

## Autoriser l'agent {#authorize-the-agent}

Ensuite, vous allez autoriser l'agent GitLab pour Kubernetes à se connecter à votre instance GitLab.

Pour autoriser l'agent :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Espaces de travail**.
1. Dans la section **Agents du groupe**, sélectionnez l'onglet **Tous les agents**.
1. Dans la liste des agents disponibles, trouvez l'agent avec le statut **Bloqué** et sélectionnez **Autoriser**.
1. Dans la boîte de dialogue de confirmation, sélectionnez **Autoriser l'agent**.

## Créer un workspace et vérifier la configuration {#create-a-workspace-and-verify-setup}

Enfin, assurons-nous que tout fonctionne correctement en créant un workspace de test.

Pour vérifier la configuration de votre workspace :

1. Créez un nouveau workspace en suivant les étapes décrites dans [créer un workspace](configuration.md#create-a-workspace).
1. Depuis votre projet, sélectionnez **Code**.
1. Sélectionnez le nom de votre workspace.
1. Interagissez avec le workspace en ouvrant le Web IDE, en accédant au terminal ou en apportant des modifications aux fichiers du projet.

Félicitations ! Vous avez correctement configuré l'infrastructure des workspaces GitLab sur AWS. Vos utilisateurs peuvent désormais créer des environnements de workspace de développement pour leurs projets.

Si vous rencontrez des problèmes, consultez les logs pour obtenir des détails supplémentaires et reportez-vous à [dépannage des workspaces](workspaces_troubleshooting.md) pour obtenir de l'aide.

## Sujets connexes {#related-topics}

- [Workspaces](_index.md)
- [Configurer les workspaces](configuration.md)
- [Paramètres des workspaces](settings.md)
- [Tutoriel : créer une image de workspace personnalisée prenant en charge les ID d'utilisateur arbitraires](create_image.md)
