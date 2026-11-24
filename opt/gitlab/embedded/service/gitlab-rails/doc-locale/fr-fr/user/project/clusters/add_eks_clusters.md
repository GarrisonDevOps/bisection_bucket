---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Connecter des clusters EKS via des certificats de cluster (déprécié)
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> Cette fonctionnalité a été dépréciée dans GitLab 14.5. Utilisez [Infrastructure as Code](../../infrastructure/iac/_index.md) pour créer de nouveaux clusters.

Via GitLab, vous pouvez créer de nouveaux clusters et ajouter des clusters existants hébergés sur Amazon Elastic Kubernetes Service (EKS).

## Connecter un cluster EKS existant {#connect-an-existing-eks-cluster}

Si vous disposez déjà d'un cluster EKS et souhaitez le connecter à GitLab, utilisez l'[agent GitLab pour Kubernetes](../../clusters/agent/_index.md).

## Créer un nouveau cluster EKS {#create-a-new-eks-cluster}

Pour créer un nouveau cluster depuis GitLab, utilisez [Infrastructure as Code](../../infrastructure/iac/_index.md).

### Comment créer un nouveau cluster sur EKS via des certificats de cluster (déprécié) {#how-to-create-a-new-cluster-on-eks-through-cluster-certificates-deprecated}

{{< history >}}

- [Déprécié](https://gitlab.com/gitlab-org/gitlab/-/issues/327908) dans GitLab 14.0.

{{< /history >}}

Prérequis :

- Un compte [Amazon Web Services](https://aws.amazon.com/).
- Autorisations pour gérer les ressources IAM.

Pour les clusters au niveau de l'instance, consultez les [exigences supplémentaires pour les instances GitLab Self-Managed](#additional-requirements-for-gitlab-self-managed-instances).

Pour créer de nouveaux clusters Kubernetes pour votre projet, groupe ou instance via la méthode basée sur les certificats :

1. [Définissez le contrôle d'accès (RBAC ou ABAC) pour votre cluster](cluster_access.md).
1. [Créez un cluster dans GitLab](#create-a-new-eks-cluster-in-gitlab).
1. [Préparez le cluster dans Amazon](#prepare-the-cluster-in-amazon).
1. [Configurez les données de votre cluster dans GitLab](#configure-your-clusters-data-in-gitlab).

Étapes supplémentaires :

1. [Créez une classe de stockage par défaut](#create-a-default-storage-class).
1. [Déployez l'application sur EKS](#deploy-the-app-to-eks).

#### Créer un nouveau cluster EKS dans GitLab {#create-a-new-eks-cluster-in-gitlab}

Pour créer un nouveau cluster EKS pour votre projet, groupe ou instance, via des certificats de cluster :

1. Accédez à votre :
   - Page **Opération** > **Clusters Kubernetes** du projet, pour un cluster au niveau du projet.
   - Page **Kubernetes** du groupe, pour un cluster au niveau du groupe.
   - Page **Admin** > **Kubernetes**, pour un cluster au niveau de l'instance.
1. Sélectionnez **Intégrer avec un certificat de cluster**.
1. Sous l'onglet **Créer un nouveau cluster**, sélectionnez **Amazon EKS** pour afficher un `Account ID` et un `External ID` nécessaires pour les étapes suivantes.
1. Dans la [console de gestion IAM](https://console.aws.amazon.com/iam/home), créez une politique IAM :
   1. Dans le panneau de gauche, sélectionnez **Politiques**.
   1. Sélectionnez **Créer une politique**, ce qui ouvre une nouvelle fenêtre.
   1. Sélectionnez l'onglet **JSON** et collez l'extrait suivant à la place du contenu existant. Ces autorisations donnent à GitLab la capacité de créer des ressources, mais pas de les supprimer :

      ```json
      {
          "Version": "2012-10-17",
          "Statement": [
              {
                  "Effect": "Allow",
                  "Action": [
                      "autoscaling:CreateAutoScalingGroup",
                      "autoscaling:DescribeAutoScalingGroups",
                      "autoscaling:DescribeScalingActivities",
                      "autoscaling:UpdateAutoScalingGroup",
                      "autoscaling:CreateLaunchConfiguration",
                      "autoscaling:DescribeLaunchConfigurations",
                      "cloudformation:CreateStack",
                      "cloudformation:DescribeStacks",
                      "ec2:AuthorizeSecurityGroupEgress",
                      "ec2:AuthorizeSecurityGroupIngress",
                      "ec2:RevokeSecurityGroupEgress",
                      "ec2:RevokeSecurityGroupIngress",
                      "ec2:CreateSecurityGroup",
                      "ec2:createTags",
                      "ec2:DescribeImages",
                      "ec2:DescribeKeyPairs",
                      "ec2:DescribeRegions",
                      "ec2:DescribeSecurityGroups",
                      "ec2:DescribeSubnets",
                      "ec2:DescribeVpcs",
                      "eks:CreateCluster",
                      "eks:DescribeCluster",
                      "iam:AddRoleToInstanceProfile",
                      "iam:AttachRolePolicy",
                      "iam:CreateRole",
                      "iam:CreateInstanceProfile",
                      "iam:CreateServiceLinkedRole",
                      "iam:GetRole",
                      "iam:listAttachedRolePolicies",
                      "iam:ListRoles",
                      "iam:PassRole",
                      "ssm:GetParameters"
                  ],
                  "Resource": "*"
              }
          ]
      }
      ```

      Si vous obtenez une erreur au cours de ce processus, GitLab n'annule pas les modifications. Vous devez supprimer les ressources manuellement. Vous pouvez le faire en supprimant la [stack CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-delete-stack.html) concernée.

   1. Sélectionnez **Vérifier la politique**.
   1. Entrez un nom approprié pour cette politique, puis sélectionnez **Créer une politique**. Vous pouvez maintenant fermer cette fenêtre.

### Préparer le cluster dans Amazon {#prepare-the-cluster-in-amazon}

1. [Créez un **rôle IAM EKS** pour votre cluster](#create-an-eks-iam-role-for-your-cluster) (**rôle A**).
1. [Créez **un autre rôle IAM EKS** pour l'authentification GitLab avec Amazon](#create-another-eks-iam-role-for-gitlab-authentication-with-amazon) (**rôle B**).

#### Créer un rôle IAM EKS pour votre cluster {#create-an-eks-iam-role-for-your-cluster}

Dans la [console de gestion IAM](https://console.aws.amazon.com/iam/home), créez un **rôle IAM EKS** (**rôle A**) en suivant les [instructions relatives au rôle IAM du cluster Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/cluster-iam-role.html). Ce rôle est nécessaire pour que les clusters Kubernetes gérés par Amazon EKS puissent appeler d'autres services AWS en votre nom afin de gérer les ressources que vous utilisez avec le service.

Pour que GitLab gère correctement le cluster EKS, vous devez inclure `AmazonEKSClusterPolicy` en plus des politiques suggérées par le guide.

#### Créer un autre rôle IAM EKS pour l'authentification GitLab avec Amazon {#create-another-eks-iam-role-for-gitlab-authentication-with-amazon}

Dans la [console de gestion IAM](https://console.aws.amazon.com/iam/home), créez un autre rôle IAM (**rôle B**) pour l'authentification GitLab avec AWS :

1. Sur la console AWS IAM, sélectionnez **Rôles** dans le panneau de gauche.
1. Sélectionnez **Créer un rôle**.
1. Sous **Sélectionner le type d'entité de confiance**, sélectionnez **Un autre compte AWS**.
1. Entrez l'ID du compte GitLab dans le champ **ID du compte**.
1. Cochez **Exiger un ID externe**.
1. Entrez l'ID externe de GitLab dans le champ **ID externe**.
1. Sélectionnez **Suivant : autorisations**, puis sélectionnez la politique que vous venez de créer.
1. Sélectionnez **Suivant : balises**, et entrez éventuellement les balises que vous souhaitez associer à ce rôle.
1. Sélectionnez **Suivant : révision**.
1. Entrez un nom de rôle et une description facultative dans les champs fournis.
1. Sélectionnez **Créer un rôle**. Le nouveau nom de rôle s'affiche en haut. Sélectionnez son nom et copiez le `Role ARN` du rôle nouvellement créé.

### Configurer les données de votre cluster dans GitLab {#configure-your-clusters-data-in-gitlab}

1. De retour dans GitLab, entrez l'ARN du rôle copié dans le champ **ARN du rôle**.
1. Dans le champ **Région du cluster**, entrez la [région](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html) que vous prévoyez d'utiliser pour votre nouveau cluster. GitLab confirme que vous avez accès à cette région lors de l'authentification de votre rôle.
1. Sélectionnez **S'authentifier avec AWS**.
1. Ajustez les [paramètres de votre cluster](#cluster-settings).
1. Sélectionnez le bouton **Créer un cluster Kubernetes**.

Après environ 10 minutes, votre cluster est prêt.

> [!note]
> Si vous avez [installé et configuré](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html#get-started-kubectl) `kubectl` et que vous souhaitez gérer votre cluster avec cet outil, vous devez ajouter votre ID externe AWS dans la configuration AWS. Pour plus d'informations sur la configuration de l'interface de ligne de commande AWS, consultez [l'utilisation d'un rôle IAM dans l'AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html#cli-configure-role-xaccount).

#### Paramètres du cluster {#cluster-settings}

Lorsque vous créez un nouveau cluster, vous disposez des paramètres suivants :

| Paramètre                 | Description |
| ----------------------- |------------ |
| Nom du cluster Kubernetes | Le nom de votre cluster. |
| Portée de l'environnement       | L'[environnement associé](multiple_kubernetes_clusters.md#setting-the-environment-scope). |
| Rôle de service            | Le **rôle IAM EKS** (**rôle A**). |
| Version de Kubernetes      | La [version de Kubernetes](../../clusters/agent/_index.md#supported-kubernetes-versions-for-gitlab-features) pour votre cluster. |
| Nom de la paire de clés           | La [paire de clés](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html) que vous pouvez utiliser pour vous connecter à vos nœuds de travail. |
| VPC                     | Le [VPC](https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html) à utiliser pour les ressources de votre cluster EKS. |
| Sous-réseaux                 | Les [sous-réseaux](https://docs.aws.amazon.com/vpc/latest/userguide/configure-subnets.html) de votre VPC où s'exécutent vos nœuds de travail. Deux sont requis. |
| Groupe de sécurité          | Le [groupe de sécurité](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html) à appliquer aux interfaces réseau élastiques gérées par EKS créées dans les sous-réseaux de vos nœuds de travail. |
| Type d'instance           | Le [type d'instance](https://aws.amazon.com/ec2/instance-types/) de vos nœuds de travail. |
| Nombre de nœuds              | Le nombre de nœuds de travail. |
| Cluster géré par GitLab  | Cochez cette option si vous souhaitez que GitLab gère les espaces de nommage et les comptes de service pour ce cluster. |

## Créer une classe de stockage par défaut {#create-a-default-storage-class}

Amazon EKS ne dispose pas de classe de stockage par défaut prête à l'emploi, ce qui signifie que les demandes de volumes persistants ne sont pas automatiquement satisfaites. Dans le cadre d'Auto DevOps, l'instance PostgreSQL déployée demande un stockage persistant, et sans classe de stockage par défaut, elle ne peut pas démarrer.

Pour créer une classe de stockage par défaut si elle n'existe pas encore, consultez [Storage Classes](https://docs.aws.amazon.com/eks/latest/userguide/storage.html#storage-classes).

Vous pouvez également désactiver PostgreSQL en définissant la variable de projet [`POSTGRES_ENABLED`](../../../topics/autodevops/cicd_variables.md) sur `false`.

## Déployer l'application sur EKS {#deploy-the-app-to-eks}

Avec RBAC désactivé et les services déployés, [Auto DevOps](../../../topics/autodevops/_index.md) peut désormais être utilisé pour créer, tester et déployer l'application.

[Activez Auto DevOps](../../../topics/autodevops/_index.md#per-project) si ce n'est pas déjà fait. Si une entrée DNS générique a été créée pour résoudre vers le Load Balancer, entrez-la dans le champ `domain` sous les paramètres Auto DevOps. Dans le cas contraire, l'application déployée n'est pas accessible depuis l'extérieur du cluster.

![Un pipeline déployant l'application sur EKS.](img/pipeline_v11_0.png)

GitLab crée un nouveau pipeline, qui commence à créer, tester et déployer l'application.

Une fois le pipeline terminé, votre application s'exécute dans EKS et est disponible pour les utilisateurs. Sélectionnez **Opération** > **Environnements**.

![Le statut de l'environnement déployé et les options d'accès.](img/environment_v11_0.png)

GitLab affiche une liste des environnements et leur statut de déploiement, ainsi que des options pour accéder à l'application, consulter les métriques de surveillance et même accéder à un shell sur le pod en cours d'exécution.

## Exigences supplémentaires pour les instances GitLab Self-Managed {#additional-requirements-for-gitlab-self-managed-instances}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si vous utilisez GitLab Self-Managed, vous devez configurer les informations d'identification Amazon. GitLab utilise ces informations d'identification pour endosser un rôle Amazon IAM afin de créer votre cluster.

Créez un utilisateur IAM et assurez-vous qu'il dispose des autorisations nécessaires pour endosser les rôles dont vos utilisateurs ont besoin pour créer des clusters EKS.

Par exemple, le document de politique suivant autorise l'endossement d'un rôle dont le nom commence par `gitlab-eks-` dans le compte `123456789012` :

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::123456789012:role/gitlab-eks-*"
  }
}
```

### Configurer l'authentification Amazon {#configure-amazon-authentication}

Prérequis :

- Disposer d'un accès administrateur.

Pour configurer l'authentification Amazon dans GitLab, générez une clé d'accès pour l'utilisateur IAM dans la console Amazon AWS, puis suivez ces étapes :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Amazon EKS**.
1. Cochez **Activer l'intégration d'Amazon EKS**.
1. Entrez votre **ID du compte**.
1. Entrez votre [clé d'accès et votre ID](#eks-access-key-and-id).
1. Sélectionnez **Enregistrer les modifications**.

#### Clé d'accès et ID EKS {#eks-access-key-and-id}

Vous pouvez utiliser des profils d'instance pour récupérer dynamiquement des informations d'identification temporaires depuis AWS lorsque cela est nécessaire. Dans ce cas, laissez les champs `Access key ID` et `Secret access key` vides et [transmettez un rôle IAM à une instance EC2](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html).

Dans le cas contraire, entrez vos informations d'identification de clé d'accès dans **ID de la clé d'accès** et **Clé d'accès secrète**.

## Dépannage {#troubleshooting}

Les erreurs suivantes sont fréquemment rencontrées lors de la création d'un nouveau cluster.

### Échec de la validation : L'ARN du rôle doit être un nom de ressource Amazon valide {#validation-failed-role-arn-must-be-a-valid-amazon-resource-name}

Vérifiez que le `Provision Role ARN` est correct. Exemple d'ARN valide :

```plaintext
arn:aws:iam::123456789012:role/gitlab-eks-provision'
```

### Accès refusé : l'utilisateur n'est pas autorisé à effectuer l'action : `sts:AssumeRole` sur la ressource : `arn:aws:iam::y` {#access-denied-user-is-not-authorized-to-perform-stsassumerole-on-resource-arnawsiamy}

Cette erreur se produit lorsque les informations d'identification définies dans [Configurer l'authentification Amazon](#configure-amazon-authentication) ne peuvent pas endosser le rôle défini par l'ARN du rôle de provisionnement :

```plaintext
User `arn:aws:iam::x` is not authorized to perform: `sts:AssumeRole` on resource: `arn:aws:iam::y`
```

Vérifiez que :

1. L'ensemble initial d'informations d'identification AWS [dispose de la politique AssumeRole](#additional-requirements-for-gitlab-self-managed-instances).
1. Le rôle de provisionnement a accès à la création de clusters dans la région spécifiée.
1. L'ID du compte et l'[ID externe](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html) correspondent à la valeur définie dans l'onglet **Relations d'approbation** dans AWS :

   ![Paramètres de relation d'approbation pour le rôle AWS IAM utilisé pour la création du cluster EKS.](img/aws_iam_role_trust_v13_7.png)

### Impossible de charger les groupes de sécurité pour ce VPC {#could-not-load-security-groups-for-this-vpc}

Lors du remplissage des options dans le formulaire de configuration, GitLab renvoie cette erreur car GitLab a bien endossé le rôle fourni, mais ce rôle ne dispose pas des autorisations suffisantes pour récupérer les ressources nécessaires au formulaire. Assurez-vous d'avoir attribué les autorisations correctes au rôle.

### Les paires de clés ne sont pas chargées {#key-pairs-are-not-loaded}

GitLab charge les paires de clés depuis la **Région du cluster** spécifiée. Assurez-vous que la paire de clés existe dans cette région.

#### `ROLLBACK_FAILED` pendant la création du cluster {#rollback_failed-during-cluster-creation}

Le processus de création s'est interrompu car GitLab a rencontré une erreur lors de la création d'une ou plusieurs ressources. Vous pouvez inspecter la [stack CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-view-stack-data-resources.html) associée pour trouver les ressources spécifiques dont la création a échoué.

Si la ressource `Cluster` a échoué avec l'erreur `The provided role doesn't have the Amazon EKS Managed Policies associated with it.`, le rôle spécifié dans **Nom du rôle** n'est pas configuré correctement.

> [!note]
> Ce rôle doit être le rôle que vous avez créé en suivant le guide [Rôle IAM du cluster EKS](https://docs.aws.amazon.com/eks/latest/userguide/cluster-iam-role.html). En plus des politiques suggérées par le guide, vous devez également inclure la politique `AmazonEKSClusterPolicy` pour ce rôle afin que GitLab gère correctement le cluster EKS.
