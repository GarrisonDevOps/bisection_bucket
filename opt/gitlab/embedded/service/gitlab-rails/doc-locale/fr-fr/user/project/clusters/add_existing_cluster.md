---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Connecter des clusters existants via des certificats de cluster (déprécié)
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) dans GitLab 14.5. Pour connecter votre cluster à GitLab, utilisez plutôt l'[agent GitLab pour Kubernetes](../../clusters/agent/_index.md).

Si vous disposez d'un cluster Kubernetes existant, vous pouvez l'ajouter à un projet, un groupe ou une instance et bénéficier de l'intégration avec GitLab.

## Prérequis {#prerequisites}

Consultez les prérequis ci-dessous pour ajouter des clusters existants à GitLab.

### Tous les clusters {#all-clusters}

Pour ajouter un cluster à GitLab, vous avez besoin :

- D'un compte sur une instance GitLab.com ou GitLab Self-Managed.
- Du rôle Maintainer pour les clusters au niveau du groupe et du projet.
- D'un accès à la zone **Admin** pour les clusters au niveau de l'instance.
- Un cluster Kubernetes.
- D'un accès d'administration du cluster avec `kubectl`.

Vous pouvez héberger votre cluster dans [EKS](#eks-clusters), [GKE](#gke-clusters), sur site et avec d'autres fournisseurs. Pour les héberger sur site ou avec d'autres fournisseurs, utilisez la méthode EKS ou GKE pour vous guider et saisissez les paramètres de votre cluster manuellement.

> [!warning]
> GitLab ne prend pas en charge les clusters `arm64`. Consultez le ticket [Helm Tiller ne parvient pas à s'installer sur le cluster `arm64`](https://gitlab.com/gitlab-org/gitlab/-/issues/29838) pour plus d'informations.

### Clusters EKS {#eks-clusters}

Pour ajouter un cluster EKS existant, vous avez besoin :

- D'un cluster Amazon EKS avec des nœuds worker correctement configurés.
- `kubectl` [installé et configuré](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html#get-started-kubectl) pour accéder au cluster EKS.
- Vérifiez que le jeton du compte dispose de droits d'administrateur sur le cluster.

### Clusters GKE {#gke-clusters}

Pour ajouter un cluster GKE existant, vous avez besoin :

- De l'autorisation `container.clusterRoleBindings.create` pour créer une liaison de rôle de cluster. Vous pouvez consulter la [documentation Google Cloud](https://cloud.google.com/iam/docs/granting-changing-revoking-access) pour obtenir l'accès.

## Comment ajouter un cluster existant {#how-to-add-an-existing-cluster}

<!-- (REVISE -  BREAK INTO SMALLER STEPS) -->

Pour ajouter un cluster Kubernetes à votre projet, groupe ou instance :

1. Accédez à :
   1. La page {{< icon name="cloud-gear" >}} **Opération** > **Clusters Kubernetes** de votre projet, pour un cluster au niveau du projet.
   1. La page {{< icon name="cloud-gear" >}} **Kubernetes** de votre groupe, pour un cluster au niveau du groupe.
   1. La page **Kubernetes** de la zone **Admin**, pour un cluster au niveau de l'instance.
1. Sur la page **Clusters Kubernetes**, sélectionnez l'option **Connecter avec un certificat** dans la liste déroulante **Actions**.
1. Sur la page **Connecter un cluster**, renseignez les informations suivantes :
   1. **Nom de la grappe de serveurs Kubernetes** (obligatoire) - Le nom que vous souhaitez donner au cluster.
   1. **Portée de l'environnement** (obligatoire) - L'[environnement associé](multiple_kubernetes_clusters.md#setting-the-environment-scope) à ce cluster.
   1. **URL de l'API** (obligatoire) - Il s'agit de l'URL que GitLab utilise pour accéder à l'API Kubernetes. Kubernetes expose plusieurs API. Utilisez l'URL « de base » commune à toutes les API. Par exemple, `https://kubernetes.example.com` plutôt que `https://kubernetes.example.com/api/v1`.

      Obtenez l'URL de l'API en exécutant cette commande :

      ```shell
      kubectl cluster-info | grep -E 'Kubernetes master|Kubernetes control plane' | awk '/http/ {print $NF}'
      ```

   1. **Certificat CA** (obligatoire) - Un certificat Kubernetes valide est nécessaire pour s'authentifier auprès du cluster. Utilisez le certificat créé par défaut.
      1. Listez les secrets avec `kubectl get secrets`, l'un d'eux devrait être nommé de manière similaire à `default-token-xxxxx`. Copiez ce nom de jeton pour l'utiliser ci-dessous.
      1. Obtenez le certificat en exécutant cette commande :

         ```shell
         kubectl get secret <secret name> -o jsonpath="{['data']['ca\.crt']}" | base64 --decode
         ```

         Si la commande renvoie la chaîne de certificats entière, vous devez copier le certificat CA racine et tous les certificats intermédiaires situés en bas de la chaîne. Un fichier de chaîne présente la structure suivante :

         ```plaintext
            -----BEGIN MY CERTIFICATE-----
            -----END MY CERTIFICATE-----
            -----BEGIN INTERMEDIATE CERTIFICATE-----
            -----END INTERMEDIATE CERTIFICATE-----
            -----BEGIN INTERMEDIATE CERTIFICATE-----
            -----END INTERMEDIATE CERTIFICATE-----
            -----BEGIN ROOT CERTIFICATE-----
            -----END ROOT CERTIFICATE-----
         ```

   1. **Jeton** \- GitLab s'authentifie auprès de Kubernetes à l'aide de jetons de service dont la portée est limitée à un `namespace` particulier. Le jeton utilisé doit appartenir à un compte de service disposant des privilèges [`cluster-admin`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles). Pour créer ce compte de service :
      1. Créez un fichier appelé `gitlab-admin-service-account.yaml` avec le contenu suivant :

         ```yaml
         apiVersion: v1
         kind: ServiceAccount
         metadata:
           name: gitlab
           namespace: kube-system
         ---
         apiVersion: rbac.authorization.k8s.io/v1
         kind: ClusterRoleBinding
         metadata:
           name: gitlab-admin
         roleRef:
           apiGroup: rbac.authorization.k8s.io
           kind: ClusterRole
           name: cluster-admin
         subjects:
           - kind: ServiceAccount
             name: gitlab
             namespace: kube-system
         ```

      1. Appliquez le compte de service et la liaison de rôle de cluster à votre cluster :

         ```shell
         kubectl apply -f gitlab-admin-service-account.yaml
         ```

         Vous avez besoin de l'autorisation `container.clusterRoleBindings.create` pour créer des rôles au niveau du cluster. Si vous ne disposez pas de cette autorisation, vous pouvez activer l'authentification de base et exécuter la commande `kubectl apply` en tant qu'administrateur :

         ```shell
         kubectl apply -f gitlab-admin-service-account.yaml --username=admin --password=<password>
         ```

         > [!note]
         > L'authentification de base peut être activée et les identifiants de mot de passe peuvent être obtenus via la console Google Cloud.

         Résultat :

         ```shell
         serviceaccount "gitlab" created
         clusterrolebinding "gitlab-admin" created
         ```

      1. Récupérez le jeton pour le compte de service `gitlab` :

         ```shell
         kubectl -n kube-system describe secret $(kubectl -n kube-system get secret | grep gitlab | awk '{print $1}')
         ```

         Copiez la valeur `<authentication_token>` depuis le résultat :

         ```plaintext
         Name:         gitlab-token-b5zv4
         Namespace:    kube-system
         Labels:       <none>
         Annotations:  kubernetes.io/service-account.name=gitlab
                      kubernetes.io/service-account.uid=bcfe66ac-39be-11e8-97e8-026dce96b6e8

         Type:  kubernetes.io/service-account-token

         Data
         ====
         ca.crt:     1025 bytes
         namespace:  11 bytes
         token:      <authentication_token>
         ```

   1. **Cluster géré par GitLab** \- Laissez cette case cochée si vous souhaitez que GitLab gère les espaces de nommage et les comptes de service pour ce cluster. Consultez la [section Clusters gérés](gitlab_managed_clusters.md) pour plus d'informations.
   1. **Espace de nommage du projet** (facultatif) - Vous n'êtes pas obligé de le renseigner. En laissant ce champ vide, GitLab en crée un pour vous. Également :
      - Chaque projet doit disposer d'un espace de nommage unique.
      - L'espace de nommage du projet n'est pas nécessairement celui du secret, si vous utilisez un secret avec des autorisations plus larges, comme le secret de `default`.
      - Vous ne devez pas utiliser `default` comme espace de nommage du projet.
      - Si vous-même ou quelqu'un d'autre avez créé un secret spécifiquement pour le projet, généralement avec des autorisations limitées, l'espace de nommage du secret et celui du projet peuvent être identiques.

1. Sélectionnez le bouton **Ajouter une grappe de serveurs Kubernetes**.

Au bout d'environ 10 minutes, votre cluster est prêt.

## Désactiver le contrôle d'accès basé sur les rôles (RBAC) (facultatif) {#disable-role-based-access-control-rbac-optional}

Lors de la connexion d'un cluster via l'intégration GitLab, vous pouvez indiquer si le cluster est activé pour le RBAC ou non. Cela affecte la façon dont GitLab interagit avec le cluster pour certaines opérations. Si vous n'avez pas coché la case **Grappe de serveurs avec contrôle d'accès par rôle** lors de la création, GitLab considère que le RBAC est désactivé pour votre cluster lors des interactions. Dans ce cas, vous devez désactiver le RBAC sur votre cluster pour que l'intégration fonctionne correctement.

![Paramètres d'intégration du cluster Kubernetes GitLab pour l'activation du RBAC.](img/rbac_v13_1.png)

> [!warning]
> La désactivation du RBAC signifie que toute application s'exécutant dans le cluster, ou tout utilisateur pouvant s'authentifier auprès du cluster, dispose d'un accès complet à l'API. Il s'agit d'un [problème de sécurité](../../infrastructure/clusters/connect/_index.md#security-implications-for-clusters-connected-with-certificates) qui peut ne pas être souhaitable.

Pour désactiver efficacement le RBAC, des autorisations globales accordant un accès complet peuvent être appliquées :

```shell
kubectl create clusterrolebinding permissive-binding \
  --clusterrole=cluster-admin \
  --user=admin \
  --user=kubelet \
  --group=system:serviceaccounts
```

## Dépannage {#troubleshooting}

### Erreurs de certificat CA et de jeton lors de l'authentification {#ca-certificate-and-token-errors-during-authentication}

Si vous rencontrez cette erreur lors de la connexion d'un cluster Kubernetes :

```plaintext
There was a problem authenticating with your cluster.
Please ensure your CA Certificate and Token are valid
```

Vérifiez que vous collez correctement le jeton de service. Certains shells peuvent ajouter un saut de ligne au jeton de service, le rendant invalide. Vérifiez qu'il n'y a pas de saut de ligne en collant votre jeton dans un éditeur et en supprimant les espaces supplémentaires.

Vous pouvez également rencontrer cette erreur si votre certificat n'est pas valide. Pour vérifier que les noms alternatifs de sujet de votre certificat contiennent le domaine correct pour l'API de votre cluster, exécutez cette commande :

```shell
echo | openssl s_client -showcerts -connect kubernetes.example.com:443 -servername kubernetes.example.com 2>/dev/null |
openssl x509 -inform pem -noout -text
```

L'argument `-connect` attend une combinaison `host:port`. Par exemple, `https://kubernetes.example.com` correspondrait à `kubernetes.example.com:443`. L'argument `-servername` attend un domaine sans URI, par exemple `kubernetes.example.com`.
