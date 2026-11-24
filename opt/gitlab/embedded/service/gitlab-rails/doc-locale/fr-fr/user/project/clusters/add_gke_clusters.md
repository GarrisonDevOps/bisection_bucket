---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Connecter des clusters GKE via des certificats de cluster (obsolète)
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) dans GitLab 14.5. Utilisez [Infrastructure as Code avec OpenTofu et GitLab](../../infrastructure/iac/_index.md). Vous pouvez également implémenter votre propre solution IaC en utilisant l'outil de votre choix.

Via GitLab, vous pouvez créer de nouveaux clusters et connecter des clusters existants hébergés sur Google Kubernetes Engine (GKE).

## Connecter un cluster GKE existant {#connect-an-existing-gke-cluster}

Si vous disposez déjà d'un cluster GKE et souhaitez le connecter à GitLab, utilisez l'[agent GitLab pour Kubernetes](../../clusters/agent/_index.md).

## Créer un nouveau cluster GKE depuis GitLab {#create-a-new-gke-cluster-from-gitlab}

Tous les clusters GKE provisionnés par GitLab sont [VPC-native](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/alias-ips).

Pour créer un nouveau cluster GKE depuis GitLab, utilisez [Infrastructure as Code avec OpenTofu et GitLab](../../infrastructure/iac/_index.md).

## Créer un nouveau cluster sur GKE via des certificats de cluster {#create-a-new-cluster-on-gke-through-cluster-certificates}

Prérequis :

- Un [compte de facturation Google Cloud](https://docs.cloud.google.com/billing/docs/how-to/manage-billing-account) configuré avec les accès nécessaires.
- L'API Kubernetes Engine et les services associés sont activés. Cela devrait fonctionner immédiatement, mais peut prendre jusqu'à 10 minutes après la création d'un projet. Pour plus d'informations, consultez la [section « Avant de commencer » de la documentation Kubernetes Engine](https://cloud.google.com/kubernetes-engine/docs/deploy-app-cluster#before-you-begin).

Notez ce qui suit :

- L'[intégration de l'authentification Google](../../../integration/google.md) doit être activée dans GitLab au niveau de l'instance. Si ce n'est pas le cas, demandez à votre administrateur GitLab de l'activer. Sur GitLab.com, cette option est activée.
- Tous les clusters GKE créés par GitLab ont RBAC activé. Consultez la [section RBAC](cluster_access.md#rbac-cluster-resources) pour plus d'informations.
- La plage d'adresses IP des pods du cluster est définie sur `/16` au lieu du `/14` habituel. `/16` est une notation CIDR.
- GitLab requiert l'activation de l'authentification de base et l'émission d'un certificat client pour le cluster afin de configurer un [compte de service initial](cluster_access.md). Dans [les versions 11.10 et ultérieures de GitLab](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/58208), le processus de création de cluster demande explicitement à GKE de créer des clusters avec l'authentification de base activée et un certificat client.

Pour créer de nouveaux clusters Kubernetes pour votre projet, groupe ou instance, via des certificats de cluster :

1. Accédez à votre :
   - Page {{< icon name="cloud-gear" >}} **Opération** > **Clusters Kubernetes** du projet, pour un cluster au niveau du projet.
   - Page {{< icon name="cloud-gear" >}} **Kubernetes** du groupe, pour un cluster au niveau du groupe.
   - Page **Kubernetes** de la zone **Admin**, pour un cluster au niveau de l'instance.
1. Sélectionnez **Intégrer avec un certificat de cluster**.
1. Sous l'onglet **Créer un nouveau cluster**, sélectionnez **Google GKE**.
1. Connectez votre compte Google si ce n'est pas déjà fait en sélectionnant le bouton **Se connecter avec Google**.
1. Choisissez les paramètres de votre cluster :
   - **Nom de la grappe de serveurs Kubernetes** \- Le nom que vous souhaitez attribuer au cluster.
   - **Portée de l'environnement** \- L'[environnement associé](multiple_kubernetes_clusters.md#setting-the-environment-scope) à ce cluster.
   - **Projet Google Cloud Platform** \- Choisissez le projet que vous avez créé dans votre console GCP pour héberger le cluster Kubernetes. Pour plus d'informations, consultez [Créer et gérer des projets](https://cloud.google.com/resource-manager/docs/creating-managing-projects).
   - **Zone** \- Choisissez la [zone de région](https://docs.cloud.google.com/compute/docs/regions-zones) dans laquelle créer le cluster.
   - **Nombre de nœuds** \- Saisissez le nombre de nœuds que vous souhaitez attribuer au cluster.
   - **Type de machine** \- Le [type de machine](https://docs.cloud.google.com/compute/docs/machine-resource) de l'instance de machine virtuelle sur laquelle baser le cluster.
   - **Activer Cloud Run pour Anthos** \- Cochez cette option si vous souhaitez utiliser Cloud Run pour Anthos pour ce cluster. Consultez la [section Cloud Run pour Anthos](#cloud-run-for-anthos) pour plus d'informations.
   - **Cluster géré par GitLab** \- Laissez cette option cochée si vous souhaitez que GitLab gère les espaces de nommage et les comptes de service pour ce cluster. Consultez la [section Clusters gérés](gitlab_managed_clusters.md) pour plus d'informations.
1. Enfin, sélectionnez le bouton **Créer un cluster Kubernetes**.

Après quelques minutes, votre cluster est prêt.

### Cloud Run pour Anthos {#cloud-run-for-anthos}

Vous pouvez choisir d'utiliser Cloud Run pour Anthos à la place d'installer Knative et Istio séparément après la création du cluster. Cela signifie que Cloud Run (Knative), Istio et l'équilibrage de charge HTTP sont activés sur le cluster dès le départ, et ne peuvent pas être installés ou désinstallés.
