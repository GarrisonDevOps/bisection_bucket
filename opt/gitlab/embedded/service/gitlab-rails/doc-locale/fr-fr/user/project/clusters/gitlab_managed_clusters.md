---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Clusters gérés par GitLab (déprécié)
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Désactivé sur GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/issues/353410) dans GitLab 15.0.

{{< /history >}}

> [!flag]
> Sur GitLab Self-Managed, cette fonctionnalité n'est pas disponible par défaut. Pour rendre cette fonctionnalité disponible, un administrateur peut [activer le feature flag](../../../administration/feature_flags/_index.md) `certificate_based_clusters`.

Vous pouvez choisir de laisser GitLab gérer votre cluster à votre place. Si votre cluster est géré par GitLab, les ressources de vos projets sont créées automatiquement. Consultez la section [Contrôles d'accès](cluster_access.md) pour en savoir plus sur les ressources créées.

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) dans GitLab 14.5. Pour connecter votre cluster à GitLab, utilisez l'[agent GitLab pour Kubernetes](../../clusters/agent/_index.md). Pour gérer les applications, utilisez le [modèle de projet de gestion de cluster](../../clusters/management_project_template.md).

Si vous choisissez de gérer votre propre cluster, les ressources spécifiques au projet ne sont pas créées automatiquement. Si vous utilisez [Auto DevOps](../../../topics/autodevops/_index.md), vous devez fournir explicitement la `KUBE_NAMESPACE` [variable de déploiement](deploy_to_cluster.md#deployment-variables) pour vos jobs de déploiement. Sinon, un espace de nommage est créé pour vous.

> [!warning]
> Notez que la gestion manuelle des ressources créées par GitLab, telles que les espaces de nommage et les comptes de service, peut provoquer des erreurs inattendues. Si cela se produit, essayez de [vider le cache du cluster](#clearing-the-cluster-cache).

## Vider le cache du cluster {#clearing-the-cluster-cache}

Si vous autorisez GitLab à gérer votre cluster, GitLab stocke une version en cache des espaces de nommage et des comptes de service qu'il crée pour vos projets. Si vous modifiez ces ressources manuellement dans votre cluster, ce cache peut se désynchroniser avec votre cluster. Cela peut entraîner l'échec des jobs de déploiement.

Pour vider le cache :

1. Accédez à la page **Opération** > **Clusters Kubernetes** de votre projet et sélectionnez votre cluster.
1. Développez la section **Paramètres avancés**.
1. Sélectionnez **Vider le cache du cluster**.

## Domaine de base {#base-domain}

La spécification d'un domaine de base définit automatiquement `KUBE_INGRESS_BASE_DOMAIN` en tant que variable de déploiement. Si vous utilisez [Auto DevOps](../../../topics/autodevops/_index.md), ce domaine est utilisé pour les différentes étapes. Par exemple, Auto Review Apps et Auto Deploy.

Le domaine doit avoir un DNS avec caractère générique configuré sur l'adresse IP d'Ingress. Vous pouvez choisir l'une des deux options suivantes :

- Créez un enregistrement `A` pointant vers l'adresse IP d'Ingress auprès de votre fournisseur de domaine.
- Saisissez une adresse DNS avec caractère générique à l'aide d'un service tel que `nip.io` ou `xip.io`. Par exemple, `192.168.1.1.xip.io`.

Pour déterminer l'adresse IP Ingress externe ou le nom d'hôte Ingress externe :

- Si le cluster est sur GKE :
  1. Sélectionnez le lien **Google Kubernetes Engine** dans les **Paramètres avancés**, ou accédez directement au [tableau de bord Google Kubernetes Engine](https://console.cloud.google.com/kubernetes/).
  1. Sélectionnez le projet et le cluster appropriés.
  1. Sélectionnez **Connecter**.
  1. Exécutez la commande `gcloud` dans un terminal local ou en utilisant le **Cloud Shell**.

- Si le cluster n'est pas sur GKE : suivez les instructions spécifiques à votre fournisseur Kubernetes pour configurer `kubectl` avec les informations d'identification appropriées. La sortie des exemples suivants affiche le point de terminaison externe de votre cluster. Ces informations peuvent ensuite être utilisées pour configurer des entrées DNS et des règles de transfert permettant l'accès externe à vos applications déployées.

Selon votre configuration d'Ingress, l'adresse IP externe peut être récupérée de différentes manières. Cette liste propose une solution générique et quelques approches spécifiques à GitLab :

- En général, vous pouvez lister les adresses IP de tous les équilibreurs de charge en exécutant :

  ```shell
  kubectl get svc --all-namespaces -o jsonpath='{range.items[?(@.status.loadBalancer.ingress)]}{.status.loadBalancer.ingress[*].ip} '
  ```

- Si vous avez installé Ingress via les **Applications**, exécutez :

  ```shell
  kubectl get service --namespace=gitlab-managed-apps ingress-nginx-ingress-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
  ```

- Certains clusters Kubernetes renvoient un nom d'hôte à la place, comme [Amazon EKS](https://aws.amazon.com/eks/). Pour ces plateformes, exécutez :

  ```shell
  kubectl get service --namespace=gitlab-managed-apps ingress-nginx-ingress-controller -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
  ```

  Si vous utilisez EKS, un [Elastic Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/) est également créé, ce qui entraîne des coûts AWS supplémentaires.

- Istio/Knative utilise une commande différente. Exécutez :

  ```shell
  kubectl get svc --namespace=istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip} '
  ```

Si vous voyez un `%` en fin de chaîne sur certaines versions de Kubernetes, ne l'incluez pas.
