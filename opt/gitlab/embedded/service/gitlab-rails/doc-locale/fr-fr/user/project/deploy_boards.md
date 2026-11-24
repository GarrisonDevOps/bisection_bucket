---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Tableaux de déploiement (obsolète)
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Désactivé sur GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/issues/353410) dans GitLab 15.0.

{{< /history >}}

> [!flag]
> Sur GitLab Self-Managed, cette fonctionnalité n'est pas disponible par défaut. Pour rendre cette fonctionnalité disponible, un administrateur peut [activer le feature flag](../../administration/feature_flags/_index.md) `certificate_based_clusters`.

Les tableaux de déploiement GitLab offrent une vue consolidée de l'état de santé et du statut actuel de chaque [environnement](../../ci/environments/_index.md) CI s'exécutant sur [Kubernetes](https://kubernetes.io), en affichant le statut des pods dans le déploiement. Les équipes de développement et les autres membres de l'équipe peuvent visualiser la progression et le statut d'un déploiement, pod par pod, dans le workflow qu'ils utilisent déjà, sans avoir besoin d'accéder à Kubernetes.

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) dans GitLab 14.5. [L'Epic 2493 existe](https://gitlab.com/groups/gitlab-org/-/work_items/2493) pour ajouter cette fonctionnalité à l'[agent](../clusters/agent/_index.md).

Si vous disposez d'un cluster Kubernetes, vous pouvez déployer automatiquement des applications dans des environnements de production à l'aide d'[Auto DevOps](../../topics/autodevops/_index.md).

Avec les tableaux de déploiement, vous pouvez obtenir plus d'informations sur les déploiements, avec des avantages tels que :

- Suivre un déploiement depuis le début, et pas uniquement lorsqu'il est terminé
- Observer le déploiement progressif d'un build sur plusieurs serveurs
- Détail d'état plus précis (Réussi, En cours, Échoué, En attente, Inconnu)
- Voir [Déploiements canari](canary_deployments.md)

Voici un exemple de tableau de déploiement de l'environnement de production.

![Tableau de bord affichant le déploiement de l'environnement de production avec les pods du cluster Kubernetes.](img/deploy_boards_landing_page_v9_0.png)

Les carrés représentent les pods de votre cluster Kubernetes associés à l'environnement donné. En survolant chaque carré, vous pouvez voir l'état d'un déploiement en cours. Le pourcentage correspond à la proportion des pods mis à jour vers la dernière release.

Les tableaux de déploiement sont étroitement liés à Kubernetes ; vous devez donc être familiarisé avec :

- [Les pods Kubernetes](https://kubernetes.io/docs/concepts/workloads/pods/)
- [Les labels Kubernetes](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)
- [Les espaces de nommage Kubernetes](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/)
- [Les déploiements canari Kubernetes](https://kubernetes.io/docs/concepts/workloads/management/#canary-deployments)

## Cas d'utilisation {#use-cases}

Le tableau de déploiement est une représentation visuelle des pods Kubernetes pour un environnement spécifique ; il existe donc de nombreux cas d'utilisation. En voici quelques-uns :

- Vous souhaitez promouvoir ce qui s'exécute en staging vers la production. Vous accédez donc à la liste des environnements, vérifiez que ce qui s'exécute en staging correspond à vos attentes, puis sélectionnez le [job manuel](../../ci/jobs/job_control.md#create-a-job-that-must-be-run-manually) pour le déployer en production.
- Vous avez déclenché un déploiement et vous avez de nombreux conteneurs à mettre à niveau ; vous savez donc que cela prend du temps (vous avez également limité votre déploiement pour ne désactiver que X conteneurs à la fois). Mais vous devez informer quelqu'un lorsque le déploiement est terminé ; vous accédez donc à la liste des environnements et consultez l'environnement de production pour voir la progression en temps réel à mesure que chaque pod est mis à jour.
- Vous recevez un rapport indiquant qu'il y a un problème en production ; vous consultez donc l'environnement de production pour voir ce qui s'exécute et si un déploiement est en cours, bloqué ou a échoué.
- Vous avez une merge request qui semble correcte, mais vous souhaitez l'exécuter en staging car l'environnement de staging est configuré d'une manière plus proche de la production. Vous accédez donc à la liste des environnements, trouvez l'[environnement éphémère](../../ci/review_apps/_index.md) qui vous intéresse et sélectionnez l'action manuelle pour le déployer en staging.

## Activation des tableaux de déploiement {#enabling-deploy-boards}

Pour afficher les tableaux de déploiement pour un [environnement](../../ci/environments/_index.md) spécifique, vous devez :

1. Avoir [défini un environnement](../../ci/environments/_index.md) avec une étape de déploiement.
1. Disposer d'un cluster Kubernetes opérationnel.

   > [!note]
   > Si vous utilisez OpenShift, assurez-vous d'utiliser la ressource `Deployment` plutôt que `DeploymentConfiguration`. Dans le cas contraire, les tableaux de déploiement ne s'affichent pas correctement. Pour plus d'informations, consultez la [documentation OpenShift](https://docs.openshift.com/container-platform/3.7/dev_guide/deployments/kubernetes_deployments.html#kubernetes-deployments-vs-deployment-configurations) et le [ticket GitLab #4584](https://gitlab.com/gitlab-org/gitlab/-/issues/4584).

1. [Configurez GitLab Runner](../../ci/runners/_index.md) avec l'exécuteur [`docker`](https://docs.gitlab.com/runner/executors/docker/) ou [`kubernetes`](https://docs.gitlab.com/runner/executors/kubernetes/).
1. Configurez l'[intégration Kubernetes](../infrastructure/clusters/_index.md) dans votre projet pour le cluster. L'espace de nommage Kubernetes est particulièrement important, car vous en avez besoin pour vos scripts de déploiement (exposé par la variable de déploiement `KUBE_NAMESPACE`).
1. Assurez-vous que les annotations Kubernetes `app.gitlab.com/env: $CI_ENVIRONMENT_SLUG` et `app.gitlab.com/app: $CI_PROJECT_PATH_SLUG` sont appliquées aux déploiements, aux replica sets et aux pods, où `$CI_ENVIRONMENT_SLUG` et `$CI_PROJECT_PATH_SLUG` correspondent aux valeurs des variables CI/CD. GitLab utilise ces variables pour rechercher l'environnement approprié dans un cluster ou un espace de nommage qui peut en contenir plusieurs. Ces ressources doivent être contenues dans l'espace de nommage défini dans les paramètres du service Kubernetes. Vous pouvez utiliser un template `.gitlab-ci.yml` de [déploiement automatique](../../topics/autodevops/stages.md#auto-deploy) qui dispose d'étapes et de commandes prédéfinies, et applique automatiquement les annotations. Chaque projet doit également disposer d'un espace de nommage unique dans Kubernetes. L'image ci-dessous illustre la façon dont cela s'affiche dans Kubernetes.

   Si vous utilisez GCP pour gérer des clusters, vous pouvez voir les détails du déploiement directement dans GCP en accédant à **Workloads** > **nom du déploiement** > **Détails** :

   ![Détails des tableaux de déploiement GCP.](img/deploy_boards_kubernetes_label_v11_9.png)

Une fois que toutes ces instructions précédentes sont mises en place et que le pipeline a été exécuté au moins une fois, accédez à la page des environnements sous **Opération** > **Environnements**.

Les tableaux de déploiement sont visibles par défaut. Vous pouvez explicitement sélectionner le triangle à côté du nom de l'environnement correspondant pour les masquer.

### Exemple de fichier manifeste {#example-manifest-file}

L'exemple suivant est un extrait d'un fichier manifeste de déploiement Kubernetes, utilisant les deux annotations `app.gitlab.com/env` et `app.gitlab.com/app` pour activer les tableaux de déploiement :

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: "APPLICATION_NAME"
  annotations:
    app.gitlab.com/app: ${CI_PROJECT_PATH_SLUG}
    app.gitlab.com/env: ${CI_ENVIRONMENT_SLUG}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: "APPLICATION_NAME"
  template:
    metadata:
      labels:
        app: "APPLICATION_NAME"
      annotations:
        app.gitlab.com/app: ${CI_PROJECT_PATH_SLUG}
        app.gitlab.com/env: ${CI_ENVIRONMENT_SLUG}
```

Les annotations sont appliquées aux déploiements, aux replica sets et aux pods. En modifiant le nombre de réplicas, par exemple avec `kubectl scale --replicas=3 deploy APPLICATION_NAME -n ${KUBE_NAMESPACE}`, vous pouvez suivre les pods des instances depuis le tableau.

> [!note]
> Le fichier YAML est statique. Si vous l'appliquez avec `kubectl apply`, vous devez fournir manuellement les slugs du projet et de l'environnement, ou créer un script pour remplacer les variables dans le fichier YAML avant de l'appliquer.

## Déploiements canari {#canary-deployments}

Une stratégie CI populaire, dans laquelle une petite partie du parc est mise à jour vers la nouvelle version de votre application.

[En savoir plus sur les déploiements canari.](canary_deployments.md)

## Pour aller plus loin {#further-reading}

- [Déploiement automatique GitLab](../../topics/autodevops/stages.md#auto-deploy)
- [Variables CI/CD GitLab](../../ci/variables/_index.md)
- [Environnements et déploiements](../../ci/environments/_index.md)
- [Exemple de déploiement Kubernetes](https://gitlab.com/gitlab-examples/kubernetes-deploy)
