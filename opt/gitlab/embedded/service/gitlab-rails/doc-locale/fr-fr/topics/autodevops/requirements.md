---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Prérequis pour Auto DevOps
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Avant d'activer [Auto DevOps](_index.md), vous devez le préparer pour le déploiement. Si ce n'est pas le cas, vous pouvez l'utiliser pour créer et tester vos applications, puis configurer le déploiement ultérieurement.

Pour préparer le déploiement :

1. Définissez la [stratégie de déploiement](#auto-devops-deployment-strategy).
1. Préparez le [domaine de base](#auto-devops-base-domain).
1. Définissez l'emplacement où vous souhaitez effectuer le déploiement :

   1. [Kubernetes](#auto-devops-requirements-for-kubernetes).
   1. [Amazon Elastic Container Service (ECS)](cloud_deployments/auto_devops_with_ecs.md).
   1. [Amazon Elastic Kubernetes Service (EKS)](https://about.gitlab.com/blog/deploying-application-eks/).
   1. [Amazon EC2](cloud_deployments/auto_devops_with_ec2.md).
   1. [Google Kubernetes Engine](cloud_deployments/auto_devops_with_gke.md).
   1. [Bare metal](#auto-devops-requirements-for-bare-metal).

1. [Activez Auto DevOps](_index.md#enable-or-disable-auto-devops).

## Stratégie de déploiement Auto DevOps {#auto-devops-deployment-strategy}

Lorsque vous utilisez Auto DevOps pour déployer vos applications, choisissez la [stratégie de déploiement continu](../../ci/_index.md) qui convient le mieux à vos besoins :

| Stratégie de déploiement                                                     | Configuration | Méthodologie |
|-------------------------------------------------------------------------|-------|-------------|
| **Déploiement continu en production**                                 | Active [Auto Deploy](stages.md#auto-deploy) avec la branche par défaut déployée en continu en production. | Déploiement continu en production.|
| **Déploiement continu en production par sorties incrémentielles programmées** | Définit la variable [`INCREMENTAL_ROLLOUT_MODE`](cicd_variables.md#timed-incremental-rollout-to-production) sur `timed`. | Déploiement continu en production avec un délai de 5 minutes entre les déploiements progressifs. |
| **Déploiement automatique pour la préproduction, déploiement manuel pour la production**    | Définit [`STAGING_ENABLED`](cicd_variables.md#deploy-policy-for-staging-and-production-environments) sur `1` et [`INCREMENTAL_ROLLOUT_MODE`](cicd_variables.md#incremental-rollout-to-production) sur `manual`. | La branche par défaut est déployée en continu en préproduction et livrée en continu en production. |

Vous pouvez choisir la méthode de déploiement lors de l'activation d'Auto DevOps ou ultérieurement :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD**.
1. Développez **Auto DevOps**.
1. Choisissez la stratégie de déploiement.
1. Sélectionnez **Enregistrer les modifications**.

> [!note]
> Utilisez la technique de [déploiement bleu/vert](../../ci/environments/incremental_rollouts.md#blue-green-deployment) pour minimiser les temps d'arrêt et les risques.

## Domaine de base Auto DevOps {#auto-devops-base-domain}

Le domaine de base Auto DevOps est requis pour utiliser [Auto Review Apps](stages.md#auto-review-apps) et [Auto Deploy](stages.md#auto-deploy).

Pour définir le domaine de base, procédez de l'une des façons suivantes :

- Au niveau du projet, du groupe ou de l'instance : accédez aux paramètres de votre cluster et ajoutez-le à cet endroit.
- Au niveau du projet ou du groupe : ajoutez-le en tant que variable d'environnement : `KUBE_INGRESS_BASE_DOMAIN`.
- Au niveau de l'instance : accédez à la zone **Admin**, puis à **Paramètres** > **CI/CD** > **Intégration et livraison continues** et ajoutez-le à cet endroit.

La variable de domaine de base `KUBE_INGRESS_BASE_DOMAIN` suit le même ordre de [priorité que les autres variables d'environnement](../../ci/variables/_index.md#cicd-variable-precedence).

Si vous ne spécifiez pas le domaine de base dans vos projets et groupes, Auto DevOps utilise le **Domaine Auto DevOps** à l'échelle de l'instance.

Auto DevOps requiert un enregistrement DNS `A` avec caractère générique correspondant aux domaines de base. Pour un domaine de base `example.com`, vous aurez besoin d'un enregistrement DNS de ce type :

```plaintext
*.example.com   3600     A     10.0.2.2
```

Dans ce cas, les applications déployées sont servies depuis `example.com`, et `10.0.2.2` est l'adresse IP de votre équilibreur de charge, généralement NGINX (voir les prérequis). La configuration de l'enregistrement DNS dépasse la portée de ce document ; consultez votre fournisseur DNS pour obtenir des informations.

Vous pouvez également utiliser des services publics gratuits tels que [nip.io](https://nip.io), qui fournissent un DNS à caractères génériques automatique sans aucune configuration. Pour [nip.io](https://nip.io), définissez le domaine de base Auto DevOps sur `10.0.2.2.nip.io`.

Une fois la configuration terminée, toutes les requêtes atteignent l'équilibreur de charge, qui les achemine vers les pods Kubernetes exécutant votre application.

## Prérequis d'Auto DevOps pour Kubernetes {#auto-devops-requirements-for-kubernetes}

Pour exploiter pleinement Auto DevOps avec Kubernetes, vous avez besoin des éléments suivants :

- **Kubernetes** (pour [Auto Review Apps](stages.md#auto-review-apps) et [Auto Deploy](stages.md#auto-deploy))

  Pour activer les déploiements, vous avez besoin des éléments suivants :

  1. Un [cluster Kubernetes 1.12+](../../user/infrastructure/clusters/_index.md) pour votre projet. Pour les clusters Kubernetes 1.16+, vous devez effectuer une configuration supplémentaire pour [Auto Deploy pour Kubernetes 1.16+](stages.md#kubernetes-116).
  1. Pour le trafic HTTP externe, un contrôleur Ingress est requis. Pour les déploiements standard, tout contrôleur Ingress devrait fonctionner, mais les [déploiements canari](../../user/project/canary_deployments.md) nécessitent NGINX Ingress. Vous pouvez déployer le contrôleur NGINX Ingress sur votre cluster Kubernetes soit via le [modèle de projet de gestion de cluster](../../user/clusters/management_project_template.md) GitLab, soit manuellement à l'aide du chart Helm [`ingress-nginx`](https://github.com/kubernetes/ingress-nginx/tree/master/charts/ingress-nginx).

     Lors du déploiement [à l'aide de charts personnalisés](customize.md#custom-helm-chart), vous devez [annoter](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) le manifeste Ingress pour qu'il soit analysé par Prometheus en utilisant `prometheus.io/scrape: "true"` et `prometheus.io/port: "10254"`.

     > [!note]
     > Si votre cluster est installé sur du bare metal, consultez [Prérequis d'Auto DevOps pour le bare metal](#auto-devops-requirements-for-bare-metal).

- **Domaine de base** (pour [Auto Review Apps](stages.md#auto-review-apps) et [Auto Deploy](stages.md#auto-deploy))

  Vous devez [spécifier le domaine de base Auto DevOps](#auto-devops-base-domain), que toutes vos applications Auto DevOps utilisent. Ce domaine doit être configuré avec un DNS à caractères génériques.
- **GitLab Runner** (pour toutes les étapes)

  Votre runner doit être configuré pour exécuter Docker, généralement avec l'exécuteur [Docker](https://docs.gitlab.com/runner/executors/docker/) ou [Kubernetes](https://docs.gitlab.com/runner/executors/kubernetes/), avec le [mode privilégié activé](https://docs.gitlab.com/runner/executors/docker/#use-docker-in-docker-with-privileged-mode). Les runners n'ont pas besoin d'être installés dans le cluster Kubernetes, mais l'exécuteur Kubernetes est facile à utiliser et s'adapte automatiquement à la charge. Vous pouvez également configurer les runners basés sur Docker pour qu'ils s'adaptent automatiquement à la charge, en utilisant [Docker Machine](https://docs.gitlab.com/runner/executors/docker_machine/).

  Les runners doivent être enregistrés en tant que [runners d'instance](../../ci/runners/runners_scope.md#instance-runners) pour l'ensemble de l'instance GitLab, ou en tant que [runners de projet](../../ci/runners/runners_scope.md#project-runners) affectés à des projets spécifiques.
- **cert-manager** (facultatif, pour TLS/HTTPS)

  Pour activer les endpoints HTTPS de votre application, vous pouvez [installer cert-manager](https://cert-manager.io/docs/releases/), un contrôleur natif de gestion de certificats Kubernetes qui facilite l'émission de certificats. L'installation de cert-manager sur votre cluster émet un certificat [Let's Encrypt](https://letsencrypt.org/) et garantit que les certificats sont valides et à jour.

Si Kubernetes ou Prometheus n'est pas configuré, [Auto Review Apps](stages.md#auto-review-apps) et [Auto Deploy](stages.md#auto-deploy) sont ignorés.

Une fois tous les prérequis satisfaits, vous pouvez [activer Auto DevOps](_index.md#enable-or-disable-auto-devops).

## Prérequis d'Auto DevOps pour le bare metal {#auto-devops-requirements-for-bare-metal}

Selon la [documentation Kubernetes Ingress-NGINX](https://kubernetes.github.io/ingress-nginx/deploy/baremetal/) :

> Dans les environnements cloud traditionnels, où les équilibreurs de charge réseau sont disponibles à la demande, un seul manifeste Kubernetes suffit à fournir un point de contact unique au contrôleur NGINX Ingress pour les clients externes et, indirectement, pour toute application s'exécutant à l'intérieur du cluster. Les environnements bare metal ne disposent pas de cette commodité et nécessitent une configuration légèrement différente pour offrir le même type d'accès aux consommateurs externes.

La documentation référencée précédemment explique le problème et propose des solutions possibles, par exemple :

- Via [MetalLB](https://github.com/metallb/metallb).
- Via [OpenELB (anciennement PorterLB)](https://github.com/openelb/openelb).
