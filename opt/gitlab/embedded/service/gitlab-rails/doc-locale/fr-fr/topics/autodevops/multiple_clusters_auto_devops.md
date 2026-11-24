---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Plusieurs clusters Kubernetes pour Auto DevOps
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lorsque vous utilisez Auto DevOps, vous pouvez déployer différents environnements sur différents clusters Kubernetes.

Le [modèle de job Deploy](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Deploy.gitlab-ci.yml) utilisé par Auto DevOps définit trois noms d'environnement :

- `review/` (chaque environnement commençant par `review/`)
- `staging`
- `production`

Ces environnements sont liés à des jobs utilisant [Auto Deploy](stages.md#auto-deploy), ils doivent donc avoir des domaines de déploiement différents. Vous devez définir des variables [`KUBE_CONTEXT`](../../user/clusters/agent/ci_cd_workflow.md#environments-that-use-auto-devops) et [`KUBE_INGRESS_BASE_DOMAIN`](requirements.md#auto-devops-base-domain) distinctes pour chacun des trois environnements.

## Déployer sur différents clusters {#deploy-to-different-clusters}

Pour déployer vos environnements sur différents clusters Kubernetes :

1. [Créez des clusters Kubernetes avec OpenTofu et GitLab](../../user/infrastructure/iac/_index.md).
1. Associez les clusters à votre projet :
   1. [Installez un agent GitLab pour Kubernetes sur chaque cluster](../../user/clusters/agent/_index.md).
   1. [Configurez chaque agent pour accéder à votre projet](../../user/clusters/agent/work_with_agent.md#configure-your-agent).
1. [Installez NGINX Ingress Controller](cloud_deployments/auto_devops_with_gke.md#install-ingress) sur chaque cluster. Enregistrez l'adresse IP et l'espace de nommage Kubernetes pour l'étape suivante.
1. [Configurez les variables de pipeline CI/CD d'Auto DevOps](cicd_variables.md#build-and-deployment-variables)
   - Configurez une variable `KUBE_CONTEXT` [pour chaque environnement](../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable). La valeur doit pointer vers l'agent du cluster concerné.
   - Configurez une variable `KUBE_INGRESS_BASE_DOMAIN`. Vous devez [configurer le domaine de base](requirements.md#auto-devops-base-domain) pour chaque environnement afin qu'il pointe vers l'Ingress du cluster concerné.
   - Ajoutez une variable `KUBE_NAMESPACE` avec la valeur de l'espace de nommage Kubernetes que vous souhaitez cibler pour vos déploiements. Vous pouvez limiter la portée de la variable à plusieurs environnements.

Pour les [clusters basés sur des certificats](../../user/infrastructure/clusters/_index.md#certificate-based-kubernetes-integration-deprecated) (obsolètes) :

1. Accédez au projet et sélectionnez **Opération** > **Clusters Kubernetes** dans la barre latérale gauche.
1. [Définissez la portée d'environnement de chaque cluster](../../user/project/clusters/multiple_kubernetes_clusters.md#setting-the-environment-scope).
1. Pour chaque cluster, [ajoutez un domaine basé sur son adresse IP Ingress](../../user/project/clusters/gitlab_managed_clusters.md#base-domain).

> [!note]
> [La portée d'environnement du cluster n'est pas respectée lors de la vérification des clusters Kubernetes actifs](https://gitlab.com/gitlab-org/gitlab/-/issues/20351). Pour qu'une configuration multi-cluster fonctionne avec Auto DevOps, vous devez créer un cluster de secours avec **Cluster environment scope** défini sur `*`. Vous pouvez définir n'importe lequel des clusters déjà ajoutés comme cluster de secours.

### Exemples de configurations {#example-configurations}

| Nom du cluster | Portée d'environnement du cluster | Valeur de `KUBE_INGRESS_BASE_DOMAIN` | Valeur de `KUBE CONTEXT`               | Portée d'environnement des variables | Remarques |
|:-------------|:--------------------------|:---------------------------------|:-----------------------------------|:---------------------------|:------|
| review       | `review/*`                | `review.example.com`             | `path/to/project:review-agent`     | `review/*`                 | Un cluster de révision qui exécute tous les [environnements éphémères](../../ci/review_apps/_index.md). |
| staging      | `staging`                 | `staging.example.com`            | `path/to/project:staging-agent`    | `staging`                  | Facultatif. Un cluster de staging qui exécute les déploiements des environnements de staging. Vous devez d'abord [l'activer](cicd_variables.md#deploy-policy-for-staging-and-production-environments). |
| production   | `production`              | `example.com`                    | `path/to/project:production-agent` | `production`               | Un cluster de production qui exécute les déploiements de l'environnement de production. Vous pouvez utiliser les [déploiements progressifs](cicd_variables.md#incremental-rollout-to-production). |

## Tester votre configuration {#test-your-configuration}

Une fois la configuration terminée, testez votre configuration en créant une merge request. Vérifiez si votre application a été déployée en tant qu'environnement éphémère dans le cluster Kubernetes avec la portée d'environnement `review/*`. De même, vérifiez les autres environnements.
