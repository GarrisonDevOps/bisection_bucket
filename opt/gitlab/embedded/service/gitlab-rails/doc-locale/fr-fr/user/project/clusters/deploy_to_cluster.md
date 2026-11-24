---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Déployer sur un cluster Kubernetes avec des certificats de cluster (déprécié)
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) dans GitLab 14.5. Pour connecter votre cluster à GitLab, utilisez l'[agent GitLab pour Kubernetes](../../clusters/agent/_index.md). Pour déployer avec l'agent, utilisez le [workflow CI/CD](../../clusters/agent/ci_cd_workflow.md).

Un cluster Kubernetes peut être la destination d'un job de déploiement. Si

- Le cluster est intégré à GitLab, des [variables de déploiement](#deployment-variables) spéciales sont mises à disposition de votre job et aucune configuration n'est requise. Vous pouvez immédiatement commencer à interagir avec le cluster depuis vos jobs en utilisant des outils tels que `kubectl` ou `helm`.
- Si vous n'utilisez pas l'intégration de cluster GitLab, vous pouvez toujours déployer sur votre cluster. Cependant, vous devez configurer les outils Kubernetes vous-même en utilisant les [variables CI/CD](../../../ci/variables/_index.md#for-a-project) avant de pouvoir interagir avec le cluster depuis vos jobs.

## Variables de déploiement {#deployment-variables}

Les variables de déploiement nécessitent un [jeton de déploiement](../deploy_tokens/_index.md) valide nommé [`gitlab-deploy-token`](../deploy_tokens/_index.md#gitlab-deploy-token), ainsi que la commande suivante dans le script de votre job de déploiement, pour que Kubernetes puisse accéder au registre :

- Avec Kubernetes 1.18+ :

  ```shell
  kubectl create secret docker-registry gitlab-registry --docker-server="$CI_REGISTRY" --docker-username="$CI_DEPLOY_USER" --docker-password="$CI_DEPLOY_PASSWORD" --docker-email="$GITLAB_USER_EMAIL" -o yaml --dry-run=client | kubectl apply -f -
  ```

- Avec Kubernetes <1.18 :

  ```shell
  kubectl create secret docker-registry gitlab-registry --docker-server="$CI_REGISTRY" --docker-username="$CI_DEPLOY_USER" --docker-password="$CI_DEPLOY_PASSWORD" --docker-email="$GITLAB_USER_EMAIL" -o yaml --dry-run | kubectl apply -f -
  ```

L'intégration de cluster Kubernetes expose ces [variables de déploiement](../../../ci/variables/predefined_variables.md#deployment-variables) dans l'environnement de build GitLab CI/CD pour les jobs de déploiement. Les jobs de déploiement ont [défini un environnement cible](../../../ci/environments/_index.md).

| Variable de déploiement        | Description |
|----------------------------|-------------|
| `KUBE_URL`                 | Égale à l'URL de l'API. |
| `KUBE_TOKEN`               | Le jeton Kubernetes du [compte de service de l'environnement](cluster_access.md). |
| `KUBE_NAMESPACE`           | L'espace de nommage associé au compte de service de déploiement du projet. Au format `<project_name>-<project_id>-<environment>`. Pour les clusters gérés par GitLab, un espace de nommage correspondant est automatiquement créé par GitLab dans le cluster. Si votre cluster a été créé avant GitLab 12.2, la valeur par défaut de `KUBE_NAMESPACE` est définie sur `<project_name>-<project_id>`. |
| `KUBE_CA_PEM_FILE`         | Chemin vers un fichier contenant des données PEM. Présent uniquement si un bundle CA personnalisé a été spécifié. |
| `KUBE_CA_PEM`              | (déprécié) Données PEM brutes. Uniquement si un bundle CA personnalisé a été spécifié. |
| `KUBECONFIG`               | Chemin vers un fichier contenant `kubeconfig` pour ce déploiement. Le bundle CA serait intégré s'il est spécifié. Cette configuration intègre également le même jeton défini dans `KUBE_TOKEN`, vous n'avez donc probablement besoin que de cette variable. Ce nom de variable est également automatiquement reconnu par `kubectl`, vous n'avez donc pas besoin de le référencer explicitement si vous utilisez `kubectl`. |
| `KUBE_INGRESS_BASE_DOMAIN` | Cette variable peut être utilisée pour définir un domaine par cluster. Consultez [les domaines de cluster](gitlab_managed_clusters.md#base-domain) pour plus d'informations. |

## Espace de nommage personnalisé {#custom-namespace}

L'intégration Kubernetes fournit un `KUBECONFIG` avec un espace de nommage généré automatiquement pour les jobs de déploiement. Par défaut, il utilise des espaces de nommage spécifiques au projet et à l'environnement, de la forme `<prefix>-<environment>`, où `<prefix>` est de la forme `<project_name>-<project_id>`. Pour plus d'informations, consultez [Variables de déploiement](#deployment-variables).

Vous pouvez personnaliser l'espace de nommage de déploiement de plusieurs façons :

- Vous pouvez choisir entre un **espace de nommage par [environnement](../../../ci/environments/_index.md)** ou un **espace de nommage par projet**. Un espace de nommage par environnement est le paramètre par défaut et recommandé, car il empêche le mélange des ressources entre les environnements de production et hors production.
- Lors de l'utilisation d'un cluster au niveau du projet, vous pouvez également personnaliser le préfixe de l'espace de nommage. Lors de l'utilisation d'un espace de nommage par environnement, l'espace de nommage de déploiement est `<prefix>-<environment>`, sinon simplement `<prefix>`.
- Pour les clusters **non gérés**, l'espace de nommage généré automatiquement est défini dans le `KUBECONFIG`, mais l'utilisateur est responsable de s'assurer de son existence. Vous pouvez entièrement personnaliser cette valeur en utilisant [`environment:kubernetes:namespace`](../../../ci/environments/configure_kubernetes_deployments.md) dans `.gitlab-ci.yml`.

Lorsque vous personnalisez l'espace de nommage, les environnements existants restent liés à leurs espaces de nommage actuels jusqu'à ce que vous [vidiez le cache du cluster](gitlab_managed_clusters.md#clearing-the-cluster-cache).

### Protection des identifiants {#protecting-credentials}

Par défaut, toute personne pouvant créer un job de déploiement peut accéder à n'importe quelle variable CI/CD dans le job de déploiement d'un environnement. Cela inclut `KUBECONFIG`, qui donne accès à tout secret disponible pour le compte de service associé dans votre cluster. Pour protéger vos identifiants de production, envisagez d'utiliser des [environnements protégés](../../../ci/environments/protected_environments.md), combinés à l'un des éléments suivants :

- Un cluster géré par GitLab et un espace de nommage par environnement.
- Un cluster à portée d'environnement par environnement protégé. Le même cluster peut être ajouté plusieurs fois avec plusieurs comptes de service restreints.

## Terminaux web pour les clusters Kubernetes {#web-terminals-for-kubernetes-clusters}

L'intégration Kubernetes ajoute la prise en charge des [terminaux web](../../../ci/environments/_index.md#web-terminals-deprecated) à vos [environnements](../../../ci/environments/_index.md). Cela repose sur la fonctionnalité `exec` présente dans Docker et Kubernetes, ce qui vous permet d'obtenir une nouvelle session shell dans vos conteneurs existants. Pour utiliser cette intégration, vous devez déployer sur Kubernetes en utilisant les variables de déploiement de cette page, en vous assurant que les déploiements, les ensembles de réplicas et les pods sont annotés avec :

- `app.gitlab.com/env: $CI_ENVIRONMENT_SLUG`
- `app.gitlab.com/app: $CI_PROJECT_PATH_SLUG`

`$CI_ENVIRONMENT_SLUG` et `$CI_PROJECT_PATH_SLUG` sont les valeurs des variables CI/CD.

Vous devez être le propriétaire du projet ou disposer des permissions `maintainer` pour utiliser les terminaux. La prise en charge est limitée au premier conteneur du premier pod de votre environnement.

## Dépannage {#troubleshooting}

Avant le démarrage du job de déploiement, GitLab crée les éléments suivants spécifiquement pour le job de déploiement :

- Un espace de nommage.
- Un compte de service.

Cependant, GitLab ne peut parfois pas les créer. Dans de tels cas, votre job peut échouer avec le message :

```plaintext
This job failed because the necessary resources were not successfully created.
```

Pour trouver la cause de cette erreur lors de la création d'un espace de nommage et d'un compte de service, consultez les [journaux](../../../administration/logs/_index.md#kuberneteslog-deprecated).

Les raisons d'échec incluent :

- Le jeton que vous avez fourni à GitLab ne dispose pas des privilèges [`cluster-admin`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles) requis par GitLab.
- Variables de déploiement `KUBECONFIG` ou `KUBE_TOKEN` manquantes. Pour être transmises à votre job, elles doivent avoir un [`environment:name`](../../../ci/environments/_index.md) correspondant. Si votre job n'a pas de `environment:name` défini, les identifiants Kubernetes ne lui sont pas transmis.

> [!note]
> Les clusters au niveau du projet mis à niveau depuis GitLab 12.0 ou une version antérieure pourraient être configurés d'une manière qui provoque cette erreur. Assurez-vous de désactiver l'option [cluster géré par GitLab](gitlab_managed_clusters.md) si vous souhaitez gérer vous-même les espaces de nommage et les comptes de service.
