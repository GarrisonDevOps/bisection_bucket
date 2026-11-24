---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Variables CI/CD
---

Utilisez des variables CI/CD pour configurer le domaine Auto DevOps, fournir un chart Helm personnalisé ou faire évoluer votre application.

## Variables de build et de déploiement {#build-and-deployment-variables}

Utilisez ces variables pour personnaliser et déployer votre build.

| **Variable CI/CD**                      | **Description** |
|-----------------------------------------|-----------------|
| `ADDITIONAL_HOSTS`                      | Noms de domaine complets spécifiés sous forme de liste séparée par des virgules, ajoutés aux hôtes Ingress. |
| `<ENVIRONMENT>_ADDITIONAL_HOSTS`        | Pour un environnement spécifique, les noms de domaine complets spécifiés sous forme de liste séparée par des virgules, ajoutés aux hôtes Ingress. Ceci a la priorité sur `ADDITIONAL_HOSTS`. |
| `AUTO_BUILD_IMAGE_VERSION`              | Personnalise la version de l'image utilisée pour le job `build`. Voir [la liste des versions](https://gitlab.com/gitlab-org/cluster-integration/auto-build-image/-/releases). |
| `AUTO_DEPLOY_IMAGE_VERSION`             | Personnalise la version de l'image utilisée pour les jobs de déploiement Kubernetes. Voir [la liste des versions](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/releases). |
| `AUTO_DEVOPS_ATOMIC_RELEASE`            | Auto DevOps utilise [`--atomic`](https://v2.helm.sh/docs/helm/#options-43) par défaut pour les déploiements Helm. Définissez cette variable sur `false` pour désactiver l'utilisation de `--atomic` |
| `AUTO_DEVOPS_BUILD_IMAGE_CNB_BUILDER`   | Le builder utilisé lors de la construction avec Cloud Native Buildpacks. Le builder par défaut est `heroku/buildpacks:22`. [Plus de détails](stages.md#auto-build-using-cloud-native-buildpacks). |
| `AUTO_DEVOPS_BUILD_IMAGE_EXTRA_ARGS`    | Arguments supplémentaires à passer à la commande `docker build`. L'utilisation de guillemets n'empêche pas la division des mots. [Plus de détails](customize.md#pass-arguments-to-docker-build). |
| `AUTO_DEVOPS_BUILD_IMAGE_FORWARDED_CI_VARIABLES` | Une [liste séparée par des virgules de noms de variables CI/CD](customize.md#forward-cicd-variables-to-the-build-environment) à transmettre à l'environnement de build (le builder buildpack ou `docker build`). |
| `AUTO_DEVOPS_BUILD_IMAGE_CNB_PORT`      | Port exposé par l'image Docker générée. Définissez sur `false` pour empêcher l'exposition de tout port. Par défaut : `5000`. |
| `AUTO_DEVOPS_BUILD_IMAGE_CONTEXT`       | Utilisé pour définir le répertoire de contexte de build pour Dockerfile et Cloud Native Buildpacks. Par défaut, le répertoire racine. |
| `AUTO_DEVOPS_CHART`                     | Chart Helm utilisé pour déployer vos applications. Par défaut, celui [fourni par GitLab](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/tree/master/assets/auto-deploy-app). |
| `AUTO_DEVOPS_CHART_REPOSITORY`          | Dépôt de charts Helm utilisé pour rechercher des charts. Par défaut : `https://charts.gitlab.io`. |
| `AUTO_DEVOPS_CHART_REPOSITORY_NAME`     | Utilisé pour définir le nom du dépôt Helm. Par défaut : `gitlab`. |
| `AUTO_DEVOPS_CHART_REPOSITORY_USERNAME` | Utilisé pour définir un nom d'utilisateur pour se connecter au dépôt Helm. Par défaut, aucune information d'identification. Définissez également `AUTO_DEVOPS_CHART_REPOSITORY_PASSWORD`. |
| `AUTO_DEVOPS_CHART_REPOSITORY_PASSWORD` | Utilisé pour définir un mot de passe pour se connecter au dépôt Helm. Par défaut, aucune information d'identification. Définissez également `AUTO_DEVOPS_CHART_REPOSITORY_USERNAME`. |
| `AUTO_DEVOPS_CHART_REPOSITORY_PASS_CREDENTIALS` | Définissez sur une valeur non vide pour activer la transmission des informations d'identification du dépôt Helm au serveur de charts lorsque les artefacts de charts se trouvent sur un hôte différent de celui du dépôt. |
| `AUTO_DEVOPS_CHART_REPOSITORY_INSECURE` | Définissez sur une valeur non vide pour ajouter un argument `--insecure-skip-tls-verify` aux commandes Helm. Par défaut, Helm utilise la vérification TLS. |
| `AUTO_DEVOPS_CHART_CUSTOM_ONLY`         | Définissez sur une valeur non vide pour utiliser uniquement un chart personnalisé. Par défaut, le dernier chart est téléchargé depuis GitLab. |
| `AUTO_DEVOPS_CHART_VERSION`             | Définit la version du chart de déploiement. Par défaut, la dernière version disponible. |
| `AUTO_DEVOPS_COMMON_NAME`               | Définissez sur un nom de domaine valide pour personnaliser le nom commun utilisé pour le certificat TLS. Par défaut : `le-$CI_PROJECT_ID.$KUBE_INGRESS_BASE_DOMAIN`. Définissez sur `false` pour ne pas définir cet hôte alternatif sur l'Ingress. |
| `AUTO_DEVOPS_DEPLOY_DEBUG`              | Si cette variable est présente, Helm génère des journaux de débogage. |
| `AUTO_DEVOPS_ALLOW_TO_FORCE_DEPLOY_V<N>` | À partir de [auto-deploy-image](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image) v1.0.0, si cette variable est présente, une nouvelle version majeure du chart est déployée de force. Pour plus d'informations, consultez [Ignorer les avertissements et continuer le déploiement](upgrading_auto_deploy_dependencies.md#ignore-warnings-and-continue-deploying). |
| `BUILDPACK_URL`                         | Une URL Buildpack complète. [Doit pointer vers une URL prise en charge par Pack](customize.md#custom-buildpacks). |
| `CANARY_ENABLED`                        | Utilisé pour définir une [politique de déploiement pour les environnements canari](#deploy-policy-for-canary-environments). |
| `BUILDPACK_VOLUMES`                     | Spécifiez un ou plusieurs [volumes Buildpack à monter](stages.md#mount-volumes-into-the-build-container). Utilisez un pipe `\|` comme séparateur de liste. |
| `CANARY_PRODUCTION_REPLICAS`            | Nombre de réplicas canari à déployer pour les [déploiements canari](../../user/project/canary_deployments.md) dans l'environnement de production. Prévaut sur `CANARY_REPLICAS`. Par défaut, 1. |
| `CANARY_REPLICAS`                       | Nombre de réplicas canari à déployer pour les [déploiements canari](../../user/project/canary_deployments.md). Par défaut, 1. |
| `CI_APPLICATION_REPOSITORY`             | Le dépôt de l'image de conteneur en cours de build ou de déploiement, `$CI_APPLICATION_REPOSITORY:$CI_APPLICATION_TAG`. Pour plus de détails, consultez [Image de conteneur personnalisée](customize.md#custom-container-image). |
| `CI_APPLICATION_TAG`                    | Le tag de l'image de conteneur en cours de build ou de déploiement, `$CI_APPLICATION_REPOSITORY:$CI_APPLICATION_TAG`. Pour plus de détails, consultez [Image de conteneur personnalisée](customize.md#custom-container-image). |
| `DAST_AUTO_DEPLOY_IMAGE_VERSION`        | Personnalise la version de l'image utilisée pour les déploiements DAST sur la branche par défaut. Doit généralement être identique à `AUTO_DEPLOY_IMAGE_VERSION`. Voir [la liste des versions](https://gitlab.com/gitlab-org/cluster-integration/auto-deploy-image/-/releases). |
| `DOCKERFILE_PATH`                       | Permet de remplacer le [chemin Dockerfile par défaut pour l'étape de build](customize.md#custom-dockerfiles) |
| `HELM_RELEASE_NAME`                     | Permet de remplacer le nom de release `helm`. Peut être utilisé pour attribuer des noms de release uniques lors du déploiement de plusieurs projets dans un même espace de nommage. |
| `HELM_UPGRADE_VALUES_FILE`              | Permet de remplacer le fichier de valeurs `helm upgrade`. Par défaut : `.gitlab/auto-deploy-values.yaml`. |
| `HELM_UPGRADE_EXTRA_ARGS`               | Autorise des options supplémentaires dans les commandes `helm upgrade` lors du déploiement de l'application. L'utilisation de guillemets n'empêche pas la division des mots. |
| `INCREMENTAL_ROLLOUT_MODE`              | Si présente, peut être utilisée pour activer un [déploiement progressif](#incremental-rollout-to-production) de votre application pour l'environnement de production. Définissez sur `manual` pour les jobs de déploiement manuels ou sur `timed` pour les déploiements automatiques avec un délai de 5 minutes entre chacun. |
| `K8S_SECRET_*`                          | Toute variable préfixée par [`K8S_SECRET_`](#configure-application-secret-variables) est mise à disposition par Auto DevOps en tant que variables d'environnement pour l'application déployée. |
| `KUBE_CONTEXT`                          | Peut être utilisé pour sélectionner un contexte à utiliser depuis `KUBECONFIG`. Lorsque `KUBE_CONTEXT` est vide, le contexte par défaut dans `KUBECONFIG` (le cas échéant) est utilisé. Un contexte doit être sélectionné lorsqu'il est utilisé [avec l'agent pour Kubernetes](../../user/clusters/agent/ci_cd_workflow.md). |
| `KUBE_INGRESS_BASE_DOMAIN`              | Peut être utilisé pour définir un domaine par cluster. Consultez [les domaines de cluster](../../user/project/clusters/gitlab_managed_clusters.md#base-domain) pour plus d'informations. |
| `KUBE_NAMESPACE`                        | L'espace de nommage utilisé pour les déploiements. Lors de l'utilisation de clusters basés sur des certificats, [cette valeur ne doit pas être écrasée directement](../../user/project/clusters/deploy_to_cluster.md#custom-namespace). |
| `KUBECONFIG`                            | La configuration kubeconfig à utiliser pour les déploiements. Les valeurs fournies par l'utilisateur ont la priorité sur les valeurs fournies par GitLab. |
| `PRODUCTION_REPLICAS`                   | Nombre de réplicas à déployer dans l'environnement de production. A la priorité sur `REPLICAS` et prend la valeur par défaut de 1. Pour les mises à niveau sans interruption de service, définissez sur 2 ou plus. |
| `REPLICAS`                              | Nombre de réplicas à déployer. Par défaut, 1. Modifiez cette variable plutôt que de [modifier](customize.md#customize-helm-chart-values) `replicaCount`. |
| `ROLLOUT_RESOURCE_TYPE`                 | Permet de spécifier le type de ressource déployé lors de l'utilisation d'un chart Helm personnalisé. La valeur par défaut est `deployment`. |
| `ROLLOUT_STATUS_DISABLED`               | Utilisé pour désactiver la vérification du statut du déploiement, car elle ne prend pas en charge tous les types de ressources, par exemple `cronjob`. |
| `STAGING_ENABLED`                       | Utilisé pour définir une [politique de déploiement pour les environnements de staging et de production](#deploy-policy-for-staging-and-production-environments). |
| `TRACE`                                 | Définissez sur n'importe quelle valeur pour que les commandes Helm produisent une sortie détaillée. Vous pouvez utiliser ce paramètre pour aider à diagnostiquer les problèmes de déploiement Auto DevOps. |

## Variables de base de données {#database-variables}

> [!warning]
> `POSTGRES_ENABLED` n'est plus défini par défaut.

Utilisez ces variables pour intégrer CI/CD aux bases de données PostgreSQL.

| **Variable CI/CD**                            | **Description**                    |
|-----------------------------------------|------------------------------------|
| `DB_INITIALIZE`                         | Utilisé pour spécifier la commande à exécuter pour initialiser la base de données PostgreSQL de l'application. S'exécute dans le pod de l'application. |
| `DB_MIGRATE`                            | Utilisé pour spécifier la commande à exécuter pour migrer la base de données PostgreSQL de l'application. S'exécute dans le pod de l'application. |
| `POSTGRES_ENABLED`                      | Indique si PostgreSQL est activé. Définissez sur `true` pour activer le déploiement automatique de PostgreSQL. |
| `POSTGRES_USER`                         | L'utilisateur PostgreSQL. Par défaut : `user`. Définissez-le pour utiliser un nom d'utilisateur personnalisé. |
| `POSTGRES_PASSWORD`                     | Le mot de passe PostgreSQL. Par défaut : `testing-password`. Définissez-le pour utiliser un mot de passe personnalisé. |
| `POSTGRES_DB`                           | Le nom de la base de données PostgreSQL. Par défaut, la valeur de [`$CI_ENVIRONMENT_SLUG`](../../ci/variables/_index.md#predefined-cicd-variables). Définissez-le pour utiliser un nom de base de données personnalisé. |
| `POSTGRES_VERSION`                      | Tag de l'[image Docker `postgres`](https://hub.docker.com/_/postgres) à utiliser. Par défaut, `9.6.16` pour les tests et les déploiements. Si `AUTO_DEVOPS_POSTGRES_CHANNEL` est défini sur `1`, les déploiements utilisent la version par défaut `9.6.2`. |
| `POSTGRES_HELM_UPGRADE_VALUES_FILE`     | Lors de l'utilisation d'[auto-deploy-image v2](upgrading_auto_deploy_dependencies.md), cette variable permet de remplacer le fichier de valeurs `helm upgrade` pour PostgreSQL. Par défaut : `.gitlab/auto-deploy-postgres-values.yaml`. |
| `POSTGRES_HELM_UPGRADE_EXTRA_ARGS`      | Lors de l'utilisation d'[auto-deploy-image v2](upgrading_auto_deploy_dependencies.md), cette variable autorise des options PostgreSQL supplémentaires dans les commandes `helm upgrade` lors du déploiement de l'application. L'utilisation de guillemets n'empêche pas la division des mots. |
| `POSTGRES_CHART_REPOSITORY`             | Dépôt de charts Helm utilisé pour rechercher le chart PostgreSQL. Par défaut : `https://raw.githubusercontent.com/bitnami/charts/eb5f9a9513d987b519f0ecd732e7031241c50328/bitnami`. |
| `POSTGRES_CHART_VERSION`                | Version du chart Helm utilisée pour le chart PostgreSQL. Par défaut : `8.2.1`. |

## Variables de suppression de jobs {#job-skipping-variables}

 Utilisez ces variables pour ignorer des types spécifiques de jobs CI/CD. Lorsqu'ils sont ignorés, les jobs CI/CD ne sont pas créés ni exécutés.

| **Nom du job**                           | **Variable CI/CD**              | **Version de GitLab**    | **Description** |
|----------------------------------------|---------------------------------|-----------------------|-----------------|
| `.fuzz_base`                           | `COVFUZZ_DISABLED`              |                       | [En savoir plus](../../user/application_security/coverage_fuzzing/_index.md) sur la façon dont `.fuzz_base` offre des fonctionnalités pour vos propres jobs. Le job n'est pas créé si la valeur est `"true"`. |
| `apifuzzer_fuzz`                       | `API_FUZZING_DISABLED`          |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `build`                                | `BUILD_DISABLED`                |                       | Si la variable est présente, le job n'est pas créé. |
| `build_artifact`                       | `BUILD_DISABLED`                |                       | Si la variable est présente, le job n'est pas créé. |
| `brakeman-sast`                        | `SAST_DISABLED`                 |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `canary`                               | `CANARY_ENABLED`                |                       | Ce job manuel est créé si la variable est présente. |
| `code_intelligence`                    | `CODE_INTELLIGENCE_DISABLED`    |                       | Si la variable est présente, le job n'est pas créé. |
| `code_quality`                         | `CODE_QUALITY_DISABLED`         |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `container_scanning`                   | `CONTAINER_SCANNING_DISABLED`   |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `dast`                                 | `DAST_DISABLED`                 |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `dast_environment_deploy`              | `DAST_DISABLED_FOR_DEFAULT_BRANCH` ou `DAST_DISABLED`  |                        | Le job n'est pas créé si la valeur est `"true"`. |
| `dependency_scanning`                  | `DEPENDENCY_SCANNING_DISABLED`  |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `flawfinder-sast`                      | `SAST_DISABLED`                 |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `gemnasium-dependency_scanning`        | `DEPENDENCY_SCANNING_DISABLED`  |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `gemnasium-maven-dependency_scanning`  | `DEPENDENCY_SCANNING_DISABLED`  |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `gemnasium-python-dependency_scanning` | `DEPENDENCY_SCANNING_DISABLED`  |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `kubesec-sast`                         | `SAST_DISABLED`                 |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `license_scanning`                     | `LICENSE_MANAGEMENT_DISABLED`   |                       | Le job n'est pas créé si la valeur est `"true"`. Job déprécié [depuis GitLab 15.9](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/111071) |
| `load_performance`                     | `LOAD_PERFORMANCE_DISABLED`     |                       | Si la variable est présente, le job n'est pas créé. |
| `nodejs-scan-sast`                     | `SAST_DISABLED`                 |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `browser_performance`                  | `BROWSER_PERFORMANCE_DISABLED`  |                       | Performance du navigateur. Si la variable est présente, le job n'est pas créé. |
| `phpcs-security-audit-sast`            | `SAST_DISABLED`                 |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `pmd-apex-sast`                        | `SAST_DISABLED`                 |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `review`                               | `REVIEW_DISABLED`               |                       | Si la variable est présente, le job n'est pas créé. |
| `review:stop`                          | `REVIEW_DISABLED`               |                       | Job manuel. Si la variable est présente, le job n'est pas créé. |
| `secret_detection`                     | `SECRET_DETECTION_DISABLED`     |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `secret_detection_default_branch`      | `SECRET_DETECTION_DISABLED`     |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `semgrep-sast`                         | `SAST_DISABLED`                 |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `sobelow-sast`                         | `SAST_DISABLED`                 |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `stop_dast_environment`                | `DAST_DISABLED_FOR_DEFAULT_BRANCH` ou `DAST_DISABLED` |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `spotbugs-sast`                        | `SAST_DISABLED`                 |                       | Le job n'est pas créé si la valeur est `"true"`. |
| `test`                                 | `TEST_DISABLED`                 |                       | Si la variable est présente, le job n'est pas créé. |
| `staging`                              | `STAGING_ENABLED`               |                       | Le job est créé si la variable est présente. |
| `stop_review`                          | `REVIEW_DISABLED`               |                       | Si la variable est présente, le job n'est pas créé. |

## Configurer les variables secrètes de l'application {#configure-application-secret-variables}

Certaines applications déployées nécessitent l'accès à des variables secrètes. Auto DevOps détecte les variables CI/CD commençant par `K8S_SECRET_` et les met à disposition de l'application déployée en tant que variables d'environnement.

Prérequis :

- La valeur de la variable doit tenir sur une seule ligne.

Pour configurer des variables secrètes :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD**.
1. Développez **Variables**.
1. Créez une variable CI/CD avec le préfixe `K8S_SECRET_`. Par exemple, vous pouvez créer une variable appelée `K8S_SECRET_RAILS_MASTER_KEY`.
1. Exécutez un pipeline Auto DevOps, soit en créant manuellement un nouveau pipeline, soit en poussant une modification de code vers GitLab.

### Secrets Kubernetes {#kubernetes-secrets}

Les pipelines Auto DevOps utilisent les variables secrètes de votre application pour alimenter un secret Kubernetes. Ce secret est unique par environnement. Lors du déploiement de votre application, le secret est chargé en tant que variables d'environnement dans le conteneur exécutant l'application. Par exemple, si vous créez un secret appelé `K8S_SECRET_RAILS_MASTER_KEY`, votre secret Kubernetes pourrait ressembler à ceci :

```shell
$ kubectl get secret production-secret -n minimal-ruby-app-54 -o yaml

apiVersion: v1
data:
  RAILS_MASTER_KEY: MTIzNC10ZXN0
kind: Secret
metadata:
  creationTimestamp: 2018-12-20T01:48:26Z
  name: production-secret
  namespace: minimal-ruby-app-54
  resourceVersion: "429422"
  selfLink: /api/v1/namespaces/minimal-ruby-app-54/secrets/production-secret
  uid: 57ac2bfd-03f9-11e9-b812-42010a9400e4
type: Opaque
```

## Mettre à jour les secrets d'application {#update-application-secrets}

Les variables d'environnement sont généralement immuables dans un pod Kubernetes. Si vous mettez à jour un secret d'application et créez ensuite manuellement un nouveau pipeline, les applications en cours d'exécution ne reçoivent pas le secret mis à jour.

Pour mettre à jour les secrets d'application, vous pouvez :

- Envoyer une mise à jour de code vers GitLab pour forcer le déploiement Kubernetes à recréer les pods.
- Supprimer manuellement les pods en cours d'exécution pour que Kubernetes crée de nouveaux pods avec les secrets mis à jour.

Les variables avec des valeurs multi-lignes ne sont pas prises en charge en raison des limitations de l'environnement de script Auto DevOps.

## Configurer les variables de réplicas {#configure-replica-variables}

Ajoutez des variables de réplicas lorsque vous souhaitez faire évoluer vos déploiements :

1. Ajoutez une variable de réplicas en tant que [variable CI/CD de projet](../../ci/variables/_index.md#for-a-project).
1. Pour faire évoluer votre application, redéployez-la.

   > [!warning]
   > Ne faites pas évoluer votre application directement avec Kubernetes. Helm risque de ne pas détecter la modification, et les déploiements ultérieurs avec Auto DevOps peuvent annuler vos modifications.

### Variables de réplicas personnalisées {#custom-replica-variables}

Vous pouvez créer des variables de réplicas personnalisées au format `<TRACK>_<ENV>_REPLICAS` :

- `<TRACK>` est la valeur en majuscules du [label Kubernetes](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/) `track` défini dans la définition de l'application du chart Helm. Si `track` n'est pas défini, omettez `<TRACK>` de la variable personnalisée.
- `<ENV>` est le nom d'environnement en majuscules du job de déploiement défini dans `.gitlab-ci.yml`.

Par exemple, si l'environnement est `qa` et le track est `foo`, créez une variable d'environnement appelée `FOO_QA_REPLICAS` :

```yaml
QA testing:
  stage: deploy
  environment:
    name: qa
  script:
    - deploy foo
```

Le track `foo` doit être défini dans le chart Helm de l'application. Par exemple :

```yaml
replicaCount: 1
image:
  repository: gitlab.example.com/group/project
  tag: stable
  pullPolicy: Always
  secrets:
    - name: gitlab-registry
application:
  track: foo
  tier: web
service:
  enabled: true
  name: web
  type: ClusterIP
  url: http://my.host.com/
  externalPort: 5000
  internalPort: 5000
```

## Politique de déploiement pour les environnements de staging et de production {#deploy-policy-for-staging-and-production-environments}

Auto DevOps utilise généralement le déploiement continu et pousse automatiquement vers l'environnement `production` à chaque fois qu'un nouveau pipeline s'exécute sur la branche par défaut. Pour déployer en production manuellement, vous pouvez utiliser la variable CI/CD `STAGING_ENABLED`.

Si vous définissez `STAGING_ENABLED`, GitLab déploie automatiquement l'application dans un environnement `staging`. Lorsque vous êtes prêt à déployer en production, GitLab crée un job `production_manual`.

Vous pouvez également activer le déploiement manuel dans vos [paramètres de projet](requirements.md#auto-devops-deployment-strategy).

## Politique de déploiement pour les environnements canari {#deploy-policy-for-canary-environments}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez utiliser un [environnement canari](../../user/project/canary_deployments.md) avant de déployer des modifications en production.

Si vous définissez `CANARY_ENABLED`, GitLab crée deux [jobs manuels](../../ci/pipelines/_index.md#add-manual-interaction-to-your-pipeline) :

- `canary` - Déploie l'application dans l'environnement canari.
- `production_manual` - Déploie l'application en production.

## Déploiement progressif en production {#incremental-rollout-to-production}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Utilisez un déploiement progressif pour déployer en continu votre application, en commençant par quelques pods seulement. Vous pouvez augmenter le nombre de pods manuellement.

Vous pouvez activer le déploiement manuel dans vos [paramètres de projet](requirements.md#auto-devops-deployment-strategy), ou en définissant `INCREMENTAL_ROLLOUT_MODE` sur `manual`.

Si vous définissez `INCREMENTAL_ROLLOUT_MODE` sur `manual`, GitLab crée quatre jobs manuels :

1. `rollout 10%`
1. `rollout 25%`
1. `rollout 50%`
1. `rollout 100%`

Le pourcentage est basé sur la variable CI/CD `REPLICAS` et définit le nombre de pods utilisés pour le déploiement. Par exemple, si la valeur est `10` et que vous exécutez le job de déploiement `10%`, votre application est déployée sur un seul pod.

Vous pouvez exécuter les jobs de déploiement dans n'importe quel ordre. Pour réduire l'échelle, réexécutez un job avec un pourcentage inférieur.

Après avoir exécuté le job `rollout 100%`, vous ne pouvez plus réduire l'échelle et devez [restaurer votre déploiement](../../ci/environments/deployments.md#retry-or-roll-back-a-deployment).

### Exemples de configurations de déploiement progressif {#example-incremental-rollout-configurations}

Sans `INCREMENTAL_ROLLOUT_MODE` et sans `STAGING_ENABLED` :

![Graphique de visualisation du workflow CI/CD avec le déploiement progressif et le staging tous deux désactivés](img/rollout_staging_disabled_v11_0.png)

Sans `INCREMENTAL_ROLLOUT_MODE` et avec `STAGING_ENABLED` :

![Graphique de visualisation du workflow CI/CD avec le déploiement progressif désactivé et le staging activé](img/staging_enabled_v11_0.png)

Avec `INCREMENTAL_ROLLOUT_MODE` défini sur `manual` et sans `STAGING_ENABLED` :

![Graphique de visualisation du workflow CI/CD avec le déploiement progressif activé et le staging désactivé](img/rollout_enabled_v10_8.png)

Avec `INCREMENTAL_ROLLOUT_MODE` défini sur `manual` et avec `STAGING_ENABLED` :

![Graphique de visualisation du workflow CI/CD avec le déploiement progressif et le staging tous deux activés](img/rollout_staging_enabled_v11_0.png)

## Déploiement progressif minuté en production {#timed-incremental-rollout-to-production}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Utilisez un déploiement progressif minuté pour déployer en continu votre application, en commençant par quelques pods seulement.

Vous pouvez activer le déploiement progressif minuté dans vos [paramètres de projet](requirements.md#auto-devops-deployment-strategy), ou en définissant la variable CI/CD `INCREMENTAL_ROLLOUT_MODE` sur `timed`.

Si vous définissez `INCREMENTAL_ROLLOUT_MODE` sur `timed`, GitLab crée quatre jobs :

1. `timed rollout 10%`
1. `timed rollout 25%`
1. `timed rollout 50%`
1. `timed rollout 100%`

Il y a un délai de cinq minutes entre les jobs.
