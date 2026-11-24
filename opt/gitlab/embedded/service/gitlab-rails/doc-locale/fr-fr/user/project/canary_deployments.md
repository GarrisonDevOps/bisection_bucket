---
stage: Deploy
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Déploiements canaris
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les déploiements canaris sont une stratégie de [déploiement continu](https://en.wikipedia.org/wiki/Continuous_deployment) populaire, dans laquelle une petite partie du parc est mise à jour vers la nouvelle version de votre application.

Lorsqu'une organisation adopte la [livraison continue](https://about.gitlab.com/blog/continuous-integration-delivery-and-deployment-with-gitlab/), elle doit décider du type de stratégie de déploiement à utiliser. L'une des stratégies les plus populaires est le déploiement canari, dans lequel une petite partie du parc est mise à jour vers la nouvelle version en premier. Ce sous-ensemble, les canaris, sert alors de [signal d'alerte précoce](https://en.wiktionary.org/wiki/canary_in_a_coal_mine) au sens proverbial du terme.

En cas de problème avec la nouvelle version de l'application, seul un faible pourcentage d'utilisateurs est affecté et le changement peut être corrigé ou rapidement annulé.

## Cas d'utilisation {#use-cases}

Les déploiements canaris peuvent être utilisés lorsque vous souhaitez déployer des fonctionnalités uniquement sur une partie de votre parc de pods et observer leur comportement lorsqu'un pourcentage de votre base d'utilisateurs accède à la fonctionnalité temporairement déployée. Si tout fonctionne bien, vous pouvez déployer la fonctionnalité en production en sachant qu'elle ne devrait pas causer de problèmes.

Les déploiements canaris sont également particulièrement nécessaires pour les refactorisations backend, les améliorations de performances ou d'autres modifications où l'interface utilisateur ne change pas, mais où vous souhaitez vous assurer que les performances restent identiques ou s'améliorent. Les équipes de développement doivent être prudentes lorsqu'elles utilisent des canaris avec des modifications visibles par les utilisateurs, car par défaut, les requêtes d'un même utilisateur sont distribuées aléatoirement entre les pods canari et non-canari, ce qui peut entraîner de la confusion, voire des erreurs. Si nécessaire, vous pouvez envisager de [définir `service.spec.sessionAffinity` sur `ClientIP` dans vos définitions de service Kubernetes](https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies), mais cela dépasse le cadre de ce document.

## Contrôle avancé du trafic avec Canary Ingress {#advanced-traffic-control-with-canary-ingress}

Les déploiements canaris peuvent être plus stratégiques grâce à [Canary Ingress](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#canary), un service de routage du trafic avancé qui contrôle les requêtes HTTP entrantes entre les déploiements stables et canaris en fonction de facteurs tels que le poids, les sessions, les cookies et d'autres paramètres. GitLab utilise ce service dans son [architecture Auto Deploy](../../topics/autodevops/upgrading_auto_deploy_dependencies.md#v2-chart-resource-architecture) pour permettre aux utilisateurs de déployer rapidement et en toute sécurité leurs nouveaux déploiements.

### Comment configurer un Canary Ingress dans un déploiement canari {#how-to-set-up-a-canary-ingress-in-a-canary-deployment}

Un Canary Ingress est installé par défaut si votre pipeline Auto DevOps utilise [`v2.0.0+` de `auto-deploy-image`](../../topics/autodevops/upgrading_auto_deploy_dependencies.md#verify-dependency-versions). Un Canary Ingress devient disponible lorsque vous créez un nouveau déploiement canari et est supprimé lorsque le déploiement canari est promu en production.

Voici un exemple de configuration de A à Z :

1. Préparez un projet avec [Auto DevOps activé](../../topics/autodevops/_index.md).
1. Configurez un [cluster Kubernetes](../infrastructure/clusters/_index.md) dans votre projet.
1. Installez [NGINX Ingress](https://github.com/kubernetes/ingress-nginx/tree/main/charts/ingress-nginx) dans votre cluster.
1. Configurez [le domaine de base](clusters/gitlab_managed_clusters.md#base-domain) en fonction de l'endpoint Ingress attribué ci-dessus.
1. Vérifiez si [`v2.0.0+` de `auto-deploy-image` est utilisé dans vos pipelines Auto DevOps](../../topics/autodevops/upgrading_auto_deploy_dependencies.md#verify-dependency-versions). Si ce n'est pas le cas, suivez la documentation pour spécifier la version de l'image.
1. [Exécutez un nouveau pipeline Auto DevOps](../../ci/pipelines/_index.md#run-a-pipeline-manually) et assurez-vous que le job `production` réussit et crée un environnement de production.
1. Configurez un [job de déploiement `canary` pour les pipelines Auto DevOps](../../topics/autodevops/cicd_variables.md#deploy-policy-for-canary-environments).
1. [Exécutez un nouveau pipeline Auto DevOps](../../ci/pipelines/_index.md#run-a-pipeline-manually) et assurez-vous que le job `canary` réussit et crée un déploiement canari avec Canary Ingress.

### Afficher les déploiements Canary Ingress sur les tableaux de déploiement (obsolète) {#show-canary-ingress-deployments-on-deploy-boards-deprecated}

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) dans GitLab 14.5.

Pour afficher les déploiements canaris, vous devez configurer correctement les tableaux de déploiement :

1. Suivez les étapes pour [activer les tableaux de déploiement](deploy_boards.md#enabling-deploy-boards).
1. Pour suivre les déploiements canaris, vous devez associer le label `track: canary` à vos déploiements et pods Kubernetes. Pour démarrer rapidement, vous pouvez utiliser le modèle [Auto Deploy](../../topics/autodevops/stages.md#auto-deploy) pour les déploiements canaris fourni par GitLab.

Selon le déploiement, le label doit être soit `stable` soit `canary`. GitLab suppose que le label de suivi est `stable` si le label est vide ou absent. Tout autre label de suivi est considéré comme `canary` (temporaire). Cela permet à GitLab de déterminer si un déploiement est stable ou canari (temporaire).

Une fois les tableaux de déploiement configurés et le pipeline exécuté au moins une fois, accédez à la page des environnements sous **Pipelines** > **Environnements**. Lors de l'exécution du pipeline, les tableaux de déploiement identifient clairement les pods canaris, offrant ainsi une visibilité rapide et précise sur le statut de chaque environnement et déploiement.

Les déploiements canaris sont marqués d'un point jaune dans le tableau de déploiement afin que vous puissiez les repérer rapidement.

![Déploiements canaris sur le tableau de déploiement](img/deploy_boards_canary_deployments_v9_2.png)

#### Comment vérifier le poids de trafic actuel sur un Canary Ingress (obsolète) {#how-to-check-the-current-traffic-weight-on-a-canary-ingress-deprecated}

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) dans GitLab 14.5.

1. Consultez le [tableau de déploiement](deploy_boards.md).
1. Consultez les poids actuels sur la droite.

   ![Statut de déploiement du Canary Ingress](img/canary_weight_v13_7.png)

#### Comment modifier le poids de trafic sur un Canary Ingress (obsolète) {#how-to-change-the-traffic-weight-on-a-canary-ingress-deprecated}

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) dans GitLab 14.5.

Vous pouvez modifier le poids du trafic dans le tableau de déploiement de votre environnement en utilisant [GraphiQL](../../api/graphql/getting_started.md#graphiql) ou en envoyant des requêtes à l'[API GraphQL](../../api/graphql/getting_started.md#command-line).

Pour utiliser votre [tableau de déploiement](deploy_boards.md) :

1. Accédez à **Opération** > **Environnements** pour votre projet.
1. Définissez le nouveau poids à l'aide de la liste déroulante sur le côté droit.
1. Confirmez votre sélection.

Voici un exemple utilisant [GraphiQL](../../api/graphql/getting_started.md#graphiql) :

1. Accédez à [GraphiQL Explorer](https://gitlab.com/-/graphql-explorer).
1. Exécutez la mutation GraphQL `environmentsCanaryIngressUpdate` :

   ```shell
   mutation {
     environmentsCanaryIngressUpdate(input:{
       id: "gid://gitlab/Environment/29",              # Your Environment ID. You can get the ID from the URL of the environment page.
       weight: 45                                      # The new traffic weight. For example, if you set `45`, 45% of traffic goes to a canary deployment and 55% of traffic goes to a stable deployment.
     }) {
       errors
     }
   }
   ```

1. Si la requête réussit, la réponse `errors` contient un tableau vide. GitLab envoie une requête `PATCH` à votre cluster Kubernetes pour mettre à jour le paramètre de poids sur un Canary Ingress.
