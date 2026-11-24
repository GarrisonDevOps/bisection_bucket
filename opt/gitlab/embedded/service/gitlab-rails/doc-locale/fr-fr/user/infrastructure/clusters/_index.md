---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Clusters Kubernetes
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour connecter des clusters à GitLab, utilisez l'[agent GitLab pour Kubernetes](../../clusters/agent/_index.md).

## Intégration Kubernetes par certificat (obsolète) {#certificate-based-kubernetes-integration-deprecated}

> [!warning]
> Dans GitLab 14.5, la méthode basée sur les certificats pour connecter des clusters Kubernetes à GitLab a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8), ainsi que ses [fonctionnalités](#deprecated-features) associées. Dans GitLab Self-Managed 17.0 et versions ultérieures, cette fonctionnalité est désactivée par défaut. Pour les utilisateurs de GitLab.com, cette fonctionnalité est disponible jusqu'à GitLab 15.9 pour les utilisateurs disposant d'au moins un cluster basé sur des certificats activé dans leur hiérarchie d'espace de nommage. Pour les utilisateurs de GitLab.com n'ayant jamais utilisé cette fonctionnalité auparavant, elle n'est plus disponible.

L'intégration Kubernetes basée sur les certificats avec GitLab est obsolète. Cette intégration présentait les problèmes suivants :

- Des problèmes de sécurité existaient, car elle nécessitait un accès direct à l'API Kubernetes par GitLab.
- Les options de configuration n'étaient pas flexibles.
- L'intégration était instable.
- Les utilisateurs signalaient constamment des problèmes avec les fonctionnalités basées sur ce modèle.

Pour cette raison, l'intégration basée sur les certificats a été dépréciée au profit du nouveau modèle, l'[agent GitLab pour Kubernetes](../../clusters/agent/_index.md). Le maintien des deux méthodes en parallèle a engendré beaucoup de confusion et a considérablement accru la complexité de leur utilisation, développement, maintenance et documentation. En conséquence, les deux ont été dépréciées au profit du nouveau modèle. Les fonctionnalités basées sur les certificats continuent de :

- Recevoir des correctifs de sécurité et des correctifs critiques.
- Fonctionner avec les versions Kubernetes prises en charge.

La suppression de ces fonctionnalités de GitLab n'est pas encore planifiée.

Suivez cet [epic](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) pour les mises à jour.

Si vous avez besoin de plus de temps pour migrer vers l'agent GitLab pour Kubernetes, vous pouvez [activer le feature flag](../../../administration/feature_flags/_index.md) nommé `certificate_based_clusters`. Pour plus d'informations, consultez l'[avis de dépréciation](../../../update/deprecations.md#gitlab-self-managed-certificate-based-integration-with-kubernetes). Ce feature flag réactive l'intégration Kubernetes basée sur les certificats.

## Fonctionnalités obsolètes {#deprecated-features}

- [Connecter un cluster existant via des certificats de cluster](../../project/clusters/add_existing_cluster.md)
- [Contrôles d'accès](../../project/clusters/cluster_access.md)
- [Clusters gérés par GitLab](../../project/clusters/gitlab_managed_clusters.md)
- [Déployer des applications via une connexion basée sur les certificats](../../project/clusters/deploy_to_cluster.md)
- [Projet de gestion de cluster](../../clusters/management_project.md)
- [Environnements de cluster](../../clusters/environments.md)
- [Afficher les déploiements Canary Ingress sur les tableaux de déploiement](../../project/canary_deployments.md#show-canary-ingress-deployments-on-deploy-boards-deprecated)
- [Tableaux de déploiement](../../project/deploy_boards.md)
- [Terminaux web](../../../administration/integration/terminal.md)

### Niveaux de cluster {#cluster-levels}

Le concept de clusters de [niveau projet](../../project/clusters/_index.md), de [niveau groupe](../../group/clusters/_index.md) et de [niveau instance](../../instance/clusters/_index.md) disparaît dans le nouveau modèle, même si la fonctionnalité subsiste dans une certaine mesure.

L'agent est toujours configuré dans un seul projet GitLab et vous pouvez exposer la connexion au cluster à d'autres projets et groupes pour [y accéder depuis GitLab CI/CD](../../clusters/agent/ci_cd_workflow.md). Ce faisant, vous accordez à ces projets et groupes l'accès au même cluster, ce qui est similaire au cas d'usage des clusters de niveau groupe.
