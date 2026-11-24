---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: "Contrôles d'accès avec des certificats de cluster (RBAC ou ABAC) (obsolète)"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) dans GitLab 14.5. Pour connecter votre cluster à GitLab, utilisez plutôt l'[agent GitLab pour Kubernetes](../../clusters/agent/_index.md).

Lors de la création d'un cluster dans GitLab, il vous est demandé si vous souhaitez créer :

- Un cluster avec [contrôle d'accès basé sur les rôles (RBAC)](https://kubernetes.io/docs/reference/access-authn-authz/rbac/), qui est l'option par défaut et recommandée dans GitLab.
- Un cluster avec [contrôle d'accès basé sur les attributs (ABAC)](https://kubernetes.io/docs/reference/access-authn-authz/abac/).

Lorsque GitLab crée le cluster, un compte de service `gitlab` disposant des privilèges `cluster-admin` est créé dans l'espace de nommage `default` pour gérer le cluster nouvellement créé.

Helm crée également des comptes de service supplémentaires et d'autres ressources pour chaque application installée. Consultez la documentation des charts Helm de chaque application pour plus de détails.

Si vous [ajoutez un cluster Kubernetes existant](add_existing_cluster.md), assurez-vous que le jeton du compte dispose des privilèges d'administrateur pour le cluster.

Les ressources créées par GitLab diffèrent selon le type de cluster.

## Remarques importantes {#important-notes}

Notez les points suivants concernant les contrôles d'accès :

- Les ressources spécifiques à l'environnement ne sont créées que si votre cluster est [géré par GitLab](gitlab_managed_clusters.md).
- Si votre cluster a été créé avant GitLab 12.2, il utilise un espace de nommage unique pour tous les environnements du projet.

## Ressources de cluster RBAC {#rbac-cluster-resources}

GitLab crée les ressources suivantes pour les clusters RBAC.

| Nom                  | Type                 | Détails                                                                                                    | Créé lors de           |
|:----------------------|:---------------------|:-----------------------------------------------------------------------------------------------------------|:-----------------------|
| `gitlab`              | `ServiceAccount`     | Espace de nommage `default`                                                                                        | Création d'un nouveau cluster |
| `gitlab-admin`        | `ClusterRoleBinding` | Rôle [`cluster-admin`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles)    | Création d'un nouveau cluster |
| `gitlab-token`        | `Secret`             | Jeton pour le ServiceAccount `gitlab`                                                                          | Création d'un nouveau cluster |
| Espace de nommage d'environnement | `Namespace`          | Contient toutes les ressources spécifiques à l'environnement                                                                | Déploiement sur un cluster |
| Espace de nommage d'environnement | `ServiceAccount`     | Utilise l'espace de nommage de l'environnement                                                                              | Déploiement sur un cluster |
| Espace de nommage d'environnement | `Secret`             | Jeton pour le ServiceAccount d'environnement                                                                       | Déploiement sur un cluster |
| Espace de nommage d'environnement | `RoleBinding`        | Rôle [`admin`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles)            | Déploiement sur un cluster |

## Ressources de cluster ABAC {#abac-cluster-resources}

GitLab crée les ressources suivantes pour les clusters ABAC.

| Nom                  | Type                 | Détails                              | Créé lors de               |
|:----------------------|:---------------------|:-------------------------------------|:---------------------------|
| `gitlab`              | `ServiceAccount`     | Espace de nommage `default`                         | Création d'un nouveau cluster |
| `gitlab-token`        | `Secret`             | Jeton pour le ServiceAccount `gitlab`           | Création d'un nouveau cluster |
| Espace de nommage d'environnement | `Namespace`          | Contient toutes les ressources spécifiques à l'environnement | Déploiement sur un cluster |
| Espace de nommage d'environnement | `ServiceAccount`     | Utilise l'espace de nommage de l'environnement               | Déploiement sur un cluster |
| Espace de nommage d'environnement | `Secret`             | Jeton pour le ServiceAccount d'environnement        | Déploiement sur un cluster |

## Sécurité des runners {#security-of-runners}

Les runners ont le [mode privilégié](https://docs.gitlab.com/runner/executors/docker/#the-privileged-mode) activé par défaut, ce qui leur permet d'exécuter des commandes spéciales et de faire fonctionner Docker dans Docker. Cette fonctionnalité est nécessaire pour exécuter certains jobs [Auto DevOps](../../../topics/autodevops/_index.md). Cela implique que les conteneurs s'exécutent en mode privilégié et vous devez donc être conscient de certains détails importants.

L'indicateur de privilège accorde toutes les capacités au conteneur en cours d'exécution, qui peut à son tour faire presque tout ce que l'hôte peut faire. Soyez conscient du risque de sécurité inhérent à l'exécution d'opérations `docker run` sur des images arbitraires, car celles-ci disposent effectivement d'un accès root.

Si vous ne souhaitez pas utiliser un runner en mode privilégié, vous pouvez :

- Utiliser les runners d'instance sur GitLab.com. Ils ne présentent pas ce problème de sécurité.
- Configurer vos propres runners utilisant [`docker+machine`](https://docs.gitlab.com/runner/executors/docker_machine/).
