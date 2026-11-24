---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Ajouter un cluster à l'aide de certificats de cluster (déprécié)"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/gitlab-org/gitlab/-/issues/327908) dans GitLab 14.0. Pour créer et gérer un nouveau cluster, utilisez [Infrastructure as Code](../../infrastructure/iac/_index.md).

## Désactiver un cluster {#disable-a-cluster}

Lorsque vous connectez avec succès un cluster existant à l'aide de certificats de cluster, la connexion du cluster à GitLab est activée. Pour la désactiver :

1. Accédez à :
   - La page {{< icon name="cloud-gear" >}} **Opération** > **Clusters Kubernetes** de votre projet, pour un cluster au niveau du projet.
   - La page {{< icon name="cloud-gear" >}} **Kubernetes** de votre groupe, pour un cluster au niveau du groupe.
   - La page **Kubernetes** de la zone **Admin**, pour un cluster au niveau de l'instance.
1. Sélectionnez le nom du cluster que vous souhaitez désactiver.
1. Désactivez **Intégration GitLab** (en gris).
1. Sélectionnez **Enregistrer les modifications**.

## Supprimer un cluster {#remove-a-cluster}

Lorsque vous supprimez une intégration de cluster, vous supprimez uniquement la relation du cluster avec GitLab, pas le cluster lui-même. Pour supprimer le cluster lui-même, accédez au tableau de bord GKE ou EKS de votre cluster pour le faire depuis leur interface utilisateur, ou utilisez `kubectl`.

Vous devez disposer du rôle Maintainer ou Owner pour votre projet ou groupe afin de supprimer l'intégration avec GitLab.

Lors de la suppression d'une intégration de cluster, vous avez deux options :

- **Retirer l'intégration** : supprimer uniquement l'intégration Kubernetes.
- **Supprimer l'intégration et les ressources** : supprimer l'intégration du cluster et toutes les ressources GitLab liées au cluster, telles que les espaces de nommage, les rôles et les liaisons.

Pour supprimer l'intégration du cluster Kubernetes :

1. Accédez à la page de détails de votre cluster.
1. Sélectionnez l'onglet **Paramètres avancés**.
1. Sélectionnez **Retirer l'intégration** ou **Supprimer l'intégration et les ressources**.

### Supprimer des clusters à l'aide de la console Rails {#remove-clusters-by-using-the-rails-console}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Démarrez une session de console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session).

Pour trouver un cluster :

``` ruby
cluster = Clusters::Cluster.find(1)
cluster = Clusters::Cluster.find_by(name: 'cluster_name')
```

Pour supprimer un cluster sans supprimer les ressources associées :

```ruby
# Find users who have administrator access
user = User.find_by(username: 'admin_user')

# Find the cluster with the ID
cluster = Clusters::Cluster.find(1)

# Delete the cluster
Clusters::DestroyService.new(user).execute(cluster)
```
