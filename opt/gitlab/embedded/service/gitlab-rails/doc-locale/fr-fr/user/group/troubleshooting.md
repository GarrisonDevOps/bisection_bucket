---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Dépannage des groupes
---

## Erreurs de validation sur les espaces de nommage et les groupes {#validation-errors-on-namespaces-and-groups}

Effectue les vérifications suivantes lors de la création ou de la mise à jour d'espaces de nommage ou de groupes :

- Les espaces de nommage ne doivent pas avoir de parents.
- Les parents de groupe doivent être des groupes et non des espaces de nommage.

Dans le cas improbable où vous verriez ces erreurs dans votre installation GitLab, [contactez le Support](https://support.gitlab.com/) afin que GitLab puisse améliorer cette validation.

## Rechercher des groupes à l'aide d'une requête SQL {#find-groups-using-an-sql-query}

Pour rechercher et stocker un tableau de groupes basé sur une requête SQL dans la [console Rails](../../administration/operations/rails_console.md) :

```ruby
# Finds groups and subgroups that end with '%oup'
Group.find_by_sql("SELECT * FROM namespaces WHERE name LIKE '%oup'")
=> [#<Group id:3 @test-group>, #<Group id:4 @template-group/template-subgroup>]
```

## Transférer un sous-groupe vers un autre emplacement à l'aide de la console Rails {#transfer-subgroup-to-another-location-using-rails-console}

Si le transfert d'un groupe ne fonctionne pas via l'interface utilisateur ou l'API, vous pouvez tenter le transfert dans une [session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session) :

> [!warning]
> Les commandes qui modifient des données peuvent causer des dommages si elles ne sont pas exécutées correctement ou dans les bonnes conditions. Exécutez toujours les commandes dans un environnement de test d'abord et disposez d'une instance de sauvegarde prête à être restaurée.

```ruby
user = User.find_by_username('<username>')
group = Group.find_by_name("<group_name>")
## Set parent_group = nil to make the subgroup a top-level group
parent_group = Group.find_by(id: "<group_id>")
service = ::Groups::TransferService.new(group, user)
service.execute(parent_group)
```

## Transfert de groupe bloqué dans l'état `transfer_in_progress` ou `transfer_scheduled` {#group-transfer-stuck-in-transfer_in_progress-or-transfer_scheduled-state}

Un transfert de groupe peut se bloquer lorsque le job de transfert asynchrone échoue, par exemple en raison d'une contention de verrou ou de délais d'expiration de requêtes. La nouvelle tentative de transfert renvoie :

`Unable to initiate transfer. The group may already have a transfer in progress.`

Dans GitLab 19.1 et versions ultérieures, relancez le transfert. GitLab replanifie le transfert même lorsque l'espace de nommage est encore dans l'état `transfer_in_progress` ou `transfer_scheduled`.

Dans les versions de GitLab antérieures à 19.1, annulez l'état de transfert obsolète dans une [session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session) avant de relancer le transfert :

> [!warning]
> Les commandes qui modifient des données peuvent causer des dommages si elles ne sont pas exécutées correctement ou dans les bonnes conditions. Exécutez toujours les commandes dans un environnement de test d'abord et disposez d'une instance de sauvegarde prête à être restaurée.

```ruby
Group.find_by_full_path('<group_path>').cancel_transfer!
```

## Rechercher les groupes en attente de suppression à l'aide de la console Rails {#find-groups-pending-deletion-using-rails-console}

Si vous avez besoin de trouver tous les groupes en attente de suppression, vous pouvez utiliser la commande suivante dans une [session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session) :

```ruby
Group.all.each do |g|
 if g.self_deletion_scheduled?
    puts "Group ID: #{g.id}"
    puts "Group name: #{g.name}"
    puts "Group path: #{g.full_path}"
 end
end
```

## Supprimer un groupe à l'aide de la console Rails {#delete-a-group-using-rails-console}

Il arrive qu'une suppression de groupe se bloque. Si nécessaire, dans une [session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session), vous pouvez tenter de supprimer un groupe à l'aide de la commande suivante :

> [!warning]
> Les commandes qui modifient des données peuvent causer des dommages si elles ne sont pas exécutées correctement ou dans les bonnes conditions. Exécutez toujours les commandes dans un environnement de test d'abord et disposez d'une instance de sauvegarde prête à être restaurée.

```ruby
GroupDestroyWorker.new.perform(group_id, user_id)
```

## Trouver les autorisations maximales d'un utilisateur pour un groupe ou un projet {#find-a-users-maximum-permissions-for-a-group-or-project}

Les administrateurs peuvent trouver les autorisations maximales d'un utilisateur pour un groupe ou un projet.

1. Démarrez une [session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session).
1. Exécutez les commandes suivantes :

   ```ruby
   user = User.find_by_username 'username'
   project = Project.find_by_full_path 'group/project'
   user.max_member_access_for_project project.id
   ```

   ```ruby
   user = User.find_by_username 'username'
   group = Group.find_by_full_path 'group'
   user.max_member_access_for_group group.id
   ```

## Impossible de supprimer des membres facturables avec le badge `Project Invite/Group Invite` {#unable-to-remove-billable-members-with-badge-project-invitegroup-invite}

L'erreur suivante se produit généralement lorsque l'utilisateur appartient à un groupe externe qui a été partagé avec vos [projets](../project/members/sharing_projects_groups.md) ou [groupes](../project/members/sharing_projects_groups.md#invite-a-group-to-a-group) :

<!-- vale gitlab_base.LatinTerms = NO -->
`Members who were invited via a group invitation cannot be removed. You can either remove the entire group, or ask an Owner of the invited group to remove the member.`
<!-- vale gitlab_base.LatinTerms = YES -->

Pour supprimer l'utilisateur en tant que membre facturable, suivez l'une de ces options :

- Supprimez l'appartenance au groupe invité depuis la page des membres de votre projet ou de votre groupe.
- Recommandé. Supprimez directement l'utilisateur du groupe invité, si vous avez accès au groupe.

## Permission manquante ou insuffisante, bouton de suppression désactivé {#missing-or-insufficient-permission-delete-button-disabled}

Cette erreur se produit généralement lorsqu'un utilisateur tente de supprimer les images `container_registry` des projets archivés lors d'un transfert de groupe. Pour résoudre cette erreur :

1. Désarchivez le projet.
1. Supprimez les images `container_registry`.
1. Archivez le projet.

## Le propriétaire du groupe ne peut pas approuver les utilisateurs en attente avec le badge `Awaiting user signup` {#group-owner-unable-to-approve-pending-users-with-awaiting-user-signup-badge}

Les invitations par e-mail envoyées aux utilisateurs non-GitLab sont répertoriées sous `Pending members` avec le statut `Awaiting user signup`. Lorsque l'utilisateur s'inscrit sur GitLab.com, le statut est mis à jour vers `Pending owner action` et le propriétaire du groupe peut finaliser le processus d'approbation.

## Base de connaissances du support {#support-knowledge-base}

Si vous rencontrez toujours des problèmes, consultez la [base de connaissances du support GitLab](https://support.gitlab.com/hc/en-us/).
