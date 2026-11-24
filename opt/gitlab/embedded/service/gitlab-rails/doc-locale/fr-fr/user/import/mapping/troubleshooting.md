---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Dépannage du mappage des contributions et des membres après migration
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lors de la réattribution des utilisateurs placeholder, vous pouvez rencontrer les tickets suivants.

## Échec de la réattribution de l'utilisateur source {#source-user-reassignment-failed}

Pour réessayer la réattribution des utilisateurs sources ayant le statut `failed`, vous pouvez utiliser l'API GraphQL ou la console Rails. Pour plus d'informations, consultez le [ticket 589777](https://gitlab.com/gitlab-org/gitlab/-/work_items/589777). La prise en charge via l'interface utilisateur est abordée dans le [ticket 593001](https://gitlab.com/gitlab-org/gitlab/-/work_items/593001).

### Utiliser l'API GraphQL {#use-the-graphql-api}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/589777) dans GitLab 18.11.

{{< /history >}}

Utilisez la mutation `importSourceUserRetryFailedReassignment` pour relancer une réattribution ayant échoué :

```graphql
mutation {
  importSourceUserRetryFailedReassignment(input: { id: "gid://gitlab/Import::SourceUser/<SOURCE_USER_ID>" }) {
    importSourceUser {
      id
      status
    }
    errors
  }
}
```

Remplacez `<SOURCE_USER_ID>` par l'ID de l'utilisateur source d'import. Vous pouvez trouver cet ID en interrogeant `importSourceUsers` sur l'espace de nommage.

### Utiliser la console Rails {#use-the-rails-console}

Vous pouvez relancer manuellement les utilisateurs sources ayant échoué dans la [console Rails](../../../administration/operations/rails_console.md) :

```ruby
# Find by the source user's placeholder user ID because placeholder user IDs are easy to fetch from the UI
placeholder_user_id = <PLACEHOLDER_USER_ID>
import_source_user = Import::SourceUser.find_by(placeholder_user_id: placeholder_user_id)

if import_source_user.failed?
  import_source_user.update!(status: Import::SourceUser::STATUSES[:reassignment_in_progress])
  Import::ReassignPlaceholderUserRecordsWorker.perform_async(import_source_user.id)
  puts "Reassignment retry queued"
else
  puts "Import source user status: #{import_source_user.status} (expected 'failed')"
end
```

### Analyser les échecs répétés {#investigate-repeated-failures}

Si l'utilisateur source échoue à nouveau, consultez [`importer.log`](../../../administration/logs/_index.md#importerlog) pour rechercher les journaux contenant le message `Failed to reassign placeholder user` afin de commencer à identifier la cause principale.

## L'utilisateur source a été réattribué avec succès, mais son utilisateur placeholder n'a pas été supprimé {#source-user-reassigned-successfully-but-its-placeholder-user-was-not-deleted}

Les utilisateurs placeholder sont supprimés après la réattribution réussie des contributions des utilisateurs. Cependant, certains enregistrements de base de données référençant l'ID de l'utilisateur placeholder peuvent encore exister dans la base de données après la réattribution, empêchant la suppression de l'utilisateur placeholder. Lorsque cela se produit, les administrateurs peuvent encore voir les utilisateurs placeholder dans le tableau des utilisateurs administrateur. Bien que les utilisateurs placeholder ne soient pas comptabilisés dans les limites de licence et n'aient aucun effet sur les opérations GitLab habituelles, certains administrateurs peuvent préférer que tous les utilisateurs placeholder soient supprimés après la migration.

Les utilisateurs qui réattribuent des utilisateurs placeholder dans GitLab 18.5 et les versions antérieures sont plus susceptibles de rencontrer ce scénario. Lorsque cela se produit, le message `Unable to delete placeholder user because it is still referenced in other tables` apparaît dans [`importer.log`](../../../administration/logs/_index.md#importerlog) associé à l'ID de l'utilisateur placeholder.

Pour supprimer ces utilisateurs, vous pouvez :

- [Supprimer l'utilisateur placeholder en tant qu'administrateur](../../profile/account/delete_account.md#delete-users-and-user-contributions). Cette approche est recommandée lorsque vous êtes certain que les contributions restantes de l'utilisateur placeholder peuvent être supprimées.
- Mettre à niveau l'instance GitLab vers GitLab 18.6 ou une version ultérieure et relancer la réattribution du placeholder pour l'utilisateur placeholder dans la console Rails. Cette approche est recommandée lorsque la réattribution a été effectuée sur GitLab 18.5 ou une version antérieure et que vous n'êtes pas certain des contributions de l'utilisateur placeholder qui restent.

Pour relancer la réattribution d'un utilisateur placeholder dont la réattribution est terminée dans la [console Rails](../../../administration/operations/rails_console.md) :

```ruby
# Find the placeholder user's source user
placeholder_user_id = <PLACEHOLDER_USER_ID>
import_source_user = Import::SourceUser.find_by(placeholder_user_id: placeholder_user_id)

if import_source_user.completed?
  import_source_user.update!(status: Import::SourceUser::STATUSES[:reassignment_in_progress])
  Import::ReassignPlaceholderUserRecordsWorker.perform_async(import_source_user.id)
  puts "Reassignment retry queued"
else
  puts "Import source user status: #{import_source_user.status} (expected 'completed')"
end
```
