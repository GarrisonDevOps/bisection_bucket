---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Supprimer des comptes utilisateur et gérer les enregistrements et contributions associés.
title: Supprimer des utilisateurs
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les utilisateurs peuvent être supprimés d'une instance GitLab, soit par :

- L'utilisateur lui-même.
- Un administrateur.

> [!note]
> La suppression d'un utilisateur supprime tous les projets dans l'espace de nommage de cet utilisateur.

## Supprimer votre propre compte {#delete-your-own-account}

{{< details >}}

- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- Le délai entre la suppression de son propre compte par un utilisateur et la suppression de l'enregistrement utilisateur a été introduit dans GitLab 16.0 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `delay_delete_own_user`. Activé par défaut sur GitLab.com.

{{< /history >}}

> [!note]
> Sur GitLab Self-Managed, cette fonctionnalité est désactivée par défaut. Utilisez l'[API des paramètres d'application](../../../api/settings.md) pour activer le paramètre `delay_user_account_self_deletion` pour l'instance.

Vous pouvez planifier la suppression de votre compte. Lorsque vous supprimez votre compte, celui-ci entre dans un état de suppression en attente. En général, les suppressions s'effectuent en une à deux heures, mais peuvent prendre jusqu'à sept jours pour les comptes associés à des commentaires, tickets, merge requests, notes ou extraits de code.

Pendant que votre compte est en attente de suppression :

- Votre compte est [bloqué](../../../administration/moderate_users.md#block-a-user).
- Vous ne pouvez pas créer un nouveau compte avec le même nom d'utilisateur.
- Vous ne pouvez pas créer un nouveau compte avec la même adresse e-mail principale, sauf si vous modifiez d'abord l'adresse e-mail.

> [!note]
> Une fois le compte supprimé, n'importe quel utilisateur peut créer un compte avec le même nom d'utilisateur. Si un autre utilisateur prend ce nom d'utilisateur, vous ne pouvez pas le récupérer.

Pour supprimer votre propre compte :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Compte**.
1. Sélectionnez **Supprimer le compte**.

Si vous ne pouvez pas supprimer votre compte sur GitLab.com, soumettez une [demande de données personnelles](https://support.gitlab.io/personal-data-request/) pour supprimer votre compte et vos données de GitLab.

## Supprimer des utilisateurs et leurs contributions {#delete-users-and-user-contributions}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Prérequis :

- Vous devez être administrateur de l'instance.

Pour supprimer un utilisateur :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Vue d'ensemble** > **Utilisateurs**.
1. Sélectionnez un utilisateur.
1. Sous l'onglet **Compte**, sélectionnez :
   - **Supprimer l'utilisateur** pour supprimer uniquement l'utilisateur tout en conservant ses [enregistrements associés](#associated-records). Vous ne pouvez pas utiliser cette option si l'utilisateur sélectionné est le seul propriétaire de groupes.
   - **Supprimer l'utilisateur et ses contributions** pour supprimer l'utilisateur et ses enregistrements associés. Cette option supprime également tous les groupes (et les projets au sein de ces groupes) dont l'utilisateur est le seul propriétaire direct. La propriété héritée ne s'applique pas.

> [!warning]
> L'utilisation de l'option **Supprimer l'utilisateur et ses contributions** peut entraîner la suppression de plus de données que prévu. Consultez les [enregistrements associés](#associated-records) pour plus de détails.

### Enregistrements associés {#associated-records}

Lors de la suppression d'utilisateurs, vous pouvez soit :

- Supprimer uniquement l'utilisateur, mais déplacer les contributions vers un utilisateur fantôme :
  - Cet utilisateur interne sert de conteneur pour toutes les contributions des utilisateurs supprimés.
  - Sur GitLab.com, cet utilisateur est appelé Ghost User (`@ghost1`).
  - Le profil et les projets personnels de l'utilisateur sont supprimés, au lieu d'être transférés à l'utilisateur fantôme.
- Supprimer l'utilisateur et ses contributions, notamment :
  - Signalements d'abus.
  - Réactions emoji.
  - Les groupes dont l'utilisateur est le seul utilisateur ayant le rôle Propriétaire.
  - Jetons d'accès personnels.
  - Epics
  - Tickets
  - Merge requests
  - Extraits de code.
  - [Notes et commentaires](../../../api/notes.md) sur les [commits](../../project/repository/_index.md#commit-changes-to-a-repository), [epics](../../group/epics/_index.md), [tickets](../../project/issues/_index.md), [merge requests](../../project/merge_requests/_index.md) et [extraits de code](../../snippets.md) d'autres utilisateurs.

Dans les deux cas, les commits conservent les [informations utilisateur](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects#_git_commit_objects) et donc l'intégrité des données au sein d'un [dépôt Git](../../project/repository/_index.md).

Une alternative à la suppression est de [bloquer un utilisateur](../../../administration/moderate_users.md#block-a-user).

Lorsqu'un utilisateur est supprimé à partir d'un [signalement d'abus](../../../administration/review_abuse_reports.md) ou d'un journal de spam, ces enregistrements associés sont toujours supprimés.

L'option de suppression des enregistrements associés peut être demandée via l'[API](../../../api/users.md#delete-a-user) ainsi que depuis la zone **Admin**.

> [!warning]
> Les approbations utilisateur sont associées à un identifiant utilisateur. Les autres contributions des utilisateurs ne sont pas associées à un identifiant utilisateur. Lorsque vous supprimez un utilisateur et que ses contributions sont transférées à un utilisateur fantôme, les contributions d'approbation font référence à un identifiant utilisateur manquant ou non valide. Plutôt que de supprimer des utilisateurs, envisagez de les [bloquer](../../../administration/moderate_users.md#block-a-user), de les [bannir](../../../administration/moderate_users.md#ban-a-user) ou de les [désactiver](../../../administration/moderate_users.md#deactivate-a-user).

## Supprimer le compte root sur une instance GitLab Self-Managed {#delete-the-root-account-on-a-gitlab-self-managed-instance}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

> [!warning]
> Le compte root est le compte le plus privilégié du système. La suppression du compte root peut entraîner la perte d'accès à la [zone **Admin**](../../../administration/admin_area.md) de l'instance si aucun autre administrateur n'est disponible sur l'instance.

Vous pouvez supprimer le compte root en utilisant l'interface utilisateur ou la [console Rails de GitLab](../../../administration/operations/rails_console.md).

Avant de supprimer le compte root :

1. Si vous avez créé des [jetons d'accès de projet](../../project/settings/project_access_tokens.md) ou des [jetons d'accès personnels](../personal_access_tokens.md) pour le compte root et que vous les utilisez dans votre workflow, transférez les autorisations ou la propriété nécessaires du compte root vers le nouvel administrateur.
1. [Sauvegardez votre instance GitLab Self-Managed](../../../administration/backup_restore/backup_gitlab.md).
1. Envisagez plutôt de [désactiver](../../../administration/moderate_users.md#deactivate-a-user) ou de [bloquer](../../../administration/moderate_users.md#block-and-unblock-users) le compte root.

### Utiliser l'interface utilisateur {#use-the-ui}

Prérequis :

- Vous devez être administrateur de l'instance GitLab Self-Managed.

Pour supprimer le compte root :

1. Dans la zone **Admin**, [créez un nouvel utilisateur avec un accès administrateur](create_accounts.md#create-a-user-in-the-admin-area). Cela garantit que vous conservez l'accès administrateur à l'instance tout en atténuant les risques associés à la suppression du compte root.
1. [Supprimez le compte root](#delete-users-and-user-contributions).

### Utiliser la console Rails de GitLab {#use-the-gitlab-rails-console}

> [!warning]
> Les commandes qui modifient des données peuvent causer des dommages si elles ne sont pas exécutées correctement ou dans les bonnes conditions. Exécutez toujours les commandes dans un environnement de test d'abord et disposez d'une instance de sauvegarde prête à être restaurée.

Prérequis :

- Vous devez avoir accès à la console Rails de GitLab.

Pour supprimer le compte root, dans la console Rails :

1. Accordez l'accès administrateur à un autre utilisateur existant :

   ```ruby
   user = User.find(username: 'Username') # or use User.find_by(email: 'email@example.com') to find by email
   user.admin = true
   user.save!
   ```

   Cela garantit que vous conservez l'accès administrateur à l'instance tout en atténuant les risques associés à la suppression du compte root.

1. Pour supprimer le compte root, effectuez l'une des opérations suivantes :

   - Bloquer le compte root :

     ```ruby
     # This needs to be a current admin user
     current_user = User.find(username: 'Username')

     # This is the root user to block
     user = User.find(username: 'Username')

     ::Users::BlockService.new(current_user).execute(user)
     ```

   - Désactiver l'utilisateur root :

     ```ruby
     # This needs to be a current admin user
     current_user = User.find(username: 'Username')

     # This is the root user to deactivate
     user = User.find(username: 'Username')

     ::Users::DeactivateService.new(current_user, skip_authorization: true).execute(user)
     ```
