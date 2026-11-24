---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Créez, modifiez et gérez les wikis de groupe pour partager la documentation entre tous les projets d'un groupe."
title: Wikis de groupe
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si vous utilisez des groupes GitLab pour gérer plusieurs projets, une partie de votre documentation peut s'étendre sur plusieurs groupes. Vous pouvez créer des wikis de groupe, au lieu de [wikis de projet](_index.md), pour vous assurer que tous les membres du groupe disposent des autorisations d'accès correctes pour contribuer. Les wikis de groupe sont similaires aux [wikis de projet](_index.md), avec quelques limitations :

- [Git LFS](../../../topics/git/lfs/_index.md) n'est pas pris en charge.
- Les modifications apportées aux wikis de groupe n'apparaissent pas dans le [fil d'activité du groupe](../../group/manage.md#group-activity-analytics).

Pour les mises à jour, suivez [l'epic qui suit la parité des fonctionnalités avec les wikis de projet](https://gitlab.com/groups/gitlab-org/-/work_items/2782).

Comme pour les wikis de projet, les membres du groupe ayant le rôle Developer, Maintainer ou Owner peuvent modifier les wikis de groupe. Les dépôts de wikis de groupe peuvent être déplacés à l'aide de l'[API de déplacement de stockage de dépôts de groupe](../../../api/group_repository_storage_moves.md).

## Afficher un wiki de groupe {#view-a-group-wiki}

Pour accéder à un wiki de groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Planification** > **Wiki**.

## Exporter un wiki de groupe {#export-a-group-wiki}

Les utilisateurs ayant le rôle Owner dans un groupe peuvent [importer ou exporter un wiki de groupe](../settings/import_export.md#migrate-groups-by-uploading-an-export-file-deprecated) lorsqu'ils importent ou exportent un groupe.

Le contenu créé dans un wiki de groupe n'est pas supprimé lorsqu'un compte est rétrogradé ou qu'un essai GitLab se termine. Les données du wiki de groupe sont exportées chaque fois que le propriétaire du groupe du wiki est exporté.

Pour accéder aux données du wiki de groupe depuis le fichier d'exportation si la fonctionnalité n'est plus disponible, vous devez :

1. Extrayez le [fichier tarball d'exportation](../settings/import_export.md#migrate-groups-by-uploading-an-export-file-deprecated) avec cette commande, en remplaçant `FILENAME` par le nom de votre fichier : `tar -xvzf FILENAME.tar.gz`
1. Accédez au répertoire `repositories`. Ce répertoire contient un [bundle Git](https://git-scm.com/docs/git-bundle) avec l'extension `.wiki.bundle`.
1. Clonez le bundle Git dans un nouveau dépôt, en remplaçant `FILENAME` par le nom de votre bundle : `git clone FILENAME.wiki.bundle`

Tous les fichiers du wiki sont disponibles dans ce dépôt Git.

## Configurer la visibilité du wiki de groupe {#configure-group-wiki-visibility}

Les wikis sont activés par défaut dans GitLab. Les [administrateurs](../../permissions.md) de groupe peuvent activer ou désactiver un wiki de groupe via les paramètres du groupe.

Pour ouvrir les paramètres du groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**.
1. Développez **Permissions et fonctionnalités du groupe**.
1. Faites défiler jusqu'à **Wiki** et sélectionnez l'une de ces options :
   - **Activé** : pour les groupes publics, tout le monde peut accéder au wiki. Pour les groupes internes, seuls les utilisateurs authentifiés peuvent accéder au wiki.
   - **Privé** : seuls les membres du groupe peuvent accéder au wiki.
   - **Désactivé** : le wiki n'est pas accessible et ne peut pas être téléchargé.
1. Sélectionnez **Enregistrer les modifications**.

## Supprimer le contenu d'un wiki de groupe {#delete-the-contents-of-a-group-wiki}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> Cette opération supprime toutes les données du wiki.

Vous pouvez supprimer le contenu d'un wiki de groupe avec la console Rails. Vous pouvez ensuite alimenter le wiki avec un nouveau contenu.

> [!warning]
> Cette commande modifie les données directement et peut être dangereuse si elle n'est pas exécutée correctement. Vous devriez d'abord exécuter ces instructions dans un environnement de test. Gardez une sauvegarde de l'instance prête afin de pouvoir restaurer l'instance si nécessaire.

Prérequis :

- Vous devez être administrateur.

Pour supprimer toutes les données d'un wiki de groupe et le recréer dans un état vierge :

1. Démarrez une [session de console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session).
1. Exécutez ces commandes :

   ```ruby
   # Enter your group's path
   g = Group.find_by_full_path('<group-name>')

   # This command deletes the wiki group from the filesystem.
   g.wiki.repository.remove

   # Refresh the wiki repository state.
   g.wiki.repository.expire_exists_cache
   ```

Toutes les données du wiki ont été effacées et le wiki est prêt à être utilisé.

## Sujets connexes {#related-topics}

- [Paramètres des wikis pour les administrateurs](../../../administration/wikis/_index.md)
- [API des wikis de projet](../../../api/wikis.md)
- [API des déplacements du stockage des dépôts de groupe](../../../api/group_repository_storage_moves.md)
- [API des wikis de groupe](../../../api/group_wikis.md)
- [Raccourcis clavier du wiki](../../shortcuts.md#wiki-pages)
- [Epic : parité des fonctionnalités avec les wikis de projet](https://gitlab.com/groups/gitlab-org/-/work_items/2782)
