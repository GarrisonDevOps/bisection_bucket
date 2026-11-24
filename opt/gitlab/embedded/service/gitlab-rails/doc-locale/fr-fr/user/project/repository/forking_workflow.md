---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Dupliquez un dépôt Git lorsque vous souhaitez contribuer des modifications à un dépôt en amont pour lequel vous ne disposez pas des autorisations nécessaires pour contribuer directement.
title: Duplications
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Une duplication est une copie personnelle d'un autre projet, créée dans l'espace de nommage de votre choix. Votre duplication contient une copie du dépôt du projet en amont et certains paramètres du projet, mais pas le contenu du projet tel que les tickets, les merge requests ou les pages wiki. Vous pouvez créer des merge requests depuis votre duplication pour cibler le projet en amont. Des commits individuels peuvent également être [sélectionnés (cherry-picked)](../merge_requests/cherry_pick_changes.md) depuis votre duplication vers le projet en amont.

Si vous disposez d'un accès en écriture au projet d'origine, vous n'avez pas besoin d'une duplication. Utilisez plutôt des branches pour gérer votre travail. Si vous ne disposez pas d'un accès en écriture à un projet auquel vous souhaitez contribuer, dupliquez-le. Effectuez vos modifications dans votre duplication, puis soumettez-les via une merge request au projet en amont.

Pour créer une [merge request confidentielle](../merge_requests/confidential.md), utilisez une duplication personnelle d'un projet public.

> [!note]
> Si le projet en amont est archivé, la relation de bifurcation est automatiquement supprimée. Les merge requests qui ont été fermées en raison d'une relation de bifurcation rompue ne sont pas rouvertes si la relation de bifurcation est ultérieurement restaurée.
>
> Pour plus d'informations, voir [archiver un projet](../working_with_projects.md#archive-a-project).

## Créer une duplication {#create-a-fork}

Pour dupliquer un projet existant dans GitLab :

1. Sur la page d'accueil du projet, dans le coin supérieur droit, sélectionnez **Bifurcation** ({{< icon name="fork" >}}).
1. Facultatif. Modifiez le **Nom du projet**.
1. Pour **URL du projet**, sélectionnez l'[espace de nommage](../../namespace/_index.md) auquel votre duplication doit appartenir.
1. Ajoutez un **Identifiant « slug » du projet**. Cette valeur fait partie de l'URL de votre duplication. Elle doit être unique dans l'espace de nommage.
1. Facultatif. Ajoutez une **Description du projet**.
1. Sélectionnez l'une des options **Branches à inclure** :
   - **Toutes les branches** (par défaut).
   - **Uniquement la branche par défaut**. Utilise les `--single-branch` et `--no-tags` [options Git](https://git-scm.com/docs/git-clone).
1. Sélectionnez le **Niveau de visibilité** de votre duplication. La visibilité d'une duplication doit être au moins aussi restrictive que la visibilité du projet en amont et de l'espace de nommage auquel appartient votre duplication. Les autres niveaux de visibilité ne sont pas disponibles pour la sélection. Pour plus d'informations sur les niveaux de visibilité, voir [visibilité des projets et des groupes](../../public_access.md).

   > [!note]
   > Après avoir créé la duplication, si le projet en amont devient plus restrictif, la visibilité de la duplication ne change pas automatiquement. Vous pouvez la modifier vous-même, mais la même règle s'applique : la duplication doit être au moins aussi restrictive que le projet en amont.

1. Sélectionnez **Bifurcation du projet**.

GitLab crée votre duplication, vous redirige vers la page de la nouvelle duplication et consigne sa création dans le [journal d'audit](../../compliance/audit_event_types.md).

Si vous prévoyez de contribuer fréquemment des modifications en amont, envisagez de définir une [cible par défaut](../merge_requests/creating_merge_requests.md#set-the-default-target-project) pour votre duplication.

## Mettre à jour votre duplication {#update-your-fork}

Une duplication peut se désynchroniser avec son projet en amont et nécessiter une mise à jour :

- **En avance** : votre duplication contient de nouveaux commits absents du dépôt en amont. Pour synchroniser votre duplication, créez une merge request afin de transmettre vos modifications au dépôt en amont.
- **En retard** : le dépôt en amont contient de nouveaux commits absents de votre duplication. Pour synchroniser votre duplication, récupérez les nouveaux commits dans votre duplication.
- **En avance et en retard** : le dépôt en amont et votre duplication contiennent tous deux de nouveaux commits absents de l'autre. Pour synchroniser entièrement votre duplication, créez une merge request pour transmettre vos modifications en amont et récupérez les nouvelles modifications du dépôt en amont dans votre duplication.

Pour synchroniser votre duplication avec son projet en amont, mettez-la à jour depuis l'interface utilisateur de GitLab ou la ligne de commande. Les éditions GitLab Premium et Ultimate peuvent également automatiser les mises à jour en [configurant les duplications comme des miroirs pull](#with-repository-mirroring) du projet en amont.

### Depuis l'interface utilisateur {#from-the-ui}

Lorsque vous mettez à jour une duplication depuis l'interface utilisateur, les paramètres de protection du dépôt suivants sont contournés sur la duplication :

- Règles de push configurées sur la duplication.
- Verrouillage de fichiers appliqué aux fichiers de la duplication.

Ce comportement évite les échecs de synchronisation lorsque le projet en amont et la duplication ont des configurations de protection différentes. Le processus de synchronisation extrait les modifications du dépôt en amont et les applique directement à la duplication.

Prérequis :

- Vous devez créer votre duplication à partir d'une [branche non protégée](branches/protected.md) dans le projet en amont.

Pour mettre à jour votre duplication depuis l'interface utilisateur de GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**.
1. Sélectionnez **Voir tous mes projets**.
1. Sélectionnez la duplication que vous souhaitez mettre à jour.
1. Sous la liste déroulante du nom de branche, trouvez la boîte d'information **Bifurcation depuis** ({{< icon name="fork" >}}) pour déterminer si votre duplication est en avance, en retard ou les deux. Dans cet exemple, la duplication est en retard par rapport au projet en amont :

   ![Boîte d'information pour une duplication en retard de plusieurs commits par rapport au projet en amont](img/update-fork_v16_6.png)

1. Si votre duplication est **en avance** par rapport au projet en amont, sélectionnez **Créer une requête de fusion** pour proposer l'ajout des modifications de votre duplication au projet en amont.
1. Si votre duplication est **en retard** par rapport au projet en amont, sélectionnez **Mettre à jour la duplication** pour récupérer les modifications du dépôt en amont.
1. Si votre duplication est **en avance et en retard** par rapport au projet en amont, vous pouvez effectuer la mise à jour depuis l'interface utilisateur uniquement si GitLab ne détecte aucun conflit de merge :
   - Si votre duplication ne contient aucun conflit de merge, vous pouvez sélectionner **Créer une requête de fusion** pour proposer la transmission de vos modifications au projet en amont, **Mettre à jour la duplication** pour récupérer les modifications dans votre duplication, ou les deux. Le type de modifications présentes dans votre duplication détermine les actions appropriées.
   - Si votre duplication contient des conflits de merge, GitLab affiche un guide étape par étape pour mettre à jour votre duplication depuis la ligne de commande.

### Depuis la ligne de commande {#from-the-command-line}

Vous pouvez également mettre à jour votre duplication depuis la ligne de commande.

Prérequis :

- Vous devez [télécharger et installer le client Git](../../../topics/git/how_to_install_git/_index.md) sur votre machine locale.
- Vous devez [créer une duplication](#create-a-fork) du projet que vous souhaitez mettre à jour.

Pour mettre à jour votre duplication depuis la ligne de commande, suivez les instructions dans [utiliser Git pour mettre à jour une duplication](../../../topics/git/forks.md).

### Avec la mise en miroir de dépôt {#with-repository-mirroring}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Une duplication peut être configurée comme miroir du projet en amont si toutes ces conditions sont remplies :

1. Votre abonnement est GitLab Premium ou GitLab Ultimate.
1. Vous créez toutes les modifications dans des branches (pas `main`).
1. Vous ne travaillez pas sur des [merge requests pour des tickets confidentiels](../merge_requests/confidential.md), ce qui nécessite des modifications sur `main`.

La [mise en miroir de dépôt](mirror/_index.md) maintient votre duplication synchronisée avec le projet d'origine. Cette méthode met à jour votre duplication une fois par heure, sans nécessiter de `git pull` manuel. Pour obtenir des instructions, voir [configurer la mise en miroir pull](mirror/pull.md#configure-pull-mirroring).

> [!warning]
> Avec la mise en miroir, avant d'approuver une merge request, vous êtes invité à effectuer une synchronisation. Vous devriez l'automatiser.

## Fusionner les modifications vers le dépôt en amont {#merge-changes-back-upstream}

Lorsque vous êtes prêt à renvoyer votre code au projet en amont, créez une nouvelle merge request comme décrit dans [lorsque vous travaillez dans une duplication](../merge_requests/creating_merge_requests.md#when-you-work-in-a-fork). Une fois la fusion réussie, vos modifications sont ajoutées au dépôt en amont.

Une fois votre merge request fusionnée en amont, la branche de votre duplication n'est pas automatiquement considérée comme **Fusionnées** à des fins de suppression en masse. La branche n'est considérée comme fusionnée que si la branche par défaut de votre duplication contient ces modifications. Pour marquer ces branches comme fusionnées dans votre duplication, [mettez à jour votre duplication](#update-your-fork) afin de la synchroniser avec le projet en amont.

## Dissocier une duplication {#unlink-a-fork}

La suppression d'une relation de bifurcation dissocie votre duplication de son projet en amont. Votre duplication devient alors un projet indépendant.

Prérequis :

- Vous devez être propriétaire du projet pour dissocier une duplication.

> [!warning]
> Si vous supprimez une relation de bifurcation, vous ne pouvez plus envoyer de nouvelles merge requests vers la source. Toutes les merge requests ouvertes existantes de la duplication vers la source sont également fermées. Si quelqu'un a dupliqué votre projet, sa duplication perd également la relation. Pour restaurer la relation de bifurcation, utilisez l'[API Project forks](../../../api/project_forks.md#create-a-fork-relationship).

Pour supprimer une relation de bifurcation :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Paramètres avancés**.
1. Dans la section **Supprimer la relation de bifurcation**, sélectionnez **Supprimer la relation de bifurcation**.
1. Pour confirmer, saisissez le chemin du projet et sélectionnez **Confirmer**.

GitLab consigne l'opération de dissociation dans le [journal d'audit](../../compliance/audit_event_types.md). Lorsque vous dissociez une duplication qui utilise un [pool de stockage haché](../../../administration/repository_storage_paths.md#hashed-object-pools) pour partager des objets avec un autre dépôt :

- Tous les objets sont copiés depuis le pool vers votre duplication.
- Une fois le processus de copie terminé, aucune autre mise à jour du pool de stockage n'est propagée vers votre duplication.

## Supprimer une duplication {#delete-a-fork}

La suppression d'une duplication entraîne la suppression définitive du projet et de tout son contenu, y compris la relation de bifurcation. Cette action est identique à la suppression de tout autre projet.

Pour supprimer une duplication, voir [supprimer un projet](../working_with_projects.md#delete-a-project).

## Vérifier l'utilisation du stockage d'une duplication {#check-a-forks-storage-usage}

Votre duplication utilise une stratégie de déduplication pour réduire l'espace de stockage dont elle a besoin. Votre duplication peut accéder au pool d'objets connecté au projet source.

Pour plus d'informations et pour vérifier l'utilisation du stockage, voir [afficher l'utilisation du stockage de la duplication du projet](../../storage_usage_quotas.md#view-project-fork-storage-usage).

## Sujets connexes {#related-topics}

- Forum de la communauté GitLab : [Actualisation d'une duplication](https://forum.gitlab.com/t/refreshing-a-fork/32469)
- [Empêcher la duplication de projet en dehors du groupe](../../group/access_and_permissions.md#prevent-project-forking-outside-group)
- [Comprendre le fonctionnement de Git LFS avec les duplications](../../../topics/git/lfs/_index.md#understand-how-git-lfs-works-with-forks)

## Dépannage {#troubleshooting}

### Erreur : `An error occurred while forking the project. Please try again` {#error-an-error-occurred-while-forking-the-project-please-try-again}

Cette erreur peut être due à une incompatibilité dans les paramètres du runner d'instance entre le projet dupliqué et le nouvel espace de nommage. Pour plus d'informations, voir [utilisation des runners d'instance dans les projets dupliqués](../../../ci/runners/configure_runners.md#using-instance-runners-in-forked-projects).

### La suppression de la relation de bifurcation échoue {#removing-fork-relationship-fails}

Si la suppression de la duplication via l'interface utilisateur ou l'API ne fonctionne pas, vous pouvez tenter de supprimer la relation de bifurcation dans une [session de console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session) :

```ruby
p = Project.find_by_full_path('<project_path>')
u = User.find_by_username('<username>')
Projects::UnlinkForkService.new(p, u).execute
```

### Erreur : `User is not allowed to import projects` {#error-user-is-not-allowed-to-import-projects}

Lors de la duplication d'un projet à l'aide d'un compte de service, vous pourriez recevoir une erreur indiquant :

```plaintext
{"message":["Namespace is not valid","User is not allowed to import projects"]}
```

Ce problème survient car les comptes de service sont des utilisateurs bot et ne peuvent pas dupliquer des projets vers leur espace de nommage personnel, même si leur limite de projet a été augmentée.

Lors de l'utilisation d'un compte de service pour dupliquer un projet, la solution consiste à spécifier un espace de nommage de groupe cible en utilisant `namespace_id` ou `namespace_path` dans l'[API Project forks](../../../api/project_forks.md). Le compte de service doit être membre du groupe cible avec le rôle Développeur, Responsable de maintenance ou Propriétaire.
