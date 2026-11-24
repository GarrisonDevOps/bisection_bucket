---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Opérations Git avancées
description: "Rebase, cherry-pick, annulation de modifications, dépôt et gestion de fichiers."
---

Les opérations Git avancées vous aident à effectuer des tâches de maintenance et de gestion de votre code. Ce sont des actions plus complexes qui vont au-delà des [opérations Git de base](basics.md). Ces opérations vous permettent de :

- Réécrire l'historique des commits.
- Annuler et défaire des modifications.
- Gérer les connexions aux dépôts distants.

Elles vous offrent les avantages suivants :

- Qualité du code : maintenir un historique de projet propre et linéaire.
- Résolution de problèmes : fournir des outils pour corriger des erreurs ou ajuster l'état de votre dépôt.
- Optimisation des workflows : simplifier les processus de développement complexes.
- Collaboration : faciliter un travail d'équipe plus fluide dans les projets de grande envergure ou complexes.

Pour utiliser efficacement les opérations Git, il est important de comprendre les concepts clés tels que les dépôts, les branches, les commits et les merge requests. Pour plus d'informations, consultez [Premiers pas avec Git](get_started.md).

## Bonnes pratiques {#best-practices}

Lorsque vous utilisez des opérations Git avancées, vous devriez :

- Créer une sauvegarde ou travailler sur une [branche distincte](branch.md).
- Communiquer avec votre équipe avant d'utiliser des opérations qui affectent l'historique des branches partagées.
- Utiliser des [messages de commit](../../tutorials/update_commit_messages/_index.md) descriptifs lorsque vous réécrivez l'historique.
- Mettre à jour vos connaissances de Git pour rester à jour avec les bonnes pratiques et les nouvelles fonctionnalités. Pour plus d'informations, consultez la [documentation Git](https://git-scm.com/docs).
- Pratiquer les opérations avancées dans un dépôt de test.

## Rebase et résolution des conflits {#rebase-and-resolve-conflicts}

La commande `git rebase` met à jour votre branche avec le contenu d'une autre branche. Elle confirme que les modifications de votre branche n'entrent pas en conflit avec les modifications de la branche cible. Si vous avez un [conflit de merge](../../user/project/merge_requests/conflicts.md), vous pouvez effectuer un rebase pour le corriger.

Pour plus d'informations, consultez [rebase pour résoudre les conflits de merge](git_rebase.md).

## Cherry-pick de modifications {#cherry-pick-changes}

La commande `git cherry-pick` applique des commits spécifiques d'une branche à une autre. Utilisez-la pour :

- Rétroporter des correctifs de bugs de la branche par défaut vers les branches de release précédentes.
- Copier des modifications d'une duplication vers le dépôt en amont.
- Appliquer des modifications spécifiques sans fusionner des branches entières.

Pour plus d'informations, consultez [cherry-pick de modifications avec Git](cherry_pick.md).

## Annulation de modifications {#revert-and-undo-changes}

Les commandes Git suivantes vous permettent d'annuler et de défaire des modifications :

- `git revert` : crée un nouveau commit qui annule les modifications effectuées dans un commit précédent. Cette commande vous aide à annuler une erreur ou une modification dont vous n'avez plus besoin. Utilisez `git revert` lorsque le commit a déjà été poussé et partagé avec d'autres personnes. Cette commande préserve l'historique des commits existant, ce qui la rend adaptée aux branches partagées.
- `git reset` : réinitialise et annule les modifications qui n'ont pas encore été commitées. Utilisez `git reset` pour les modifications locales qui n'ont pas été poussées vers une branche partagée. Cette commande peut réécrire l'historique des commits.
- `git restore` : restaure les modifications perdues ou supprimées.

Pour plus d'informations, consultez [annuler des modifications](undo.md).

## Réduire la taille du dépôt {#reduce-repository-size}

La taille d'un dépôt Git peut avoir un impact sur les performances et les coûts de stockage. Elle peut légèrement différer d'une instance à l'autre en raison de la compression, de la maintenance et d'autres facteurs. Pour plus d'informations sur la taille du dépôt, consultez [taille du dépôt](../../user/project/repository/repository_size.md).

Vous pouvez utiliser Git pour purger des fichiers de l'historique de votre dépôt et réduire sa taille. Pour plus d'informations, consultez [réduire la taille du dépôt](repository.md).

## Gestion des fichiers {#file-management}

Vous pouvez utiliser Git pour gérer les fichiers de votre dépôt. Cette commande vous aide à suivre les modifications, à collaborer avec d'autres personnes et à gérer les fichiers volumineux. Les options suivantes sont disponibles :

- `git log` : afficher les modifications apportées aux fichiers de votre dépôt.
- `git blame` : identifier qui a modifié en dernier une ligne de code dans un fichier.
- `git lfs` : gérer, suivre et verrouiller les fichiers de votre dépôt.

Pour plus d'informations, consultez [gestion des fichiers](file_management.md).

## Mettre à jour les URL distantes Git {#update-git-remote-urls}

La commande `git remote set-url` met à jour l'URL du dépôt distant. Utilisez cette commande dans les cas suivants :

- Vous avez importé un projet existant depuis un autre hôte de dépôt Git.
- Votre organisation a déplacé vos projets vers une nouvelle instance GitLab avec un nouveau nom de domaine.
- Le projet a été renommé avec un nouveau chemin dans la même instance GitLab.

Pour plus d'informations, consultez [mettre à jour les URL distantes Git](../../tutorials/update_git_remote_url/_index.md).

## Sujets connexes {#related-topics}

- [Prise en main](get_started.md)
- [Opérations Git de base](basics.md)
- [Commandes Git courantes](commands.md)
