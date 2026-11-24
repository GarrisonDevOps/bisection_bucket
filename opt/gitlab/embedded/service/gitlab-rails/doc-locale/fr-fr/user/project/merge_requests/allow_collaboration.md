---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Lorsque vous dupliquez une merge request, vous pouvez définir si les membres du dépôt en amont peuvent contribuer ou non à votre duplication."
title: Collaborer sur des merge requests entre duplications
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lorsque vous ouvrez une merge request depuis votre [duplication](../repository/forking_workflow.md), vous pouvez autoriser les membres en amont à collaborer avec vous sur votre branche. Lorsque vous activez cette option, les membres disposant de l'autorisation de fusionner vers la branche cible obtiennent l'autorisation d'écrire dans la branche source de la merge request.

Les membres du projet en amont peuvent alors apporter de petites corrections ou rebaser des branches avant la fusion.

Cette fonctionnalité est disponible pour les merge requests entre projets dupliqués qui sont [accessibles publiquement](../../public_access.md).

## Autoriser les commits des membres en amont {#allow-commits-from-upstream-members}

En tant qu'auteur d'une merge request, vous pouvez autoriser les modifications de commit de la part des membres en amont du projet auquel vous contribuez :

1. Lors de la création ou de la modification d'une merge request, faites défiler jusqu'à **Contribution** et cochez la case **Allow commits from members who can merge to the target branch**.
1. Terminez la création de votre merge request.

Une fois la merge request créée, le widget de merge request affiche le message **Members who can merge are allowed to add commits**. Les membres en amont peuvent alors :

- Effectuer des commits directement dans votre branche.
- Relancer les pipelines et les jobs de la merge request.

## Empêcher les commits des membres en amont {#prevent-commits-from-upstream-members}

En tant qu'auteur d'une merge request, vous pouvez empêcher les modifications de commit de la part des membres en amont du projet auquel vous contribuez :

1. Lors de la création ou de la modification d'une merge request, faites défiler jusqu'à **Contribution** et décochez la case **Allow commits from members who can merge to the target branch**.
1. Terminez la création de votre merge request.

## Pousser vers la duplication en tant que membre en amont {#push-to-the-fork-as-the-upstream-member}

Vous pouvez pousser directement vers la branche du dépôt dupliqué si :

- L'auteur de la merge request a activé les contributions des membres en amont.
- Vous disposez du rôle Developer, Maintainer ou Owner pour le projet en amont.

Pour pousser des modifications ou ajouter un commit vers la branche d'une duplication, vous pouvez utiliser Git en ligne de commande. Pour plus d'informations, consultez [utiliser Git pour pousser vers une duplication en tant que membre en amont](../../../topics/git/forks.md#push-to-a-fork-as-an-upstream-member).

## Dépannage {#troubleshooting}

### Statut du pipeline indisponible depuis la page MR d'un projet dupliqué {#pipeline-status-unavailable-from-mr-page-of-forked-project}

Lorsqu'un utilisateur duplique un projet, les permissions de la copie dupliquée ne sont pas copiées depuis le projet d'origine. Le créateur de la duplication doit accorder des permissions à la copie dupliquée avant que les membres du projet en amont puissent consulter ou fusionner les modifications de la merge request.

Pour consulter le statut du pipeline depuis la page de merge request d'un projet dupliqué en revenant au projet d'origine :

1. [Créez un groupe](../../group/_index.md#create-a-group) contenant tous les membres en amont.
1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet dupliqué.
1. Accédez à la page **Gérer** > **Membres** dans le projet dupliqué et invitez le groupe nouvellement créé dans le projet dupliqué.
