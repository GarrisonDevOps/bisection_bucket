---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Créez des modèles pour les textes fréquemment utilisés dans les commentaires, et partagez ces modèles avec votre projet ou groupe."
title: Modèles de commentaires
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Réponses enregistrées pour les groupes :
  - [Introduite](https://gitlab.com/groups/gitlab-org/-/work_items/12669) dans GitLab 16.11 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `group_saved_replies_flag`. Fonctionnalité désactivée par défaut.
  - [Disponible généralement](https://gitlab.com/gitlab-org/gitlab/-/issues/504028) dans GitLab 17.8. Le feature flag `group_saved_replies_flag` a été supprimé.
- Réponses enregistrées pour les projets :
  - [Introduite](https://gitlab.com/groups/gitlab-org/-/work_items/12669) dans GitLab 17.0 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `project_saved_replies_flag`. Activés par défaut.
  - [Disponible généralement](https://gitlab.com/gitlab-org/gitlab/-/issues/504028) dans GitLab 17.8. Le feature flag `project_saved_replies_flag` a été supprimé.

{{< /history >}}

Avec les modèles de commentaires, créez et réutilisez du texte pour n'importe quelle zone de texte dans :

- Les merge requests, y compris les diffs.
- Les tickets, y compris les commentaires de gestion des designs.
- Epics
- Les éléments de travail.

Les modèles de commentaires peuvent être courts, comme l'approbation d'une merge request et la désassignation de celle-ci, ou longs, comme des blocs de texte standard que vous utilisez fréquemment :

![Liste déroulante des modèles de commentaires](img/group_comment_templates_v16_11.png)

## Utiliser les modèles de commentaires dans une zone de texte {#use-comment-templates-in-a-text-area}

Pour inclure le texte d'un modèle de commentaire dans votre commentaire :

1. Dans la barre d'outils de l'éditeur de votre commentaire, sélectionnez **Modèles de commentaires** ({{< icon name="comment-lines" >}}).
1. Sélectionnez le modèle de commentaire souhaité.

## Créer des modèles de commentaires {#create-comment-templates}

Vous pouvez créer des modèles de commentaires pour votre propre usage, ou à partager avec tous les membres d'un groupe.

Pour créer un modèle de commentaire pour votre propre usage :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Dans la liste déroulante, sélectionnez **Préférences**.
1. Dans la barre latérale gauche, sélectionnez **Modèles de commentaires** ({{< icon name="comment-lines" >}}).
1. Sélectionnez **Ajouter nouveau**.
1. Indiquez un **Nom** pour votre modèle de commentaire.
1. Saisissez le **Contenu** de votre réponse. Vous pouvez utiliser n'importe quelle mise en forme utilisée dans les autres zones de texte GitLab.
1. Sélectionnez **Sauvegarder**, et la page se recharge en affichant votre modèle de commentaire.

### Pour un groupe {#for-a-group}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

Pour créer un modèle de commentaire partagé avec tous les membres d'un groupe :

1. Dans la barre d'outils de l'éditeur d'un commentaire, sélectionnez **Modèles de commentaires** ({{< icon name="comment-lines" >}}), puis sélectionnez **Gérer les modèles de commentaires du groupe**.
1. Sélectionnez **Ajouter nouveau**.
1. Indiquez un **Nom** pour votre modèle de commentaire.
1. Saisissez le **Contenu** de votre réponse. Vous pouvez utiliser n'importe quelle mise en forme utilisée dans les autres zones de texte GitLab.
1. Sélectionnez **Sauvegarder**, et la page se recharge en affichant votre modèle de commentaire.

### Pour un projet {#for-a-project}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

Pour créer un modèle de commentaire partagé avec tous les membres d'un projet :

1. Dans la barre d'outils de l'éditeur d'un commentaire, sélectionnez **Modèles de commentaires** ({{< icon name="comment-lines" >}}), puis sélectionnez **Gérer les modèles de commentaires du projet**.
1. Sélectionnez **Ajouter nouveau**.
1. Indiquez un **Nom** pour votre modèle de commentaire.
1. Saisissez le **Contenu** de votre réponse. Vous pouvez utiliser n'importe quelle mise en forme utilisée dans les autres zones de texte GitLab.
1. Sélectionnez **Sauvegarder**, et la page se recharge en affichant votre modèle de commentaire.

## Afficher les modèles de commentaires {#view-comment-templates}

Pour consulter les modèles de commentaires existants :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Dans la liste déroulante, sélectionnez **Préférences**.
1. Dans la barre latérale gauche, sélectionnez **Modèles de commentaires** ({{< icon name="comment-lines" >}}).
1. Faites défiler jusqu'à **Modèles de commentaires**.

### Pour un groupe {#for-a-group-1}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

1. Dans la barre d'outils de l'éditeur d'un commentaire, sélectionnez **Modèles de commentaires** ({{< icon name="comment-lines" >}}).
1. Sélectionnez **Gérer les modèles de commentaires du groupe**.

### Pour un projet {#for-a-project-1}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

1. Dans la barre d'outils de l'éditeur d'un commentaire, sélectionnez **Modèles de commentaires** ({{< icon name="comment-lines" >}}).
1. Sélectionnez **Gérer les modèles de commentaires du projet**.

## Modifier ou supprimer des modèles de commentaires {#edit-or-delete-comment-templates}

Pour modifier ou supprimer un modèle de commentaire existant :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Dans la liste déroulante, sélectionnez **Préférences**.
1. Dans la barre latérale gauche, sélectionnez **Modèles de commentaires** ({{< icon name="comment-lines" >}}).
1. Faites défiler jusqu'à **Modèles de commentaires** et identifiez le modèle de commentaire que vous souhaitez modifier.
1. Pour modifier, sélectionnez **Modifier** ({{< icon name="pencil" >}}).
1. Pour supprimer, sélectionnez **Supprimer** ({{< icon name="remove" >}}), puis sélectionnez à nouveau **Supprimer** dans la boîte de dialogue.

### Pour un groupe {#for-a-group-2}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

1. Dans la barre d'outils de l'éditeur d'un commentaire, sélectionnez **Modèles de commentaires** ({{< icon name="comment-lines" >}}), puis sélectionnez **Gérer les modèles de commentaires du groupe**.
1. Pour modifier, sélectionnez **Modifier** ({{< icon name="pencil" >}}).
1. Pour supprimer, sélectionnez **Supprimer** ({{< icon name="remove" >}}), puis sélectionnez à nouveau **Supprimer** dans la boîte de dialogue.

### Pour un projet {#for-a-project-2}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

1. Dans la barre d'outils de l'éditeur d'un commentaire, sélectionnez **Modèles de commentaires** ({{< icon name="comment-lines" >}}), puis sélectionnez **Gérer les modèles de commentaires du projet**.
1. Pour modifier, sélectionnez **Modifier** ({{< icon name="pencil" >}}).
1. Pour supprimer, sélectionnez **Supprimer** ({{< icon name="remove" >}}), puis sélectionnez à nouveau **Supprimer** dans la boîte de dialogue.
