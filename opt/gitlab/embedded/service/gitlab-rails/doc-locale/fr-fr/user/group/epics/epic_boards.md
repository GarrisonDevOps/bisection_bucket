---
stage: Plan
group: Portfolio Planning
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Gérez et visualisez les épics de groupe dans GitLab avec les tableaux d'épopées. Créez, organisez, filtrez et suivez la progression à l'aide de labels et de poids."
title: "Tableaux d'épopées"
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) du rôle utilisateur minimum, passant de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Les tableaux d'épopées s'appuient sur la [fonctionnalité de suivi des épics](_index.md) existante et les [labels](../../project/labels.md). Vos épics apparaissent sous forme de cartes dans des listes verticales, organisées par labels assignés.

En haut de chaque liste, vous pouvez voir le nombre d'épics dans la liste ({{< icon name="work-item-epic" >}}) et le poids total de tous ses épics ({{< icon name="weight" >}}).

<div class="video-fallback">
  Voir la vidéo : <a href="https://www.youtube.com/watch?v=eQUnHwbKEkY">Épics et tableaux des tickets - Gestion de projet</a>.
</div>
<figure class="video-container">
  <iframe src="https://www.youtube-nocookie.com/embed/eQUnHwbKEkY" frameborder="0" allowfullscreen> </iframe>
</figure>

Pour afficher un tableau d'épopées :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Tableaux d'épopées**.

![Un tableau d'épopées affichant des épics dans des listes.](img/epic_board_v15_10.png)

## Créer un tableau d'épopées {#create-an-epic-board}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.

Pour créer un nouveau tableau d'épopées :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Tableaux d'épopées**.
1. Dans le coin supérieur gauche, sélectionnez la liste déroulante avec le nom du tableau actuel.
1. Sélectionnez **Créer un nouveau tableau**.
1. Saisissez le titre du nouveau tableau.
1. Facultatif. Pour masquer les listes Ouvert ou Fermé, décochez les cases **Afficher la liste des tickets ouverts** et **Afficher la liste des tickets fermés**.
1. Facultatif. Définir la portée du tableau :
   1. À côté de **Portée**, sélectionnez **Étendre**.
   1. À côté de **Labels**, sélectionnez **Modifier** et choisissez les labels à utiliser comme portée du tableau.
1. Sélectionnez **Créer un tableau**.

Vous pouvez maintenant [ajouter des listes](#create-a-new-list). Pour modifier ces options ultérieurement, [modifiez le tableau](#edit-the-scope-of-an-epic-board).

## Supprimer un tableau d'épopées {#delete-an-epic-board}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.
- Un minimum de deux tableaux doit être présent dans un groupe.

Pour supprimer le tableau d'épopées actif :

1. Dans le coin supérieur gauche de la page du tableau d'épopées, sélectionnez la liste déroulante.
1. Sélectionnez **Supprimer le tableau**.
1. Sélectionnez **Supprimer**.

## Actions réalisables sur un tableau d'épopées {#actions-you-can-take-on-an-epic-board}

- [Créer une nouvelle liste](#create-a-new-list).
- [Supprimer une liste existante](#remove-a-list).
- [Filtrer les épics](#filter-epics).
- Créer des workflows, comme lors de l'utilisation des [tableaux des tickets](../../../tutorials/plan_and_track.md).
- [Déplacer les épics et les listes](#move-epics-and-lists).
- Modifier les labels d'un epic (en faisant glisser un epic entre les listes).
- Fermer un epic (en le faisant glisser vers la liste **Fermé**).
- [Modifier la portée d'un tableau](#edit-the-scope-of-an-epic-board).

### Créer une nouvelle liste {#create-a-new-list}

{{< history >}}

- La création d'une liste entre des listes existantes a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/462515) dans GitLab 17.5.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.

Pour créer une nouvelle liste :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Tableaux d'épopées**.
1. Dans le coin supérieur droit, sélectionnez **Nouvelle liste**.
1. Survolez avec la souris ou déplacez le focus du clavier entre deux listes.
1. Sélectionnez **Nouvelle liste**. Le panneau de la nouvelle liste s'ouvre.

   ![Le panneau de la nouvelle liste inséré entre deux listes existantes.](img/issue_board_add_list_between_lists_v17_6.png)
1. Dans la colonne **Nouvelle liste**, développez la liste déroulante **Sélectionnez un label** et choisissez le label à utiliser comme portée de la liste.
1. Sélectionnez **Ajouter au tableau**.

La nouvelle liste est insérée à la même position sur le tableau que le panneau de la nouvelle liste.

Pour déplacer et réorganiser les listes, faites-les glisser.

Vous pouvez également sélectionner **Nouvelle liste** à l'extrémité droite du tableau. La nouvelle liste est insérée à l'extrémité droite des listes, avant **Fermé**.

### Supprimer une liste {#remove-a-list}

La suppression d'une liste n'a aucun effet sur les épics et les labels, car seule la vue de la liste est supprimée. Vous pouvez toujours la recréer ultérieurement si nécessaire.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.

Pour supprimer une liste d'un tableau d'épopées :

1. En haut de la liste que vous souhaitez supprimer, sélectionnez l'icône **Paramètres de la liste** ({{< icon name="settings" >}}). La barre latérale des paramètres de la liste s'ouvre à droite.
1. Sélectionnez **Supprimer la liste**.
1. Dans la boîte de dialogue de confirmation, sélectionnez **OK**.

### Créer un epic depuis un tableau d'épopées {#create-an-epic-from-an-epic-board}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.
- Vous devez d'abord avoir [créé une liste](#create-a-new-list).

Pour créer un epic depuis une liste dans un tableau d'épopées :

1. En haut d'une liste, sélectionnez l'icône **Nouvelle épopée** ({{< icon name="plus" >}}).
1. Saisissez le titre du nouvel epic.
1. Sélectionnez **Créer une épopée**.

![Le formulaire intégré utilisé pour créer un nouvel epic dans une liste de tableau.](img/epic_board_epic_create_v15_10.png)

### Modifier un epic {#edit-an-epic}

Lorsque vous sélectionnez une carte d'epic dans le tableau d'épopées, l'[epic s'ouvre dans un panneau latéral](manage_epics.md#open-epics-in-a-drawer). Vous pouvez y modifier tous les champs, y compris la description, les commentaires ou les éléments associés.

### Filtrer les épics {#filter-epics}

Utilisez les filtres en haut de votre tableau d'épopées pour afficher uniquement les résultats souhaités. Le filtrage est similaire à celui utilisé dans la liste des épics, car les métadonnées des épics et des labels sont réutilisées dans le tableau d'épopées.

Vous pouvez filtrer par les critères suivants :

- Auteur
- Label

### Afficher le nombre d'éléments de travail, le poids et la progression d'un epic {#view-count-of-work-items-weight-and-progress-of-an-epic}

Les épics d'un tableau d'épopées affichent un résumé de leurs éléments de travail, de leur poids et de leur progression. Pour voir le nombre d'éléments de travail ouverts et fermés, ainsi que le poids complété et incomplet, survolez l'icône des éléments de travail {{< icon name="work-items" >}}, l'icône de poids {{< icon name="weight" >}} ou l'icône de progression {{< icon name="progress" >}}.

### Déplacer les épics et les listes {#move-epics-and-lists}

Vous pouvez déplacer les épics et les listes en les faisant glisser.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.

Pour déplacer un epic, sélectionnez la carte de l'epic et faites-la glisser vers une autre position dans sa liste actuelle ou dans une autre liste. Découvrez les effets possibles dans [Faire glisser des épics entre des listes](#dragging-epics-between-lists).

Pour déplacer une liste, sélectionnez sa barre supérieure et faites-la glisser horizontalement. Vous ne pouvez pas déplacer les listes **Ouvrir** et **Fermé**, mais vous pouvez les masquer lors de la modification d'un tableau d'épopées.

#### Déplacer un epic au début de la liste {#move-an-epic-to-the-start-of-the-list}

Lorsque vous avez de nombreux épics, il est peu pratique de faire glisser manuellement un epic du bas d'une liste de tableau jusqu'en haut. Vous pouvez déplacer les épics en haut de la liste à l'aide d'un raccourci de menu.

Votre epic est déplacé en haut de la liste, même si d'autres épics sont masqués par un filtre.

Prérequis :

- Vous devez au moins disposer du rôle Planificateur pour un groupe.

Pour déplacer un epic au début de la liste :

1. Dans un tableau d'épopées, survolez la carte de l'epic que vous souhaitez déplacer.
1. Sélectionnez **Options de la carte** ({{< icon name="ellipsis_v" >}}), puis **Déplacer en début de liste**.

#### Déplacer un epic à la fin de la liste {#move-an-epic-to-the-end-of-the-list}

Lorsque vous avez de nombreux épics, il est peu pratique de faire glisser manuellement un epic du haut d'une liste de tableau jusqu'en bas. Vous pouvez déplacer les épics en bas de la liste à l'aide d'un raccourci de menu.

Votre epic est déplacé en bas de la liste, même si d'autres épics sont masqués par un filtre.

Prérequis :

- Vous devez au moins disposer du rôle Planificateur pour un groupe.

Pour déplacer un epic à la fin de la liste :

1. Dans un tableau d'épopées, survolez la carte de l'epic que vous souhaitez déplacer.
1. Sélectionnez **Options de la carte** ({{< icon name="ellipsis_v" >}}), puis **Déplacer en fin de liste**.

#### Faire glisser des épics entre des listes {#dragging-epics-between-lists}

Lorsque vous faites glisser des épics entre des listes, le résultat varie en fonction de la liste source et de la liste cible.

|                       | Vers Ouvert        | Vers Fermé  | Vers la liste label B                |
| --------------------- | -------------- | ---------- | ------------------------------ |
| **Depuis Ouvert**         | -              | Fermer l'epic | Ajouter le label B                    |
| **Depuis Fermé**       | Rouvrir l'epic    | -          | Rouvrir l'epic et ajouter le label B    |
| **Depuis la liste label A** | Supprimer le label A | Fermer l'epic | Supprimer le label A et ajouter le label B |

### Modifier la portée d'un tableau d'épopées {#edit-the-scope-of-an-epic-board}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.

Pour modifier la portée d'un tableau d'épopées :

1. Dans le coin supérieur droit, sélectionnez **Configurer le tableau** ({{< icon name="settings" >}}).
1. Facultatif :
   - Modifier le titre du tableau.
   - Afficher ou masquer les colonnes Ouvert et Fermé.
   - Sélectionner d'autres labels comme portée du tableau.
1. Sélectionnez **Enregistrer les modifications**.
