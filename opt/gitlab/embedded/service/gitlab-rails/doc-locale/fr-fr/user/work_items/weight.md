---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Attribuez un poids numérique aux éléments de travail GitLab pour représenter leur effort estimé, leur valeur ou leur complexité, et faciliter la planification et la priorisation."
title: Poids des éléments de travail
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Les poids des éléments de travail pour les epics [introduits](https://gitlab.com/groups/gitlab-org/-/work_items/12273) dans GitLab 18.11.

{{< /history >}}

Lorsque vous avez de nombreux éléments de travail, il peut être difficile d'en avoir une vue d'ensemble. Grâce aux éléments de travail pondérés, vous pouvez mieux estimer le temps, la valeur ou la complexité qu'un élément de travail donné représente ou engendre. Vous pouvez également [trier par poids](_index.md#sort-work-items) pour identifier les éléments de travail à prioriser.

## Afficher le poids d'un élément de travail {#view-the-work-item-weight}

Vous pouvez afficher le poids d'un élément de travail sur la page de l'élément de travail lui-même ou sur plusieurs tableaux et listes associés dans l'interface utilisateur.

Pour afficher le poids d'un élément de travail individuel :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Sélectionnez un élément de travail.
1. Dans la barre latérale droite, sous **Poids**, affichez le poids de l'élément de travail.

Pour afficher les poids des éléments de travail dans la liste **Éléments de travail** :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Dans la zone de filtre, sélectionnez le filtre **Poids** ({{< icon name="weight" >}}) et ajoutez une valeur, par exemple `1`.
1. Affichez les éléments de travail et leurs poids.

Pour afficher le poids d'un élément de travail sur un tableau des tickets :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Tableaux des tickets**.
1. Sur un élément de travail individuel, survolez **Poids** ({{< icon name="weight" >}}) pour afficher le poids de l'élément de travail.

Pour afficher le poids d'un élément de travail sur la page **Jalons** :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Jalons**.
1. Sélectionnez un jalon.
1. Sur la page **Jalon**, dans la barre latérale droite sous **Poids total**, affichez la somme totale des poids des éléments de travail.

## Afficher le poids cumulé des éléments de travail {#view-the-work-item-roll-up-weight}

Le poids cumulé d'un élément de travail correspond à la somme de tous les poids des éléments de travail enfants remontés jusqu'à leur parent.

Par exemple, si un élément de travail a un poids explicite de sept et deux éléments enfants avec des poids de quatre et cinq, le poids cumulé serait de neuf.

Pour afficher le poids cumulé d'un élément de travail :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Sélectionnez un élément de travail parent.
1. À côté de **Éléments enfants**, affichez le **Poids** cumulé de l'élément de travail ({{< icon name="weight" >}}).

Dans les listes et les tableaux, seul le poids directement défini pour un élément de travail est affiché.

## Définir le poids d'un élément de travail {#set-the-work-item-weight}

{{< history >}}

- Le rôle minimum requis pour définir le poids d'un élément de travail a été [modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet ou le groupe parent.

Les points suivants s'appliquent :

- Vous pouvez définir le poids d'un élément de travail lors de sa création ou de sa modification.
- Vous devez saisir des nombres entiers positifs.
- Lorsque vous modifiez le poids d'un élément de travail, la nouvelle valeur écrase la valeur précédente.

### Lors de la création d'un élément de travail {#when-you-create-a-work-item}

Pour définir le poids d'un élément de travail lors de sa création, saisissez un nombre sous **Poids**.

### À partir d'un élément de travail existant {#from-an-existing-work-item}

Pour définir le poids d'un élément de travail à partir d'un élément de travail existant :

1. Accédez à l'élément de travail.
1. Dans la barre latérale droite, dans la section **Poids**, sélectionnez **Modifier**.
1. Saisissez le nouveau poids.
1. Sélectionnez n'importe quelle zone en dehors de la liste déroulante.

### À partir d'un tableau des tickets {#from-an-issue-board}

Pour définir le poids d'un ticket lorsque vous [modifiez un ticket depuis un tableau des tickets](../project/issue_board.md#edit-an-issue) :

1. Accédez à votre tableau des tickets.
1. Sélectionnez une carte de ticket (pas son titre).
1. Dans la barre latérale droite, dans la section **Poids**, sélectionnez **Modifier**.
1. Saisissez le nouveau poids.
1. Sélectionnez n'importe quelle zone en dehors de la liste déroulante.

## Supprimer le poids d'un élément de travail {#remove-work-item-weight}

{{< history >}}

- Le rôle minimum requis pour supprimer le poids d'un élément de travail a été [modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet ou le groupe parent.

Pour supprimer le poids d'un élément de travail, suivez les mêmes étapes que pour [définir le poids d'un élément de travail](#set-the-work-item-weight), puis sélectionnez **supprimer le poids**.
