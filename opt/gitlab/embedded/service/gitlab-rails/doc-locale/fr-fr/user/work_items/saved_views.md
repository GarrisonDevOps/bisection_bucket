---
stage: Plan
group: Portfolio Planning
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Créez et utilisez des vues enregistrées pour filtrer et organiser votre liste d'éléments de travail."
title: Vues enregistrées
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/479571) dans GitLab 18.9.

{{< /history >}}

Les vues enregistrées sont des combinaisons de filtres personnalisées pour votre liste d'éléments de travail que vous pouvez réutiliser et partager. Créez plusieurs vues pour différents workflows, comme des filtres par assigné, statut ou priorité, et passez rapidement de l'une à l'autre. Chaque vue enregistre également les [options d'affichage](_index.md#configure-list-display-preferences) de votre liste, notamment les champs à afficher et l'ordre de tri des éléments.

## Visibilité des vues enregistrées {#saved-view-visibility}

Lorsque vous créez une vue enregistrée, vous contrôlez qui peut la voir, l'utiliser et la modifier.

Vues privées :

- Sont visibles uniquement par le créateur de la vue.
- Ne peuvent pas être modifiées ou utilisées par d'autres utilisateurs.

Vues partagées :

- Sont visibles par tous les membres du groupe ou du projet.
- Peuvent être ajoutées et utilisées par d'autres membres.
- Peuvent être modifiées par les membres qui remplissent les [prérequis](#edit-a-saved-view).

## Créer une vue enregistrée {#create-a-saved-view}

Prérequis :

- Vous devez avoir le rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet ou le groupe.

Pour créer une vue enregistrée :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. En haut de la page, dans la barre de filtres, sélectionnez un filtre, un opérateur et sa valeur.
1. Facultatif. Ajoutez d'autres filtres.
1. Au-dessus de la barre de filtres, sélectionnez **Ajouter une vue** > **Nouvelle vue**.
1. Saisissez un titre.
1. Facultatif. Saisissez une description. Ce champ peut aider les autres à trouver la vue et à comprendre son utilité.
1. Sous **Visibilité**, sélectionnez l'une des options suivantes :
   - **Privé**. Les vues privées sont visibles uniquement par vous.
   - **Partagé**. Les vues partagées sont visibles par tous les membres du groupe ou du projet.
1. Sélectionnez **Créer une vue**.

La vue est créée et ajoutée au-dessus de la barre de filtres, à droite de vos autres vues enregistrées (s'il y en a).

## Ajouter une vue enregistrée à votre liste {#add-a-saved-view-to-your-list}

Ajoutez à votre liste de vues enregistrées les vues que vous ou vos collègues avez créées. Vous seul pouvez voir quelles vues vous avez ajoutées à votre liste.

Lorsque vous parcourez les vues, vous pouvez voir toutes les vues disponibles, y compris vos vues privées et les vues partagées par vos collègues.

Pour ajouter une vue enregistrée à votre liste :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Au-dessus de la barre de filtres, sélectionnez **Ajouter une vue** > **Parcourir les vues**.
1. Dans la liste, sélectionnez la vue que vous souhaitez ajouter.

## Modifier une vue enregistrée {#edit-a-saved-view}

Modifiez une vue enregistrée pour changer son nom, sa description ou sa visibilité.

Prérequis :

- Vous devez avoir le rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet ou le groupe.

Pour modifier une vue enregistrée :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Sélectionnez la vue que vous souhaitez modifier.
1. Sélectionnez à nouveau la vue, puis sélectionnez **Modifier**.
1. Modifiez le titre ou la description de la vue.
1. Modifiez la visibilité de la vue. Pour modifier ce paramètre, vous devez être le créateur de la vue.
1. Sélectionnez **Enregistrer**.

## Copier un lien vers une vue enregistrée {#copy-a-link-to-a-saved-view}

Partagez un lien vers une vue enregistrée avec d'autres personnes. Lorsque vous sélectionnez un lien vers une vue enregistrée qui ne figure pas encore dans votre liste, elle est automatiquement ajoutée à votre liste.

Pour copier un lien vers une vue enregistrée :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Sélectionnez la vue que vous souhaitez copier.
1. Sélectionnez à nouveau la vue, puis sélectionnez **Copier le lien vers la vue**.

## Retirer une vue enregistrée de votre liste {#remove-a-saved-view-from-your-list}

Pour retirer une vue enregistrée de votre liste :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Sélectionnez la vue que vous souhaitez retirer.
1. Sélectionnez à nouveau la vue, puis sélectionnez **Retirer de la liste**.

La vue est retirée de votre liste, mais reste disponible pour être ajoutée à nouveau.

## Supprimer une vue enregistrée {#delete-a-saved-view}

Prérequis :

- Vous devez avoir le rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet ou le groupe.

> [!warning]
> Lorsque vous supprimez une vue, elle disparaît pour tout le monde. Assurez-vous que les autres membres de l'équipe ne l'utilisent pas.

Pour supprimer une vue enregistrée :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. Sélectionnez la vue que vous souhaitez supprimer.
1. Sélectionnez à nouveau la vue, puis sélectionnez **Supprimer la vue**.
1. Dans la boîte de dialogue de confirmation, sélectionnez **Supprimer la vue**.

## Limites des vues enregistrées {#saved-view-limits}

Les utilisateurs de l'édition Gratuite ne peuvent avoir que cinq vues enregistrées à la fois. Cette limite n'inclut pas la vue **Tous les éléments** par défaut.

Lorsque vous atteignez la limite de vues enregistrées :

- Si vous créez ou ajoutez une vue enregistrée, elle remplace la dernière vue enregistrée de votre liste.
- Si vous sélectionnez un lien vers une vue enregistrée, la vue n'est pas automatiquement ajoutée à votre liste.

## Sujets connexes {#related-topics}

- [Afficher tous les éléments de travail](_index.md#view-all-work-items)
