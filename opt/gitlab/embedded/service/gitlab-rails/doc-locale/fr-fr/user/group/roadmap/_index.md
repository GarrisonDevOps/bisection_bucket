---
stage: Plan
group: Portfolio Planning
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Feuille de route
description: "Progression des epics, chronologies, jalons et objectifs."
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les epics d'un groupe contenant une date de début ou une date d'échéance peuvent être visualisés sous la forme d'une chronologie.

Le roadmap dans GitLab fournit une vue d'ensemble de haut niveau du travail planifié et de la progression des epics et des jalons dans une vue chronologique (c'est-à-dire un diagramme de Gantt). Utilisez le roadmap pour visualiser et communiquer la direction stratégique et les dépendances de vos projets.

Le roadmap des epics offre les avantages suivants :

- Aligne l'équipe autour d'une vision et d'objectifs communs.
- Facilite la planification à long terme et l'allocation des ressources.
- Identifie les obstacles potentiels, les dépendances et les risques en amont.
- Fournit aux parties prenantes une compréhension claire de la chronologie et des jalons du projet.
- Aide à suivre et à mettre à jour la progression du projet.

## Afficher le roadmap {#view-the-roadmap}

Pour afficher le roadmap dans un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Feuille de route**.

Le roadmap affiche les epics et les jalons dans un groupe, l'un de ses sous-groupes, ou un projet dans l'un des groupes.

Sur les barres d'epics, vous pouvez voir le titre, la progression et le pourcentage de poids complété de chaque epic. Lorsque vous survolez une barre d'epic, une fenêtre contextuelle apparaît avec le titre de l'epic, sa date de début, sa date d'échéance et le poids complété.

Vous pouvez développer les epics contenant des epics enfants pour afficher leurs epics enfants dans le roadmap. Vous pouvez sélectionner le chevron ({{< icon name="chevron-down" >}}) situé à côté du titre de l'epic pour développer et réduire les epics enfants.

En haut des barres de jalons, vous pouvez voir leur titre. Lorsque vous pointez sur une barre de jalon ou son titre, une fenêtre contextuelle apparaît avec son titre, sa date de début et sa date d'échéance. Vous pouvez également sélectionner le chevron ({{< icon name="chevron-down" >}}) situé à côté de l'en-tête **Jalons** pour activer ou désactiver la liste des barres de jalons.

![La vue du roadmap avec les epics et les jalons.](img/roadmap_view_v14_3.png)

Depuis un epic, vous pouvez également [afficher le roadmap filtré sur les descendants de cet epic](../../work_items/child_items.md#view-child-epics-on-a-roadmap).

## Trier et filtrer le roadmap {#sort-and-filter-the-roadmap}

{{< history >}}

- Le tri par titre, date de création et date de dernière mise à jour a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/460492) dans GitLab 17.0.

{{< /history >}}

> [!note]
> Il est possible que le filtrage des roadmaps par jalon ne soit pas disponible pour vous. Veillez à consulter l'historique de cette section pour plus de détails.

Lorsque vous souhaitez explorer un roadmap, plusieurs méthodes permettent de le faciliter en triant les epics ou en les filtrant selon ce qui est important pour vous.

Dans la vue Roadmap, vous pouvez trier les epics par :

- Date de début
- Date d'échéance
- Titre
- Date de création
- Date de dernière mise à jour

Chaque option contient un bouton qui bascule l'ordre de tri entre **croissant** et **décroissant**. L'option et l'ordre de tri persistent lors de la navigation dans les epics, y compris dans la [vue liste des epics](../epics/_index.md).

Dans la vue Roadmap, vous pouvez également filtrer par les caractéristiques des epics :

- Auteur
- Label
- Jalon
- [Confidentialité](../epics/manage_epics.md#make-an-epic-confidential)
- Epic
- Votre réaction
- Groupes

![Filtrage d'un roadmap d'epics GitLab par le label « Documentation Update », affichant des options de filtrage supplémentaires dans la liste déroulante.](img/roadmap_filters_v13_11.png)

Depuis un epic, vous pouvez également [afficher le roadmap filtré sur les descendants de cet epic](../../work_items/child_items.md#view-child-epics-on-a-roadmap).

### Améliorer les performances du roadmap {#improve-the-performance-of-the-roadmap}

Si votre groupe contient un grand nombre d'epics, l'utilisation de filtres peut réduire le temps de chargement de votre roadmap. Le filtrage du roadmap réduit la quantité de données qu'il contient. Réduire les données du roadmap peut également vous permettre de trouver plus facilement les informations que vous recherchez.

En particulier, le filtrage basé sur les labels peut entraîner une amélioration significative des performances.

Une fois les filtres que vous souhaitez appliquer définis, vous pouvez enregistrer l'URL comme signet dans votre navigateur. À l'avenir, vous pourrez charger rapidement le roadmap filtré à l'aide du signet.

### Paramètres du roadmap {#roadmap-settings}

Lorsque vous activez la barre latérale des paramètres du roadmap, vous pouvez l'utiliser pour affiner les epics affichés dans le roadmap.

Vous pouvez configurer les éléments suivants :

- Sélectionner la plage de dates.
- Activer ou désactiver les jalons, et choisir d'afficher tous les jalons, les jalons de groupe, de sous-groupe ou de projet.
- Afficher tous les epics, les epics ouverts ou les epics fermés.
- Activer ou désactiver le suivi de progression des tickets enfants et choisir d'utiliser les poids ou les nombres de tickets pour calculer la progression.
- Activer ou désactiver les labels.

Les paramètres de configuration du roadmap ne sont pas enregistrés dans les préférences utilisateur, mais sont enregistrés ou partagés via des paramètres d'URL.

## Durée de la chronologie {#timeline-duration}

{{< history >}}

- [Déplacé](https://gitlab.com/gitlab-org/gitlab/-/issues/198062) de GitLab Ultimate vers GitLab Premium dans la version 12.9.

{{< /history >}}

### Présélections de plage de dates {#date-range-presets}

Le roadmap propose ces options de plage de dates, chacune avec une durée de chronologie prédéfinie :

- **Ce trimestre** : inclut les semaines présentes dans le trimestre en cours.
- **Cette année** : inclut les semaines ou les mois présents dans l'année en cours.
- **Dans les 3 ans** : inclut les semaines, les mois ou les trimestres présents à la fois dans les 18 mois précédents et dans les 18 mois à venir (trois ans au total).

### Présélections de mise en page {#layout-presets}

En fonction de la [présélection de plage de dates](#date-range-presets) sélectionnée, le roadmap prend en charge les présélections de mise en page suivantes :

- **Trimestres** : disponible uniquement lorsque la plage de dates **Dans les 3 ans** est sélectionnée.
- **Mois** : disponible lorsque la plage de dates **Cette année** ou **Dans les 3 ans** est sélectionnée.
- **Semaines** (par défaut) : disponible pour toutes les présélections de plage de dates.

### Trimestres {#quarters}

![En-tête de chronologie affichant les trimestres et les mois pour 6 trimestres, mettant en évidence l'échelle de temps.](img/roadmap_timeline_quarters_v11_10.png)

Dans la présélection **Trimestres**, le roadmap affiche les epics et les jalons dont les dates de début ou d'échéance tombent dans la plage de dates actuellement sélectionnée, où la date du jour est indiquée par la ligne rouge verticale dans la chronologie. Les sous-en-têtes situés sous le nom du trimestre dans l'en-tête de chronologie représentent le mois du trimestre.

### Mois {#months}

![En-tête de chronologie affichant les mois avec des marqueurs de date hebdomadaires sous chaque mois.](img/roadmap_timeline_months_v11_10.png)

Dans la présélection **Mois**, le roadmap affiche les epics et les jalons dont les dates de début ou d'échéance tombent dans la plage de dates actuellement sélectionnée ou la traversent, où la date du jour est indiquée par la ligne rouge verticale dans la chronologie. Les sous-en-têtes situés sous le nom du mois dans l'en-tête de chronologie représentent la date du premier jour (dimanche) de la semaine. Cette présélection est sélectionnée par défaut.

### Semaines {#weeks}

![La présélection de plage de dates Semaines dans un roadmap.](img/roadmap_timeline_weeks_v11_11.png)

Dans la présélection **Semaines**, le roadmap affiche les epics et les jalons dont les dates de début ou d'échéance tombent dans la plage de dates actuellement sélectionnée ou la traversent, où la date du jour est indiquée par la ligne rouge verticale dans la chronologie. Les sous-en-têtes situés sous le nom de la semaine dans l'en-tête de chronologie représentent les jours de la semaine.

## Barre de chronologie du roadmap {#roadmap-timeline-bar}

La barre de chronologie indique la position approximative d'un epic ou d'un jalon en fonction de ses dates de début et d'échéance.

## Epics bloqués {#blocked-epics}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si un epic est [bloqué par un autre epic](../epics/linked_epics.md#blocking-epics), une icône apparaît à côté de son titre pour indiquer son statut de blocage.

Lorsque vous survolez l'icône de blocage ({{< icon name="entity-blocked" >}}), une fenêtre contextuelle d'informations détaillées s'affiche.

![La fenêtre contextuelle affichant des informations détaillées sur un epic bloqué.](img/roadmap_blocked_icon_v15_5.png)
