---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Les jalons
description: "Graphiques d'avancement (burndown charts), objectifs, suivi de la progression et releases."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les jalons permettent de suivre et d'organiser le travail dans GitLab. Les jalons :

- Regroupent les tickets, epics et merge requests connexes pour suivre la progression vers un objectif.
- Prennent en charge la planification temporelle avec des dates de début et d'échéance facultatives.
- Fonctionnent en parallèle des itérations pour suivre les timeboxes simultanées.
- Permettent de suivre les releases et de générer des preuves de release.
- S'appliquent aux projets et aux groupes.

Les jalons peuvent appartenir à un [projet](../_index.md) ou à un [groupe](../../group/_index.md). Les jalons de projet s'appliquent uniquement aux tickets et aux merge requests de ce projet. Les jalons de groupe s'appliquent à tout ticket, epic ou merge request des projets de ce groupe.

Pour plus d'informations sur l'API des jalons de projet et de groupe, consultez :

- [API des jalons de projet](../../../api/milestones.md)
- [API des jalons de groupe](../../../api/group_milestones.md)

## Jalons en tant que releases {#milestones-as-releases}

Les jalons peuvent être utilisés pour suivre les releases. Pour ce faire :

1. Définissez la date d'échéance du jalon pour qu'elle corresponde à la date de release de votre release. Si vous n'avez pas de date de début définie pour votre cycle de release, vous pouvez laisser la date de début du jalon vide.
1. Définissez le titre du jalon avec la version de votre release, par exemple `Version 9.4`.
1. Ajoutez des tickets à votre release en sélectionnant le jalon depuis la barre latérale droite du ticket.

De plus, pour générer automatiquement une preuve de release lors de la création de votre release, intégrez les jalons à la [fonctionnalité de releases](../releases/_index.md#associate-milestones-with-a-release).

## Jalons de projet et jalons de groupe {#project-milestones-and-group-milestones}

Un jalon peut appartenir à un [projet](../_index.md) ou à un [groupe](../../group/_index.md).

Vous pouvez assigner des **jalons de projet** aux tickets ou aux merge requests de ce projet uniquement. Vous pouvez assigner des **jalons de groupe** à tout ticket, epic ou merge request de n'importe quel projet de ce groupe.

Pour plus d'informations sur l'API des jalons de projet et de groupe, consultez :

- [API des jalons de projet](../../../api/milestones.md)
- [API des jalons de groupe](../../../api/group_milestones.md)

### Afficher les jalons d'un projet ou d'un groupe {#view-project-or-group-milestones}

Pour afficher la liste des jalons :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Jalons**.

Dans un projet, GitLab affiche les jalons appartenant au projet. Dans un groupe, GitLab affiche les jalons appartenant au groupe ainsi que tous les projets et sous-groupes du groupe.

### Afficher les jalons dans un projet avec les tickets désactivés {#view-milestones-in-a-project-with-issues-turned-off}

Si le suivi des tickets d'un projet est [désactivé](../settings/_index.md#configure-project-features-and-permissions), accédez à la page des jalons en saisissant son URL.

Pour ce faire :

1. Accédez à votre projet.
1. Ajoutez `/-/milestones` à l'URL de votre projet. Par exemple `https://gitlab.com/gitlab-org/sample-data-templates/sample-gitlab-project/-/milestones`.

Les tickets de ce projet sont également visibles sur la page des jalons du groupe.

L'amélioration de cette expérience est suivie dans le [ticket 339009](https://gitlab.com/gitlab-org/gitlab/-/issues/339009).

### Afficher tous les jalons {#view-all-milestones}

Vous pouvez afficher tous les jalons auxquels vous avez accès dans l'ensemble de l'espace de nommage GitLab. Il est possible que certains jalons ne soient pas visibles, car ils appartiennent à des projets ou des groupes dont vous n'êtes pas membre.

Pour ce faire :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**.
1. Sélectionnez **Votre travail**.
1. Dans la barre latérale gauche, sélectionnez **Jalons**.

### Afficher les détails d'un jalon {#view-milestone-details}

Pour afficher plus d'informations sur un jalon, dans la page **Jalons**, sélectionnez le titre du jalon que vous souhaitez consulter.

La vue du jalon affiche le titre et la description. Les onglets sous le titre et la description affichent les éléments suivants :

- **Éléments de travail** : affiche tous les éléments de travail assignés au jalon. Les éléments de travail sont affichés dans trois colonnes nommées :
  - Tickets non démarrés (ouverts et non assignés)
  - Tickets en cours (ouverts et assignés)
  - Tickets terminés (fermés)
- **requêtes de fusion** : affiche toutes les merge requests assignées au jalon. Les merge requests sont affichées dans quatre colonnes nommées :
  - Travaux en cours (ouverts et non assignés)
  - En attente de fusion (ouverts et assignés)
  - Rejetées (fermées)
  - Fusionnées
- **Participants** : affiche tous les responsables des tickets assignés au jalon.
- **Labels** : affiche tous les labels utilisés dans les tickets assignés au jalon.

#### Graphiques d'avancement (burndown charts) {#burndown-charts}

La vue du jalon contient un [graphique d'avancement (burndown and burnup chart)](burndown_and_burnup_charts.md), montrant la progression vers la complétion d'un jalon.

![Un graphique d'avancement (burndown and burnup chart) illustrant la progression du projet au fil du temps.](img/burndown_and_burnup_charts_v15_3.png)

#### Barre latérale du jalon {#milestone-sidebar}

La barre latérale de la vue du jalon affiche les éléments suivants :

- Le pourcentage d'avancement, calculé comme le nombre d'éléments de travail fermés divisé par le nombre total d'éléments de travail.
- La date de début et la date d'échéance.
- Le temps total passé sur tous les éléments de travail et les merge requests assignés au jalon.
- Le poids total des tickets de tous les éléments de travail assignés au jalon.
- Le nombre total de merge requests, ouvertes, fermées et fusionnées.
- Liens vers les releases associées.
- La référence du jalon que vous pouvez copier dans votre presse-papiers.

![La page des jalons du projet, affichant une liste de jalons avec leur progression et leurs dates d'échéance.](img/milestones_project_milestone_page_sidebar_v13_11.png)

## Créer un jalon {#create-a-milestone}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) du rôle utilisateur minimum, passant de Reporter à Planificateur dans GitLab 17.7.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/195530) des jalons dans les éléments de travail Epic dans GitLab 18.2.

{{< /history >}}

Vous pouvez créer un jalon dans un projet ou dans un groupe.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet ou le groupe auquel appartient le jalon.

Pour créer un jalon :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Jalons**.
1. Sélectionnez **Nouveau jalon**.
1. Saisissez le titre.
1. Facultatif. Saisissez la description, la date de début et la date d'échéance.
1. Sélectionnez **Nouveau jalon**.

![Le formulaire de création d'un nouveau jalon, avec des champs pour un titre, une description, une date de début et une date d'échéance.](img/milestones_new_project_milestone_v16_11.png)

### Règles relatives aux titres des jalons {#milestone-title-rules}

Pour éviter toute confusion dans les hiérarchies de groupes, les titres de jalons en double ne sont pas autorisés.

- Pour les **jalons de projet**, les titres doivent être uniques dans la hiérarchie ancêtre du projet, pour les titres de projet et de jalon.
- Pour les **jalons de groupe**, les titres doivent être uniques dans la hiérarchie du groupe, pour les ancêtres et les enfants, y compris les jalons de groupe et de projet.

## Modifier un jalon {#edit-a-milestone}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) du rôle utilisateur minimum, passant de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet ou le groupe auquel appartient le jalon.

Pour modifier un jalon :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Jalons**.
1. Sélectionnez le titre d'un jalon.
1. Dans le coin supérieur droit, sélectionnez **Actions sur les jalons** ({{< icon name="ellipsis_v" >}}) puis sélectionnez **Modifier**.
1. Modifiez le titre, la date de début, la date d'échéance ou la description.
1. Sélectionnez **Enregistrer les modifications**.

## Fermer un jalon {#close-a-milestone}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) du rôle utilisateur minimum, passant de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Un jalon se ferme après sa date d'échéance. Vous pouvez également fermer un jalon manuellement.

Lorsqu'un jalon est fermé, ses tickets ouverts restent ouverts.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet ou le groupe auquel appartient le jalon.

Pour fermer un jalon :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Jalons**.
1. L'une ou l'autre des options :
   - À côté du jalon que vous souhaitez fermer, sélectionnez **Actions sur les jalons** ({{< icon name="ellipsis_v" >}}) > **Fermer**.
   - Sélectionnez le titre du jalon, puis sélectionnez **Fermer**.

## Supprimer un jalon {#delete-a-milestone}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) du rôle utilisateur minimum, passant de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet ou le groupe auquel appartient le jalon.

Pour supprimer un jalon :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Jalons**.
1. L'une ou l'autre des options :
   - À côté du jalon que vous souhaitez supprimer, sélectionnez **Actions sur les jalons** ({{< icon name="ellipsis_v" >}}) > **Supprimer**.
   - Sélectionnez le titre du jalon, puis sélectionnez **Actions sur les jalons** ({{< icon name="ellipsis_v" >}}) > **Supprimer**.
1. Sélectionnez **Supprimer le jalon**.

## Promouvoir un jalon de projet en jalon de groupe {#promote-a-project-milestone-to-a-group-milestone}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) du rôle utilisateur minimum, passant de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Si vous augmentez le nombre de projets dans un groupe, vous souhaiterez peut-être partager les mêmes jalons entre les projets de ce groupe. Vous pouvez promouvoir des jalons de projet vers le groupe parent pour les rendre disponibles aux autres projets du même groupe.

La promotion d'un jalon fusionne tous les jalons de projet portant le même nom dans tous les projets de ce groupe en un seul jalon de groupe. Tous les tickets et les merge requests précédemment assignés à l'un de ces jalons de projet sont assignés au nouveau jalon de groupe.

> [!warning]
> Cette action est irréversible et les modifications sont permanentes.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le groupe.

Pour promouvoir un jalon de projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Jalons**.
1. L'une ou l'autre des options :
   - À côté du jalon que vous souhaitez promouvoir, sélectionnez **Actions sur les jalons** ({{< icon name="ellipsis_v" >}}) > **Promouvoir**.
   - Sélectionnez le titre du jalon, puis sélectionnez **Actions sur les jalons** ({{< icon name="ellipsis_v" >}}) > **Promouvoir**.
1. Sélectionnez **Promouvoir le jalon**.

## Assigner un jalon à un élément {#assign-a-milestone-to-an-item}

{{< history >}}

- L'assignation de jalons aux epics a été [introduite](https://gitlab.com/groups/gitlab-org/-/work_items/329) dans GitLab 18.2.

{{< /history >}}

Chaque ticket, epic ou merge request peut se voir assigner un seul jalon. Les jalons sont visibles sur chaque page de ticket et de merge request, dans la barre latérale droite. Ils sont également visibles dans le tableau des éléments de travail.

Pour assigner ou désassigner un jalon :

1. Affichez un ticket, un epic ou une merge request.
1. Dans la barre latérale droite, à côté de **Jalons**, sélectionnez **Modifier**.
1. Dans la liste **Assigner un jalon**, recherchez un jalon en saisissant son nom. Vous pouvez sélectionner parmi les jalons de projet et de groupe.
1. Sélectionnez le jalon que vous souhaitez assigner.

Pour assigner ou désassigner un jalon, vous pouvez également :

- Utiliser la [action rapide `/milestone`](../quick_actions.md#milestone) dans un commentaire ou une description
- Faire glisser un ticket vers une [liste de jalons](../issue_board.md#milestone-lists) dans un tableau
- [Modifier des tickets en masse](../issues/managing_issues.md#bulk-edit-issues) depuis la liste des tickets

## Filtrer les tickets et les merge requests par jalon {#filter-issues-and-merge-requests-by-milestone}

### Filtres dans les pages de liste {#filters-in-list-pages}

Vous pouvez filtrer par jalons de groupe et de projet depuis les pages de liste des tickets/merge requests de projet et de groupe.

### Filtres dans les tableaux de tickets {#filters-in-issue-boards}

Depuis les [tableaux des tickets de projet](../issue_board.md), vous pouvez filtrer par jalons de groupe et jalons de projet dans :

- [Barre de recherche et de filtre](../issue_board.md#filter-issues)
- [Configuration du tableau des tickets](../issue_board.md#configurable-issue-boards)

Depuis les [tableaux des tickets de groupe](../issue_board.md#group-issue-boards), vous pouvez filtrer uniquement par jalons de groupe dans :

- [Barre de recherche et de filtre](../issue_board.md#filter-issues)
- [Configuration du tableau des tickets](../issue_board.md#configurable-issue-boards)

### Filtres spéciaux de jalons {#special-milestone-filters}

{{< history >}}

- La logique des filtres **Commencé** et **À venir** a [changé](https://gitlab.com/gitlab-org/gitlab/-/issues/429728) dans GitLab 18.0.

{{< /history >}}

Lors du filtrage par jalon, en plus de choisir un jalon de projet ou de groupe spécifique, vous pouvez choisir un filtre de jalon spécial.

- **Aucun** : affiche les tickets ou les merge requests sans jalon assigné.
- **Tout** : affiche les tickets ou les merge requests avec un jalon assigné.
- **À venir** : affiche les tickets ou les merge requests avec un jalon ouvert assigné commençant dans le futur.
- **Commencé** : affiche les tickets ou les merge requests avec un jalon ouvert assigné qui chevauche la date actuelle. La liste exclut les jalons sans date de début et date d'échéance définies.
