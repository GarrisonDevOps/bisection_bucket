---
stage: Plan
group: Planning Views
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 'Tutoriel : utiliser GitLab pour faciliter le Kanban'
description: "Travail en cours, flow et distribution."
---

<!-- vale gitlab_base.FutureTense = NO -->

Ce tutoriel vous guide à travers les étapes d'utilisation des tableaux des tickets GitLab pour gérer vos tâches dans un workflow Kanban. En configurant des groupes, des projets, des tableaux et en organisant les tickets, vous pouvez améliorer la transparence, la collaboration et la livraison.

Pour utiliser les tableaux des tickets GitLab afin de gérer vos tâches dans un workflow Kanban :

- [Configurer les groupes et les projets](#set-up-groups-and-projects)
- [Créer des labels](#create-labels)
- [Configurer le tableau Kanban](#set-up-kanban-board)
- [Visualiser le flow et la distribution](#visualize-flow-and-distribution)

Pour d'autres informations, consultez [les conseils et astuces avancés](#advanced-tips-and-tricks) en bas de cette page.

## Configurer les groupes et les projets {#set-up-groups-and-projects}

Suivez les étapes correspondantes pour [créer vos groupes](../../user/group/_index.md#create-a-group) et vos [projets](../../user/project/_index.md).

Si votre équipe travaille sur plusieurs dépôts, créez un projet pour chaque dépôt dans votre groupe.

Les tickets se trouveront canoniquement dans leurs projets respectifs, mais votre tableau Kanban sera dans votre groupe afin que vous puissiez maintenir la visibilité sur l'ensemble de vos projets. Si vous travaillez dans un seul dépôt, vous pouvez ignorer cette étape.

## Créer des labels {#create-labels}

Ensuite, créons quelques labels pour représenter chaque étape de votre cycle de vie Kanban :

- Si vous travaillez dans un seul projet, créez les labels dans ce projet.
- Si vous travaillez sur plusieurs projets, créez les labels dans votre groupe. Cela vous permet d'utiliser un seul ensemble de labels pour tous vos projets.

Dans les deux cas, le processus de [création de labels](../../user/project/labels.md#create-a-label) est identique. Créez des [labels à portée limitée](../../user/project/labels.md#scoped-labels) pour **status::to do**, **status::doing** et **status::done**.

## Configurer le tableau Kanban {#set-up-kanban-board}

Une fois vos labels créés, l'étape suivante consiste à créer un tableau Kanban :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe ou votre projet.
1. Sélectionnez **Forfait** > **Tableaux des tickets**.
1. Dans le coin supérieur gauche du tableau des tickets, sélectionnez la liste déroulante avec le nom du tableau actuel.
1. Sélectionnez **Créer un nouveau tableau**.
1. Saisissez le nom du nouveau tableau, puis sélectionnez **Créer un tableau**.
1. Créez une nouvelle liste de labels en sélectionnant **\+ Nouvelle liste**.
1. Définissez la portée de la liste sur **Label** et la valeur sur **status::to do**.
1. Répétez le même processus de création de liste de labels pour créer deux listes supplémentaires : **status::doing** et **status::done**.

Félicitations, vous disposez maintenant d'un tableau Kanban. Vous pouvez désormais créer de nouveaux tickets dans chaque liste, faire glisser et déposer des tickets d'une étape du workflow à une autre, et assigner des tickets aux membres de l'équipe.

Vous pouvez également activer les [limites du travail en cours (WIP)](../../user/project/issue_board.md#work-in-progress-limits) pour chaque liste de labels de votre tableau. Pour ce faire :

1. Sélectionnez l'icône d'engrenage **Modifier les paramètres de la liste** dans le coin supérieur droit d'une liste de labels.
1. Sélectionnez **Limite du travail en cours** > **Modifier**.
1. Saisissez le nombre maximum de tickets autorisés dans la liste correspondante, puis appuyez sur la touche **Entrée**.

L'arrière-plan de votre liste deviendra automatiquement rouge lorsque la limite est atteinte. Une ligne de coupure « limite du travail en cours » sera également visible dans la liste pour afficher visuellement tous les tickets qui dépassent la limite en dessous de la ligne.

## Visualiser le flow et la distribution {#visualize-flow-and-distribution}

Le Kanban utilise traditionnellement des diagrammes de flux cumulatif pour visualiser la charge et aider à identifier les goulots d'étranglement. Dans GitLab, cela peut être réalisé avec [Value Stream Analytics (VSA)](../../user/group/value_stream_analytics/_index.md). Ensuite, créez un rapport VSA personnalisé correspondant à votre workflow Kanban.

### Visualiser le flow {#visualize-flow}

Pour visualiser le flow :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe ou votre projet.
1. Dans la navigation latérale, sélectionnez **Analyse** > **Données d'analyse des chaînes de valeur**.
1. Sélectionnez la liste déroulante **Chaînes de valeur** dans le coin supérieur gauche de la page, puis sélectionnez **Nouvelle chaîne de valeur**.
1. Saisissez le nom souhaité pour le rapport VSA, puis sélectionnez **Créer à partir d'un modèle**.
1. Saisissez **À faire** comme nom de l'étape.
1. Pour l'événement de début, sélectionnez **Ajout du label de ticket**, puis sélectionnez le label **status::to do**.
1. Pour l'événement de fin, sélectionnez **Suppression du label de ticket**, puis sélectionnez le label **status::to do**.
1. Ensuite, sélectionnez **Ajouter une étape**.
1. Répétez ce même processus pour créer des étapes pour **status::in progress** et **status::done**.
1. Lorsque les trois étapes ont été ajoutées, sélectionnez **Nouvelle chaîne de valeur**.

Grâce à votre rapport VSA personnalisé correspondant au même workflow que votre tableau Kanban, GitLab calcule automatiquement le temps que chaque ticket passe à chaque étape et agrège les données sur l'ensemble des étapes. Vous obtenez ainsi le délai de livraison et le temps de cycle. Vous pouvez approfondir chaque étape pour consulter les durées spécifiques de chaque ticket.

### Visualiser la distribution {#visualize-distribution}

Pour visualiser la distribution :

1. Dans le rapport VSA que vous avez créé, faites défiler vers le bas jusqu'au graphique **Tâches par type**.
1. Sélectionnez la liste déroulante de l'icône d'engrenage dans le coin supérieur droit, puis recherchez et sélectionnez les labels représentant le type de ticket.
1. Si vous n'avez pas créé de labels à portée limitée **type::...** ou quelque chose de similaire, c'est le bon moment pour commencer à intégrer des types d'éléments de travail dans votre workflow (par exemple, **feature**, **bug** et **maintenance**).
1. Sélectionnez **Afficher les tickets**, puis sélectionnez n'importe où en dehors de la liste déroulante pour appliquer les modifications.
1. Le graphique **Tâches par type** affiche désormais la distribution des tickets correspondant aux labels sélectionnés au fil du temps.

## Conseils et astuces avancés {#advanced-tips-and-tricks}

- Pour créer des politiques qui mettent automatiquement à jour les tickets selon les conditions spécifiées, configurez [`gitlab-triage`](https://gitlab.com/gitlab-org/ruby/gems/gitlab-triage). Par exemple, vous pouvez créer une politique pour fermer automatiquement les tickets lorsque le label **status::done** est appliqué, ou ajouter automatiquement le label **status::to do** lors de la création d'un ticket. Le gem open source `gitlab-triage` est conçu pour fonctionner de manière transparente avec les pipelines GitLab.
- Pour rendre la création de différents types de tickets plus efficace et standardisée, créez des [modèles de description](../../user/project/description_templates.md).
- Pour visualiser la charge de travail de chaque membre de l'équipe dans votre groupe ou projet, créez un tableau des tickets supplémentaire avec des **listes par cessionnaire**.
- Créez un ensemble de labels à portée limitée pour le dimensionnement en taille de T-shirt des tickets. Par exemple, **size::small**, **size::medium** et **size::large**.
