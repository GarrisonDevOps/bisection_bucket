---
stage: Plan
group: Planning Views
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Configurez un tableau des tickets avec des labels et des listes de workflow afin qu'une équipe puisse suivre les tâches lors des stand-ups quotidiens."
title: 'Tutoriel : configurer un tableau de tickets pour un stand-up d''équipe'
---

<!-- vale gitlab_base.FutureTense = NO -->

Ce tutoriel vous montre comment créer et configurer un tableau des tickets qui aide les équipes à organiser des stand-ups efficaces. Une fois terminé, vous disposerez d'un tableau prenant en charge le workflow suivant :

1. Avant chaque stand-up :

   - Les membres de l'équipe mettent à jour le statut de leurs tâches assignées.
   - Les tâches progressent dans des listes affichant leur état actuel : planification, en développement, bloquée ou terminée.

1. Pendant le stand-up :

   - Les membres de l'équipe discutent du travail en cours et partagent les délais d'achèvement.
   - Les tâches bloquées sont identifiées et des plans sont établis pour les résoudre.
   - De nouvelles tâches sont ajoutées à la liste « prêt ».
   - Les tâches terminées sont célébrées et déplacées vers « terminé ».

Le résultat : votre équipe quitte chaque stand-up alignée sur la progression du sprint, avec les risques identifiés et des plans pour y remédier.

Pour configurer un tableau des tickets pour les stand-ups d'équipe :

1. [Créer un groupe](#create-a-group)
1. [Créer un projet](#create-a-project)
1. [Créer des labels](#create-labels)
1. [Créer le tableau de stand-up d'équipe](#create-the-team-stand-up-board)
1. [Configurer les listes de votre tableau](#configure-your-board-lists)
1. [Créer des tickets pour les tâches de l'équipe](#create-issues-for-team-tasks)

## Avant de commencer {#before-you-begin}

- Si vous utilisez un groupe existant pour ce tutoriel, assurez-vous de disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour ce groupe.
- Si vous utilisez un projet existant pour ce tutoriel, assurez-vous de disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour ce projet.

## Créer un groupe {#create-a-group}

Commencez par créer un groupe pour gérer un ou plusieurs projets connexes. Les groupes vous permettent de gérer les accès des membres et de partager des paramètres entre les projets.

Pour créer un groupe :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) puis **Nouveau groupe**.
1. Sélectionnez **Créer un groupe**.
1. Remplissez les champs :
   - Dans **Nom du groupe**, saisissez `Paperclip Software Factory`.
1. Sélectionnez **Créer un groupe**.

Vous avez créé un groupe vide. Ensuite, créez un projet pour stocker vos tickets et votre code.

## Créer un projet {#create-a-project}

Les projets stockent vos dépôts de code et les tickets que vous utiliserez pour la planification. Tout le travail de développement s'effectue dans les projets.

Pour créer un projet vide :

1. Dans votre groupe, dans le coin supérieur droit, sélectionnez **Nouveau projet**.
1. Sélectionnez **Créer un projet vide**.
1. Remplissez les champs :
   - Dans **Nom du projet**, saisissez `Paperclip Assistant`.
1. Sélectionnez **Créer le projet**.

## Créer des labels {#create-labels}

Pour suivre le statut des tickets lors des stand-ups, vous avez besoin de labels de workflow.

Créez ces labels dans votre groupe `Paperclip Software Factory` plutôt que dans le projet. Les labels de groupe sont disponibles pour tous les projets du groupe, ce qui contribue à établir des workflows cohérents entre les équipes.

Pour créer un label de workflow :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre groupe **Paperclip Software Factory**.
1. Sélectionnez **Gérer** > **Labels**.
1. Sélectionnez **Nouveau label**.
1. Dans la zone de texte **Intitulé**, saisissez le nom du label.
1. Facultatif. Sélectionnez une couleur d'arrière-plan ou saisissez une valeur de couleur hexadécimale.
1. Sélectionnez **Créer un label**.

Répétez ces étapes pour créer tous les labels de workflow :

- `workflow::planning breakdown`
- `workflow::ready for development`
- `workflow::in development`
- `workflow::ready for review`
- `workflow::in review`
- `workflow::blocked`
- `workflow::verification`
- `workflow::complete`

## Créer le tableau de stand-up d'équipe {#create-the-team-stand-up-board}

Créez votre tableau dans le groupe afin de pouvoir gérer les tickets depuis n'importe quel projet du groupe.

Pour créer un tableau des tickets de groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre groupe **Paperclip Software Factory**.
1. Sélectionnez **Forfait** > **Tableaux des tickets**.
1. Dans le coin supérieur gauche, sélectionnez la liste déroulante affichant le nom du tableau actuel.
1. Sélectionnez **Créer un nouveau tableau**.
1. Remplissez les champs :
   - Dans **Intitulé**, saisissez `Team stand-up`.
   - Cochez à la fois **Afficher la liste des tickets ouverts** et **Afficher la liste des tickets fermés**.
1. Sélectionnez **Créer un tableau**.

### Ajouter des listes de workflow à votre tableau {#add-workflow-lists-to-your-board}

1. Dans le coin supérieur droit, sélectionnez **Ajouter une liste** ({{< icon name="plus" >}}).
1. Depuis **Nouvelle liste**, sélectionnez **Label**.
1. Dans la liste déroulante **Valeur**, sélectionnez un label de workflow.
1. Sélectionnez **Ajouter au tableau**.
1. Répétez les étapes 1 à 4 pour chaque label de workflow.

Votre tableau dispose maintenant de listes pour chaque état de workflow, même si elles seront vides jusqu'à ce que vous ajoutiez des tickets lors des étapes suivantes.

![Tableau des tickets intitulé « Team stand-up » avec des listes de workflow mais sans tickets.](img/team_standup_board_with_workflow_lists_v17_8.png)

## Configurer les listes de votre tableau {#configure-your-board-lists}

Vous pouvez personnaliser votre tableau en définissant des filtres qui s'appliquent à toutes les listes. Par exemple, vous pouvez afficher uniquement les tickets de l'itération en cours ou avec des labels spécifiques.

Pour configurer votre tableau :

1. Sur votre tableau de stand-up d'équipe, sélectionnez **Configurer le tableau** ({{< icon name="settings" >}}).
1. Remplissez l'un de ces champs pour filtrer les tickets :
   - **Jalon** : pour afficher les tickets d'un jalon spécifique.
   - **Personne assignée** : pour afficher les tickets assignés à des membres spécifiques de l'équipe.
   - **Labels** : pour afficher les tickets avec des labels spécifiques.
   - **Poids** : pour afficher les tickets avec des valeurs de poids spécifiques.
   - **Itération** : pour afficher les tickets de l'itération en cours.
1. Sélectionnez **Créer un tableau**.

Votre tableau affiche désormais uniquement les tickets correspondant à vos filtres. Par exemple, si vous sélectionnez un jalon, seuls les tickets assignés à ce jalon apparaissent dans les listes du tableau.

![Tableau des tickets intitulé « Team stand-up » avec des listes de workflow.](img/team_standup_board_with_workflow_lists_v17_8.png)

## Créer des tickets pour les tâches de l'équipe {#create-issues-for-team-tasks}

Vous pouvez créer des tickets directement depuis votre tableau pendant le stand-up d'équipe.

Pour créer un ticket :

1. Sur votre tableau de stand-up d'équipe, dans la liste `workflow::ready for development`, sélectionnez **Créer un nouveau ticket** ({{< icon name="plus" >}}).
1. Remplissez les champs :
   - Dans **Intitulé**, saisissez `Redesign user profile page`
   - Dans la liste déroulante **Projets**, sélectionnez **Paperclip Software Factory / Paperclip Assistant**
1. Sélectionnez **Créer un ticket**.

Le ticket est créé avec le label `workflow::ready for development` car vous l'avez créé dans cette liste.

### Ajouter des métadonnées au ticket {#add-metadata-to-the-issue}

1. Sur la carte du ticket, sélectionnez n'importe quel endroit sauf le titre.
1. Dans la barre latérale droite, dans le champ que vous souhaitez mettre à jour, sélectionnez **Modifier**.
1. Sélectionnez vos modifications.
1. Sélectionnez n'importe quelle zone en dehors du champ pour enregistrer.

Félicitations ! Vous avez configuré un tableau de stand-up d'équipe qui aide à suivre le travail et à faciliter les discussions. Votre équipe peut désormais utiliser ce tableau pour organiser des stand-ups efficaces.

## Sujets connexes {#related-topics}

- [Tutoriels de planification et de suivi du travail](../plan_and_track.md)
- [Tutoriel : faciliter les stand-ups, les rétrospectives et le suivi de la vélocité](../scrum_events/standups_retrospectives_velocity.md)
