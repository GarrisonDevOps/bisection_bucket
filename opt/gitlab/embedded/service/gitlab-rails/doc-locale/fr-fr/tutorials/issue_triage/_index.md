---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Configurez des labels à portée limitée et un tableau des tickets dans un seul projet pour trier les tickets par type, gravité et priorité."
title: 'Tutoriel : configurer un projet pour le triage des tickets'
---

<!-- vale gitlab_base.FutureTense = NO -->

Le triage des tickets est le processus de catégorisation selon le type et la gravité. Au fur et à mesure que votre projet se développe et que les utilisateurs créent davantage de tickets, il vaut la peine de mettre en place un workflow pour trier les tickets entrants.

Dans ce tutoriel, vous apprendrez comment configurer un projet GitLab pour cela.

Pour configurer GitLab pour le triage des tickets dans un projet :

1. [Créer un projet](#create-a-project)
1. [Définir les critères de types, de gravité et de priorité](#decide-on-the-criteria-for-types-severity-and-priority)
1. [Documenter vos critères](#document-your-criteria)
1. [Créer des labels à portée limitée](#create-scoped-labels)
1. [Prioriser les nouveaux labels](#prioritize-the-new-labels)
1. [Créer un tableau de triage des tickets](#create-an-issue-triage-board)
1. [Créer des tickets pour les fonctionnalités](#create-issues-for-features)

## Avant de commencer {#before-you-begin}

- Si vous utilisez un projet existant pour ce tutoriel, assurez-vous de disposer du rôle Reporter, Developer, Maintainer ou Owner pour le projet.
- Si vous suivez les étapes ci-dessous et décidez ultérieurement de créer un groupe parent pour votre projet, pour utiliser au mieux les labels, vous devrez promouvoir les labels du projet en labels de groupe. Envisagez de créer un groupe en premier.

## Créer un projet {#create-a-project}

Un projet contient les tickets utilisés pour planifier vos prochaines modifications de code.

Si vous travaillez déjà dans un projet, passez à [définir les critères de types, de gravité et de priorité](#decide-on-the-criteria-for-types-severity-and-priority).

Pour créer un projet vide :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer un projet vide**.
1. Saisissez les détails du projet.
   - Pour **Nom du projet**, saisissez `Issue triage tutorial`.
1. Sélectionnez **Créer le projet**.

## Définir les critères de types, de gravité et de priorité {#decide-on-the-criteria-for-types-severity-and-priority}

Ensuite, vous devrez déterminer :

- **Types** de tickets que vous souhaitez identifier. Si vous avez besoin d'une approche plus granulaire, vous pouvez également créer des sous-types pour chaque type. Les types permettent de catégoriser le travail afin de mieux comprendre la nature des demandes adressées à votre équipe.
- Niveaux de **priorités** et de **gravités** pour définir l'impact que le travail entrant a sur les utilisateurs finaux et pour faciliter la priorisation.

Pour ce tutoriel, supposons que vous ayez décidé des éléments suivants :

- Type : `Bug`, `Feature` et `Maintenance`
- Priorité : `1`, `2`, `3` et `4`
- Gravité : `1`, `2`, `3` et `4`

Pour vous inspirer, consultez la façon dont GitLab les définit :

- [Types et sous-types](https://handbook.gitlab.com/handbook/engineering/metrics/#work-type-classification)
- [Priorité](https://handbook.gitlab.com/handbook/product-development/how-we-work/issue-triage/#priority)
- [Gravité](https://handbook.gitlab.com/handbook/product-development/how-we-work/issue-triage/#severity)

## Documenter vos critères {#document-your-criteria}

Une fois que vous avez convenu de tous les critères, consignez-les dans un endroit accessible en permanence à vos coéquipiers.

Par exemple, ajoutez-les à un [wiki](../../user/project/wiki/_index.md) dans votre projet, ou dans le manuel de votre entreprise publié avec [GitLab Pages](../../user/project/pages/_index.md).

<!-- Idea for expanding this tutorial:
     Add steps for [creating a wiki page](../../user/project/wiki/_index.md#create-a-new-wiki-page). -->

## Créer des labels à portée limitée {#create-scoped-labels}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Ensuite, vous allez créer des labels à ajouter aux tickets pour les catégoriser.

Le meilleur outil pour cela est les [labels à portée limitée](../../user/project/labels.md#scoped-labels), que vous pouvez utiliser pour définir des attributs mutuellement exclusifs.

En vous référant à la liste des types, gravités et priorités que vous avez établie [précédemment](#decide-on-the-criteria-for-types-severity-and-priority), vous voudrez créer des labels à portée limitée correspondants.

Le double deux-points (`::`) dans le nom d'un label à portée limitée empêche l'utilisation simultanée de deux labels de même portée. Par exemple, si vous ajoutez le label `type::feature` à un ticket qui possède déjà `type::bug`, le précédent est supprimé.

> [!note]
> Les labels à portée limitée sont disponibles dans les éditions Premium et Ultimate. Si vous utilisez l'édition Gratuite, vous pouvez utiliser des labels ordinaires à la place. Cependant, ils ne sont pas mutuellement exclusifs.

Pour créer chaque label :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Gérer** > **Labels**.
1. Sélectionnez **Nouveau label**.
1. Dans la zone de texte **Intitulé**, saisissez le nom du label. Commencez par `type::bug`.
1. Facultatif. Sélectionnez une couleur parmi les couleurs disponibles, ou saisissez une valeur de couleur hexadécimale pour une couleur spécifique dans la zone de texte **Couleur d'arrière‐plan**.
1. Sélectionnez **Créer un label**.

Répétez ces étapes pour créer tous les labels dont vous aurez besoin :

- `type::bug`
- `type::feature`
- `type::maintenance`
- `priority::1`
- `priority::2`
- `priority::3`
- `priority::4`
- `severity::1`
- `severity::2`
- `severity::3`
- `severity::4`

## Prioriser les nouveaux labels {#prioritize-the-new-labels}

À présent, définissez les nouveaux labels comme labels prioritaires, ce qui garantit que les tickets les plus importants s'affichent en haut de la liste si vous triez par priorité ou par priorité du label.

Pour en savoir plus sur ce qui se passe lorsque vous triez par priorité ou par priorité du label, consultez [le tri et l'ordonnancement des listes de tickets](../../user/project/issues/sorting_issue_lists.md).

Pour prioriser un label :

1. Sur la page Labels, à côté d'un label que vous souhaitez prioriser, sélectionnez l'étoile ({{< icon name="star-o" >}}). Ce label s'affiche désormais en haut de la liste des labels, sous **Étiquettes prioritaires**.
1. Pour modifier la priorité relative de ces labels, faites-les glisser vers le haut ou vers le bas dans la liste. Les labels situés plus haut dans la liste ont une priorité plus élevée.
1. Priorisez tous les labels que vous avez créés précédemment. Assurez-vous que les labels de priorité et de gravité plus élevées sont placés plus haut dans la liste que les valeurs inférieures.

![Liste de onze labels à portée limitée priorisés.](img/priority_labels_v16_3.png)

## Créer un tableau de triage des tickets {#create-an-issue-triage-board}

Pour préparer l'arrivée du backlog de tickets, créez un [tableau des tickets](../../user/project/issue_board.md) qui organise les tickets par label. Vous l'utiliserez pour créer rapidement des tickets et leur ajouter des labels en faisant glisser des cartes vers différentes listes.

Pour configurer votre tableau des tickets :

1. Définissez la portée du tableau. Par exemple, créez-en un que vous utiliserez pour attribuer une gravité aux tickets.
1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre projet **Issue triage tutorial**.
1. Sélectionnez **Forfait** > **Tableaux des tickets**.
1. Dans le coin supérieur gauche de la page du tableau des tickets, sélectionnez la liste déroulante avec le nom du tableau actuel.
1. Sélectionnez **Créer un nouveau tableau**.
1. Dans la zone de texte **Intitulé**, saisissez `Issue triage (by severity)`.
1. Laissez la case **Afficher la liste des tickets ouverts** cochée et décochez la case **Afficher la liste des tickets fermés**.
1. Sélectionnez **Créer un tableau**. Vous devriez voir un tableau vide.
1. Créez une liste pour le label `severity::1` :
   1. Dans le coin supérieur droit de la page du tableau des tickets, sélectionnez **Créer une liste**.
   1. Dans la colonne qui s'affiche, depuis la liste déroulante **Valeur**, sélectionnez le label `severity::1`.
   1. Sélectionnez **Ajouter au tableau**.
1. Répétez l'étape précédente pour les labels `severity::2`, `severity::3` et `severity::4`.

Pour l'instant, les listes de votre tableau devraient être vides. Ensuite, vous les alimenterez avec quelques tickets.

## Créer des tickets pour les fonctionnalités {#create-issues-for-features}

Pour suivre les fonctionnalités et les bugs à venir, vous devez créer quelques tickets. Les tickets appartiennent à des projets, mais vous pouvez également les créer directement depuis votre tableau des tickets.

Commencez par créer quelques tickets pour les fonctionnalités planifiées. Vous pouvez créer des tickets pour les bugs au fur et à mesure que vous les découvrez (espérons qu'ils ne soient pas trop nombreux !).

Pour créer un ticket depuis votre tableau **Triage des tickets (par gravité)** :

1. Dans la liste **Ouvrir**, sélectionnez **Créer un nouveau ticket** ({{< icon name="plus" >}}). La liste **Ouvrir** affiche les tickets qui ne correspondent à aucune autre liste du tableau.

   Si vous savez déjà quel label de gravité votre ticket devrait avoir, vous pouvez le créer directement depuis cette liste de labels. Chaque ticket créé depuis une liste de labels recevra ce label.
1. Remplissez les champs :
   - Sous **Intitulé**, saisissez `User registration`.
1. Sélectionnez **Créer un ticket**.
1. Répétez ces étapes pour créer quelques tickets supplémentaires.

   Par exemple, si vous développez une application, créez les tickets suivants :

   - `User registration`
   - `Profile creation`
   - `Search functionality`
   - `Add to favorites`
   - `Push notifications`
   - `Social sharing`
   - `In-app messaging`
   - `Track progress`
   - `Feedback and ratings`
   - `Settings and preferences`

Votre premier tableau de triage des tickets est prêt ! Testez-le en faisant glisser des tickets depuis la liste **Ouvrir** vers l'une des listes de labels pour ajouter l'un des labels de gravité.

![Tableau des tickets avec des tickets sans label et des labels « severity » priorisés pour étiqueter les tickets.](img/triage_board_v16_3.png)

## Étapes suivantes {#next-steps}

Ensuite, vous pouvez :

- Ajuster la façon dont vous utilisez les tableaux des tickets. Voici quelques options :
  - Modifiez votre tableau des tickets actuel pour y ajouter également des listes pour les labels de priorité et de type. Ainsi, le tableau sera plus large et pourrait nécessiter un défilement horizontal.
  - Créez des tableaux des tickets distincts nommés `Issue triage (by priority)` et `Issue triage (by type)`. Ainsi, vous séparerez les différents types de travail de triage, mais vous devrez basculer entre les tableaux.
  - [Configurer des tableaux des tickets pour le transfert entre équipes](../boards_for_teams/_index.md).
- Parcourez les tickets par priorité ou par gravité dans les listes de tickets, [filtrées par chaque label](../../user/project/issues/managing_issues.md#filter-the-list-of-issues). Si disponible, utilisez [l'opérateur de filtre « est l'un de »](../../user/project/issues/managing_issues.md#filter-the-list-of-issues).
- Décomposez les tickets en [tâches](../../user/tasks.md).
- Créez des politiques qui permettent d'automatiser le triage des tickets dans un projet avec le [gem `gitlab-triage`](https://gitlab.com/gitlab-org/ruby/gems/gitlab-triage). Générez des rapports récapitulatifs avec des cartes thermiques comme celle-ci :

  ![Carte thermique diagonale pour les tickets avec les labels « priority » et « severity ».](img/triage_report_v16_3.png)

Pour en savoir plus sur le triage des tickets chez GitLab, consultez [le triage des tickets](https://handbook.gitlab.com/handbook/product-development/how-we-work/issue-triage/) et [les opérations de triage](https://handbook.gitlab.com/handbook/engineering/infrastructure-platforms/developer-experience/triage-operations/).
