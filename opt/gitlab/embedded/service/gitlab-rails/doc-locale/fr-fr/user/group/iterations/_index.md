---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Itérations
description: "Workflow en timeboxing, incréments de programme, cadence et sprints."
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Une itération dans GitLab désigne un workflow en timeboxing qui regroupe les tickets à traiter au cours d'une période spécifique, généralement de 1 à 3 semaines.

Les équipes peuvent utiliser les itérations pour suivre les métriques de vélocité et de volatilité. Pour suivre un même élément sur plusieurs périodes simultanées, vous pouvez utiliser les itérations avec les [jalons](../../project/milestones/_index.md). Créez et gérez diverses [cadences d'itération](#iteration-cadences) dans un groupe.

Par exemple, vous pouvez utiliser :

- Les jalons pour les incréments de programme, qui s'étendent sur 8 à 12 semaines.
- Les itérations pour les sprints, qui s'étendent sur 2 semaines.

Dans GitLab, les itérations sont similaires aux jalons, à quelques différences près :

- Les itérations sont uniquement disponibles pour les groupes.
- Les itérations sont regroupées dans des cadences d'itération.
- Les itérations nécessitent une date de début et une date de fin.
- Les plages de dates des itérations ne peuvent pas se chevaucher dans une cadence d'itération.

## Planification des workflows avec les itérations {#planning-workflows-with-iterations}

Vous pouvez utiliser les itérations pour organiser et suivre le travail sur des périodes fixes. Les exemples suivants montrent comment les itérations aident les équipes à maintenir des cycles de livraison cohérents.

### Planification et exécution des sprints {#sprint-planning-and-execution}

Utilisez les itérations pour planifier et exécuter le travail sur des périodes fixes, et aider les équipes à maintenir une cadence de livraison prévisible. Lorsque les équipes travaillent en sprints, chaque itération fournit un timeboxing clair pour la planification, l'exécution et la livraison des éléments de travail. Pour plus d'informations, consultez le [tutoriel sur l'utilisation de GitLab pour faciliter Scrum](../../../tutorials/scrum_events/_index.md).

Par exemple, lors de l'exécution de sprints de deux semaines, les équipes ont souvent besoin de coordonner plusieurs flux de travail. L'équipe de développement suit l'implémentation dans le sprint en cours, tandis que les chefs de produit préparent les éléments du backlog pour les sprints à venir.

En utilisant les itérations :

- Les équipes peuvent visualiser l'ensemble de leur planning de sprints.
- Le travail est automatiquement reporté d'un sprint à l'autre.
- Les parties prenantes peuvent suivre la progression du sprint via des graphiques d'avancement (burndown chart).
- Les équipes peuvent mesurer la vélocité sur plusieurs sprints.

Cette structure aide les équipes à effectuer le travail de manière cohérente tout en maintenant une visibilité sur la progression.

Lorsque vous configurez des itérations pour les sprints :

- Chaque équipe travaille dans la même cadence d'itération.
- Les équipes peuvent consulter le statut du travail dans les rapports d'itération.
- La planification des sprints devient plus prévisible.

### Cycles de développement rapide {#rapid-development-cycles}

Utilisez les itérations pour prendre en charge des cycles de développement plus courts lorsque votre équipe a besoin de releases fréquentes. Lors de la pratique de méthodologies telles que l'Extreme Programming (XP), les équipes peuvent utiliser des itérations d'une semaine pour maintenir des boucles de rétroaction rapides.

Par exemple, lors de la mise en œuvre de changements rapides, les équipes peuvent déployer en production plusieurs fois par itération. L'équipe suit son travail dans des itérations hebdomadaires tout en conservant la flexibilité de publier dès que le code est prêt.

En utilisant les itérations :

- Les équipes maintiennent des timeboxings structurés.
- Vous pouvez suivre la vélocité de développement.
- Les équipes peuvent adapter la planification en fonction des métriques hebdomadaires.
- Les parties prenantes peuvent voir des progrès concrets chaque semaine.

Cette approche aide les équipes à équilibrer les pratiques agiles avec une planification organisée.

Lorsque vous utilisez les itérations pour des cycles rapides :

- Le travail est organisé en limites hebdomadaires claires.
- Les équipes suivent la progression par incréments plus petits.
- La planification des releases s'aligne sur les limites des itérations.

## Cadences d'itération {#iteration-cadences}

Les cadences d'itération sont des conteneurs pour les itérations et peuvent être utilisées pour automatiser la planification des itérations. Vous pouvez les utiliser pour automatiser la création d'itérations toutes les 1, 2, 3 ou 4 semaines. Vous pouvez également configurer les cadences d'itération pour reporter automatiquement les tickets incomplets vers l'itération suivante.

### Créer une cadence d'itération {#create-an-iteration-cadence}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) du rôle utilisateur minimum de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.

Pour créer une cadence d'itération :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Itérations**.
1. Sélectionnez **Nouvelle cadence d'itération**.
1. Saisissez le titre et la description de la cadence d'itération.

   Pour gérer manuellement la cadence d'itération, décochez la case **Activer la programmation automatique** et ignorez l'étape suivante.
1. Remplissez les champs requis pour utiliser la programmation automatique.
   - Sélectionnez la date de début de l'automatisation de la cadence d'itération. Les itérations sont planifiées pour commencer le même jour de la semaine que le jour de la semaine de la date de début.
   - Dans la liste déroulante **Durée**, sélectionnez le nombre de semaines que doit durer chaque itération.
   - Dans la liste déroulante **Itérations à venir**, sélectionnez le nombre d'itérations futures à planifier en plus de celle en cours.
   - Facultatif. Pour déplacer les tickets incomplets vers l'itération suivante, cochez la case **Activer le report**. À la fin de l'itération en cours, [Automation Bot](#gitlab-automation-bot-user) déplace tous les tickets ouverts vers l'itération suivante. Les tickets sont déplacés à minuit dans le fuseau horaire de l'instance (UTC par défaut). Les administrateurs peuvent modifier le fuseau horaire de l'instance.
1. Sélectionnez **Créer une cadence**. La page de liste des cadences s'ouvre.

Pour gérer manuellement la cadence créée, consultez [créer une itération manuellement](#create-an-iteration-manually).

### Afficher la liste des itérations {#view-the-iterations-list}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Itérations**.

Pour afficher toutes les itérations d'une cadence, classées par date décroissante, sélectionnez cette cadence d'itération. De là, vous pouvez créer une nouvelle itération ou en sélectionner une pour obtenir une vue plus détaillée.

> [!note]
> Si le suivi des tickets d'un projet est [désactivé](../../project/settings/_index.md#configure-project-features-and-permissions), pour afficher la liste des itérations, saisissez son URL. Pour ce faire, ajoutez : `/-/cadences` à l'URL de votre projet ou groupe. Par exemple `https://gitlab.com/gitlab-org/sample-data-templates/sample-gitlab-project/-/cadences`. [Ticket 339009](https://gitlab.com/gitlab-org/gitlab/-/issues/339009) suit l'amélioration de cette fonctionnalité.

### Modifier une cadence d'itération {#edit-an-iteration-cadence}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.

Pour modifier une cadence d'itération :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Itérations**.
1. À droite de la cadence que vous souhaitez modifier, sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) puis sélectionnez **Modifier la cadence**.
1. Modifiez les champs.
   - Lorsque vous utilisez la programmation automatique et modifiez la **Date de début de l'automatisation**, vous devez définir une nouvelle date de début qui ne chevauche pas les itérations en cours ou passées existantes.
   - La modification des **Itérations à venir** est une action non destructive. Par exemple, si dix itérations à venir existent déjà, changer le nombre sous **Itérations à venir** à `2` ne supprime pas les huit itérations à venir existantes.
1. Sélectionnez **Enregistrer les modifications**.

#### Activer et désactiver la programmation automatique pour une cadence d'itération {#turn-on-and-off-automatic-scheduling-for-an-iteration-cadence}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Itérations**.
1. À droite de la cadence pour laquelle vous souhaitez activer ou désactiver la programmation automatique, sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) puis sélectionnez **Modifier la cadence**.
1. Cochez ou décochez la case **Activer la programmation automatique**.
1. Si vous activez la programmation automatique, renseignez les champs requis **Date de début de l'automatisation**, **Durée** et **Itérations à venir**.
   - Pour la **Date de début de l'automatisation**, vous pouvez sélectionner n'importe quelle date qui ne chevauche pas les itérations ouvertes existantes. Si vous avez des itérations à venir, la programmation automatique les ajuste de manière appropriée pour correspondre à la durée choisie.
1. Sélectionnez **Enregistrer les modifications**.

#### Exemple : activer la programmation automatique pour une cadence d'itération manuelle {#example-turn-on-automatic-scheduling-for-a-manual-iteration-cadence}

Supposons que nous sommes vendredi 15 avril et que vous avez trois itérations dans une cadence d'itération manuelle :

- Lundi 4 avril - Vendredi 8 avril (clôturée)
- Mardi 12 avril - Vendredi 15 avril (en cours)
- Mardi 3 mai - Vendredi 6 mai (à venir)

La **Date de début de l'automatisation** la plus précoce que vous pouvez choisir dans ce scénario est le samedi 16 avril, car le 15 avril chevauche l'itération en cours.

Si vous sélectionnez le lundi 18 avril comme date de début de l'automatisation pour automatiser la planification des itérations chaque semaine jusqu'à deux itérations à venir, après la conversion vous avez les itérations suivantes :

- Lundi 4 avril - Vendredi 8 avril (clôturée)
- Mardi 12 avril - Vendredi 15 avril (en cours)
- Lundi 18 avril - Dimanche 24 avril (à venir)
- Lundi 25 avril - Dimanche 1er mai (à venir)

Votre itération à venir existante « Mardi 12 avril - Vendredi 15 avril » est remplacée par « 18 avril - Dimanche 24 avril ».

Une itération à venir supplémentaire « 25 avril - Dimanche 1er mai » est planifiée pour satisfaire l'exigence qu'au moins deux itérations à venir soient planifiées.

### Supprimer une cadence d'itération {#delete-an-iteration-cadence}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) du rôle utilisateur minimum de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.

La suppression d'une cadence d'itération supprime également toutes les itérations de cette cadence.

Pour supprimer une cadence d'itération :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Itérations**.
1. À droite de la cadence que vous souhaitez supprimer, sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) puis sélectionnez **Supprimer la cadence**.
1. Sélectionnez **Supprimer la cadence**.

### Utilisateur GitLab Automation Bot {#gitlab-automation-bot-user}

Lorsque le report des itérations est activé, à la fin de l'itération en cours, tous les tickets ouverts sont déplacés vers l'itération suivante.

Les itérations sont modifiées par l'utilisateur spécial GitLab Automation Bot, que vous pouvez voir dans les [notes système](../../project/system_notes.md) du ticket. Cet utilisateur n'est pas un [utilisateur facturable](../../../subscriptions/manage_seats.md#criteria-for-non-billable-users), il ne compte donc pas dans la limite de licences.

Sur GitLab.com, il s'agit de l'utilisateur `automation-bot1`.

## Créer une itération manuellement {#create-an-iteration-manually}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) du rôle utilisateur minimum de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Lorsque la programmation automatique est activée pour une cadence d'itération, les itérations sont créées selon le planning. Si vous désactivez cette option, vous pouvez créer des itérations manuellement.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.
- Il doit y avoir au moins une cadence d'itération dans le groupe et la [programmation automatique doit être désactivée](#turn-on-and-off-automatic-scheduling-for-an-iteration-cadence) pour la cadence d'itération.

Pour créer une itération :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Itérations**.
1. À droite de la cadence dans laquelle vous souhaitez créer une itération, sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) puis sélectionnez **Ajouter une itération**.
1. Remplissez les champs.
1. Sélectionnez **Créer une itération**. La page de détails de l'itération s'ouvre.

## Modifier une itération {#edit-an-iteration}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) du rôle utilisateur minimum de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.

Pour modifier une itération :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Itérations** et sélectionnez une cadence d'itération.
1. Sélectionnez l'itération que vous souhaitez modifier. La page de détails de l'itération s'ouvre.
1. Dans le coin supérieur droit, sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) puis sélectionnez **Modifier**.
1. Modifiez les champs :
   - Vous pouvez modifier le **Intitulé**, la **Date de début** et la **Date d'échéance** uniquement si la [programmation automatique est désactivée](#turn-on-and-off-automatic-scheduling-for-an-iteration-cadence) pour la cadence d'itération.
1. Sélectionnez **Enregistrer les modifications**.

## Supprimer une itération {#delete-an-iteration}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) du rôle utilisateur minimum de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour un groupe.
- [La programmation automatique doit être désactivée](#turn-on-and-off-automatic-scheduling-for-an-iteration-cadence) pour la cadence d'itération.

Pour supprimer une itération :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Itérations** et sélectionnez une cadence d'itération.
1. Sélectionnez l'itération que vous souhaitez modifier. La page de détails de l'itération s'ouvre.
1. Dans le coin supérieur droit, sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) puis sélectionnez **Supprimer**.
1. Sélectionnez **Supprimer**.

## Rapport d'itération {#iteration-report}

Vous pouvez suivre la progression d'une itération en consultant les rapports d'itération. Un rapport d'itération affiche la liste de tous les tickets assignés à une itération et leur statut.

Le rapport montre également une répartition du nombre total de tickets dans une itération. Les rapports d'itération ouverts affichent un résumé des tickets terminés, non commencés et en cours. Les rapports d'itération clôturés indiquent le nombre total de tickets terminés avant la date d'échéance.

### Afficher un rapport d'itération {#view-an-iteration-report}

Pour afficher un rapport d'itération :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Itérations** et sélectionnez une cadence d'itération.
1. Sélectionnez une itération.

### Graphiques d'avancement (burndown et burnup) des itérations {#iteration-burndown-and-burnup-charts}

Le rapport d'itération inclut des [graphiques d'avancement (burndown et burnup)](../../project/milestones/burndown_and_burnup_charts.md), similaires à ceux qui apparaissent lors de l'affichage d'un [jalon](../../project/milestones/_index.md) :

- Les graphiques d'avancement (burndown chart) aident à suivre la progression vers l'achèvement de la portée totale.
- Les graphiques d'avancement (burnup chart) suivent le nombre total quotidien et le poids des tickets ajoutés et terminés dans un timeboxing donné.

#### Afficher les graphiques d'itération limités aux sous-groupes ou aux projets {#view-iteration-charts-scoped-to-subgroups-or-projects}

Affichez les graphiques d'avancement (burndown et burnup) pour les itérations créées pour un groupe dans l'un de ses sous-groupes ou projets. Dans ce cas, les graphiques comptabilisent uniquement les tickets appartenant au sous-groupe ou au projet.

Par exemple, supposons qu'un groupe possède deux projets nommés `Project 1` et `Project 2`. Chaque projet possède un seul ticket assigné à la même itération du groupe.

Un rapport d'itération généré pour le groupe affiche le nombre de tickets pour tous les projets du groupe :

- Terminés : 0 sur 2
- Incomplets : 0 sur 2
- Non commencés : 2 sur 2
- Total des tickets dans le graphique d'avancement (burndown chart) : 2
- Total des tickets dans le graphique d'avancement (burnup chart) : 2

Un rapport d'itération généré pour `Project 1` affiche uniquement les tickets appartenant à ce projet :

- Terminés : 0 sur 1
- Incomplets : 0 sur 1
- Non commencés : 1 sur 1
- Total des tickets dans le graphique d'avancement (burndown chart) : 1
- Total des tickets dans le graphique d'avancement (burnup chart) : 1

### Regrouper les tickets par label {#group-issues-by-label}

Regroupez la liste des tickets par label pour afficher les tickets appartenant à votre équipe et mieux comprendre la portée attribuable à chaque label.

Pour regrouper les tickets par label :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Itérations** et sélectionnez une cadence d'itération.
1. Sélectionnez une itération.
1. Dans la liste déroulante **Regrouper par**, sélectionnez **Label**.
1. Dans la liste déroulante **Filtrer par label**, sélectionnez les labels par lesquels vous souhaitez regrouper.
1. Sélectionnez n'importe quelle zone en dehors de la liste déroulante de labels. La page est maintenant regroupée par les labels sélectionnés.

## Sujets connexes {#related-topics}

- [Ajouter un ticket à une itération](../../project/issues/managing_issues.md#add-an-issue-to-an-iteration)
- [Tutoriel : utiliser GitLab pour exécuter une itération Agile](../../../tutorials/agile_sprint/_index.md)
