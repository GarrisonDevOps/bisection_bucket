---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Visualisez la progression des jalons avec des graphiques d'avancement (burndown chart) et des graphiques d'avancement (burnup chart) pour suivre les tickets restants et terminés au fil du temps."
title: "Graphiques d'avancement (burndown et burnup)"
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Le graphique d'avancement (burndown chart)](#burndown-charts) et le [graphique d'avancement (burnup chart)](#burnup-charts) indiquent la progression vers la réalisation d'un jalon. Les graphiques d'avancement (burndown charts) affichent les tickets restants (burndown) au cours d'un [jalon](_index.md) de projet. Les graphiques d'avancement (burnup charts) affichent le nombre total de tickets par rapport aux tickets terminés.

![Graphique d'avancement (burndown et burnup), montrant la progression du jalon avec le graphique burndown affichant les tickets restants au fil du temps et le graphique burnup montrant le total par rapport aux tickets terminés.](img/burndown_and_burnup_charts_v15_3.png)

## Similitudes et différences {#similarities-and-differences}

Les graphiques d'avancement (burndown et burnup) partagent certaines caractéristiques générales. Les graphiques d'avancement (burndown et burnup) :

- Affichent le nombre total de tickets pour chaque jour du jalon en cours.
- Disposent d'un [bouton bascule](#switch-between-number-of-issues-and-issue-weight) entre le nombre total de tickets ou le [poids](../../work_items/weight.md) total des tickets pour chaque jour du jalon.

Les différences entre les graphiques d'avancement (burndown et burnup) sont les suivantes :

- Les graphiques d'avancement (burnup charts) contiennent une ligne distincte représentant les tickets terminés au cours d'un jalon.
- Les graphiques d'avancement (burnup charts) reflètent la différence entre un ticket déplacé vers un autre jalon (la ligne des tickets **Total** descend) et un ticket fermé (la ligne des tickets **Total** reste inchangée).
- Les graphiques d'avancement (burndown charts) mesurent « le nombre total de tickets moins les tickets fermés » pour chaque jour, tandis que les graphiques d'avancement (burnup charts) mesurent le nombre total de tickets (ouverts et fermés) séparément des tickets résolus pour chaque jour.

## Basculer entre le nombre de tickets et le poids des tickets {#switch-between-number-of-issues-and-issue-weight}

Pour basculer entre les deux paramètres, sélectionnez **Tickets** ou **Poids des tickets** au-dessus des graphiques.

Lors du tri par poids, assurez-vous que tous vos tickets ont un poids assigné, car les tickets sans poids ne sont pas représentés dans les totaux de poids restants.

## Quand utiliser les graphiques d'avancement (burndown et burnup) {#when-to-use-burndown-and-burnup-charts}

Les graphiques d'avancement (burndown et burnup) fournissent des informations précieuses pour le suivi de la progression des jalons. Leur utilisation dépend de [la façon dont vous structurez vos jalons](_index.md) dans votre workflow.

Ces graphiques aident les équipes à :

- Visualiser la progression en temps réel tout au long d'une période de jalon.
- Identifier les retards potentiels tôt en comparant la progression réelle à la progression idéale.
- Communiquer le statut aux parties prenantes avec des données visuelles claires.
- Prendre des décisions basées sur les données concernant l'allocation des ressources et la priorisation.

Utilisez les graphiques d'avancement (burndown charts) pour vous concentrer sur le travail restant. Utilisez les graphiques d'avancement (burnup charts) pour suivre à la fois le travail terminé et les changements de portée au fil du temps. Les graphiques d'avancement (burnup charts) vous aident à surveiller le glissement de portée (ajouts non contrôlés à la portée d'un projet) en affichant des pics dans le total des tickets du graphique.

## Graphiques d'avancement (burndown charts) {#burndown-charts}

Les graphiques d'avancement (burndown charts) affichent le nombre de tickets au cours d'un jalon.

![Graphique d'avancement (burndown chart), montrant une tendance à la baisse des tickets restants sur la durée du jalon.](img/burndown_chart_v15_3.png)

En un coup d'œil, vous voyez l'état actuel de l'avancement d'un jalon donné. Sans ces graphiques, vous devriez organiser les données du jalon et les tracer vous-même pour avoir la même vision de la progression.

GitLab les trace pour vous et les présente dans un graphique clair et soigné.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une présentation générale, consultez la démonstration vidéo sur [Mapping work versus time with burndown charts](https://www.youtube.com/watch?v=zJU2MuRChzs).

Pour afficher le graphique d'avancement (burndown chart) d'un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Jalons**.
1. Sélectionnez un jalon dans la liste.

Pour afficher le graphique d'avancement (burndown chart) d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Jalons**.
1. Sélectionnez un jalon dans la liste.

### Fonctionnement des graphiques d'avancement (burndown charts) {#how-burndown-charts-work}

Un graphique d'avancement (burndown chart) est disponible pour chaque jalon de projet ou de groupe auquel une **date de début** et une **date d'échéance** ont été attribuées.

> [!note]
> Vous pouvez [promouvoir les jalons de projet](_index.md#promote-a-project-milestone-to-a-group-milestone) en jalons de groupe et continuer à afficher le **graphique d'avancement (burndown chart)** pour ceux-ci, dans le respect des limitations de licence.

Le graphique indique la progression du projet tout au long de ce jalon (pour les tickets qui lui sont assignés).

En particulier, il indique le nombre de tickets ouverts ou encore ouverts pour un jour donné dans la période correspondant au jalon.

Vous pouvez également activer le graphique d'avancement (burndown chart) pour afficher le [poids cumulé des tickets ouverts](#switch-between-number-of-issues-and-issue-weight) pour un jour donné.

### Graphiques d'avancement (burndown charts) fixes {#fixed-burndown-charts}

Pour les jalons créés avant GitLab 13.6, les graphiques d'avancement (burndown charts) disposent d'un bouton bascule supplémentaire pour passer entre les vues Héritage et Fixe.

| Héritage | Fixe |
| ----- | ----- |
| ![Graphique d'avancement héritage (burndown chart), montrant une ligne à tendance descendante représentant la diminution des tickets restants.](img/burndown_chart_legacy_v13_6.png) | ![Graphique d'avancement fixe (burndown chart), montrant un pic lorsque de nombreux tickets ont été ajoutés au jalon.](img/burndown_chart_fixed_v13_6.png) |

Les graphiques d'avancement **fixes (Fixed burndown)** suivent l'historique complet de l'activité du jalon, depuis sa création jusqu'à son expiration. Une fois la date d'échéance du jalon dépassée, les tickets supprimés du jalon n'affectent plus le graphique.

Les graphiques d'avancement **héritage (Legacy burndown)** suivent la date de création des tickets et leur dernière date de fermeture, et non leur historique complet. Pour chaque jour, un graphique d'avancement héritage (legacy burndown chart) prend le nombre de tickets ouverts et les tickets créés ce jour-là, puis soustrait le nombre de tickets fermés ce jour-là. Les tickets créés et assignés à un jalon avant sa date de début (et restant ouverts à la date de début) sont considérés comme ayant été ouverts à la date de début. Par conséquent, lorsque la date de début du jalon est modifiée, le nombre de tickets ouverts chaque jour peut changer. Les tickets rouverts sont considérés comme ayant été ouverts le jour suivant leur dernière fermeture.

## Graphiques d'avancement (burnup charts) {#burnup-charts}

Les graphiques d'avancement (burnup charts) affichent le travail assigné et terminé pour un jalon.

![Graphique d'avancement (burnup chart), affichant deux lignes avec une ligne bleue représentant le total des tickets restant relativement stable et une ligne orange représentant les tickets terminés augmentant régulièrement.](img/burnup_chart_v15_3.png)

Pour afficher le graphique d'avancement (burnup chart) d'un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Jalons**.
1. Sélectionnez un jalon dans la liste.

Pour afficher le graphique d'avancement (burnup chart) d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Jalons**.
1. Sélectionnez un jalon dans la liste.

### Fonctionnement des graphiques d'avancement (burnup charts) {#how-burnup-charts-work}

Les graphiques d'avancement (burnup charts) comportent des lignes distinctes pour le travail total et le travail terminé :

- La ligne **Total** reflète les changements apportés à la portée d'un jalon en mesurant le nombre de tickets assignés à ce jalon.
- La ligne **Processus terminé** mesure le nombre de tickets fermés pour ce jalon.

Lorsqu'un ticket ouvert est déplacé vers un autre jalon, la ligne **Total** descend, mais la ligne **Processus terminé** reste inchangée. La ligne **Processus terminé** reste inchangée car elle ne suit que les tickets fermés.

Lorsqu'un ticket est fermé, la ligne **Total** reste inchangée et la ligne **Processus terminé** monte.

## Cumul des poids {#roll-up-weights}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/381879) dans GitLab 17.1 [avec le feature flag](../../../administration/feature_flags/_index.md) `rollup_timebox_chart`. Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> Sur GitLab Self-Managed, cette fonctionnalité n'est pas disponible par défaut. Pour plus d'informations, consultez l'historique. Cette fonctionnalité est disponible à des fins de test, mais n'est pas prête pour une utilisation en production.

Avec les [tâches](../../tasks.md), une planification plus granulaire est possible. Si cette fonctionnalité est activée, le poids des tickets qui ont des tâches est dérivé des tâches du même jalon. Les tickets avec des tâches ne sont pas comptabilisés séparément dans les graphiques d'avancement (burndown ou burnup charts).

Comment le poids des tickets est comptabilisé dans les graphiques :

- Si les tâches d'un ticket n'ont pas de poids assigné, le poids du ticket est utilisé à la place.
- Si un ticket comporte plusieurs tâches et que certaines ont été terminées lors d'une itération précédente, seules les tâches de cette itération sont affichées et comptabilisées.
- Si une tâche est directement assignée à une itération, sans son parent, elle constitue l'élément de niveau supérieur et contribue avec son propre poids. Le ticket parent n'est pas affiché.

### Exemples de cumul de poids {#weight-rollup-examples}

**Exemple 1**

- Le ticket a un poids de 5 et est assigné au Jalon 2.
- La Tâche 1 a un poids de 2 et est assignée au Jalon 1.
- La Tâche 2 a un poids de 2 et est assignée au Jalon 2.
- La Tâche 3 a un poids de 2 et est assignée au Jalon 2.

Les graphiques pour le Jalon 1 afficheraient la Tâche 1 avec un poids de 2.

Les graphiques pour le Jalon 2 afficheraient le Ticket avec un poids de 4.

**Exemple 2**

- Le ticket a un poids de 5 et est assigné au Jalon 2.
- La Tâche 1 est assignée au Jalon 1 sans aucun poids.
- La Tâche 2 est assignée au Jalon 2 sans aucun poids.
- La Tâche 3 est assignée au Jalon 2 sans aucun poids.

Les graphiques pour le Jalon 1 afficheraient la Tâche 1 avec un poids de 0.

Les graphiques pour le Jalon 2 afficheraient le Ticket avec un poids de 5.

**Exemple 3**

- Le ticket est assigné au Jalon 2 sans aucun poids.
- La Tâche 1 a un poids de 2 et est assignée au Jalon 1
- La Tâche 2 a un poids de 2 et est assignée au Jalon 2
- La Tâche 3 a un poids de 2 et est assignée au Jalon 2

Les graphiques pour le Jalon 1 afficheraient la Tâche 1 avec un poids de 2.

Les graphiques pour le Jalon 2 afficheraient le Ticket avec un poids de 4.

## Dépannage {#troubleshooting}

### Les graphiques d'avancement (burndown et burnup) n'affichent pas le statut correct des tickets {#burndown-and-burnup-charts-do-not-show-the-correct-issue-status}

Une limitation de ces graphiques est que [les jours sont dans le fuseau horaire UTC](https://gitlab.com/gitlab-org/gitlab/-/issues/267967).

Cela peut entraîner des inexactitudes dans les graphiques pour d'autres fuseaux horaires. Par exemple :

- Tous les tickets d'un jalon sont enregistrés comme fermés au plus tard le dernier jour.
- Un ticket a été fermé le dernier jour à 18h00 PST (heure du Pacifique), soit UTC-7.
- Le journal d'activité du ticket affiche l'heure de fermeture à 18h00 le dernier jour du jalon.
- Les graphiques tracent l'heure en UTC, donc pour ce ticket, l'heure de fermeture est 1h00 du matin le jour suivant.
- Les graphiques indiquent que le jalon est incomplet et qu'il manque un ticket fermé.
