---
stage: Analytics
group: Optimize
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Données d'analyse des contributions"
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les données d'analyse des contributions fournissent une vue d'ensemble des [événements de contribution](../../profile/contributions_calendar.md#user-contribution-events) réalisés par les membres de votre groupe au cours de la semaine, du mois ou des trois derniers mois. Des graphiques à barres interactifs et un tableau détaillé affichent les événements de contribution (événements push, tickets et merge requests) par membre du groupe.

![Graphique à barres des données d'analyse des contributions indiquant le nombre de push par utilisateur pour la semaine dernière.](img/contribution_analytics_push_v17_7.png)

Utilisez les données d'analyse des contributions pour obtenir des informations sur l'activité de l'équipe et les performances individuelles, et exploitez ces informations pour :

- Équilibrage de la charge de travail : analysez les contributions de votre groupe sur une période donnée et identifiez les membres du groupe qui sont très performants ou qui pourraient bénéficier d'un soutien supplémentaire.
- Collaboration d'équipe : évaluez l'équilibre des contributions, comme les push de code par rapport aux révisions ou aux approbations, afin de garantir des pratiques de développement collaboratif.
- Opportunités de formation : identifiez les domaines dans lesquels les membres de l'équipe pourraient bénéficier d'un mentorat ou d'une formation, par exemple en cas de faibles taux d'approbation de merge requests ou de résolution de tickets.
- Évaluation rétrospective : intégrez les données d'analyse des contributions dans les rétrospectives pour évaluer dans quelle mesure l'équipe a atteint ses objectifs et déterminer où des ajustements pourraient être nécessaires.

## Suivi {#tracking}

Les données d'analyse des contributions sont basées sur les événements push, car ils offrent une vue plus fiable des contributions que les commits uniques. Le comptage des commits uniques peut entraîner des doublons lorsque des commits sont poussés sur plusieurs branches. En suivant plutôt les événements push, GitLab garantit que chaque contribution est comptabilisée avec précision.

Par exemple, un utilisateur pousse trois commits vers la branche A en un seul push. Ensuite, l'utilisateur pousse deux de ces commits de la branche A vers la branche B. GitLab enregistre cinq commits, bien que l'utilisateur ait effectué trois commits uniques.

## Afficher les données d'analyse des contributions {#view-contribution-analytics}

Pour afficher les données d'analyse des contributions :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des contributions**.
1. Facultatif. Filtrez les résultats :

   - Pour afficher les données d'analyse des contributions pour la semaine, le mois ou les trois derniers mois, sélectionnez l'un des trois onglets. La période sélectionnée s'applique à tous les graphiques et au tableau.
   - Pour effectuer un zoom sur un graphique à barres afin d'afficher uniquement un sous-ensemble de membres du groupe, sélectionnez les curseurs ({{< icon name="status-paused" >}}) sous le graphique et faites-les glisser le long de l'axe.
   - Pour trier le tableau des contributions par colonne, sélectionnez l'en-tête de colonne ou le chevron ({{< icon name="chevron-lg-down" >}} pour l'ordre décroissant, {{< icon name="chevron-lg-up" >}} pour l'ordre croissant).

1. Facultatif. Pour afficher les contributions d'un membre du groupe, effectuez l'une des opérations suivantes :

   - Dans les graphiques à barres **Données d'analyse des contributions**, survolez la barre portant le nom du membre.
   - Dans le tableau **Contributions par membre du groupe**, sélectionnez le nom du membre. Le profil GitLab du membre s'affiche et vous pouvez explorer son [calendrier des contributions](../../profile/contributions_calendar.md).

Pour récupérer des métriques sur les contributions des utilisateurs, vous pouvez également utiliser l'[API GraphQL](../../../api/graphql/reference/_index.md#groupcontributions).

## Données d'analyse des contributions avec ClickHouse {#contribution-analytics-with-clickhouse}

Sur GitLab.com, les données d'analyse des contributions s'exécutent via le cluster ClickHouse Cloud. Sur GitLab Self-Managed, lorsque vous configurez l'intégration ClickHouse, la table ClickHouse `events` est automatiquement renseignée à partir de la table PostgreSQL `events`. Ce processus peut prendre un certain temps pour les installations de grande taille. Une fois la table entièrement synchronisée, les nouveaux événements deviennent disponibles dans ClickHouse avec un délai d'environ trois minutes.

Pour plus d'informations, consultez :

- [Instructions d'intégration ClickHouse](../../../integration/clickhouse.md)
- [Utilisation de ClickHouse chez GitLab](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/clickhouse_usage/)
