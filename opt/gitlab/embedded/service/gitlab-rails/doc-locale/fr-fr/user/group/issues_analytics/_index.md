---
stage: Analytics
group: Optimize
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Données d'analyse des tickets"
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les données d'analyse des tickets fournissent des informations sur les tickets créés chaque mois dans un groupe ou un projet. Un graphique à barres illustre le nombre de tickets ouverts et fermés chaque mois. Un tableau affiche les 100 premiers tickets basés sur les filtres globaux de la page, avec les détails suivants pour chaque ticket :

- Nom
- Âge
- Statut
- Jalon
- Itération
- Poids
- Date d'échéance
- Responsable
- Auteur

![Graphique à barres et tableau des données d'analyse des tickets affichant les tickets créés dans un groupe.](img/issue_analytics_v17_8.png)

## Afficher les données d'analyse des tickets {#view-issue-analytics}

Pour afficher les données d'analyse des tickets :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse des tickets**. Pour afficher le nombre total de tickets pour un mois, survolez une barre.
1. Facultatif. Pour filtrer les résultats, dans la zone de texte **Rechercher ou filtrer les résultats**, saisissez vos critères :

   - Auteur
   - Responsable
   - Jalon
   - Label
   - Ma réaction
   - Poids

1. Facultatif. Pour modifier le nombre total de mois affichés, ajoutez le paramètre `months_back=n` à l'URL. Par exemple, `https://gitlab.com/groups/gitlab-org/-/issues_analytics?months_back=15` affiche un graphique avec les données des 15 derniers mois pour le groupe GitLab.org.

Vous pouvez également accéder aux données d'analyse des tickets depuis le [tableau de bord Value Streams](../../analytics/value_streams_dashboard.md) via le rapport d'exploration **Nouveaux tickets**.

### Données d'analyse des tickets enrichies {#enhanced-issue-analytics}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les données d'analyse des tickets enrichies affichent la métrique supplémentaire `Issues closed`, qui représente le nombre total de tickets résolus dans votre groupe sur une période sélectionnée. Vous pouvez utiliser cette métrique pour améliorer le délai de traitement global et la valeur livrée à vos clients.

![Graphique à barres et tableau des données d'analyse des tickets enrichies affichant les tickets ouverts et fermés dans un groupe.](img/enhanced_issue_analytics_v17_8.png)
