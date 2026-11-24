---
stage: Analytics
group: Optimize
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Affichez l'impact de votre utilisation de GitLab Duo Agent Platform dans votre organisation."
title: "Tableau de bord d'impact de GitLab Duo Agent Platform"
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com
- Statut : version bêta

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/632113) dans GitLab 19.5.

{{< /history >}}

Cette fonctionnalité est en [version bêta](../../policy/development_stages_support.md) privée. Pour tester cette fonctionnalité, vous devez [demander l'accès](https://gitlab.com/gitlab-org/gitlab/-/work_items/632123). Partagez vos commentaires dans le [ticket 632127](https://gitlab.com/gitlab-org/gitlab/-/work_items/632127).

Le tableau de bord d'impact de GitLab Duo Agent Platform indique comment votre organisation utilise Agent Platform et ce que cette utilisation coûte. Le tableau de bord affiche des données agrégées de vos groupes et projets sous forme de métriques d'adoption et d'engagement des utilisateurs, d'activité de travail et de consommation de crédits.

Utilisez ce tableau de bord pour :

- Mesurer le volume des workflows Agent Platform dans votre organisation.
- Suivre la consommation de crédits par modèle, type de flow et groupe ou projet.
- Surveiller les tendances d'adoption des utilisateurs, notamment la rétention, le taux d'attrition et les niveaux d'activité.
- Identifier les projets et groupes qui utilisent le plus activement Agent Platform.

## Vue d'ensemble {#overview}

L'onglet **Vue d'ensemble** affiche un résumé de haut niveau de l'utilisation d'Agent Platform pour la portée et la période sélectionnées.

- **Projets actifs** : nombre de projets avec au moins une session Agent Platform.
- **Utilisateurs actifs** : nombre d'utilisateurs avec au moins une session Agent Platform.
- **Sessions terminées** : nombre de sessions Agent Platform créées qui se sont terminées.
- **Crédits consommés** : nombre de crédits consommés par les sessions Agent Platform.
- **Destination des crédits** : nombre de crédits consommés par chaque type de flow Agent Platform.

## Adoption {#adoption}

L'onglet **Adoption** affiche des métriques sur la façon dont les utilisateurs adoptent les fonctionnalités d'Agent Platform pour la portée et la période sélectionnées.

La section **Utilisateurs** affiche les métriques suivantes :

- **Nombre total d'utilisateurs** : nombre d'utilisateurs avec au moins une session Agent Platform.
- **Nouveaux et récurrents** : nombre et pourcentage de nouveaux utilisateurs et d'utilisateurs récurrents ayant au moins une session Agent Platform. Les utilisateurs récurrents sont des utilisateurs qui ont eu une session Agent Platform au cours de la période précédente de même durée.
- **Utilisateurs par activité** : nombre d'utilisateurs par type de flow Agent Platform. Un utilisateur de plusieurs types de flows est comptabilisé dans chaque catégorie.

La section **Engagement** affiche les métriques suivantes :

- **Utilisateurs multi-activités** : nombre d'utilisateurs avec des sessions pour plusieurs types de flows Agent Platform.
- **Abandon** : nombre d'utilisateurs actifs un seul jour au cours de la période précédente et qui ne sont pas revenus au cours de la période sélectionnée.
- **Sessions par niveau et principales capacités** : nombre de sessions par niveau d'utilisateur pour les cinq capacités Agent Platform les plus utilisées.

La section **Niveaux d'adoption** affiche les métriques suivantes :

- **Utilisateurs par niveau** : nombre d'utilisateurs avec au moins une session Agent Platform.
- **Total des sessions** : nombre de sessions Agent Platform par types de flows et agents.
- **Part des utilisateurs vs part des sessions** : nombre d'utilisateurs et de sessions par niveau d'utilisateur.
- **Intensité des sessions par niveau** : nombre d'utilisateurs et de sessions par niveau d'utilisateur.
- **Comparaison des groupes et projets** : nombre d'utilisateurs et de crédits utilisés par groupe et projet.

## Travail {#work}

L'onglet **Travail** affiche des métriques sur la façon dont les fonctionnalités d'Agent Platform sont utilisées pour la portée et la période sélectionnées.

La section **Résumé de l'activité** affiche les métriques suivantes :

- **Sessions** : nombre total de sessions Agent Platform.
- **Sessions par activité** : nombre de sessions Agent Platform par activité.
- **Sessions dans le temps** : nombre de sessions Agent Platform créées, empilées par type de flow.

La section **Temps de cycle des merge requests** affiche les métriques suivantes :

- **Temps de cycle : créées par Duo** : temps médian et 75e percentile en jours entre l'ouverture et la fusion des merge requests créées par GitLab Duo. Inclut le nombre de merge requests fusionnées.
- **Temps de cycle : toutes les autres** : temps médian et 75e percentile en jours entre l'ouverture et la fusion des merge requests qui n'ont pas été créées par GitLab Duo et dont les auteurs sont des personnes. Inclut le nombre de merge requests fusionnées.

Une merge request est créée par GitLab Duo lorsqu'une session Agent Platform enregistre qu'elle a ouvert la merge request, quel qu'en soit l'auteur. Une merge request à partir de laquelle une session a été démarrée, par exemple pour la réviser, est comptabilisée comme n'ayant pas été créée par GitLab Duo.

Les métriques **toutes les autres** excluent les merge requests créées par des bots, des comptes de service et d'autres utilisateurs non humains, afin de comparer GitLab Duo avec le travail effectué par des personnes.

La section **Volume de merge requests** affiche les métriques suivantes :

- **Ouvertes par Duo** : nombre de merge requests créées par GitLab Duo.
- **Fusionnées : créées par Duo** : nombre de merge requests fusionnées créées par GitLab Duo.
- **Fusionnées : toutes les autres** : nombre de merge requests fusionnées qui n'ont pas été créées par GitLab Duo et dont les auteurs sont des personnes.
- **Merge requests créées par Duo par statut** : nombre de merge requests créées par GitLab Duo avec le statut actuel sur la période sélectionnée.

La section **Résultats des capacités** affiche les métriques suivantes :

- **Sessions de revue de code agentique** : nombre de sessions du flow Code Review.
- **Revues demandées** : nombre de revues demandées à Code Review.
- **Revues publiées** : nombre de revues publiées par Code Review.
- **Avec commentaires** : nombre de revues publiées par Code Review avec au moins un commentaire.
- **Sans commentaires** : nombre de revues publiées par Code Review sans commentaire.
- **Résultats de la revue de code agentique dans le temps** : nombre de revues demandées et publiées par Code Review avec et sans commentaires sur la période sélectionnée.
- **Sessions Developer agentique** : nombre de sessions du flow Developer.
- **Processus terminé** : nombre de sessions terminées du flow Developer.
- **En pause** : nombre de sessions en pause du flow Developer.
- **Annulée** : nombre de sessions annulées du flow Developer.
- **Échec** : nombre de sessions en échec du flow Developer.
- **Sessions Developer agentique dans le temps** : nombre de sessions terminées, en pause, annulées et en échec du flow Developer sur la période sélectionnée.
- **Sessions Fix Pipeline agentique** : nombre de sessions du flow Fix Pipeline.
- **Suggestions publiées** : nombre de suggestions de correction publiées par GitLab Duo sur les pipelines en échec.
- **Suggestions appliquées** : nombre de suggestions de correction appliquées publiées par GitLab Duo sur les pipelines en échec.
- **Suggestions Fix Pipeline agentique dans le temps** : nombre de suggestions de correction publiées par GitLab Duo et appliquées sur les pipelines en échec sur la période sélectionnée.
- **Sessions SAST agentique** : nombre de sessions du flow SAST agentique.
- **Merge requests créées après la détection d'une vulnérabilité** : nombre de merge requests créées par les sessions Resolve SAST Vulnerability.
- **Sessions SAST agentique dans le temps** : nombre de sessions du flow SAST créées et de merge requests créées dans les sessions.

## Dépenses {#spend}

L'onglet **Dépenses** affiche des métriques sur l'ampleur de l'utilisation des fonctionnalités d'Agent Platform pour la portée et la période sélectionnées.

- **Crédits par modèle, par capacité** : nombre de crédits utilisés par différents modèles, empilés par capacité Agent Platform.
- **Crédits** : nombre total de crédits consommés.
- **Chat** : nombre de crédits consommés par les sessions Chat.
- **Crédits dans le temps** : nombre de crédits utilisés au fil du temps, empilés par capacité.

## Afficher le tableau de bord {#view-the-dashboard}

Prérequis :

- Le rôle Propriétaire pour le groupe afin d'afficher les données d'utilisation des crédits.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** > **Explorer**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Intelligence**.
1. Sélectionnez **DAP Impact**.
1. Sélectionnez les onglets pour afficher les différentes métriques.
1. Facultatif. Par défaut, le tableau de bord affiche les métriques du groupe principal au cours des 30 derniers jours. Vous pouvez filtrer les résultats :

   - Pour afficher les métriques de groupes ou projets spécifiques, dans l'onglet correspondant, sélectionnez les groupes ou projets que vous souhaitez afficher dans la liste déroulante **Portée**.
   - Pour afficher les métriques d'une période différente, dans l'onglet correspondant, sélectionnez la période souhaitée dans la liste déroulante **Période**.
   - Pour réinitialiser la portée et la période sélectionnées, sélectionnez **Réinitialiser**.

1. Pour analyser les métriques affichées avec GitLab Duo, sélectionnez **Analyser avec Duo**.
