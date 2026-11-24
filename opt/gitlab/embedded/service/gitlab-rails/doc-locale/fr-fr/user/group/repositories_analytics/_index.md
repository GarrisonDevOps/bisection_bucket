---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Données d'analyse du dépôt pour les groupes"
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les données d'analyse du dépôt pour les groupes fournissent des données de couverture de test pour tous les projets d'un groupe.

Vous pouvez utiliser les données d'analyse du dépôt de groupe pour :

- Surveiller les tendances de couverture du code dans tous les projets d'un groupe.
- Suivre le nombre total de projets et de jobs qui génèrent des rapports de couverture.
- Télécharger les données de couverture historiques à des fins d'analyse.

La prise en charge des sous-groupes est proposée dans le [ticket 273527](https://gitlab.com/gitlab-org/gitlab/-/issues/273527).

## Afficher les données d'analyse du dépôt de groupe {#view-group-repository-analytics}

Prérequis :

- Les projets du groupe doivent être configurés pour collecter les données de couverture de test.

Pour afficher les données d'analyse du dépôt d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Données d'analyse du dépôt**.

## Métriques de couverture {#coverage-metrics}

La page **Données d'analyse du dépôt** du groupe affiche :

- **Couverture du code du groupe actuel** :
  - Nombre de projets avec des rapports de couverture.
  - Pourcentage de couverture moyen pour tous les projets.
  - Nombre total de jobs de pipeline qui produisent des rapports de couverture.
- **Couverture de test moyenne** : un graphique qui affiche la couverture de test moyenne pour tous les projets de votre groupe au cours des 30 derniers jours.
- **Derniers résultats de la couverture de test** : une liste des données de couverture les plus récentes pour chaque projet de votre groupe. Sélectionnez des projets dans la liste déroulante pour filtrer les résultats.

## Télécharger les données de couverture {#download-coverage-data}

Vous pouvez télécharger un fichier CSV contenant les données de couverture historiques pour les projets de votre groupe.

Le rapport CSV :

- Contient jusqu'à 1 000 enregistrements.
- Inclut les données de la branche par défaut de chaque projet.
- Affiche une ligne par jour lorsque la couverture a été signalée.
- Utilise la dernière valeur de la journée si plusieurs rapports de couverture ont été générés.
- Contient les informations suivantes pour chaque rapport de couverture :
  - Date d'exécution du job de couverture
  - Nom du job qui a généré le rapport
  - Nom du projet
  - Pourcentage de couverture

Pour télécharger les données de couverture :

1. Sur la page **Données d'analyse du dépôt** du groupe, sélectionnez **Télécharger les données de couverture de test historisées (.csv)**.
1. Sélectionnez les projets à inclure :
   - Dans la liste déroulante **Projets**, choisissez des projets spécifiques. La liste déroulante des projets affiche jusqu'à 100 projets.
   - Facultatif. Sélectionnez **Tout sélectionner** pour inclure tous les projets de votre groupe.
1. Dans la liste déroulante **Plage de dates**, sélectionnez la période à inclure.
1. Sélectionnez **Télécharger les données de couverture de test (.csv)**.

## Sujets connexes {#related-topics}

- [Données d'analyse du dépôt pour les projets](../../analytics/repository_analytics.md)
- [Couverture du code](../../../ci/testing/code_coverage/_index.md)
