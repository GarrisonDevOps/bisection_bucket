---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: "Tableau de bord de vue d'ensemble de la conformité"
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/epics/13909) dans GitLab 18.2 avec un indicateur nommé `compliance_group_dashboard`. Activés par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/555804) dans GitLab 18.3. Suppression du feature flag `compliance_group_dashboard`.

{{< /history >}}

Le tableau de bord de vue d'ensemble de la conformité fournit des informations visuelles sur la posture de conformité de votre groupe grâce à des graphiques et des métriques interactifs. Il vous aide à identifier rapidement les domaines nécessitant une attention particulière et à suivre votre statut de conformité global.

Le tableau de bord de vue d'ensemble de la conformité affiche quatre domaines clés de surveillance de la conformité :

- Couverture du cadre de conformité.
- Statut des exigences en échec.
- Statut des contrôles en échec.
- Cadres de conformité nécessitant une attention particulière.

## Afficher le tableau de bord de vue d'ensemble de la conformité {#view-the-compliance-overview-dashboard}

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour afficher le tableau de bord de vue d'ensemble de la conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sélectionnez **Vue d'ensemble** pour afficher le tableau de bord de conformité.

## Couverture du cadre de conformité {#compliance-framework-coverage}

La section de couverture du cadre fournit une vue d'ensemble du nombre de projets de votre groupe auxquels des cadres de conformité sont assignés.

La section de couverture du cadre affiche :

- **Nombre total de projets** : le nombre total de projets dans votre groupe.
- **Projets couverts** : nombre de projets auxquels au moins un cadre de conformité est assigné.
- **Pourcentage de couverture** : représentation visuelle de la couverture du cadre sur l'ensemble de vos projets.

Sous les métriques de résumé, vous pouvez consulter la couverture individuelle de chaque cadre, notamment :

- Nom du cadre avec badge visuel.
- Nombre de projets utilisant chaque cadre.
- Pourcentage du total des projets couverts par chaque cadre.

## Graphique des exigences en échec {#failed-requirements-chart}

Le graphique des exigences en échec visualise le statut de conformité des exigences au sein de vos cadres.

Le graphique des exigences en échec affiche trois catégories :

- **Réussi** : exigences entièrement conformes (affichées en bleu).
- **En attente** : exigences en cours d'examen (affichées en orange).
- **Échec** : exigences ne satisfaisant pas aux normes de conformité (affichées en magenta).

## Graphique des contrôles en échec {#failed-controls-chart}

Le graphique des contrôles en échec fournit une représentation visuelle du statut de conformité des contrôles au sein de votre organisation.

Le graphique des contrôles en échec affiche trois catégories :

- **Réussi** : contrôles satisfaisant aux exigences de conformité (affichés en bleu).
- **En attente** : contrôles en attente d'évaluation (affichés en orange).
- **Échec** : contrôles ne satisfaisant pas aux exigences de conformité (affichés en magenta).

## Tableau des cadres {#frameworks-table}

Le tableau des cadres met en évidence les cadres de conformité nécessitant une attention immédiate. Cette vue vous aide à identifier les cadres présentant des problèmes de configuration ou des composants manquants.

Le tableau des cadres affiche :

- **Nom du cadre** : le cadre de conformité avec un badge visuel.
- **Projets** : nombre de projets utilisant ce cadre (mis en évidence en rouge si zéro).
- **Exigences** : nombre total d'exigences dans le cadre (mis en évidence en rouge si zéro).
- **Exigences sans contrôles** : liste les exigences spécifiques ne disposant pas de contrôles associés.
- **Politiques** : politiques de sécurité liées au cadre, notamment :
  - Politiques d'exécution d'analyse.
  - Politiques de gestion des vulnérabilités.
  - Politiques de résultat d'analyse.
  - Politiques d'exécution de pipeline.
- **Actions** : bouton de modification du cadre (visible pour les utilisateurs disposant des autorisations d'administration).
