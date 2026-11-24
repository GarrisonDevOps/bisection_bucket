---
stage: Analytics
group: Optimize
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Adoption de DevOps par groupe
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'adoption de DevOps vous montre comment les groupes de votre organisation adoptent et utilisent les fonctionnalités de GitLab. Ces informations sont disponibles pour les groupes et les [instances](../../../administration/analytics/devops_adoption.md).

Utilisez l'adoption de DevOps pour les groupes afin de :

- Identifier les sous-groupes qui sont en retard dans leur adoption des fonctionnalités de GitLab, afin de les guider dans leur parcours DevOps.
- Trouver les sous-groupes qui ont adopté certaines fonctionnalités et fournir des conseils aux autres sous-groupes sur la façon d'utiliser ces fonctionnalités.
- Vérifier si vous obtenez le retour sur investissement que vous attendiez de GitLab.

## Adoption des fonctionnalités {#feature-adoption}

L'adoption de DevOps montre l'adoption des fonctionnalités pour le développement, la sécurité et les opérations.

| Catégorie    | Fonctionnalité |
|-------------|---------|
| Développement | Approbations<br>Propriétaires du code<br>Les tickets<br>Les merge requests |
| Sécurité    | DAST<br>Analyse des dépendances<br>Tests à données aléatoires<br>SAST |
| Opérations  | Déploiements<br>Pipelines<br>Runners |

Une fonctionnalité apparaît comme adoptée lorsqu'un groupe ou sous-groupe a utilisé la fonctionnalité dans un projet au cours du dernier mois civil complet. Par exemple, si un ticket a été créé dans un projet d'un groupe, le groupe a adopté les tickets au cours de cette période.

![L'onglet Vue d'ensemble d'un rapport d'adoption de DevOps.](img/devops_adoption_v17_8.png)

L'onglet **Vue d'ensemble** illustre :

- Le nombre total de fonctionnalités adoptées.
- Les fonctionnalités adoptées dans chaque catégorie.
- Le nombre de fonctionnalités adoptées dans chaque catégorie par mois dans le graphique à barres **Adoption au cours du temps**. Le graphique affiche uniquement les données à partir de la date à laquelle vous avez activé l'adoption de DevOps pour le groupe.
- Le nombre de fonctionnalités adoptées dans chaque catégorie par sous-groupe dans le tableau **Adoption par sous-groupe**.

Les onglets **Dev**, **Sec** et **Ops** illustrent les fonctionnalités adoptées dans le développement, la sécurité et les opérations par sous-groupe.

Le rapport d'adoption de DevOps exclut :

- Les projets dormants. Le nombre de projets qui utilisent une fonctionnalité n'est pas pris en compte. Avoir de nombreux projets dormants ne réduit pas l'adoption.
- Les nouvelles fonctionnalités de GitLab. L'adoption correspond au nombre total de fonctionnalités adoptées, et non au pourcentage de fonctionnalités.

## Traitement des données {#data-processing}

Une tâche hebdomadaire traite les données pour l'adoption de DevOps. Cette tâche est désactivée jusqu'à ce que vous accédiez pour la première fois à l'adoption de DevOps pour un groupe.

La tâche de traitement des données met à jour les données le premier jour de chaque mois. Si la mise à jour mensuelle échoue, la tâche réessaie quotidiennement jusqu'à ce qu'elle réussisse.

Les données d'adoption de DevOps peuvent mettre jusqu'à une minute à apparaître pendant que GitLab traite les données du groupe.

## Afficher l'adoption de DevOps pour les groupes {#view-devops-adoption-for-groups}

Prérequis :

- Vous devez disposer du rôle Rapporteur, Développeur, Chargé de maintenance ou Propriétaire pour le groupe.

Pour afficher l'adoption de DevOps :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Adoption de DevOps**.
1. Pour afficher les fonctionnalités adoptées par catégorie dans un mois, survolez une barre.

## Ajouter un sous-groupe à l'adoption de DevOps {#add-a-subgroup-to-devops-adoption}

Prérequis :

- Vous devez disposer du rôle Rapporteur, Développeur, Chargé de maintenance ou Propriétaire pour le groupe.

Pour ajouter un sous-groupe au rapport d'adoption de DevOps :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Adoption de DevOps**.
1. Dans la liste déroulante **Ajouter ou supprimer des sous-groupes**, sélectionnez le sous-groupe que vous souhaitez ajouter.

## Supprimer un sous-groupe de l'adoption de DevOps {#remove-a-subgroup-from-devops-adoption}

Prérequis :

- Vous devez disposer du rôle Rapporteur, Développeur, Chargé de maintenance ou Propriétaire pour le groupe.

Pour supprimer un sous-groupe du rapport d'adoption de DevOps :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Analyse** > **Adoption de DevOps**.
1. L'une ou l'autre des options :

- Dans la liste déroulante **Ajouter ou supprimer des sous-groupes**, désélectionnez le sous-groupe que vous souhaitez supprimer.
- Dans le tableau **Adoption par sous-groupe**, dans la ligne du groupe que vous souhaitez supprimer, sélectionnez **Supprimer le groupe du tableau** ({{< icon name="remove" >}}).
