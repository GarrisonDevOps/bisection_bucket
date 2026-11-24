---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Connecter un cluster à GitLab
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'[intégration Kubernetes basée sur les certificats avec GitLab](../_index.md) a été [dépréciée](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8) dans GitLab 14.5. Pour connecter vos clusters, utilisez l'[agent GitLab pour Kubernetes](../../../clusters/agent/_index.md).

## Niveaux de cluster (déprécié) {#cluster-levels-deprecated}

> [!warning]
> Le [concept de niveaux de cluster a été déprécié](../_index.md#cluster-levels) dans GitLab 14.5.

Choisissez le niveau de votre cluster en fonction de son utilisation :

| Niveau                                                  | Objectif |
|--------------------------------------------------------|---------|
| [Niveau projet](../../../project/clusters/_index.md)   | Utilisez votre cluster pour un seul projet. |
| [Niveau groupe](../../../group/clusters/_index.md)       | Utilisez le même cluster pour plusieurs projets au sein de votre groupe. |
| [Niveau instance](../../../instance/clusters/_index.md) | Utilisez le même cluster pour des groupes et des projets au sein de votre instance. |

### Afficher vos clusters {#view-your-clusters}

Pour afficher les clusters Kubernetes connectés à votre projet, groupe ou instance, ouvrez la page du cluster selon le niveau de votre cluster.

**Clusters au niveau projet** :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Opération** > **Clusters Kubernetes**.

**Clusters au niveau groupe** :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Opération** > **Clusters Kubernetes**.

**Clusters au niveau instance** :

Prérequis :

- Accès administrateur.

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Kubernetes**.

## Implications de sécurité pour les clusters connectés avec des certificats {#security-implications-for-clusters-connected-with-certificates}

> [!warning]
> L'ensemble de la sécurité du cluster repose sur un modèle dans lequel les [développeurs](../../../permissions.md) sont considérés comme fiables. Par conséquent, **seuls les utilisateurs de confiance doivent être autorisés à contrôler vos clusters**.

L'utilisation de certificats de cluster pour connecter votre cluster accorde l'accès à un large ensemble de fonctionnalités nécessaires pour concevoir et déployer avec succès une application conteneurisée. Gardez à l'esprit que les mêmes informations d'identification sont utilisées pour toutes les applications s'exécutant sur le cluster.
