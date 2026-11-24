---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Fonctionnement des règles de protection avec les branches protégées dans GitLab, en particulier dans les scénarios complexes."
title: Règles de protection et permissions
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les règles de protection contrôlent l'accès aux branches et déterminent ce qui se passe lorsque plusieurs règles s'appliquent à la même branche. Elles vous aident à mettre en œuvre les mesures de sécurité appropriées pour les branches de votre dépôt. Ces règles couvrent :

- Les niveaux de permissions, la précédence et les conflits de règles.
- Les permissions de poussée forcée sur plusieurs règles correspondantes.
- Les approbations des propriétaires du code.
- Les paramètres de protection entre les groupes et les projets.

## Comportements des règles {#rule-behaviors}

Lorsqu'une branche correspond à plusieurs règles de protection, ces comportements s'appliquent :

- Les règles de groupe s'appliquent à tous les projets d'un groupe et ne peuvent pas être modifiées depuis les paramètres du projet. Pour plus d'informations, voir [les règles entre groupes et projets](#rules-across-groups-and-projects).
- Lorsqu'une branche correspond à plusieurs règles, la règle la plus permissive s'applique. Cependant, [l'approbation du propriétaire du code](#code-owner-approval) utilise la règle la plus restrictive.
- Les noms de branches exacts comme `main` ne remplacent pas les modèles avec caractères génériques comme `m*`.

## Permissions de poussée et de fusion {#push-and-merge-permissions}

Lorsqu'une branche est protégée, le comportement par défaut applique ces restrictions :

| Action                   | Qui peut le faire |
|:-------------------------|:--------------|
| Protéger une branche         | Les utilisateurs disposant du rôle Chargé de maintenance ou Propriétaire. |
| Pousser vers la branche       | Toute personne disposant de la permission **Autorisée**. (1) |
| Forcer la poussée vers la branche | Personne.       |
| Supprimer la branche        | Personne. (2)   |

1. Les utilisateurs disposant du rôle Développeur peuvent créer un projet dans un groupe, mais il est possible qu'ils ne soient pas autorisés à pousser initialement vers la [branche par défaut](default.md).
1. Personne ne peut supprimer une branche protégée à l'aide de commandes Git. Cependant, les utilisateurs disposant au minimum du rôle Chargé de maintenance peuvent [supprimer une branche protégée](protected.md#delete-protected-branches) depuis l'interface ou l'API.

Lorsque vous configurez ces permissions, la sélection d'un rôle accorde l'accès aux utilisateurs disposant de ce rôle et de tous les rôles supérieurs. Par exemple :

- La sélection de **Chargés de maintenance** accorde l'accès aux utilisateurs disposant des rôles Chargé de maintenance et Propriétaire.
- La sélection de **Développeurs + Chargés de maintenance** accorde l'accès aux utilisateurs disposant des rôles Développeur, Chargé de maintenance et Propriétaire.

Ce comportement garantit que les utilisateurs disposant de privilèges supérieurs conservent l'accès disponible pour les utilisateurs disposant de privilèges inférieurs.

## Permissions de poussée forcée {#force-push-permissions}

Les permissions de poussée forcée suivent la même logique selon laquelle la règle la plus permissive s'applique. Par exemple, prenez en compte ces règles, qui incluent des [caractères génériques](protected.md#use-wildcard-rules) :

| Modèle de nom de branche | Autoriser les poussées forcées |
|---------------------|------------------|
| `v1.x`              | Oui              |
| `v1.*`              | Non               |
| `v*`                | Non               |

Une branche nommée `v1.x` correspond aux trois modèles de noms de branche : `v1.x`, `v1.*` et `v*`. Comme l'option la plus permissive détermine le comportement, les permissions résultantes pour la branche `v1.x` sont :

- **Autoriser les poussées forcées** : parmi les trois paramètres, `Oui` est le plus permissif et contrôle par conséquent le comportement de la branche. Même si la branche correspond également à `v1.x` et `v*` (qui ont chacun des permissions plus strictes), tout utilisateur pouvant pousser vers cette branche peut également effectuer une poussée forcée.

## Approbation du propriétaire du code {#code-owner-approval}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Contrairement aux permissions de poussée et de fusion, et aux permissions de poussée forcée, l'approbation du propriétaire du code utilise la règle la plus restrictive. Si une branche est protégée par plusieurs règles, l'approbation du propriétaire du code est requise si l'une des règles applicables a **Approbation requise des propriétaires du code** activé. Pour plus d'informations, voir [exiger l'approbation du propriétaire du code](protected.md#require-code-owner-approval).

Par exemple, prenez en compte ces règles :

| Modèle de nom de branche | Approbation du propriétaire du code requise |
|---------------------|------------------------------|
| `v1.x`              | Oui                          |
| `v1.*`              | Non                           |
| `v*`                | Non                           |

Une branche nommée `v1.x` correspond aux trois modèles de noms de branche : `v1.x`, `v1.*` et `v*`. Comme au moins une règle (`v1.x`) exige l'approbation du propriétaire du code, toutes les merge requests vers cette branche nécessitent l'approbation d'un propriétaire du code avant de pouvoir être fusionnées.

## Règles entre groupes et projets {#rules-across-groups-and-projects}

Les règles de protection des branches peuvent être définies à la fois dans les groupes et dans les projets :

- Les règles de groupe s'appliquent à tous les projets d'un groupe et ne peuvent pas être modifiées depuis les paramètres du projet.
- Les règles de projet s'appliquent uniquement au projet dans lequel elles sont définies.

Lorsque des règles de groupe et de projet correspondent à une branche, GitLab évalue toutes les règles correspondantes ensemble :

- Pour la plupart des paramètres, la règle la plus permissive s'applique.
- Pour [l'approbation du propriétaire du code](#code-owner-approval), la règle la plus restrictive s'applique.

Vous ne pouvez pas modifier ni supprimer les règles de groupe depuis les paramètres du projet, mais vous pouvez ajouter des règles de projet pour la même branche. L'évaluation combinée peut aboutir à un comportement plus permissif que la règle de groupe seule.

Par exemple :

- Une règle de groupe pour `main` interdit la poussée forcée.
- Un chargé de maintenance de projet ajoute une règle de projet pour `main` qui autorise la poussée forcée.
- Les deux règles sont évaluées ensemble. La règle la plus permissive s'applique, donc la poussée forcée est autorisée sur la branche `main` de ce projet.

## Exemples de règles de branches multiples {#multiple-branch-rule-examples}

Les exemples suivants montrent comment différentes règles peuvent affecter la protection des branches.

### Autorisés à fusionner {#allowed-to-merge}

Un exemple illustrant comment un nom de branche exact ne remplace pas un modèle avec caractères génériques plus permissif.

| Modèle de branche | Autorisés à fusionner          |
|----------------|---------------------------|
| `release-v1.0` | Personne                    |
| `release*`     | Chargé de maintenance                |
| `*`            | Développeur + Chargé de maintenance    |

- La branche `release-v1.0` correspond aux trois modèles. La règle la plus permissive s'applique :
  - **Autorisés à fusionner** : Développeur + Chargé de maintenance peut fusionner (depuis la règle `*`).

### Autorisés à pousser et fusionner {#allowed-to-push-and-merge}

Un exemple illustrant comment plusieurs règles de branches s'appliquent à différents noms de branches.

| Modèle de branche | Autorisés à fusionner       | Autorisés à pousser et fusionner |
|----------------|------------------------|---------------------------|
| `main`         | Chargé de maintenance             | Personne                    |
| `m*`           | Développeur + Chargé de maintenance | Développeur + Chargé de maintenance    |
| `r*`           | Personne                 | Personne                    |

- La branche `main` correspond à deux modèles (`main` et `m*`). La règle la plus permissive s'applique :
  - **Autorisés à fusionner** : Développeur + Chargé de maintenance peut fusionner (depuis la règle `m*`).
  - **Autorisés à pousser et fusionner** : Développeur + Chargé de maintenance peut pousser (depuis la règle `m*`).
- La branche `release-v1.0` correspond à un seul modèle :
  - **Autorisés à fusionner** : personne ne peut fusionner (depuis la règle `r*`).
  - **Autorisés à pousser et fusionner** : personne ne peut pousser (depuis la règle `r*`).

### Exigences relatives aux propriétaires du code {#code-owner-requirements}

L'approbation du propriétaire du code fonctionne différemment des autres paramètres de protection des branches. Lorsque plusieurs règles correspondent, la règle la plus restrictive s'applique à la place de la règle la plus permissive.

| Modèle de branche | Approbation du propriétaire du code requise |
|----------------|------------------------------|
| `production`   | Oui                          |
| `prod*`        | Non                           |
| `p*`           | Oui                          |

- La branche `production` correspond aux trois modèles. La règle la plus restrictive s'applique :
  - **Approbation du propriétaire du code** : requise (depuis les règles `production` et `p*`).
- La branche `product-v1.0` correspond à deux modèles (`prod*` et `p*`). La règle la plus restrictive s'applique :
  - **Approbation du propriétaire du code** : requise (depuis la règle `p*`).

### Garantir une protection stricte {#ensure-strict-protection}

Pour garantir une protection stricte qui ne peut pas être remplacée par des modèles plus permissifs, configurez tous les modèles correspondants avec les mêmes paramètres restrictifs.

| Modèle de branche | Autorisés à fusionner | Autorisés à pousser et fusionner |
|----------------|------------------|---------------------------|
| `production`   | Chargé de maintenance       | Personne                    |
| `prod*`        | Chargé de maintenance       | Personne                    |
| `p*`           | Chargé de maintenance       | Personne                    |
| `*`            | Chargé de maintenance       | Personne                    |

Désormais, la branche `production` dispose de permissions de poussée restrictives, car toutes les règles correspondantes spécifient que **Personne** ne peut pousser.

## Sujets connexes {#related-topics}

- [Branches protégées](protected.md)
- [API des branches protégées](../../../../api/protected_branches.md)
- [Règles de branche](branch_rules.md)
- [Propriétaires du code](../../codeowners/_index.md#code-owners-and-protected-branches)
