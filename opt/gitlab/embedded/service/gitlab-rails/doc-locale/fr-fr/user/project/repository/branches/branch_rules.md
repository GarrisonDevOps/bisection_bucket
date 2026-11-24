---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Comprendre comment nommer, gérer et protéger les branches Git."
title: Règles des branches
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab propose plusieurs méthodes pour protéger les branches individuelles. Ces méthodes garantissent que vos branches font l'objet d'une supervision et de vérifications de qualité, de leur création à leur suppression :

- Appliquez une sécurité et une protection renforcées à la [branche par défaut](default.md) de votre projet.
- Configurez les [branches protégées](protected.md) pour :
  - Limiter qui peut pousser vers une branche et y fusionner du contenu.
  - Gérer si les utilisateurs peuvent forcer le push vers la branche.
  - Gérer si les modifications apportées aux fichiers répertoriés dans le fichier `CODEOWNERS` peuvent être poussées directement vers la branche.
- Configurez les [règles d'approbation](../../merge_requests/approvals/rules.md#approvals-for-protected-branches) pour gérer les exigences de révision et mettre en œuvre les [approbations liées à la sécurité](../../merge_requests/approvals/rules.md#security-approvals).
- Intégrez des [vérifications d'état](../../merge_requests/status_checks.md) tierces pour vous assurer que le contenu de votre branche respecte vos normes de qualité définies.

Vous pouvez gérer vos branches :

- Via l'interface utilisateur de GitLab.
- Avec Git en ligne de commande.
- Via l'[API Branches](../../../../api/branches.md).

## Afficher les règles des branches {#view-branch-rules}

La page de présentation des règles des branches affiche toutes les branches avec les protections configurées, ainsi que leurs méthodes de protection :

![Exemple d'une branche avec des protections configurées](img/view_branch_protections_v15_10.png)

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour afficher la liste de présentation des règles des branches :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Règles des branches** pour afficher toutes les branches avec des protections.

### Détails des règles des branches {#view-branch-rule-details}

Pour afficher les règles et les protections d'une branche unique :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Règles des branches** pour afficher toutes les branches avec des protections.
1. Identifiez la branche souhaitée et sélectionnez **Afficher les détails**.

## Créer une règle de branche {#create-a-branch-rule}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279) dans GitLab 16.8 avec un flag nommé `add_branch_rules`. Fonctionnalité désactivée par défaut.
- Le feature flag `add_branch_rules` [renommé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279) en `edit_branch_rules` dans GitLab 16.11. Fonctionnalité désactivée par défaut.
- Les options **Toutes les branches** et **Toutes les branches protégées** ont été [introduites](https://gitlab.com/gitlab-org/gitlab/-/issues/388129) dans GitLab 17.0.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/454501) dans GitLab 17.4.
- [Activé sur GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/454501) dans GitLab 17.5.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/586354) dans GitLab 18.9. Suppression du feature flag `edit_branch_rules`.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour créer une règle de branche :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Règles des branches**.
1. Sélectionnez **Ajouter une règle de branche**.
1. Choisissez l'une des options suivantes :
   - Pour saisir un nom de branche ou un modèle spécifique :
     1. Sélectionnez **Schéma ou nom de la branche**.
     1. Dans la liste déroulante **Créer une règle de branche**, sélectionnez un nom de branche ou créez un [caractère générique](protected.md#use-wildcard-rules) avec `*`.
   - Pour protéger toutes les branches du projet :
     1. Sélectionnez **Toutes les branches**.
     1. Sur la page des détails de la règle, sous **Approbations des requêtes de fusion**, saisissez le nombre d'approbations requis pour la règle.
   - Pour protéger toutes les branches du projet déjà spécifiées comme protégées :
     1. Sélectionnez **Toutes les branches protégées**.
     1. Sur la page des détails de la règle, sous **Approbations des requêtes de fusion**, saisissez le nombre d'approbations requis pour la règle.

### Ajouter une protection de règle de branche {#add-a-branch-rule-protection}

> [!note]
> Non disponible pour `all branches`.

Pour ajouter des protections à une nouvelle branche :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Règles des branches**.
1. Sélectionnez **Ajouter une règle de branche**.
1. Sélectionnez **Toutes les branches protégées** ou **Schéma ou nom de la branche**.
1. Sélectionnez **Créer une règle de branche**.

### Ajouter une règle d'approbation {#add-an-approval-rule}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!note]
> Non disponible pour `all branches`.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour ajouter une règle d'approbation de merge request :

1. Depuis la page [des détails des règles des branches](#view-branch-rule-details), accédez à la section **Approbations des requêtes de fusion**.
1. Dans la section **Règles d'approbation**, sélectionnez **Ajouter une règle d'approbation**.
1. Dans la barre latérale droite, renseignez les champs :
   - Saisissez un **Nom de la règle**.
   - Dans **Nombre requis d'approbations**, saisissez une valeur (`0`-`100`).

     Une valeur de `0` rend [la règle facultative](../../merge_requests/approvals/rules.md#configure-optional-approval-rules), et tout nombre supérieur à `0` crée une règle obligatoire. Le nombre maximum d'approbations requises est `100`.
   - Sélectionnez les utilisateurs ou les groupes [habilités à approuver](../../merge_requests/approvals/rules.md#eligible-approvers).

     GitLab suggère des approbateurs en fonction des auteurs précédents des fichiers modifiés par la merge request.
1. Sélectionnez **Enregistrer les modifications**.

Pour plus d'informations, consultez les [règles d'approbation](../../merge_requests/approvals/rules.md#approvals-for-protected-branches).

### Modifier l'option de combinaison des commits {#edit-squash-commits-option}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/181370) dans GitLab 17.9 avec un flag nommé `branch_rule_squash_settings`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/506542) dans GitLab 17.10.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/524860) dans GitLab 17.11. Suppression du feature flag `branch_rule_squash_settings`.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.
- Dans GitLab Free, cette fonctionnalité est disponible uniquement si la règle de branche cible **Toutes les branches**.
- Dans GitLab Premium et GitLab Ultimate, cette fonctionnalité est disponible pour toutes les règles de branche.

Pour modifier une option de combinaison des commits :

1. Depuis la page [des détails des règles des branches](#view-branch-rule-details), accédez à la section **Squasher les commits lors de la fusion**.
1. Sélectionner **Éditer**.
1. Sélectionnez l'une des options suivantes :

   - **Par défaut** : supprime le paramètre de combinaison des commits au niveau de la branche et hérite des paramètres par défaut du projet. Cette option n'est pas disponible pour la règle **Toutes les branches**, qui définit les paramètres par défaut du projet.
   - **Ne pas autoriser** : la combinaison des commits n'est jamais autorisée et la case à cocher est masquée.
   - **Autoriser** : la case à cocher est visible et désélectionnée par défaut.
   - **Encourager** : la case à cocher est visible et sélectionnée par défaut.
   - **Exiger** : la combinaison des commits est toujours effectuée. La case à cocher est visible et sélectionnée, et les utilisateurs ne peuvent pas la modifier.

1. Sélectionnez **Enregistrer les modifications**.

### Ajouter un service de vérification d'état {#add-a-status-check-service}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/epics/12522) dans GitLab 17.4 [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `edit_branch_rules`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/454501) dans GitLab 17.4.
- [Activé sur GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/454501) dans GitLab 17.5.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/586354) dans GitLab 18.9. Suppression du feature flag `edit_branch_rules`.

{{< /history >}}

> [!note]
> Non disponible pour `all protected branches`.

Pour ajouter un service de vérification d'état :

1. Depuis la page [des détails des règles des branches](#view-branch-rule-details), accédez à la section **Vérifications d'état**.
1. Sélectionnez **Ajouter une vérification d'état**.
1. Saisissez le **Nom du service**.
1. Dans le champ **API à vérifier**, saisissez l'URL.

   Vous devriez utiliser une URL HTTPS pour protéger les données de vos merge requests en transit.

![Vérifications d'état des règles des branches](img/branch_rule_status_check_v17_4.png)

Pour plus d'informations, consultez les [vérifications d'état externes](../../merge_requests/status_checks.md).

## Modifier la cible d'une règle de branche {#edit-a-branch-rule-target}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279) dans GitLab 16.8 avec un flag nommé `add_branch_rules`. Fonctionnalité désactivée par défaut.
- Le feature flag `add_branch_rules` [renommé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279) en `edit_branch_rules` dans GitLab 16.11. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/454501) dans GitLab 17.4.
- [Activé sur GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/454501) dans GitLab 17.5.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/586354) dans GitLab 18.9. Suppression du feature flag `edit_branch_rules`.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour modifier la cible d'une règle de branche :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Règles des branches** pour afficher toutes les branches avec des protections.
1. Identifiez la branche souhaitée et sélectionnez **Afficher les détails**.
1. Dans la section **Cible de la règle**, sélectionnez **Modifier**.
1. Modifiez les informations selon vos besoins.
1. Sélectionnez **Mettre à jour**.

### Modifier une protection de règle de branche {#edit-a-branch-rule-protection}

Pour plus d'informations sur les contrôles de protection des branches, consultez [Branches protégées](protected.md).

> [!note]
> Non disponible pour `all branches`.

## Supprimer une règle de branche {#delete-a-branch-rule}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279) dans GitLab 16.8 avec un flag nommé `add_branch_rules`. Fonctionnalité désactivée par défaut.
- Le feature flag `add_branch_rules` [renommé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/88279) en `edit_branch_rules` dans GitLab 16.11. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/454501) dans GitLab 17.4.
- [Activé sur GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/454501) dans GitLab 17.5.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/586354) dans GitLab 18.9. Suppression du feature flag `edit_branch_rules`.

{{< /history >}}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour supprimer une règle de branche :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Règles des branches**.
1. En regard de la règle à supprimer, sélectionnez **Afficher les détails**.
1. Dans le coin supérieur droit, sélectionnez **Supprimer la règle**.
1. Dans la boîte de dialogue de confirmation, sélectionnez **Supprimer la règle de branche**.

> [!note]
> La suppression d'une règle de branche n'est pas disponible pour les règles ciblant `all branches`.

## Sujets connexes {#related-topics}

- [Branche par défaut](default.md)
- [Branches protégées](protected.md)
- [Protéger votre dépôt](../protect.md)
- [Stratégies de branchement](strategies/_index.md)
- [Approbations des merge requests](../../merge_requests/approvals/_index.md)
