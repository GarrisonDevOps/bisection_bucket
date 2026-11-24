---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Paramètres du projet
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

## Prérequis {#prerequisites}

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

## Configurer les fonctionnalités et les autorisations d'un projet {#configure-project-features-and-permissions}

Pour configurer les fonctionnalités et les autorisations d'un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Visibilité, fonctionnalités du projet, autorisations**.
1. Pour permettre aux utilisateurs de demander l'accès au projet, cochez la case **Les utilisateurs peuvent demander l'accès**.
1. Pour activer ou désactiver des fonctionnalités dans le projet, utilisez les boutons de basculement des fonctionnalités.
1. Sélectionnez **Enregistrer les modifications**.

### Dépendances des fonctionnalités {#feature-dependencies}

Lorsque vous désactivez une fonctionnalité, les fonctionnalités supplémentaires suivantes deviennent également indisponibles :

- Si vous désactivez la fonctionnalité **Éléments de travail**, les utilisateurs du projet ne peuvent pas utiliser :
  - **Tableaux des tickets**
  - **Service d'assistance**
  - Les utilisateurs du projet peuvent toujours accéder à **Jalons** depuis les merge requests.
- Si vous désactivez **Éléments de travail** et **requêtes de fusion**, les utilisateurs du projet ne peuvent pas utiliser :
  - **Labels**
  - **Les jalons**
- Si vous désactivez **Dépôt**, les utilisateurs du projet ne peuvent pas accéder à :
  - **Les merge requests**
  - **CI/CD**
  - **Git Large File Storage**
  - **les paquets ;**
- Le tableau de bord des métriques nécessite un accès en lecture aux environnements et aux déploiements du projet. Les utilisateurs ayant accès au tableau de bord des métriques peuvent également accéder aux environnements et aux déploiements.

## Activer/désactiver les fonctionnalités du projet {#toggle-project-features}

Les fonctionnalités disponibles du projet sont visibles et accessibles aux membres du projet. Vous pouvez désactiver des fonctionnalités spécifiques du projet afin qu'elles ne soient pas visibles et accessibles aux membres du projet, quel que soit leur rôle.

Pour activer ou désactiver la disponibilité de fonctionnalités individuelles dans un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Visibilité, fonctionnalités du projet, autorisations**.
1. Pour modifier la disponibilité d'une fonctionnalité, activez ou désactivez le bouton de basculement.
1. Sélectionnez **Enregistrer les modifications**.

## Désactiver l'analytique du projet {#turn-off-project-analytics}

> [!note]
> La désactivation de l'analytique du projet supprime uniquement l'élément de navigation **Analyse**, mais les données continuent d'être calculées et sont disponibles via les points de terminaison d'API correspondants.

Par défaut, l'analytique du projet est affichée sous l'élément **Analyse** dans la barre latérale gauche. Pour désactiver cette fonctionnalité et supprimer l'élément **Analyse** de la barre latérale gauche :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Visibilité, fonctionnalités du projet, autorisations**.
1. Désactivez le bouton de basculement **Données d'analyse**.
1. Sélectionnez **Enregistrer les modifications**.

## Désactiver la demande d'identifiant CVE dans les tickets {#turn-off-cve-identifier-request-in-issues}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Cette fonctionnalité est disponible uniquement pour les projets publics sur GitLab.com.

Dans certains environnements, les utilisateurs peuvent soumettre une [demande d'identifiant CVE](../../application_security/cve_id_request.md) dans un ticket.

Pour désactiver l'option de demande d'identifiant CVE dans les tickets de votre projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Visibilité, fonctionnalités du projet, autorisations**.
1. Sous **Éléments de travail**, désactivez le bouton de basculement **Demandes d'ID CVE dans la barre latérale du ticket**.
1. Sélectionnez **Enregistrer les modifications**.

## Désactiver les notifications par courriel du projet {#turn-off-project-email-notifications}

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le projet.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section **Visibilité, fonctionnalités du projet, autorisations**.
1. Décochez la case **Activer les notifications par courriel**.

### Désactiver les aperçus diff dans les notifications par courriel du projet {#turn-off-diff-previews-in-project-email-notifications}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/24733) dans GitLab 15.6 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `diff_preview_in_email`. Fonctionnalité désactivée par défaut.
- [Disponible de manière générale](https://gitlab.com/gitlab-org/gitlab/-/issues/382055) dans GitLab 17.1. Le feature flag `diff_preview_in_email` a été supprimé.

{{< /history >}}

Lorsque vous révisez du code dans une merge request et commentez une ligne de code, GitLab inclut quelques lignes du diff dans la notification par courriel envoyée aux participants. Certaines politiques organisationnelles considèrent le courriel comme un système moins sécurisé, ou peuvent ne pas contrôler leur propre infrastructure de messagerie. Cela peut présenter des risques pour la propriété intellectuelle ou le contrôle d'accès au code source.

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le projet.

Pour désactiver les aperçus diff pour un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section **Visibilité, fonctionnalités du projet, autorisations**.
1. Décochez **Inclure les aperçus diff**.
1. Sélectionnez **Enregistrer les modifications**.

## Configurer les paramètres de merge request pour un projet {#configure-merge-request-settings-for-a-project}

Configurez les paramètres de merge request de votre projet :

- Configurez la [méthode de merge request](../merge_requests/methods/_index.md) (commit de fusion, fusion fast-forward).
- Ajoutez des [modèles de description](../description_templates.md) pour les merge requests.
- Activez :
  - [Approbations de merge request](../merge_requests/approvals/_index.md).
  - [Vérifications de statut](../merge_requests/status_checks.md).
  - [Fusionner uniquement si le pipeline réussit](../merge_requests/auto_merge.md).
  - [Fusionner uniquement lorsque tous les fils de discussion sont résolus](../merge_requests/_index.md#prevent-merge-unless-all-threads-are-resolved).
  - [Ticket Jira associé requis](../../../integration/jira/issues.md#require-associated-jira-issue-for-merge-requests-to-be-merged).
  - [Validation du titre de la merge request](../merge_requests/title_validation.md).
  - [Rebase automatique avant la fusion](../merge_requests/methods/_index.md#automatic-rebase-before-merge) pour les méthodes de fusion semi-linéaire et fast-forward.
  - [**Option Supprimer la branche source lorsque la merge request est acceptée** par défaut](#delete-the-source-branch-on-merge-by-default).
- Configurez :
  - [Messages de commit pour les modifications suggérées](../merge_requests/reviews/suggestions.md#configure-the-commit-message-for-applied-suggestions).
  - [Modèles de messages de commit de fusion et de squash](../merge_requests/commit_templates.md).
  - [Modèles de titre de merge request](../merge_requests/title_templates.md).
  - [Projet cible par défaut](../merge_requests/creating_merge_requests.md#set-the-default-target-project) pour les merge requests provenant de duplications.

### Supprimer la branche source lors de la fusion par défaut {#delete-the-source-branch-on-merge-by-default}

Dans les merge requests, vous pouvez modifier le comportement par défaut afin que la case **Supprimer la branche source** soit toujours cochée.

Pour définir ce paramètre par défaut :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Sélectionnez **Activer par défaut l'option « Supprimer la branche source »**.
1. Sélectionnez **Enregistrer les modifications**.

Ce paramètre s'applique aux merge requests dont la branche source se trouve dans ce projet. Pour les merge requests provenant d'une duplication, la valeur par défaut provient du paramètre de la duplication, et non de ce projet. Les duplications n'héritent pas de ce paramètre lors de leur création.

## Ajouter des déclencheurs de webhook supplémentaires pour l'expiration du jeton d'accès au projet {#add-additional-webhook-triggers-for-project-access-token-expiration}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/499732) des déclencheurs à 60 et 30 jours pour les webhooks de jeton d'accès au projet et au groupe dans GitLab 17.9 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `extended_expiry_webhook_execution_setting`. Fonctionnalité désactivée par défaut.
- [Disponible de manière générale](https://gitlab.com/gitlab-org/gitlab/-/issues/513684) dans GitLab 17.10. Le feature flag `extended_expiry_webhook_execution_setting` a été supprimé.

{{< /history >}}

GitLab envoie plusieurs [courriels d'expiration](project_access_tokens.md#project-access-token-expiry-emails) et déclenche un [webhook](../integrations/webhook_events.md#project-and-group-access-token-events) associé avant l'expiration d'un jeton de projet. Par défaut, ces webhooks se déclenchent 7 jours avant l'expiration d'un jeton.

Pour configurer ces webhooks afin qu'ils se déclenchent également 60 jours et 30 jours avant l'expiration d'un jeton :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section **Visibilité, fonctionnalités du projet, autorisations**.
1. Cochez la case **Ajouter des déclencheurs de webhook supplémentaires pour l'expiration du jeton d'accès au projet**.
1. Sélectionnez **Enregistrer les modifications**.

## Désactiver CI/CD pour un projet {#turn-off-cicd-for-a-project}

Si votre projet n'utilise pas CI/CD, vous pouvez le désactiver. Cela supprime la bannière CI/CD des merge requests.

Pour désactiver CI/CD :

1. Dans la barre latérale gauche, sélectionnez **Rechercher ou accéder à** et repérez votre projet.
1. Sélectionnez **Paramètres** > **Généralités**.
1. Développez **Visibilité, fonctionnalités du projet, autorisations**.
1. Désactivez le bouton de basculement **CI/CD**.
1. Sélectionnez **Enregistrer les modifications**.
