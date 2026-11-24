---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Utilisez les propriétaires du code pour définir des experts pour votre base de code et définir des exigences de révision en fonction du type ou de l'emplacement du fichier."
title: Dépannage des propriétaires du code
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lorsque vous travaillez avec les propriétaires du code, vous pouvez rencontrer les problèmes suivants.

Pour plus d'informations sur la façon dont la fonctionnalité Propriétaires du code gère les erreurs, consultez [la gestion des erreurs](advanced.md#error-handling).

## Valider votre fichier CODEOWNERS {#validate-your-codeowners-file}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/epics/15598) dans GitLab 17.11 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `accessible_code_owners_validation`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/524437) dans GitLab 18.1.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/549626) dans GitLab 18.2. Le feature flag `accessible_code_owners_validation` a été supprimé.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Lors de la consultation d'un [fichier `CODEOWNERS`](_index.md#codeowners-file), GitLab exécute des validations pour vous aider à identifier les problèmes de syntaxe et de permissions. Si aucun problème de syntaxe n'est détecté, GitLab :

- N'exécute pas d'autres validateurs sur le fichier.
- Exécute davantage de validations de permissions sur les 200 premières références uniques d'utilisateurs et de groupes trouvées dans le fichier.

Fonctionnement :

1. Recherche de toutes les références pouvant accéder au projet. Si une référence d'utilisateur ou de groupe est ajoutée, mais ne dispose pas d'un accès au projet, une erreur est affichée.
1. Pour chaque référence d'utilisateur valide, vérifiez que l'utilisateur dispose de la permission d'approuver les merge requests dans le projet. Si l'utilisateur ne dispose pas de cette permission, une erreur est affichée.
1. Pour chaque référence de groupe valide, vérifiez que la valeur du rôle maximum est Developer ou supérieure. Pour chaque référence de groupe dont la valeur est inférieure à Developer, une erreur est affichée.
1. Pour chaque référence de groupe valide, vérifiez que le groupe contient au moins un utilisateur ayant la permission d'approuver les merge requests. Pour toute référence de groupe ne contenant aucun utilisateur ayant la permission d'approuver les merge requests, une erreur est affichée.

## Les approbations ne s'affichent pas {#approvals-do-not-show}

Le [fichier `CODEOWNERS`](_index.md#codeowners-file) doit être présent dans la branche cible.

Les règles d'approbation des propriétaires du code sont mises à jour lorsque :

- Vous créez ou mettez à jour la merge request.
- Vous poussez des commits vers la branche source.
- Vous poussez un fichier `CODEOWNERS` mis à jour vers une branche cible protégée.

Si les approbations ne s'affichent toujours pas après avoir modifié le fichier `CODEOWNERS`, poussez un nouveau commit vers la branche source ou modifiez la merge request pour les actualiser.

## Approbations affichées comme optionnelles {#approvals-shown-as-optional}

Une règle d'approbation de propriétaire du code est optionnelle si l'une de ces conditions est vraie :

- L'utilisateur ou le groupe n'est pas membre du projet. Les propriétaires du code [ne peuvent pas hériter des membres des groupes parents](https://gitlab.com/gitlab-org/gitlab/-/issues/288851/).
- L'utilisateur ou le groupe est [malformé ou inaccessible](advanced.md#malformed-owners).
- [L'approbation du propriétaire du code sur une branche protégée](../repository/branches/protected.md#require-code-owner-approval) n'a pas été configurée.
- La section est [marquée comme optionnelle](reference.md#optional-sections).
- Aucun propriétaire du code éligible n'est disponible pour approuver la merge request en raison de conflits avec d'autres [paramètres d'approbation des merge requests](../merge_requests/approvals/settings.md).

## L'utilisateur n'est pas affiché comme approbateur possible {#user-not-shown-as-possible-approver}

Un utilisateur peut ne pas apparaître comme approbateur dans les règles d'approbation des merge requests des propriétaires du code si l'une de ces conditions est vraie :

- Une règle empêche l'utilisateur spécifique d'approuver la merge request. Vérifiez les paramètres [d'approbation des merge requests](../merge_requests/approvals/settings.md#edit-merge-request-approval-settings) du projet.
- Un groupe de propriétaires du code a une visibilité privée, et l'utilisateur actuel n'est pas membre du groupe de propriétaires du code.
- Le nom d'utilisateur spécifique est mal orthographié ou [malformé dans le fichier `CODEOWNERS`](advanced.md#malformed-owners).
- L'utilisateur actuel est un utilisateur externe qui ne dispose pas de la permission d'accès au groupe interne de propriétaires du code.

## La règle d'approbation est invalide {#approval-rule-is-invalid}

Vous pourriez obtenir une erreur indiquant :

```plaintext
Approval rule is invalid.
GitLab has approved this rule automatically to unblock the merge request.
```

Ce problème survient lorsqu'une règle d'approbation utilise un propriétaire du code qui n'est pas un membre direct du projet.

La solution de contournement consiste à vérifier que le groupe ou l'utilisateur a été invité au projet.

## `CODEOWNERS` non mis à jour lors du changement de noms d'utilisateurs ou de groupes {#codeowners-not-updated-when-user-or-group-names-change}

Lorsqu'un utilisateur ou un groupe change de nom, le fichier `CODEOWNERS` n'est pas automatiquement mis à jour avec les nouveaux noms. Pour saisir les nouveaux noms, vous devez modifier le fichier.

Les organisations utilisant SAML SSO peuvent [définir des noms d'utilisateurs](../../../integration/saml.md#set-a-username) pour empêcher les utilisateurs de modifier leurs noms d'utilisateurs.

## Incompatibilité avec les verrous globaux d'appartenance aux groupes {#incompatibility-with-global-group-memberships-locks}

La fonctionnalité Propriétaires du code nécessite des appartenances directes aux groupes pour les projets. Lorsque les verrous globaux d'appartenance aux groupes sont activés, ils empêchent les groupes d'être invités en tant que membres directs dans les projets. Cela crée une incompatibilité entre les deux fonctionnalités.

Lorsque le verrou global d'appartenance aux groupes [SAML](../../group/saml_sso/group_sync.md#global-saml-group-memberships-lock) ou [LDAP](../../../administration/auth/ldap/ldap_synchronization.md#global-ldap-group-memberships-lock) est activé, vous ne pouvez pas utiliser des groupes ou des sous-groupes comme propriétaires du code.

Si vous avez activé le verrou global d'appartenance aux groupes SAML ou LDAP, vous disposez des options suivantes :

- Utilisez des utilisateurs individuels comme propriétaires du code plutôt que des groupes.
- Si l'utilisation de propriétaires du code basés sur des groupes est une priorité plus élevée, désactivez le verrou global d'appartenance aux groupes.

La prise en charge des membres de groupes hérités est proposée dans le [ticket 288851](https://gitlab.com/gitlab-org/gitlab/-/issues/288851).
