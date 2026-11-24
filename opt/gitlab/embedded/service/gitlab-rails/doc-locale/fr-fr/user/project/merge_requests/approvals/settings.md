---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Définissez des règles et des limites d'approbation dans GitLab avec les paramètres d'approbation des merge requests. Les options incluent la prévention de l'approbation par l'auteur, l'exigence d'une réauthentification et la suppression des approbations lors de nouveaux commits."
title: "Paramètres d'approbation des merge requests"
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez configurer les paramètres des [approbations de merge requests](_index.md) pour vous assurer que les règles d'approbation correspondent à votre cas d'utilisation. Vous pouvez également configurer des [règles d'approbation](rules.md), qui définissent le nombre et le type d'utilisateurs devant approuver le travail avant qu'il ne soit fusionné. Les paramètres d'approbation des merge requests définissent comment appliquer ces règles au fur et à mesure qu'une merge request avance vers sa finalisation.

Utilisez n'importe quelle combinaison de ces paramètres pour configurer les limites d'approbation des merge requests :

- [**Empêcher l'approbation des requêtes de fusion par leur auteur ou autrice**](#prevent-approval-by-merge-request-creator) : empêche l'auteur d'une merge request de l'approuver.
- [**Empêcher les approbations par les utilisateurs qui ajoutent des validations**](#prevent-approvals-by-users-who-add-commits) : empêche les utilisateurs qui ajoutent des commits à une merge request de l'approuver également.
- [**Empêcher la modification des règles d'approbation dans les requêtes de fusion**](#prevent-editing-approval-rules-in-merge-requests) : empêche les utilisateurs de remplacer les règles d'approbation du projet sur les merge requests.
- [**Exiger une réauthentification utilisateur (mot de passe ou SAML) pour approuver**](#require-user-re-authentication-to-approve) : Force les approbateurs potentiels à s'authentifier d'abord avec un mot de passe ou via SAML.
- Suppressions d'approbations des propriétaires du code : définit ce qui se passe avec les approbations existantes lorsque des commits sont ajoutés à la merge request.
  - **Conserver les approbations** : ne supprimer aucune approbation.
  - [**Supprimer toutes les approbations**](#remove-all-approvals-when-commits-are-added-to-the-source-branch) : supprimer toutes les approbations existantes.
  - [**Supprimer les approbations données par les propriétaires du code si leurs fichiers ont été modifiés**](#remove-approvals-by-code-owners-if-their-files-changed) : si un propriétaire du code approuve une merge request et qu'un commit ultérieur modifie des fichiers dont il est propriétaire du code, son approbation est supprimée.

## Modifier les paramètres d'approbation des merge requests {#edit-merge-request-approval-settings}

Pour afficher ou modifier les paramètres d'approbation des merge requests pour un seul projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Développez **Approbations**.

### Paramètres en cascade depuis l'instance ou le groupe principal {#cascade-settings-from-the-instance-or-top-level-group}

Pour simplifier la gestion des paramètres de règles d'approbation, configurez-les aussi largement que possible. Paramètres configurés :

- [Pour votre instance](../../../../administration/merge_requests_approvals.md), ils s'appliquent à tous les groupes et projets de l'instance.
- Pour un [groupe principal](../../../group/manage.md#group-merge-request-approval-settings), ils s'appliquent à ses sous-groupes et projets.

La façon dont un paramètre se propage en cascade dépend de l'endroit où il est configuré :

- Un paramètre configuré pour votre instance verrouille le paramètre équivalent pour tous les groupes et projets. Vous ne pouvez pas modifier le paramètre hérité dans un groupe ou un projet.
- Un paramètre configuré pour un groupe principal se propage en cascade à ses sous-groupes et projets :
  - Lorsqu'un paramètre de prévention est activé pour un groupe, le paramètre de projet équivalent est verrouillé. Les Mainteneurs de projet ne peuvent pas le modifier.
  - Lorsqu'un paramètre de prévention est désactivé pour un groupe, les Mainteneurs de projet peuvent le configurer pour des projets individuels.

## Empêcher l'approbation par le créateur de la merge request {#prevent-approval-by-merge-request-creator}

Par défaut, le créateur d'une merge request (auteur) ne peut pas l'approuver. Pour modifier ce paramètre :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, faites défiler jusqu'à **Paramètres d'approbation** et décochez la case **Empêcher l'approbation des requêtes de fusion par leur auteur ou autrice**.
1. Sélectionnez **Enregistrer les modifications**.

Les créateurs de merge requests peuvent modifier la règle d'approbation dans une merge request individuelle et remplacer ce paramètre, sauf si vous configurez l'une de ces options :

- [Empêcher les remplacements des approbations par défaut](#prevent-editing-approval-rules-in-merge-requests) pour votre projet.
- *(Instances GitLab Self-Managed uniquement)* Empêcher les remplacements des approbations par défaut [pour votre instance](../../../../administration/merge_requests_approvals.md). Lorsque ce paramètre est configuré pour votre instance, vous ne pouvez pas modifier ce paramètre sur les projets ou les merge requests individuelles.

## Empêcher les approbations par les utilisateurs qui ajoutent des commits {#prevent-approvals-by-users-who-add-commits}

Par défaut, les utilisateurs qui effectuent des commits dans une merge request (les validateurs) peuvent toujours l'approuver. Pour empêcher les validateurs de votre projet (ou de votre instance) d'approuver des merge requests qui sont partiellement les leurs :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, faites défiler jusqu'à **Paramètres d'approbation** et sélectionnez **Empêcher les approbations par les utilisateurs qui ajoutent des validations**. Si cette case est décochée, un administrateur l'a désactivée [pour votre instance](../../../../administration/merge_requests_approvals.md), et vous ne pouvez pas la modifier pour votre projet.
1. Sélectionnez **Enregistrer les modifications**.

Les [propriétaires du code](../../codeowners/_index.md) qui effectuent des commits dans une merge request ne peuvent pas l'approuver si la merge request affecte des fichiers dont ils sont propriétaires.

Pour plus d'informations, consultez la [documentation officielle de Git](https://git-scm.com/book/en/v2/Git-Basics-Viewing-the-Commit-History).

> [!warning]
> Si une merge request est rebasée par quelqu'un d'autre que l'utilisateur qui a initialement commis les modifications, l'historique des commits est réécrit avec un nouveau validateur. Cela pourrait permettre aux utilisateurs qui avaient précédemment commis des modifications dans une merge request d'approuver désormais des modifications dans celle-ci, car ils ne sont plus considérés comme validateurs.
>
> Voir aussi [approuver après un rebase](../../../../topics/git/git_rebase.md#approving-after-rebase)

## Empêcher la modification des règles d'approbation dans les merge requests {#prevent-editing-approval-rules-in-merge-requests}

Par défaut, les utilisateurs peuvent remplacer les règles d'approbation que vous [créez pour un projet](rules.md) sur la base d'une merge request individuelle. Si vous ne souhaitez pas que les utilisateurs modifient les règles d'approbation sur les merge requests, vous pouvez désactiver ce paramètre :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, faites défiler jusqu'à **Paramètres d'approbation** et sélectionnez **Empêcher la modification des règles d'approbation dans les requêtes de fusion**.
1. Sélectionnez **Enregistrer les modifications**.

> [!note]
> Ce paramètre a une portée différente à chaque niveau. Pour un projet ou un groupe, il empêche les remplacements de règles d'approbation par merge request. La liste des règles d'approbation dans les paramètres du projet reste modifiable. Pour empêcher également les Mainteneurs de projet de modifier la liste des règles d'approbation, un administrateur doit activer [**Empêcher la modification des règles d'approbation dans les projets et les requêtes de fusion**](../../../../administration/merge_requests_approvals.md) pour votre instance. Lorsque vous modifiez ce champ, cela peut affecter toutes les merge requests ouvertes en fonction du paramètre :

- Si les utilisateurs pouvaient auparavant modifier les règles d'approbation et que vous désactivez ce comportement, GitLab met à jour toutes les merge requests ouvertes pour appliquer les règles d'approbation.
- Si les utilisateurs ne pouvaient pas auparavant modifier les règles d'approbation et que vous activez la modification des règles d'approbation, les merge requests ouvertes restent inchangées. Cela préserve toute modification déjà apportée aux règles d'approbation dans ces merge requests.

## Exiger une réauthentification utilisateur pour approuver {#require-user-re-authentication-to-approve}

{{< history >}}

- L'exigence de réauthentification via l'authentification SAML pour les groupes GitLab.com a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/5981) dans GitLab 16.6 [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `ff_require_saml_auth_to_approve`. Fonctionnalité désactivée par défaut.
- L'exigence de réauthentification via l'authentification SAML pour les instances GitLab Self-Managed a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/431415) dans GitLab 16.7 [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `ff_require_saml_auth_to_approve`. Fonctionnalité désactivée par défaut.
- [Activation de `ff_require_saml_auth_to_approve` par défaut](https://gitlab.com/gitlab-org/gitlab/-/issues/431714) dans GitLab 16.8 pour GitLab.com et les instances GitLab Self-Managed.
- Feature flag supprimé dans GitLab 18.3

{{< /history >}}

> [!flag]
> Sur GitLab Self-Managed, l'exigence de réauthentification via l'authentification SAML est disponible par défaut. Pour masquer la fonctionnalité, un administrateur peut [désactiver le feature flag](../../../../administration/feature_flags/_index.md) `ff_require_saml_auth_to_approve`. Sur GitLab.com et GitLab Dedicated, cette fonctionnalité est disponible.

Vous pouvez forcer les approbateurs potentiels à s'authentifier d'abord avec SAML ou un mot de passe. Cette autorisation permet une signature électronique pour les approbations, telle que celle définie par le [Code of Federal Regulations (CFR) Part 11](https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfcfr/CFRSearch.cfm?CFRPart=11&showFR=1&subpartNode=21:1.0.1.1.8.3).

Prérequis :

- Ce paramètre est uniquement disponible pour les groupes principaux.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Activez l'authentification par mot de passe et l'authentification SAML. Pour plus d'informations sur :
   - L'authentification par mot de passe, consultez la [documentation sur les restrictions de connexion](../../../../administration/settings/sign_in_restrictions.md#password-and-passkey-authentication).
   - L'authentification SAML pour les groupes GitLab.com, consultez la [documentation sur l'authentification SSO SAML pour les groupes GitLab.com](../../../group/saml_sso/_index.md).
   - L'authentification SAML pour les instances GitLab Self-Managed, consultez [l'authentification SSO SAML pour GitLab Self-Managed](../../../../integration/saml.md).
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, faites défiler jusqu'à **Paramètres d'approbation** et sélectionnez **Exiger une réauthentification utilisateur (mot de passe ou SAML) pour approuver**.
1. Sélectionnez **Enregistrer les modifications**.

## Supprimer toutes les approbations lorsque des commits sont ajoutés à la branche source {#remove-all-approvals-when-commits-are-added-to-the-source-branch}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Par défaut, une approbation sur une merge request est supprimée lorsque vous ajoutez d'autres modifications après l'approbation.

GitLab utilise [`git patch-id`](https://git-scm.com/docs/git-patch-id) pour identifier les diffs dans les merge requests. Cette valeur est un identifiant raisonnablement stable et unique, qui permet de prendre des décisions plus intelligentes concernant la réinitialisation des approbations dans une merge request. Lorsque vous poussez de nouvelles modifications vers une merge request, le `patch-id` est évalué par rapport au `patch-id` précédent pour déterminer si les approbations doivent être réinitialisées. Cela permet à GitLab de prendre de meilleures décisions de réinitialisation lorsque vous exécutez des commandes telles que `git rebase` ou `git merge <target>` sur une branche de fonctionnalité.

Pour conserver les approbations existantes après l'ajout de modifications supplémentaires à une merge request :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, faites défiler jusqu'à **Paramètres d'approbation** et décochez la case **Supprimer toutes les approbations**.
1. Sélectionnez **Enregistrer les modifications**.

Si vous automatisez la création et l'approbation des merge requests, intégrez une logique pour vous assurer que les commits sont entièrement traités avant d'approuver la merge request. Cela évite une réinitialisation involontaire des approbations. Pour plus d'informations, consultez [gérer les problèmes de synchronisation avec les approbations automatisées](../../../../api/merge_request_approvals.md#prevent-approval-resets-in-automated-merge-requests).

## Supprimer les approbations des propriétaires du code si leurs fichiers ont été modifiés {#remove-approvals-by-code-owners-if-their-files-changed}

Pour supprimer les approbations uniquement des propriétaires du code dont les fichiers sont modifiés dans un nouveau commit :

Prérequis :

- Vous devez disposer du rôle Mainteneur ou Propriétaire pour un projet.

Pour cela :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, faites défiler jusqu'à **Paramètres d'approbation** et sélectionnez **Supprimer les approbations données par les propriétaires du code si leurs fichiers ont été modifiés**.
1. Sélectionnez **Enregistrer les modifications**.

## Sujets connexes {#related-topics}

- [Paramètres d'approbation des merge requests pour votre instance](../../../../administration/merge_requests_approvals.md)
- [Centre de conformité](../../../compliance/compliance_center/_index.md)
- [API des approbations de merge requests](../../../../api/merge_request_approvals.md)
- [API des paramètres d'approbation des merge requests](../../../../api/merge_request_approval_settings.md)
