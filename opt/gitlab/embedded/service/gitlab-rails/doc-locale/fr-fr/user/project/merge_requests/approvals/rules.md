---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Utilisez les règles d'approbation pour définir les utilisateurs ou les groupes qui doivent approuver les merge requests. Les approbateurs peuvent être facultatifs ou obligatoires."
title: "Règles d'approbation des merge requests"
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les règles d'approbation définissent le nombre d'[approbations](_index.md) qu'une merge request doit recevoir avant de pouvoir être fusionnée, et quels utilisateurs doivent effectuer ces approbations. Elles peuvent être utilisées conjointement avec les [propriétaires du code](#code-owners-as-approvers) pour s'assurer que les modifications sont examinées à la fois par le groupe qui maintient la fonctionnalité et par tout groupe responsable de domaines spécifiques de supervision.

Vous pouvez définir des règles d'approbation :

- [En tant que valeurs par défaut du projet](#add-an-approval-rule).
- [Par merge request](#edit-or-override-merge-request-approval-rules).

Vous pouvez configurer des règles d'approbation :

- [Pour l'ensemble de l'instance](../../../../administration/merge_requests_approvals.md).

Si vous ne définissez pas de [règle d'approbation par défaut](#add-an-approval-rule), tout utilisateur peut approuver une merge request. Même si vous ne définissez pas de règle, vous pouvez toujours imposer un [nombre minimum d'approbateurs requis](settings.md) dans les paramètres du projet.

Les merge requests qui ciblent un projet différent, par exemple d'une duplication vers le projet amont, utilisent les règles d'approbation par défaut du projet cible (amont), et non du projet source (duplication).

Les approbations de merge request peuvent être configurées globalement pour s'appliquer à tous les projets (ou à un sous-ensemble) via des [politiques](../../../application_security/policies/_index.md). Les [politiques d'approbation de merge request](../../../application_security/policies/merge_request_approval_policies.md) offrent également une flexibilité supplémentaire avec des options de configuration plus granulaires.

## Ajouter une règle d'approbation {#add-an-approval-rule}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.
- Pour ajouter un groupe en tant qu'approbateur dans GitLab.com, vous devez être membre du groupe ou le groupe doit être public.

Pour ajouter une règle d'approbation de merge request :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, dans la section **Règles d'approbation**, sélectionnez **Ajouter une règle d'approbation**.
1. Dans la barre latérale droite, renseignez les champs :
   - Dans **Approbation requise**, une valeur de `0` rend [la règle facultative](#configure-optional-approval-rules), et tout nombre supérieur à `0` crée une règle obligatoire. Le nombre maximum d'approbations requises est de `100`.
   - Dans **Ajouter des approbateurs**, sélectionnez les utilisateurs ou les groupes [éligibles à l'approbation](#eligible-approvers). GitLab suggère des approbateurs en fonction des auteurs précédents des fichiers modifiés par la merge request.
1. Sélectionnez **Enregistrer les modifications**. Vous pouvez ajouter [plusieurs règles d'approbation](#multiple-approval-rules).

Votre configuration pour les remplacements de règles d'approbation détermine si la nouvelle règle est appliquée aux merge requests existantes :

- Si les [remplacements de règles d'approbation](settings.md#prevent-editing-approval-rules-in-merge-requests) sont autorisés, les modifications apportées à ces règles par défaut ne sont pas appliquées aux merge requests existantes, sauf pour les modifications apportées à la [branche cible](#approvals-for-protected-branches) de la règle.
- Si les remplacements de règles d'approbation ne sont pas autorisés, toutes les modifications apportées aux règles par défaut sont appliquées aux merge requests existantes. Les règles d'approbation qui ont été précédemment [remplacées](#edit-or-override-merge-request-approval-rules) manuellement pendant la période où les remplacements de règles d'approbation étaient autorisés ne sont pas modifiées.

## Modifier une règle d'approbation {#edit-an-approval-rule}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.
- Pour ajouter un groupe en tant qu'approbateur dans GitLab.com, vous devez être membre du groupe ou le groupe doit être public.

Pour modifier une règle d'approbation de merge request :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, dans la section **Règles d'approbation**, à côté de la règle que vous souhaitez modifier, sélectionnez **Modifier**.
1. Dans la barre latérale droite, modifiez les champs :
   - Dans **Approbation requise**, une valeur de `0` rend [la règle facultative](#configure-optional-approval-rules), et tout nombre supérieur à `0` crée une règle obligatoire. Le nombre maximum d'approbations requises est de `100`.
   - Pour supprimer des utilisateurs ou des groupes, identifiez le groupe ou l'utilisateur à supprimer, puis sélectionnez **Supprimer** ({{< icon name="remove" >}}).
1. Sélectionnez **Enregistrer les modifications**.

## Supprimer une règle d'approbation {#delete-an-approval-rule}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour supprimer une règle d'approbation de merge request :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, à côté de la règle que vous souhaitez supprimer, sélectionnez la corbeille ({{< icon name="remove" >}}).
1. Sélectionnez **Supprimer les approbateurs**.

## Règles d'approbation multiples {#multiple-approval-rules}

Pour imposer plusieurs règles d'approbation sur une merge request, ajoutez plusieurs règles d'approbation par défaut pour un projet.

Lorsqu'un [approbateur éligible](#eligible-approvers) approuve une merge request, cela réduit le nombre d'approbations restantes (la colonne **Approbations**) pour toutes les règles auxquelles appartient l'approbateur :

![Le widget d'approbations affichant les règles des propriétaires du code avec les approbateurs éligibles, les exigences et le statut d'approbation.](img/mr_approvals_widget_v16_0.png)

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une vue d'ensemble, consultez la vidéo [multiple approvers](https://www.youtube.com/watch?v=8JQJ5821FrA).

## Recevoir des notifications pour toutes les merge requests que vous pouvez approuver {#get-notified-about-all-merge-requests-you-can-approve}

Pour recevoir des notifications par e-mail chaque fois qu'une merge request que vous êtes éligible à approuver est créée :

- [Définissez votre niveau de notification](../../../profile/notifications.md#edit-notification-settings) sur **Personnalisé** et sélectionnez l'événement **Une requête de fusion que vous pouvez approuver a été créée**.

## Modifier ou remplacer les règles d'approbation de merge request {#edit-or-override-merge-request-approval-rules}

Vous pouvez remplacer les règles d'approbation de merge request pour un projet en :

- Modifiant une merge request existante.
- Créant une nouvelle merge request.

Prérequis :

- Le paramètre de projet [**Empêcher la modification des règles d'approbation dans les requêtes de fusion**](settings.md#prevent-editing-approval-rules-in-merge-requests) est désactivé.
- L'une des conditions suivantes doit être remplie :
  - Vous disposez d'un accès administrateur.
  - Vous êtes l'auteur de la merge request et vous disposez du rôle Developer, Maintainer ou Owner dans le projet.
  - Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour remplacer les approbateurs d'une merge request :

1. Lors de la [création d'une nouvelle merge request](../creating_merge_requests.md), faites défiler jusqu'à la section **Règles d'approbation** et ajoutez ou supprimez les règles d'approbation souhaitées avant de sélectionner **Créer une requête de fusion**.
1. Lors de la consultation d'une merge request existante :
   1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
   1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion** et repérez votre merge request.
   1. Sélectionner **Éditer**.
   1. Faites défiler jusqu'à la section **Règles d'approbation**.
   1. Ajoutez ou supprimez les règles d'approbation souhaitées.
   1. Sélectionnez **Enregistrer les modifications**.

Les administrateurs peuvent modifier les [paramètres d'approbation des merge requests](settings.md#prevent-editing-approval-rules-in-merge-requests) pour empêcher les utilisateurs de remplacer les règles d'approbation pour les merge requests.

## Exiger plusieurs approbations pour une règle {#require-multiple-approvals-for-a-rule}

Pour créer une règle d'approbation qui nécessite plus d'une approbation :

- Lorsque vous [créez](#add-an-approval-rule) ou [modifiez](#edit-an-approval-rule) une règle, définissez **Approbation requise** sur `2` ou plus.

Pour exiger plusieurs approbations pour une règle, vous pouvez également utiliser l'[API d'approbation des merge requests](../../../../api/merge_request_approvals.md#update-an-approval-rule-for-a-project) pour définir l'attribut `approvals_required` sur `2` ou plus.

## Configurer des règles d'approbation facultatives {#configure-optional-approval-rules}

Les approbations de merge request peuvent être facultatives pour les projets où les approbations sont appréciées, mais non obligatoires. Pour rendre une règle d'approbation facultative :

- Lorsque vous [créez ou modifiez une règle](#edit-an-approval-rule), définissez **Approbation requise** sur `0`.

Pour rendre une règle d'approbation facultative, vous pouvez également utiliser l'API pour [mettre à jour une règle d'approbation pour un projet](../../../../api/merge_request_approvals.md#update-an-approval-rule-for-a-project) et définir l'attribut `approvals_required` sur `0`.

## Approbations pour les branches protégées {#approvals-for-protected-branches}

Les règles d'approbation sont souvent pertinentes uniquement pour des branches spécifiques, comme votre [branche par défaut](../../repository/branches/default.md). Pour configurer une règle d'approbation pour certaines branches :

1. [Créez une règle d'approbation](#add-an-approval-rule).
1. Accédez à votre projet et sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, faites défiler jusqu'à **Règles d'approbation**.
1. Pour **Branche cible** :
   - Pour appliquer la règle à toutes les branches protégées, sélectionnez **Toutes les branches protégées**.
   - Pour appliquer la règle à une branche spécifique, sélectionnez-la dans la liste.
1. Pour activer cette configuration, suivez [Exiger l'approbation du propriétaire du code sur une branche protégée](../../repository/branches/protected.md#require-code-owner-approval).

## Activer les autorisations d'approbation pour des utilisateurs supplémentaires {#enable-approval-permissions-for-additional-users}

Avant que les utilisateurs disposant du rôle Planificateur ou Reporter puissent fusionner vers une branche protégée, vous devez leur accorder l'autorisation d'approuver les merge requests. Certains utilisateurs (comme les responsables) peuvent ne pas avoir besoin de l'autorisation de pousser ou de fusionner du code, mais ont tout de même besoin d'une supervision sur le travail proposé.

Les utilisateurs disposant du rôle Planificateur ou Reporter ne peuvent approuver les merge requests que via des règles d'approbation régulières. Les règles d'approbation des propriétaires du code exigent que les utilisateurs disposent du rôle Developer, Maintainer ou Owner. Pour plus d'informations, consultez [les approbateurs éligibles](#eligible-approvers).

Prérequis :

- Vous devez sélectionner une branche spécifique, car cette méthode ne fonctionne pas avec les paramètres `All Branches` ou `All protected branches`.
- Le groupe partagé doit être ajouté à une règle d'approbation et non à des utilisateurs individuels, même si l'utilisateur ajouté fait partie du groupe.

Pour activer les autorisations d'approbation pour ces utilisateurs sans leur accorder l'accès en push :

1. [Créez une branche protégée](../../repository/branches/protected.md)
1. [Créez un nouveau groupe](../../../group/_index.md#create-a-group) pour les utilisateurs disposant du rôle Planificateur ou Reporter qui ont besoin d'autorisations d'approbation.
1. [Ajoutez les utilisateurs au groupe](../../../group/_index.md#add-users-to-a-group). Les utilisateurs doivent disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner.
1. [Partagez le projet avec votre groupe](../../members/sharing_projects_groups.md#invite-a-group-to-a-project), avec le rôle Reporter, Developer, Maintainer ou Owner.
1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, dans la section **Règles d'approbation** :
   - Pour une nouvelle règle, sélectionnez **Ajouter une règle d'approbation** et ciblez la branche protégée.
   - Pour une règle existante, sélectionnez **Modifier** et ciblez la branche protégée.
1. Dans la barre latérale droite, dans **Ajouter des approbateurs**, sélectionnez le groupe que vous avez créé.
1. Sélectionnez **Enregistrer les modifications**.

## Approbations de sécurité {#security-approvals}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez utiliser les [politiques d'approbation de merge request](../../../application_security/policies/merge_request_approval_policies.md#merge-request-approval-policy-editor) pour définir des approbations de sécurité en fonction du statut des vulnérabilités dans la merge request et dans la branche par défaut. Les détails de chaque politique de sécurité sont affichés dans la section Approbations de sécurité de votre configuration de merge request.

Les règles d'approbation de sécurité s'appliquent à toutes les merge requests jusqu'à la fin du pipeline. L'application des règles d'approbation de sécurité empêche les utilisateurs de fusionner du code avant l'exécution des analyses de sécurité. Une fois le pipeline terminé, les règles d'approbation de sécurité sont vérifiées pour déterminer si les approbations de sécurité sont toujours requises. Si les scanners du pipeline identifient un problème et que des approbations de sécurité sont requises, un commentaire de bot est généré sur la merge request pour indiquer les étapes nécessaires pour continuer.

![La section Approbations de sécurité affichant une règle de politique qui nécessite une approbation lorsqu'un scanner détecte des vulnérabilités.](img/security_approvals_v15_0.png)

Ces politiques sont à la fois créées et modifiées dans l'[éditeur de politique de sécurité](../../../application_security/policies/_index.md#policy-editor).

## Approbateurs éligibles {#eligible-approvers}

Pour être éligible en tant qu'approbateur pour votre projet, un utilisateur doit être un membre direct d'au moins l'un des éléments suivants :

- Votre projet.
- Le groupe de votre projet.
- L'un des groupes parents du groupe de votre projet.
- Un autre groupe qui a été [partagé avec votre projet](../../members/sharing_projects_groups.md#sharing-projects).
- Un autre groupe qui a été [partagé avec le groupe de votre projet ou l'un des parents du groupe](../../members/sharing_projects_groups.md#sharing-groups).
- Un [groupe ajouté en tant qu'approbateur](#group-approvers).

Les utilisateurs disposant du rôle Developer peuvent approuver les merge requests si l'une des conditions suivantes est remplie :

- Utilisateurs ajoutés en tant qu'approbateurs au niveau du projet ou de la merge request.
- Utilisateurs qui sont des [propriétaires du code](#code-owners-as-approvers) des fichiers modifiés dans la merge request.

Les utilisateurs disposant du rôle Planificateur ou Reporter ne peuvent approuver que si toutes les conditions suivantes sont remplies :

- Les utilisateurs font partie d'un groupe qui a été [partagé](../../members/sharing_projects_groups.md) avec le projet. Le groupe doit disposer du rôle Reporter, Developer, Maintainer ou Owner.
- Les autorisations d'approbation pour les utilisateurs disposant du rôle Planificateur et Reporter [sont activées](#enable-approval-permissions-for-additional-users).

Pour afficher qui a participé à la revue de la merge request, le widget Approbations dans une merge request affiche une colonne **Commentaire effectué par**. Cette colonne liste les approbateurs éligibles qui ont commenté la merge request. Elle aide les auteurs et les relecteurs à identifier qui contacter pour des questions sur le contenu de la merge request.

Si le nombre d'approbations requises est supérieur au nombre d'approbateurs assignés, les approbations d'autres utilisateurs disposant du rôle Developer, Maintainer ou Owner dans le projet sont comptabilisées pour atteindre le nombre d'approbations requis, même si ces utilisateurs ne sont pas explicitement listés dans les règles d'approbation.

### Propriétaires du code en tant qu'approbateurs {#code-owners-as-approvers}

Si vous ajoutez des [propriétaires du code](../../codeowners/_index.md) à votre dépôt, les propriétaires des fichiers deviennent des approbateurs éligibles dans le projet. Pour activer cette règle d'approbation de merge request :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Approbations des requêtes de fusion**, dans la section **Règles d'approbation**, repérez la règle **Tous les utilisateurs/utilisatrices éligibles**.
1. Dans la colonne **Approbation requise**, saisissez le nombre d'approbations requises.

Vous pouvez également [exiger l'approbation du propriétaire du code](../../repository/branches/protected.md#require-code-owner-approval) pour les branches protégées.

### Approbateur par type d'appartenance {#approver-by-membership-type}

Les tableaux suivants montrent comment le type d'appartenance affecte l'éligibilité pour les règles d'approbation et les propriétaires du code.

#### Éligibilité des utilisateurs {#user-eligibility}

Lorsque vous assignez des utilisateurs individuels en tant qu'approbateurs pour des règles d'approbation ou que vous référencez des utilisateurs dans des fichiers `CODEOWNERS`, comme `@username` :

| Type d'appartenance                                                                                                    | Règles d'approbation | Propriétaires du code |
|--------------------------------------------------------------------------------------------------------------------|----------------|-------------|
| Membre direct du projet                                                                                       | {{< yes >}}    | {{< yes >}} |
| Membre direct du groupe du projet                                                                               | {{< yes >}}    | {{< yes >}} |
| Membre hérité du groupe du projet                                                                            | {{< yes >}}    | {{< yes >}} |
| Membre direct d'un [groupe invité dans le projet](../../members/sharing_projects_groups.md#sharing-projects)       | {{< yes >}}    | {{< yes >}} |
| Membre hérité d'un groupe invité dans le projet                                                                 | {{< no >}}     | {{< no >}}  |
| Membre direct d'un [groupe invité dans le groupe du projet](../../members/sharing_projects_groups.md#sharing-groups) | {{< yes >}}    | {{< yes >}} |
| Membre hérité d'un groupe invité dans le groupe du projet                                                         | {{< no >}}     | {{< no >}}  |
| Membre direct d'un groupe invité dans les groupes parents du groupe du projet                                            | {{< yes >}}    | {{< yes >}} |
| Membre hérité d'un groupe invité dans les groupes parents du groupe du projet                                         | {{< no >}}     | {{< no >}}  |

#### Éligibilité des groupes {#group-eligibility}

Lorsque vous assignez des groupes en tant qu'approbateurs pour des règles d'approbation ou que vous référencez des groupes dans des fichiers `CODEOWNERS`, comme `@group-name`, seuls les membres directs des groupes éligibles peuvent fournir des approbations :

| Type de groupe                                                                                       | Règles d'approbation | Propriétaires du code |
|--------------------------------------------------------------------------------------------------|----------------|-------------|
| [Groupes invités dans le projet](../../members/sharing_projects_groups.md#sharing-projects)       | {{< yes >}}    | {{< yes >}} |
| [Groupes invités dans le groupe du projet](../../members/sharing_projects_groups.md#sharing-groups) | {{< yes >}}    | {{< no >}}  |
| Groupes invités dans un groupe parent du groupe du projet                                                | {{< yes >}}    | {{< no >}}  |
| Le groupe du projet                                                                              | {{< yes >}}    | {{< yes >}} |
| Un groupe parent du groupe du projet                                                                  | {{< yes >}}    | {{< yes >}} |

> [!note]
> Pour les approbations basées sur des groupes, seuls les membres directs du groupe peuvent approuver les merge requests. Les membres hérités des groupes éligibles ne peuvent pas fournir d'approbations.

### Approbateurs de groupe {#group-approvers}

Vous pouvez ajouter un groupe d'utilisateurs en tant qu'approbateurs. Tous les membres directs de ce groupe peuvent approuver la règle. Les membres hérités ne peuvent pas approuver la règle.

En général, le groupe est un sous-groupe dans votre espace de nommage de niveau supérieur, sauf si vous collaborez avec un groupe externe. Si vous collaborez avec un autre groupe et souhaitez utiliser les membres de ce groupe en tant qu'approbateurs, vous pouvez soit :

- [Partager l'accès au projet](../../members/sharing_projects_groups.md#sharing-projects).
- [Partager l'accès au groupe de votre projet](../../members/sharing_projects_groups.md#sharing-groups), ce qui donne au groupe externe un accès d'approbation à tous les projets du groupe de votre projet.

L'appartenance d'un utilisateur à un groupe approbateur détermine ses autorisations d'approbation individuelles de la manière suivante :

- Les membres hérités ne sont pas considérés comme des approbateurs. Seuls les membres directs peuvent approuver les merge requests.
- Un utilisateur d'un groupe approbateur qui est ensuite également ajouté en tant qu'approbateur individuel est comptabilisé comme un seul approbateur, et non deux.
- Par défaut, les auteurs de merge requests ne sont pas comptabilisés comme approbateurs éligibles pour leurs propres merge requests. Pour modifier ce comportement, désactivez le paramètre de projet [**Empêcher l'approbation par le créateur de la merge request**](settings.md#prevent-approval-by-merge-request-creator).
- Par défaut, les contributeurs aux merge requests peuvent approuver une merge request. Pour modifier ce comportement, activez le paramètre de projet [**Empêcher l'approbation par les contributeurs**](settings.md#prevent-approvals-by-users-who-add-commits).

## Dépannage {#troubleshooting}

### Le nom de la règle d'approbation ne peut pas être vide {#approval-rule-name-cant-be-blank}

Pour contourner cette erreur de validation, vous pouvez supprimer la règle d'approbation via l'API.

1. [Lister toutes les règles d'approbation pour le projet](../../../../api/merge_request_approvals.md#list-all-approval-rules-for-a-project).
1. [Supprimer (DELETE) la règle](../../../../api/merge_request_approvals.md#delete-an-approval-rule-for-a-project).

Pour plus d'informations sur cette erreur de validation, consultez le [ticket 285129](https://gitlab.com/gitlab-org/gitlab/-/issues/285129).

### Les groupes ont besoin du rôle Developer explicite ou hérité sur un projet {#groups-need-explicit-or-inherited-developer-role-on-a-project}

Un groupe créé pour gérer les approbations peut être créé dans une zone différente de la hiérarchie du projet par rapport au projet nécessitant une revue. Dans ce cas, les membres du groupe peuvent ne pas avoir l'autorisation d'approuver la merge request car ils n'y ont pas accès.

Par exemple :

Dans la structure de groupe ci-dessous, le projet 1 appartient au sous-groupe 1 et le sous-groupe 4 contient des utilisateurs.

![Exemple de scénario - hiérarchie du projet et du groupe](img/group_access_example_01_v16_8.png)

Le projet 1 a configuré une règle d'approbation pour le projet, qui assigne le sous-groupe 4 en tant qu'approbateurs. Lorsqu'une merge request est créée, les approbateurs du sous-groupe 4 apparaissent dans la liste des approbateurs éligibles. Cependant, comme les utilisateurs du sous-groupe 4 n'ont pas l'autorisation de consulter la merge request, l'erreur `404` est renvoyée. Pour accorder l'appartenance, le groupe doit être invité en tant que membre du projet. Il est désormais possible pour les utilisateurs du sous-groupe 4 d'approuver.

![Page des membres du projet affichant le sous-groupe 4 en tant que membre](img/group_access_example_02_v16_8.png)
