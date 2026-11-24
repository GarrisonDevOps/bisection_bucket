---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Pour vous assurer que toutes les modifications sont examinées, configurez des approbations facultatives ou obligatoires pour les merge requests dans votre projet."
title: Approbations des merge requests
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour configurer un processus de revue des modifications dans votre projet, paramétrez les approbations de merge request. Elles permettent de s'assurer que les modifications sont examinées avant d'être fusionnées dans votre projet. Vous pouvez configurer des approbations facultatives ou obligatoires selon les besoins de votre projet et votre édition GitLab.

Pour en savoir plus sur la relation entre les approbations, les personnes assignées et les relecteurs, consultez [personnes assignées et relecteurs](../_index.md#assignees-and-reviewers).

- [GitLab Gratuite](https://about.gitlab.com/pricing/) permet à tous les utilisateurs disposant au minimum du [rôle](../../../permissions.md) Développeur d'approuver les merge requests. Ces approbations sont facultatives et n'empêchent pas la fusion sans approbation.
- [GitLab Premium](https://about.gitlab.com/pricing/) et [GitLab Ultimate](https://about.gitlab.com/pricing/) vous offrent plus de flexibilité pour :

  - Créer des [règles](rules.md) obligatoires concernant le nombre et le type d'approbations requises.
  - Créer une liste de [propriétaires du code](../../codeowners/_index.md) pour des fichiers spécifiques.
  - Configurer les approbations [pour l'ensemble de l'instance](../../../../administration/merge_requests_approvals.md).
  - Configurer les [paramètres d'approbation des merge requests au niveau du groupe](../../../group/manage.md#group-merge-request-approval-settings).

    > [!note]
    > La prise en charge des paramètres d'approbation des merge requests au niveau du groupe est suivie dans l'[epic 4367](https://gitlab.com/groups/gitlab-org/-/work_items/4367).

## Configurer les règles d'approbation {#configure-approval-rules}

Prérequis :

- Vous devez disposer du rôle Développeur, Chargé de maintenance ou Propriétaire pour le projet.

Pour configurer les règles d'approbation :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Accédez à la section **Approbations des requêtes de fusion**.
1. Configurez vos règles selon vos besoins.

Vous pouvez également configurer :

- Des [paramètres d'approbation des merge requests](settings.md) supplémentaires pour mieux contrôler le niveau de surveillance et de sécurité dont votre projet a besoin.
- Des règles d'approbation de merge request via l'[API des approbations de merge request](../../../../api/merge_request_approvals.md).

Pour plus d'informations sur la configuration des règles, consultez [les règles d'approbation](rules.md).

### Approbations obligatoires {#required-approvals}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les approbations obligatoires imposent des revues de code par des utilisateurs désignés. Sans ces approbations, la fusion n'est pas possible.

Les cas d'usage incluent :

- Imposer la revue de tout le code fusionné dans un dépôt.
- Spécifier les relecteurs et un nombre minimal d'approbations.
- Spécifier des catégories de relecteurs, telles que backend, frontend, assurance qualité, base de données ou documentation.
- Utiliser le [fichier `CODEOWNERS`](../../codeowners/_index.md#codeowners-file) pour déterminer les relecteurs.
- Exiger une approbation en cas de [baisse de la couverture de tests](../../../../ci/testing/code_coverage/coverage_reporting.md#add-a-coverage-check-approval-rule).
- GitLab Ultimate : [Exiger l'approbation de l'équipe sécurité](../../../application_security/policies/merge_request_approval_policies.md) pour les vulnérabilités potentielles.

## Afficher le statut d'approbation {#view-approval-status}

{{< history >}}

- L'affichage plus granulaire des approbateurs est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/183058) dans GitLab 17.10. Le feature flag `mr_approvers_filter_hidden_users` a été supprimé.

{{< /history >}}

Pour afficher le statut d'approbation d'une merge request, consultez la merge request elle-même ou la liste des merge requests pour votre projet ou groupe.

### Pour une merge request individuelle {#for-a-single-merge-request}

Les [approbateurs éligibles](rules.md#eligible-approvers) peuvent afficher le statut d'approbation d'une merge request individuelle.

Pour afficher le statut d'approbation :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion** et repérez votre merge request.
1. Pour afficher la merge request, sélectionnez son titre.
1. Accédez au widget de la merge request pour voir le statut d'approbation. Dans cet exemple, vous pouvez approuver la merge request :

   ![La section de statut d'approbation où un relecteur peut approuver la merge request.](img/approval_and_merge_status_v17_3.png)

Le widget affiche l'un des statuts suivants :

- **Approuver** : la merge request nécessite davantage d'approbations.
- **Approuver en complément** : la merge request dispose des approbations requises.
- **Révoquer l'approbation** : vous avez déjà approuvé la merge request.

Pour vérifier si votre approbation satisfait aux exigences des propriétaires du code, sélectionnez **Afficher les approbateurs éligibles** ({{< icon name="chevron-lg-down" >}}).

La visibilité des approbateurs dépend de votre appartenance au projet et de la confidentialité du groupe :

- Les membres du projet voient tous les approbateurs.
- Les non-membres du projet voient :
  - Tous les approbateurs, si ceux-ci proviennent tous de groupes publics.
  - Aucune information sur les approbateurs, si certains d'entre eux proviennent de groupes privés.

### Dans la liste des merge requests {#in-the-list-of-merge-requests}

La liste des merge requests pour [votre projet ou groupe](../_index.md#view-merge-requests) affiche le statut d'approbation de chaque merge request :

|                                       Exemple                                       | Description |
|:-----------------------------------------------------------------------------------:|-------------|
|         ![L'indicateur signalant des approbations manquantes.](img/approvals_unsatisfied_v17_1.png)         | Des approbations obligatoires sont manquantes. ({{< icon name="approval" >}}) |
|            ![L'indicateur signalant que les approbations sont satisfaites.](img/approvals_satisfied_v17_1.png)            | Les approbations sont satisfaites. ({{< icon name="check" >}}) |
| ![L'indicateur indiquant que vous avez personnellement approuvé.](img/you_approvals_satisfied_v17_1.png) | Les approbations sont satisfaites, et vous êtes l'un des approbateurs. ({{< icon name="approval-solid" >}}) |

### Statut individuel des relecteurs {#individual-reviewer-status}

Pour afficher le statut de revue et d'approbation de chaque relecteur :

1. Ouvrez la merge request.
1. Consultez la barre latérale droite.

Le statut de chaque relecteur est affiché à côté de son nom.

- {{< icon name="dash-circle" >}} En attente de revue
- {{< icon name="status_running" >}} Revue en cours
- {{< icon name="check-circle" >}} Approuvé
- {{< icon name="comment-lines" >}} Le relecteur a commenté
- {{< icon name="status_warning" >}} Le relecteur a demandé des modifications

  ![Le statut d'avertissement indiquant qu'un relecteur a demandé des modifications.](img/reviewer_blocks_mr_v17_3.png)

Pour [redemander une revue](../reviews/_index.md#re-request-a-review), sélectionnez l'icône **Redemander une revue** ({{< icon name="redo" >}}) à côté de l'utilisateur.

## Approuver une merge request {#approve-a-merge-request}

Les approbateurs éligibles peuvent approuver les merge requests de deux manières :

- Dans le widget de la merge request, sélectionnez **Approuver**.
- Utilisez la [quick action `/approve`](../../quick_actions.md#approve) dans un commentaire.

Les merge requests approuvées affichent une coche verte ({{< icon name="check-circle-filled" >}}) à côté du nom de l'utilisateur dans la liste des relecteurs. Lorsqu'une merge request reçoit les approbations requises, elle est prête à être fusionnée, sauf si elle est bloquée en raison de :

- [Conflits de merge](../conflicts.md)
- [Fils de discussion ouverts](../_index.md#prevent-merge-unless-all-threads-are-resolved)
- [Échec du pipeline CI/CD](../auto_merge.md)

### Empêcher l'approbation de la merge request par son auteur {#prevent-merge-request-creator-approval}

Pour empêcher les auteurs de merge request d'approuver leur propre travail, activez le paramètre [**Empêcher l'approbation des requêtes de fusion par leur auteur ou autrice**](settings.md#prevent-approval-by-merge-request-creator).

### Modifications des règles d'approbation {#approval-rule-changes}

Si vous activez les [remplacements de règles d'approbation](settings.md#prevent-editing-approval-rules-in-merge-requests), les modifications apportées aux règles d'approbation par défaut n'affectent pas les merge requests existantes, à l'exception des modifications de [branche cible](rules.md#approvals-for-protected-branches).

## Règles invalides {#invalid-rules}

GitLab marque les règles d'approbation comme **Approbation automatique** lorsqu'elles sont impossibles à satisfaire, par exemple quand :

- Le seul approbateur éligible est l'auteur de la merge request.
- Aucun approbateur éligible n'est assigné à la règle.
- Les approbations requises dépassent le nombre d'approbateurs éligibles.

Ces règles sont automatiquement approuvées pour débloquer les merge requests, sauf si vous avez créé des règles via une [politique d'approbation des merge requests](../../../application_security/policies/merge_request_approval_policies.md).

Les règles invalides créées par une politique :

- S'affichent comme **Action requise**.
- Ne sont pas automatiquement approuvées.
- Bloquent les merge requests concernées.

## Sujets connexes {#related-topics}

- [API des approbations de merge request](../../../../api/merge_request_approvals.md)
- [Règles d'approbation au niveau de l'instance](../../../../administration/merge_requests_approvals.md) pour les instances GitLab Self-Managed
- [Activer les autorisations d'approbation pour les utilisateurs avec le rôle Planificateur ou Reporter](rules.md#enable-approval-permissions-for-additional-users)
- [Modifier ou remplacer les règles d'approbation des merge requests](rules.md#edit-or-override-merge-request-approval-rules)
