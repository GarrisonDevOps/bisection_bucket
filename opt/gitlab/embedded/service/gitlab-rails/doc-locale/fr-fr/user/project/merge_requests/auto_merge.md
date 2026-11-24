---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Configurez la fusion automatique sur une merge request après avoir examiné son contenu, afin qu'elle puisse fusionner sans intervention lorsque toutes les vérifications de fusion réussissent."
title: Fusion automatique
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Fusion automatique améliorée :
  - [Introduite](https://gitlab.com/groups/gitlab-org/-/work_items/10874) dans GitLab 16.5 [avec deux feature flags](../../../administration/feature_flags/_index.md) nommés `merge_when_checks_pass` et `additional_merge_when_checks_ready`. Fonctionnalité désactivée par défaut.
  - [Fusion](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/154366) du flag `additional_merge_when_checks_ready` avec le flag `merge_when_checks_pass` dans GitLab 17.1.
  - [Disponible en général](https://gitlab.com/gitlab-org/gitlab/-/issues/412995) dans GitLab 17.7. Le feature flag `merge_when_checks_pass` a été supprimé.
- Fusion automatique pour les merge trains :
  - [Introduite](https://gitlab.com/groups/gitlab-org/-/work_items/10874) dans GitLab 17.2 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `merge_when_checks_pass_merge_train`. Fonctionnalité désactivée par défaut.
  - [Disponible en général](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/174357) dans GitLab 17.7. Le feature flag `merge_when_checks_pass_merge_train` a été supprimé.

{{< /history >}}

Si le contenu d'une merge request est prêt à fusionner, vous pouvez sélectionner **Configurer la fusion automatique**. La merge request fusionne automatiquement lorsque toutes les vérifications requises se terminent avec succès, et vous n'avez pas besoin de vous rappeler de fusionner manuellement la merge request.

Les vérifications de fusion vous permettent de vous concentrer sur l'examen du contenu d'une merge request et d'utiliser les paramètres du projet pour déterminer leur fusionnabilité. Lorsque vous examinez une merge request et que vous approuvez ses modifications, configurez-la en fusion automatique. GitLab applique les paramètres de votre projet et, tant que la merge request ne satisfait pas toutes les vérifications de fusion (comme les règles d'approbation et les propriétaires du code requis), elle ne peut pas fusionner. Une fois toutes les vérifications de fusion requises satisfaites, la merge request fusionne, sans aucune action de votre part.

Les vérifications de fusion incluent un pipeline CI/CD réussi, et bien plus encore :

- Toutes les approbations requises doivent être accordées.
- Aucune autre merge request ne bloque cette merge request.
- Aucun conflit de merge n'existe.
- Un pipeline CI/CD doit se terminer avec succès, quels que soient les [paramètres du projet](#require-a-successful-pipeline-for-merge).
- Tous les fils de discussion sont résolus.
- La merge request n'est pas un **Brouillon**.
- Toutes les vérifications de statut externes ont réussi.
- La merge request doit être ouverte.
- Aucune politique refusée n'existe.
- Tous les pipelines pour le dernier commit doivent réussir avant que la merge request soit fusionnée lorsque des [politiques d'exécution de scan](../../application_security/policies/scan_execution_policies.md) ou des [politiques d'exécution de pipeline](../../application_security/policies/pipeline_execution_policies.md) sont configurées.
- Si votre projet [exige que les merge requests référencent un ticket Jira](../../../integration/jira/issues.md#require-associated-jira-issue-for-merge-requests-to-be-merged), le titre ou la description de la merge request doit contenir un lien vers un ticket Jira.
- Si un [modèle de validation de titre](title_validation.md) est configuré, le titre de la merge request doit correspondre au modèle.
- Si la merge request a une date **Fusion après** définie, l'heure actuelle doit être postérieure à la date configurée.

Pour obtenir la liste complète des vérifications et leurs équivalents API, consultez [le statut de fusion](../../../api/merge_requests.md#merge-status).

![La fusion automatique est prête](img/auto_merge_ready_v16_0.png)

Après avoir configuré la fusion automatique, vous ne pouvez plus modifier les tickets qui [se ferment automatiquement](../issues/managing_issues.md#closing-issues-automatically) lorsque la merge request fusionne.

## Fusionner automatiquement une merge request {#auto-merge-a-merge-request}

Prérequis :

- Vous devez disposer du rôle Développeur, Chargé de maintenance ou Propriétaire pour le projet.
- Si la configuration de votre projet l'exige, tous les fils de discussion de la merge request doivent être résolus.
- La merge request doit avoir reçu toutes les approbations requises.

Pour effectuer cette opération lors d'un push depuis la ligne de commande, utilisez l'[option push](../../../topics/git/commit.md#push-options) `merge_request.merge_when_pipeline_succeeds`.

Pour effectuer cette opération depuis l'interface utilisateur de GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**.
1. Sélectionnez la merge request à modifier.
1. Faites défiler jusqu'à la section des rapports de merge request.
1. Facultatif. Sélectionnez les options de fusion souhaitées, telles que **Supprimer la branche source**, **Combiner (squash) les commits** ou **Modifier le message de validation**.
1. Examinez le contenu de la section des rapports de merge request. S'il contient un [modèle de fermeture de ticket](../issues/managing_issues.md#closing-issues-automatically), confirmez que le ticket doit se fermer lorsque la merge request fusionne :

   ![Cette merge request ferme le ticket #2754.](img/closing_pattern_v18_5.png)

1. Sélectionnez **Configurer la fusion automatique**.

Si vous commentez la merge request après l'avoir configurée en fusion automatique, mais avant que le pipeline ne se termine, la fusion est bloquée jusqu'à ce que vous résolviez tous les fils de discussion existants.

## Annuler une fusion automatique {#cancel-an-auto-merge}

Vous pouvez annuler la fusion automatique d'une merge request.

Prérequis :

- Vous devez être soit l'auteur de la merge request, soit un membre du projet avec le rôle Développeur, Mainteneur ou Propriétaire.
- Le pipeline de la merge request doit encore être en cours d'exécution.

Pour cela :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**.
1. Sélectionnez la merge request souhaitée.
1. Faites défiler jusqu'à la section des rapports de merge request.
1. Sélectionnez **Annuler la fusion automatique**.

![L'option d'annulation de la fusion lorsque le pipeline réussit](img/cancel-mwps_v15_4.png)

## Succès du pipeline pour la fusion automatique {#pipeline-success-for-auto-merge}

{{< history >}}

- La fusion automatique est conservée lors de la mise à jour de la branche cible et lorsque le rebase automatique est activé, [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248017) dans GitLab 19.3 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `retain_auto_merge_with_automatic_rebase`. Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Si le pipeline réussit, la merge request fusionne. Si le pipeline échoue, l'auteur peut soit relancer les jobs ayant échoué, soit pousser de nouveaux commits pour corriger l'échec :

- Si un job relancé réussit au deuxième essai, la merge request fusionne.
- Si vous ajoutez de nouveaux commits à la merge request, GitLab annule la demande pour s'assurer que les nouvelles modifications font l'objet d'une révision avant la fusion.
- Si vous ajoutez de nouveaux commits à la branche cible et que votre projet utilise la méthode **Validation de fusion avec un historique semi-linéaire** ou **Fusion en avance rapide** sans que l'option [rebase automatique avant la fusion](methods/_index.md#automatic-rebase-before-merge) soit activée, GitLab annule la demande pour éviter les conflits de merge. Si le rebase automatique avant la fusion est activé, la fusion automatique reste active et GitLab effectue un rebase lors de la fusion de la merge request.

Pour un contrôle plus strict du statut du pipeline, vous pouvez également [exiger un pipeline réussi](#require-a-successful-pipeline-for-merge) avant la fusion.

### Exiger un pipeline réussi pour la fusion {#require-a-successful-pipeline-for-merge}

Vous pouvez configurer votre projet pour exiger un pipeline complet et réussi avant la fusion. Cette configuration fonctionne pour les deux cas suivants :

- Pipelines CI/CD GitLab.
- Pipelines exécutés depuis une [intégration CI externe](../integrations/_index.md#available-integrations).

Par conséquent, [la désactivation des pipelines CI/CD GitLab](../../../ci/pipelines/settings.md#disable-gitlab-cicd-pipelines) ne désactive pas cette fonctionnalité, mais vous pouvez l'utiliser avec des pipelines provenant de fournisseurs CI externes.

Prérequis :

- Assurez-vous que la configuration CI/CD de votre projet exécute un pipeline pour chaque merge request.
- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour activer ce paramètre :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Faites défiler jusqu'à **Vérifications de fusion** et sélectionnez **Les pipelines doivent réussir**. Ce paramètre empêche également la fusion des merge requests en l'absence de pipeline, ce qui peut [entrer en conflit avec certaines règles](#merge-request-cant-merge-despite-no-failed-pipeline).
1. Sélectionnez **Enregistrer**.

Si [plusieurs types de pipelines s'exécutent pour la même merge request](#merge-request-can-still-be-merged-despite-a-failed-pipeline), les pipelines de merge request ont la priorité sur les autres types de pipelines. Par exemple, un pipeline de merge request plus ancien mais réussi permet à une merge request de fusionner, malgré un pipeline de branche plus récent mais ayant échoué.

De même, un pipeline [importé avec le projet](../../group/import/migrated_items.md#migrated-project-items) conserve son statut source et peut satisfaire cette vérification sans s'exécuter sur la destination. Exécutez un nouveau pipeline sur toutes les merge requests importées avant de les fusionner.

### Autoriser la fusion après des pipelines ignorés {#allow-merge-after-skipped-pipelines}

Lorsque vous définissez **Les pipelines doivent réussir** pour un projet, les [pipelines ignorés](../../../ci/pipelines/_index.md#skip-a-pipeline) empêchent la fusion des merge requests.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour modifier ce comportement :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Sous **Vérifications de fusion** :
   - Sélectionnez **Les pipelines doivent réussir**.
   - Sélectionnez **Les pipelines ignorés sont considérés réussis**.
1. Sélectionnez **Enregistrer**.

## Empêcher la fusion avant une date spécifique {#prevent-merge-before-a-specific-date}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/14380) dans GitLab 17.6.

{{< /history >}}

Si votre merge request ne doit pas fusionner avant une date et une heure spécifiques, définissez une date **La fusion peut commencer**. Cette valeur définit quand la fusion (ou le merge train) peut commencer. L'heure exacte de la fusion peut toutefois varier en fonction de la satisfaction des autres vérifications de fusion ou de la longueur de votre merge train.

Prérequis :

- Vous devez disposer du rôle Développeur, Chargé de maintenance ou Propriétaire pour le projet.

Pour cela :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**.
1. Sélectionnez la merge request à modifier.
1. Sélectionner **Éditer**.
1. Dans la liste déroulante **La fusion peut commencer**, sélectionnez `After scheduled date`, puis sélectionnez une date et une heure.
1. Sélectionnez **Enregistrer les modifications**.

## Dépannage {#troubleshooting}

### La merge request ne peut pas fusionner malgré l'absence de pipeline en échec {#merge-request-cant-merge-despite-no-failed-pipeline}

Dans certains cas, vous pouvez [exiger un pipeline réussi pour la fusion](#require-a-successful-pipeline-for-merge), mais être dans l'impossibilité de fusionner une merge request sans pipeline en échec. Le paramètre exige l'existence d'un pipeline réussi, et non l'absence de pipelines en échec. Une merge request sans aucun pipeline n'est pas considérée comme ayant un pipeline réussi et ne peut pas fusionner.

Lorsque vous activez ce paramètre, utilisez [`rules`](../../../ci/yaml/_index.md#rules) ou [`workflow:rules`](../../../ci/yaml/_index.md#workflowrules) pour vous assurer que des pipelines s'exécutent pour chaque merge request.

### La merge request peut quand même fusionner malgré un pipeline en échec {#merge-request-can-still-be-merged-despite-a-failed-pipeline}

Dans certains cas, vous pouvez [exiger un pipeline réussi pour la fusion](#require-a-successful-pipeline-for-merge), mais quand même fusionner une merge request avec un pipeline en échec.

Les pipelines de merge request ont la priorité la plus élevée pour le paramètre **Les pipelines doivent réussir**. Si plusieurs types de pipelines s'exécutent pour la même merge request, GitLab vérifie uniquement le succès des pipelines de merge request.

Les merge requests peuvent avoir plusieurs pipelines dans les cas suivants :

- Une configuration [`rules`](../../../ci/yaml/_index.md#rules) qui entraîne des [pipelines en double](../../../ci/jobs/job_rules.md#avoid-duplicate-pipelines) : un pipeline de merge request et un pipeline de branche. Dans ce cas, le statut du dernier pipeline de merge request détermine si une merge request peut fusionner, et non le pipeline de branche.
- Des pipelines déclenchés par des outils externes ciblant la même branche que la merge request.

Dans tous les cas, mettez à jour votre configuration CI/CD pour éviter plusieurs types de pipelines pour la même merge request.
