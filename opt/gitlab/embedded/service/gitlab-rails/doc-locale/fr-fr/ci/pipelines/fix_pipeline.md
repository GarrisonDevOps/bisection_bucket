---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Flow Fix CI/CD Pipeline
---

{{< details >}}

- Édition : [Gratuite](../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Introduction en [version expérimentale](../../policy/development_stages_support.md) dans GitLab 18.4 [avec les feature flags](../../administration/feature_flags/_index.md) `duo_workflow_in_ci` et `ai_duo_agent_fix_pipeline_button`. `duo_workflow_in_ci` est activé par défaut. `ai_duo_agent_fix_pipeline_button` est désactivé par défaut. Ces feature flags peuvent être activés ou désactivés pour l'instance ou le projet.
- Activés sur GitLab.com et GitLab Self-Managed dans GitLab 18.5.
- Feature flag `ai_duo_agent_fix_pipeline_button` [activé par défaut](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/205086) dans GitLab 18.5.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273) dans GitLab 18.8. [Suppression](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/216681) du feature flag `ai_duo_agent_fix_pipeline_button`. Le feature flag `duo_workflow_in_ci` a été supprimé dans GitLab 18.9.
- Disponible sur l'édition Gratuite sur GitLab.com avec des GitLab Credits dans GitLab 18.10.
- Les corrections apportées aux pipelines associés à une merge request ont [été modifiées](https://gitlab.com/groups/gitlab-org/-/work_items/21837) pour s'appliquer en tant que suggestions de code dans GitLab 19.1 [avec le feature flag](../../administration/feature_flags/_index.md) `fix_pipeline_next`. Activé sur GitLab.com pour un sous-ensemble d'utilisateurs.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241608) dans GitLab 19.2. Le feature flag `fix_pipeline_next` a été supprimé.

{{< /history >}}

Le flow Fix CI/CD Pipeline diagnostique et propose des correctifs pour les problèmes de votre pipeline CI/CD GitLab. Pour diagnostiquer les échecs, le flow examine :

- Les logs du pipeline, notamment les messages d'erreur, les sorties des jobs en échec et les codes de sortie.
- Les modifications de la merge request qui auraient pu causer l'échec.
- Le contenu du dépôt, pour identifier les erreurs de syntaxe, de linting ou d'importation.
- Les erreurs de script, notamment les échecs de commandes, les exécutables manquants ou les problèmes d'autorisations.

La façon dont le flow applique les corrections dépend du contexte du pipeline :

- Si le pipeline est associé à une merge request, le flow applique des suggestions de code en ligne sur la branche source. Vous pouvez examiner et appliquer les suggestions directement depuis la merge request.
  - Si la correction nécessite des modifications de fichiers en dehors du diff de la merge request actuelle, le flow crée une nouvelle merge request à la place.
- Si le pipeline n'est pas associé à une merge request, le flow crée une nouvelle merge request contenant la correction.

Dans certains cas, au lieu de tenter une correction, le flow publie un commentaire décrivant l'échec et les prochaines étapes possibles. Cela se produit lorsque le pipeline est associé à une merge request, par exemple :

- Le contexte est insuffisant pour déterminer une correction fiable.
- L'échec est sensible du point de vue de la sécurité et doit être examiné par une personne.
- La catégorie d'échec ne peut pas être traitée par le flow.

Lorsqu'une session démarre et se termine, le flow publie des notes système dans la merge request avec un lien vers la session. Ce flow est disponible uniquement dans l'interface utilisateur de GitLab.

Ce flow est le chemin recommandé si vous utilisez la GitLab Duo Agent Platform et souhaitez corriger automatiquement un pipeline en échec. Il s'agit d'une expérience distincte de l'[analyse des causes profondes](../../user/gitlab_duo_chat/examples.md#troubleshoot-failed-cicd-jobs-with-root-cause-analysis), une fonctionnalité de GitLab Duo Chat permettant de résoudre les échecs de jobs individuels.

## Prérequis {#prerequisites}

- Satisfaire aux [prérequis pour GitLab Duo Agent Platform](../../user/duo_agent_platform/_index.md#prerequisites).
- Activez **Autoriser les flows par défaut** et **Corriger un pipeline CI/CD** [pour le groupe principal](../../user/duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off).
- Disposer du rôle Développeur, Chargé de maintenance ou Propriétaire pour le projet.
- Disposer d'un pipeline en échec existant.
- [Configurer les règles push pour autoriser un compte de service](../../user/duo_agent_platform/troubleshooting.md#configure-push-rules-to-allow-a-service-account).
- [Configurer vos propres runners](../../user/duo_agent_platform/flows/execution/_index.md#configure-runners-to-execute-flows) ou activer les [runners hébergés par GitLab](../runners/hosted_runners/_index.md) pour votre projet.
- Recommandé. Créez un [fichier de configuration d'agent](../../user/duo_agent_platform/flows/execution/_index.md#create-the-agent-configuration-file) afin que le flow ait accès à la chaîne d'outils et aux dépendances de votre projet.

## Réparer le pipeline dans une merge request {#fix-the-pipeline-in-a-merge-request}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/20484) de l'utilisation d'un flow dans une conversation GitLab Duo Agentic Chat dans GitLab 19.2 [avec le feature flag](../../administration/feature_flags/_index.md) `agentic_foundational_flow_tool`. Activés par défaut.
- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/work_items/605446) dans GitLab 19.5. Le feature flag `agentic_foundational_flow_tool` a été supprimé.

{{< /history >}}

Pour corriger le pipeline CI/CD dans une merge request :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion** et ouvrez votre merge request.
1. Utilisez l'une de ces méthodes pour corriger le pipeline :
   - Sélectionnez l'onglet **Vue d'ensemble** et, sous le pipeline en échec, sélectionnez **Réparer le pipeline avec GitLab Duo**.
   - Sélectionnez l'onglet **Pipelines** et, dans la colonne la plus à droite, sélectionnez **Réparer le pipeline avec GitLab Duo** ({{< icon name="tanuki-ai" >}}).
   - Dans la barre latérale GitLab Duo, ouvrez une conversation Agentic Chat nouvelle ou existante. Demandez à Agentic Chat de corriger le pipeline.
1. Pour surveiller la progression, dans la barre latérale gauche, sélectionnez **IA** > **Sessions**.

   Si vous êtes dans Agentic Chat, vous pouvez également effectuer les actions suivantes :
   - Voir la progression dans la conversation Chat.
   - Sélectionnez **Afficher la session de l'agent** dans la conversation.

Lorsque la session est terminée, le flow ajoute des suggestions de code à la merge request, ou un commentaire décrit les prochaines étapes possibles.

## Corriger d'autres pipelines CI/CD {#fix-other-cicd-pipelines}

Pour corriger un pipeline CI/CD qui n'est pas associé à une merge request :

1. Sélectionnez **Version** > **Pipelines**.
1. Sélectionnez votre pipeline en échec.
1. Dans le coin supérieur droit, sélectionnez **Réparer le pipeline avec GitLab Duo**.
1. Pour surveiller la progression, sélectionnez **IA** > **Sessions**.

## Utiliser `AGENTS.md` pour personnaliser le flow {#use-agentsmd-to-customize-the-flow}

Le flow lit les instructions spécifiques au dépôt depuis un fichier [`AGENTS.md`](../../user/duo_agent_platform/customize/agents_md.md) dans votre dépôt. Vous pouvez utiliser `AGENTS.md` pour personnaliser le comportement, par exemple :

- Le format du message de commit pour les modifications effectuées par le flow.
- Les métadonnées de merge request, telles que les labels et la description, pour les merge requests créées par le flow.
- Comment classifier et traiter des types d'échecs spécifiques.
- Comment gérer les échecs répétés du même type, pour éviter que le flow n'applique plus d'une fois le même correctif sans succès.

Par exemple :

```markdown
## Fix pipeline merge requests

When opening a merge request as part of the Fix Pipeline flow (the title contains [FixPipeline]),
apply labels based on the following failed pipeline scenarios:

- Pipeline failed on merge_request: apply "pipeline::tier-1". This runs the cheaper tier-1
  pipeline instead of the full default pipeline.
- Pipeline failed on the default_branch (main): apply both "pipeline::expedited" and
  "main:broken". Do not apply pipeline::tier-1 in this case.
- Pipeline failed on other branches: apply "pipeline::tier-1". Same treatment as the
  merge_request case.
```

Par exemple, pour gérer les échecs de migration :

```markdown
## Migration failures

If a pipeline fails because of a database migration:

- Run `bin/rails db:migrate:status` to check the current migration state before attempting
  a fix.
- Do not edit or delete past migration files.
- If the migration cannot be safely reversed, post a comment describing the issue instead
  of attempting a fix.
```

## Problèmes connus {#known-issues}

- La passerelle d'IA traite uniquement les 150 derniers Kio des job logs. Si votre job génère un volume important de données, le flow pourrait ne pas capturer les informations d'échec pertinentes qui apparaissent plus tôt dans le log. Consultez la section suivante pour les solutions de contournement.
- Le flow ne peut pas toujours vérifier l'installation des paquets dans l'environnement d'exécution sandboxé. Si des dépendances sont manquantes, vous pouvez personnaliser l'image du flow par défaut. Consultez [modifier l'image Docker par défaut](../../user/duo_agent_platform/flows/execution/images.md#change-the-default-docker-image).
- Les instructions du dépôt dans `AGENTS.md` influencent le comportement du flow, mais leur application n'est pas garantie dans tous les cas.

## Dépannage {#troubleshooting}

Lorsque vous travaillez avec le flow Fix CI/CD Pipeline, vous pouvez rencontrer les problèmes suivants.

### Le flow ne parvient pas à identifier la cause première d'un échec {#flow-cannot-identify-the-root-cause-of-a-failure}

Le flow pourrait ne pas identifier la cause première d'un échec de pipeline.

Ce problème se produit lorsque les job logs dépassent 150 Kio. La passerelle d'IA traite uniquement les derniers 150 Kio, de sorte que les informations d'échec pertinentes apparaissant plus tôt dans le log pourraient ne pas être capturées.

Pour contourner ce problème, essayez les solutions suivantes :

- Réduisez les données de sorties détaillées en supprimant les logs de débogage et les indicateurs de progression.
- Redirigez les sorties non critiques à l'aide de la redirection shell (`> /dev/null`).
- Ajoutez une étape de synthèse à la fin de votre script qui affiche les messages d'erreur clés.
- Utilisez `after_script` pour afficher des informations de diagnostic après la fin du script principal.
- Divisez les jobs volumineux en jobs plus petits et ciblés avec des logs plus concis.

### Échec du démarrage de la session {#session-failed-to-start}

La session du flow Fix CI/CD Pipeline échoue et, sur la page des sessions (**IA** > **Sessions**), l'alerte `Session failed to start` s'affiche.

Deux pipelines sont impliqués : le pipeline qui a échoué et le [pipeline de charge de travail](pipeline_types.md#workload-pipeline) que le flow crée pour le corriger. Vérifiez le statut du job dans le pipeline de charge de travail.

Pour connaître les causes et les résolutions, consultez [le job ou la session d'un flow ne démarre pas](../../user/duo_agent_platform/troubleshooting.md#a-flows-job-or-session-fails-to-start).

### Le bouton Réparer le pipeline avec GitLab Duo n'apparaît pas {#fix-pipeline-with-duo-button-does-not-appear}

Vous remplissez les [prérequis](#prerequisites), mais le bouton **Réparer le pipeline avec GitLab Duo** n'apparaît pas.

Ce problème survient car le bouton dépend de paramètres répartis sur trois pages distinctes (GitLab Duo, l'Agent Platform et les flows par défaut). L'activation d'un paramètre à un niveau ne garantit pas qu'il est activé à tous les niveaux inférieurs.

Pour résoudre ce problème, vérifiez à nouveau chaque exigence :

- [GitLab Duo](../../user/duo_agent_platform/turn_on_off.md#turn-gitlab-duo-on-or-off) ou [GitLab Duo Core](../../user/duo_agent_platform/turn_on_off.md#turn-gitlab-duo-core-on-or-off) est activé.
- L'[Agent Platform est activé](../../user/duo_agent_platform/turn_on_off.md#turn-gitlab-duo-agent-platform-on-or-off).
- **Autoriser les flows par défaut** et **Corriger un pipeline CI/CD** sont activés pour le groupe principal et, sur GitLab Self-Managed, pour l'instance.

## Donner un avis {#give-feedback}

L'équipe améliore activement le flow Fix CI/CD Pipeline. Pour signaler des problèmes ou suggérer des améliorations, laissez vos commentaires dans le [ticket 601991](https://gitlab.com/gitlab-org/gitlab/-/work_items/601991).
