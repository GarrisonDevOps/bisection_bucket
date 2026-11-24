---
stage: AI Clients
group: Duo Chat
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Utiliser GitLab Duo Agentic Chat pour répondre à des questions complexes et créer ou modifier des fichiers de manière autonome.
title: GitLab Duo Agentic Chat
---

{{< details >}}

- Édition : [Gratuite](../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated, GitLab Dedicated for Government

{{< /details >}}

{{< collapsible title="Informations sur le modèle" >}}

- [LLM par défaut](../duo_agent_platform/model_selection.md#default-models)
- Disponible sur [GitLab Duo avec des modèles auto-hébergés](../../administration/gitlab_duo_self_hosted/_index.md)

{{< /collapsible >}}

{{< history >}}

- [Introduction de VS Code sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/work_items/540917) dans GitLab 18.1 en [version expérimentale](../../policy/development_stages_support.md) avec le [feature flag](../../administration/feature_flags/_index.md) `duo_agentic_chat`. Désactivé par défaut.
- [Activation de VS Code sur GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/196688) dans GitLab 18.2.
- [Introduction de l'interface utilisateur GitLab sur GitLab.com et GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/issues/546140) dans GitLab 18.2 [avec les feature flags](../../administration/feature_flags/_index.md) `duo_workflow_workhorse` et `duo_workflow_web_chat_mutation_tools`. Les deux feature flags sont activés par défaut.
- Activation par défaut du feature flag `duo_agentic_chat` dans GitLab 18.2.
- [Introduction](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/issues/1077) des IDE JetBrains dans GitLab 18.2.
- Passage en version bêta dans GitLab 18.2.
- [Introduction](https://gitlab.com/gitlab-org/editor-extensions/gitlab-visual-studio-extension/-/issues/245) de Visual Studio pour Windows dans GitLab 18.3.
- [Ajout](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/201721) à GitLab Duo Core dans GitLab 18.3.
- [Suppression](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/198487) des feature flags `duo_workflow_workhorse` et `duo_workflow_web_chat_mutation_tools` dans GitLab 18.4.
- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/19213) de GitLab Duo Agent Platform sur GitLab Self-Managed, avec des [modèles auto-hébergés](../../administration/gitlab_duo_self_hosted/_index.md) et des modèles GitLab connectés au cloud, dans GitLab 18.4 en [version expérimentale](../../policy/development_stages_support.md#experiment) avec le [feature flag](../../administration/feature_flags/_index.md) `self_hosted_agent_platform`. Désactivé par défaut.
- GitLab Duo Agent Platform sur GitLab Self-Managed est passé de la version expérimentale à la [version bêta](https://gitlab.com/groups/gitlab-org/-/epics/19402) dans GitLab 18.5.
- [Mise à jour du LLM par défaut](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/issues/1541) vers Claude Sonnet 4.5 dans GitLab 18.6.
- [Activation](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/208951) du feature flag `self_hosted_agent_platform` dans GitLab 18.7.
- [Mise à jour du LLM par défaut](https://gitlab.com/groups/gitlab-org/-/epics/19998) vers Claude Haiku 4.5 dans GitLab 18.7.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/581872) dans GitLab 18.8 avec les [feature flags](../../administration/feature_flags/_index.md) `agentic_chat_ga` et `ai_duo_agent_platform_ga_rollout_self_managed`. Les deux feature flags sont activés par défaut. Suppression du feature flag `duo_agentic_chat`.
- Suppression des feature flags [`self_hosted_agent_platform`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/218589), [`agentic_chat_ga`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/219679) et [`ai_duo_agent_platform_ga_rollout_self_managed`](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/219679) dans GitLab 18.10.
- Disponible sur l'édition Gratuite sur GitLab.com avec des GitLab Credits dans GitLab 18.10.

{{< /history >}}

GitLab Duo Agentic Chat est une version améliorée de GitLab Duo Non-Agentic Chat. Ce nouveau Chat peut effectuer des actions de manière autonome en votre nom pour vous aider à apporter des réponses plus complètes aux questions complexes.

Alors que le Chat non-agentique répond aux questions à partir d'un seul contexte, Agentic Chat recherche, récupère et combine des informations provenant de plusieurs sources dans l'ensemble de vos projets GitLab pour fournir des réponses plus approfondies et plus pertinentes.

Agentic Chat peut :

- Rechercher dans les projets les tickets, les merge requests et les autres artefacts pertinents à l'aide d'une recherche par mots-clés, et non d'une recherche sémantique.
- Accéder aux fichiers de votre projet local sans spécifier manuellement leurs chemins.
- Créer et modifier des fichiers à plusieurs emplacements.
- Récupérer des ressources telles que des tickets, des merge requests et des pipelines CI/CD.
- Analyser plusieurs sources pour fournir des réponses complètes. Utilisez le [Model Context Protocol](../gitlab_duo/model_context_protocol/_index.md) pour vous connecter à des sources de données et des outils externes.
- Fournir des réponses personnalisées en utilisant vos règles personnalisées.
- Créer des commits, lorsque vous utilisez le Chat dans l'interface GitLab.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une présentation générale, consultez la page [GitLab Duo Chat (agentique)](https://youtu.be/uG9-QLAJrrg?si=c25SR7DoRAep7jvQ).

<!-- Video published on 2025-06-02 -->

Partagez vos commentaires dans [le ticket 542198](https://gitlab.com/gitlab-org/gitlab/-/issues/542198).

## Utiliser GitLab Duo Chat {#use-gitlab-duo-chat}

Vous pouvez utiliser GitLab Duo Chat dans :

- L'interface GitLab
- VS Code
- Un IDE JetBrains
- Visual Studio pour Windows

Avec [GitLab Duo CLI](../gitlab_duo_cli/_index.md), vous pouvez également utiliser Agentic Chat depuis votre terminal.

### Utiliser GitLab Duo Chat dans l'interface GitLab {#use-gitlab-duo-chat-in-the-gitlab-ui}

{{< history >}}

- [Ajout](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203653) de la capacité du Chat à mémoriser votre conversation la plus récente dans GitLab 18.4.
- Introduction de la nouvelle navigation et de la barre latérale GitLab Duo sur GitLab.com dans GitLab 18.6 avec le [feature flag](../../administration/feature_flags/_index.md) `paneled_view`. Activé par défaut.
- Suppression des instructions de navigation précédentes dans GitLab 18.7.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/574049) de la nouvelle navigation et de la barre latérale GitLab Duo dans GitLab 18.8. Suppression du feature flag `paneled_view`.
- La possibilité de réessayer la question précédente a été [introduite](https://gitlab.com/groups/gitlab-org/-/work_items/21289) dans GitLab 19.5 avec un [feature flag](../../administration/feature_flags/_index.md) nommé `agentic_manual_retry_for_duo_chat_responses`. Désactivé par défaut.
- La possibilité de réessayer la question précédente est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/work_items/601522) dans GitLab 19.5. Le feature flag `agentic_manual_retry_for_duo_chat_responses` a été supprimé.

{{< /history >}}

Prérequis :

- Satisfaire aux [prérequis de GitLab Duo Agent Platform](../duo_agent_platform/_index.md#prerequisites).
- Définir un [espace de nommage GitLab Duo par défaut](../profile/preferences.md#set-a-default-gitlab-duo-namespace).

Pour utiliser le Chat dans l'interface GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre projet.
1. Dans la barre latérale GitLab Duo, sélectionnez soit **Ajouter une discussion** ({{< icon name="pencil-square" >}}) soit **GitLab Duo Chat actuel** ({{< icon name="duo-chat" >}}).

   Si vous avez sélectionné une nouvelle discussion, sélectionnez un agent dans la liste déroulante.

   Une conversation Chat s'ouvre dans la barre latérale GitLab Duo située à droite de l'écran.

1. Sous la zone de texte du Chat, vérifiez que le bouton bascule **Agentique** est activé.
1. Saisissez votre question dans la zone de texte du Chat et appuyez sur <kbd>Entrée</kbd> ou sélectionnez **Envoyer**.
   - Vous pouvez fournir du [contexte](../duo_agent_platform/context.md#gitlab-duo-agentic-chat) supplémentaire pour votre conversation Chat.
   - Le chat interactif alimenté par l'IA peut mettre quelques secondes à générer une réponse.
1. Facultatif. Vous pouvez :
   - Sélectionnez **Réessayer** ({{< icon name="retry" >}}) pour tenter d'obtenir une réponse différente à votre question. Utilisez les flèches pour sélectionner la réponse originale ou les nouvelles tentatives afin de poursuivre la conversation.
   - Poser une question de suivi.
   - Démarrer [une autre conversation](#have-multiple-conversations).

Si vous rechargez la page Web sur laquelle vous vous trouvez, ou si vous accédez à une autre page Web, le Chat mémorise votre conversation la plus récente, et cette conversation est toujours active dans le tiroir du Chat.

#### Flows par défaut {#foundational-flows}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/20484) du déclenchement des flows par défaut dans une conversation GitLab Duo Agentic Chat dans GitLab 19.2 [avec le feature flag](../../administration/feature_flags/_index.md) `agentic_foundational_flow_tool`. Activé par défaut.
- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/work_items/605446) dans GitLab 19.5. Le feature flag `agentic_foundational_flow_tool` a été supprimé.

{{< /history >}}

Le cas échéant, les flows par défaut suivants peuvent être déclenchés depuis une conversation Agentic Chat pour répondre à une question ou atteindre un objectif.

- [Flow Developer](../project/merge_requests/developer.md#use-the-flow-in-agentic-chat)
- [Flow Code Review](../duo_agent_platform/flows/foundational_flows/code_review/_index.md#use-the-flow)
- [Flow Fix CI/CD Pipeline](../../ci/pipelines/fix_pipeline.md#fix-the-pipeline-in-a-merge-request)

#### Déclencher un flow avec une commande slash {#trigger-a-flow-with-a-slash-command}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252920) dans GitLab 19.4 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `duo_chat_flow_commands`. Désactivé par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/work_items/629298) dans GitLab 19.4.
- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/work_items/629298) dans GitLab 19.5.

{{< /history >}}

Dans GitLab Duo Agentic Chat, vous pouvez démarrer un flow avec une commande slash. Utilisez une commande de flow lorsqu'un flow ne dispose pas d'un déclencheur configuré, ou lorsque vous souhaitez démarrer le flow vous-même plutôt que d'attendre un déclencheur.

Prérequis :

- Vous devez avoir Chat ouvert dans un projet. Les commandes de flow ne sont pas disponibles en dehors d'un projet.
- Le flow doit être [activé dans le projet](../duo_agent_platform/flows/custom.md#enable-a-flow).

> [!warning]
> Si vous déclenchez un flow avec une commande slash, il dispose d'un accès en écriture à l'API GitLab et à Git. Le flow peut commiter et pousser des modifications, et publier des commentaires sur des tickets et des merge requests. Contrairement à Chat, un flow ne vous demande pas d'approuver ces actions. Les [approbations d'outils](#tool-approvals) s'appliquent uniquement à la session Chat, pas aux flows démarrés par la session. Chaque exécution de flow utilise également des [minutes de calcul](../../ci/pipelines/compute_minutes.md), car les flows démarrés depuis l'interface GitLab s'exécutent en tant que pipeline CI/CD.

Pour déclencher un flow depuis Chat :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre projet.
1. Dans la barre latérale GitLab Duo, ouvrez une conversation Chat nouvelle ou existante.
1. Dans la zone de message Chat, saisissez `/` au début de votre message.
1. Dans la section **Flux**, sélectionnez un flow. La commande correspond au nom du flow au format slug, avec le préfixe `/flow:`. Par exemple, un flow nommé `Security scanner` devient `/flow:security-scanner`. Si deux flows d'un même projet ont des noms qui produisent la même commande, un identifiant numérique est ajouté à la deuxième commande.
1. Facultatif. Après la commande, saisissez l'objectif du flow. Par exemple, `/flow:security-scanner check the auth module`.
1. Appuyez sur <kbd>Entrée</kbd> ou sélectionnez **Envoyer**.

#### Démarrer une tâche longue avec la commande `/goal` {#start-a-long-running-task-with-the-goal-command}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/23107) dans GitLab 19.5 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `duo_chat_goal_command`. Désactivé par défaut.
- [Activé sur GitLab.com](https://gitlab.com/groups/gitlab-org/-/work_items/23107) dans GitLab 19.5.

{{< /history >}}

> [!flag]
> Un feature flag contrôle la disponibilité de cette fonctionnalité. Pour plus d'informations, consultez l'historique.

Utilisez `/goal` lorsque vous souhaitez que GitLab Duo continue de travailler sur une tâche jusqu'à ce qu'elle soit terminée, plutôt que de répondre un tour à la fois en attendant que vous lui demandiez de continuer.

Lorsque vous envoyez un objectif, Chat démarre une session [flow Developer](../project/merge_requests/developer.md) qui travaille à sa réalisation. Les objectifs fonctionnent mieux pour un changement concret avec un état final clair, par exemple, corriger un ensemble de tests en échec ou apporter une modification sur plusieurs fichiers. Pour poser une question, utilisez plutôt un message Chat ordinaire.

Prérequis :

- [Ouvrez une fenêtre de chat](#use-gitlab-duo-chat-in-the-gitlab-ui) dans un projet. `/goal` n'est pas disponible en dehors d'un projet.
- Satisfaire les [prérequis du flow Developer](../project/merge_requests/developer.md#prerequisites), notamment activer le flow Developer pour le groupe principal.

> [!warning]
> Un objectif exécute le flow Developer, qui dispose d'un accès en écriture à l'API GitLab et à Git. Le flow peut commiter et pousser des modifications, créer des merge requests, et publier des commentaires sur des tickets et des merge requests. Contrairement à Chat, le flow ne vous demande pas d'approuver ces actions. Les [approbations d'outils](#tool-approvals) s'appliquent uniquement à la session Chat, pas aux flows démarrés par la session. Chaque objectif utilise également des [minutes de calcul](../../ci/pipelines/compute_minutes.md), car les flows démarrés depuis l'interface GitLab s'exécutent en tant que pipeline CI/CD.

Pour démarrer une tâche longue :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre projet.
1. Dans la barre latérale GitLab Duo, ouvrez une conversation Chat nouvelle ou existante.
1. Dans la zone de message Chat, effectuez l'une des actions suivantes :
   - Au début de votre message, saisissez `/goal` et sélectionnez-le dans la liste.
   - Sélectionnez **Plus d'actions** ({{< icon name="plus" >}}) > **Objectif**.

   Un label **Objectif** apparaît dans la zone de message.
1. Décrivez ce que vous souhaitez accomplir. Par exemple :

   ```plaintext
   Fix the failing tests in spec/models/user_spec.rb
   ```

1. Appuyez sur <kbd>Entrée</kbd> ou sélectionnez **Envoyer**.

Dans la conversation, votre message affiche un label **Objectif**.

Pour supprimer l'objectif avant d'envoyer le message, sur le label **Objectif**, sélectionnez **Supprimer l'objectif** ({{< icon name="close" >}}).

### Utiliser GitLab Duo Chat dans VS Code {#use-gitlab-duo-chat-in-vs-code}

Prérequis :

- [Installer et configurer l'extension GitLab pour VS Code](../../editor_extensions/visual_studio_code/setup.md) version 6.15.1 ou ultérieure.
- Satisfaire aux [prérequis de GitLab Duo Agent Platform](../duo_agent_platform/_index.md#prerequisites).
- Définir un [espace de nommage GitLab Duo par défaut](../profile/preferences.md#set-a-default-gitlab-duo-namespace).

Activez GitLab Duo Chat :

1. Dans VS Code, ouvrez l'éditeur de paramètres :
   - Pour macOS, appuyez sur <kbd>Commande</kbd>+<kbd>,</kbd>.
   - Pour Windows ou Linux, appuyez sur <kbd>Ctrl</kbd>+<kbd>,</kbd>.
1. Sélectionnez **Extensions** > **GitLab** > **GitLab Duo**.
1. Sous **GitLab › Duo Agent Platform : Activé**, cochez la case **Activer GitLab Duo Agent Platform**.

Ensuite, pour utiliser GitLab Duo Chat :

1. Dans la barre latérale gauche, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
1. Si vous utilisez la [mise en page classique](#change-the-layout-in-your-ide), sélectionnez l'onglet **Chat**.
1. Sélectionnez **Actualiser la page** si vous y êtes invité.
1. Dans la zone de message, saisissez votre question et appuyez sur <kbd>Entrée</kbd> ou sélectionnez **Envoyer**.

### Utiliser GitLab Duo Chat dans les IDE JetBrains {#use-gitlab-duo-chat-in-jetbrains-ides}

Prérequis :

- [Installer et configurer le plug-in GitLab Duo pour les IDE JetBrains](../../editor_extensions/jetbrains_ide/setup.md) version 3.11.1 ou ultérieure.
- Satisfaire aux [prérequis de GitLab Duo Agent Platform](../duo_agent_platform/_index.md#prerequisites).
- Définir un [espace de nommage GitLab Duo par défaut](../profile/preferences.md#set-a-default-gitlab-duo-namespace).

Activez GitLab Duo Chat :

1. Dans votre IDE JetBrains, accédez à **Paramètres** > **Outils** > **GitLab Duo**.
1. Sous **GitLab Duo Agent Platform**, cochez la case **Activer GitLab Duo Agent Platform**.
1. Redémarrez votre IDE si vous y êtes invité.

Ensuite, pour utiliser GitLab Duo Chat :

1. Dans la barre d'outils de droite, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
1. Si vous utilisez la [mise en page classique](#change-the-layout-in-your-ide), sélectionnez l'onglet **Chat**.
1. Dans la zone de message, saisissez votre question et appuyez sur <kbd>Entrée</kbd> ou sélectionnez **Envoyer**.

### Utiliser GitLab Duo Chat dans Visual Studio {#use-gitlab-duo-chat-in-visual-studio}

Prérequis :

- Installer et configurer l'[extension GitLab pour Visual Studio](../../editor_extensions/visual_studio/setup.md) version 0.60.0 ou ultérieure.
- Satisfaire aux [prérequis de GitLab Duo Agent Platform](../duo_agent_platform/_index.md#prerequisites).
- Définir un [espace de nommage GitLab Duo par défaut](../profile/preferences.md#set-a-default-gitlab-duo-namespace).

Activez GitLab Duo Chat :

1. Dans Visual Studio, accédez à **Outils** > **Options** > **GitLab**.
1. Sous **GitLab**, sélectionnez **Général**.
1. Pour **Activer Agentic Duo Chat**, sélectionnez **Vrai**, puis **OK**.

Ensuite, pour utiliser GitLab Duo Chat :

1. Sélectionnez **Extensions** > **GitLab** > **Ouvrir Agentic Chat**.
1. Dans la zone de message, saisissez votre question et appuyez sur **Entrée**.

## Modifier la mise en page dans votre IDE {#change-the-layout-in-your-ide}

{{< history >}}

- La nouvelle mise en page est [définie par défaut](https://gitlab.com/groups/gitlab-org/editor-extensions/-/epics/243) dans GitLab pour VS Code 7.2.0 et le plugin GitLab Duo pour JetBrains IDEs 3.50.0.

{{< /history >}}

Dans VS Code et JetBrains IDEs, le panneau **GitLab Duo Agent Platform** utilise la nouvelle mise en page par défaut. La nouvelle mise en page ne comporte pas d'onglets. Vous démarrez des conversations, consultez votre historique de chat et sélectionnez un agent et un modèle dans la même vue.

La mise en page classique dispose d'onglets distincts **Chat** et **Flux**. Passez à la mise en page classique pour :

- Utiliser le [flow Software Development](../../editor_extensions/software_development.md).
- Afficher les flows que vous avez exécutés dans votre IDE.

Votre IDE mémorise la mise en page que vous sélectionnez. Visual Studio utilise uniquement la mise en page classique.

### Passer à la mise en page classique {#switch-to-the-classic-layout}

Avant le changement de mise en page, un sondage facultatif vous demande pourquoi vous effectuez ce changement. Vous pouvez :

- Sélectionnez une ou plusieurs raisons, puis sélectionnez **Donnez votre avis**.
- Sélectionnez **Ne plus afficher** pour changer sans répondre.
- Sélectionnez **Ignorer** ({{< icon name="close" >}}) pour changer sans répondre. Le sondage réapparaît la prochaine fois que vous effectuez un changement.

Après avoir donné votre avis ou sélectionné **Ne plus afficher**, le sondage n'apparaît plus.

{{< tabs >}}

{{< tab title="VS Code" >}}

Pour passer à la mise en page classique :

1. Dans la barre latérale, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
1. Dans la barre de titre du panneau, sélectionnez **Utiliser la mise en page classique**.
1. Facultatif. Complétez le sondage.

{{< /tab >}}

{{< tab title="JetBrains EDIs" >}}

Pour passer à la mise en page classique :

1. Dans la barre d'outils, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
1. Dans la barre de titre de la fenêtre d'outils, sélectionnez **Utiliser la mise en page classique**.
1. Facultatif. Complétez le sondage.

Vous pouvez également effectuer ce changement dans les paramètres. Accédez à **Paramètres** > **Outils** > **GitLab Duo**, et sous **GitLab Duo Agent Platform**, cochez la case **Utiliser la mise en page classique**.

{{< /tab >}}

{{< /tabs >}}

### Passer à la nouvelle mise en page {#switch-to-the-new-layout}

Pour revenir à la nouvelle mise en page :

- Dans VS Code, dans la barre de titre du panneau **GitLab Duo Agent Platform**, sélectionnez **Utiliser la nouvelle mise en page**.
- Dans un IDE JetBrains, dans la barre de titre de la fenêtre d'outils **GitLab Duo Agent Platform**, sélectionnez **Utiliser la nouvelle mise en page**. Vous pouvez également accéder à **Paramètres** > **Outils** > **GitLab Duo**, et sous **GitLab Duo Agent Platform**, décocher la case **Utiliser la mise en page classique**.

## Afficher l'historique de discussion {#view-the-chat-history}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/epics/17922) de l'historique de discussion dans les IDE dans GitLab 18.2.
- [Ajout](https://gitlab.com/gitlab-org/gitlab/-/issues/556875) à l'interface GitLab dans GitLab 18.3.

{{< /history >}}

Pour afficher votre historique de discussion :

- Dans l'interface GitLab, dans la barre latérale GitLab Duo, sélectionnez **Historique GitLab Duo Chat** ({{< icon name="history" >}}).

- Dans votre IDE, en haut du panneau, sélectionnez **Historique** ({{< icon name="history" >}}). Dans la [mise en page classique](#change-the-layout-in-your-ide), dans le coin supérieur droit de la zone de message, sélectionnez **Historique de discussion** ({{< icon name="history" >}}).

Dans l'interface GitLab, toutes les conversations de votre historique de discussion sont visibles.

Dans votre IDE, faites défiler l'historique de chat vers le bas pour charger les conversations plus anciennes. Dans la mise en page classique, seules les 20 dernières conversations sont visibles.

## Avoir plusieurs conversations {#have-multiple-conversations}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/556875) des conversations multiples dans GitLab 18.3.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/582513) de la fonctionnalité de recherche dans l'historique de discussion de l'interface GitLab dans GitLab 18.9.

{{< /history >}}

Vous pouvez avoir un nombre illimité de conversations simultanées avec GitLab Duo Chat.

Vos conversations se synchronisent entre GitLab Duo Chat dans l'interface GitLab et votre IDE.

1. Ouvrez GitLab Duo Chat dans l'interface GitLab ou votre IDE.
1. Saisissez votre question et appuyez sur <kbd>Entrée</kbd> ou sélectionnez **Envoyer**.
1. Créez une nouvelle conversation Chat :
   - Dans l'interface GitLab, vous pouvez effectuer l'une des opérations suivantes :
     - Pour créer une nouvelle conversation avec un agent spécifique :
       1. Dans la barre latérale GitLab Duo, sélectionnez **Ajouter une discussion** ({{< icon name="pencil-square" >}}).
       1. Dans la liste déroulante, sélectionnez un agent.
     - Pour créer une nouvelle conversation avec le même agent que la conversation existante, saisissez `/new` dans la zone de message, puis appuyez sur <kbd>Entrée</kbd> ou sélectionnez **Envoyer**.

     Une nouvelle conversation Chat remplace la conversation existante.

   - Sous la zone de texte du Chat, vérifiez que le bouton bascule **Agentique** est activé.
   - Dans votre IDE, en haut du panneau, sélectionnez **Nouvelle discussion** ({{< icon name="plus" >}}). Dans la mise en page classique, **Nouvelle discussion** se trouve dans le coin supérieur droit de la zone de message.

1. Saisissez votre question et appuyez sur <kbd>Entrée</kbd> ou sélectionnez **Envoyer**.
1. Pour afficher toutes vos conversations, consultez votre [historique de discussion](#view-the-chat-history).
1. Pour basculer entre les conversations, sélectionnez la conversation appropriée dans votre historique de discussion.
1. Pour rechercher une conversation spécifique dans l'historique de discussion :
   - Interface GitLab : dans la zone de texte **Rechercher un fil de discussion**, saisissez votre terme de recherche.
   - IDE : dans la zone de texte **Rechercher dans l'historique**, saisissez votre terme de recherche. Dans la mise en page classique, utilisez la zone de texte **Rechercher dans les discussions**.

En raison des limites de la fenêtre de contexte du LLM, les conversations sont tronquées à 200 000 jetons (environ 800 000 caractères) chacune.

## Supprimer une conversation {#delete-a-conversation}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/545289) de la possibilité de supprimer une conversation dans GitLab 18.2.

{{< /history >}}

1. Dans l'interface GitLab ou votre IDE, sélectionnez l'[historique de discussion](#view-the-chat-history).
1. Dans l'historique, sélectionnez **Supprimer cette discussion** ({{< icon name="remove" >}}).

Les conversations individuelles expirent et sont automatiquement supprimées après 30 jours d'inactivité.

## Personnaliser GitLab Duo Chat dans votre environnement local {#customize-gitlab-duo-chat-in-your-local-environment}

Personnalisez le comportement de GitLab Duo Chat dans votre environnement local en fournissant des instructions qui reflètent votre style de codage, les pratiques de votre équipe et les exigences de votre projet.

GitLab Duo Chat prend en charge deux approches :

- [Règles personnalisées](../duo_agent_platform/customize/custom_rules.md) dans `chat-rules.md` : pour GitLab uniquement. Idéal pour les préférences personnelles et les standards d'équipe.
- [Règles partagées dans `AGENTS.md`](../duo_agent_platform/customize/agents_md.md) : pour GitLab et d'autres outils d'IA prenant en charge la spécification `AGENTS.md`. Idéal pour le contexte de projet, l'organisation des monorepos et les conventions spécifiques aux répertoires.

Vous pouvez utiliser les deux fichiers simultanément. GitLab Duo Chat applique les instructions de tous les fichiers de règles disponibles.

Pour en savoir plus, consultez [Personnaliser GitLab Duo](../duo_agent_platform/customize/_index.md).

## Sélectionner un modèle {#select-a-model}

{{< details >}}

- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/epics/19251) dans GitLab 18.4 en tant que fonctionnalité en [version bêta](../../policy/development_stages_support.md#beta) avec un [feature flag](../../administration/feature_flags/_index.md) nommé `ai_user_model_switching`. Désactivé par défaut.
- [Activation](https://gitlab.com/gitlab-org/gitlab/-/issues/560319) dans GitLab 18.4.
- [Disponibilité sur GitLab Self-Managed](https://gitlab.com/groups/gitlab-org/-/epics/19344) dans GitLab 18.6.
- [Ajout](https://gitlab.com/groups/gitlab-org/-/epics/19345) à VS Code et aux IDE JetBrains dans GitLab 18.6.
- [Suppression](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/214042) du feature flag `ai_user_model_switching` dans GitLab 18.7.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/569140) dans GitLab 18.8.

{{< /history >}}

Lorsque vous utilisez le Chat dans l'interface GitLab, VS Code ou un IDE JetBrains, vous pouvez sélectionner le modèle à utiliser pour les conversations.

Si vous ouvrez une conversation précédente depuis l'historique de discussion et que vous la poursuivez, le Chat utilise le modèle que vous avez précédemment sélectionné.

Si vous sélectionnez un nouveau modèle dans une conversation existante, Chat continue la conversation en cours avec le modèle nouvellement sélectionné.

Prérequis :

{{< tabs >}}

{{< tab title=GitLab.com >}}

- Un utilisateur disposant du rôle Propriétaire pour le groupe principal n'a pas épinglé de modèle pour Agentic Chat. S'il a [sélectionné un modèle non par défaut sans restreindre Agentic Chat à des modèles spécifiques](../duo_agent_platform/model_selection.md#select-a-model-for-agentic-chat), le modèle est épinglé et ne peut pas être modifié. Sinon, vous pouvez choisir parmi les modèles disponibles.
- Vous devez utiliser le Chat dans le groupe principal. Vous ne pouvez pas modifier le modèle si vous accédez au Chat dans l'organisation.

{{< /tab >}}

{{< tab title="GitLab Self-Managed" >}}

- Un administrateur n'a pas épinglé de modèle pour Agentic Chat. S'il a [sélectionné un modèle non par défaut sans restreindre Agentic Chat à des modèles spécifiques](../../administration/gitlab_duo/model_selection.md#select-a-model-for-agentic-chat), le modèle est épinglé et ne peut pas être modifié. Sinon, vous pouvez choisir parmi les modèles disponibles.
- Votre instance doit être connectée à la passerelle d'IA GitLab.

{{< /tab >}}

{{< /tabs >}}

Pour sélectionner un modèle :

- Dans l'interface GitLab :
  1. Sous la zone de texte du Chat, vérifiez que le bouton bascule **Agentique** est activé.
  1. Sélectionnez un modèle dans la liste déroulante.
- Dans votre IDE :
  1. Dans la barre latérale, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
  1. Si vous utilisez la [mise en page classique](#change-the-layout-in-your-ide), sélectionnez l'onglet **Chat**.
  1. Sélectionnez un modèle dans la liste déroulante.

## Sélectionner un agent {#select-an-agent}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/562708) dans GitLab 18.4.
- [Ajout](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/merge_requests/2196) à VS Code et aux IDE JetBrains dans GitLab 18.5.

{{< /history >}}

Lorsque vous utilisez le Chat pour un projet dans l'interface GitLab, VS Code ou un IDE JetBrains, vous pouvez sélectionner l'agent que le Chat doit utiliser.

Prérequis :

- Dans votre projet, [un agent du catalogue d'IA doit être activé](../duo_agent_platform/agents/custom.md#enable-an-agent).
- Vous devez être membre du projet dans lequel l'agent est activé.
- Pour VS Code, [installez et configurez l'extension GitLab pour VS Code](../../editor_extensions/visual_studio_code/setup.md) version 6.49.12 ou ultérieure.
- Pour un IDE JetBrains, [installez et configurez le plug-in GitLab Duo pour les IDE JetBrains](../../editor_extensions/jetbrains_ide/setup.md) version 3.22.0 ou ultérieure.

Pour sélectionner un agent :

1. Dans l'interface GitLab ou votre IDE, ouvrez une nouvelle conversation dans GitLab Duo Chat.
1. Dans l'interface GitLab, sous la zone de texte du Chat, vérifiez que le bouton bascule **Agentique** est activé.
1. Dans la liste déroulante, sélectionnez un agent. Si vous n'avez configuré aucun agent, il n'y a pas de liste déroulante et le Chat utilise l'agent GitLab Duo par défaut.
1. Saisissez votre question et appuyez sur <kbd>Entrée</kbd> ou sélectionnez **Envoyer**.

Après avoir créé une conversation avec un agent :

- La conversation mémorise l'agent que vous avez sélectionné. Vous ne pouvez pas sélectionner un agent différent pour cette conversation. Dans la nouvelle mise en page IDE, si vous sélectionnez un agent différent, Chat vous demande de confirmer, puis démarre une nouvelle conversation.
- Si vous utilisez l'historique de discussion pour revenir à la même conversation, celle-ci utilise le même agent.
- Si vous revenez à une conversation et que l'agent associé n'est plus disponible, vous ne pouvez pas continuer cette conversation.

## Mise en cache des prompts {#prompt-caching}

{{< history >}}

- Introduction dans GitLab 18.7.

{{< /history >}}

La mise en cache des prompts est activée par défaut et ne fonctionne que lorsque le modèle d'Agentic Chat sélectionné est d'Anthropic ou est un modèle Anthropic servi via Vertex.

Lorsque la mise en cache des prompts est activée, les données des prompts de Chat sont temporairement stockées en mémoire par le fournisseur du modèle.

La mise en cache des prompts améliore considérablement la latence en évitant le retraitement des données de prompt et d'entrée mises en cache.

Vous pouvez [désactiver la mise en cache des prompts](../gitlab_duo/data_usage.md#turn-off-prompt-caching) :

- Sur GitLab.com : pour un groupe principal.
- Sur GitLab Self-Managed : pour une instance.

Ce paramètre s'applique à toutes les fonctionnalités de GitLab Duo Agent Platform.

## Approbations d'outils {#tool-approvals}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/20519) dans GitLab 19.0
  - Introduction dans [GitLab for VS Code](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.72.0) 6.72.0
  - Introduction dans [le plug-in GitLab Duo pour les IDE JetBrains](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.33.0) 3.33.0
  - Introduction dans [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.80.0) 8.80.0.
- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/21850) de l'approbation d'outils fondée sur des motifs dans GitLab 19.1
  - Introduction dans [GitLab for VS Code](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.83.2) 6.83.2.
  - Introduction dans [le plug-in GitLab Duo pour les IDE JetBrains](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.38.0) 3.38.0.
  - Introduction dans [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.101.0) 8.101.0.
- [Suppression](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/merge_requests/3699) de l'approbation d'outil basée sur des modèles le 10 juillet 2026.
  - Suppression dans [GitLab for VS Code](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.85.3) 6.85.3.
  - Suppression dans [GitLab Duo plugin for JetBrains IDEs](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.43.0) 3.43.0.
  - Suppression dans [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.3.0) 9.3.0.

{{< /history >}}

Avant qu'Agentic Chat puisse utiliser un outil en votre nom, vous devez approuver cette utilisation. Par défaut, chaque invocation d'outil requiert une approbation.

Si vous faites confiance à un outil et souhaitez simplifier votre workflow, vous pouvez l'approuver une seule fois pour toute la session.

Les approbations de session s'appliquent uniquement au Chat, pas aux flows.

### Gérer les approbations d'outils {#manage-tool-approvals}

Les propriétaires et les administrateurs peuvent contrôler si les utilisateurs peuvent approuver des outils pour une session. Les paramètres se propagent de l'instance au groupe, puis au projet.

Configurez l'une des options suivantes pour un groupe ou une instance :

- **Activé par défaut** : les utilisateurs peuvent approuver des outils une fois par session. Les groupes et sous-groupes peuvent désactiver cette option.
- **Désactivé par défaut** : (par défaut) les utilisateurs doivent approuver chaque invocation d'outil. Les groupes et sous-groupes peuvent activer cette option.
- **Toujours désactivé** : les utilisateurs ne peuvent pas approuver des outils pour une session. Les groupes et sous-groupes ne peuvent pas remplacer ce paramètre.

#### Gérer les paramètres par défaut {#manage-default-settings}

Configurez le paramètre d'approbation d'outils par défaut pour votre instance ou votre groupe principal.

{{< tabs >}}

{{< tab title="GitLab.com" >}}

Prérequis :

- Disposer du rôle Propriétaire pour le groupe principal.

Pour configurer les paramètres d'approbation d'outils par défaut :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre groupe.
1. Sélectionnez **Paramètres** > **GitLab Duo**.
1. Dans la liste déroulante **Autorisation des outils pour les sessions**, sélectionnez l'option de votre choix.

{{< /tab >}}

{{< tab title="GitLab Self-Managed" >}}

Prérequis :

- Disposer d'un accès administrateur.

Pour configurer les paramètres d'approbation d'outils par défaut :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Sélectionnez **GitLab Duo**.
1. Dans la liste déroulante **Autorisation des outils pour les sessions**, sélectionnez l'option de votre choix.

{{< /tab >}}

{{< tab title="GitLab Dedicated" >}}

Prérequis :

- Disposer d'un accès administrateur.

Pour configurer les paramètres d'approbation d'outils par défaut :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Sélectionnez **GitLab Duo**.
1. Dans la liste déroulante **Autorisation des outils pour les sessions**, sélectionnez l'option de votre choix.

{{< /tab >}}

{{< /tabs >}}

#### Gérer les paramètres de groupe ou de projet {#manage-group-or-project-settings}

Configurez les paramètres d'approbation d'outils pour un groupe ou un projet spécifique.

Prérequis :

- Disposer du rôle Propriétaire pour le groupe ou du rôle Chargé de maintenance pour le projet.

Pour configurer les paramètres d'approbation d'outils :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et repérez votre groupe ou votre projet.
1. Sélectionnez **Paramètres** > **GitLab Duo**.
1. Pour les groupes, sélectionnez l'option de votre choix dans la liste déroulante **Autorisation des outils pour les sessions**.
1. Pour les projets, cochez ou décochez la case **Autoriser l'approbation des outils pour la session**.

### Approuver des outils dans votre environnement local {#approve-tools-in-your-local-environment}

Prérequis :

- Les approbations d'outils sont activées pour votre groupe ou instance.
- Pour utiliser GitLab Duo Chat dans votre environnement local, installez et configurez l'un des éléments suivants :
  - [GitLab for VS Code](../../editor_extensions/visual_studio_code/setup.md) 6.72.0 ou version ultérieure.
  - [Plug-in GitLab Duo pour les IDE JetBrains](../../editor_extensions/jetbrains_ide/setup.md) 3.33.0 ou version ultérieure.
  - [GitLab Duo CLI](../gitlab_duo_cli/_index.md) 8.80.0 ou version ultérieure.

Pour approuver ou refuser un outil pour votre session en cours :

1. Lorsqu'un prompt d'approbation d'outil apparaît, ouvrez la liste déroulante située à côté du bouton d'approbation.
1. Sélectionnez l'une des options suivantes :
   - **Approuver** : le Chat peut utiliser l'outil une seule fois avec ces arguments.
   - **Approuver pour la session** : le Chat peut utiliser l'outil avec ces arguments jusqu'à la fin de la session. Des arguments différents nécessitent une approbation supplémentaire.
   - **Refuser** : le Chat ne peut pas utiliser l'outil.

Toutes les approbations sont réinitialisées lorsque vous démarrez une nouvelle conversation.

## Comparaison des fonctionnalités du Chat {#chat-feature-comparison}

| Capacité                                     | GitLab Duo Non-Agentic Chat                                              | GitLab Duo Agentic Chat                                                                                           |
| ---------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Poser des questions générales de programmation              | Oui                                                                      | Oui                                                                                                               |
| Obtenir des réponses sur un fichier ouvert dans l'éditeur   | Oui                                                                      | Oui. Indiquez le chemin du fichier dans votre question.                                                               |
| Fournir du contexte sur les fichiers indiqués          | Oui. Utilisez `/include` pour ajouter un fichier à la conversation.[^not-in-ide-chat] | Oui. Indiquez le chemin du fichier dans votre question. Dans la nouvelle mise en page IDE, vous pouvez également saisir `@` pour ajouter le fichier. |
| Rechercher de manière autonome dans le contenu du projet           | Non                                                                       | Oui                                                                                                               |
| Créer et modifier des fichiers de manière autonome     | Non                                                                       | Oui. Demandez-lui de modifier des fichiers. Cela peut écraser les modifications que vous avez apportées manuellement et que vous n'avez pas encore commitées.   |
| Récupérer des tickets et des merge requests sans spécifier d'identifiants | Non                                                                       | Oui. Recherchez selon d'autres critères. Par exemple, le titre d'une merge request ou d'un ticket, ou la personne qui y est assignée.                                   |
| Combiner des informations provenant de plusieurs sources      | Non                                                                       | Oui                                                                                                               |
| Analyser les journaux de pipeline                          | Oui. Nécessite le module d'extension GitLab Duo Enterprise.                              | Oui                                                                                                               |
| Redémarrer une conversation                         | Oui. Utilisez `/new` ou `/reset`.                                             | Oui. Utilisez `/new` ou `/reset` si vous êtes dans l'interface.                                                                       |
| Supprimer une conversation                          | Oui, dans l'historique de discussion.                                                | Oui, dans l'historique de discussion                                                                                          |
| Créer des tickets et des merge requests                          | Non                                                                       | Oui                                                                                                               |
| Utiliser les commandes Git en lecture seule                     | Non                                                                       | Oui                                                                                                               |
| Utiliser les commandes Git en écriture                         | Non                                                                       | Oui, dans l'interface uniquement                                                                                                      |
| Exécuter des commandes Shell                             | Non                                                                       | Oui, dans les IDE uniquement                                                                                                    |
| Exécuter des outils MCP                                  | Non                                                                       | Oui, dans les IDE uniquement                                                                                                    |
| Approuver des outils pour une session                    | Non                                                                       | Oui, dans les IDE uniquement                                                                                                    |

[^not-in-ide-chat]: Non disponible lors de l'utilisation de GitLab Duo Non-Agentic Chat dans l'IDE Web.

## Sujets connexes {#related-topics}

- [Article de blog : GitLab Duo Chat fait peau neuve : place à l'IA agentique](https://about.gitlab.com/blog/gitlab-duo-chat-gets-agentic-ai-makeover/)
