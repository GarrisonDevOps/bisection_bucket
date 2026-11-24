---
stage: Agent Foundations
group: Agent Developer
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Flow Developer
---

{{< details >}}

- Édition : [Gratuite](../../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Introduit en version [bêta](../../../policy/development_stages_support.md) dans GitLab 18.3 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `duo_workflow_in_ci`. Désactivé par défaut, mais peut être activé pour l'instance ou un utilisateur.
- Renommé de `Issue to MR` en `Developer Flow` avec un feature flag nommé `duo_developer_button` dans GitLab 18.6. Désactivé par défaut, mais peut être activé pour l'instance ou un utilisateur. Le feature flag `duo_workflow` doit également être activé, mais il l'est par défaut.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273) dans GitLab 18.8.
- Les feature flags `duo_workflow_in_ci`, `duo_developer_button` et `duo_workflow` ont été supprimés dans GitLab 18.9.
- Disponible sur l'édition Gratuite sur GitLab.com avec des GitLab Credits dans GitLab 18.10.
- Les déclencheurs de mention ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/228817) dans GitLab 18.11.
- Les déclencheurs de changement de statut des éléments de travail, ainsi que la prise en charge des plans de travail lors de l'assignation du flow, ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/work_items/633027) dans GitLab 19.6.

{{< /history >}}

Le flow Developer vous aide à travailler plus efficacement sur les tickets et les merge requests. Vous pouvez utiliser le flow Developer pour :

- Créer une ébauche de merge request à partir d'un ticket.
- Modifier une merge request existante en tenant compte des commentaires de révision.
- Étudier les différentes approches de mise en œuvre et partager vos conclusions dans un fil de discussion.
- Diviser une merge request volumineuse en plusieurs merge requests plus petites et ciblées.
- Résoudre les conflits de merge.

Le flow Developer est différent du [flow Software Development](../../../editor_extensions/software_development.md), qui s'exécute dans votre IDE. Pour plus d'informations, consultez [choisir un flow pour les tâches de codage](../../duo_agent_platform/flows/foundational_flows/_index.md#choose-a-flow-for-coding-tasks).

## Prérequis {#prerequisites}

- Satisfaire aux [prérequis pour GitLab Duo Agent Platform](../../duo_agent_platform/_index.md#prerequisites).
- Activer **Autoriser les flows par défaut** et **Developer** [pour le groupe principal](../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off).
- Disposer du rôle Développeur, Chargé de maintenance ou Propriétaire pour le projet.
- [Configurer les règles push pour autoriser un compte de service](../../duo_agent_platform/troubleshooting.md#configure-push-rules-to-allow-a-service-account).
- [Configurer vos propres runners](../../duo_agent_platform/flows/execution/_index.md#configure-runners-to-execute-flows) ou activer les [runners hébergés par GitLab](../../../ci/runners/hosted_runners/_index.md) pour votre projet.

Pour garantir les meilleurs résultats, avant d'utiliser le flow Developer pour la première fois, [configurez votre projet](#set-up-your-project). Configurez les fichiers `AGENTS.md` et `agent-config.yml` pour améliorer considérablement la qualité et la fiabilité des résultats du flow Developer.

## Configurer votre projet {#set-up-your-project}

Pour optimiser les performances du flow Developer, vous devez configurer votre projet avec les paramètres facultatifs suivants :

- Ajouter un fichier `AGENTS.md` : Documentez les conventions de votre projet, telles que les commandes de test, les règles de linting, le format de commit et les modèles de codage. Le flow Developer utilise ce fichier comme contexte lorsque vous travaillez dans votre dépôt. Pour plus d'informations, consultez [Fichiers de personnalisation AGENTS.md](../../duo_agent_platform/customize/agents_md.md).
- Ajouter des sous-agents workspace : définissez des sous-agents spécialisés dans le répertoire `.agents/agents/` auxquels le flow Developer peut déléguer des tâches ciblées, comme des révisions ou des recherches. Cette fonctionnalité est une version expérimentale. Pour plus d'informations, consultez [sous-agents workspace](../../duo_agent_platform/customize/workspace_subagents.md).
- Configurer l'environnement d'exécution : Si votre projet nécessite des outils spécifiques (par exemple, Go, Python ou Node.js), configurez l'environnement de l'agent à l'aide d'un fichier `agent-config.yml`. Sans cela, le flow Developer ne peut pas installer les dépendances ni exécuter les tests, et est plus susceptible de produire des modifications qui ne compilent pas ou échouent. Dans un environnement correctement configuré, le flow Developer peut exécuter des tests et vérifier ses propres modifications avant d'effectuer un commit. Pour plus d'informations, consultez [Configurer l'exécution du flow](../../duo_agent_platform/flows/execution/_index.md).
- Choisissez un modèle : le flow Developer utilise le modèle par défaut de GitLab, optimisé pour équilibrer coût et performance. Pour les tâches ciblées, un modèle plus rapide réduit le temps d'itération pour les tâches complexes à plusieurs étapes, un modèle plus performant réduit le risque d'un plan incomplet. Pour plus d'informations, consultez [les modèles d'IA GitLab Duo](../../duo_agent_platform/model_selection.md).

## Utiliser le flow {#use-the-flow}

Prérequis :

- Les types d'événements **Mentionner** et **Assigner** sont [configurés](../../duo_agent_platform/triggers/_index.md) dans le déclencheur du flow Developer.

### Mentionner GitLab Duo Developer dans une discussion {#mention-duo-developer-in-a-discussion}

Pour transformer votre commentaire en tâche actionnable pour le flow Developer, mentionnez `@duo-developer-<namespace>` dans un commentaire. Remplacez `<namespace>` par votre chemin d'espace de nommage GitLab (par exemple, `gitlab-org`).

En fonction du contenu du ticket ou de la merge request et de la quantité d'informations de contexte que vous fournissez, le flow peut exécuter les tâches suivantes :

- Modifications du code
- Création de merge requests et de tickets
- Recherche d'une approche de mise en œuvre et notification ou mise à jour correspondante

Par exemple :

```plaintext
@duo-developer-<namespace> research approaches for implementing pagination
on the /users endpoint, then create a draft MR with the most
promising approach.
```

Le flow Developer répond avec un lien vers sa session.

Vous pouvez également, pour surveiller la progression, sélectionner **IA** > **Sessions** dans la barre latérale gauche.

### Générer une merge request à partir d'un ticket {#generate-a-merge-request-from-an-issue}

Pour créer une merge request à partir d'un ticket :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Planifier** > **Éléments de travail**, puis filtrez par **Type** = **Ticket**.
1. Sélectionnez le ticket pour lequel vous souhaitez créer une merge request.
1. Pour créer une merge request à partir du ticket, vous pouvez :
   - Assigner le compte de service Duo Developer au ticket :
     1. Dans la barre latérale droite, dans la section **Personnes assignées**, sélectionnez **Modifier**.
     1. Saisissez `duo developer` et sélectionnez-le dans les résultats de recherche.
   - Sous l'en-tête du ticket, sélectionnez **Mettre en œuvre**.
1. Pour surveiller la progression, dans la barre latérale gauche, sélectionnez **IA** > **Sessions**.
1. Une fois la session terminée, consultez la merge request depuis le lien dans la section **Activité** du ticket.

Lorsque vous assignez le flow à un ticket disposant d'un [plan de travail](../../work_items/workplan.md), le flow suit le plan de travail. Si la description et le plan de travail sont contradictoires, le flow suit le plan de travail.

### Démarrer le flow lors d'un changement de statut d'un élément de travail {#start-the-flow-when-a-work-item-status-changes}

Lorsqu'un élément de travail passe à un statut que vous sélectionnez, le flow Developer implémente l'élément de travail et crée une merge request. Le flow utilise le [plan de travail](../../work_items/workplan.md) de l'élément de travail comme spécification. Si l'élément de travail ne dispose pas de plan de travail, le flow utilise la description.

Prérequis :

- [Créez un déclencheur](../../duo_agent_platform/triggers/_index.md#create-a-trigger) pour le flow Developer avec le type d'événement **Élément de travail** et uniquement l'action **État modifié**. Si vous sélectionnez également **Créés**, vous ne pouvez pas sélectionner de statuts et le flow ne démarre pas lors de la création d'un élément de travail.
- Dans le déclencheur, sélectionnez les statuts qui démarrent le travail. Si vous ne sélectionnez aucun statut, chaque changement de statut démarre une session, y compris un passage à un statut « terminé ».

Pour démarrer le flow :

1. Modifiez le statut de l'élément de travail en l'un des statuts sélectionnés dans le déclencheur.
1. Pour surveiller la progression, dans la barre latérale gauche, sélectionnez **IA** > **Sessions**.
1. Une fois la session terminée, consultez la merge request à partir du lien dans la section **Activité** de l'élément de travail. Le flow assigne la merge request à l'utilisateur qui a modifié le statut.

### Utiliser le flow dans Agentic Chat {#use-the-flow-in-agentic-chat}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/20484) dans GitLab 19.2 [avec le feature flag](../../../administration/feature_flags/_index.md) `agentic_foundational_flow_tool`. Activés par défaut.
- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/work_items/605446) dans GitLab 19.5. Le feature flag `agentic_foundational_flow_tool` a été supprimé.

{{< /history >}}

Vous pouvez utiliser le flow Developer dans une conversation GitLab Duo Agentic Chat pour réaliser différentes tâches, par exemple :

- Atteindre un objectif de codage. Vous n'avez pas besoin d'un ticket associé à cet objectif.
- Résoudre un ticket en ouvrant une merge request.

Pour utiliser le flow dans une conversation Agentic Chat :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale GitLab Duo, ouvrez une conversation Agentic Chat nouvelle ou existante.
1. Demandez à Agentic Chat d'utiliser le flow Developer pour accomplir une tâche.

   La progression du flow s'affiche dans la conversation Chat. Pour plus d'informations, vous pouvez effectuer les opérations suivantes :
   - Sélectionnez **Afficher la session de l'agent** dans la conversation.
   - Dans la barre latérale gauche, sélectionnez **IA** > **Sessions**.

### Utiliser le flow dans la CLI GitLab Duo {#use-the-flow-in-the-gitlab-duo-cli}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/603623) comme flow par défaut dans la CLI GitLab Duo dans GitLab 19.2 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `duo_cli_default_flow`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251583) dans GitLab 19.4.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Prérequis :

- CLI GitLab Duo 9.4.0 ou version ultérieure.

La [CLI GitLab Duo](../../gitlab_duo_cli/_index.md) utilise le flow Developer en mode interactif et en mode headless. Le flow s'exécute là où vous lancez la CLI, par exemple sur votre ordinateur ou dans un job CI/CD, et non sur un runner que GitLab démarre pour la session.

Pour utiliser le flow, exécutez la CLI GitLab Duo dans l'un de ces modes :

- [Mode interactif](../../gitlab_duo_cli/use.md#interactive-mode).
- [Mode headless](../../gitlab_duo_cli/use.md#headless-mode).

### Fournir des images comme contexte {#provide-images-as-context}

{{< history >}}

- Introduit dans GitLab 19.5 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `dap_tool_image_input`. Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Prérequis :

- Utilisez un modèle géré par GitLab. Les modèles que vous hébergez vous-même ne sont pas pris en charge.
- Pour un flow que GitLab exécute sur un runner, par exemple un flow démarré depuis Agentic Chat, une discussion ou un ticket, l'environnement d'exécution doit inclure la CLI GitLab Duo 9.29.0 ou version ultérieure. Dans GitLab 19.5.0, l'image d'exécution par défaut ne répond pas à cette exigence. GitLab 19.5.1 et les versions ultérieures y répondent.

Le flow Developer peut lire des images et les utiliser comme contexte pour une tâche. Vous pouvez fournir des images lorsque vous utilisez le flow dans Agentic Chat, dans la [CLI GitLab Duo](../../gitlab_duo_cli/use.md#provide-images-as-context), ou dans un flow démarré depuis une discussion ou un ticket. Le flow peut lire :

- Les fichiers image dans le dépôt.
- Les images jointes à un ticket, une merge request ou un commentaire dans le même projet.

Vous ne pouvez pas téléverser une image directement dans votre invite. Indiquez plutôt une image qui existe déjà :

- Pour un fichier dans le dépôt, indiquez le chemin du fichier. Par exemple, `docs/architecture.png`.
- Pour une pièce jointe, indiquez la référence de téléversement telle qu'elle apparaît dans le Markdown. Par exemple, `/uploads/<secret>/screenshot.png`.

Lorsque le flow travaille sur un ticket, il peut également lire les images jointes à ce ticket.

#### Exigences relatives aux images {#image-requirements}

Pour utiliser une image comme contexte, l'image doit satisfaire aux exigences suivantes :

- Format : fichier PNG, JPEG ou WebP
- Taille : 10 Mo ou moins
- Dimensions : pas plus de 8 000 pixels de large ou de hauteur

## Bonnes pratiques {#best-practices}

### Fournir un contexte clair {#provide-clear-context}

Le flow Developer ne connaît que ce que vous lui indiquez ou ce qui est disponible dans le contexte du ticket, de la merge request, de la conversation Chat ou du fil de discussion. Les mêmes pratiques qui aident un collaborateur humain s'appliquent ici :

- Rédigez une description claire du problème avec des liens vers les fichiers ou discussions pertinents.
- Incluez des critères d'acceptation qui définissent à quoi ressemble une « tâche terminée ».
- Spécifiez les chemins de fichiers exacts lorsque vous les connaissez.
- Incluez des exemples de code illustrant les modèles existants afin de garantir la cohérence.
- Joignez des captures d'écran, des diagrammes ou des maquettes au ticket, ou commitez-les dans le dépôt, et nommez-les dans votre demande. Pour plus d'informations, consultez [Fournir des images comme contexte](#provide-images-as-context).

### Soyez explicite lorsque vous mentionnez GitLab Duo Developer dans les discussions {#be-explicit-when-mentioning-duo-developer-in-discussions}

Lorsque vous mentionnez GitLab Duo Developer dans une discussion, dites-lui exactement ce que vous souhaitez qu'il fasse. Par exemple :

- « Crée une ébauche de merge request qui intègre la pagination pour le point de terminaison `/api/users`. »
- « Prends en compte les commentaires de révision sur cette merge request. »
- « Divise les modifications de journalisation en une merge request séparée. »
- « Recherche des approches pour migrer ce service vers gRPC et publie les résultats ici. »
- « Il y a des conflits de merge sur cette merge request. Corrige-les. »

Sans instructions explicites, le flow choisit sa propre approche, qui peut ne pas correspondre à vos attentes.

### Maintenir les tâches ciblées {#keep-tasks-focused}

Décomposez les tâches complexes en demandes plus petites, ciblées et orientées vers l'action. Les tâches volumineuses et ouvertes sont plus susceptibles d'atteindre les limites d'itération.

## Exemples {#examples}

### Ticket pour générer une merge request {#issue-for-generating-a-merge-request}

Cet exemple montre un ticket bien conçu que le flow Developer peut utiliser pour générer une merge request.

```plaintext
## Description
The users endpoint currently returns all users at once,
which will cause performance issues as the user base grows.
Implement cursor-based pagination for the `/api/users` endpoint
to handle large datasets efficiently.

## Implementation plan
Add pagination to GET /users API endpoint.
Include pagination metadata in /users API response (per_page, page).
Add query parameters for per page size limit (default 5, max 20).

#### Files to modify
- `src/api/users.py` - Add pagination parameters and logic.
- `src/models/user.py` - Add pagination query method.
- `tests/api/test_users_api.py` - Add pagination tests.

## Acceptance criteria
- Accepts page and per_page query parameters (default: page=5, per_page=10).
- Limits per_page to a maximum of 20 users.
- Maintains existing response format for user objects in data array.
```

### Itérer sur les commentaires de révision d'une merge request {#iterate-on-merge-request-review-feedback}

Après avoir révisé une merge request, vous pouvez mentionner le flow Developer pour traiter les commentaires. Par exemple, dans un commentaire de révision sur une ligne spécifique :

```plaintext
@duo-developer-<namespace> move this validation logic into the `BaseService` class
in `app/services/base_service.rb` instead of duplicating it here.
```

Vous pouvez également soumettre une révision complète, puis mentionner le flow Developer pour traiter tous les fils de discussion ouverts :

```plaintext
@duo-developer-<namespace> please address the review feedback on this MR.
```

### Diviser une merge request {#split-a-merge-request}

Si une merge request est devenue trop volumineuse, vous pouvez demander au flow Developer d'en extraire une partie dans une merge request séparée :

```plaintext
@duo-developer-<namespace> the logging changes in this MR are out of scope.
Split them into a separate MR.
```

### Étudier une approche de mise en œuvre {#research-an-implementation-approach}

Vous pouvez demander au flow Developer d'analyser un problème et de faire un rapport avant d'effectuer des modifications :

```plaintext
@duo-developer-<namespace> research whether the `PUT /api/users` endpoint also needs
rate limiting like we added to the `POST /api/users` endpoint.
Post your findings here.
```

### Utiliser des images comme contexte {#use-images-as-context}

Le flow Developer peut lire des images depuis votre dépôt ou depuis des pièces jointes à des tickets et des merge requests dans le même projet. Nommez l'image dans votre invite.

Vous pouvez demander au flow Developer de corriger un bug d'interface affiché dans une capture d'écran jointe à un ticket :

```plaintext
Look at the screenshot attached to issue 1234 and fix the alignment bug it shows.
```

Vous pouvez demander au flow Developer d'expliquer un diagramme d'architecture :

```plaintext
Read docs/architecture.png, explain the data flow, and identify any single points of failure.
```

Vous pouvez demander au flow Developer de transformer une photo de tableau blanc en document de conception :

```plaintext
Read whiteboard.jpg and turn it into a design document in docs/design.md.
```

### Utiliser le flow Developer dans Agentic Chat {#use-the-developer-flow-in-agentic-chat}

Vous pouvez utiliser le flow Developer dans une conversation Agentic Chat pour réaliser différentes tâches :

- Pour atteindre un objectif de codage, vous pouvez saisir ce qui suit :
  - `Use the developer flow to resolve this code review feedback.`
  - `Use the developer flow to update this dependency.`
- Pour résoudre un ticket en ouvrant une merge request, vous pouvez saisir ce qui suit :
  - `Resolve this issue.`
  - `Open a merge request to resolve this issue.`
