---
stage: Agent Foundations
group: Agent Developer
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Flow Software Development
---

{{< details >}}

- Édition : [Gratuite](../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< collapsible title="Informations sur le modèle" >}}

- LLM : Anthropic [Claude Sonnet 4](https://www.anthropic.com/claude/sonnet)
- Disponible sur [GitLab Duo avec des modèles auto-hébergés](../administration/gitlab_duo_self_hosted/_index.md)

{{< /collapsible >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/epics/14153) en tant que version bêta privée dans GitLab 17.4 [avec un feature flag](../administration/feature_flags/_index.md) nommé `duo_workflow`. Activé pour les membres de l'équipe GitLab uniquement.
- Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated, et passé en version bêta dans GitLab 18.2.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273) dans GitLab 18.8. Le feature flag `duo_workflow` a été supprimé.
- Disponible sur l'édition Gratuite sur GitLab.com avec des GitLab Credits dans GitLab 18.10.

{{< /history >}}

Le flow Software Development vous aide à créer des solutions générées par l'IA pour les tâches couvrant l'ensemble du cycle de vie du développement logiciel. Anciennement connu sous le nom de GitLab Duo Workflow, ce flow :

- S'exécute dans votre IDE afin que vous n'ayez pas à changer de contexte ou d'outil.
- Crée un plan et le suit, en réponse à votre invite.
- Prépare les modifications proposées dans le dépôt de votre projet. Vous contrôlez le moment auquel accepter, modifier ou rejeter les suggestions.
- Comprend le contexte de la structure de votre projet, de la base de code et de l'historique. Vous pouvez également ajouter votre propre contexte, comme des tickets GitLab ou des merge requests pertinents.

Ce flow est disponible dans VS Code, Visual Studio et JetBrains.

> [!note]
> Le flow Software Development est le flow IDE d'origine et diffère du [flow Developer](../user/project/merge_requests/developer.md). Pour la plupart des tâches de codage, utilisez le flow Developer dans l'interface utilisateur de GitLab ou le CLI GitLab Duo. Pour plus d'informations, consultez [choisir un flow pour les tâches de codage](../user/duo_agent_platform/flows/foundational_flows/_index.md#choose-a-flow-for-coding-tasks).

## Prérequis {#prerequisites}

- Satisfaire aux [prérequis pour GitLab Duo Agent Platform](../user/duo_agent_platform/_index.md#prerequisites).
- Installez et configurez une [extension d'éditeur](_index.md) pour votre IDE :
  - GitLab pour VS Code 6.85.0 et versions ultérieures
  - Plugin GitLab Duo pour les IDE JetBrains 3.40.0 et versions ultérieures
  - GitLab pour Visual Studio 0.79.0 et versions ultérieures
- Dans VS Code et les IDE JetBrains, utilisez la [disposition classique](../user/gitlab_duo_chat/agentic_chat.md#change-the-layout-in-your-ide). La nouvelle disposition n'inclut pas le flow.

## Comparaison entre le flow et le chat {#flow-and-chat-comparison}

Le flow Software Development et GitLab Duo Chat sont tous deux disponibles dans votre IDE. Dans la disposition classique, ils se trouvent sur des onglets séparés.

Utilisez le flow Software Development lorsque vous souhaitez examiner un plan complet avant que le flow n'apporte des modifications.

- Le flow rassemble un contexte complet, crée un plan détaillé que vous pouvez examiner et suit les tâches de manière méthodique.
- Le flow utilise une approche structurée idéale pour les sessions plus longues et plus approfondies nécessitant une large fenêtre de contexte, et produit de meilleurs résultats pour la génération de code nécessitant des itérations.
- Chaque flow a un début et une fin. Lorsque vous démarrez un nouveau flow, il rassemble à nouveau le contexte et crée un nouveau plan basé sur l'état actuel de votre projet.

Utilisez GitLab Duo Chat pour les interactions conversationnelles dans lesquelles vous guidez la direction.

- Le chat peut rassembler des informations pour répondre aux questions, fournir des suggestions et effectuer de manière autonome des actions en votre nom en réponse à vos invites.
- Le chat maintient des conversations continues, ce qui vous permet de revenir à n'importe quelle discussion en cours et de reprendre là où vous vous étiez arrêté.

Bien que les deux puissent aider pour des tâches similaires, ils fonctionnent différemment. Le flow rassemble d'emblée un contexte complet et s'exécute avec un minimum d'interaction humaine. Le chat fonctionne comme une boucle de rétroaction constante avec vous et rassemble le contexte selon les besoins au cours de la conversation. Par exemple, le flow envisage différentes solutions avant de proposer une approche, tandis que le chat se dirige directement vers le premier chemin viable pour fournir des résultats rapides.

## Utiliser le flow Software Development {#use-the-software-development-flow}

Pour utiliser le flow :

1. Dans votre IDE, sélectionnez **GitLab Duo Agent Platform** ({{< icon name="duo-agentic-chat" >}}).
1. Sélectionnez l'onglet **Flux**.
1. Dans la zone de texte, spécifiez une tâche de code en détail.
   - Le flow a connaissance de tous les fichiers disponibles pour Git dans la branche du projet.
   - Vous pouvez fournir du [contexte](../user/duo_agent_platform/context.md#gitlab-duo-agentic-chat) supplémentaire pour votre conversation Chat.
   - Le flow ne peut pas accéder à des sources externes ni au web.
   - Par exemple :

     ```plaintext
     I have a large Ruby class that is used in a few places and I want to break it down.
     Analyze this class and see what sub-methods or properties can be delegated to a
     separate class. Then, propose a transition plan to implement this new sub-class
     and update all of the required tests.
     ```

1. Sélectionnez **Démarrer**.

Après avoir décrit votre tâche, le flow génère et exécute un plan. Vous pouvez mettre en pause ou demander au flow d'ajuster le plan.

## Langages pris en charge {#supported-languages}

Cette liste s'applique uniquement au flow Software Development, et non aux autres flows. Le flow prend officiellement en charge les langages suivants :

- CSS
- Go
- HTML
- Java
- JavaScript
- Markdown
- Python
- Ruby
- TypeScript

## API auxquelles le flow a accès {#apis-that-the-flow-has-access-to}

Pour créer des solutions et comprendre le contexte du problème, le flow accède à plusieurs API GitLab.

Plus précisément, un jeton OAuth avec la portée `ai_workflows` a accès aux API suivantes :

- [API Projects](../api/projects.md)
- [API Search](../api/search.md)
- [API CI Pipelines](../api/pipelines.md)
- [API CI Jobs](../api/jobs.md)
- [API Job Artifacts](../api/job_artifacts.md)
- [API de déploiements](../api/deployments.md)
- [API Merge Requests](../api/merge_requests.md)
- [API Epics](../api/epics.md)
- [API Issues](../api/issues.md)
- [API de notes](../api/notes.md)
- [API Usage Data](../api/usage_data.md)
- [API Metadata](../api/metadata.md) (y compris le point de terminaison obsolète `/version`)

## Journal d'audit {#audit-log}

Le flow Software Development génère un événement d'audit pour chaque requête API. Sur votre instance GitLab Self-Managed, vous pouvez consulter ces événements sur la page des [événements d'audit de l'instance](../administration/compliance/audit_event_reports.md#instance-audit-events).

## Risques {#risks}

Le flow Software Development utilise un agent d'IA capable d'effectuer des actions à l'aide de votre compte GitLab. Les outils d'IA basés sur des grands modèles de langage peuvent être imprévisibles. Examinez les risques potentiels avant utilisation.

Le flow Software Development dans VS Code, les IDE JetBrains et Visual Studio exécute des workflows sur votre poste de travail local. Tenez compte de tous les risques documentés avant d'activer ce produit. Les principaux risques incluent :

- Le flow Software Development peut accéder aux fichiers du système de fichiers local du projet, y compris les fichiers non suivis par Git ou exclus dans `.gitignore`. Cela peut inclure des informations sensibles, telles que des identifiants dans les fichiers `.env`.
- Le flow Software Development se voit accorder un jeton OAuth GitLab à durée limitée avec la portée `ai_workflows`, lié à votre identité d'utilisateur. Ce jeton permet d'accéder aux API GitLab désignées pendant la durée du workflow. Par défaut, seules les opérations de lecture sont effectuées sans approbation explicite, mais des opérations d'écriture sont possibles en fonction de vos permissions.
- Ne fournissez pas au flow Software Development des identifiants ou des secrets supplémentaires (par exemple, dans des messages ou des objectifs), car ceux-ci pourraient être utilisés involontairement ou exposés dans du code ou des appels API.
