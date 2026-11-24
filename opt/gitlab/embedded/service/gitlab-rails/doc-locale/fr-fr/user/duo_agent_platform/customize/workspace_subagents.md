---
stage: Agent Foundations
group: Agent Developer
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Définissez des sous-agents spécialisés dans votre dépôt pour que le flow Developer puisse leur déléguer des tâches.
title: Sous-agents workspace
---

{{< details >}}

- Édition : [Gratuite](../../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259664) dans GitLab 19.5 en [version expérimentale](../../../policy/development_stages_support.md#experiment) [avec le feature flag](../../../administration/feature_flags/_index.md) `dap_workspace_agents`. Activés par défaut.

{{< /history >}}

Les sous-agents workspace sont des agents spécialisés que vous définissez sous forme de fichiers Markdown dans le dépôt de votre projet. Cette fonctionnalité est disponible uniquement pour le flow Developer, aussi bien dans l'interface utilisateur GitLab que dans GitLab Duo CLI.

Le flow Developer décide quand déléguer une tâche à un sous-agent en fonction de la `description` du sous-agent. Vous pouvez également demander au flow Developer d'utiliser un sous-agent par son nom. Par exemple, dans un commentaire d'un ticket ou d'une merge request, [mentionnez le flow Developer](../../project/merge_requests/developer.md#mention-duo-developer-in-a-discussion) et nommez le sous-agent :

```plaintext
@duo-developer-<namespace> delegate the review of these changes to the reviewer subagent.
```

Remplacez `<namespace>` par le chemin de votre espace de nommage GitLab. Nommer un sous-agent rend la délégation probable, mais c'est le flow Developer qui décide si la tâche doit être déléguée.

Les sous-agents workspace consomment des GitLab Credits comme les autres fonctionnalités de GitLab Duo Agent Platform.

## Quand utiliser les sous-agents workspace {#when-to-use-workspace-subagents}

Les sous-agents workspace ne partagent pas le contexte avec le flow Developer. Utilisez un sous-agent lorsqu'une tâche produit des détails dont le flow Developer n'a pas besoin, afin que ces détails restent en dehors du contexte principal du flow Developer.

Par exemple, un sous-agent linter avec les outils `run_command` et `edit_file` peut exécuter les linters du projet et corriger les erreurs de lint. La sortie du linter et les corrections individuelles restent dans la conversation du sous-agent. Le flow Developer ne reçoit que le résultat, tel qu'un résumé des corrections. Si le prompt du sous-agent le demande, le résultat peut également lister les problèmes de lint typiques à éviter la prochaine fois. D'autres exemples incluent la revue des modifications, la recherche d'une approche ou la vérification d'un domaine spécifique comme la sécurité.

Lorsque le flow Developer délègue une tâche à un sous-agent, le sous-agent :

- Travaille dans sa propre conversation, qui commence par la tâche que lui confie le flow Developer. Seul le résultat est renvoyé au flow Developer.
- Suit son propre prompt plutôt que les instructions du flow Developer.
- Ne peut utiliser que les outils listés dans son champ `tools`. Par exemple, un sous-agent de revue disposant uniquement de `read_file` et `grep` ne peut pas modifier les fichiers.

Le tableau suivant compare les sous-agents workspace avec d'autres façons de personnaliser GitLab Duo Developer.

| Personnalisation | Objectif | À utiliser quand |
|---------------|--------------|-------------|
| `AGENTS.md` | Ajoute le contexte et les conventions du projet, tels que la structure, les conventions de codage et les instructions de build et de test, au contexte de l'agent qui effectue le travail. S'applique à tout le travail dans le dépôt. | Vous souhaitez que chaque tâche dans le dépôt suive les mêmes conventions. |
| Compétences d'agent | Fournit des connaissances ou des workflows qu'un agent charge automatiquement lorsqu'une tâche correspond à la description de la compétence. L'agent qui charge la compétence effectue le travail lui-même, dans la même conversation et avec les mêmes outils. | Vous souhaitez qu'un agent suive un workflow spécifique ou utilise des connaissances spécifiques lorsqu'une tâche correspond. |
| Sous-agents workspace | Exécute une tâche dans un agent distinct avec son propre prompt et ses propres outils, et renvoie uniquement le résultat. | Vous souhaitez garder les détails d'une tâche, comme la sortie du linter, en dehors du contexte du flow Developer, ou vous souhaitez un agent distinct avec ses propres instructions et des outils limités. |

## Définitions des sous-agents {#subagent-definitions}

Chaque sous-agent workspace est un fichier Markdown dans le répertoire `.agents/agents/` à la racine de votre dépôt. Le fichier commence par un en-tête YAML entre des lignes `---`, suivi du prompt. Le prompt correspond au corps Markdown du fichier.

Le tableau suivant décrit les champs de l'en-tête et le prompt.

| Champ | Obligatoire | Description |
|-------|----------|-------------|
| `name` | Non | Le nom que le flow Developer utilise pour identifier le sous-agent. Par défaut, correspond au nom du fichier sans l'extension `.md`. doit être unique dans le projet. Maximum 64 caractères. |
| `description` | Oui | Ce que fait le sous-agent. Le flow Developer l'utilise pour décider quand déléguer au sous-agent. Maximum 1 024 caractères. |
| `tools` | Non | Les outils que le sous-agent peut utiliser, sous forme de liste séparée par des virgules ou de liste YAML. Utilisez les noms d'outils figurant dans [la liste des outils disponibles](../agents/tools.md). Si vous omettez `tools`, le sous-agent ne peut utiliser aucun outil. Il ne peut que raisonner sur la tâche à partir des informations qui lui sont fournies. |
| Prompt | Oui | Les instructions destinées au sous-agent, après l'en-tête. Maximum 10 000 caractères. |

### Exigences relatives aux fichiers {#file-requirements}

Un sous-agent workspace n'est utilisé que si son fichier remplit toutes les exigences suivantes :

- Le fichier se trouve directement dans le répertoire `.agents/agents/`. Les fichiers dans les sous-répertoires sont ignorés.
- Le nom du fichier se termine par `.md`.
- Le fichier est encodé en UTF-8.
- Le fichier commence par un en-tête YAML entre des lignes `---`.
- L'en-tête contient un champ `description`.
- Le fichier contient un prompt après l'en-tête.
- Le fichier fait 64 Ko ou moins.

Si un fichier ne remplit pas ces exigences, il est ignoré.

### Limites de nombre et de taille {#number-and-size-limits}

Les limites suivantes s'appliquent à tous les sous-agents d'un projet.

| Limite | Sessions dans GitLab | Sessions GitLab Duo CLI |
|-------|--------------------|-------------------------|
| Nombre de sous-agents | Les 10 premiers fichiers `.md` par nom de fichier sont lus. | Jusqu'à 10 sous-agents. Chaque sous-agent qui remplit les exigences est envoyé. |
| Taille totale | Jusqu'à 112 Ko. La taille prend en compte le nom, la description, les outils et le prompt de chaque sous-agent. Si la taille totale est supérieure, certains sous-agents ne sont pas disponibles pour le flow Developer. | Limitée par la taille maximale des messages gRPC. |

### Erreurs empêchant le démarrage d'une session {#errors-that-prevent-a-session-from-starting}

Une session du flow Developer échoue au démarrage dans les cas suivants :

- Deux sous-agents portent le même nom.
- Un sous-agent liste un outil qui n'est pas disponible dans le flow Developer.
- Un `name`, un `description` ou un prompt dépasse sa longueur maximale.
- Dans les sessions GitLab Duo CLI, plus de 10 sous-agents remplissent les exigences.

## Créer un sous-agent workspace {#create-a-workspace-subagent}

Créez un sous-agent workspace pour doter le flow Developer d'un agent spécialisé auquel déléguer des tâches.

Prérequis :

- Activez les [fonctionnalités bêta et expérimentales](../turn_on_off.md#turn-on-beta-and-experimental-features). Vous ne pouvez pas activer ce paramètre pour un seul projet :
  - Sur GitLab.com, une personne disposant du rôle Owner modifie ce paramètre sur le groupe principal. Tous les sous-groupes et projets du groupe principal héritent de ce paramètre.
  - Sur GitLab Self-Managed et GitLab Dedicated, un administrateur modifie ce paramètre pour l'instance. Tous les groupes et projets de l'instance héritent de ce paramètre.
- Remplissez les [prérequis du flow Developer](../../project/merge_requests/developer.md#prerequisites).
- Pour tester le sous-agent avant de le fusionner, installez [GitLab Duo CLI](../../gitlab_duo_cli/_index.md) 9.21.0 ou une version ultérieure.

Pour créer un sous-agent workspace :

1. Dans une branche de votre projet, créez un fichier Markdown dans le répertoire `.agents/agents/`. Par exemple, `.agents/agents/reviewer.md`.
1. Ajoutez l'en-tête et le prompt. Par exemple :

   ```markdown
   ---
   name: reviewer
   description: Reviews code changes and reports a short list of findings.
   tools: read_file, grep
   ---

   You are a meticulous code reviewer. When delegated a task, read the files it
   names and report a short list of findings. Do not modify any file.
   ```

1. Testez le sous-agent avant de le fusionner. Les sessions dans GitLab lisent les sous-agents uniquement depuis la branche par défaut, mais GitLab Duo CLI lit les fichiers depuis votre répertoire de travail local.
   1. Dans le répertoire racine du projet, démarrez une session du flow Developer avec GitLab Duo CLI.
   1. Demandez au flow Developer de déléguer une tâche au sous-agent, ou donnez-lui une tâche correspondant à la description du sous-agent.
   1. Vérifiez que la session affiche `Delegated to workspace/agents/<subagent-name>`, suivi du résultat du sous-agent. Pour voir ce que le sous-agent a effectué, appuyez sur <kbd>Control</kbd>+<kbd>T</kbd>.

1. Committez ou fusionnez le fichier dans la branche par défaut.
1. Dans GitLab, démarrez une nouvelle session du flow Developer pour utiliser le sous-agent. Pour voir le résultat, ouvrez la session depuis le lien publié par le flow Developer, ou dans la barre latérale gauche, sélectionnez **IA** > **Sessions**. Lorsque le flow Developer délègue une tâche, la session affiche **Tâche déléguée à un sous-agent**, suivi de **Tâche renvoyée à l'agent** avec le résultat du sous-agent.

Dans GitLab, seules les nouvelles sessions prennent en compte les modifications apportées à la configuration du sous-agent. Les sessions existantes ne prennent pas en compte les modifications, même lorsque vous les reprenez.

## Empêcher les sous-agents workspace dans un projet {#prevent-workspace-subagents-in-a-project}

Vous ne pouvez pas désactiver les sous-agents workspace pour un seul projet. Pour empêcher les définitions de sous-agents d'être intégrées dans un dépôt, utilisez une ou les deux méthodes suivantes :

- Ajoutez `.agents/agents/` au fichier `.gitignore` du projet, afin que les fichiers ne soient pas commités par accident.
- Créez une [règle push pour interdire les fichiers par nom](../../project/repository/push_rules.md#prohibit-files-by-name) avec l'expression régulière `^\.agents\/agents\/`. GitLab rejette alors les pushs contenant ces fichiers.

## Sujets connexes {#related-topics}

- [Fichiers de personnalisation AGENTS.md](agents_md.md)
- [Compétences d'agent](agent_skills.md)
- [Règles personnalisées](custom_rules.md)

## Dépannage {#troubleshooting}

Si un sous-agent workspace ne fonctionne pas comme prévu :

1. Vérifiez que les fonctionnalités bêta et expérimentales sont activées.
1. Vérifiez le fichier par rapport aux [exigences relatives aux fichiers](#file-requirements). Les fichiers qui ne remplissent pas les exigences sont ignorés.
1. Pour les sessions dans GitLab, vérifiez que le fichier se trouve sur la branche par défaut.
1. Si la session échoue au démarrage, consultez les [erreurs empêchant le démarrage d'une session](#errors-that-prevent-a-session-from-starting).
