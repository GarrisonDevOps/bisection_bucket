---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "API REST pour créer, démarrer et gérer les flows de la plateforme GitLab Duo Agent."
title: API Flows
---

{{< details >}}

- Édition : Premium, Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Utilisez cette API pour créer et gérer des [flows](../user/duo_agent_platform/flows/_index.md) dans la [plateforme GitLab Duo Agent](../user/duo_agent_platform/_index.md). Les flows sont des combinaisons d'agents d'IA qui travaillent ensemble pour accomplir des tâches de développement, comme la correction de bugs, l'écriture de code ou la résolution de vulnérabilités.

## Déclencher un flow {#trigger-a-flow}

{{< history >}}

- Exigence d'un compte de service à identité composite lorsque `start_workflow` est `true` [introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/601901) dans GitLab 19.4 [avec un feature flag](../administration/feature_flags/_index.md) nommé `enforce_composite_identity_for_api_started_workflows`. Fonctionnalité désactivée par défaut.
- Les attributs `callback_hook_id` et `client_reference` [introduits](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249147) dans GitLab 19.4 [avec un feature flag](../administration/feature_flags/_index.md) nommé `duo_flow_callback_hooks`. Fonctionnalité désactivée par défaut.
- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258242) dans GitLab 19.5.

{{< /history >}}

> [!flag]
> L'exigence d'un compte de service à identité composite est contrôlée par un feature flag. La disponibilité des attributs `callback_hook_id` et `client_reference` est contrôlée par un feature flag distinct. Pour plus d'informations, consultez l'historique.

Déclenche et démarre un nouveau flow.

Prérequis :

- Si le feature flag `enforce_composite_identity_for_api_started_workflows` est activé et que `start_workflow` est `true`, le flow doit disposer d'un compte de service à [identité composite](../user/duo_agent_platform/composite_identity.md). Le compte de service est soit configuré pour le flow dans le catalogue d'IA, soit le compte de service associé à l'identité composite de la requête. Dans le cas contraire, GitLab retourne `403 Forbidden` et ne démarre pas le flow.

```plaintext
POST /ai/duo_workflows/workflows
```

Attributs pris en charge :

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `additional_context` | tableau d'objets | Non | Contexte supplémentaire pour le flow. Chaque élément doit être un objet comportant au minimum une clé `Category` (chaîne) et `Content` (chaîne, JSON sérialisé). |
| `agent_privileges` | tableau d'entiers | Non | ID de privilèges que l'agent d'IA est autorisé à utiliser. Par défaut, tous les privilèges sont accordés. Voir [Répertorier tous les privilèges des agents](#list-all-agent-privileges). |
| `ai_catalog_item_consumer_id` | entier | Non | ID du consommateur d'élément du catalogue d'IA qui configure l'élément du catalogue à exécuter. Nécessite `project_id`. Ne peut pas être utilisé avec `workflow_definition` ; si les deux sont fournis, `ai_catalog_item_consumer_id` est prioritaire. Voir [Rechercher l'ID du consommateur](#look-up-the-consumer-id). |
| `ai_catalog_item_version_id` | entier | Non | ID de la version de l'élément du catalogue d'IA qui est à l'origine de la configuration du flow. |
| `allow_agent_to_request_user` | boolean | Non | Lorsque la valeur est `true` (par défaut), l'agent d'IA peut s'interrompre pour poser des questions à l'utilisateur avant de continuer. Lorsque la valeur est `false`, l'agent d'IA s'exécute jusqu'à la fin sans saisie de l'utilisateur. |
| `callback_hook_id` | entier | Non | ID d'un webhook avec [les callbacks webhook de flow GitLab Duo](../user/duo_agent_platform/flows/webhook_callbacks.md) activés. GitLab envoie les événements du cycle de vie du flow à ce webhook, ce qui vous évite d'avoir à interroger le statut du flow. Le webhook doit appartenir au projet ou à l'espace de nommage dans lequel le flow s'exécute, ou à l'un de ses groupes ancêtres. Cet attribut est une [version expérimentale](../policy/development_stages_support.md). |
| `client_reference` | string | Non | Chaîne opaque renvoyée dans chaque payload de callback, permettant de corréler les callbacks avec la requête qui a déclenché le flow. 255 caractères maximum. N'a aucun effet sans `callback_hook_id`. Cet attribut est une [version expérimentale](../policy/development_stages_support.md). |
| `environment` | string | Non | Environnement d'exécution. L'un des suivants : `ide`, `web`, `chat_partial`, `chat`, `ambient`. |
| `goal` | string | Non | Description de la tâche que l'agent d'IA doit accomplir. Exemple : `Fix the failing pipeline`. |
| `image` | string | Non | Image de conteneur à utiliser pour le flow. S'applique uniquement lorsque le flow s'exécute dans un pipeline CI. Doit satisfaire aux [exigences relatives aux images personnalisées](../user/duo_agent_platform/flows/execution/images.md#use-a-custom-image). Exemple : `registry.gitlab.com/gitlab-org/duo-workflow/custom-image:latest`. |
| `issue_id` | entier | Non | IID du ticket à associer au flow. Nécessite `project_id`. |
| `merge_request_id` | entier | Non | IID du merge request à associer au flow. Nécessite `project_id`. |
| `namespace_id` | string | Non | ID ou chemin de l'espace de nommage à associer au flow. |
| `pre_approved_agent_privileges` | tableau d'entiers | Non | ID de privilèges que l'agent d'IA peut utiliser sans demander l'approbation de l'utilisateur. Doit être un sous-ensemble de `agent_privileges`. |
| `project_id` | string | Non | ID ou chemin du projet à associer au flow. |
| `source` | string | Non | Origine du déclenchement de la session. L'un des points d'entrée des fonctionnalités GitLab (par exemple, `merge_request_code_conflict`) ou la surface cliente ayant créé la session (`duo_cli_interactive`, `duo_cli_run`, `duo_cli_acp`, `ide_extension`). Persisté en tant que `source_type` de la session. |
| `source_branch` | string | Non | Branche source du flow. S'applique uniquement lorsque le flow s'exécute dans un pipeline CI. Lorsqu'elle n'est pas spécifiée, un flow dont l'objectif est un pipeline ou une merge request, tel que `fix_pipeline/v1` ou `code_review/v1`, s'exécute sur la branche de ce pipeline ou de cette merge request. Pour `fix_pipeline/v1`, les entrées `merge_request` et `pipeline` dans `additional_context` sont également renseignées à partir du pipeline. Les autres flows s'exécutent sur la branche par défaut du projet. |
| `start_workflow` | boolean | Non | Lorsque la valeur est `true`, le flow démarre immédiatement après sa création. |
| `workflow_definition` | string | Non | Identifiant du type de flow. Exemple : `developer/v1`. Ne peut pas être utilisé avec `ai_catalog_item_consumer_id` ; si les deux sont fournis, `ai_catalog_item_consumer_id` est prioritaire. |

En cas de succès, renvoie [`201 Created`](rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut | Type | Description |
|-----------|------|-------------|
| `agent_privileges` | tableau d'entiers | ID de privilèges attribués à l'agent d'IA. |
| `agent_privileges_names` | tableau de chaînes | Noms correspondant à `agent_privileges`. |
| `ai_catalog_item_version_id` | entier | ID de la version de l'élément du catalogue d'IA. `null` si non défini. |
| `allow_agent_to_request_user` | boolean | Lorsque la valeur est `true`, l'agent d'IA peut s'interrompre pour attendre une saisie de l'utilisateur. |
| `environment` | string | Environnement d'exécution. `null` si non défini. |
| `gitlab_url` | string | URL de base de l'instance GitLab. |
| `id` | entier | ID du flow. |
| `image` | string | Image de conteneur pour l'exécution du pipeline CI. `null` si non définie. |
| `mcp_enabled` | boolean | Indique si les outils `MCP` (Model Context Protocol) sont activés pour ce flow. |
| `namespace_id` | entier | ID de l'espace de nommage associé. `null` si non défini. |
| `pre_approved_agent_privileges` | tableau d'entiers | ID de privilèges que l'agent d'IA peut utiliser sans demander d'approbation. |
| `pre_approved_agent_privileges_names` | tableau de chaînes | Noms correspondant à `pre_approved_agent_privileges`. |
| `project_id` | entier | ID du projet associé. `null` si non défini. |
| `status` | string | Statut actuel du flow. L'un des suivants : `created`, `running`, `paused`, `finished`, `failed`, `stopped`, `input_required`, `plan_approval_required` ou `tool_call_approval_required`. GitLab peut ajouter de nouvelles valeurs. |
| `summary` | string | Bref résumé textuel du workflow. |
| `title` | string | Titre de la session. |
| `web_url` | string | URL de la session dans l'interface utilisateur GitLab. `null` si la session n'est pas associée à un projet. |
| `workflow_definition` | string | Identifiant du type de flow. |
| `workload` | objet | Informations sur la charge de travail. |
| `workload.id` | entier | ID de la charge de travail. `null` si aucune charge de travail n'a été créée, par exemple lorsque `start_workflow` n'est pas `true`. |
| `workload.message` | string | Message de statut de la charge de travail. `null` si aucune charge de travail n'a été créée. |

Si l'utilisateur doit effectuer une [vérification d'identité](../security/identity_verification.md) avant de pouvoir utiliser GitLab Duo Agent Platform, GitLab retourne [`403 Forbidden`](rest/troubleshooting.md#status-codes) avec un `message` :

```json
{
  "message": "403 Forbidden - Identity verification is required to use GitLab Duo Agent Platform"
}
```

GitLab retourne [`400 Bad request`](rest/troubleshooting.md#status-codes) lorsque `callback_hook_id` est défini et que l'une des conditions suivantes est vraie :

- Le feature flag `duo_flow_callback_hooks` n'est pas activé pour le groupe principal du projet ou de l'espace de nommage dans lequel le flow s'exécute.
- L'ID ne fait pas référence à un webhook sur lequel les callbacks de flow GitLab Duo sont activés dans le projet ou l'espace de nommage dans lequel le flow s'exécute, ou dans l'un de ses groupes ancêtres.

### Rechercher l'ID du consommateur {#look-up-the-consumer-id}

Avant de pouvoir utiliser `ai_catalog_item_consumer_id`, vous devez utiliser l'API GraphQL pour récupérer l'ID depuis le [catalogue d'IA](../user/duo_agent_platform/ai_catalog.md). L'élément doit déjà être activé pour le projet.

```graphql
query {
  aiCatalogConfiguredItems(projectId: "gid://gitlab/Project/<project_id>") {
    nodes {
      id
      item { name }
    }
  }
}
```

Le champ `id` est un ID global au format `gid://gitlab/AiCatalogItemConsumer/<numeric_id>`. Utilisez le suffixe numérique comme valeur de `ai_catalog_item_consumer_id`.

Exemple de requête utilisant un type de flow intégré :

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --header "Content-Type: application/json" \
  --data '{
    "project_id": "5",
    "goal": "Fix the failing pipeline by correcting the syntax error in .gitlab-ci.yml",
    "workflow_definition": "developer/v1",
    "start_workflow": true
  }' \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows"
```

Exemple de requête utilisant un flow configuré via le catalogue :

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --header "Content-Type: application/json" \
  --data '{
    "project_id": "5",
    "goal": "Fix the failing pipeline by correcting the syntax error in .gitlab-ci.yml",
    "ai_catalog_item_consumer_id": 12,
    "start_workflow": true
  }' \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows"
```

Exemple de réponse :

```json
{
  "id": 1,
  "web_url": "https://gitlab.example.com/group/project/-/automate/agent-sessions/1",
  "project_id": 5,
  "namespace_id": null,
  "agent_privileges": [1, 2, 3, 4, 5, 6],
  "agent_privileges_names": [
    "read_write_files",
    "read_only_gitlab",
    "read_write_gitlab",
    "run_commands",
    "use_git",
    "run_mcp_tools"
  ],
  "pre_approved_agent_privileges": [],
  "pre_approved_agent_privileges_names": [],
  "workflow_definition": "developer/v1",
  "status": "running",
  "allow_agent_to_request_user": true,
  "image": null,
  "environment": null,
  "ai_catalog_item_version_id": null,
  "workload": {
    "id": "abc-123",
    "message": "Workflow started"
  },
  "mcp_enabled": false,
  "gitlab_url": "https://gitlab.example.com"
}
```

## Redémarrer un flow {#restart-a-flow}

{{< details >}}

- Statut : version expérimentale

{{< /details >}}

Redémarre un flow en échec ou arrêté en démarrant un nouveau flow avec les mêmes paramètres de flow. Le nouveau flow s'exécute depuis le début. Le flow d'origine n'est pas modifié et conserve son statut `failed` ou `stopped`.

Seuls les flows de niveau projet avec un statut `failed` ou `stopped` peuvent être redémarrés. Le redémarrage d'un flow avec tout autre statut, ou d'un flow de niveau groupe, retourne `403 Forbidden`. Le redémarrage du même flow alors qu'un redémarrage est encore en cours retourne `409 Conflict`.

```plaintext
POST /ai/duo_workflows/workflows/:workflow_id/restart
```

Attributs pris en charge :

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `workflow_id` | entier | Oui | ID du flow à redémarrer. |

En cas de succès, retourne [`201 Created`](rest/troubleshooting.md#status-codes) et les mêmes attributs de réponse que [Déclencher un flow](#trigger-a-flow). La réponse décrit le nouveau flow ; ainsi, `id` est l'ID du nouveau flow et non celui que vous avez redémarré.

Exemple de requête :

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows/42/restart"
```

## Obtenir la trace du workflow au format JSONL {#get-workflow-trace-as-jsonl}

{{< details >}}

- Statut : version expérimentale

{{< /details >}}

Retourne les entrées `ui_chat_log` d'une session de workflow sous forme de [JSON Lines](https://jsonlines.org/) (JSONL). Chaque ligne est un objet JSON valide représentant une entrée du tableau `ui_chat_log`. Utilisez cet endpoint pour analyser ou diriger la trace vers des outils tels que `jq`.

Par défaut, l'endpoint retourne la conversation complète de tous les fils de discussion de la session, y compris les messages antérieurs à toute compaction de contexte. Utilisez l'attribut `thread` pour retourner un seul fil de discussion à la place.

```plaintext
GET /ai/duo_workflows/workflows/:workflow_id/trace.jsonl
```

Attributs pris en charge :

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `workflow_id` | entier | Oui | ID du workflow. |
| `thread` | string | Non | Fil de discussion à retourner. Omettez cet attribut pour obtenir la trace complète de tous les fils de discussion. Utilisez `latest` pour le fil de discussion le plus récent uniquement, ou un ID de fil de discussion pour un fil de discussion spécifique. |

En cas de succès, retourne [`200 OK`](rest/troubleshooting.md#status-codes) avec :

- **Content-Type** : `application/x-ndjson`
- **Corps** : un objet JSON par ligne, chacun représentant une entrée `ui_chat_log`. Retourne un corps vide si le workflow n'a pas de points de contrôle ou n'a pas d'entrées `ui_chat_log`.

Si l'utilisateur doit effectuer une [vérification d'identité](../security/identity_verification.md) avant de pouvoir utiliser GitLab Duo Agent Platform, GitLab retourne [`403 Forbidden`](rest/troubleshooting.md#status-codes) avec un `message` :

```json
{
  "message": "403 Forbidden - Identity verification is required to use GitLab Duo Agent Platform"
}
```

Exemple de requête :

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows/1/trace.jsonl"
```

Exemple de réponse (chaque ligne est un objet JSON distinct) :

```jsonl
{"status":"success","content":"Analyze the issue","message_type":"human"}
{"status":"success","content":"I'll start by reading the codebase.","message_type":"ai"}
```

Vous pouvez diriger la sortie vers `jq` pour filtrer les entrées par type :

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows/1/trace.jsonl" \
  | jq 'select(.message_type == "ai")'
```

## Répertorier tous les privilèges des agents {#list-all-agent-privileges}

Répertorie tous les privilèges d'agent d'IA disponibles avec leurs ID, noms, descriptions et indique si chacun est activé par défaut.

```plaintext
GET /ai/duo_workflows/workflows/agent_privileges
```

Ce point de terminaison ne prend en charge aucun attribut.

En cas de succès, renvoie [`200 OK`](rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut | Type | Description |
|-----------|------|-------------|
| `all_privileges` | tableau d'objets | Tous les privilèges d'agent d'IA disponibles. |
| `all_privileges[].default_enabled` | boolean | Indique si le privilège est activé par défaut. |
| `all_privileges[].description` | string | Description lisible par l'humain de ce que le privilège autorise. |
| `all_privileges[].id` | entier | ID de privilège. |
| `all_privileges[].name` | string | Nom de privilège lisible par machine. |

Exemple de requête :

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows/agent_privileges"
```

Exemple de réponse :

```json
{
  "all_privileges": [
    {
      "id": 1,
      "name": "read_write_files",
      "description": "Allow local filesystem read/write access",
      "default_enabled": true
    },
    {
      "id": 2,
      "name": "read_only_gitlab",
      "description": "Allow read only access to GitLab APIs",
      "default_enabled": true
    },
    {
      "id": 3,
      "name": "read_write_gitlab",
      "description": "Allow write access to GitLab APIs",
      "default_enabled": true
    },
    {
      "id": 4,
      "name": "run_commands",
      "description": "Allow running any commands",
      "default_enabled": true
    },
    {
      "id": 5,
      "name": "use_git",
      "description": "Allow git commits, push and other git commands",
      "default_enabled": true
    },
    {
      "id": 6,
      "name": "run_mcp_tools",
      "description": "Allow running MCP tools",
      "default_enabled": true
    }
  ]
}
```
