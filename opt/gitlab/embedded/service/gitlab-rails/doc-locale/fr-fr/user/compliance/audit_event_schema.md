---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: "Schéma et exemples d'événements d'audit"
---

## Schéma des événements d'audit {#audit-event-schema}

Les événements d'audit ont un schéma prévisible dans le corps de la réponse.

| Champ            | Description                                                | Remarques                                                                             | Champ réservé au streaming |
|------------------|------------------------------------------------------------|-----------------------------------------------------------------------------------|----------------------|
| `author_id`      | ID de l'utilisateur qui a déclenché l'événement                |                                                                                   | {{< no >}}           |
| `author_name`    | Nom lisible par l'humain de l'auteur qui a déclenché l'événement | Utile lorsque l'auteur n'existe plus                                          | {{< yes >}}          |
| `created_at`     | Horodatage du déclenchement de l'événement                         |                                                                                   | {{< no >}}           |
| `details`        | Objet JSON contenant des métadonnées supplémentaires                 | Ne possède pas de schéma défini, mais contient souvent des informations supplémentaires sur un événement    | {{< no >}}           |
| `entity_id`      | ID de l'entité de l'événement d'audit                             |                                                                                   | {{< no >}}           |
| `entity_path`    | Chemin complet de l'entité affectée par l'événement auditable    |                                                                                   | {{< yes >}}          |
| `entity_type`    | Représentation sous forme de chaîne du type d'entité                | Les valeurs acceptables incluent `User`, `Group` et `Key`. Cette liste n'est pas exhaustive | {{< no >}}           |
| `event_type`     | Représentation sous forme de chaîne du type d'événement d'audit           |                                                                                   | {{< yes >}}          |
| `id`             | Identifiant unique de l'événement d'audit                      | Peut être utilisé pour la déduplication si nécessaire                                         | {{< no >}}           |
| `ip_address`     | Adresse IP de l'hôte utilisé pour déclencher l'événement           |                                                                                   | {{< yes >}}          |
| `target_details` | Informations supplémentaires sur la cible                        |                                                                                   | {{< yes >}}          |
| `target_id`      | ID de la cible de l'événement d'audit                             |                                                                                   | {{< yes >}}          |
| `target_type`    | Représentation sous forme de chaîne du type de la cible                 |                                                                                   | {{< yes >}}          |

### Schéma JSON des événements d'audit {#audit-event-json-schema}

```json
{
  "properties": {
    "id": {
      "type": "string"
    },
    "author_id": {
      "type": "integer"
    },
    "author_name": {
      "type": "string"
    },
    "details": {},
    "ip_address": {
      "type": "string"
    },
    "entity_id": {
      "type": "integer"
    },
    "entity_path": {
      "type": "string"
    },
    "entity_type": {
      "type": "string"
    },
    "event_type": {
      "type": "string"
    },
    "target_id": {
      "type": "integer"
    },
    "target_type": {
      "type": "string"
    },
    "target_details": {
      "type": "string"
    },
  },
  "type": "object"
}
```

### Événements liés à GitLab Duo {#gitlab-duo-related-events}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/239648) dans GitLab 19.3.

{{< /history >}}

Lorsqu'un événement d'audit est lié à la plateforme GitLab Duo Agent, l'objet `details` inclut un champ `duo_related` défini sur `true`.

Les événements suivants peuvent inclure ce champ :

| Type d'événement                    | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| `application_setting_updated` | Un paramètre d'application lié à la plateforme GitLab Duo Agent est mis à jour. |
| `member_destroyed`            | L'appartenance d'un compte de service de la plateforme GitLab Duo Agent est supprimée.   |

Utilisez ce champ pour identifier l'activité de la plateforme GitLab Duo Agent dans votre outil de gestion des informations et des événements de sécurité (SIEM) ou d'autres outils externes, plutôt que des modèles de nommage de comptes de service.

### Événements créés avec une identité composite {#events-created-with-a-composite-identity}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/240418) dans GitLab 19.3.

{{< /history >}}

Lorsqu'un compte de service effectue une action au nom d'un utilisateur humain avec une [identité composite](../duo_agent_platform/composite_identity.md), l'événement d'audit est attribué au compte de service :

- `author_id` contient l'ID utilisateur du compte de service.
- `author_name` contient `<service account name> on behalf of @<human username>`, tronqué à 255 caractères. Cette valeur apparaît dans la colonne **Auteur** sur les pages d'événements d'audit et dans les exports CSV.

L'objet `details` enregistre l'utilisateur humain qui a autorisé l'action :

| Champ                   | Description                     |
|-------------------------|---------------------------------|
| `human_author_id`       | ID de l'utilisateur humain       |
| `human_author_name`     | Nom de l'utilisateur humain          |
| `human_author_username` | Nom d'utilisateur de l'utilisateur humain      |

Ces champs sont inclus dans les événements d'audit en streaming et dans l'objet `details` retourné par l'[API des événements d'audit](../../api/audit_events.md).

Pour ces événements, le champ `author_class` dans l'objet `details` contient `Gitlab::Audit::CompositeIdentityAuthor`. Utilisez cette valeur pour identifier les événements d'identité composite dans votre SIEM ou d'autres outils externes.

Les événements de session d'agent d'IA, tels que `ai_agent_session_started` et `ai_tool_invoked`, enregistrent également les champs `human_author_*` mais n'utilisent pas cette valeur `author_class`. Pour faire correspondre les deux types d'événements, filtrez plutôt sur la présence de `human_author_id`.

Lorsqu'un utilisateur humain effectue l'action et qu'un compte de service ne fait que participer à l'action, par exemple lorsque l'utilisateur humain désigne un compte de service comme relecteur d'une merge request, l'événement d'audit est attribué à l'utilisateur humain et les champs `human_author_*` ne sont pas ajoutés.

### En-têtes {#headers}

Les en-têtes sont formatés comme suit :

```plaintext
POST /logs HTTP/1.1
Host: <DESTINATION_HOST>
Content-Type: application/x-www-form-urlencoded
X-Gitlab-Event-Streaming-Token: <DESTINATION_TOKEN>
X-Gitlab-Audit-Event-Type: repository_git_operation
```

## Exemple : streaming d'événements d'audit sur les opérations Git {#example-audit-event-streaming-on-git-operations}

Des événements d'audit en streaming peuvent être envoyés lorsque des utilisateurs authentifiés effectuent un push, un pull ou un clone des dépôts Git distants d'un projet :

- [Via SSH](../ssh.md).
- Via HTTP ou HTTPS.
- Via **Téléchargement** ({{< icon name="download" >}}) dans l'interface GitLab.

Les événements d'audit ne sont pas capturés pour les utilisateurs qui ne sont pas connectés. Par exemple, lors du téléchargement d'un projet public.

### Exemple : charges utiles d'événements d'audit pour les événements Git via SSH avec une clé de déploiement {#example-audit-event-payloads-for-git-over-ssh-events-with-deploy-key}

{{< history >}}

- Les champs `gl_key_type` et `gl_key_id` dans `custom_message` ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/244603) dans GitLab 19.3.

{{< /history >}}

Récupération :

```json
{
  "id": "1",
  "author_id": -3,
  "entity_id": 29,
  "entity_type": "Project",
  "details": {
    "author_name": "deploy-key-name",
    "author_class": "DeployKey",
    "target_id": 29,
    "target_type": "Project",
    "target_details": "example-project",
    "custom_message": {
      "protocol": "ssh",
      "action": "git-upload-pack",
      "written_bytes": 1048576,
      "received_bytes": 2048,
      "gl_key_type": "deploy_key",
      "gl_key_id": 24
    },
    "ip_address": "127.0.0.1",
    "entity_path": "example-group/example-project"
  },
  "ip_address": "127.0.0.1",
  "author_name": "deploy-key-name",
  "entity_path": "example-group/example-project",
  "target_details": "example-project",
  "created_at": "2022-07-26T05:43:53.662Z",
  "target_type": "Project",
  "target_id": 29,
  "event_type": "repository_git_operation"
}
```

L'objet `custom_message` inclut des champs de taille de transfert de données pour les opérations Git :

- `written_bytes` : nombre d'octets envoyés au client lors de l'opération Git (par exemple, lors d'un clone, d'une récupération ou d'un pull).
- `received_bytes` : nombre d'octets reçus du client lors de l'opération Git (par exemple, lors d'un push).

Ces champs sont omis lorsqu'aucun octet n'est transféré, par exemple lorsqu'une requête échoue avant tout échange de données.

L'objet `custom_message` inclut des informations clés pour les opérations Git authentifiées avec une clé SSH ou une clé de déploiement :

- `gl_key_type` : Type de clé utilisée pour l'authentification. `key` pour les clés SSH utilisateur, ou `deploy_key` pour les clés de déploiement.
- `gl_key_id` : ID de la clé utilisée pour l'authentification.

Ces champs sont omis lorsque l'opération n'est pas authentifiée avec une clé, par exemple HTTP(S) avec un nom d'utilisateur et un mot de passe, ou un jeton de déploiement.
