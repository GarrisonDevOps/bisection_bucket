---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Résoudre les problèmes courants liés au serveur MCP GitLab.
title: Dépannage du serveur MCP GitLab
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Statut : Disponibilité générale

{{< /details >}}

Lorsque vous utilisez le serveur MCP GitLab, vous pouvez rencontrer les problèmes suivants.

## Erreur : `403 Forbidden` {#error-403-forbidden}

Vous pouvez obtenir cette erreur lorsque vous démarrez le serveur MCP GitLab. Vous pouvez également obtenir cette erreur lorsque `POST /api/v4/mcp` ou `GET /api/v4/mcp` renvoie `403 Forbidden` après la fin du flux OAuth.

Dans GitLab 19.4 et versions antérieures, le même problème renvoie `404 Not Found` à la place. Les deux codes de statut partagent les mêmes causes.

Pour résoudre ce problème, assurez-vous de remplir les [prérequis pour le serveur MCP GitLab](mcp_server.md#prerequisites).

Pour trouver la cause, lisez le message dans le corps de la réponse. Les administrateurs peuvent également vérifier le champ `denial_reason` dans le fichier [`mcp.log`](../../administration/logs/_index.md#mcplog) :

- `MCP server disabled for this instance` (`denial_reason` : `instance_setting_disabled`) : sur GitLab Self-Managed, un administrateur a [désactivé](../../administration/settings/visibility_and_access_controls.md#allow-access-to-the-mcp-server) le serveur MCP pour l'instance.
- `MCP server not enabled for any of your groups` (`denial_reason` : `no_enabled_namespace`) : sur GitLab.com, aucun groupe principal auquel vous appartenez n'a le serveur MCP [activé](../group/access_and_permissions.md#allow-access-to-the-mcp-server).

> [!note]
> Les erreurs `404` renvoyées par un appel d'outil basé sur REST, par exemple `404 Project Not Found`, apparaissent dans le corps de la réponse JSON-RPC avec `isError: true`, et dans `mcp.log` avec `tool_status` défini sur `not_found`. Les autres échecs d'appel d'outil apparaissent également dans le corps de la réponse avec `isError: true`, et dans `mcp.log` avec un `tool_status` qui décrit ce qui s'est passé.

## Erreur : `Server's protocol version is not supported: 2025-06-18` {#error-servers-protocol-version-is-not-supported-2025-06-18}

Dans GitLab 18.6 et versions antérieures, vous pouvez obtenir cette erreur lorsque la bibliothèque client MCP ne prend pas en charge la spécification du protocole du serveur MCP GitLab.

Pour résoudre ce problème, demandez au fournisseur de l'outil d'IA de mettre à jour son implémentation client.

## Erreur : `429 Too Many Requests` {#error-429-too-many-requests}

Votre client MCP peut cesser de fonctionner et signaler une erreur HTTP générique ou une erreur de connexion, et chaque requête échoue jusqu'à la réinitialisation de la période de limite de débit. Cela se produit lorsqu'une limite de débit est dépassée : soit la limite de débit du serveur MCP, soit la limite de débit de l'API authentifiée, car les requêtes du serveur MCP sont comptabilisées dans les deux. GitLab rejette la requête avant qu'elle n'atteigne le serveur MCP, de sorte qu'aucun outil ne s'exécute. Contrairement à un résultat d'outil [`rate_limited`](#error-rate_limited-tool-result), il ne s'agit pas d'un `200 OK` qui contient un résultat d'erreur.

La réponse est HTTP `429` avec le type de contenu `text/plain` et, par défaut, le corps `Retry later`. Il ne s'agit pas d'un message JSON-RPC, de sorte qu'un client MCP ne peut pas le lire comme une réponse MCP.

Pour confirmer la cause, vérifiez les en-têtes de réponse :

- `RateLimit-Name` identifie la limite atteinte. Sur GitLab Self-Managed, la limite de débit du serveur MCP est `throttle_authenticated_mcp`. Toute autre valeur correspond à une limite différente, telle que la limite générale de l'API authentifiée.
- `Retry-After` est le nombre de secondes à attendre avant de réessayer. Il s'agit du temps restant dans la période en cours, et non de la période complète. Les clients doivent le respecter plutôt que de réessayer immédiatement.

La réponse inclut également les autres [en-têtes de limite de débit](../../administration/settings/user_and_ip_rate_limits.md#response-headers).

Avant que la limite ne soit atteinte, les réponses `200 OK` réussies incluent déjà `RateLimit-Remaining`, de sorte qu'un client ou un proxy qui lit les en-têtes peut voir la limite approcher.

Les administrateurs peuvent également consulter les journaux :

- Une requête refusée apparaît dans le [journal Workhorse](../../administration/logs/_index.md#workhorse-logs) avec `status` `429` et `uri` `/api/v4/mcp`. L'entrée ne comporte ni utilisateur ni nom de limite.
- Une requête refusée n'apparaît pas dans `api_json.log` ni dans [`mcp.log`](../../administration/logs/_index.md#mcplog), car elle n'atteint jamais l'API. Elle n'apparaît pas non plus dans `auth.log`, contrairement à d'autres limites de débit GitLab.
- Les requêtes qui ont été comptabilisées mais autorisées apparaissent dans [`api_json.log`](../../administration/logs/_index.md#api_jsonlog) avec un champ `rate_limit_state` contenant `rack_request_mcp:authenticated_mcp:allow`. Utilisez cette information pour identifier les utilisateurs qui consomment la limite.

Pour résoudre ce problème, attendez le nombre de secondes indiqué dans `Retry-After`, puis réessayez.

- Sur GitLab.com, des limites par abonnement s'appliquent aux requêtes MCP. Pour les valeurs publiées, consultez les [limites de débit](mcp_server.md#rate-limits).
- Sur GitLab Self-Managed, la limite est désactivée par défaut. Si elle est activée, un administrateur peut [l'augmenter ou la désactiver](../../administration/settings/user_and_ip_rate_limits.md#enable-authenticated-mcp-server-request-rate-limit).

## Erreur : résultat d'outil `rate_limited` {#error-rate_limited-tool-result}

Si vous avez reçu une réponse HTTP `429 Too Many Requests` à la place, consultez [`429 Too Many Requests`](#error-429-too-many-requests).

Vous pouvez obtenir un résultat d'outil avec `isError: true`, même si le serveur MCP lui-même a renvoyé `200 OK`. Cela se produit lorsqu'un appel d'outil atteint une limite de débit sur le point de terminaison de l'API GitLab sous-jacent qu'il appelle, par exemple la limite de débit de recherche lorsqu'un outil de recherche s'exécute.

Le serveur MCP ne renvoie pas `429 Too Many Requests` dans ce cas. Il suit plutôt la spécification du protocole Model Context, qui classe les échecs d'API comme des erreurs d'exécution d'outil signalées dans le résultat afin qu'un client ou un modèle de langage puisse les lire et se corriger.

Le champ `content` contient un message lisible par une personne, par exemple :

```plaintext
Rate limited by search_rate_limit. Retry after 60 seconds.
```

Le champ `structuredContent` contient des détails de nouvelle tentative lisibles par une machine :

```json
{
  "error": {
    "type": "rate_limited",
    "retry_after_seconds": 60,
    "limit": "search_rate_limit",
    "message": "This endpoint has been requested too many times. Try again later."
  }
}
```

Pour résoudre ce problème, attendez et relancez l'appel d'outil. Lorsque vous créez un client MCP, vérifiez `error.type == "rate_limited"` plutôt que de faire correspondre le texte du message, car la formulation peut changer. Utilisez `limit` pour identifier quelle limite de débit a été atteinte, car un seul appel d'outil peut en consommer plusieurs. Traitez `retry_after_seconds` comme une borne supérieure sûre plutôt que comme un temps d'attente exact, car il s'agit de la période complète de limite de débit plutôt que du temps restant dans la fenêtre actuelle.

> [!note]
> `retry_after_seconds` et `limit` ne sont présents que lorsque le point de terminaison appelé par GitLab les a fournis. Gérez toujours une réponse dans laquelle ces champs sont absents. Les administrateurs peuvent modifier les limites de débit pour les points de terminaison individuels, de sorte que les valeurs réelles varient selon l'instance.

## Erreur : résultat d'outil `403 Forbidden` provenant de `start_duo_session` {#error-403-forbidden-tool-result-from-start_duo_session}

Vous pourriez obtenir une erreur indiquant `403 Forbidden` lorsque vous appelez l'outil `start_duo_session`. Le serveur MCP renvoie `200 OK`, et le résultat de l'outil contient `isError: true` avec le message suivant dans le champ `content` :

```plaintext
403 Forbidden
```

Ce problème se produit lorsque vous ne pouvez pas exécuter le flow dans le projet. `start_duo_session` démarre toujours le flow en tant que session qui s'exécute dans un job CI, et vous devez avoir l'autorisation d'exécuter ce flow dans le projet.

Pour résoudre ce problème, effectuez l'une des opérations suivantes :

- Si vous n'avez pas accès à GitLab Duo Agent Platform, remplissez les [prérequis pour GitLab Duo Agent Platform](../duo_agent_platform/_index.md#prerequisites).
- Si vous avez le rôle Reporter ou un rôle inférieur dans le projet, demandez à un propriétaire ou mainteneur du projet d'obtenir au moins le rôle Developer.
- Si les flows par défaut sont désactivés, demandez à un mainteneur ou propriétaire du projet, ou à un propriétaire du groupe principal, d'[activer les flows par défaut](../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off).
- Si le flow est en version bêta, demandez à un propriétaire du groupe principal d'[activer les fonctionnalités bêta et expérimentales](../duo_agent_platform/turn_on_off.md#turn-on-beta-and-experimental-features).

Si vous n'utilisez pas GitLab Duo Agent Platform, vous pouvez masquer ses outils dans votre client MCP. Si votre client prend en charge les en-têtes personnalisés, envoyez l'en-tête `X-Gitlab-Enabled-Mcp-Server-Toolsets` avec une liste qui n'inclut pas `duo_agent_platform`. Pour plus d'informations, consultez [sélectionner des groupes d'outils (toolsets)](mcp_server.md#select-tool-groups-toolsets).

## Dépanner le serveur MCP GitLab dans Cursor {#troubleshoot-the-gitlab-mcp-server-in-cursor}

1. Dans Cursor, pour ouvrir la vue Output, effectuez l'une des actions suivantes :
   - Accédez à **Afficher** > **Output**.
   - Sur macOS, appuyez sur <kbd>Command</kbd>+<kbd>Shift</kbd>+<kbd>U</kbd>.
   - Sur Windows ou Linux, appuyez sur <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>U</kbd>.
1. Dans la vue Output, sélectionnez **MCP:SERVERNAME**. Le nom dépend de la valeur de configuration MCP. L'exemple avec `GitLab` donne `MCP: user-GitLab`.
1. Lors du signalement de bugs, copiez la sortie dans la section des journaux du modèle de ticket.

## Dépanner le serveur MCP GitLab sur l'interface de ligne de commande avec mcp-remote {#troubleshoot-the-gitlab-mcp-server-on-the-cli-with-mcp-remote}

1. Installez [Node.js](https://nodejs.org/en/download) version 20 ou ultérieure.
1. Pour tester exactement la même commande que les IDE et les clients de bureau :
   1. Extrayez la configuration MCP.
   1. Assemblez la chaîne de commande `npx` en une seule ligne.
   1. Exécutez la chaîne de commande.

   ```shell
   rm -rf ~/.mcp-auth/mcp-remote*

   npx -y mcp-remote@latest https://gitlab.example.com/api/v4/mcp --static-oauth-client-metadata '{"scope": "mcp"}'
   ```

1. Ajoutez le paramètre `--debug` pour enregistrer une sortie plus détaillée :

   ```shell
   rm -rf ~/.mcp-auth/mcp-remote*

   npx -y mcp-remote@latest https://gitlab.example.com/api/v4/mcp --static-oauth-client-metadata '{"scope": "mcp"}' --debug
   ```

1. Facultatif. Exécutez directement l'exécutable `mcp-remote-client`.

   ```shell
   rm -rf ~/.mcp-auth/mcp-remote*

   npx -p mcp-remote@latest mcp-remote-client https://gitlab.example.com/api/v4/mcp --static-oauth-client-metadata '{"scope": "mcp"}'
   ```

1. Facultatif. Si vous rencontrez des bugs spécifiques à une version, épinglez la version du module `mcp-remote` à une version spécifique. Par exemple, utilisez `mcp-remote@0.1.26` pour épingler la version à `0.1.26`.

   > [!note]
   > Pour des raisons de sécurité, évitez d'épingler les versions si possible.

## Dépanner le serveur MCP GitLab avec Claude Desktop {#troubleshoot-gitlab-mcp-server-with-claude-desktop}

Vérifiez les versions de [Node.js](https://nodejs.org/en/download) installées. Claude Desktop nécessite Node.js version 20 ou ultérieure.

```shell
for n in $(which -a node); do echo "$n" && $n -v; done
```

## Supprimer les caches d'authentification MCP {#delete-mcp-authentication-caches}

L'authentification MCP est fortement mise en cache localement. Lors du dépannage, vous pouvez rencontrer des faux positifs. Pour les éviter, supprimez le répertoire de cache pendant le dépannage :

```shell
rm -rf ~/.mcp-auth/mcp-remote*
```

## Outils de débogage et de développement {#debugging-and-development-tools}

[MCP Inspector](https://modelcontextprotocol.io/legacy/tools/inspector) est un outil de développement interactif pour tester et déboguer les serveurs MCP. Pour exécuter cet outil, utilisez l'interface de ligne de commande et accédez à l'interface web pour inspecter le serveur MCP GitLab.

```shell
npx -y @modelcontextprotocol/inspector npx
```
