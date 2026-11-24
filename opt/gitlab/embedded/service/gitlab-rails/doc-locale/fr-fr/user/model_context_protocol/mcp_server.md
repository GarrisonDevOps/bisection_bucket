---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Connecter des outils d'IA à votre instance GitLab à l'aide du serveur MCP GitLab."
title: Serveur MCP GitLab
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Statut : Disponibilité générale

{{< /details >}}

{{< history >}}

- Introduction en [version expérimentale](../../policy/development_stages_support.md#experiment) dans GitLab 18.3 [avec les feature flags](../../administration/feature_flags/_index.md) `mcp_server` et `oauth_dynamic_client_registration`. Fonctionnalité désactivée par défaut.
- Passage de la version expérimentale à la [version bêta](../../policy/development_stages_support.md#beta) dans GitLab 18.6. Suppression des feature flags [`mcp_server`](https://gitlab.com/gitlab-org/gitlab/-/issues/556448) et [`oauth_dynamic_client_registration`](https://gitlab.com/gitlab-org/gitlab/-/issues/555942).
- [Ajout](https://gitlab.com/gitlab-org/gitlab/-/issues/581459) de la prise en charge des spécifications `2025-03-26` et `2025-06-18` du protocole MCP dans GitLab 18.7.
- Prise en charge de la spécification de protocole MCP `2025-11-25` [ajoutée](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/216219) dans GitLab 18.7.
- [Passage](https://gitlab.com/gitlab-org/gitlab/-/work_items/590729) à un paramètre distinct et [transfert](https://gitlab.com/groups/gitlab-org/-/work_items/21183) de GitLab Premium vers l'édition Gratuite dans GitLab 19.2.
- Sélection de toolset [ajoutée](https://gitlab.com/gitlab-org/gitlab/-/work_items/607755) dans GitLab 19.5.
- Le toolset `duo_agent_platform` est [inclus par défaut](https://gitlab.com/gitlab-org/gitlab/-/work_items/630992) dans GitLab 19.5.
- Passée de [version bêta](../../policy/development_stages_support.md#beta) à [disponibilité générale](../../policy/development_stages_support.md#generally-available) dans GitLab 19.5.
- Le toolset `duo_agent_platform` est [répertorié uniquement](https://gitlab.com/gitlab-org/gitlab/-/work_items/631747) lorsque GitLab Duo Agent Platform est disponible pour l'utilisateur dans GitLab 19.5.
- Les outils `code_security` sont [répertoriés uniquement](https://gitlab.com/gitlab-org/gitlab/-/work_items/629267) lorsque la fonctionnalité sous licence derrière chaque outil est disponible pour l'utilisateur dans GitLab 19.5.
- Le toolset `orbit` a été [ajouté](https://gitlab.com/gitlab-org/orbit/knowledge-graph/-/work_items/1294) dans GitLab 19.6.

{{< /history >}}

> [!warning]
> Pour fournir des commentaires sur cette fonctionnalité, laissez un commentaire sur [l'issue 630189](https://gitlab.com/gitlab-org/gitlab/-/issues/630189).

Vous pouvez connecter en toute sécurité des outils et des applications d'IA à votre instance GitLab à l'aide du serveur [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) de GitLab. Les assistants d'IA comme Claude Desktop, Claude Code et Cursor, ainsi que les autres outils compatibles avec MCP, peuvent alors accéder à vos données GitLab et effectuer des actions en votre nom.

Le serveur MCP GitLab permet aux outils d'IA d'effectuer les actions suivantes de manière standardisée :

- Accéder aux informations sur les projets GitLab.
- Récupérer les données des tickets et des merge request.
- Interagir en toute sécurité avec les API GitLab.
- Effectuer des opérations propres à GitLab à l'aide d'assistants d'IA.

Le serveur MCP GitLab prend en charge [l'enregistrement dynamique de clients OAuth 2.0](https://tools.ietf.org/html/rfc7591) et permet ainsi aux outils d'IA de s'enregistrer auprès de votre instance GitLab. Lorsqu'un outil d'IA se connecte pour la première fois à votre serveur MCP GitLab, il effectue les opérations suivantes :

1. Il s'enregistre lui-même comme application OAuth.
1. Il demande l'autorisation d'accéder à vos données GitLab.
1. Il reçoit un jeton d'accès pour accéder à l'API en toute sécurité.

Pour une démonstration interactive, consultez [GitLab Duo Agent Platform - GitLab MCP server](https://gitlab.navattic.com/gitlab-mcp-server).
<!-- Demo published on 2025-09-11 -->

## Prérequis {#prerequisites}

- Autorisez l'accès au serveur MCP :
  - Sur GitLab.com, [pour le groupe principal](../group/access_and_permissions.md#allow-access-to-the-mcp-server).
  - Sur GitLab Self-Managed et GitLab Dedicated, [pour l'instance](../../administration/settings/visibility_and_access_controls.md#allow-access-to-the-mcp-server).

## Authentification {#authentication}

Le serveur MCP GitLab accepte les jetons suivants :

- Un jeton d'accès OAuth avec la portée `mcp`. Les clients MCP obtiennent ce jeton via le flux OAuth lors de la connexion, soit avec l'enregistrement dynamique de client, soit avec une [application OAuth pré-enregistrée](#reuse-a-single-oauth-application).
- Un [jeton d'accès personnel à granularité fine](../../auth/tokens/fine_grained_access_tokens.md) avec la [ressource d'outil MCP et l'autorisation Execute](../../auth/tokens/fine_grained_access_tokens_rest.md#mcp-tool).

Ces jetons ne peuvent pas avoir la portée `mcp`, de sorte que le serveur MCP GitLab les rejette, même avec des portées telles que `api` :

- Jetons d'accès personnels hérités
- Jetons d'accès au projet
- Jetons d'accès de groupe

Si vous utilisez l'un de ces jetons, le serveur MCP GitLab renvoie `403 Forbidden` avec l'erreur `insufficient_scope`. La réponse mentionne la portée `mcp`, que vous ne pouvez pas ajouter à ces jetons. La prise en charge de ces méthodes d'authentification est proposée dans le [ticket 586184](https://gitlab.com/gitlab-org/gitlab/-/work_items/586184).

## Connecter un client au serveur MCP GitLab {#connect-a-client-to-the-gitlab-mcp-server}

Le serveur MCP GitLab prend en charge deux types de transport :

- **Transport HTTP (recommandé)** : connexion directe sans dépendances supplémentaires.
- **Transport stdio avec `mcp-remote`** : connexion via un proxy (nécessite Node.js).

Les outils d'IA courants prennent en charge le format de configuration JSON pour la clé `mcpServers` et proposent différentes méthodes pour configurer les paramètres du serveur MCP GitLab.

Pour limiter les outils renvoyés par le serveur, consultez [Sélectionner des groupes d'outils (toolsets)](#select-tool-groups-toolsets).

### Transport HTTP (recommandé) {#http-transport-recommended}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/577575) dans GitLab 18.6.
- [Ajout](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/230406) du préfixage des outils dans GitLab 18.11.

{{< /history >}}

Pour configurer le serveur MCP GitLab avec le transport HTTP, utilisez le format suivant :

- Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
  - Sur GitLab Self-Managed, l'URL de votre instance GitLab.
  - Sur GitLab.com, `gitlab.com`.

```json
{
  "mcpServers": {
    "GitLab": {
      "type": "http",
      "url": "https://<gitlab.example.com>/api/v4/mcp"
    }
  }
}
```

Vous pouvez ajouter un préfixe aux noms des outils en définissant l'en-tête HTTP `X-Gitlab-Mcp-Server-Tool-Name-Prefix`. Le préfixage peut vous aider à éviter les conflits entre les noms d'outils lorsque votre configuration comprend d'autres serveurs MCP ou plusieurs instances GitLab.

Le préfixe est tronqué aux 32 premiers caractères s'il dépasse cette limite.

```json
{
  "mcpServers": {
    "GitLab": {
      "type": "http",
      "url": "https://<gitlab.example.com>/api/v4/mcp",
      "headers": {
        "X-Gitlab-Mcp-Server-Tool-Name-Prefix": "gitlab_"
      }
    }
  }
}
```

### Sélectionner des groupes d'outils (toolsets) {#select-tool-groups-toolsets}

Pour limiter les outils renvoyés par le serveur MCP GitLab à des groupes spécifiques, configurez l'en-tête HTTP `X-Gitlab-Enabled-Mcp-Server-Toolsets` avec une liste de noms de toolsets séparés par des virgules.

Toolsets disponibles :

| Toolset | Inclus par défaut |
|---------|----------------------|
| `meta` | Toujours |
| `core` | Oui |
| `merge_requests` | Oui |
| `work_items` | Oui |
| `repository` | Oui |
| `ci` | Oui |
| `duo_agent_platform` | Oui, si GitLab Duo Agent Platform est disponible |
| `wikis` | Non (opt-in) |
| `code_security` | Non (opt-in) |
| `orbit` | Non (opt-in) |

Les outils `duo_agent_platform` ne sont répertoriés que lorsque GitLab Duo Agent Platform est disponible pour vous. Cela s'applique même lorsque vous demandez le toolset dans l'en-tête ou que vous définissez l'en-tête sur `all`.

Sur GitLab.com, les deux conditions suivantes doivent être remplies :

- Vous appartenez à un groupe principal avec le plan Premium ou GitLab Ultimate dont GitLab Duo Agent Platform est activé, ou vous disposez de GitLab Duo Agent Platform via GitLab Credits.
- Vous êtes autorisé à utiliser GitLab Duo Agent Platform, par exemple, vous disposez du siège requis.

Sur GitLab Self-Managed et GitLab Dedicated, toutes les conditions suivantes doivent être remplies :

- GitLab Duo n'est pas défini sur **Toujours désactivée** pour l'instance. Avec **Désactivé(e) par défaut**, les outils sont répertoriés afin que les groupes qui activent GitLab Duo puissent les utiliser.
- L'instance dispose d'une licence incluant GitLab Duo Agent Platform ou de GitLab Credits.
- GitLab Duo Agent Platform est activé pour votre organisation.
- Vous êtes autorisé à utiliser GitLab Duo Agent Platform, par exemple, vous disposez du siège requis.

Pour plus d'informations, consultez les [prérequis de GitLab Duo Agent Platform](../duo_agent_platform/_index.md#prerequisites) et [comment activer ou désactiver GitLab Duo Agent Platform](../duo_agent_platform/turn_on_off.md).

Les outils `code_security` ne sont répertoriés que lorsque la fonctionnalité derrière chaque outil est disponible pour vous. Cela s'applique même lorsque vous demandez le toolset dans l'en-tête ou que vous définissez l'en-tête sur `all`.

- `list_vulnerabilities`, `get_vulnerability` et `save_vulnerability` nécessitent le tableau de bord de sécurité.
- `attach_scan_profile` nécessite des profils d'analyse de sécurité.

Ces deux outils sont des fonctionnalités GitLab Ultimate. Sur GitLab.com, les outils sont répertoriés si vous appartenez à au moins un groupe principal avec le plan GitLab Ultimate, y compris les essais GitLab Ultimate. L'accès à un projet dans ce groupe est également pris en compte. Sur GitLab Self-Managed et GitLab Dedicated, les outils sont répertoriés si la licence de l'instance inclut la fonctionnalité.

Le toolset `orbit` dispose d'un outil pour chaque commande Orbit, par exemple `query_graph`. Le serveur Orbit définit les noms des outils, les descriptions et les schémas d'entrée. Les outils ne sont répertoriés et exécutés que lorsque vous satisfaites aux [exigences d'Orbit](https://docs.gitlab.com/orbit/).

Les outils Orbit ne sont répertoriés que lorsque vous demandez le toolset `orbit` ou que vous définissez l'en-tête sur `all`. Nommer un outil Orbit dans `X-Gitlab-Enabled-Mcp-Server-Tools` ne le répertorie pas.

Répertorier un outil ne donne pas accès à cet outil. Chaque outil vérifie toujours les permissions de votre projet et de votre espace de nommage lorsqu'il est appelé.

Pour inclure un toolset en opt-in, ajoutez-le explicitement à la valeur de l'en-tête. Pour demander chaque toolset, y compris tous les toolsets en opt-in, définissez l'en-tête sur `all`.

Lorsque vous omettez les deux en-têtes, le serveur renvoie les toolsets par défaut. Si vous omettez l'en-tête des toolsets mais définissez `X-Gitlab-Enabled-Mcp-Server-Tools`, le serveur renvoie uniquement les outils que vous avez nommés, sans aucun toolset par défaut ni outil `meta`.

Les noms de toolsets dans l'en-tête `X-Gitlab-Enabled-Mcp-Server-Toolsets` sont mis en correspondance sans tenir compte de la casse, de sorte que `ci`, `CI` et `Ci` sont tous acceptés.

Un nom de toolset non reconnu dans l'en-tête renvoie une erreur `400`.

Si vous définissez également `X-Gitlab-Enabled-Mcp-Server-Tools`, le serveur renvoie l'union des deux listes, et non l'intersection. Définir les deux en-têtes ne renvoie jamais moins d'outils que l'un ou l'autre en-tête seul.

```json
{
  "mcpServers": {
    "GitLab": {
      "type": "http",
      "url": "https://<gitlab.example.com>/api/v4/mcp",
      "headers": {
        "X-Gitlab-Enabled-Mcp-Server-Toolsets": "core,work_items"
      }
    }
  }
}
```

La façon dont vous définissez cet en-tête dépend de la configuration de votre client. Consultez la section de votre client sur cette page pour connaître son format de configuration.

- Les clients configurés avec un objet JSON qui accepte une clé `headers`, notamment Cursor et Kiro : utilisez l'exemple précédent.
- opencode utilise une clé `mcp` de premier niveau et `"type": "remote"`, donc ajoutez une clé `headers` à la définition du serveur dans [Connecter opencode au serveur MCP GitLab](#connect-opencode-to-the-gitlab-mcp-server).
- Claude Code, qui est configuré depuis la ligne de commande : passez `--header`.

  ```shell
  claude mcp add -s user --transport http GitLab https://<gitlab.example.com>/api/v4/mcp \
    --header "X-Gitlab-Enabled-Mcp-Server-Toolsets: core,work_items"
  ```

- Les clients qui se connectent via `mcp-remote`, notamment Claude Desktop et Zed : passez `--header` en argument.

  ```json
  {
    "mcpServers": {
      "GitLab": {
        "command": "npx",
        "args": [
          "-y", "mcp-remote", "https://<gitlab.example.com>/api/v4/mcp",
          "--header", "X-Gitlab-Enabled-Mcp-Server-Toolsets: core,work_items"
        ]
      }
    }
  }
  ```

  Sous Windows, les espaces dans `args` ne sont pas échappés lorsque `npx` est invoqué, ce qui corrompt la valeur de l'en-tête. Placez la valeur dans une variable d'environnement et omettez l'espace après les deux-points :

  ```json
  {
    "mcpServers": {
      "GitLab": {
        "command": "npx",
        "args": [
          "-y", "mcp-remote", "https://<gitlab.example.com>/api/v4/mcp",
          "--header", "X-Gitlab-Enabled-Mcp-Server-Toolsets:${GITLAB_TOOLSETS}"
        ],
        "env": {
          "GITLAB_TOOLSETS": "core,work_items"
        }
      }
    }
  }
  ```

D'autres clients, notamment Gemini Code Assist et Gemini CLI, GitHub Copilot dans VS Code et OpenAI Codex, utilisent leurs propres formats de configuration. Consultez la documentation de votre client pour savoir comment envoyer un en-tête HTTP personnalisé.

### Transport stdio avec `mcp-remote` {#stdio-transport-with-mcp-remote}

Prérequis :

- Installez la version 20 ou une version ultérieure de Node.js.

Pour configurer le serveur MCP GitLab avec le transport stdio, utilisez le format suivant :

- Si `npx` est installé localement plutôt que globalement, renseignez le chemin complet de `npx` dans le paramètre `"command":`.
- Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
  - pour GitLab Self-Managed, l'URL de votre instance GitLab ;
  - pour GitLab.com, `gitlab.com`.

```json
{
  "mcpServers": {
    "GitLab": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://<gitlab.example.com>/api/v4/mcp"
      ]
    }
  }
}
```

## Connecter Cursor au serveur MCP GitLab {#connect-cursor-to-the-gitlab-mcp-server}

Cursor utilise le transport HTTP pour se connecter directement sans dépendances supplémentaires. Pour configurer le serveur MCP GitLab dans Cursor :

1. Dans Cursor, accédez à **Settings** > **Cursor Settings** > **Tools & MCP**.
1. Sous **Installed MCP Servers**, sélectionnez **New MCP Server**.
1. Ajoutez cette définition sous la clé `mcpServers` du fichier `mcp.json` ouvert :
   - Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
     - pour GitLab Self-Managed, l'URL de votre instance GitLab ;
     - pour GitLab.com, `gitlab.com`.

   ```json
   {
     "mcpServers": {
       "GitLab": {
          "type": "http",
          "url": "https://<gitlab.example.com>/api/v4/mcp"
       }
     }
   }
   ```

1. Enregistrez le fichier et attendez que votre navigateur ouvre la page d'autorisation OAuth.

   Si cela ne se produit pas, fermez et redémarrez Cursor.
1. Dans votre navigateur, examinez et approuvez la demande d'autorisation.

Vous pouvez maintenant démarrer une nouvelle conversation et poser une question adaptée aux [outils disponibles](mcp_server_tools.md).

> [!warning]
> Vous devez vous prémunir contre les injections de prompt lorsque vous utilisez ces outils. Faites preuve de la plus grande prudence ou n'utilisez les outils MCP que sur des objets GitLab auxquels vous faites confiance.

## Connecter Amazon Q Developer au serveur MCP GitLab {#connect-amazon-q-developer-to-the-gitlab-mcp-server}

Amazon Q Developer utilise le transport stdio via le proxy `mcp-remote`. Vous configurez le serveur dans un formulaire plutôt que dans un fichier JSON.

Prérequis :

- Installez la version 20 ou une version ultérieure de Node.js.

Pour configurer le serveur MCP GitLab dans Amazon Q Developer :

1. Dans le panneau Amazon Q, accédez aux paramètres du serveur MCP et ajoutez un serveur.
1. Remplissez le formulaire :
   - Pour **Portée**, sélectionnez **Globales** pour utiliser le serveur partout, ou **This workspace** pour le limiter à un workspace.
   - Pour **Nom**, saisissez `gitlab`.
   - Pour **Transport**, sélectionnez `stdio`.
   - Pour **Command**, saisissez `npx`. Si `npx` est installé localement plutôt que globalement, indiquez le chemin complet vers `npx`.
   - Pour **Arguments**, ajoutez trois arguments distincts : `-y`, `mcp-remote` et `https://<gitlab.example.com>/api/v4/mcp`. Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
     - pour GitLab Self-Managed, l'URL de votre instance GitLab ;
     - pour GitLab.com, `gitlab.com`.
   - Pour **Délai d'attente**, saisissez `60`.
1. Enregistrez la configuration.
1. Dans votre navigateur, examinez et approuvez la demande d'autorisation.

N'épinglez pas `mcp-remote` à une version spécifique. L'épinglage était une solution de contournement pour la façon dont la portée OAuth était demandée, et le serveur définit désormais cette portée par défaut lors de l'enregistrement dynamique du client. Un proxy épinglé rate également les correctifs en amont.

Vous pouvez maintenant démarrer une nouvelle conversation et poser une question adaptée aux [outils disponibles](mcp_server_tools.md).

> [!warning]
> Vous devez vous prémunir contre les injections de prompt lorsque vous utilisez ces outils. Faites preuve de la plus grande prudence ou n'utilisez les outils MCP que sur des objets GitLab auxquels vous faites confiance.

## Connecter Claude Code au serveur MCP GitLab {#connect-claude-code-to-the-gitlab-mcp-server}

Claude Code utilise le transport HTTP pour se connecter directement sans dépendances supplémentaires. Pour configurer le serveur MCP GitLab dans Claude Code :

1. Dans votre terminal, ajoutez le serveur MCP GitLab à l'aide de la CLI :
   - Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
     - pour GitLab Self-Managed, l'URL de votre instance GitLab ;
     - pour GitLab.com, `gitlab.com`.

   ```shell
   claude mcp add -s user --transport http GitLab https://<gitlab.example.com>/api/v4/mcp
   ```

   La portée `-s user` rend le serveur disponible dans chaque projet. Sans cela, le serveur est ajouté à la portée `local` et n'est disponible que dans le répertoire où vous avez exécuté la commande.

   Si vous avez déjà configuré un serveur MCP GitLab, `claude mcp add` ne l'écrase pas. Listez vos serveurs existants et vérifiez quelle portée utilise l'entrée GitLab :

   ```shell
   claude mcp list
   ```

   Supprimez l'entrée existante à cette portée, puis ajoutez-la à nouveau. Les entrées ajoutées en suivant les versions précédentes de ces instructions sont à la portée `local`, car aucun flag `-s` n'a été fourni, et une entrée `local` a la priorité sur une entrée `user` portant le même nom.

   ```shell
   claude mcp remove GitLab -s local
   ```

1. Démarrez Claude Code :

   ```shell
   claude
   ```

1. Authentifiez-vous auprès du serveur MCP GitLab :
   - Dans le chat, saisissez `/mcp`.
   - Dans la liste, sélectionnez votre serveur GitLab.
   - Dans votre navigateur, examinez et approuvez la demande d'autorisation.

1. Facultatif. Pour vérifier la connexion, saisissez à nouveau `/mcp`. Votre serveur GitLab devrait apparaître comme connecté.

Vous pouvez maintenant démarrer une nouvelle conversation et poser une question adaptée aux [outils disponibles](mcp_server_tools.md).

> [!warning]
> Vous devez vous prémunir contre les injections de prompt lorsque vous utilisez ces outils. Faites preuve de la plus grande prudence ou n'utilisez les outils MCP que sur des objets GitLab auxquels vous faites confiance.

## Connecter Claude Desktop au serveur MCP GitLab {#connect-claude-desktop-to-the-gitlab-mcp-server}

Prérequis :

- Installez la version 20 ou une version ultérieure de Node.js.
- Assurez-vous que Node.js est accessible globalement au moyen de la variable d'environnement `PATH` (`which -a node`).

Pour configurer le serveur MCP GitLab dans Claude Desktop :

1. Ouvrez Claude Desktop.
1. Modifiez le fichier de configuration. Vous pouvez procéder de l'une des manières suivantes :
   - Dans Claude Desktop, accédez à **Paramètres** > **Développeur** > **Modifier la configuration**.
   - Sous macOS, ouvrez le fichier `~/Library/Application Support/Claude/claude_desktop_config.json`.
1. Ajoutez cette entrée pour le serveur MCP GitLab et modifiez-la si nécessaire :
   - Si `npx` est installé localement plutôt que globalement, renseignez le chemin complet de `npx` dans le paramètre `"command":`.
   - Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
     - pour GitLab Self-Managed, l'URL de votre instance GitLab ;
     - Sur GitLab.com, `GitLab.com`.

   ```json
   {
     "mcpServers": {
       "GitLab": {
         "command": "npx",
         "args": [
           "-y",
           "mcp-remote",
           "https://<gitlab.example.com>/api/v4/mcp"
         ]
       }
     }
   }
   ```

1. Enregistrez la configuration et redémarrez Claude Desktop.
1. Lors de la première connexion, Claude Desktop ouvre une fenêtre de navigateur pour OAuth. Examinez et approuvez la demande.
1. Accédez à **Paramètres** > **Développeur** et vérifiez la nouvelle configuration MCP GitLab.
1. Accédez à **Paramètres** > **Connecteurs** et inspectez le serveur MCP GitLab connecté.

Vous pouvez maintenant démarrer une nouvelle conversation et poser une question adaptée aux [outils disponibles](mcp_server_tools.md).

> [!warning]
> Vous devez vous prémunir contre les injections de prompt lorsque vous utilisez ces outils. Faites preuve de la plus grande prudence ou n'utilisez les outils MCP que sur des objets GitLab auxquels vous faites confiance.

## Connecter Gemini Code Assist et Gemini CLI au serveur MCP GitLab {#connect-gemini-code-assist-and-gemini-cli-to-the-gitlab-mcp-server}

Gemini Code Assist et Gemini CLI utilisent le transport HTTP pour se connecter directement sans dépendances supplémentaires. Pour configurer le serveur MCP GitLab dans Gemini Code Assist ou Gemini CLI :

1. Modifiez `~/.gemini/settings.json` et ajoutez le serveur MCP GitLab.
   - Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
     - pour GitLab Self-Managed, l'URL de votre instance GitLab ;
     - pour GitLab.com, `gitlab.com`.

   ```json
   {
     "mcpServers": {
       "GitLab": {
         "httpUrl": "https://<gitlab.example.com>/api/v4/mcp"
       }
     }
   }
   ```

1. Dans Gemini Code Assist ou Gemini CLI, exécutez la commande `/mcp auth GitLab`.

   La page d'autorisation OAuth devrait s'afficher. Sinon, redémarrez Gemini Code Assist ou Gemini CLI.

1. Dans votre navigateur, examinez et approuvez la demande d'autorisation.

Vous pouvez maintenant démarrer une nouvelle conversation et poser une question adaptée aux [outils disponibles](mcp_server_tools.md).

> [!warning]
> Vous devez vous prémunir contre les injections de prompt lorsque vous utilisez ces outils. Faites preuve de la plus grande prudence ou n'utilisez les outils MCP que sur des objets GitLab auxquels vous faites confiance.

## Connecter GitHub Copilot dans VS Code au serveur MCP GitLab {#connect-github-copilot-in-vs-code-to-the-gitlab-mcp-server}

GitHub Copilot utilise le transport HTTP pour se connecter directement sans dépendances supplémentaires. Pour configurer le serveur MCP GitLab dans GitHub Copilot pour VS Code :

1. Dans VS Code, ouvrez la palette de commandes :
   - Sous macOS, appuyez sur <kbd>Commande</kbd>+<kbd>Maj</kbd>+<kbd>P</kbd>.
   - Sous Windows ou Linux, appuyez sur <kbd>Ctrl</kbd>+<kbd>Maj</kbd>+<kbd>P</kbd>.
1. Saisissez `MCP: Add Server` et appuyez sur <kbd>Entrée</kbd>.
1. Sélectionnez **HTTP** comme type de serveur.
1. Saisissez `https://<gitlab.example.com>/api/v4/mcp` comme URL du serveur.
   - Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
     - pour GitLab Self-Managed, l'URL de votre instance GitLab ;
     - pour GitLab.com, `gitlab.com`.
1. Saisissez `GitLab` comme ID du serveur.
1. Enregistrez la configuration globalement ou dans le workspace `vscode/mcp.json`.

   La page d'autorisation OAuth devrait s'afficher. Sinon, ouvrez la palette de commandes et recherchez **MCP : List Servers** pour vérifier le statut du serveur ou le redémarrer.

1. Dans votre navigateur, examinez et approuvez la demande d'autorisation.

Vous pouvez maintenant démarrer une nouvelle conversation et poser une question adaptée aux [outils disponibles](mcp_server_tools.md).

> [!warning]
> Vous devez vous prémunir contre les injections de prompt lorsque vous utilisez ces outils. Faites preuve de la plus grande prudence ou n'utilisez les outils MCP que sur des objets GitLab auxquels vous faites confiance.

## Connecter Kiro IDE et Kiro CLI au serveur MCP GitLab {#connect-kiro-ide-and-cli-to-the-gitlab-mcp-server}

Kiro IDE et Kiro CLI utilisent le transport HTTP pour se connecter directement sans dépendances supplémentaires. Pour configurer le serveur MCP GitLab dans Kiro IDE ou Kiro CLI :

1. Modifiez `~/.kiro/settings/mcp.json` et ajoutez-y le serveur MCP GitLab.
   - Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
     - pour GitLab Self-Managed, l'URL de votre instance GitLab ;
     - pour GitLab.com, `gitlab.com`.

   ```json
   {
     "mcpServers": {
       "GitLab": {
         "type": "http",
         "url": "https://<gitlab.example.com>/api/v4/mcp"
       }
     }
   }
   ```

1. Enregistrez la configuration.

   La page d'autorisation OAuth devrait s'afficher. Sinon, lancez Kiro CLI et exécutez la commande `/mcp`.

1. Dans votre navigateur, examinez et approuvez la demande d'autorisation.

Vous pouvez maintenant démarrer une nouvelle conversation et poser une question adaptée aux [outils disponibles](mcp_server_tools.md).

> [!warning]
> Vous devez vous prémunir contre les injections de prompt lorsque vous utilisez ces outils. Faites preuve de la plus grande prudence ou n'utilisez les outils MCP que sur des objets GitLab auxquels vous faites confiance.

## Connecter OpenCode au serveur MCP GitLab {#connect-opencode-to-the-gitlab-mcp-server}

OpenCode utilise le transport HTTP pour une connexion directe sans dépendances supplémentaires. Pour configurer le serveur MCP GitLab dans OpenCode :

1. Ajoutez cette définition à la clé `mcp` dans votre fichier `~/.config/opencode/opencode.json` :
   - Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
     - pour GitLab Self-Managed, l'URL de votre instance GitLab ;
     - pour GitLab.com, `gitlab.com`.

   ```json
   {
     "mcp": {
       "gitlab-mcp": {
         "type": "remote",
         "url": "https://<gitlab.example.com>/api/v4/mcp",
         "enabled": true
       }
     }
   }
   ```

1. Enregistrez le fichier.
1. Authentifiez-vous auprès du serveur MCP GitLab :

   ```shell
   opencode mcp auth gitlab-mcp
   ```

1. Dans votre navigateur, examinez et approuvez la demande d'autorisation.

Vous pouvez maintenant démarrer une nouvelle conversation et poser une question adaptée aux [outils disponibles](mcp_server_tools.md).

> [!warning]
> Vous devez vous prémunir contre les injections de prompt lorsque vous utilisez ces outils. Faites preuve de la plus grande prudence ou n'utilisez les outils MCP que sur des objets GitLab auxquels vous faites confiance.

## Connecter OpenAI Codex au serveur MCP GitLab {#connect-openai-codex-to-the-gitlab-mcp-server}

OpenAI Codex utilise le transport HTTP pour se connecter directement sans dépendances supplémentaires. Pour configurer le serveur MCP GitLab dans OpenAI Codex :

1. Dans votre terminal, ajoutez le serveur MCP GitLab à l'aide de la CLI :
   - Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
     - pour GitLab Self-Managed, l'URL de votre instance GitLab ;
     - pour GitLab.com, `gitlab.com`.

   ```shell
   codex mcp add GitLab --url "https://<gitlab.example.com>/api/v4/mcp"
   ```

1. Modifiez `~/.codex/config.toml` et activez le feature flag `rmcp_client` dans la section `[features]`.

   ```toml
   [features]
   "rmcp_client" = true

   [mcp_servers.GitLab]
   url = "https://<gitlab.example.com>/api/v4/mcp"
   ```

1. Suivez le processus de connexion et authentifiez-vous auprès de l'instance GitLab.

   ```shell
   codex mcp login GitLab
   ```

1. Dans votre navigateur, examinez et approuvez la demande d'autorisation.

Vous pouvez maintenant démarrer une nouvelle conversation et poser une question adaptée aux [outils disponibles](mcp_server_tools.md).

> [!warning]
> Vous devez vous prémunir contre les injections de prompt lorsque vous utilisez ces outils. Faites preuve de la plus grande prudence ou n'utilisez les outils MCP que sur des objets GitLab auxquels vous faites confiance.

## Connecter Zed au serveur MCP GitLab {#connect-zed-to-the-gitlab-mcp-server}

Prérequis :

- Installez la version 20 ou une version ultérieure de Node.js.
- Assurez-vous que Node.js est accessible globalement au moyen de la variable d'environnement `PATH` (`which -a node`).

Pour configurer le serveur MCP GitLab dans Zed :

1. Dans Zed, ouvrez la palette de commandes :
   - Sous macOS, appuyez sur <kbd>Commande</kbd>+<kbd>Maj</kbd>+<kbd>P</kbd>.
   - Sous Windows ou Linux, appuyez sur <kbd>Ctrl</kbd>+<kbd>Maj</kbd>+<kbd>P</kbd>.
1. Saisissez `agent: open settings` et appuyez sur <kbd>Entrée</kbd>.
1. Dans la section **Model Context Protocol (MCP) Servers**, sélectionnez **Add Server**.
1. Dans `args`, utilisez `https://<gitlab.example.com>/api/v4/mcp` comme URL du serveur.
   - Remplacez `<gitlab.example.com>` par l'une des valeurs suivantes :
     - pour GitLab Self-Managed, l'URL de votre instance GitLab ;
     - pour GitLab.com, `gitlab.com`.

   ```json
   {
     /// The name of your MCP server
     "GitLab": {
       /// The command which runs the MCP server
       "command": "npx",
       /// The arguments to pass to the MCP server
       "args": ["-y","mcp-remote@latest","https://<gitlab.example.com>/api/v4/mcp"],
       /// The environment variables to set
       "env": {}
     }
   }
   ```

1. Enregistrez la configuration.

   La page d'autorisation OAuth devrait s'afficher. Sinon, désactivez puis réactivez le commutateur **GitLab**.

1. Dans votre navigateur, examinez et approuvez la demande d'autorisation.

Vous pouvez maintenant démarrer une nouvelle conversation et poser une question adaptée aux [outils disponibles](mcp_server_tools.md).

> [!warning]
> Vous devez vous prémunir contre les injections de prompt lorsque vous utilisez ces outils. Faites preuve de la plus grande prudence ou n'utilisez les outils MCP que sur des objets GitLab auxquels vous faites confiance.

## Réutiliser une seule application OAuth {#reuse-a-single-oauth-application}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245979) de la création d'applications OAuth à partir de l'interface d'administration dans GitLab 19.3.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/247698) de la création d'applications OAuth à partir des interfaces des groupes et des utilisateurs dans GitLab 19.3.

{{< /history >}}

Lorsqu'un client MCP se connecte au serveur MCP GitLab, il utilise l'enregistrement dynamique des clients OAuth 2.0 (DCR) pour créer une nouvelle application OAuth sur votre instance GitLab.

La nécessité de réutiliser une application OAuth pré-enregistrée unique dépend de l'instance :

- Sur les instances où un administrateur désactive le DCR, vous devez réutiliser une application OAuth pré-enregistrée, car les clients MCP ne peuvent pas enregistrer des applications automatiquement. Pour plus d'informations, consultez [Désactiver l'enregistrement dynamique de client OAuth](../../administration/settings/account_and_limit_settings.md#turn-off-oauth-dynamic-client-registration).
- Sur toutes les autres instances, la réutilisation d'une application OAuth pré-enregistrée est facultative. Réutilisez-en une pour éviter les problèmes suivants avec le DCR :
  - Avec GitLab Self-Managed et GitLab Dedicated, de nombreux utilisateurs ou des clients qui se connectent à plusieurs reprises peuvent créer un grand nombre d'applications OAuth sur l'instance.
  - Pour chaque adresse IP, les requêtes DCR sont limitées à 10 enregistrements par heure. Les utilisateurs qui partagent une adresse IP de sortie, par exemple lorsqu'ils utilisent un réseau d'entreprise ou un VPN, peuvent dépasser cette limite et ne pas parvenir à s'authentifier auprès du serveur MCP.

Chaque utilisateur autorise néanmoins l'application au moyen d'OAuth et reçoit son propre jeton d'accès. Une application partagée constitue l'identité du client OAuth, et non des informations d'identification partagées.

Créez l'application OAuth à l'un des niveaux suivants, selon les utilisateurs qui la réutiliseront :

- Instance : l'application est partagée par tous les utilisateurs de l'instance.
- Groupe : l'application est partagée par les membres d'un groupe.
- Utilisateur : l'application est destinée au compte d'un seul utilisateur.

Prérequis :

- Un client MCP qui prend en charge les éléments suivants :
  - Identifiants OAuth préconfigurés
  - Le champ `clientId` dans sa configuration
- Disposer d'un accès administrateur si vous créez l'application pour l'instance.
- Disposer du rôle Propriétaire dans le groupe si vous créez l'application pour un groupe.

Pour créer l'application OAuth :

1. Créez une application OAuth pour une [instance](../../integration/oauth_provider.md#create-an-instance-wide-application), un [groupe](../../integration/oauth_provider.md#create-a-group-owned-application) ou un [utilisateur](../../integration/oauth_provider.md#create-a-user-owned-application).
1. Sélectionnez la portée **mcp**, puis décochez la case **Confidentiel**.
1. Enregistrez l'application.
1. Renseignez l'ID de l'application dans la configuration de votre client MCP ou communiquez cet ID aux utilisateurs qui réutiliseront l'application. L'ID de l'application correspond à `clientId`. La clé de la configuration OAuth du serveur MCP GitLab varie selon le client. Elle s'appelle généralement `clientId` ou `client_id` et se trouve le plus souvent dans un fichier `mcp.json`.

Vous pouvez également utiliser l'[API REST](../../api/applications.md#create-an-application) pour créer une application pour une instance ou un utilisateur. Aucune API REST ne permet de créer une application appartenant à un groupe. Vous devez donc utiliser l'interface du groupe.

> [!note]
> L'URI de redirection enregistrée dans l'application OAuth doit correspondre exactement à celle que votre client MCP envoie au cours du flux OAuth. Consultez la documentation de votre client pour connaître l'URI de redirection qu'il utilise. Une seule application OAuth partagée ne peut pas prendre en charge des clients MCP qui utilisent des URI de redirection différentes. Si vos utilisateurs emploient des clients MCP dont les URI de redirection diffèrent, créez une application OAuth partagée distincte pour chaque type de client.

### Considérations relatives à la sécurité {#security-considerations}

Les utilisateurs qui s'authentifient au moyen de l'ID client doivent néanmoins finaliser l'autorisation OAuth avec leurs propres identifiants GitLab. Ils ne peuvent accéder qu'aux données dont l'accès leur est autorisé.

GitLab ne vérifie pas quelle application cliente MCP présente le `clientId`. Si vous créez une application OAuth pour un client MCP donné, tout autre client MCP qui prend en charge le préenregistrement pourrait utiliser le même `clientId` pour s'authentifier. Le `clientId` détermine quelle application OAuth est utilisée, mais pas quel logiciel client est autorisé.

Les applications préenregistrées créées avec l'API REST n'imposent pas le mécanisme Proof Key for Code Exchange (PKCE). Le mécanisme PKCE protège les clients publics contre l'interception du code d'autorisation.

Pour imposer l'utilisation de PKCE, vérifiez que votre client MCP envoie les paramètres `code_challenge` et `code_challenge_method` au cours du flux OAuth. GitLab accepte les paramètres PKCE pour les applications préenregistrées, sans toutefois les exiger.

## Limites de débit {#rate-limits}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/629883) dans GitLab 19.5 [avec des feature flags](../../administration/feature_flags/_index.md) nommés `rate_limiter_mcp_limits_free_info`, `rate_limiter_mcp_limits_free_enforce`, `rate_limiter_mcp_limits_premium_info`, `rate_limiter_mcp_limits_premium_enforce`, `rate_limiter_mcp_limits_ultimate_info` et `rate_limiter_mcp_limits_ultimate_enforce`. Désactivé par défaut. Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Les requêtes adressées à l'endpoint du serveur MCP, `POST /api/v4/mcp`, sont limitées pour chaque utilisateur selon le plan de leur espace de nommage :

| Plan     | Limite            |
| -------- | ---------------- |
| Gratuite     | 60 par minute   |
| GitLab Premium  | 600 par minute  |
| GitLab Ultimate | 600 par minute  |

Ces limites s'appliquent par utilisateur, et non par client ou par jeton. Un utilisateur qui connecte plusieurs clients MCP partage une seule limite entre tous ses clients.

Les requêtes du serveur MCP sont également comptabilisées dans les [limites de débit de GitLab.com](../gitlab_com/rate_limits.md) qui s'appliquent à l'ensemble du trafic. Une requête peut donc atteindre l'une ou l'autre limite. La limite de débit du serveur MCP est la plus basse des deux pour chaque plan.

Lorsque vous dépassez la limite, GitLab renvoie `429 Too Many Requests` avec les [en-têtes de limite de débit standard](../../administration/settings/user_and_ip_rate_limits.md#response-headers), notamment `Retry-After` et `RateLimit-Reset`. `RateLimit-Name` identifie la limite atteinte.

Une limite de débit sur l'endpoint de l'API GitLab derrière un outil est signalée différemment. Pour ce cas, consultez [le résultat de l'outil `rate_limited`](mcp_server_troubleshooting.md#error-rate_limited-tool-result).

Sur GitLab Self-Managed et GitLab Dedicated, un administrateur définit une limite de débit unique pour le serveur MCP de l'instance. Pour plus d'informations, consultez [la limite de débit des requêtes authentifiées au serveur MCP](../../administration/settings/user_and_ip_rate_limits.md#enable-authenticated-mcp-server-request-rate-limit).

## Versions du protocole MCP prises en charge {#supported-mcp-protocol-versions}

Le serveur MCP GitLab négocie la version du protocole dans la requête `initialize`. Si le client demande une version que le serveur ne prend pas en charge, le serveur renvoie une erreur JSON-RPC répertoriant les versions prises en charge.

| Version du protocole | Prise en charge |
|------------------|---------|
| `2025-11-25`     | Prise en charge. Le serveur répond également avec cette version lorsqu'un client demande une version plus récente. |
| `2025-06-18`     | Prise en charge. |
| `2025-03-26`     | Prise en charge. |
| `2026-07-28`     | Accepté uniquement dans la requête `initialize`. Le serveur répond avec `2025-11-25`, car il n'implémente pas encore les fonctionnalités sans état de cette version. Pour suivre l'avancement, consultez le [ticket 627825](https://gitlab.com/gitlab-org/gitlab/-/work_items/627825). |

GitLab continue à prendre en charge une version de protocole après que la spécification MCP la déprécie. La suppression d'une version de protocole est une modification incompatible. GitLab annonce la suppression sur la page [dépréciations et suppressions](../../update/deprecations.md) avant que la version ne soit supprimée.

## Sujets connexes {#related-topics}

- [Serveurs MCP dans le catalogue d'IA](../gitlab_duo/model_context_protocol/ai_catalog_mcp_servers.md)
