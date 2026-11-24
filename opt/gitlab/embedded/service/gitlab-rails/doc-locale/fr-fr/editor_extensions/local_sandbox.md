---
stage: AI Clients
group: Duo Client SDK
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Exécutez des actions d'agent GitLab Duo et des serveurs MCP locaux dans un sandbox de processus sur votre ordinateur."
title: Sandbox local
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.80.0) en tant que [version expérimentale](../policy/development_stages_support.md#experiment) dans GitLab pour VS Code 6.80.0, lors de la release GitLab 19.0.
- [Introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.94.0) en tant que [version expérimentale](../policy/development_stages_support.md#experiment) dans GitLab Duo CLI 8.94.0, lors de la release GitLab 19.1.
- Fichier de configuration du sandbox [introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.4.0) dans GitLab Language Server 9.4.0 et GitLab Duo CLI 9.4.0, lors de la release GitLab 19.3.

{{< /history >}}

Le sandbox local restreint ce que les agents GitLab Duo peuvent lire, écrire et atteindre sur le réseau lorsqu'ils s'exécutent sur votre ordinateur. Il s'applique aux agents dans votre éditeur et dans GitLab Duo CLI.

Le sandbox est désactivé par défaut. Tant que vous ne l'activez pas, les risques décrits dans [les considérations de sécurité pour les extensions d'éditeur et les outils CLI](security_considerations.md) s'appliquent.

Pour les flows qui s'exécutent sur GitLab Runner, consultez le [sandbox de l'environnement d'exécution à distance](../user/duo_agent_platform/environment_sandbox.md).

## Fonctionnement du sandbox {#how-the-sandbox-works}

Lorsque le sandbox est activé, GitLab Duo exécute les actions d'agent dans un processus de travail distinct que le système d'exploitation restreint. Les actions d'agent comprennent les commandes shell, les lectures et écritures de fichiers, les recherches de fichiers et les listes de répertoires.

Les serveurs MCP locaux qui utilisent le transport `stdio` s'exécutent dans le même type de sandbox.

Le sandbox supprime les variables d'environnement d'identification connues, telles que `GITLAB_TOKEN`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY` et `SSH_AUTH_SOCK`, de l'environnement des processus dans le sandbox. Les autres variables d'environnement ne sont pas supprimées.

Par défaut, le sandbox bloque également :

- Les lectures depuis les répertoires d'identification et personnels courants.
- Les écritures en dehors du workspace et du répertoire temporaire.
- L'accès réseau à tous les hôtes sauf votre instance GitLab.

Pour la liste complète, consultez les [règles de sandbox par défaut](#default-sandbox-rules).

Le sandbox est un sandbox de processus, pas un conteneur ni une machine virtuelle. Les éléments suivants s'exécutent en dehors du sandbox :

- Votre éditeur et GitLab Duo lui-même.
- Les connexions aux serveurs MCP qui utilisent le transport `http` ou `sse`.
- Les serveurs MCP avec `"sandboxEnabled": false`.
- [Les hooks GitLab Duo CLI](../user/gitlab_duo_cli/customize.md#hooks).

Le sandbox réduit les risques liés à l'exécution locale des agents, mais ne les supprime pas. Les agents peuvent toujours lire et modifier des fichiers dans votre workspace, et envoyer des données aux hôtes que le sandbox autorise.

Si le sandbox est activé mais ne peut pas démarrer, par exemple parce qu'une dépendance est manquante, les actions d'agent et les serveurs MCP locaux échouent avec une erreur. Ils ne s'exécutent pas sans le sandbox. Ce comportement est différent du sandbox de l'environnement d'exécution à distance, qui exécute les flows sans le sandbox et affiche un avertissement.

## Plateformes prises en charge {#supported-platforms}

| Système d'exploitation | Pris en charge |
|------------------|-----------|
| macOS            | Oui       |
| Linux            | Oui, avec les [prérequis](#prerequisites) |
| Windows          | Non        |

## Prérequis {#prerequisites}

Sur Linux, installez `bubblewrap` et `socat`. Par exemple :

- Sur Debian ou Ubuntu :

  ```shell
  sudo apt-get install bubblewrap socat
  ```

- Sur Fedora :

  ```shell
  sudo dnf install bubblewrap socat
  ```

Sur macOS, aucun logiciel supplémentaire n'est requis.

## Activer le sandbox {#turn-on-the-sandbox}

Pour activer le sandbox :

{{< tabs >}}

{{< tab title="VS Code" >}}

1. Dans VS Code, ouvrez les paramètres :
   - Pour macOS, appuyez sur <kbd>Commande</kbd>+<kbd>,</kbd>.
   - Pour Windows ou Linux, appuyez sur <kbd>Ctrl</kbd>+<kbd>,</kbd>.
1. Recherchez `gitlab.duoAgentPlatform.sandbox.enabled`.
1. Cochez la case **Activer le sandboxing**.

Sinon, dans la barre de statut inférieure, sélectionnez **Duo** ({{< icon name="tanuki-ai" >}}), puis sélectionnez **Activer le sandboxing des agents**.

{{< /tab >}}

{{< tab title="JetBrains EDIs" >}}

Le paramètre de sandbox est disponible uniquement dans les versions alpha du plugin GitLab Duo pour les IDE JetBrains.

1. Dans votre IDE, dans la barre supérieure, sélectionnez le nom de votre IDE, puis sélectionnez **Paramètres**.
1. Dans la barre latérale gauche, sélectionnez **Outils** > **GitLab Duo**.
1. Sous **GitLab Duo Agent Platform**, cochez la case **Activer le sandboxing**.
1. Sélectionnez **OK** ou **Sauvegarder**.

{{< /tab >}}

{{< tab title="GitLab Duo CLI" >}}

Démarrez GitLab Duo CLI avec l'option `--sandbox` définie sur `true` :

```shell
duo --sandbox true
```

Sinon, définissez la variable d'environnement `DUO_SANDBOX_ENABLED` :

```shell
export DUO_SANDBOX_ENABLED=true
```

{{< /tab >}}

{{< /tabs >}}

## Vérifier le statut du sandbox {#check-sandbox-status}

Pour vérifier si le sandbox est activé et disponible :

{{< tabs >}}

{{< tab title="VS Code" >}}

- Dans la barre de statut inférieure, sélectionnez **Duo** ({{< icon name="tanuki-ai" >}}). Le menu affiche le statut du sandbox, par exemple **Sandboxing des agents : activé** ou **Sandboxing des agents : dépendances manquantes**.

Pour plus de détails, ouvrez la palette de commandes, exécutez **GitLab : diagnostic**, et accédez à la section **GitLab Duo Agent Sandboxing**.

{{< /tab >}}

{{< tab title="JetBrains EDIs" >}}

- Dans la barre de statut, sélectionnez **Duo** ({{< icon name="tanuki-ai" >}}). Le menu affiche le statut du sandbox, par exemple **Sandboxing des agents : activé** ou **Sandboxing des agents : dépendances manquantes**.

{{< /tab >}}

{{< tab title="GitLab Duo CLI" >}}

1. Démarrez GitLab Duo CLI avec le sandbox activé :

   ```shell
   duo --sandbox true
   ```

1. Exécutez la commande `/doctor`.
1. Accédez à la section **Sandbox**.

La section **Sandbox** rend compte de la session en cours uniquement. Si vous démarrez la CLI sans `--sandbox true` ni `DUO_SANDBOX_ENABLED=true`, la section affiche le sandbox comme désactivé.

{{< /tab >}}

{{< /tabs >}}

Chaque vérification du statut indique si :

- Le sandbox de processus est activé dans les paramètres.
- Le sandbox de processus est pris en charge sur cette plateforme.
- Les dépendances système requises pour le sandbox de processus sont installées.

## Règles de sandbox par défaut {#default-sandbox-rules}

Ces règles s'appliquent aux actions d'agent et aux serveurs MCP locaux lorsque le sandbox est activé.

### Réseau {#network}

Les processus dans le sandbox peuvent se connecter uniquement à l'hôte et au port de l'URL de votre instance GitLab. Si l'URL de votre instance n'inclut pas de port, le sandbox utilise `443` pour `https` et `80` pour `http`.

Tous les autres hôtes sont bloqués, y compris les registres de packages. Pour autoriser davantage d'hôtes, [personnalisez les règles de sandbox](#customize-sandbox-rules).

Le sandbox vérifie uniquement l'hôte et le port de chaque connexion. Il n'inspecte pas les requêtes. Les agents peuvent envoyer des données à tout projet ou compte sur un hôte que le sandbox autorise.

### Lecture du système de fichiers {#file-system-read}

Les processus dans le sandbox ne peuvent pas lire :

- Les fichiers et répertoires d'identification, tels que `~/.ssh/`, `~/.gnupg/`, `~/.aws/`, `~/.azure/`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc` et `~/.pypirc`.
- `~/.config/`, sauf `~/.config/git/`.
- Les répertoires personnels : `~/Documents/`, `~/Downloads/`, `~/Desktop/`, `~/Pictures/`, `~/Movies/` et `~/Music/`.
- L'historique shell : `~/.bash_history` et `~/.zsh_history`.
- Sur macOS, `~/Library/Application Support/`, `~/Library/Containers/`, `~/Library/Group Containers/` et `~/Library/Keychains/`.

Sur Linux et sur macOS dans VS Code, les processus dans le sandbox peuvent lire uniquement un ensemble de chemins autorisés. Les chemins autorisés incluent le workspace, les répertoires système tels que `/usr/`, `/bin/` et `/etc/`, le répertoire temporaire, le répertoire de configuration de GitLab Duo, votre configuration Git et les répertoires courants des gestionnaires de versions Node.js.

Sur macOS dans les IDE JetBrains et GitLab Duo CLI, les processus dans le sandbox peuvent lire tout chemin qui ne figure pas dans la liste bloquée.

Un chemin autorisé est prioritaire sur un chemin bloqué qui le contient. Par exemple, si votre workspace se trouve dans `~/Documents/`, les processus dans le sandbox peuvent lire le workspace.

### Écriture dans le système de fichiers {#file-system-write}

Les processus dans le sandbox peuvent écrire uniquement dans le workspace, le répertoire temporaire et quelques répertoires de journaux utilisés par le runtime du sandbox.

Dans le workspace, les processus dans le sandbox ne peuvent pas écrire dans :

- `.git/hooks/` et `.git/config`
- `.gitlab-ci.yml` et `.gitlab/`
- `.gitconfig` et `.gitmodules`
- Les fichiers de démarrage du shell, tels que `.bashrc`, `.zshrc` et `.profile`
- Les répertoires de configuration de l'éditeur : `.vscode` et `.idea`

Dans GitLab Duo CLI, si vous utilisez l'option `--cwd` pour ouvrir un workspace depuis un autre répertoire, les règles pour `.git/config`, `.gitmodules`, les fichiers de démarrage du shell et les répertoires de configuration de l'éditeur s'appliquent au répertoire depuis lequel vous avez démarré la CLI, et non au workspace. Pour que ces règles s'appliquent au workspace, démarrez la CLI depuis le répertoire du workspace.

## Personnaliser les règles de sandbox {#customize-sandbox-rules}

Vous pouvez ajouter des règles aux valeurs par défaut dans un fichier de configuration du sandbox. Vos règles s'appliquent à tous les workspaces.

Pour personnaliser les règles de sandbox :

1. Créez un fichier `sandbox.json` à l'[emplacement du fichier](#file-location).
1. Ajoutez les règles dont vous avez besoin. Par exemple, pour permettre aux agents d'installer des packages depuis le registre npm et de lire un répertoire dans votre répertoire home :

   ```json
   {
     "network": {
       "allowedDomains": ["registry.npmjs.org"]
     },
     "filesystem": {
       "allowRead": ["~/reference-docs/"],
       "allowWrite": ["~/.npm/"]
     }
   }
   ```

   npm stocke les packages téléchargés dans `~/.npm/`, donc l'exemple autorise également les écritures dans ce répertoire.

1. Enregistrez le fichier.
1. Redémarrez votre IDE ou GitLab Duo CLI.

Dans GitLab Duo CLI, vous pouvez utiliser un fichier différent avec l'option `--sandbox-config` ou la variable d'environnement `DUO_SANDBOX_CONFIG`. Utilisez un chemin absolu ou un chemin commençant par `~/`. Le sandbox doit également être activé :

```shell
duo --sandbox true --sandbox-config ~/sandbox-strict.json
```

### Emplacement du fichier {#file-location}

Le fichier se trouve à `~/.gitlab/duo/sandbox.json`.

Si vous définissez la variable d'environnement `XDG_CONFIG_HOME`, le fichier se trouve à `$XDG_CONFIG_HOME/gitlab/duo/sandbox.json`.

### Référence du fichier de configuration {#configuration-file-reference}

Le fichier prend en charge les clés suivantes. Sauf indication contraire, chaque clé accepte une liste de chaînes de caractères.

| Clé | Description |
|-----|-------------|
| `filesystem.allowRead` | Chemins que les processus dans le sandbox peuvent lire. |
| `filesystem.denyRead` | Chemins que les processus dans le sandbox ne peuvent pas lire. |
| `filesystem.allowWrite` | Chemins dans lesquels les processus dans le sandbox peuvent écrire. |
| `filesystem.denyWrite` | Chemins dans lesquels les processus dans le sandbox ne peuvent pas écrire. |
| `network.allowedDomains` | Hôtes auxquels les processus dans le sandbox peuvent se connecter. Pour autoriser un port spécifique, utilisez `host:port`. |
| `network.deniedDomains` | Hôtes auxquels les processus dans le sandbox ne peuvent pas se connecter. |
| `srt.enableWeakerNestedSandbox` | Booléen. Sur Linux, définissez sur `true` pour s'exécuter dans un conteneur qui ne prend pas en charge le sandbox complet. Ce paramètre affaiblit le sandbox. |
| `srt.ignoreViolations` | Objet qui associe des modèles de commandes à des listes de chemins. Les accès bloqués à ces chemins ne sont pas signalés. |

Vos règles s'ajoutent aux règles par défaut. Vous ne pouvez pas supprimer :

- L'accès en écriture au workspace et au répertoire temporaire.
- L'accès réseau à votre instance GitLab.
- Les chemins d'écriture bloqués dans le workspace.

Si le fichier n'est pas un JSON valide ou contient une clé qui ne figure pas dans ce tableau, GitLab Duo ignore l'intégralité du fichier et utilise les règles par défaut. L'erreur est consignée dans le journal GitLab Duo.

## Configurer le sandbox pour un serveur MCP {#configure-the-sandbox-for-an-mcp-server}

Certains serveurs MCP locaux nécessitent un accès que les règles par défaut bloquent. Par exemple, un serveur MCP qui lit sa propre configuration depuis `~/.config/` ne peut pas démarrer.

Pour modifier les règles de sandbox pour un serveur MCP :

1. Ouvrez votre [fichier de configuration MCP utilisateur](../user/gitlab_duo/model_context_protocol/mcp_clients.md#create-user-configuration).
1. Dans la configuration du serveur, ajoutez un objet `sandbox`. Par exemple :

   ```json
   {
     "mcpServers": {
       "gitlab": {
         "type": "stdio",
         "command": "glab",
         "args": ["mcp", "serve"],
         "sandbox": {
           "allowRead": ["~/.config/glab-cli/"]
         }
       }
     }
   }
   ```

   Cet exemple utilise le répertoire de configuration `glab` sur Linux. Sur macOS, utilisez `~/Library/Application Support/glab-cli/`.

1. Enregistrez le fichier.
1. Redémarrez votre IDE ou GitLab Duo CLI.

Le sandbox supprime les variables d'environnement d'identification d'un serveur MCP, même lorsque vous les définissez dans l'objet `env` du serveur.

### Paramètres de sandbox du serveur MCP {#mcp-server-sandbox-settings}

L'objet `sandbox` s'applique uniquement aux serveurs MCP qui utilisent le transport `stdio`. Il prend en charge les clés suivantes :

| Clé | Type | Description |
|-----|------|-------------|
| `sandboxEnabled` | Booléen | Définissez sur `false` pour exécuter ce serveur sans le sandbox. Le définir sur `true` n'a aucun effet lorsque le sandbox est désactivé. |
| `allowRead` | Liste de chaînes de caractères | Chemins que ce serveur peut lire, en plus des valeurs par défaut. |
| `allowWrite` | Liste de chaînes de caractères | Chemins dans lesquels ce serveur peut écrire, en plus des valeurs par défaut. |
| `denyRead` | Liste de chaînes de caractères | Chemins que ce serveur ne peut pas lire, en plus des valeurs par défaut. |

L'endroit où vous définissez l'objet `sandbox` détermine les clés qui s'appliquent :

- Configuration utilisateur : toutes les clés s'appliquent.
- Configuration du workspace (`.gitlab/duo/mcp.json` ) : seul `denyRead` s'applique. Un projet peut restreindre un serveur, mais ne peut pas lui accorder un accès supplémentaire. GitLab Duo ignore les autres clés et consigne un avertissement.
- Plugins : l'objet `sandbox` est ignoré.

> [!warning]
> Lorsque vous définissez `"sandboxEnabled": false`, le serveur MCP s'exécute avec le même accès que votre compte utilisateur. N'utilisez ce paramètre que pour les serveurs auxquels vous faites confiance.

## Dépannage {#troubleshooting}

Lorsque vous travaillez avec le sandbox local, vous pouvez rencontrer les problèmes suivants.

### Erreur : `Sandbox is enabled but sandbox provider is not available (missing_dependencies)` {#error-sandbox-is-enabled-but-sandbox-provider-is-not-available-missing_dependencies}

Vous pouvez obtenir cette erreur lorsque le sandbox est activé et que le logiciel requis n'est pas installé. Dans VS Code, un avertissement liste également les dépendances manquantes.

Pour résoudre ce problème, installez les [prérequis](#prerequisites), puis redémarrez votre IDE ou GitLab Duo CLI.

### Erreur : `Sandbox is enabled but sandbox provider is not available (unsupported_platform)` {#error-sandbox-is-enabled-but-sandbox-provider-is-not-available-unsupported_platform}

Vous pouvez obtenir cette erreur lorsque le sandbox est activé et que votre système d'exploitation n'est pas [pris en charge](#supported-platforms).

Pour résoudre ce problème, désactivez le sandbox :

- Dans VS Code, dans les paramètres, recherchez `gitlab.duoAgentPlatform.sandbox.enabled`, puis décochez la case **Activer le sandboxing**.
- Dans GitLab Duo CLI, annulez la définition des variables d'environnement `DUO_SANDBOX_ENABLED` et `DUO_SANDBOX_CONFIG`, puis démarrez la CLI sans les options `--sandbox` et `--sandbox-config`.

### Erreur : `Operation is blocked by sandbox.` {#error-operation-is-blocked-by-sandbox}

Vous pouvez obtenir cette erreur lorsqu'une action d'agent tente de lire, d'écrire ou de se connecter à quelque chose que les règles de sandbox bloquent.

Pour résoudre ce problème, si l'agent nécessite cet accès, ajoutez une règle à votre [fichier de configuration du sandbox](#customize-sandbox-rules).

### Échec du démarrage du serveur MCP {#mcp-server-fails-to-start}

Lorsque le sandbox est activé, un serveur MCP local peut ne pas démarrer parce que :

- Le sandbox ne peut pas démarrer. L'erreur inclut `Sandbox is enabled but sandbox provider is not available`. Pour résoudre ce problème, installez les [prérequis](#prerequisites).
- Le serveur lit des fichiers ou se connecte à des hôtes que le sandbox bloque. Pour résoudre ce problème, [configurez le sandbox pour le serveur MCP](#configure-the-sandbox-for-an-mcp-server).
- Le serveur nécessite une variable d'environnement d'identification que le sandbox supprime, telle que `GITHUB_TOKEN`. Pour résoudre ce problème, si vous faites confiance au serveur, définissez `"sandboxEnabled": false` dans son objet `sandbox`.

### Les paramètres de sandbox MCP du projet sont ignorés {#project-mcp-sandbox-settings-are-ignored}

Vous pouvez recevoir un avertissement qui inclut `sandbox settings from this project's committed config can only narrow, not widen`.

Cet avertissement se produit lorsque le fichier `.gitlab/duo/mcp.json` du workspace définit des clés `sandbox` autres que `denyRead`.

Pour résoudre ce problème, déplacez les clés vers votre [fichier de configuration MCP utilisateur](../user/gitlab_duo/model_context_protocol/mcp_clients.md#create-user-configuration).

### Les requêtes vers l'instance GitLab sont bloquées {#requests-to-the-gitlab-instance-are-blocked}

Les processus dans le sandbox peuvent se connecter à votre instance GitLab uniquement sur l'hôte et le port indiqués dans l'URL de votre instance. Les requêtes vers un port différent sont bloquées. Par exemple, si l'URL de votre instance est `https://gitlab.example.com`, le port autorisé est `443`, donc une requête vers `http://gitlab.example.com` sur le port `80` est bloquée.

Pour résoudre ce problème, utilisez le même port que l'URL de votre instance, ou ajoutez l'hôte et le port à `network.allowedDomains` dans votre [fichier de configuration du sandbox](#customize-sandbox-rules). Par exemple, `gitlab.example.com:8080`.
