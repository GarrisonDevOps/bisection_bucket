---
stage: AI Clients
group: Developer Clients
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Modifiez les paramètres de GitLab Duo CLI dans le panneau des paramètres ou le fichier de paramètres, et appliquez des paramètres à l'aide d'un fichier de paramètres géré."
title: Paramètres de GitLab Duo CLI
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez modifier le comportement de GitLab Duo CLI de différentes façons :

- Dans le [panneau des paramètres](#settings-panel), depuis le mode interactif.
- Dans le [fichier de paramètres](#settings-file), qui stocke les choix effectués dans le panneau des paramètres. Vous pouvez également modifier le fichier directement.
- Avec un [fichier de paramètres géré](#managed-settings-file), que les administrateurs système déploient pour appliquer des paramètres.

## Panneau des paramètres {#settings-panel}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.90.0) du panneau de paramètres dans GitLab Duo CLI 8.90.0, lors de la release GitLab 19.0
- Paramètre pour afficher les éléments de travail dans les nouvelles sessions [introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.11.0) dans GitLab Duo CLI 9.11.0, lors de la release GitLab 19.4.
- Paramètre pour ajuster le thème [introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.11.0) dans GitLab Duo CLI 9.11.0, lors de la release GitLab 19.4.
- Paramètre pour exécuter les invites suggérées en tant que sessions `/goal` [introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.24.0) dans GitLab Duo CLI 9.24.0, lors de la release GitLab 19.5.

{{< /history >}}

Pour modifier un paramètre :

1. En mode interactif, saisissez `/settings` et appuyez sur <kbd>Entrée</kbd>.
1. Utilisez les touches fléchées pour naviguer dans la liste des paramètres.
1. Pour modifier le paramètre sélectionné, appuyez sur <kbd>Entrée</kbd> ou <kbd>Espace</kbd>.
1. Pour fermer le panneau, appuyez sur <kbd>Échap</kbd>.

Les modifications sont conservées entre les sessions dans le fichier de paramètres. Si votre organisation applique un paramètre, le panneau affiche **Défini par votre organisation** et vous ne pouvez pas le modifier.

Les paramètres suivants sont disponibles :

| Paramètre                  | Description                                                                                       |
|--------------------------|---------------------------------------------------------------------------------------------------|
| **Télémétrie**            | Envoyer des données d'utilisation anonymes pour améliorer GitLab Duo.                                                  |
| **Notifications**        | Contrôler les [notifications système](use.md#system-notifications) (`auto` ou `disabled`).                     |
| **Afficher les éléments de travail au démarrage de la session** | Affichez vos éléments de travail ouverts lorsque vous démarrez une nouvelle session. |
| **Exécuter les invites suggérées en tant que sessions /goal** | Exécutez les invites suggérées en tant que sessions `/goal` plutôt que comme de simples messages de chat. Un redémarrage est requis pour que les modifications prennent effet. |
| **Thème**        | Modifiez le paramètre de thème. Les options disponibles sont `auto`, `dark`, `light`, `dark high contrast` et `light high contrast`. |

## Fichier de paramètres {#settings-file}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.26.0) dans GitLab Duo CLI 9.26.0, lors de la release GitLab 19.5.

{{< /history >}}

GitLab Duo CLI stocke les paramètres que vous modifiez dans le panneau `/settings` dans un fichier de paramètres. Vous pouvez également modifier le fichier directement ou le créer à l'avance, par exemple dans une image de conteneur.

GitLab Duo CLI lit le fichier à son démarrage. Les modifications apportées au fichier s'appliquent lors du prochain démarrage de GitLab Duo CLI.

### Emplacement du fichier {#file-location}

L'emplacement du fichier dépend de votre système d'exploitation :

| Système d'exploitation | Chemin                                 |
|------------------|--------------------------------------|
| Linux et macOS  | `~/.gitlab/duo/settings.json`        |
| Windows          | `%APPDATA%\GitLab\duo\settings.json` |

Si vous avez défini `XDG_CONFIG_HOME`, le fichier est `$XDG_CONFIG_HOME/gitlab/duo/settings.json`.

GitLab Duo CLI crée le fichier la première fois que vous modifiez un paramètre dans le panneau `/settings`.

### Format du fichier {#file-format}

Le fichier doit contenir un objet JSON et peut inclure des commentaires (`//` et `/* */`) ainsi que des virgules finales. Lorsque vous modifiez un paramètre dans le panneau `/settings`, GitLab Duo CLI conserve vos commentaires, votre mise en forme et toutes les clés qu'il ne reconnaît pas.

L'exemple suivant définit chaque paramètre à sa valeur par défaut :

```json
{
  "telemetry": {
    "enabled": true
  },
  "showWorkItemsInNewSessions": true,
  "goalFlowInWelcomePrompts": true,
  "notifications": {
    "channel": "auto" // or "disabled"
  },
  "theme": "auto" // or "dark", "light", "dark-high-contrast", "light-high-contrast"
}
```

### Fichiers et valeurs non valides {#invalid-files-and-values}

GitLab Duo CLI ne supprime ni ne réécrit jamais le fichier pour le corriger :

- Si le fichier n'est pas un JSON valide, GitLab Duo CLI ignore l'intégralité du fichier et consigne un avertissement.
- Si un paramètre a une valeur non valide, GitLab Duo CLI ignore ce paramètre et consigne un avertissement.
- Si GitLab Duo CLI ne reconnaît pas un paramètre, par exemple un paramètre provenant d'une version plus récente, il l'ignore.

Si le fichier est en lecture seule, les modifications apportées dans le panneau `/settings` s'appliquent uniquement à la session en cours.

## Fichier de paramètres géré {#managed-settings-file}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.27.0) dans GitLab Duo CLI 9.27.0, lors de la release GitLab 19.5.

{{< /history >}}

Pour appliquer des paramètres, les administrateurs système déploient un fichier de paramètres géré sur chaque machine. Par exemple, ils peuvent utiliser un outil de gestion des appareils mobiles ou une stratégie de groupe.

Les paramètres du fichier de paramètres géré ont la priorité sur les options de ligne de commande, les variables d'environnement et le fichier de paramètres, y compris les modifications apportées par les utilisateurs dans le panneau des paramètres.

Les paramètres appliqués ne peuvent pas être modifiés par les utilisateurs. Les paramètres ne figurant pas dans le fichier restent sous le contrôle de l'utilisateur.

### Emplacement du fichier {#file-location-1}

GitLab Duo CLI lit le fichier depuis un emplacement fixe qui ne peut pas être modifié :

| Système d'exploitation                  | Chemin                                                            |
|-----------------------------------|-----------------------------------------------------------------|
| Linux et autres systèmes d'exploitation | `/etc/gitlab/duo/settings.managed.json`                         |
| macOS                             | `/Library/Application Support/GitLab/duo/settings.managed.json` |
| Windows                           | `C:\Program Files\GitLab\duo\settings.managed.json`             |

Limitez l'accès en écriture aux administrateurs système et accordez un accès en lecture seule à tous les autres utilisateurs.

GitLab Duo CLI lit le fichier à son démarrage. Les modifications apportées au fichier s'appliquent lors du prochain démarrage de GitLab Duo CLI par les utilisateurs.

Dans Windows Subsystem for Linux (WSL), GitLab Duo CLI lit le chemin Linux à l'intérieur de la distribution, et la stratégie de groupe Windows ne s'applique pas.

### Format du fichier {#file-format-1}

Le fichier doit contenir un objet JSON et peut inclure des commentaires (`//` et `/* */`) ainsi que des virgules finales.

L'exemple suivant définit chaque paramètre que vous pouvez appliquer :

```json
{
  "telemetry": {
    "enabled": false
  },
  "showWorkItemsInNewSessions": true,
  "goalFlowInWelcomePrompts": true,
  "notifications": {
    "channel": "auto" // or "disabled"
  },
}
```

## Priorité des paramètres {#settings-precedence}

Pour chaque paramètre, GitLab Duo CLI utilise la première valeur trouvée, dans cet ordre :

1. Le fichier de paramètres géré, si votre organisation applique le paramètre.
1. Les options de ligne de commande et les variables d'environnement, qui s'appliquent uniquement à la session en cours.
1. Le fichier de paramètres.
1. La valeur par défaut.
