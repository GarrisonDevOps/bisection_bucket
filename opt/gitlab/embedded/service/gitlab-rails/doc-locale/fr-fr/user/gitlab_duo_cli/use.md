---
stage: AI Clients
group: Developer Clients
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Utiliser GitLab Duo CLI en modes interactif et headless.
title: Utiliser GitLab Duo CLI
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez utiliser GitLab Duo CLI dans deux modes :

- Mode interactif : offre une expérience de chat similaire à GitLab Duo Chat dans l'interface GitLab ou dans les extensions d'éditeur. Prend en charge les modes build, plan et auto.
- Mode headless : permet une utilisation non interactive dans les runners, les scripts et autres workflows automatisés.

## Prérequis {#prerequisites}

- GitLab Duo CLI installé et [configuré](set_up.md).
- Un [espace de nommage GitLab Duo par défaut](../profile/preferences.md#namespace-resolution-in-your-local-environment) défini, ou un projet ouvert ayant accès à GitLab Duo.

## Mode interactif {#interactive-mode}

Pour utiliser GitLab Duo CLI en mode interactif :

1. En fonction de votre configuration, saisissez la commande pour démarrer le mode interactif :

   {{< tabs >}}

   {{< tab title="glab" >}}

   ```shell
   glab duo cli
   ```

   {{< /tab >}}

   {{< tab title="duo" >}}

   ```shell
   duo
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. Le prompt `>` s'affiche dans votre fenêtre de terminal. Après le prompt, saisissez votre question ou votre demande, puis appuyez sur <kbd>Entrée</kbd>.

   Par exemple :

   ```plaintext
   What is this repository about?

   Which issues need my attention?

   Help me implement issue 15.

   The pipelines in MR 23 are failing. Please help me fix them.
   ```

Pour annuler une réponse pendant que GitLab Duo CLI travaille, appuyez sur <kbd>Échap</kbd>. GitLab Duo CLI arrête l'opération en cours et revient au prompt.

Utilisez la touche <kbd>↑</kbd> pour afficher l'historique de vos prompts, ou <kbd>Ctrl</kbd>+<kbd>R</kbd> pour y effectuer une recherche.

Lorsque vous démarrez une nouvelle session, l'espace réservé à l'invite peut afficher une astuce sur une fonctionnalité de GitLab Duo CLI.

### Cartes de démarrage {#startup-cards}

{{< history >}}

- Carte de bienvenue [introduite](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.11.0) dans GitLab Duo CLI 9.11.0, lors de la release GitLab 19.4.
- Option `--startup-cards` et variable d'environnement `STARTUP_CARDS` [introduites](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.17.0) dans GitLab Duo CLI 9.17.0, lors de la release GitLab 19.4.
- Carte d'intégration [introduite](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.28.0) dans GitLab Duo CLI 9.28.0, lors de la release GitLab 19.5.

{{< /history >}}

Des cartes de démarrage s'affichent dans votre terminal lorsque vous démarrez une nouvelle session en mode interactif : une carte d'intégration lors de votre première exécution, et une carte de bienvenue lors des exécutions suivantes. Les cartes ne s'affichent pas lorsque vous reprenez une session existante.

Les cartes de démarrage sont activées par défaut, mais vous pouvez les désactiver.

#### Carte d'intégration {#onboarding-card}

La première fois que vous exécutez GitLab Duo CLI sur une machine, une carte d'intégration vous aide à [connecter des serveurs MCP](#model-context-protocol-mcp-connections) et à installer des [plugins](customize.md#plugins) depuis le marketplace GitLab.

La carte affiche des indications de navigation pour sélectionner et exécuter les étapes. Les étapes terminées affichent une coche avec le nombre de serveurs MCP connectés ou de plugins installés.

La carte reste affichée jusqu'à ce que vous envoyiez votre première invite, même après avoir effectué les deux étapes. Elle ne s'affiche plus lors des exécutions ultérieures.

#### Carte de bienvenue {#welcome-card}

Chaque fois que vous démarrez une nouvelle session, une carte de bienvenue s'affiche par défaut. Vous pouvez désactiver la carte avec le paramètre [**Afficher les éléments de travail au démarrage de la session**](#settings).

La carte suggère des invites pour lancer des tâches courantes et affiche des indications de navigation pour parcourir et exécuter des invites. Par exemple, lorsque vous travaillez dans un projet GitLab, les invites suggérées sont construites à partir de vos merge requests et tickets ouverts. Sinon, la carte affiche des exemples génériques.

Lorsque vous sélectionnez une invite pour l'une de vos merge requests et que sa branche source existe, l'invite demande à GitLab Duo de récupérer d'abord cette branche.

Si le paramètre [**Exécuter les invites suggérées en tant que sessions /goal**](#settings) est activé et que votre instance est GitLab 19.3 ou une version ultérieure, l'invite pour traiter les retours de revue s'exécute en tant que session `/goal`.

#### Masquer les cartes de démarrage {#hide-the-startup-cards}

Les cartes de démarrage sont activées par défaut. Pour les désactiver, définissez `--startup-cards` sur `false` :

{{< tabs >}}

{{< tab title="glab" >}}

```shell
glab duo cli --startup-cards false
```

{{< /tab >}}

{{< tab title="duo" >}}

```shell
duo --startup-cards false
```

{{< /tab >}}

{{< /tabs >}}

Vous pouvez également définir la variable d'environnement `STARTUP_CARDS` sur `false`. Si vous définissez les deux, l'option `--startup-cards` est prioritaire sur la variable d'environnement.

### Barre de statut {#status-bar}

Le bas de l'écran affiche une barre de statut avec :

- Le répertoire de travail actuel et la branche Git.
- Le projet GitLab détecté et, le cas échéant, la merge request ouverte pour la branche actuelle et le statut de son pipeline.
- La progression d'une session `/goal` en cours d'exécution.
- Le statut des serveurs MCP configurés.

### Changer de mode {#switch-modes}

En mode interactif, vous pouvez basculer GitLab Duo CLI entre les modes pendant votre travail :

| Mode                 | Autorisations | Fonctionnement                                                                  |
|----------------------|-------------|-------------------------------------------------------------------------------|
| Mode build (par défaut) | Lecture-écriture  | GitLab Duo peut exécuter des tâches et apporter des modifications à votre projet.               |
| Mode plan            | Lecture seule   | GitLab Duo peut analyser votre projet et créer des plans sans apporter de modifications. |
| Mode auto            | Lecture-écriture  | GitLab Duo peut utiliser des outils sans demander d'approbation au préalable. Pour plus d'informations, consultez [le mode auto](#auto-mode). |

Par exemple, commencez par discuter d'un problème avec GitLab Duo en mode plan. Lorsque vous êtes prêt, passez en mode build et demandez à GitLab Duo d'implémenter le plan.

GitLab Duo CLI affiche le mode actuel sous le prompt `>`. Pour basculer entre les modes, appuyez sur <kbd>Tab</kbd>.

### Commandes slash {#slash-commands}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.88.0) de la commande slash `/exit` dans GitLab Duo CLI 8.88.0, lors de la release GitLab 19.0
- [Introduction](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.94.0) de la commande slash `/doctor` dans GitLab Duo CLI 8.94.0, lors de la release GitLab 19.0
- [Introduction](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.81.0) de la commande slash `/skills` dans GitLab Duo CLI 8.81.0, lors de la release GitLab 19.0
- [Introduction](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.95.0) de la commande slash `/mcp` dans GitLab Duo CLI 8.95.0, lors de la release GitLab 19.0
- La commande slash `/goal` [introduite](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.17.0) dans GitLab Duo CLI 9.17.0, lors de la release GitLab 19.4, en tant que [version bêta](../../policy/development_stages_support.md#beta).
- La commande slash `/goal` [généralement disponible](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.27.0) dans GitLab Duo CLI 9.27.0, lors de la release GitLab 19.5.
- La commande slash `/compact` [introduite](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.109.0) dans GitLab Duo CLI 8.109.0, lors de la release GitLab 19.2.
- La commande slash `/export` [introduite](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.11.0) dans GitLab Duo CLI 9.11.0, lors de la release GitLab 19.4.
- La commande slash `/review` [introduite](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.14.0) dans GitLab Duo CLI 9.14.0, lors de la release GitLab 19.4.
- La commande slash `/whatsnew` [introduite](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.20.0) dans GitLab Duo CLI 9.20.0, lors de la release GitLab 19.4.

{{< /history >}}

En mode interactif, utilisez les commandes slash pour configurer GitLab Duo CLI et effectuer des actions. Saisissez une commande slash au promptet appuyez sur <kbd>Entrée</kbd>.

Les commandes slash suivantes sont disponibles :

| Commande     | Description                                          |
|-------------|------------------------------------------------------|
| `/compact`  | Compresser l'historique de la conversation pour économiser de l'espace de contexte. |
| `/copy`     | Copier la dernière réponse de GitLab Duo dans le presse-papiers.  |
| `/doctor`   | Afficher les diagnostics de l'environnement de GitLab Duo CLI. |
| `/exit`     | Quitter GitLab Duo CLI.                             |
| `/export`   | Exporter la session sous forme de bundle JSON portable.        |
| `/feedback` | Soumettre un rapport de bug ou une demande de fonctionnalité.              |
| `/goal`     | Démarrer une session qui travaille à l'atteinte d'un objectif. Nécessite GitLab 19.3 ou une version ultérieure. |
| `/help`     | Afficher les raccourcis, modes et commandes slash disponibles. |
| `/mcp`      | Afficher les serveurs MCP configurés et leur statut.        |
| `/model`    | Changer le modèle d'IA pour la session en cours.         |
| `/new`      | Démarrer une nouvelle session de chat.                            |
| `/review`   | Réviser vos modifications avec le sous-agent de revue de code.   |
| `/sessions` | Parcourir, rechercher et changer de session.                 |
| `/settings` | Ouvrir le panneau de paramètres.                             |
| `/skills`   | Lister les compétences d'agent disponibles dans le projet actuel.  |
| `/whatsnew` | Afficher les modifications récentes apportées à GitLab Duo CLI.           |

Pour fermer un panneau ou une boîte de dialogue ouverts par une commande slash, appuyez sur <kbd>Échap</kbd>.

Vous pouvez également créer vos propres commandes slash. Pour plus d'informations, voir [commandes slash personnalisées](customize.md#custom-slash-commands).

### Paramètres {#settings}

Pour afficher et modifier les paramètres, saisissez `/settings` en mode interactif. Pour plus d'informations, consultez [les paramètres de GitLab Duo CLI](settings.md).

### Notifications système {#system-notifications}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.105.0) des notifications système dans GitLab Duo CLI 8.105.0, lors de la release GitLab 19.1

{{< /history >}}

GitLab Duo CLI peut envoyer une notification système lorsqu'une session nécessite votre attention (par exemple, lorsqu'elle termine une tâche ou nécessite l'approbation d'un outil) pendant que la fenêtre du terminal n'est pas au premier plan.

Les notifications sont contrôlées par le paramètre **Notifications** dans le [panneau de paramètres](settings.md#settings-panel) :

- `auto` (par défaut) : envoyer une notification système lorsque le terminal n'est pas au premier plan.
- `disabled` : ne jamais envoyer de notifications système.

### Approbations d'outils {#tool-approvals}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/work_items/2129) de l'option Approuver des outils pour une session dans GitLab 19.0
  - Introduction dans [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.80.0) 8.80.0
- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/21850) de l'approbation d'outil basée sur des modèles dans GitLab 19.1
  - Introduction dans [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.101.0) 8.101.0
- [Suppression](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/merge_requests/3699) de l'approbation d'outil basée sur des modèles le 10 juillet 2026
  - Suppression dans [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.3.0) 9.3.0

{{< /history >}}

Lorsque GitLab Duo a besoin d'utiliser un outil, il vous invite à l'approuver avant de commencer. Par exemple, lorsqu'il a besoin de lire un fichier ou d'exécuter une commande.

Vos options sont :

- **Approuver** : GitLab Duo peut utiliser l'outil une seule fois.
- **Approuver pour la session** : GitLab Duo peut utiliser l'outil avec ces arguments pour le reste de la session. Des arguments différents nécessitent une approbation supplémentaire.
- **Refuser** : GitLab Duo ne peut pas utiliser l'outil.

> [!note]
> Pour utiliser l'option **Approuver pour la session**, votre administrateur doit l'activer pour votre groupe ou votre instance. Pour plus d'informations, voir les [approbations d'outils](../gitlab_duo_chat/agentic_chat.md#tool-approvals).

### Mode auto {#auto-mode}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/618088) dans GitLab 19.5 avec un [feature flag](../../administration/feature_flags/_index.md) nommé `duo_auto_mode`. Activés par défaut.
  - Introduit dans [GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.22.0) 9.22.0.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

En mode auto, GitLab Duo utilise des outils sans demander d'approbation. Dans la limite de ce que vos paramètres autorisent, GitLab Duo peut effectuer les actions suivantes :

- Exécuter n'importe quelle commande shell, y compris des commandes qui suppriment des fichiers ou modifient votre système.
- Exécuter des commandes `git`, notamment des commits et des pushs.
- Créer ou mettre à jour des tickets, des merge requests et d'autres ressources GitLab.
- Exécuter des outils MCP et démarrer des flows.

Le mode auto ne remplace pas la [gouvernance des outils des agents](../ai-governance/tool-governance.md). Les outils définis sur **Toujours refuser** restent bloqués.

> [!warning]
> GitLab Duo peut faire des erreurs. Tout contenu que GitLab Duo lit, comme des fichiers, des tickets, des merge requests ou des pages web, peut contenir des instructions malveillantes utilisées pour une injection de prompt. Pour limiter le risque :
>
> - Utilisez le mode auto uniquement dans des dépôts de confiance et sur des branches que vous pouvez supprimer.
> - N'utilisez pas le mode auto sur des appareils ou dans des shells contenant des identifiants sensibles.
> - Restez dans la session et vérifiez toutes les modifications avant de merger.
> - Repassez en mode build lorsque vous n'avez pas besoin du mode auto.
>
> Pour plus d'informations, consultez [les considérations de sécurité pour les extensions d'éditeur](../../editor_extensions/security_considerations.md).

#### Activer le mode auto {#turn-on-auto-mode}

Le paramètre **Mode auto** est désactivé par défaut. Le mode auto doit être activé pour votre instance, groupe ou projet avant de pouvoir l'utiliser. Les groupes héritent du paramètre de l'instance, et les sous-groupes et projets héritent du paramètre de leur groupe parent.

{{< tabs >}}

{{< tab title="Instance" >}}

Prérequis :

- Disposer d'un accès administrateur.

Pour activer le mode auto pour une instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Dans la liste déroulante **Mode auto**, sélectionnez l'une des options suivantes :
   - **Activé par défaut** : le mode auto est disponible. Les groupes et sous-groupes peuvent le désactiver.
   - **Désactivé(e) par défaut** : le mode auto n'est pas disponible. Les groupes et sous-groupes peuvent l'activer.
   - **Toujours désactivé** : le mode auto n'est pas disponible. Les groupes et sous-groupes ne peuvent pas l'activer.
1. Sélectionnez **Enregistrer les modifications**.

{{< /tab >}}

{{< tab title="Groupe" >}}

Prérequis :

- Le rôle Propriétaire pour le groupe.

Pour activer le mode auto pour un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Sélectionnez **Paramètres** > **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Dans la liste déroulante **Mode auto**, sélectionnez l'une des options suivantes :
   - **Activé par défaut** : le mode auto est disponible. Les sous-groupes et projets peuvent le désactiver.
   - **Désactivé(e) par défaut** : le mode auto n'est pas disponible. Les sous-groupes et projets peuvent l'activer.
   - **Toujours désactivé** : le mode auto n'est pas disponible. Les sous-groupes et projets ne peuvent pas l'activer.
1. Sélectionnez **Enregistrer les modifications**.

{{< /tab >}}

{{< tab title="Projet" >}}

Si un groupe parent a défini le mode auto sur **Toujours désactivée**, le paramètre du projet est verrouillé et ne peut pas être activé.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour activer le mode auto pour un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Sélectionnez **Paramètres** > **Généralités**.
1. Développez **GitLab Duo**.
1. Activez le bouton **Mode auto**.
1. Sélectionnez **Enregistrer les modifications**.

{{< /tab >}}

{{< /tabs >}}

#### Utiliser le mode auto {#use-auto-mode}

Prérequis :

- GitLab Duo CLI 9.22.0 ou une version ultérieure.
- Le mode auto activé pour votre projet.

Pour utiliser le mode auto :

1. Démarrez ou redémarrez GitLab Duo CLI dans votre projet pour prendre en compte le paramètre.
1. Appuyez sur <kbd>Tab</kbd> jusqu'à ce que le mode sous l'invite `>` affiche `auto`.
1. Saisissez votre invite. Le mode auto s'applique à partir de cette invite et pour toutes les suivantes.

Pour arrêter d'utiliser le mode auto, appuyez sur <kbd>Tab</kbd> pour passer à un autre mode. La modification s'applique à votre prochaine invite.

Le mode auto ne persiste pas entre les sessions. Chaque nouvelle session ou session reprise, y compris une session démarrée avec `/new`, démarre en mode build.

#### Dépannage du mode auto {#troubleshooting-auto-mode}

Si `auto` n'apparaît pas lorsque vous appuyez sur <kbd>Tab</kbd> :

1. Vérifiez que le paramètre **Mode auto** est activé pour votre projet.
1. Vérifiez qu'aucun groupe parent n'est défini sur **Toujours désactivée**.
1. Redémarrez GitLab Duo CLI.

## Mode headless {#headless-mode}

> [!caution]
> Utilisez le mode headless avec prudence et dans un [environnement sandbox](../../editor_extensions/security_considerations.md#use-development-containers-for-isolation) contrôlé.

Pour exécuter un workflow en mode non interactif, utilisez la commande correspondant à votre configuration :

{{< tabs >}}

{{< tab title="glab" >}}

Utilisez `glab duo cli run` :

```shell
glab duo cli run --goal "Your goal or prompt here"
```

Par exemple, vous pouvez exécuter une commande ESLint et rediriger les erreurs vers GitLab Duo CLI pour les résoudre :

```shell
glab duo cli run --goal "Fix these errors: $eslint_output"
```

{{< /tab >}}

{{< tab title="duo" >}}

Utilisez `duo run` :

```shell
duo run --goal "Your goal or prompt here"
```

Par exemple, vous pouvez exécuter une commande ESLint et rediriger les erreurs vers GitLab Duo CLI pour les résoudre :

```shell
duo run --goal "Fix these errors: $eslint_output"
```

{{< /tab >}}

{{< /tabs >}}

Lorsque vous utilisez le mode headless, GitLab Duo CLI :

- Dans GitLab 19.4 et les versions ultérieures, exécute le [flow Developer](../project/merge_requests/developer.md#use-the-flow-in-the-gitlab-duo-cli).
- Contourne les approbations manuelles des outils et approuve automatiquement tous les outils pour utilisation.
- Ne maintient pas le contexte des conversations précédentes. Un nouveau workflow démarre à chaque fois que vous exécutez la commande `run`.

## Fournir des images comme contexte {#provide-images-as-context}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v9.27.0) dans GitLab Duo CLI 9.27.0, lors de la release GitLab 19.5, [avec un feature flag](../../administration/feature_flags/_index.md) nommé `dap_tool_image_input`. Activés par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Prérequis :

- GitLab Duo CLI 9.27.0 ou une version ultérieure.
- Utilisez un modèle géré par GitLab. Les modèles que vous hébergez vous-même ne sont pas pris en charge.

Lorsque vous exécutez GitLab Duo CLI localement en mode interactif ou headless, GitLab Duo peut lire des images et les utiliser comme contexte. La CLI peut lire :

- Les fichiers image dans le dépôt.
- Les images jointes à un ticket, une merge request ou un commentaire dans le même projet.

Vous ne pouvez pas téléverser une image directement dans votre invite. Indiquez plutôt une image qui existe déjà :

- Pour un fichier dans le dépôt, indiquez le chemin du fichier. Par exemple, `docs/architecture.png`.
- Pour une pièce jointe, indiquez la référence de téléversement telle qu'elle apparaît dans le Markdown. Par exemple, `/uploads/<secret>/screenshot.png`.

### Exigences relatives aux images {#image-requirements}

Pour utiliser une image comme contexte, l'image doit satisfaire aux exigences suivantes :

- Format : fichier PNG, JPEG ou WebP
- Taille : 10 Mo ou moins
- Dimensions : pas plus de 8 000 pixels de large ou de hauteur

### Exemples de prompts {#example-prompts}

Vous pouvez demander à GitLab Duo CLI de corriger un bug d'interface affiché dans une capture d'écran jointe à un ticket :

```plaintext
Look at the screenshot attached to issue 1234 and fix the alignment bug it shows.
```

Vous pouvez demander à GitLab Duo CLI d'expliquer un diagramme d'architecture :

```plaintext
Read docs/architecture.png, explain the data flow, and identify any single points of failure.
```

Vous pouvez demander à GitLab Duo CLI de transformer une photo de tableau blanc en document de conception :

```plaintext
Read whiteboard.jpg and turn it into a design document in docs/design.md.
```

## Sélectionner un modèle {#select-a-model}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.68.0) de l'option de sélection de modèle et de la variable d'environnement dans GitLab Duo CLI 8.68.0, lors de la release GitLab 18.10
- [Introduction](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.76.0) de la commande slash de sélection de modèle dans GitLab Duo CLI 8.76.0, lors de la release GitLab 18.10

{{< /history >}}

Vous pouvez sélectionner un modèle pour le mode interactif ou le mode headless.

### Pour le mode interactif {#for-interactive-mode}

Le modèle que vous sélectionnez persiste d'une session à l'autre, et vous pouvez changer de modèle en cours de conversation sans perdre le contexte.

Prérequis :

- GitLab Duo CLI 8.76.0 ou version ultérieure

Pour sélectionner un modèle en mode interactif :

1. En mode interactif, saisissez `/model` et appuyez sur <kbd>Entrée</kbd>.
1. Utilisez les touches fléchées pour faire défiler la liste des modèles disponibles, ou saisissez un nom de modèle pour filtrer la liste.
1. Sélectionnez un modèle et appuyez sur <kbd>Entrée</kbd> pour y basculer.

### Pour le mode headless {#for-headless-mode}

Le modèle que vous sélectionnez ne persiste pas d'une session à l'autre.

Prérequis :

- GitLab Duo CLI 8.68.0 ou version ultérieure

Pour sélectionner un modèle en mode headless :

1. Trouvez le [`gitlab_identifier` pour le modèle](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/blob/HEAD/ai_gateway/model_selection/models.yml).
1. Lorsque vous exécutez GitLab Duo CLI, définissez l'option `--model` ou la variable d'environnement `GITLAB_DUO_MODEL` sur la valeur `gitlab_identifier`.

   {{< tabs >}}

   {{< tab title="glab" >}}

   Utilisez l'option `--model` :

   ```shell
   glab duo cli --model <gitlab_identifier_for_the_model>
   ```

   Utilisez la variable d'environnement `GITLAB_DUO_MODEL` :

   ```shell
   GITLAB_DUO_MODEL=<gitlab_identifier_for_the_model> glab duo cli
   ```

   Par exemple, pour utiliser [`GPT-5-Codex - OpenAI`](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/blob/HEAD/ai_gateway/model_selection/models.yml#L448) :

   ```shell
   glab duo cli --model gpt_5_codex
   ```

   ```shell
   GITLAB_DUO_MODEL=gpt_5_codex glab duo cli
   ```

   {{< /tab >}}

   {{< tab title="duo" >}}

   Utilisez l'option `--model` :

   ```shell
   duo --model <gitlab_identifier_for_the_model>
   ```

   Utilisez la variable d'environnement `GITLAB_DUO_MODEL` :

   ```shell
   GITLAB_DUO_MODEL=<gitlab_identifier_for_the_model> duo
   ```

   Par exemple, pour utiliser [`GPT-5-Codex - OpenAI`](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/blob/HEAD/ai_gateway/model_selection/models.yml#L448) :

   ```shell
   duo --model gpt_5_codex
   ```

   ```shell
   GITLAB_DUO_MODEL=gpt_5_codex duo
   ```

   {{< /tab >}}

   {{< /tabs >}}

## Changer de session {#switch-sessions}

Les sessions GitLab Duo Chat stockent l'historique de vos conversations et les données de workflow, et sont partagées entre GitLab Duo CLI, l'interface GitLab et les extensions d'éditeur.

Par exemple, vous pouvez démarrer une conversation dans votre navigateur et la poursuivre dans votre terminal.

Pour parcourir et passer à une session :

1. En mode interactif, saisissez `/sessions` et appuyez sur <kbd>Entrée</kbd>.
1. Utilisez les touches fléchées pour faire défiler la liste des sessions disponibles, ou saisissez du texte pour filtrer la liste.
1. Sélectionnez une session et appuyez sur <kbd>Entrée</kbd>.

Pour passer à une session en mode headless, utilisez l'option `--existing-session-id`.

## Connexions Model Context Protocol (MCP) {#model-context-protocol-mcp-connections}

Pour connecter GitLab Duo CLI à des serveurs MCP locaux ou distants, utilisez la même configuration MCP que les extensions GitLab IDE. Pour obtenir des instructions, voir [configurer les serveurs MCP](../gitlab_duo/model_context_protocol/mcp_clients.md#configure-mcp-servers).

## Sujets connexes {#related-topics}

- [Référence complète de GitLab Duo CLI](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/blob/main/packages/cli/app/docs/cli-reference.md)
- [Considérations de sécurité pour les extensions d'éditeur](../../editor_extensions/security_considerations.md)
- [GitLab CLI](https://docs.gitlab.com/cli/)
- [Personnaliser GitLab Duo Agent Platform](../duo_agent_platform/customize/_index.md)
- [Sessions de GitLab Duo Agent Platform](../duo_agent_platform/sessions/_index.md)

## Dépannage {#troubleshooting}

Lorsque vous utilisez GitLab Duo CLI, vous pouvez rencontrer les problèmes suivants.

### Erreurs de certificat {#certificate-errors}

Vous pouvez rencontrer des erreurs de certificat :

```plaintext
Error: unable to verify the first certificate
Error: self-signed certificate in certificate chain
```

Ces erreurs se produisent si votre organisation utilise une autorité de certification (CA) personnalisée pour un proxy d'interception HTTPS ou similaire.

Pour résoudre les erreurs de certificat, utilisez l'une des méthodes suivantes :

- Utiliser le magasin de certificats système (recommandé) :
  1. Si votre certificat CA est installé dans le magasin de certificats de votre système d'exploitation, configurez Node.js pour l'utiliser. Nécessite Node.js 22.15.0, 23.9.0 ou 24.0.0 et versions ultérieures.
  1. Si vous exécutez GitLab Duo CLI dans un conteneur, installez le certificat CA dans le magasin système du conteneur, et non dans le magasin système hôte.

     ```shell
     export NODE_OPTIONS="--use-system-ca"
     ```

- Spécifier un fichier de certificat CA :
  1. Pour les versions plus anciennes de Node.js, ou lorsque le certificat CA n'est pas dans le magasin système, indiquez directement à Node.js le chemin du fichier de certificat. Le fichier doit être au format PEM.
  1. Si vous exécutez GitLab Duo CLI dans un conteneur, définissez le chemin vers un emplacement dans le conteneur. Utilisez un montage de volume pour fournir le fichier de certificat.

     ```shell
     export NODE_EXTRA_CA_CERTS=/path/to/custom-ca.pem
     ```

### Ignorer les erreurs de certificat {#ignore-certificate-errors}

Si vous rencontrez encore des erreurs de certificat, vous pouvez désactiver la vérification des certificats.

> [!warning]
> La désactivation de la vérification des certificats est un risque de sécurité. Vous ne devez pas désactiver la vérification dans les environnements de production.

Les erreurs de certificat vous alertent sur des failles de sécurité potentielles. Vous ne devez donc désactiver la vérification des certificats que lorsque vous êtes certain que cette désactivation est sans risque.

Prérequis :

- Vous avez vérifié la chaîne de certificats dans votre navigateur, ou votre administrateur a confirmé que cette erreur peut être ignorée sans risque.

Pour désactiver la vérification des certificats :

```shell
export NODE_TLS_REJECT_UNAUTHORIZED=0
```
