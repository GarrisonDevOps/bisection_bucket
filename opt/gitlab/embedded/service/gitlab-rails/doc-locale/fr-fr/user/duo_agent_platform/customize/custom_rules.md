---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Règles personnalisées
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Règles personnalisées [ajoutées](https://gitlab.com/gitlab-org/gitlab/-/issues/550743) dans GitLab 18.2.
  - [Introduit](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.32.2) dans GitLab for VS Code 6.32.2.
  - [Introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.12.2) dans le plugin GitLab Duo pour JetBrains IDEs 3.12.2.
  - [Introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-visual-studio-extension/-/releases/v0.60.0) dans GitLab for Visual Studio 0.60.0.
  - [Introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.43.0) dans GitLab Duo CLI 8.43.0.
- Règles personnalisées au niveau utilisateur [ajoutées](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/merge_requests/2452) dans GitLab 18.7.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273) dans GitLab 18.8.
- Prise en charge de l'interface utilisateur GitLab [introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/593279) dans GitLab 18.11.

{{< /history >}}

Vous pouvez utiliser des règles personnalisées dans la plateforme d'agents GitLab Duo pour vous assurer que les sorties générées (par exemple, du code ou de la documentation) sont conformes à vos instructions spécifiques, ou à toute autre exigence telle que des guides de style de développement.

Les fonctionnalités suivantes de la plateforme d'agents prennent en charge les règles personnalisées :

- [GitLab Duo Agentic Chat](../../gitlab_duo_chat/agentic_chat.md) dans l'interface utilisateur GitLab et votre environnement local.
- [Agents fondamentaux et personnalisés](../agents/_index.md).
- [Flows fondamentaux et personnalisés](../flows/_index.md), à l'exclusion du flow Code Review.

## Créer des règles personnalisées {#create-custom-rules}

Vous pouvez créer des règles personnalisées à deux niveaux, selon la façon dont vous utilisez GitLab Duo :

| Niveau                                                           | Interface utilisateur GitLab | Extensions d'éditeur | GitLab Duo CLI |
|-----------------------------------------------------------------|--------------------------|------------------|--------------|
| Niveau utilisateur : s'applique à tous vos projets        | {{< no >}}  |  {{< yes >}}    | {{< yes >}} |
| Niveau projet : s'applique uniquement à un projet spécifique  | {{< yes >}} | {{< yes >}}         | {{< yes >}} |

Si vous utilisez un workspace multi-racine dans votre IDE, vous pouvez créer des règles personnalisées au niveau du projet pour chaque projet dans le workspace.

Si des règles au niveau utilisateur et au niveau projet existent toutes les deux, GitLab Duo Chat applique les deux aux conversations.

Prérequis :

- Satisfaire les [prérequis de la plateforme d'agents](../_index.md#prerequisites).
- Pour GitLab Duo dans votre environnement local, installez et configurez l'un des éléments suivants :
  - [GitLab for VS Code](../../../editor_extensions/visual_studio_code/setup.md) 6.32.2 ou version ultérieure.
  - [Plugin GitLab Duo pour JetBrains IDEs](../../../editor_extensions/jetbrains_ide/setup.md) 3.12.2 ou version ultérieure.
  - [GitLab for Visual Studio](../../../editor_extensions/visual_studio/setup.md) 0.60.0 ou version ultérieure.
  - [GitLab Duo CLI](../../gitlab_duo_cli/set_up.md) 8.43.0 ou version ultérieure.

> [!note]
> Les conversations créées avant que vous n'ayez défini des règles personnalisées ne suivent pas ces règles.

### Créer des règles personnalisées au niveau utilisateur {#create-user-level-custom-rules}

Les règles personnalisées au niveau utilisateur s'appliquent à tous vos projets dans votre environnement local.

1. Créez un fichier de règles personnalisées dans votre répertoire home :
   - Sous Linux ou macOS, créez le fichier à l'emplacement `~/.gitlab/duo/chat-rules.md`.
   - Sous Windows, créez le fichier à l'emplacement `%APPDATA%\GitLab\duo\chat-rules.md`.
1. Ajoutez des règles personnalisées au fichier. Par exemple :

   ```markdown
   - Don't put comments in the generated code
   - Be brief in your explanations
   - Always use single quotes for JavaScript strings
   ```

1. Enregistrez le fichier.
1. Pour appliquer les nouvelles règles personnalisées, effectuez l'une des actions suivantes selon le cas :
   - Démarrez une nouvelle conversation GitLab Duo Chat.
   - Utilisez un agent dans une conversation Chat, une discussion, un ticket ou une merge request.
   - Déclenchez un flow.

Si vous avez défini une variable d'environnement spécifique, vous devez créer le fichier de règles personnalisées dans un emplacement différent :

- Si vous avez défini la variable d'environnement `GLAB_CONFIG_DIR`, créez le fichier à l'emplacement `$GLAB_CONFIG_DIR/chat-rules.md`.
- Si vous avez défini la variable d'environnement `XDG_CONFIG_HOME`, créez le fichier à l'emplacement `$XDG_CONFIG_HOME/gitlab/duo/chat-rules.md`.

### Créer des règles personnalisées au niveau du projet {#create-project-level-custom-rules}

Les règles personnalisées au niveau du projet s'appliquent uniquement à un projet spécifique. Vous pouvez utiliser cette méthode pour appliquer un ensemble de règles personnalisées au projet pour votre équipe. Par exemple, vous pouvez appliquer un ensemble de guides de style de développement utilisés par votre équipe.

1. À la racine de votre projet, créez un fichier de règles personnalisées : `.gitlab/duo/chat-rules.md`.
1. Ajoutez des règles personnalisées au fichier. Par exemple :

   ```markdown
   - Don't put comments in the generated code
   - Be brief in your explanations
   - Always use single quotes for JavaScript strings
   ```

1. Enregistrez le fichier.
1. Pour un projet : ajoutez le fichier `.gitlab/duo/chat-rules.md` au dépôt Git. Chat, les agents et les flows lisent alors automatiquement les règles personnalisées depuis le dépôt dans le contexte.
1. Pour appliquer les nouvelles règles personnalisées, démarrez une nouvelle conversation GitLab Duo.

   Vous devez effectuer cette opération à chaque fois que vous modifiez les règles personnalisées.

Pour plus d'informations, consultez le [blog de tutoriel sur les règles personnalisées dans GitLab Duo Chat](https://about.gitlab.com/blog/custom-rules-duo-agentic-chat-deep-dive/).

## Mettre à jour les règles personnalisées {#update-custom-rules}

Pour mettre à jour vos règles personnalisées, modifiez et enregistrez le fichier de règles personnalisées. Ensuite, démarrez une nouvelle conversation GitLab Duo pour appliquer les règles mises à jour.

Vous ne pouvez pas utiliser Chat pour modifier directement votre fichier de règles personnalisées.

Pour gérer les personnes devant approuver les modifications apportées aux règles personnalisées, utilisez les [propriétaires du code](../../project/codeowners/_index.md).

## Sujets connexes {#related-topics}

- [Fichiers de personnalisation AGENTS.md](agents_md.md)
- [compétences d'agent](agent_skills.md)
