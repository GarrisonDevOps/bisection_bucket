---
stage: Agent Foundations
group: Agent Developer
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Fichiers de personnalisation AGENTS.md
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Prise en charge de `AGENTS.md` dans GitLab Duo Chat [introduite](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/merge_requests/2597) dans GitLab 18.7.
  - [Introduit](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.60.0) dans GitLab pour VS Code 6.60.0.
  - [Introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.26.0) dans le plugin GitLab Duo pour les IDE JetBrains 3.26.0.
  - [Introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/releases/v8.47.0) dans GitLab Duo CLI 8.47.0.
- Prise en charge de `AGENTS.md` dans les flows agentiques [introduite](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/issues/1509) dans GitLab 18.8.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273) dans GitLab 18.8.
- Prise en charge de l'interface utilisateur GitLab [introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/593279) dans GitLab 18.11.

{{< /history >}}

GitLab Duo prend en charge la [spécification `AGENTS.md`](https://agents.md/), une norme émergente pour fournir du contexte et des instructions aux assistants de codage IA.

Utilisez les fichiers `AGENTS.md` pour documenter la structure de votre dépôt, les conventions de codage, les directives de style, les instructions de compilation et de test, ainsi que le contexte du projet. Lorsque vous spécifiez un fichier `AGENTS.md`, ces informations sont disponibles pour la plateforme d'agents GitLab Duo et tout autre outil d'IA prenant en charge la spécification.

Spécifiez les fichiers `AGENTS.md` que GitLab Duo doit utiliser avec :

- GitLab Duo Chat dans l'interface utilisateur GitLab et votre environnement local.
- Les flows fondamentaux et les flows personnalisés, à l'exclusion du flow Code Review.

## Comment GitLab Duo utilise les fichiers `AGENTS.md` {#how-gitlab-duo-uses-agentsmd-files}

Vous pouvez créer des fichiers `AGENTS.md` à plusieurs niveaux, selon la façon dont vous utilisez GitLab Duo :

| Niveau                                                           | Interface utilisateur GitLab | Extensions de l'éditeur | GitLab Duo CLI |
|-----------------------------------------------------------------|--------------------------|------------------|--------------|
| Niveau utilisateur : s'applique à tous vos projets        | {{< no >}}  |  {{< yes >}}    | {{< yes >}} |
| Niveau projet : s'applique uniquement à un projet spécifique  | {{< yes >}} | {{< yes >}}         | {{< yes >}} |
| Niveau sous-répertoire : s'applique uniquement à un projet spécifique dans un monorepo ou dans un projet avec des composants distincts | {{< no >}} | {{< yes >}} | {{< yes >}} |

Si vous utilisez un workspace multi-root dans votre IDE, vous pouvez créer des fichiers `AGENTS.md` au niveau du projet pour chaque projet dans le workspace.

GitLab Duo combine les instructions disponibles des fichiers `AGENTS.md` au niveau utilisateur et au niveau projet pour toutes les conversations. Si une tâche nécessite de travailler avec des fichiers dans un répertoire contenant un fichier `AGENTS.md` supplémentaire, Chat applique également ces instructions.

## Utiliser `AGENTS.md` avec GitLab Duo {#use-agentsmd-with-gitlab-duo}

> [!note]
> Seules les nouvelles conversations et les nouveaux flows créés après l'ajout ou la mise à jour des fichiers `AGENTS.md` suivent les nouvelles instructions. Les conversations précédemment existantes ne le font pas.

### Prérequis {#prerequisites}

- Satisfaire les [prérequis de la plateforme d'agents](../_index.md#prerequisites).
- Pour utiliser GitLab Duo Chat dans votre environnement local, installez et configurez l'un des éléments suivants :
  - [GitLab pour VS Code](../../../editor_extensions/visual_studio_code/setup.md) 6.60 ou version ultérieure.
  - [Plugin GitLab Duo pour les IDE JetBrains](../../../editor_extensions/jetbrains_ide/setup.md) 3.26.0 ou version ultérieure.
  - [GitLab Duo CLI](../../gitlab_duo_cli/set_up.md) 8.47.0 ou version ultérieure.
- Pour les flows personnalisés, mettez à jour le fichier de configuration du flow pour accéder au contexte `user_rule` transmis par l'exécuteur :

  ```yaml
  components:
  - name: "my_agent"
     type: AgentComponent
     prompt_id: "my_prompt"
     inputs:
     - from: "context:inputs.user_rule"
        as: "agents_dot_md"
      optional: true
  ```

  En définissant `optional: true`, le flow gère de manière transparente les cas où aucun fichier `AGENTS.md` n'existe. L'agent fonctionne avec ou sans contexte supplémentaire.

### Créer des fichiers `AGENTS.md` au niveau utilisateur {#create-user-level-agentsmd-files}

Les fichiers `AGENTS.md` au niveau utilisateur s'appliquent à tous vos projets.

1. Créez un fichier `AGENTS.md` dans votre répertoire personnel :
   - Sous Linux ou macOS, créez le fichier à l'emplacement `~/.gitlab/duo/AGENTS.md`.
   - Sous Windows, créez le fichier à l'emplacement `%APPDATA%\GitLab\duo\AGENTS.md`.
1. Ajoutez des instructions dans le fichier. Par exemple :

   {{< tabs >}}

   {{< tab title="Préférences personnelles" >}}

   ```markdown
   # My personal coding preferences

   - Always explain code changes in simple terms for beginners
   - Use descriptive variable names
   - Add comments for complex logic
   - Prefer functional programming patterns when appropriate
   ```

   {{< /tab >}}

   {{< tab title="Standards d'équipe" >}}

   ```markdown
   # Team coding standards

   - Follow our company's style guide for all code
   - Use TypeScript strict mode
   - Write unit tests for all new functions
   - Document all public APIs with JSDoc
   ```

   {{< /tab >}}

   {{< tab title="Contexte monorepo" >}}

   ```markdown
   # Monorepo context

   - This is a monorepo with multiple services
   - Frontend code is in /apps/web
   - Backend services are in /services
   - Shared libraries are in /packages
   - Follow the architecture decision records in /docs/adr
   ```

   {{< /tab >}}

   {{< tab title="Directives de sécurité" >}}

   ```markdown
   # Security review guidelines

   - Always validate user input
   - Use parameterized queries for database operations
   - Implement proper authentication and authorization
   - Follow OWASP security best practices
   - Never log sensitive information
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. Enregistrez le fichier.
1. Pour appliquer les instructions, démarrez une nouvelle conversation ou un nouveau flow. Vous devez effectuer cette opération chaque fois que vous modifiez le fichier `AGENTS.md`.

Si vous avez défini une variable d'environnement spécifique, créez le fichier `AGENTS.md` à un emplacement différent :

- Si vous avez défini la variable d'environnement `GLAB_CONFIG_DIR`, créez le fichier à l'emplacement `$GLAB_CONFIG_DIR/AGENTS.md`.
- Si vous avez défini la variable d'environnement `XDG_CONFIG_HOME`, créez le fichier à l'emplacement `$XDG_CONFIG_HOME/gitlab/duo/AGENTS.md`.

### Créer des fichiers `AGENTS.md` au niveau du projet {#create-project-level-agentsmd-files}

Les fichiers `AGENTS.md` au niveau du projet s'appliquent uniquement à un projet spécifique.

1. À la racine de votre projet, créez un fichier `AGENTS.md`.
1. Ajoutez des instructions dans le fichier. Par exemple :

   {{< tabs >}}

   {{< tab title="Directives du projet" >}}

   ```markdown
   # Project-specific guidelines

   - This project uses React with TypeScript
   - Follow the component structure in /src/components
   - Use our custom hooks from /src/hooks
   - State management uses Redux Toolkit
   ```

   {{< /tab >}}

   {{< tab title="Migrations de base de données" >}}

   ```markdown
   # Database migrations

   - To run database migrations, use `bin/rails db:migrate` from the project root
   - Do not run `rake db:migrate` directly
   - If a migration fails with a lock timeout, wait and retry once. Do not attempt
     a schema workaround
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. Enregistrez le fichier.
1. Pour appliquer les instructions, démarrez une nouvelle conversation ou un nouveau flow. Vous devez effectuer cette opération chaque fois que vous modifiez le fichier `AGENTS.md`.

### Créer des fichiers `AGENTS.md` dans les monorepos et les sous-répertoires {#create-agentsmd-files-in-monorepos-and-subdirectories}

Pour les monorepos ou les projets avec des composants distincts, vous pouvez placer des fichiers `AGENTS.md` dans des sous-répertoires afin de fournir des instructions spécifiques au contexte pour différentes parties de votre base de code.

Lorsque GitLab Duo Chat découvre des fichiers `AGENTS.md` supplémentaires dans des sous-répertoires, il lit le fichier pertinent avant de modifier les fichiers dans ce répertoire. Par exemple :

```plaintext
/my-project
  AGENTS.md              # Root instructions (included in all conversations)
  /frontend
    AGENTS.md            # Frontend-specific instructions
  /backend
    AGENTS.md            # Backend-specific instructions
```

Dans cet exemple :

- Le fichier `AGENTS.md` racine est toujours inclus dans les conversations.
- Lorsque GitLab Duo modifie des fichiers dans `/frontend`, il lit d'abord `/frontend/AGENTS.md`.
- Lorsque GitLab Duo modifie des fichiers dans `/backend`, il lit d'abord `/backend/AGENTS.md`.

Cette approche permet de s'assurer que GitLab Duo respecte les conventions appropriées pour chaque partie de votre projet.

Pour utiliser `AGENTS.md` dans un sous-répertoire :

1. Dans un sous-répertoire de votre projet, créez un fichier `AGENTS.md`.
1. Ajoutez des instructions spécifiques à ce répertoire. Par exemple, pour un service backend :

   ```markdown
   # Backend service guidelines

   - This service uses Node.js with Express
   - Follow RESTful API conventions
   - Use async/await for asynchronous operations
   - Validate all inputs with Joi schemas
   ```

1. Enregistrez le fichier.
1. Pour appliquer les instructions, démarrez une nouvelle conversation impliquant des fichiers dans ce répertoire. Vous devez effectuer cette opération chaque fois que vous modifiez le fichier `AGENTS.md`.

## Sujets connexes {#related-topics}

- [Règles personnalisées](custom_rules.md)
