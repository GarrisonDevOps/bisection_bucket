---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 'Tutoriel : Créez, enregistrez et exécutez votre propre runner de projet'
---

<!-- vale gitlab_base.FutureTense = NO -->

Ce tutoriel vous montre comment configurer et exécuter votre premier runner dans GitLab.

Un runner est un agent de l'application GitLab Runner qui exécute des jobs dans un pipeline CI/CD GitLab. Les jobs sont définis dans le fichier `.gitlab-ci.yml` et assignés aux runners disponibles.

GitLab propose trois types de runners :

- Partagé : disponible pour tous les groupes et projets d'une instance GitLab.
- Groupe : disponible pour tous les projets et sous-groupes d'un groupe.
- Projet : associé à des projets spécifiques. En règle générale, les runners de projet sont utilisés par un seul projet à la fois.

Dans ce tutoriel, vous allez créer un runner de projet pour exécuter des jobs définis dans une configuration de pipeline basique :

1. [Créer un projet vide](#create-a-blank-project)
1. [Créer un pipeline de projet](#create-a-project-pipeline).
1. [Créer et enregistrer un runner de projet](#create-and-register-a-project-runner).
1. [Déclencher un pipeline pour exécuter votre runner](#trigger-a-pipeline-to-run-your-runner).

## Avant de commencer {#before-you-begin}

Avant de pouvoir créer, enregistrer et exécuter un runner, vous devez [installer GitLab Runner](https://docs.gitlab.com/runner/install/) sur un ordinateur local.

## Créer un projet vide {#create-a-blank-project}

Commencez par créer un projet vide dans lequel vous pourrez créer votre pipeline CI/CD et votre runner.

Pour créer un projet vide :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer un projet vide**.
1. Saisissez les détails du projet :
   - Dans le champ **Nom du projet**, saisissez le nom de votre projet. Le nom doit commencer par une lettre minuscule ou majuscule (`a-zA-Z`), un chiffre (`0-9`), un emoji ou un tiret bas (`_`). Il peut également contenir des points (`.`), des signes plus (`+`), des tirets (`-`) ou des espaces.
   - Dans le champ **Identifiant « slug » du projet**, saisissez le chemin d'accès à votre projet. L'instance GitLab utilise le slug comme chemin d'URL vers le projet. Pour modifier le slug, commencez par saisir le nom du projet, puis modifiez le slug.
1. Sélectionnez **Créer le projet**.

## Créer un pipeline de projet {#create-a-project-pipeline}

Ensuite, créez un fichier `.gitlab-ci.yml` pour votre projet. Il s'agit d'un fichier YAML dans lequel vous spécifiez les instructions pour GitLab CI/CD.

Dans ce fichier, vous définissez :

- La structure et l'ordre des jobs que le runner doit exécuter.
- Les décisions que le runner doit prendre lorsque des conditions spécifiques sont rencontrées.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Sélectionnez **Vue d'ensemble du projet**.
1. Sélectionnez l'icône plus ({{< icon name="plus" >}}), puis sélectionnez **Nouveau fichier**.
1. Dans le champ **Nom du fichier**, saisissez `.gitlab-ci.yml`.
1. Dans la grande zone de texte, collez cet exemple de configuration :

   ```yaml
   stages:
     - build
     - test

   job_build:
     stage: build
     script:
       - echo "Building the project"

   job_test:
     stage: test
     script:
       - echo "Running tests"
   ```

   Cette configuration comprend deux jobs que le runner exécute : un job de build et un job de test.
1. Sélectionnez **Valider les modifications**.

## Créer et enregistrer un runner de projet {#create-and-register-a-project-runner}

Ensuite, créez un runner de projet et enregistrez-le. Vous devez enregistrer le runner pour le lier à GitLab afin qu'il puisse récupérer des jobs depuis le pipeline de projet.

Pour créer un runner de projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD**.
1. Développez la section **Runners**.
1. Sélectionnez **Créer un runner de projet**.
1. Dans la section **Étiquettes**, cochez la case **Exécuter sans étiquette**. [Les étiquettes](../../ci/runners/configure_runners.md#control-jobs-that-a-runner-can-run) indiquent les jobs que le runner peut exécuter et sont facultatives.
1. Sélectionnez **Créer un runner**.
1. Sélectionnez votre système d'exploitation.
1. Suivez les instructions à l'écran pour enregistrer le runner depuis la ligne de commande. Lorsque vous y êtes invité :
   - Pour `executor`, étant donné que votre runner s'exécutera directement sur l'ordinateur hôte, saisissez `shell`. L'[exécuteur](https://docs.gitlab.com/runner/executors/) est l'environnement dans lequel le runner exécute le job.
   - Pour `GitLab instance URL`, utilisez l'URL de votre instance GitLab. Par exemple, si votre projet est hébergé sur `gitlab.example.com/yourname/yourproject`, alors l'URL de votre instance GitLab est `https://gitlab.example.com`. Si votre projet est hébergé sur GitLab.com, l'URL est `https://gitlab.com`.
1. Démarrez votre runner :

   ```shell
   gitlab-runner run
   ```

### Vérifier le fichier de configuration du runner {#check-the-runner-configuration-file}

Une fois le runner enregistré, la configuration et le jeton d'authentification du runner sont enregistrés dans votre `config.toml`. Le runner utilise le jeton pour s'authentifier auprès de GitLab lors de la récupération des jobs depuis la file d'attente des jobs.

Vous pouvez utiliser le `config.toml` pour définir des [configurations avancées du runner](https://docs.gitlab.com/runner/configuration/advanced-configuration/).

Voici à quoi devrait ressembler votre `config.toml` après avoir enregistré et démarré le runner :

```toml
[[runners]]
  name = "my-project-runner1"
  url = "http://127.0.0.1:3000"
  id = 38
  token = "glrt-TOKEN"
  token_obtained_at = 2023-07-05T08:56:33Z
  token_expires_at = 0001-01-01T00:00:00Z
  executor = "shell"
```

## Déclencher un pipeline pour exécuter votre runner {#trigger-a-pipeline-to-run-your-runner}

Ensuite, déclenchez un pipeline dans votre projet afin de visualiser l'exécution d'un job par votre runner.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**.
1. Sélectionnez **Nouveau pipeline**.
1. Sélectionnez un job pour afficher le job log. La sortie doit ressembler à cet exemple, qui montre votre runner exécutant le job avec succès :

   ```shell
      Running with gitlab-runner 18.0.0 (d7f2cea7)
      on my-project-runner TOKEN, system ID: SYSTEM ID
      Preparing the "shell" executor
      00:00
      Using Shell (bash) executor...
      Preparing environment
      00:00
      /Users/username/.bash_profile: line 9: setopt: command not found
      Running on MACHINE-NAME...
      Getting source from Git repository
      00:01
      /Users/username/.bash_profile: line 9: setopt: command not found
      Fetching changes with git depth set to 20...
      Reinitialized existing Git repository in /Users/username/project-repository
      Checking out 7226fc70 as detached HEAD (ref is main)...
      Skipping object checkout, Git LFS is not installed for this repository.
      Consider installing it with 'git lfs install'.
      Skipping Git submodules setup
      Executing "step_script" stage of the job script
      00:00
      /Users/username/.bash_profile: line 9: setopt: command not found
      $ echo "Building the project"
      Building the project
      Job succeeded

   ```

Vous avez maintenant créé, enregistré et exécuté votre premier runner avec succès !
