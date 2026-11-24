---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 'Tutoriel : créer un site web GitLab Pages de zéro'
description: "Créez un site web GitLab Pages à partir d'un projet vide avec Jekyll et une configuration CI/CD personnalisée."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Ce tutoriel vous montre comment créer un site Pages de zéro à l'aide du générateur de site statique (SSG) [Jekyll](https://jekyllrb.com/). Vous commencez avec un projet vide et créez votre propre fichier de configuration CI/CD, qui donne des instructions à un [runner](https://docs.gitlab.com/runner/). Lorsque votre [pipeline](../../../../ci/pipelines/_index.md) CI/CD s'exécute, le site Pages est créé.

Cet exemple utilise Jekyll, mais les autres SSG suivent des étapes similaires. Vous n'avez pas besoin de connaître Jekyll ou les SSG pour suivre ce tutoriel.

> [!note]
> Pour créer un site Pages en HTML brut, consultez le tutoriel [Créer un site web GitLab Pages à partir d'un modèle CI/CD](pages_ci_cd_template.md). Pour obtenir la liste des modèles disponibles, consultez [les modèles de projet](pages_new_project_template.md#project-templates).

Pour créer un site web GitLab Pages :

- [Étape 1 : créer les fichiers du projet](#create-the-project-files)
- [Étape 2 : choisir une image Docker](#choose-a-docker-image)
- [Étape 3 : installer Jekyll](#install-jekyll)
- [Étape 4 : spécifier le répertoire `public` pour la sortie](#specify-the-public-directory-for-output)
- [Étape 5 : spécifier le répertoire `public` pour les artefacts](#specify-the-public-directory-for-artifacts)
- [Étape 6 : déployer et afficher votre site web](#deploy-and-view-your-website)

## Avant de commencer {#before-you-begin}

Vous devez disposer d'un [projet vide](../../_index.md#create-a-blank-project) dans GitLab.

## créer les fichiers du projet {#create-the-project-files}

Créez trois fichiers dans le répertoire racine (niveau supérieur) :

- `.gitlab-ci.yml` : un fichier YAML qui contient les commandes que vous souhaitez exécuter. Pour l'instant, laissez le contenu du fichier vide.

- `index.html` : un fichier HTML non vide que vous pouvez remplir avec le contenu HTML de votre choix, par exemple :

  ```html
  <html>
  <head>
    <title>Home</title>
  </head>
  <body>
    <h1>Hello World!</h1>
  </body>
  </html>
  ```

- [`Gemfile`](https://bundler.io/gemfile.html) : un fichier qui décrit les dépendances des programmes Ruby.

  Remplissez-le avec ce contenu :

  ```ruby
  source "https://rubygems.org"

  gem "jekyll"
  ```

## choisir une image Docker {#choose-a-docker-image}

Dans cet exemple, le runner utilise une [image Docker](../../../../ci/docker/using_docker_images.md) pour exécuter des scripts et déployer le site.

Cette image Ruby spécifique est maintenue sur [DockerHub](https://hub.docker.com/_/ruby).

Ajoutez une image par défaut à votre pipeline en ajoutant cette configuration CI/CD au début de votre fichier `.gitlab-ci.yml` :

```yaml
default:
  image: ruby:3.2
```

Si votre SSG a besoin de [NodeJS](https://nodejs.org/) pour la compilation, vous devez spécifier une image qui contient NodeJS dans son système de fichiers. Par exemple, pour un site [Hexo](https://gitlab.com/pages/hexo), vous pouvez utiliser `image: node:12.17.0`.

## installer Jekyll {#install-jekyll}

Pour exécuter [Jekyll](https://jekyllrb.com/) localement, vous devez l'installer :

1. Ouvrez votre terminal.
1. Installez [Bundler](https://bundler.io/) en exécutant `gem install bundler`.
1. Créez `Gemfile.lock` en exécutant `bundle install`.
1. Installez Jekyll en exécutant `bundle exec jekyll build`.

Pour exécuter Jekyll dans votre projet, modifiez le fichier `.gitlab-ci.yml` et ajoutez les commandes d'installation :

```yaml
script:
  - gem install bundler
  - bundle install
  - bundle exec jekyll build
```

De plus, dans le fichier `.gitlab-ci.yml`, chaque `script` est organisé par un `job`. Un `job` inclut les scripts et les paramètres que vous souhaitez appliquer à cette tâche spécifique.

```yaml
job:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build
```

Pour GitLab Pages, ce `job` doit inclure une propriété appelée `pages`. Ce paramètre indique au runner que vous souhaitez que le job déploie votre site web avec GitLab Pages :

```yaml
create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build
  pages: true  # specifies that this is a Pages job
```

L'exemple de cette page utilise des [noms de job définis par l'utilisateur](../_index.md#user-defined-job-names).

## spécifier le répertoire `public` pour la sortie {#specify-the-public-directory-for-output}

Jekyll doit savoir où générer sa sortie. GitLab Pages ne prend en compte que les fichiers présents dans un répertoire appelé `public`.

Jekyll utilise un indicateur de destination (`-d`) pour spécifier un répertoire de sortie pour le site compilé. Ajoutez la destination à votre fichier `.gitlab-ci.yml` :

```yaml
create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job
```

## spécifier le répertoire `public` pour les artefacts {#specify-the-public-directory-for-artifacts}

{{< history >}}

- Ajout automatique du chemin `pages.publish` à `artifacts:paths` [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/428018) dans GitLab 17.10 pour les jobs Pages uniquement.

{{< /history >}}

Maintenant que Jekyll a généré les fichiers dans le répertoire `public`, le runner doit savoir où les récupérer. Dans GitLab 17.10 et versions ultérieures, pour les jobs Pages uniquement, le répertoire `public` est automatiquement ajouté à [`artifacts:paths`](../../../../ci/yaml/_index.md#artifactspaths) lorsque le chemin [`pages.publish`](../../../../ci/yaml/_index.md#pagespublish) n'est pas explicitement spécifié :

```yaml
create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
```

Votre fichier `.gitlab-ci.yml` devrait maintenant ressembler à ceci :

```yaml
default:
  image: ruby:3.2

create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
```

## déployer et afficher votre site web {#deploy-and-view-your-website}

Après avoir effectué les étapes précédentes, déployez votre site web :

1. Enregistrez et commitez le fichier `.gitlab-ci.yml`.
1. Accédez à **Version** > **Pipelines** pour surveiller le pipeline.
1. Une fois le pipeline terminé, accédez à **Déployer** > **Pages** pour trouver le lien vers votre site web Pages.

Lorsque ce job `pages` se termine avec succès, un job spécial `pages:deploy` apparaît dans la vue du pipeline. Il prépare le contenu du site web pour le démon GitLab Pages. GitLab l'exécute en arrière-plan et n'utilise pas de runner.

## Autres options pour votre fichier CI/CD {#other-options-for-your-cicd-file}

Si vous souhaitez effectuer des tâches plus avancées, vous pouvez mettre à jour votre fichier `.gitlab-ci.yml` avec d'[autres mots-clés YAML CI/CD](../../../../ci/yaml/_index.md). Vous pouvez valider votre fichier `.gitlab-ci.yml` avec l'outil [CI Lint](../../../../ci/yaml/lint.md) inclus dans GitLab.

Les sections suivantes présentent d'autres options que vous pouvez ajouter à votre fichier CI/CD.

### Déployer des branches spécifiques vers un site Pages {#deploy-specific-branches-to-a-pages-site}

Vous pouvez souhaiter déployer vers un site Pages uniquement à partir de branches spécifiques.

Commencez par ajouter une section `workflow` pour forcer le pipeline à s'exécuter uniquement lorsque des modifications sont poussées vers des branches :

```yaml
default:
  image: ruby:3.2

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH

create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
```

Configurez ensuite le pipeline pour exécuter le job uniquement pour la [branche par défaut](../../repository/branches/default.md) (ici, `main`).

```yaml
default:
  image: ruby:3.2

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH

create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

### Spécifier une étape pour le déploiement {#specify-a-stage-to-deploy}

Les trois étapes par défaut pour GitLab CI/CD sont la compilation (build), le test et le déploiement.

Si vous souhaitez tester votre script et vérifier le site compilé avant de le déployer en production, vous pouvez exécuter le test exactement tel qu'il s'exécute lorsque vous poussez vers votre [branche par défaut](../../repository/branches/default.md) (ici, `main`).

Pour spécifier une étape dans laquelle votre job s'exécutera, ajoutez une ligne `stage` à votre fichier CI :

```yaml
default:
  image: ruby:3.2

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH

create-pages:
  stage: deploy
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  environment: production
```

Ajoutez maintenant un autre job au fichier CI, en lui indiquant de tester chaque push vers chaque branche sauf la branche `main` :

```yaml
default:
  image: ruby:3.2

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH

create-pages:
  stage: deploy
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  environment: production

test:
  stage: test
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d test
  artifacts:
    paths:
      - test
  rules:
    - if: $CI_COMMIT_BRANCH != "main"
```

Lorsque le job `test` s'exécute dans l'étape `test`, Jekyll compile le site dans un répertoire appelé `test`. Le job affecte toutes les branches sauf `main`.

Le job `test` ne publie pas vers GitLab Pages, donc sa sortie est stockée uniquement en tant qu'artefact de job. Pour afficher le site compilé, [parcourez le contenu de l'archive des artefacts](../../../../ci/jobs/job_artifacts.md#browse-the-contents-of-the-artifacts-archive). Si GitLab Pages est activé pour votre instance, vous pouvez prévisualiser les fichiers `.html` directement dans votre navigateur. Pour un projet privé ou interne, un administrateur doit également activer le [contrôle d'accès GitLab Pages](../pages_access_control.md) pour l'instance.

Pour publier une branche en tant que site Pages distinct avec sa propre URL, utilisez plutôt les [déploiements parallèles](../parallel_deployments.md).

Lorsque vous appliquez des étapes à différents jobs, chaque job de la même étape est compilé en parallèle. Si votre application web nécessite plusieurs tests avant d'être déployée, vous pouvez exécuter tous vos tests simultanément.

### Supprimer les commandes dupliquées {#remove-duplicate-commands}

Pour éviter de dupliquer les mêmes commandes `before_script` dans chaque job, vous pouvez les ajouter à la section default.

Dans l'exemple, `gem install bundler` et `bundle install` s'exécutaient pour les deux jobs, `create-pages` et `test`.

Déplacez ces commandes vers la section `default` :

```yaml
default:
  image: ruby:3.2
  before_script:
    - gem install bundler
    - bundle install

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH

create-pages:
  stage: deploy
  script:
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  environment: production

test:
  stage: test
  script:
    - bundle exec jekyll build -d test
  artifacts:
    paths:
      - test
  rules:
    - if: $CI_COMMIT_BRANCH != "main"
```

### Compiler plus rapidement avec des dépendances en cache {#build-faster-with-cached-dependencies}

Pour compiler plus rapidement, vous pouvez mettre en cache les fichiers d'installation des dépendances de votre projet en utilisant le paramètre `cache`.

Cet exemple met en cache les dépendances Jekyll dans un répertoire `vendor` lorsque vous exécutez `bundle install` :

```yaml
default:
  image: ruby:3.2
  before_script:
    - gem install bundler
    - bundle install --path vendor
  cache:
    paths:
      - vendor/

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH


create-pages:
  stage: deploy
  script:
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  environment: production

test:
  stage: test
  script:
    - bundle exec jekyll build -d test
  artifacts:
    paths:
      - test
  rules:
    - if: $CI_COMMIT_BRANCH != "main"
```

Dans ce cas, vous devez exclure le répertoire `/vendor` de la liste des dossiers que Jekyll compile. Sinon, Jekyll tente de compiler le contenu du répertoire en même temps que le site.

Dans le répertoire racine, créez un fichier appelé `_config.yml` et ajoutez ce contenu :

```yaml
exclude:
  - vendor
```

Désormais, GitLab CI/CD ne se contente pas de compiler le site web, il effectue également les opérations suivantes :

- Pousse avec des tests continus vers les branches de fonctionnalités.
- Met en cache les dépendances installées avec Bundler.
- Déploie en continu chaque push vers la branche `main`.

Pour afficher le HTML et les autres ressources créés pour le site, [téléchargez les artefacts de job](../../../../ci/jobs/job_artifacts.md#download-job-artifacts).

L'exemple de cette page utilise des [noms de job définis par l'utilisateur](../_index.md#user-defined-job-names).

## Sujets connexes {#related-topics}

- [Déployer votre application web en staging et en production](https://about.gitlab.com/blog/ci-deployment-and-environments/)
- [Exécuter des jobs de manière séquentielle, en parallèle, ou créer un pipeline personnalisé](https://about.gitlab.com/blog/basics-of-gitlab-ci-updated/)
- [Extraire des répertoires spécifiques de différents projets](https://about.gitlab.com/blog/building-a-new-gitlab-docs-site-with-nanoc-gitlab-ci-and-gitlab-pages/)
- [Utiliser GitLab Pages pour produire un rapport de couverture de code](https://about.gitlab.com/blog/publish-code-coverage-report-with-gitlab-pages/)
