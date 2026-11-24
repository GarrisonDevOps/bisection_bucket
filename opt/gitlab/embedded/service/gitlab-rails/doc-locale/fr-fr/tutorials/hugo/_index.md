---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 'Tutoriel : créer, tester et déployer votre site Hugo avec GitLab'
description: "Créez, testez et déployez un site statique Hugo sur GitLab Pages avec un pipeline CI/CD."
---

<!-- vale gitlab_base.FutureTense = NO -->

Dans ce tutoriel, vous allez créer un pipeline CI/CD pour créer, tester et déployer un site Hugo.

À la fin de ce tutoriel, vous disposerez d'un pipeline fonctionnel et d'un site Hugo déployé sur GitLab Pages.

Voici un aperçu de ce que vous allez faire :

1. Préparer votre site Hugo.
1. Créer un projet GitLab.
1. Pousser votre site Hugo vers GitLab.
1. Créer votre site Hugo avec un pipeline CI/CD.
1. Déployer votre site Hugo avec GitLab Pages.

## Avant de commencer {#before-you-begin}

- Un compte sur GitLab.com.
- Une connaissance de Git.
- Un site Hugo (si vous n'en avez pas encore, vous pouvez suivre le [guide de démarrage rapide de Hugo](https://gohugo.io/getting-started/quick-start/)).

## Préparer votre site Hugo {#prepare-your-hugo-site}

Tout d'abord, assurez-vous que votre site Hugo est prêt à être poussé vers GitLab. Vous devez disposer de votre contenu, d'un thème et d'un fichier de configuration Hugo.

Ne générez pas votre site, car GitLab s'en charge pour vous. En fait, il est important de ne pas téléverser votre dossier `public`, car cela peut entraîner des conflits par la suite.

La façon la plus simple d'exclure votre dossier `public` est de créer un fichier `.gitignore` et d'y ajouter une nouvelle ligne avec `public/` comme texte.

Vous pouvez effectuer cette opération avec la commande suivante, à la racine de votre projet Hugo :

```shell
echo "public/" >> .gitignore
```

Cela ajoute `public/` dans un nouveau fichier `.gitignore` ou l'ajoute à un fichier existant.

Votre site Hugo est prêt à être poussé, après avoir créé un projet GitLab.

## Créer un projet GitLab {#create-a-gitlab-project}

Si vous ne l'avez pas encore fait, créez un projet GitLab vide pour votre site Hugo.

Pour créer un projet vide, dans GitLab :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer un projet vide**.
1. Saisissez les détails du projet :
   - Dans la zone de texte **Nom du projet**, entrez le nom de votre projet. Le nom doit commencer par une lettre minuscule ou majuscule (`a-zA-Z`), un chiffre (`0-9`), un emoji ou un tiret bas (`_`). Il peut également contenir des points (`.`), des signes plus (`+`), des tirets (`-`) ou des espaces.
   - Dans la zone de texte **Identifiant « slug » du projet**, entrez le chemin d'accès à votre projet. L'instance GitLab utilise l'identifiant « slug » comme chemin URL vers le projet. Pour modifier l'identifiant « slug », entrez d'abord le nom du projet, puis modifiez l'identifiant « slug ».
   - Le **Niveau de visibilité** peut être Privé ou Public. Si vous choisissez Privé, votre site web reste accessible au public, mais votre code demeure privé.
   - Étant donné que vous poussez un dépôt existant, décochez la case **Initialiser le dépôt avec un README**.
1. Lorsque vous êtes prêt, sélectionnez **Créer le projet**.
1. Vous devriez voir les instructions pour pousser votre code vers ce nouveau projet. Vous aurez besoin de ces instructions à l'étape suivante.

Votre site Hugo a désormais un emplacement !

## Pousser votre site Hugo vers GitLab {#push-your-hugo-site-to-gitlab}

Vous devez ensuite pousser votre site Hugo local vers votre projet GitLab distant.

Si vous avez créé un nouveau projet GitLab à l'étape précédente, vous verrez les instructions pour initialiser votre dépôt, puis pour effectuer un commit et pousser vos fichiers.

Sinon, assurez-vous que l'origine distante de votre dépôt Git local correspond à votre projet GitLab.

En supposant que votre branche par défaut est `main`, vous pouvez pousser votre site Hugo avec la commande suivante :

```shell
git push origin main
```

Après avoir poussé votre site, vous devriez voir tout le contenu à l'exception du dossier `public`. Le dossier `public` a été exclu par le fichier `.gitignore`.

À l'étape suivante, vous utiliserez un pipeline CI/CD pour créer votre site et recréer ce dossier `public`.

## Créer votre site Hugo avec un pipeline CI/CD {#build-your-hugo-site-with-a-cicd-pipeline}

Pour créer un site Hugo avec GitLab, vous devez d'abord créer un fichier `.gitlab-ci.yml` afin de spécifier les instructions pour le pipeline CI/CD. Si vous ne l'avez jamais fait auparavant, cela peut sembler intimidant. Cependant, GitLab vous fournit tout ce dont vous avez besoin.

Pour utiliser le fichier `.gitlab-ci.yml` présenté ci-dessous, assurez-vous que votre fichier `hugo.toml` indique également un chemin de thème correspondant. L'exemple de fichier `hugo.toml` ci-dessous illustre également les paramètres `baseURL` pour un projet GitLab Pages.

```yaml
baseURL = 'https://<your-namespace>.gitlab.io/<project-path>'
languageCode = 'en-us'
title = 'Hugo on GitLab'
[module]
[[module.imports]]
  path = 'github.com/adityatelange/hugo-PaperMod'
```

### Ajouter vos options de configuration GitLab {#add-your-gitlab-configuration-options}

Vous spécifiez vos options de configuration dans un fichier spécial appelé `.gitlab-ci.yml`.

Pour créer un fichier `.gitlab-ci.yml` à l'aide du modèle Hugo :

1. Dans la barre latérale gauche, sélectionnez **Code** > **Dépôt**.
1. Au-dessus de la liste des fichiers, sélectionnez l'icône plus ( + ), puis sélectionnez **Nouveau fichier** dans la liste déroulante.
1. Pour le nom de fichier, entrez `.gitlab-ci.yml`. N'omettez pas le point au début.
1. Sélectionnez la liste déroulante **Appliquer un modèle**, puis entrez « Hugo » dans la zone de filtre.
1. Sélectionnez le résultat **Hugo**, et votre fichier est rempli avec tout le code nécessaire pour créer votre site Hugo avec CI/CD.

Examinons de plus près ce qui se passe dans ce fichier `.gitlab-ci.yml`.

```yaml
default:
  image: "hugomods/hugo:exts"

variables:
  GIT_SUBMODULE_STRATEGY: recursive
  THEME_URL: "github.com/adityatelange/hugo-PaperMod"

test:  # builds and tests your site
  script:
    - hugo
  rules:
    - if: $CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH

create-pages:  # a user-defined job that builds your pages and saves them to the specified path.
  script:
    - hugo
  pages: true  # specifies that this is a Pages job
  artifacts:
    paths:
      - public
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  environment: production
```

- `image` spécifie une image du registre GitLab qui contient Hugo. Cette image est utilisée pour créer l'environnement dans lequel votre site est généré.
- La variable `GIT_SUBMODULE_STRATEGY` garantit que GitLab examine également vos sous-modules Git, qui sont parfois utilisés pour les thèmes Hugo.
- `test` est un job dans lequel vous pouvez exécuter des tests sur votre site Hugo avant son déploiement. Le job test s'exécute dans tous les cas, sauf si vous effectuez un commit d'une modification sur votre branche par défaut. Placez toutes les commandes sous `script`. La commande dans ce job, `hugo`, génère votre site pour qu'il puisse être testé.
- `create-pages` est un job défini par l'utilisateur pour créer des pages à partir de générateurs de sites statiques. Ce job utilise également les [noms de jobs définis par l'utilisateur](../../user/project/pages/_index.md#user-defined-job-names) et exécute la commande `hugo` pour générer votre site. Ensuite, `pages: true` spécifie qu'il s'agit d'un job Pages et `artifacts` spécifie que les pages résultantes sont ajoutées à un répertoire appelé `public`. Avec `rules`, vous vérifiez que ce commit a été effectué sur la branche par défaut. En général, vous ne souhaitez pas générer et déployer le site en production depuis une autre branche.

Vous n'avez rien d'autre à ajouter à ce fichier. Lorsque vous êtes prêt, sélectionnez **Valider les modifications** en haut de la page.

Vous venez de déclencher un pipeline pour générer votre site Hugo !

## Déployer votre site Hugo avec GitLab Pages {#deploy-your-hugo-site-with-gitlab-pages}

Si vous êtes rapide, vous pouvez voir GitLab générer et déployer votre site.

Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**.

Vous constatez que GitLab a exécuté vos jobs `test` et `create-pages`.

Pour consulter votre site, une fois le pipeline terminé, dans la barre latérale gauche, sélectionnez **Déployer** > **Pages** pour trouver le lien vers votre site Pages.

### Ajouter vos options de configuration Hugo {#add-your-hugo-configuration-options}

Lorsque vous consultez votre site Hugo pour la première fois, la feuille de style ne fonctionnera pas. Ne vous inquiétez pas, vous devez apporter une petite modification à votre fichier de configuration Hugo. Hugo doit connaître l'URL de votre site GitLab Pages pour pouvoir générer des liens relatifs vers les feuilles de style et d'autres ressources :

1. Dans votre site Hugo local, récupérez les dernières modifications et ouvrez votre fichier `config.yaml` ou `config.toml`.
1. Modifiez la valeur du paramètre `BaseURL` pour qu'elle corresponde à l'URL qui apparaît dans les paramètres de votre GitLab Pages.
1. Poussez votre fichier modifié vers GitLab, et votre pipeline est déclenché à nouveau.

### Trouver votre URL GitLab Pages {#find-your-gitlab-pages-url}

Une fois le pipeline terminé, accédez à **Déployer** > **Pages** pour trouver le lien vers votre site Pages.

Le job `pages` de votre pipeline a déployé le contenu de votre répertoire `public` sur GitLab Pages. Sous **Accès aux pages**, vous devriez voir le lien au format suivant : `https://<your-namespace>.gitlab.io/<project-path>`.

Vous ne verrez pas ce lien si vous n'avez pas encore exécuté votre pipeline.

Sélectionnez le lien affiché pour consulter votre site. Vous devez modifier le paramètre `BaseURL` dans votre configuration Hugo pour qu'il corresponde à l'URL de déploiement GitLab.

### Définir la visibilité de vos GitLab Pages {#set-your-gitlab-pages-visibility}

Si votre site Hugo est stocké dans un dépôt privé, vous devrez modifier vos autorisations pour que le site Pages soit visible. Sinon, il n'est visible que par les membres du projet. Pour modifier les autorisations du site :

1. Accédez à **Paramètres** > **Général** > **Visibilité, fonctionnalités du projet, autorisations**.
1. Faites défiler vers le bas jusqu'à la section **Pages** et sélectionnez **Tout le monde** dans la liste déroulante.
1. Sélectionnez **Enregistrer les modifications**.

Désormais, tout le monde peut voir le site à l'URL.

Vous avez créé, testé et déployé votre site Hugo avec GitLab. Excellent travail !

Chaque fois que vous modifiez votre site et le poussez vers GitLab, votre site est automatiquement généré, testé et déployé, en utilisant les règles définies dans le fichier `.gitlab-ci.yml`.

Pour en savoir plus sur les pipelines CI/CD, essayez [ce tutoriel sur la création d'un pipeline complexe](../../ci/quick_start/tutorial.md). Vous pouvez également en apprendre davantage sur les [différents types de tests disponibles](../../ci/testing/_index.md).
