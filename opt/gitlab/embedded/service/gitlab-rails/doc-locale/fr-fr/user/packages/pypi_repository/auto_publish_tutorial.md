---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 'Tutoriel : créer et publier automatiquement des paquets avec CI/CD'
---

Vous pouvez utiliser CI/CD pour créer et publier vos paquets PyPI. Les builds automatiques peuvent vous aider à maintenir vos paquets à jour et disponibles pour d'autres utilisateurs.

Dans ce tutoriel, vous allez créer une nouvelle configuration CI/CD pour créer, tester et publier un exemple de paquet PyPI. Une fois le tutoriel terminé, vous devriez mieux comprendre le fonctionnement de chaque étape du pipeline et être à l'aise pour intégrer CI/CD à votre propre workflow de registre de paquets.

Pour créer et publier automatiquement des paquets avec CI/CD :

1. [Créer un fichier `.gitlab-ci.yml`](#create-a-gitlab-ciyml-file)
   1. Facultatif. [S'authentifier sans variable CI/CD](#authenticate-without-a-cicd-variable)
1. [Vérifier le pipeline](#check-the-pipeline)

## Avant de commencer {#before-you-begin}

Avant de suivre ce tutoriel, assurez-vous de disposer des éléments suivants :

- Un projet de test. Vous pouvez utiliser n'importe quel projet Python, mais envisagez d'en créer un spécifiquement pour ce tutoriel.
- Une connaissance de PyPI et du registre de paquets GitLab.

## Créer un fichier `.gitlab-ci.yml` {#create-a-gitlab-ciyml-file}

Chaque configuration CI/CD nécessite un fichier `.gitlab-ci.yml`. Ce fichier définit chaque étape du pipeline CI/CD. Dans ce cas, les étapes sont :

- `build` - Créer un paquet PyPI.
- `test` - Valider le paquet avec le framework de test `pytest`.
- `publish` - Publier le paquet dans le registre de paquets.

Pour créer un fichier `.gitlab-ci.yml` :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Dépôt**.
1. Au-dessus de la liste des fichiers, sélectionnez la branche sur laquelle vous souhaitez effectuer un commit.
1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}).
1. Nommez le fichier `.gitlab-ci.yml`. Dans la fenêtre principale, collez cet exemple de configuration :

   ```yaml
   default:
     image: python:3.9
     cache:
       paths:
         - .pip-cache/
     before_script:
       - python --version
       - pip install --upgrade pip
       - pip install build twine

   stages:
     - build
     - test
     - publish

   variables:
     PIP_CACHE_DIR: "$CI_PROJECT_DIR/.pip-cache"

   build:
     stage: build
     script:
       - python -m build
     artifacts:
       paths:
         - dist/

   test:
     stage: test
     script:
       - pip install pytest
       - pip install dist/*.whl
       - pytest

   publish:
     stage: publish
     script:
       - TWINE_PASSWORD=${CI_JOB_TOKEN} TWINE_USERNAME=gitlab-ci-token python -m twine upload --repository-url ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/pypi dist/*
     rules:
       - if: $CI_COMMIT_TAG
   ```

1. Sélectionnez **Valider les modifications**.

Voici une brève explication du code commité :

- `image` - Spécifie l'image Docker à utiliser.
- `stages` - Définit les trois étapes de ce pipeline.
- `variables` et `cache` \- Configure PIP pour utiliser la mise en cache. Cela peut accélérer légèrement les pipelines suivants.
- `before_script` - Installe les outils nécessaires pour effectuer les trois étapes.
- `build` - Crée les paquets et stocke les résultats sous forme d'artefact.
- `test` - Installe et exécute pytest pour valider le paquet.
- `publish` - Charge le paquet dans le registre de paquets avec twine, uniquement si un nouveau tag est poussé. Authentifiez-vous auprès du registre de paquets à l'aide de `CI_JOB_TOKEN`.

### S'authentifier sans variable CI/CD {#authenticate-without-a-cicd-variable}

Pour s'authentifier auprès du registre de paquets, l'exemple de configuration utilise le `CI_JOB_TOKEN`, qui est automatiquement fourni par GitLab CI/CD. Pour publier dans des registres PyPI externes, vous devez configurer une variable secrète dans les paramètres de votre projet :

1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD** > **Variables**.
1. Ajoutez une nouvelle variable nommée `PYPI_TOKEN` avec votre jeton API PyPI comme valeur.
1. Dans votre fichier `.gitlab-ci.yml`, remplacez le `publish:script` par :

   ```yaml
   script:
   - TWINE_PASSWORD=${PYPI_TOKEN} TWINE_USERNAME=__token__ python -m twine upload dist/*
   ```

## Vérifier le pipeline {#check-the-pipeline}

Lorsque vous effectuez un commit de vos modifications, vérifiez que le pipeline s'exécute correctement :

- Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**. Le pipeline le plus récent devrait comporter les trois étapes définies précédemment.

Si le pipeline ne s'est pas exécuté, lancez manuellement un nouveau pipeline et assurez-vous qu'il se termine avec succès.

## Bonnes pratiques {#best-practices}

Pour garantir la sécurité et la stabilité de vos paquets, vous devez suivre les bonnes pratiques en matière de publication dans le registre de paquets. La configuration que vous avez ajoutée :

- Implémente la mise en cache pour accélérer votre pipeline.
- Utilise des artefacts pour transférer le paquet créé entre les étapes.
- Inclut une étape de test pour valider le paquet avant la publication.
- Utilise des variables CI/CD GitLab pour les informations sensibles telles que les jetons d'authentification.
- Publie uniquement lorsqu'un nouveau tag Git est poussé. Cela garantit que seules les releases correctement versionnées sont publiées.

Félicitations ! Vous avez créé, testé et publié avec succès un paquet avec GitLab CI/CD. Vous devriez être en mesure d'utiliser une configuration similaire pour rationaliser vos propres processus de développement.
