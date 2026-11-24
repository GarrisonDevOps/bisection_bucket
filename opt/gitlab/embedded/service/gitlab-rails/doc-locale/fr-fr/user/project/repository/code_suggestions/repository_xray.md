---
stage: AI Coding
group: DAP Repository Flows
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Repository X-Ray donne à Code Suggestions plus d'informations sur la base de code et les dépendances de votre projet."
title: Repository X-Ray avec Code Suggestions
---

Repository X-Ray enrichit automatiquement :

- Les requêtes de génération de code pour [GitLab Duo Code Suggestions](_index.md) en fournissant un contexte supplémentaire sur les dépendances d'un projet, afin d'améliorer la précision et la pertinence des recommandations de code.
- Les requêtes pour [refactoriser du code](../../../gitlab_duo_chat/examples.md#refactor-code-in-the-ide), [corriger du code](../../../gitlab_duo_chat/examples.md#fix-code-in-the-ide) et [écrire des tests](../../../gitlab_duo_chat/examples.md#write-tests-in-the-ide).

Pour ce faire, Repository X-Ray offre à l'assistant de code plus d'informations sur la base de code et les dépendances du projet en :

- Recherchant les fichiers de configuration du gestionnaire de dépendances (par exemple, `Gemfile.lock`, `package.json`, `go.mod`).
- Extrayant une liste de bibliothèques à partir de leur contenu.
- Fournissant la liste extraite comme contexte supplémentaire à utiliser par GitLab Duo Code Suggestions pour les requêtes de génération de code, de refactorisation de code, de correction de code et d'écriture de tests.

En comprenant les bibliothèques et les autres dépendances utilisées, Repository X-Ray aide l'assistant de code à adapter les suggestions aux patterns de codage, aux styles et aux technologies utilisés dans le projet. Cela génère des suggestions de code qui s'intègrent plus facilement et suivent les bonnes pratiques pour la stack concernée.

> [!note]
> Repository X-Ray améliore uniquement les requêtes de génération de code, et non les requêtes de complétion de code.

## Fonctionnement de Repository X-Ray {#how-repository-x-ray-works}

{{< history >}}

- Le nombre maximum de bibliothèques a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/500365) dans GitLab 17.6.

{{< /history >}}

Lorsque vous envoyez un nouveau commit vers la branche par défaut de votre projet, Repository X-Ray déclenche un job en arrière-plan. Ce job analyse et parse les fichiers de configuration applicables dans votre dépôt.

En général, un seul job d'analyse s'exécute à la fois dans chaque projet. Si une deuxième analyse est déclenchée alors qu'une analyse est déjà en cours, cette deuxième analyse attend que la première soit terminée avant de s'exécuter. Cela peut entraîner un léger délai avant que les données les plus récentes du fichier de configuration soient parsées et mises à jour dans la base de données.

Lorsqu'une requête de génération de code est effectuée, un maximum de 300 bibliothèques issues des données parsées est inclus dans le prompt en tant que contexte supplémentaire.

## Activer Repository X-Ray {#enable-repository-x-ray}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/476180) dans GitLab 17.4 [avec un feature flag](../../../../administration/feature_flags/list.md) nommé `ai_enable_internal_repository_xray_service`. Fonctionnalité désactivée par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/483928) dans GitLab 17.6. Suppression du feature flag `ai_enable_internal_repository_xray_service`.

{{< /history >}}

Le service Repository X-Ray est automatiquement activé si votre projet a accès à [GitLab Duo Code Suggestions](_index.md).

## Langages et gestionnaires de dépendances pris en charge {#supported-languages-and-dependency-managers}

Repository X-Ray effectue des recherches dans un maximum de deux niveaux de répertoires à partir de la racine du dépôt. Par exemple, il prend en charge `Gemfile.lock`, `api/Gemfile.lock` ou `api/client/Gemfile.lock`, mais pas `api/v1/client/Gemfile.lock`. Pour chaque langage, seul le premier gestionnaire de dépendances correspondant est traité. Lorsqu'ils sont disponibles, les fichiers lock ont la priorité sur leurs équivalents sans lock.

| Langage   | Gestionnaire de dépendances | Fichier de configuration                  | Version de GitLab |
| ---------- |--------------------| ----------------------------------- | -------------- |
| C/C++      | Conan              | `conanfile.py`                      | 17.5 ou version ultérieure  |
| C/C++      | Conan              | `conanfile.txt`                     | 17.5 ou version ultérieure  |
| C/C++      | vcpkg              | `vcpkg.json`                        | 17.5 ou version ultérieure  |
| C#         | NuGet              | `*.csproj`                          | 17.5 ou version ultérieure  |
| Go         | Go Modules         | `go.mod`                            | 17.4 ou version ultérieure  |
| Java       | Gradle             | `build.gradle`                      | 17.4 ou version ultérieure  |
| Java       | Maven              | `pom.xml`                           | 17.4 ou version ultérieure  |
| JavaScript | NPM                | `package-lock.json`, `package.json` | 17.5 ou version ultérieure  |
| Kotlin     | Gradle             | `build.gradle.kts`                  | 17.5 ou version ultérieure  |
| PHP        | Composer           | `composer.lock`, `composer.json`    | 17.5 ou version ultérieure  |
| Python     | Conda              | `environment.yml`                   | 17.5 ou version ultérieure  |
| Python     | Pip                | `*requirements*.txt`[^pip-configuration-files]   | 17.5 ou version ultérieure  |
| Python     | Poetry             | `poetry.lock`, `pyproject.toml`     | 17.5 ou version ultérieure  |
| Ruby       | RubyGems           | `Gemfile.lock`                      | 17.4 ou version ultérieure  |

[^pip-configuration-files]: pour Python Pip, tous les fichiers de configuration correspondant au pattern glob `*requirements*.txt` sont traités.
