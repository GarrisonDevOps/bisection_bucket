---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Utilisez les étiquettes Git pour marquer des points importants dans l'historique d'un dépôt et déclencher des pipelines CI/CD."
title: Tags
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Dans Git, une étiquette marque un point important dans l'historique d'un dépôt. Git prend en charge deux types d'étiquettes :

- Les étiquettes légères pointent vers des commits spécifiques et ne contiennent aucune autre information. Également appelées étiquettes souples. Créez-les ou supprimez-les selon vos besoins.
- Les étiquettes annotées contiennent des métadonnées, peuvent être signées à des fins de vérification et ne peuvent pas être modifiées.

La création ou la suppression d'une étiquette peut servir de déclencheur pour l'automatisation, notamment :

- L'utilisation d'un [webhook](../../integrations/webhook_events.md#tag-events) pour automatiser des actions telles que les notifications Slack.
- Signaler à un [miroir de dépôt](../mirror/_index.md) de se mettre à jour.
- L'exécution d'un pipeline CI/CD avec [`if: $CI_COMMIT_TAG`](../../../../ci/jobs/job_rules.md#common-if-clauses-with-predefined-variables).

Lorsque vous [créez une release](../../releases/_index.md), GitLab crée également une étiquette pour marquer le point de release. De nombreux projets combinent une étiquette annotée de release avec une branche stable. Envisagez de définir automatiquement des étiquettes de déploiement ou de release.

Dans l'interface utilisateur de GitLab, chaque étiquette affiche :

![Exemple d'une étiquette unique](img/tag-display_v18_3.png)

- Le nom de l'étiquette ({{< icon name="tag" >}})
- Copiez le nom de l'étiquette ({{< icon name="copy-to-clipboard" >}}).
- Facultatif. Si l'étiquette est [protégée](../../protected_tags.md), un badge **protégées**.
- Le SHA du commit ({{< icon name="commit" >}}), lié au contenu du commit.
- Le titre du commit et sa date de création.
- Facultatif. Un lien vers la release ({{< icon name="rocket" >}}).
- Facultatif. Si un pipeline a été exécuté, le statut actuel du pipeline.
- Liens de téléchargement vers le code source et les artefacts liés à l'étiquette.
- Un lien [**Créer une release**](../../releases/_index.md#create-a-release) ({{< icon name="pencil" >}}).
- Un lien pour supprimer l'étiquette.

## Afficher les étiquettes d'un projet {#view-tags-for-a-project}

Pour afficher toutes les étiquettes existantes d'un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Étiquettes**.

## Suivre les étiquettes avec un flux RSS {#track-tags-with-an-rss-feed}

GitLab fournit un flux RSS des étiquettes d'un projet. Le bouton du flux n'apparaît que si le projet comporte au moins une étiquette.

Pour afficher le flux :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Étiquettes**.
1. Dans le coin supérieur droit, sélectionnez le symbole de flux ({{< icon name="rss" >}}).

L'URL du flux contient un [jeton de flux](../../../../security/tokens/_index.md#feed-token) qui vous authentifie en tant que lecteur du flux.

## Afficher les commits étiquetés dans la liste des commits {#view-tagged-commits-in-the-commits-list}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Commits**.
1. Les commits avec une étiquette sont marqués d'une icône d'étiquette ({{< icon name="tag" >}}) et du nom de l'étiquette. Cet exemple montre un commit étiqueté `v1.26.0` :

   ![Un commit étiqueté dans la vue Commits](img/tags_commits_view_v15_10.png)

Pour afficher la liste des commits dans cette étiquette, sélectionnez le nom de l'étiquette.

## Créer une étiquette {#create-a-tag}

Les étiquettes peuvent être créées depuis la ligne de commande ou depuis l'interface utilisateur de GitLab.

### Depuis la ligne de commande {#from-the-command-line}

Pour créer une étiquette légère ou annotée depuis la ligne de commande et la pousser en amont :

1. Pour créer une étiquette légère, exécutez la commande `git tag TAG_NAME`, en remplaçant `TAG_NAME` par le nom d'étiquette souhaité.
1. Pour créer une étiquette annotée, exécutez l'une des versions de `git tag` depuis la ligne de commande :

   ```shell
   # In this short version, the annotated tag's name is "v1.0",
   # and the message is "Version 1.0".
   git tag -a v1.0 -m "Version 1.0"

   # Use this version to write a longer tag message
   # for annotated tag "v1.0" in your text editor.
   git tag -a v1.0
   ```

1. Poussez vos étiquettes en amont avec `git push origin --tags`.

### Depuis l'interface utilisateur {#from-the-ui}

Pour créer une étiquette depuis l'interface utilisateur de GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Étiquettes**.
1. Sélectionnez **Nouvelle étiquette**.
1. Indiquez un **Nom de l'étiquette**.
1. Pour **Créer à partir de**, sélectionnez un nom de branche, une étiquette ou un SHA de commit existant.
1. Facultatif. Ajoutez un **Message** pour créer une étiquette annotée, ou laissez ce champ vide pour créer une étiquette légère.
1. Sélectionnez **Créer une étiquette**.

## Nommer votre étiquette {#name-your-tag}

Git applique des [règles de nommage des étiquettes](https://git-scm.com/docs/git-check-ref-format) pour garantir la compatibilité des noms d'étiquettes avec les autres outils. GitLab ajoute des exigences supplémentaires pour les noms d'étiquettes et offre des avantages pour les noms d'étiquettes bien structurés.

GitLab applique ces règles supplémentaires à toutes les étiquettes :

- Les espaces ne sont pas autorisés dans les noms d'étiquettes.
- Les noms d'étiquettes commençant par 40 ou 64 caractères hexadécimaux sont interdits, car ils ressemblent aux hachages de commit Git.
- Les noms d'étiquettes ne peuvent pas commencer par `-`, `refs/heads/`, `refs/tags/` ou `refs/remotes/`.
- Les noms d'étiquettes sont sensibles à la casse.

## Copier un nom d'étiquette {#copy-a-tag-name}

Pour copier un nom d'étiquette dans votre presse-papiers :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Étiquettes**.
1. À côté du nom de l'étiquette, sélectionnez **Copier le nom de l'étiquette** ({{< icon name="copy-to-clipboard" >}}).

## Empêcher la suppression d'une étiquette {#prevent-tag-deletion}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour empêcher les utilisateurs de supprimer une étiquette avec `git push`, créez une [règle push](../push_rules.md).

## Déclencher des pipelines depuis une étiquette {#trigger-pipelines-from-a-tag}

GitLab CI/CD fournit une variable prédéfinie, [`CI_COMMIT_TAG`](../../../../ci/variables/predefined_variables.md), pour identifier les étiquettes dans vos configurations de pipeline. Vous pouvez utiliser cette variable dans les règles de job et les règles de workflow pour vérifier si un pipeline a été déclenché par une étiquette.

Par défaut, si vos jobs CI/CD n'ont pas de règles spécifiques en place, ils sont inclus dans un pipeline d'étiquette pour toute nouvelle étiquette créée. Les pipelines d'étiquette sont créés uniquement lorsqu'une étiquette cible un commit.

Dans votre fichier `.gitlab-ci.yml` pour la configuration du pipeline CI/CD de votre projet, vous pouvez utiliser la variable `CI_COMMIT_TAG` pour contrôler les pipelines pour les nouvelles étiquettes :

- Au niveau du job avec [`rules:if`](../../../../ci/yaml/_index.md#rulesif).
- Au niveau du pipeline avec le mot-clé [`workflow`](../../../../ci/yaml/workflow.md).

## Déclencher des analyses de sécurité dans les pipelines d'étiquette {#trigger-security-scans-in-tag-pipelines}

Par défaut, les politiques d'exécution d'analyse s'exécutent uniquement sur les branches, et non sur les étiquettes. Cependant, vous pouvez configurer des politiques d'exécution de pipeline pour exécuter des analyses de sécurité sur les étiquettes.

Pour exécuter des analyses de sécurité sur les étiquettes :

1. Créez un fichier YAML de configuration CI/CD avec des jobs personnalisés qui étendent les templates de l'analyseur de sécurité et incluent des règles pour s'exécuter sur les étiquettes.
1. Créez une politique d'exécution de pipeline qui injecte cette configuration dans vos pipelines.

### Exemple de politique d'exécution de pipeline {#example-pipeline-execution-policy}

Cet exemple montre comment créer une politique d'exécution de pipeline qui exécute des analyses des dépendances et des analyses SAST sur les étiquettes :

```yaml
pipeline_execution_policy:
- name: Pipeline Execution Policy
  description: Run security scans on tags
  enabled: true
  pipeline_config_strategy: inject_policy
  content:
    include:
    - project: <Project path to YAML>
      file: tag-security-scans.yml
  skip_ci:
    allowed: false
```

### Exemple de configuration CI/CD {#example-cicd-configuration}

Cet exemple montre comment étendre les jobs de l'analyseur de sécurité pour s'exécuter sur les étiquettes :

```yaml
include:
  - template: Jobs/Dependency-Scanning.gitlab-ci.yml
  - template: Jobs/SAST.gitlab-ci.yml

# Extend dependency scanning to run on tags
gemnasium-python-dependency_scanning_tags:
  extends: gemnasium-python-dependency_scanning
  rules:
    - if: $CI_COMMIT_TAG

# Extend SAST scanning to run on tags
semgrep-sast_tags:
  extends: semgrep-sast
  rules:
    - if: $CI_COMMIT_TAG

# Example of a custom job that runs only on tags
policy_job_for_tags:
  script:
    - echo "This job runs only on tags"
  rules:
    - if: $CI_COMMIT_TAG

# Example of a job that runs on all pipelines
policy_job_always:
  script:
    - echo "This policy job runs always."
```

## Sujets connexes {#related-topics}

- [Étiquetage (page de référence Git)](https://git-scm.com/book/en/v2/Git-Basics-Tagging)
- [Étiquettes protégées](../../protected_tags.md)
- [Comparer les révisions](../compare_revisions.md)
- [API de tags](../../../../api/tags.md)
