---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Pipelines de conformité (dépréciés)
description: "Les pipelines de conformité (dépréciés dans la version 17.3, dont la suppression est prévue dans la version 20.0) permettent un contrôle CI/CD centralisé pour les projets labellisés. Remplacés par les politiques d'exécution de pipeline."
---

<!--- start_remove The following content will be removed on remove_date: '2027-05-25' -->

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/159841) dans GitLab 17.3 et sa suppression est prévue dans la version 20.0. Utilisez plutôt le [type de politique d'exécution de pipeline](../application_security/policies/pipeline_execution_policies.md). Ce changement est un changement majeur. Pour plus d'informations, consultez le [guide de migration](#pipeline-execution-policies-migration).

Les propriétaires de groupe peuvent configurer un pipeline de conformité dans un projet distinct des autres projets. Par défaut, la configuration du pipeline de conformité (par exemple, `.compliance-gitlab-ci.yml`) est exécutée à la place de la configuration de pipeline (par exemple, `.gitlab-ci.yml`) des projets labellisés.

Cependant, la configuration du pipeline de conformité peut référencer le fichier `.gitlab-ci.yml` des projets labellisés afin que :

- Le pipeline de conformité peut également exécuter des jobs des pipelines de projets labellisés. Cela permet un contrôle centralisé de la configuration du pipeline.
- Les jobs et les variables définis dans le pipeline de conformité ne peuvent pas être modifiés par des variables dans le fichier `.gitlab-ci.yml` du projet labellisé.

> [!note]
> En raison d'un [problème connu](https://gitlab.com/gitlab-org/gitlab/-/issues/414004), les pipelines de projet doivent être inclus en premier, en haut de la configuration du pipeline de conformité, afin d'éviter que les projets remplacent les paramètres en aval.

Pour plus d'informations, consultez :

- [Exemple de configuration](#example-configuration) pour vous aider à configurer un pipeline de conformité qui exécute des jobs depuis la configuration de pipeline de projets labellisés.
- Le tutoriel [Créer un pipeline de conformité](../../tutorials/compliance_pipeline/_index.md).

## Migration des politiques d'exécution de pipeline {#pipeline-execution-policies-migration}

Les politiques d'exécution de pipeline visent à consolider et à simplifier l'application des analyses et des pipelines. Les pipelines de conformité ont été dépréciés dans GitLab 17.3 et seront supprimés dans GitLab 19.0.

Les politiques d'exécution de pipeline étendent le fichier `.gitlab-ci.yml` d'un projet avec la configuration fournie dans un fichier YAML distinct (par exemple, `pipeline-execution.yml`) lié dans la politique d'exécution de pipeline.

Par défaut, lors de la création d'un nouveau framework de conformité, vous êtes invité à utiliser le type de politique d'exécution de pipeline plutôt que les pipelines de conformité.

Les pipelines de conformité existants doivent être migrés. Les clients doivent migrer des pipelines de conformité vers le nouveau [type de politique d'exécution de pipeline](../application_security/policies/pipeline_execution_policies.md) dès que possible.

### Migrer un framework de conformité existant {#migrate-an-existing-compliance-framework}

Pour migrer un framework de conformité existant afin d'utiliser le type de politique d'exécution de pipeline :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. [Modifiez](compliance_frameworks/_index.md#create-edit-or-delete-a-compliance-framework) le framework de conformité existant.
1. Dans la bannière qui s'affiche, sélectionnez **Migrer le pipeline vers une stratégie** pour créer une nouvelle stratégie dans les politiques de sécurité.
1. Modifiez à nouveau le framework de conformité pour supprimer le pipeline de conformité.

Pour plus d'informations, consultez [Projet de politique de sécurité](../application_security/policies/enforcement/security_policy_projects.md).

Si vous recevez une erreur `Pipeline execution policy error: Job names must be unique` lors de la migration, consultez les [informations de dépannage pertinentes](#error-job-names-must-be-unique).

## Effet sur les projets labellisés {#effect-on-labeled-projects}

Les utilisateurs n'ont aucun moyen de savoir qu'un pipeline de conformité a été configuré et peuvent être déconcertés de voir que leurs propres pipelines ne s'exécutent pas du tout, ou qu'ils incluent des jobs qu'ils n'ont pas définis eux-mêmes.

Lors de la création de pipelines sur un projet labellisé, rien n'indique qu'un pipeline de conformité a été configuré. Le seul marqueur au niveau du projet est le label du framework de conformité lui-même, mais ce label n'indique pas si le framework possède un pipeline de conformité configuré ou non.

Par conséquent, communiquez avec les utilisateurs du projet au sujet de la configuration du pipeline de conformité afin de réduire l'incertitude et la confusion.

### Plusieurs frameworks de conformité {#multiple-compliance-frameworks}

Vous pouvez [appliquer à un seul projet](compliance_frameworks/_index.md#apply-a-compliance-framework-to-a-project) plusieurs frameworks de conformité avec des pipelines de conformité configurés. Dans ce cas, seul le premier framework de conformité appliqué à un projet voit son pipeline de conformité inclus dans le pipeline du projet.

Pour vous assurer que le pipeline de conformité correct est inclus dans un projet :

1. Supprimez tous les frameworks de conformité du projet.
1. Appliquez le framework de conformité avec le pipeline de conformité correct au projet.
1. Appliquez des frameworks de conformité supplémentaires au projet.

## Configurer un pipeline de conformité {#configure-a-compliance-pipeline}

Pour configurer un pipeline de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sélectionnez la section **Frameworks**.
1. Sélectionnez la section **Nouveau framework** et ajoutez les informations du framework de conformité, notamment le chemin vers la configuration du framework de conformité. Utilisez le format `path/file.y[a]ml@group-name/project-name`. Par exemple :

   - `.compliance-ci.yml@gitlab-org/gitlab`.
   - `.compliance-ci.yaml@gitlab-org/gitlab`.

Cette configuration est héritée par les projets auxquels le label du framework de conformité est [appliqué](../project/working_with_projects.md#add-a-compliance-framework-to-a-project). Dans les projets auxquels le label du framework de conformité est appliqué, la configuration du pipeline de conformité est exécutée à la place de la propre configuration de pipeline du projet labellisé.

L'utilisateur qui exécute le pipeline dans le projet labellisé doit au minimum avoir le rôle Reporter sur le projet de conformité.

Lorsqu'elle est utilisée pour appliquer l'exécution des analyses, cette fonctionnalité présente un certain recoupement avec les [politiques d'exécution des analyses](../application_security/policies/scan_execution_policies.md). L'expérience utilisateur pour ces deux fonctionnalités [n'a pas été unifiée](https://gitlab.com/groups/gitlab-org/-/epics/7312).

## Considérations importantes {#important-considerations}

> [!warning]
> N'activez pas les [politiques d'exécution de pipeline](../application_security/policies/pipeline_execution_policies.md) avant d'avoir migré les pipelines de conformité existants dans le même projet. Lorsque les deux sont configurés, les pipelines de conformité remplacent le pipeline de projet standard, mais les politiques d'exécution de pipeline s'appliquent en fonction du pipeline de projet d'origine. Cela crée un comportement imprévisible qui varie en fonction de la stratégie de politique d'exécution de pipeline et des configurations CI/CD, et peut entraîner des jobs dupliqués, des échecs de pipeline ou des vérifications de sécurité et de conformité critiques manquantes. Les pipelines de conformité sont [dépréciés](../../update/deprecations.md#compliance-pipelines). Vous devez migrer les pipelines de conformité existants dès que possible et utiliser les politiques d'exécution de pipeline pour toutes les nouvelles implémentations.

### Exemple de configuration {#example-configuration}

L'exemple suivant `.compliance-gitlab-ci.yml` inclut le mot-clé `include` pour s'assurer que la configuration du pipeline du projet labellisé est également exécutée.

```yaml
include:  # Execute individual project's configuration (if project contains .gitlab-ci.yml)
  - project: '$CI_PROJECT_PATH'
    file: '$CI_CONFIG_PATH'
    ref: '$CI_COMMIT_SHA' # Must be defined or MR pipelines always use the use default branch
    rules:
      - if: $CI_PROJECT_PATH != "my-group/project-1" # Must run on projects other than the one hosting this configuration.

# Allows compliance team to control the ordering and interweaving of stages/jobs.
# Stages without jobs defined will remain hidden.
stages:
  - pre-compliance
  - build
  - test
  - pre-deploy-compliance
  - deploy
  - post-compliance

variables:  # Can be overridden by setting a job-specific variable in project's local .gitlab-ci.yml
  FOO: sast

sast:  # None of these attributes can be overridden by a project's local .gitlab-ci.yml
  variables:
    FOO: sast
  image: ruby:2.6
  stage: pre-compliance
  rules:
    - if: $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS && $CI_PIPELINE_SOURCE == "push"
      when: never
    - when: always  # or when: on_success
  allow_failure: false
  before_script:
    - "# No before scripts."
  script:
    - echo "running $FOO"
  after_script:
    - "# No after scripts."

sanity check:
  image: ruby:2.6
  stage: pre-deploy-compliance
  rules:
    - if: $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS && $CI_PIPELINE_SOURCE == "push"
      when: never
    - when: always  # or when: on_success
  allow_failure: false
  before_script:
    - "# No before scripts."
  script:
    - echo "running $FOO"
  after_script:
    - "# No after scripts."

audit trail:
  image: ruby:2.7
  stage: post-compliance
  rules:
    - if: $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS && $CI_PIPELINE_SOURCE == "push"
      when: never
    - when: always  # or when: on_success
  allow_failure: false
  before_script:
    - "# No before scripts."
  script:
    - echo "running $FOO"
  after_script:
    - "# No after scripts."
```

La configuration `rules` dans la définition `include` évite une inclusion circulaire dans le cas où le pipeline de conformité doit pouvoir s'exécuter dans le projet hôte lui-même. Vous pouvez l'omettre si votre pipeline de conformité ne s'exécute que dans des projets labellisés.

#### Pipelines de conformité et configuration de pipeline personnalisée hébergée en externe {#compliance-pipelines-and-custom-pipeline-configuration-hosted-externally}

L'exemple précédent suppose que tous les projets hébergent leur configuration de pipeline dans le même projet. Si des projets utilisent une [configuration hébergée en externe](../../ci/pipelines/settings.md#specify-a-custom-cicd-configuration-file), l'exemple de configuration ne fonctionne pas. Consultez le [ticket 393960](https://gitlab.com/gitlab-org/gitlab/-/issues/393960) pour plus de détails.

Pour les projets utilisant une configuration hébergée en externe, vous pouvez essayer cette solution de contournement :

- La section `include` dans l'exemple de configuration du pipeline de conformité doit être ajustée. Par exemple, en utilisant [`include:rules`](../../ci/yaml/includes.md#use-rules-with-include) :

  ```yaml
  include:
    # If the custom path variables are defined, include the project's external config file.
    - project: '$PROTECTED_PIPELINE_CI_PROJECT_PATH'
      file: '$PROTECTED_PIPELINE_CI_CONFIG_PATH'
      ref: '$PROTECTED_PIPELINE_CI_REF'
      rules:
        - if: $PROTECTED_PIPELINE_CI_PROJECT_PATH && $PROTECTED_PIPELINE_CI_CONFIG_PATH && $PROTECTED_PIPELINE_CI_REF
    # If any custom path variable is not defined, include the project's internal config file as normal.
    - project: '$CI_PROJECT_PATH'
      file: '$CI_CONFIG_PATH'
      ref: '$CI_COMMIT_SHA'
      rules:
        - if: $PROTECTED_PIPELINE_CI_PROJECT_PATH == null || $PROTECTED_PIPELINE_CI_CONFIG_PATH == null || $PROTECTED_PIPELINE_CI_REF == null
  ```

- Des [variables CI/CD](../../ci/variables/_index.md) doivent être ajoutées aux projets avec une configuration de pipeline externe. Dans cet exemple :

  - `PROTECTED_PIPELINE_CI_PROJECT_PATH` : le chemin vers le projet hébergeant le fichier de configuration, par exemple `group/subgroup/project`.
  - `PROTECTED_PIPELINE_CI_CONFIG_PATH` : le chemin vers le fichier de configuration dans le projet, par exemple `path/to/.gitlab-ci.yml`.
  - `PROTECTED_PIPELINE_CI_REF` : la référence à utiliser lors de la récupération du fichier de configuration, par exemple `main`.

#### Pipelines de conformité dans les merge requests provenant de duplications de projet {#compliance-pipelines-in-merge-requests-originating-in-project-forks}

Lorsqu'une merge request provient d'une duplication, la branche à fusionner n'existe généralement que dans la duplication. Lors de la création d'une telle merge request contre un projet avec des pipelines de conformité, le fragment précédent échoue avec le message d'erreur `Project <project-name> reference <branch-name> does not exist!`. Cette erreur se produit car dans le contexte du projet cible, `$CI_COMMIT_REF_NAME` est évalué comme un nom de branche inexistant.

Pour obtenir le contexte correct, utilisez `$CI_MERGE_REQUEST_SOURCE_PROJECT_PATH` à la place de `$CI_PROJECT_PATH`. Cette variable n'est disponible que dans les [pipelines de merge request](../../ci/pipelines/merge_request_pipelines.md).

Par exemple, pour une configuration qui prend en charge à la fois les pipelines de merge request provenant de duplications de projet et les pipelines de branche, vous devez [combiner les deux directives `include` avec `rules:if`](../../ci/yaml/includes.md#use-rules-with-include) :

```yaml
include:  # Execute individual project's configuration (if project contains .gitlab-ci.yml)
  - project: '$CI_MERGE_REQUEST_SOURCE_PROJECT_PATH'
    file: '$CI_CONFIG_PATH'
    ref: '$CI_COMMIT_REF_NAME'
    rules:
      - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
  - project: '$CI_PROJECT_PATH'
    file: '$CI_CONFIG_PATH'
    ref: '$CI_COMMIT_REF_NAME'
    rules:
      - if: $CI_PIPELINE_SOURCE != 'merge_request_event'
```

#### Pipelines de conformité dans les projets sans fichier de configuration {#compliance-pipelines-in-projects-with-no-configuration-file}

L'[exemple de configuration](#example-configuration) suppose que tous les projets contiennent un fichier de configuration de pipeline (`.gitlab-ci.yml` par défaut). Cependant, dans les projets sans fichier de configuration (et donc sans pipeline par défaut), le pipeline de conformité échoue car le fichier spécifié dans `include:project` est obligatoire.

Pour n'inclure un fichier de configuration que s'il existe dans un projet cible, utilisez [`rules:exists:project`](../../ci/yaml/_index.md#rulesexistsproject) :

```yaml
include:  # Execute individual project's configuration
  - project: '$CI_PROJECT_PATH'
    file: '$CI_CONFIG_PATH'
    ref: '$CI_COMMIT_SHA'
    rules:
      - exists:
          paths:
            - '$CI_CONFIG_PATH'
          project: '$CI_PROJECT_PATH'
          ref: '$CI_COMMIT_SHA'
```

Dans cet exemple, un fichier de configuration n'est inclus que s'il existe pour le `ref` donné dans le projet spécifié dans `exists:project: '$CI_PROJECT_PATH'`.

Si `exists:project` n'est pas spécifié dans la configuration du pipeline de conformité, le système recherche des fichiers dans le projet dans lequel `include` est défini. Dans les pipelines de conformité, le `include` de l'exemple précédent est défini dans le projet hébergeant le fichier de configuration du pipeline de conformité, et non dans le projet exécutant le pipeline.

## S'assurer que les jobs de conformité sont toujours exécutés {#ensure-compliance-jobs-are-always-run}

Les pipelines de conformité [utilisent GitLab CI/CD](../../ci/_index.md) pour vous offrir une flexibilité exceptionnelle dans la définition de tout type de jobs de conformité. En fonction de vos objectifs, ces jobs peuvent être configurés pour être :

- Modifiables par les utilisateurs.
- Non modifiables.

En général, si une valeur dans un job de conformité :

- Est définie, elle ne peut pas être modifiée ou remplacée par des configurations au niveau du projet.
- N'est pas définie, une configuration au niveau du projet peut être définie.

L'un ou l'autre peut être souhaitable ou non selon votre cas d'usage.

Voici quelques bonnes pratiques pour s'assurer que ces jobs sont toujours exécutés exactement comme vous les avez définis et que les configurations de pipeline en aval, au niveau du projet, ne peuvent pas les modifier :

- Ajoutez [un bloc `rules:when:always`](../../ci/yaml/_index.md#when) à chacun de vos jobs de conformité. Cela garantit qu'ils sont non modifiables et qu'ils sont toujours exécutés.
- Définissez explicitement toutes les [variables](../../ci/yaml/_index.md#variables) référencées par le job. Cela :
  - Garantit que les configurations de pipeline au niveau du projet ne les définissent pas et n'altèrent pas leur comportement. Par exemple, consultez la configuration de `before_script` et de `after_script` dans l'[exemple de configuration](#example-configuration).
  - Inclut tous les jobs qui pilotent la logique de votre job.
- Définissez explicitement l'[image de conteneur](../../ci/yaml/_index.md#image) dans laquelle exécuter le job. Cela garantit que les étapes de votre script s'exécutent dans le bon environnement.
- Définissez explicitement tous les [mots-clés de job](../../ci/yaml/_index.md#job-keywords) prédéfinis GitLab pertinents. Cela garantit que votre job utilise les paramètres que vous avez prévus et qu'ils ne sont pas remplacés par des pipelines au niveau du projet.

## Dépannage {#troubleshooting}

### Les jobs de conformité sont écrasés par le dépôt cible {#compliance-jobs-are-overwritten-by-target-repository}

Si vous utilisez l'instruction `extends` dans une configuration de pipeline de conformité, les jobs de conformité sont écrasés par le job du dépôt cible. Par exemple, vous pourriez avoir la configuration `.compliance-gitlab-ci.yml` suivante :

```yaml
"compliance job":
  extends:
    - .compliance_template
  stage: build

.compliance_template:
  script:
    - echo "take compliance action"
```

Vous pourriez également avoir la configuration `.gitlab-ci.yml` suivante :

```yaml
"compliance job":
  stage: test
  script:
    - echo "overwriting compliance action"
```

Cette configuration entraîne l'écrasement du pipeline de conformité par le pipeline du dépôt cible, et vous obtenez le message suivant : `overwriting compliance action`.

Pour éviter d'écraser un job de conformité, n'utilisez pas le mot-clé `extends` dans la configuration du pipeline de conformité. Par exemple, vous pourriez avoir la configuration `.compliance-gitlab-ci.yml` suivante :

```yaml
"compliance job":
  stage: build
  script:
    - echo "take compliance action"
```

Vous pourriez également avoir la configuration `.gitlab-ci.yml` suivante :

```yaml
"compliance job":
  stage: test
  script:
    - echo "overwriting compliance action"
```

Cette configuration n'écrase pas le pipeline de conformité et vous obtenez le message suivant : `take compliance action`.

### Les variables préremplies ne sont pas affichées {#prefilled-variables-are-not-shown}

En raison d'un [problème connu](https://gitlab.com/gitlab-org/gitlab/-/issues/382857), les pipelines de conformité peuvent empêcher l'affichage des [variables préremplies](../../ci/pipelines/_index.md#prefill-variables-in-manual-pipelines) lors du démarrage manuel d'un pipeline.

Pour contourner ce problème, utilisez `ref: '$CI_COMMIT_SHA'` à la place de `ref: '$CI_COMMIT_REF_NAME'` dans l'instruction `include:` qui exécute la configuration du projet individuel.

L'[exemple de configuration](#example-configuration) a été mis à jour avec ce changement :

```yaml
include:
  - project: '$CI_PROJECT_PATH'
    file: '$CI_CONFIG_PATH'
    ref: '$CI_COMMIT_SHA'
```

### Erreur : `Job names must be unique` {#error-job-names-must-be-unique}

Pour configurer un pipeline de conformité, l'[exemple de configuration](#example-configuration) recommande d'inclure la configuration du projet individuel avec `include.project`.

Cette configuration peut entraîner une erreur lors de l'exécution du pipeline des projets : `Pipeline execution policy error: Job names must be unique`. Cette erreur se produit parce que la politique d'exécution de pipeline inclut le fichier `.gitlab-ci.yml` du projet et tente d'insérer les jobs alors que ceux-ci ont déjà été déclarés dans le pipeline.

Pour résoudre cette erreur, supprimez `include.project` du fichier YAML distinct lié dans la politique d'exécution de pipeline.

<!--- end_remove -->
