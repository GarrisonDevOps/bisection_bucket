---
stage: Security Risk Management
group: Security Platform Management
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Configuration de la sécurité
description: "Configuration, test, conformité, analyse et activation."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez configurer les scanners de sécurité pour des projets individuellement ou créer une configuration de scanner partagée par plusieurs projets. La configuration manuelle de chaque projet offre une flexibilité maximale, mais devient difficile à maintenir à grande échelle. Pour plusieurs projets ou groupes, une configuration de scanner partagée facilite la gestion tout en permettant certaines personnalisations selon les besoins.

Par exemple, si vous disposez de 10 projets avec la même configuration d'analyse de sécurité appliquée manuellement, une seule modification doit être effectuée 10 fois. Si vous créez plutôt une configuration CI/CD partagée, la modification ne doit être effectuée qu'une seule fois.

## Configurer un projet individuel {#configure-an-individual-project}

Pour configurer l'analyse de sécurité dans un projet individuel, vous pouvez :

- Modifier le fichier de configuration CI/CD.
- Modifier la configuration CI/CD dans l'interface utilisateur.

### Avec un fichier CI/CD {#with-a-cicd-file}

Pour activer manuellement l'analyse de sécurité de projets individuels, vous pouvez :

- Activer des scanners de sécurité individuels.
- Activer tous les scanners de sécurité en utilisant AutoDevOps.

AutoDevOps offre un chemin à moindre effort pour activer la plupart des scanners de sécurité. Cependant, les options de personnalisation sont limitées, comparées à l'activation de scanners de sécurité individuels.

#### Activer des scanners de sécurité individuels {#enable-individual-security-scanners}

Pour activer des outils d'analyse de sécurité individuels avec la possibilité de personnaliser les paramètres, incluez les templates du scanner de sécurité dans votre fichier `.gitlab-ci.yml`.

Pour obtenir des instructions sur l'activation des scanners de sécurité individuels, consultez leur documentation.

#### Activer l'analyse de sécurité avec Auto DevOps {#enable-security-scanning-by-using-auto-devops}

Pour activer les outils d'analyse de sécurité suivants avec les paramètres par défaut, activez [Auto DevOps](../../../topics/autodevops/_index.md) :

- [Auto SAST](../../../topics/autodevops/stages.md#auto-sast)
- [Détection automatique des secrets](../../../topics/autodevops/stages.md#auto-secret-detection)
- [Auto DAST](../../../topics/autodevops/stages.md#auto-dast)
- [Analyse automatique des dépendances](../../../topics/autodevops/stages.md#auto-dependency-scanning)
- [Analyse automatique des conteneurs](../../../topics/autodevops/stages.md#auto-container-scanning)

Bien que vous ne puissiez pas personnaliser directement Auto DevOps, vous pouvez [inclure le template Auto DevOps dans le fichier `.gitlab-ci.yml` de votre projet](../../../topics/autodevops/customize.md#customize-gitlab-ciyml) et remplacer ses paramètres selon vos besoins.

### Avec l'interface utilisateur {#with-the-ui}

Utilisez la page **Configuration de la sécurité** pour afficher et configurer les paramètres de test de sécurité et de gestion des vulnérabilités d'un projet.

L'onglet **Tests de sécurité** reflète le statut de chacun des outils de sécurité en vérifiant le pipeline CI/CD dans le commit le plus récent sur la branche par défaut.

Activé : l'artefact de l'outil de test de sécurité a été trouvé dans la sortie du pipeline.

Non activé : soit aucun pipeline CI/CD n'existe, soit l'artefact de l'outil de test de sécurité n'a pas été trouvé dans la sortie du pipeline.

#### Afficher la page de configuration de la sécurité {#view-security-configuration-page}

Prérequis :

- Le rôle Responsable sécurité, Chargé de maintenance ou Propriétaire pour le projet.

Pour afficher la configuration de sécurité d'un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Sécurisation** > **Configuration de la sécurité**.

Pour afficher un historique des modifications apportées au fichier de configuration CI/CD, sélectionnez **Historique de la configuration**.

#### Modifier la configuration de sécurité d'un projet {#edit-a-projects-security-configuration}

Prérequis :

- Le rôle Responsable sécurité, Chargé de maintenance ou Propriétaire pour le projet.

Pour modifier la configuration de sécurité d'un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Sécurisation** > **Configuration de la sécurité**.
1. Sélectionnez le scanner de sécurité que vous souhaitez activer ou configurer et suivez les instructions.

Pour plus d'informations sur l'activation et la configuration des scanners de sécurité individuels, consultez leur documentation.

## Créer une configuration partagée {#create-a-shared-configuration}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour appliquer la même configuration d'analyse de sécurité à plusieurs projets, utilisez l'une des méthodes suivantes :

- [Politique d'exécution des scans](../policies/scan_execution_policies.md)
- [Politique d'exécution de pipeline](../policies/pipeline_execution_policies.md)

Chacune de ces méthodes permet de définir une configuration CI/CD, incluant l'analyse de sécurité, une seule fois et de l'appliquer à plusieurs projets et groupes. Ces méthodes présentent plusieurs avantages par rapport à la configuration individuelle de chaque projet, notamment :

- Les modifications de configuration ne doivent être effectuées qu'une seule fois au lieu de l'être pour chaque projet.
- L'autorisation d'effectuer des modifications de configuration est restreinte, ce qui assure une séparation des responsabilités.

## Personnaliser l'analyse de sécurité {#customize-security-scanning}

Vous pouvez personnaliser l'analyse de sécurité pour répondre à vos exigences et à votre environnement. Pour plus d'informations sur la personnalisation des scanners de sécurité individuels, consultez leur documentation.

### Bonnes pratiques {#best-practices}

Lors de la personnalisation de la configuration d'analyse de sécurité :

- Testez toute personnalisation des outils d'analyse de sécurité en utilisant une merge request avant de fusionner les modifications dans la branche par défaut. Ne pas le faire peut donner des résultats inattendus, y compris un grand nombre de faux positifs.
- [Incluez](../../../ci/yaml/_index.md#include) le template CI/CD de l'outil d'analyse. Ne copiez pas le contenu du template.
- Ne remplacez les valeurs dans le template que si nécessaire. Toutes les autres valeurs sont héritées du template.
- Utilisez l'édition stable de chaque template pour les workflows de production. L'édition stable change moins souvent, et les changements cassants ne sont effectués qu'entre les versions majeures de GitLab. La dernière version contient les modifications les plus récentes, mais peut présenter des changements significatifs entre les versions mineures de GitLab.

### Éditions de templates {#template-editions}

Les outils de sécurité des applications GitLab proposent jusqu'à trois éditions de templates :

- **Stable** : le template stable est le template par défaut. Il offre une expérience de sécurité des applications fiable et cohérente. Il est recommandé d'utiliser le template stable pour la plupart des utilisateurs et des projets nécessitant une stabilité et un comportement prévisible dans leurs pipelines CI/CD.
- **Latest** : le template latest est destiné à ceux qui souhaitent accéder aux fonctionnalités de pointe et les tester. Il est identifié par le mot `latest` dans le nom du template. Il n'est pas considéré comme stable et peut inclure des changements cassants prévus pour la prochaine version majeure. Ce template vous permet d'essayer les nouvelles fonctionnalités et mises à jour avant qu'elles ne fassent partie de la release stable.
- **Versionné** : un template versionné introduit des changements cassants qui ne sont pas rétrocompatibles avec le template stable. Les templates versionnés ont un suffixe de version (comme `v2`, `v3`) dans le nom du template. Chaque version est stable dans sa version majeure, mais vous devez choisir de l'adopter en raison des changements cassants. Seule l'analyse des dépendances fournit un template versionné (`Dependency-Scanning.v2.gitlab-ci.yml`), qui exécute [l'analyse des dépendances avec SBOM](../dependency_scanning/dependency_scanning_sbom/_index.md). Pour plus d'informations, consultez le [guide de migration](../dependency_scanning/migration_guide_to_sbom_based_scans.md).

> [!note]
> Ne mélangez pas les templates de sécurité **Stable** et **Latest** dans le même projet. Le mélange de différentes éditions de templates de sécurité peut entraîner l'exécution des pipelines de merge request et de branche.

### Remplacer l'adresse de base du registre par défaut {#override-the-default-registry-base-address}

Par défaut, les scanners de sécurité GitLab utilisent `registry.gitlab.com/security-products` comme adresse de base pour les images Docker. Vous pouvez remplacer cette valeur pour la plupart des scanners en définissant la variable CI/CD `SECURE_ANALYZERS_PREFIX` sur un autre emplacement. Cela affecte tous les scanners simultanément.

L'analyseur de [scan de conteneurs](../container_scanning/_index.md) est une exception et n'utilise pas la variable `SECURE_ANALYZERS_PREFIX`. Pour remplacer son image Docker, consultez les instructions pour [Exécuter le scan de conteneurs dans un environnement hors connexion](../container_scanning/_index.md#offline-environment).

### Utiliser des outils d'analyse de sécurité avec les pipelines de merge request {#use-security-scanning-tools-with-merge-request-pipelines}

Par défaut, les jobs de sécurité des applications sont configurés pour s'exécuter uniquement pour les pipelines de branche. Pour les utiliser avec les [pipelines de merge request](../../../ci/pipelines/merge_request_pipelines.md), vous pouvez :

- Définir la variable CI/CD `AST_ENABLE_MR_PIPELINES` sur `"true"` ([introduit dans la version 18.0](https://gitlab.com/gitlab-org/gitlab/-/issues/410880)) (recommandé)
- Utiliser le [template d'édition `latest`](#template-editions), qui active les pipelines de merge request par défaut.

Par exemple, pour exécuter à la fois SAST et l'analyse des dépendances avec les pipelines de merge request activés, la configuration suivante est utilisée :

```yaml
include:
  - template: Jobs/Dependency-Scanning.v2.gitlab-ci.yml
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  AST_ENABLE_MR_PIPELINES: "true"
```

### Utiliser une étape d'analyse personnalisée {#use-a-custom-scanning-stage}

Les templates de scanner de sécurité utilisent par défaut l'étape `test` prédéfinie. Pour les faire s'exécuter dans une étape différente, ajoutez le nom de l'étape personnalisée à la section `stages:` du fichier `.gitlab-ci.yml`.

Pour plus d'informations sur le remplacement des jobs de sécurité, consultez :

- [Remplacer les jobs SAST](../sast/_index.md#override-sast-jobs).
- [Remplacement des jobs d'analyse des dépendances](../dependency_scanning/dependency_scanning_sbom/_index.md#customizing-analyzer-behavior).
- [Remplacement des jobs de scan de conteneurs](../container_scanning/_index.md#overriding-the-container-scanning-template).
- [Remplacement des jobs de détection des secrets](../secret_detection/pipeline/configure.md).
- [Remplacement des jobs DAST](../dast/browser/_index.md).

## Dépannage {#troubleshooting}

Lors de la configuration de l'analyse de sécurité, vous pourriez rencontrer les problèmes suivants.

### Erreur : `chosen stage test does not exist` {#error-chosen-stage-test-does-not-exist}

Lors de l'exécution d'un pipeline, vous pourriez obtenir une erreur indiquant `chosen stage test does not exist`.

Ce problème survient lorsque l'étape utilisée par les jobs d'analyse de sécurité n'est pas déclarée dans le fichier `.gitlab-ci.yml`.

Pour résoudre ce problème, vous pouvez :

- Ajouter une étape `test` dans votre `.gitlab-ci.yml` :

  ```yaml
  stages:
    - test
    - unit-tests

  include:
    - template: Jobs/Dependency-Scanning.v2.gitlab-ci.yml
    - template: Jobs/SAST.gitlab-ci.yml
    - template: Jobs/Secret-Detection.gitlab-ci.yml

  custom job:
    stage: unit-tests
    script:
      - echo "custom job"
  ```

- Remplacer l'étape par défaut de chaque job de sécurité. Par exemple, pour utiliser une étape prédéfinie nommée `unit-tests` :

  ```yaml
  stages:
    - unit-tests

  include:
    - template: Jobs/Dependency-Scanning.v2.gitlab-ci.yml
      inputs:
        stage: unit-tests
    - template: Jobs/SAST.gitlab-ci.yml
    - template: Jobs/Secret-Detection.gitlab-ci.yml

  sast:
    stage: unit-tests

  .secret-analyzer:
    stage: unit-tests

  custom job:
    stage: unit-tests
    script:
      - echo "custom job"
  ```
