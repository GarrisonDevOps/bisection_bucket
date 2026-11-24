---
stage: Agent Foundations
group: Agent Developer
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Flow Convert to GitLab CI/CD
---

{{< details >}}

- Édition : [Gratuite](../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Introduit en version [bêta](../../policy/development_stages_support.md) dans GitLab 18.3 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `duo_workflow_in_ci`. Désactivé par défaut, mais peut être activé pour l'instance ou un utilisateur.
- Le feature flag `duo_workflow_in_ci` est activé par défaut dans GitLab 18.4. Le feature flag `duo_workflow` doit également être activé, mais il l'est par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273) dans GitLab 18.8.
- Les feature flags `duo_workflow_in_ci` et `duo_workflow` ont été supprimés dans GitLab 18.9.
- Disponible dans l'édition Gratuite sur GitLab.com avec GitLab Credits dans GitLab 18.10.

{{< /history >}}

Le flow Convert to GitLab CI/CD vous aide à migrer vos pipelines Jenkins vers GitLab CI/CD. Ce flow :

- Analyse votre configuration de pipeline Jenkins existante.
- Convertit la syntaxe de pipeline Jenkins en YAML GitLab CI/CD.
- Suggère les meilleures pratiques pour l'implémentation de GitLab CI/CD.
- Crée une merge request avec la configuration de pipeline convertie.
- Fournit des conseils sur la migration des plugins Jenkins vers les fonctionnalités GitLab.

Ce flow est disponible uniquement dans l'interface utilisateur de GitLab.

## Prérequis {#prerequisites}

- Satisfaire aux [prérequis pour GitLab Duo Agent Platform](../../user/duo_agent_platform/_index.md#prerequisites).
- Activez {{< ui text="Autoriser les flows par défaut" >}} et {{< ui text="Convertir pour GitLab CI/CD" >}} [pour le groupe principal](../../user/duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off).
- Disposer du rôle Developer, Maintainer ou Owner pour le projet GitLab cible.
- Avoir accès à votre configuration de pipeline Jenkins.
- [Configurer les règles push pour autoriser un compte de service](../../user/duo_agent_platform/troubleshooting.md#configure-push-rules-to-allow-a-service-account).
- [Configurer vos propres runners](../../user/duo_agent_platform/flows/execution/_index.md#configure-runners-to-execute-flows) ou activer les [runners hébergés par GitLab](../../ci/runners/hosted_runners/_index.md) pour votre projet.
- Recommandé. Créez un [fichier de configuration d'agent](../../user/duo_agent_platform/flows/execution/_index.md#create-the-agent-configuration-file) afin que le flow ait accès à la chaîne d'outils et aux dépendances de votre projet.

## Utiliser le flow {#use-the-flow}

Pour convertir votre Jenkinsfile en GitLab CI/CD :

1. Dans la barre supérieure, sélectionnez {{< ui text="Rechercher ou accéder à" >}} et trouvez votre projet.
1. Ouvrez votre Jenkinsfile.
1. Au-dessus du fichier, sélectionnez {{< ui text="Convertir en GitLab CI/CD" >}}.
1. Suivez la progression en sélectionnant {{< ui text="IA" >}} > {{< ui text="Sessions" >}}.
1. Une fois le pipeline exécuté avec succès, dans la barre latérale gauche, sélectionnez {{< ui text="Code" >}} > {{< ui text="Requêtes de fusion" >}}. Une merge request avec le titre `Duo Workflow: Convert to GitLab CI` s'affiche.
1. Examinez la merge request et apportez les modifications nécessaires.

### Processus de conversion {#conversion-process}

Le processus convertit :

- Les étapes et les actions du pipeline.
- Les variables d'environnement.
- Les déclencheurs et les paramètres de build.
- Les artefacts et les dépendances.
- L'exécution parallèle.
- La logique conditionnelle.
- Les actions post-build.

## Exemple {#example}

Entrée Jenkinsfile :

```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'npm install'
                sh 'npm build'
            }
        }
        stage('Test') {
            steps {
                sh 'npm test'
            }
        }
        stage('Deploy') {
            when { branch 'main' }
            steps {
                sh './deploy.sh'
            }
        }
    }
}
```

Sortie GitLab :

```yaml
stages:
  - build
  - test
  - deploy

build:
  stage: build
  script:
    - npm install
    - npm build
  artifacts:
    paths:
      - node_modules/
      - dist/

test:
  stage: test
  script:
    - npm test

deploy:
  stage: deploy
  script:
    - ./deploy.sh
  only:
    - main
```
