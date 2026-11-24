---
stage: Verify
group: Mobile DevOps
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Google Play
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Cette fonctionnalité fait partie de [Mobile DevOps](../../../ci/mobile_devops/_index.md) développé par GitLab. La fonctionnalité est encore en cours de développement, mais vous pouvez :

- [Demander une fonctionnalité](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=feature_request).
- [Signaler un bug](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=report_bug).
- [Partager vos commentaires](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=general_feedback).

Avec l'intégration Google Play, vous pouvez configurer vos pipelines CI/CD pour vous connecter à la [Google Play Console](https://play.google.com/console/about/) afin de créer et de publier des applications pour les appareils Android.

L'intégration Google Play fonctionne immédiatement avec [fastlane](https://fastlane.tools/). Vous pouvez également utiliser cette intégration avec d'autres outils de compilation.

## Activer l'intégration dans GitLab {#enable-the-integration-in-gitlab}

Prérequis :

- Vous devez disposer d'un compte développeur [Google Play Console](https://play.google.com/console/about/).
- Vous devez [générer une nouvelle clé de compte de service pour votre projet](https://developers.google.com/android-publisher/getting_started) depuis la console Google Cloud.

Pour activer l'intégration Google Play dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Google Play**.
1. Dans **Activer l'intégration**, cochez la case **Actif**.
1. Dans **Nom du package**, saisissez le nom du package de l'application (par exemple, `com.gitlab.app_name`).
1. Facultatif. Sous **Étiquettes et branches protégées uniquement**, cochez la case **Définir des variables uniquement sur les étiquettes et branches protégées**.
1. Dans **Clé de compte de service (.JSON)**, faites glisser ou importez votre fichier de clé.
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

Une fois l'intégration activée, les variables globales `$SUPPLY_PACKAGE_NAME` et `$SUPPLY_JSON_KEY_DATA` sont créées pour une utilisation CI/CD.

### Sécurité des variables CI/CD {#cicd-variable-security}

Du code malveillant poussé vers votre fichier `.gitlab-ci.yml` pourrait compromettre vos variables, notamment `$SUPPLY_JSON_KEY_DATA`, et les envoyer vers un serveur tiers. Pour plus d'informations, consultez [Sécurité des variables CI/CD](../../../ci/variables/_index.md#cicd-variable-security).

## Activer l'intégration dans fastlane {#enable-the-integration-in-fastlane}

Pour activer l'intégration dans fastlane et téléverser la compilation vers la piste donnée dans Google Play, vous pouvez ajouter le code suivant au fichier `fastlane/Fastfile` de votre application :

```ruby
upload_to_play_store(
  track: 'internal',
  aab: '../build/app/outputs/bundle/release/app-release.aab'
)
```
