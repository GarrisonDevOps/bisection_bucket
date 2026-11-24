---
stage: Verify
group: Mobile DevOps
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Apple App Store Connect
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Cette fonctionnalité fait partie de [Mobile DevOps](../../../ci/mobile_devops/_index.md) développé par GitLab. La fonctionnalité est encore en cours de développement, mais vous pouvez :

- [Demander une fonctionnalité](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=feature_request).
- [Signaler un bug](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=report_bug).
- [Partager vos retours](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=general_feedback).

Utilisez l'intégration Apple App Store Connect pour configurer vos pipelines CI/CD afin de vous connecter à [App Store Connect](https://appstoreconnect.apple.com). Avec cette intégration, vous pouvez créer et publier des applications pour iOS, iPadOS, macOS, tvOS et watchOS.

L'intégration Apple App Store Connect fonctionne immédiatement avec [fastlane](https://fastlane.tools/). Vous pouvez également utiliser cette intégration avec d'autres outils de build.

## Activer l'intégration dans GitLab {#enable-the-integration-in-gitlab}

Prérequis :

- Vous devez disposer d'un identifiant Apple inscrit au [Apple Developer Program](https://developer.apple.com/programs/enroll/).
- Vous devez [générer une nouvelle clé privée](https://developer.apple.com/documentation/appstoreconnectapi/creating_api_keys_for_app_store_connect_api) pour votre projet dans le portail Apple App Store Connect.

Pour activer l'intégration Apple App Store Connect dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Apple App Store Connect**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Renseignez les informations de configuration Apple App Store Connect :
   - **Issuer ID** : l'identifiant d'émetteur (issuer ID) Apple App Store Connect.
   - **Key ID** : l'identifiant de clé (key ID) de la clé privée générée.
   - **Clé privée** : la clé privée générée. Vous ne pouvez télécharger cette clé qu'une seule fois.
   - **Étiquettes et branches protégées uniquement** : activez cette option pour définir des variables uniquement sur les branches et les étiquettes protégées.
1. Sélectionnez **Enregistrer les modifications**.

Une fois l'intégration activée :

- Les variables globales `$APP_STORE_CONNECT_API_KEY_ISSUER_ID`, `$APP_STORE_CONNECT_API_KEY_KEY_ID`, `$APP_STORE_CONNECT_API_KEY_KEY` et `$APP_STORE_CONNECT_API_KEY_IS_KEY_CONTENT_BASE64` sont créées pour une utilisation CI/CD.
- `$APP_STORE_CONNECT_API_KEY_KEY` contient la clé privée encodée en Base64.
- `$APP_STORE_CONNECT_API_KEY_IS_KEY_CONTENT_BASE64` est toujours `true`.

## Considérations relatives à la sécurité {#security-considerations}

### Sécurité des variables CI/CD {#cicd-variable-security}

Du code malveillant intégré à votre fichier `.gitlab-ci.yml` pourrait compromettre vos variables, notamment `$APP_STORE_CONNECT_API_KEY_KEY`, et les envoyer à un serveur tiers. Pour en savoir plus, consultez la section [Sécurité des variables CI/CD](../../../ci/variables/_index.md#cicd-variable-security).

## Activer l'intégration dans fastlane {#enable-the-integration-in-fastlane}

Pour activer l'intégration dans fastlane et publier une release TestFlight ou une release publique sur l'App Store, vous pouvez ajouter le code suivant au fichier `fastlane/Fastfile` de votre application :

```ruby
app_store_connect_api_key
```
