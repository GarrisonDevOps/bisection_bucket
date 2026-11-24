---
stage: Fulfillment
group: Provision
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Créer des comptes utilisateurs dans GitLab.
title: Créer des utilisateurs
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les comptes utilisateurs constituent le fondement de la collaboration dans GitLab. Toute personne ayant besoin d'accéder à vos projets GitLab doit disposer d'un compte. Les comptes utilisateurs contrôlent les autorisations d'accès, suivent les contributions et maintiennent la sécurité de votre instance.

Vous pouvez créer des comptes utilisateurs dans GitLab de différentes manières :

- Créer manuellement des comptes utilisateurs pour les équipes qui valorisent l'autonomie
- Création pilotée par l'administrateur pour un onboarding contrôlé
- Intégration d'authentification pour les environnements d'entreprise
- Accès à la console pour l'automatisation et les opérations en masse

Vous pouvez également utiliser le [point d'entrée de l'API des utilisateurs](../../../api/users.md#create-a-user) pour créer automatiquement des utilisateurs.

Choisissez la méthode appropriée en fonction de la taille de votre organisation, de ses exigences de sécurité et de ses workflows.

## Créer un utilisateur sur la page de connexion {#create-a-user-on-the-sign-in-page}

Par défaut, tout utilisateur visitant votre instance GitLab peut créer un compte. Si vous avez précédemment [désactivé ce paramètre](../../../administration/settings/sign_up_restrictions.md#disable-new-user-account-creation), vous devez le réactiver.

Les utilisateurs peuvent créer leur propre compte en :

- Sélectionnant le lien **Inscrivez-vous maintenant** sur la page de connexion.
- Accédant au lien de création de compte de votre instance GitLab (par exemple : `https://gitlab.example.com/users/sign_up`).

## Créer un utilisateur dans la zone d'administration {#create-a-user-in-the-admin-area}

Prérequis :

- Vous devez être administrateur de l'instance.

Pour créer un utilisateur :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Vue d'ensemble** > **Utilisateurs**.
1. Sélectionnez **Nouvel utilisateur**.
1. Dans la section **Compte**, saisissez les informations de compte requises.
1. Facultatif. Dans la section **Accès**, configurez les limites de projet ou les paramètres de type d'utilisateur souhaités.
1. Sélectionnez **Créer un utilisateur**.

GitLab envoie un e-mail à l'utilisateur avec un lien de connexion, et l'utilisateur doit créer un mot de passe lors de sa première connexion. Vous pouvez également [définir un mot de passe](../../../security/reset_user_password.md#use-the-ui) directement pour l'utilisateur.

## Créer un utilisateur via une intégration d'authentification {#create-a-user-with-an-authentication-integration}

GitLab peut créer automatiquement des comptes utilisateurs via des intégrations d'authentification. Les utilisateurs sont créés lorsqu'ils :

- Sont provisionnés via [SCIM](../../group/saml_sso/scim_setup.md) dans le fournisseur d'identité.
- Se connectent pour la première fois avec :
  - [LDAP](../../../administration/auth/ldap/_index.md)
  - [SAML de groupe](../../group/saml_sso/_index.md)
  - Un [fournisseur OmniAuth](../../../integration/omniauth.md) dont le paramètre `allow_single_sign_on` est activé

## Créer un utilisateur via la console Rails {#create-a-user-through-the-rails-console}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

> [!warning]
> Les commandes qui modifient des données peuvent causer des dommages si elles ne sont pas exécutées correctement ou dans les bonnes conditions. Exécutez toujours les commandes dans un environnement de test au préalable et disposez d'une instance de sauvegarde prête à être restaurée.

Pour créer un utilisateur via la console Rails :

1. Démarrez une [session de console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session).
1. Exécutez la commande correspondant à votre version de GitLab :

   {{< tabs >}}

   {{< tab title="16.10 et versions antérieures" >}}

   ```ruby
   u = User.new(username: 'test_user', email: 'test@example.com', name: 'Test User', password: 'password', password_confirmation: 'password')
   # u.assign_personal_namespace
   u.skip_confirmation! # Use only if you want the user to be automatically confirmed. If you do not use this, the user receives a confirmation email.
   u.save!
   ```

   {{< /tab >}}

   {{< tab title="16.11 à 17.6" >}}

   ```ruby
   u = User.new(username: 'test_user', email: 'test@example.com', name: 'Test User', password: 'password', password_confirmation: 'password')
   u.assign_personal_namespace(Organizations::Organization.default_organization)
   u.skip_confirmation! # Use only if you want the user to be automatically confirmed. If you do not use this, the user receives a confirmation email.
   u.save!
   ```

   {{< /tab >}}

   {{< tab title="17.7 et versions ultérieures" >}}

   ```ruby
   u = Users::CreateService.new(nil,
     username: 'test_user',
     email: 'test@example.com',
     name: 'Test User',
     password: '123password',
     password_confirmation: '123password',
     organization_id: Organizations::Organization.first.id,
     skip_confirmation: true
   ).execute
   ```

   > [!note]
   > Si vous avez [désactivé les nouveaux comptes utilisateurs](../../../administration/settings/sign_up_restrictions.md#disable-new-user-account-creation), vous devez exécuter cette commande en tant qu'administrateur. Dans la commande précédente, remplacez `Users::CreateService.new(nil,` par `Users::CreateService.new(User.find_by(admin: true),`

   {{< /tab >}}

   {{< /tabs >}}
