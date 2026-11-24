---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Intégrez GitLab à Beyond Identity pour vérifier les clés GPG ajoutées aux comptes utilisateurs.
title: Beyond Identity
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Dans GitLab, les utilisateurs peuvent signer leurs commits après [avoir ajouté une clé GPG à leur profil](../repository/signed_commits/gpg.md). L'intégration GitLab avec [Beyond Identity](https://www.beyondidentity.com/) étend cette fonctionnalité.

Une fois configurée, cette intégration utilise Beyond Identity pour valider toute nouvelle clé GPG qu'un utilisateur ajoute à son profil. Les clés qui ne passent pas la validation sont rejetées et l'utilisateur doit téléverser une nouvelle clé.

Lorsqu'un utilisateur envoie un commit signé vers l'instance GitLab, GitLab effectue une vérification de pré-réception pour valider ces commits par rapport à la clé GPG stockée dans le profil de l'utilisateur. Cela garantit que seuls les commits signés avec des clés validées sont acceptés.

## Configurer l'intégration Beyond Identity pour votre instance {#set-up-the-beyond-identity-integration-for-your-instance}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance GitLab.
- L'adresse e-mail utilisée dans le profil GitLab doit être identique à celle associée à la clé dans l'authentificateur Beyond Identity.
- Vous devez disposer d'un jeton d'API Beyond Identity. Vous pouvez en faire la demande auprès de leur ingénieur commercial.

Pour activer l'intégration Beyond Identity pour votre instance :

1. Connectez-vous à GitLab en tant qu'administrateur.
1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Beyond Identity**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Dans **Jeton d'API**, collez le jeton d'API reçu de Beyond Identity.
1. Sélectionnez **Enregistrer les modifications**.

L'intégration Beyond Identity pour votre instance est désormais activée.

## Vérification des clés GPG {#gpg-key-verification}

Lorsqu'un utilisateur ajoute une clé GPG à son profil, la clé est vérifiée :

- Si la clé n'a pas été émise par l'authentificateur Beyond Identity, elle est acceptée.
- Si la clé a été émise par l'authentificateur Beyond Identity, mais que la clé est invalide, elle est rejetée. Par exemple : l'e-mail utilisé dans le profil GitLab de l'utilisateur est différent de l'e-mail associé à la clé dans l'authentificateur Beyond Identity.

Lorsqu'un utilisateur envoie un commit, GitLab vérifie que le commit a été signé par une signature GPG téléversée dans le profil de l'utilisateur. Si la signature ne peut pas être vérifiée, l'envoi est rejeté. Les commits Web sont acceptés sans signature.

## Ignorer la vérification de push pour les comptes de service {#skip-push-check-for-service-accounts}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance GitLab.

Pour ignorer la vérification de push pour les [comptes de service](../../profile/service_accounts.md) :

1. Connectez-vous à GitLab en tant qu'administrateur.
1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Beyond Identity**.
1. Cochez la case **Exclure les comptes de service**.
1. Sélectionnez **Enregistrer les modifications**.

## Exclure des groupes ou des projets de la vérification Beyond Identity {#exclude-groups-or-projects-from-the-beyond-identity-check}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/454372) dans GitLab 17.0 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `beyond_identity_exclusions`. Activés par défaut.
- Option permettant d'exclure des groupes [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/454372) dans GitLab 17.1.
- [Disponible de manière générale](https://gitlab.com/gitlab-org/gitlab/-/issues/457893) dans GitLab 17.7. Le feature flag `beyond_identity_exclusions` a été supprimé.

{{< /history >}}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance GitLab.

Pour exclure des groupes ou des projets de la vérification Beyond Identity :

1. Connectez-vous à GitLab en tant qu'administrateur.
1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Beyond Identity**.
1. Sélectionnez l'onglet **Exclusions**.
1. Sélectionnez **Ajouter des exclusions**.
1. Dans le panneau latéral, recherchez et sélectionnez les groupes ou les projets à exclure.
1. Sélectionnez **Ajouter des exclusions**.
