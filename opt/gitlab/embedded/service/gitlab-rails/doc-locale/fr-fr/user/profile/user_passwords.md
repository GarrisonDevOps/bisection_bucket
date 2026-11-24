---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Mots de passe des utilisateurs
description: "Sécurisez les mots de passe des utilisateurs grâce à l'application des exigences et aux procédures de réinitialisation des mots de passe."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si vous utilisez un mot de passe pour vous connecter à GitLab, un mot de passe robuste est très important. Un mot de passe faible ou facile à deviner facilite la connexion de personnes non autorisées à votre compte.

Certaines organisations vous demandent de respecter certaines exigences lors du choix d'un mot de passe.

Améliorez la sécurité de votre compte grâce à l'[authentification à deux facteurs](account/two_factor_authentication.md).

## Exigences relatives aux mots de passe {#password-requirements}

Les exigences relatives aux mots de passe s'appliquent lorsque vous :

- Choisissez un mot de passe lors de l'inscription.
- Réinitialisez votre mot de passe.
- Modifiez votre mot de passe.
- Demandez à un administrateur de créer ou de mettre à jour votre compte.

Par défaut, GitLab applique les exigences suivantes :

- Longueur minimale du mot de passe : 8 caractères.
- Longueur maximale du mot de passe : 128 caractères.
- Ne doit pas correspondre à une liste de plus de 4 500 mots de passe connus et compromis.
- Ne doit pas contenir une partie de votre nom, de votre nom d'utilisateur ou de votre adresse e-mail.
- Ne doit pas contenir un mot prévisible (par exemple, `gitlab` ou `devops`).

Sur GitLab Self-Managed et GitLab Dedicated, les administrateurs peuvent [modifier les exigences de complexité des mots de passe](../../administration/settings/sign_up_restrictions.md#modify-password-complexity-requirements).

## Détection des mots de passe compromis {#compromised-password-detection}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/188723) dans GitLab 18.0 [avec le feature flag](../../administration/feature_flags/_index.md) `notify_compromised_passwords`. Fonctionnalité désactivée par défaut.
- Activé sur GitLab.com dans GitLab 18.1. Le feature flag `notify_compromised_passwords` a été supprimé.

{{< /history >}}

GitLab peut vous notifier si vos identifiants GitLab.com sont compromis dans le cadre d'une violation de données sur un autre service ou une autre plateforme. Les identifiants GitLab sont chiffrés et GitLab lui-même n'y a pas accès directement.

Lorsqu'un identifiant compromis est détecté, GitLab affiche une bannière de sécurité et envoie une alerte par e-mail qui inclut des instructions sur la façon de changer votre mot de passe et de renforcer la sécurité de votre compte.

La détection des mots de passe compromis n'est pas disponible lors de l'authentification [avec un fournisseur externe](../../administration/auth/_index.md), ou si votre compte est déjà [verrouillé](../../security/unlock_user.md).

## Choisir votre mot de passe {#choose-your-password}

Vous pouvez choisir un mot de passe lorsque vous [créez un compte utilisateur](account/create_accounts.md).

### Mots de passe pour les comptes authentifiés en externe {#passwords-for-externally-authenticated-accounts}

Si votre compte a été créé avec un [fournisseur d'authentification et d'autorisation](../../administration/auth/_index.md) externe, GitLab génère automatiquement un mot de passe aléatoire pour maintenir la cohérence des données.

Ce mot de passe possède les propriétés suivantes :

- 128 caractères de longueur
- Généré à l'aide de la [méthode `friendly_token` du gem Devise](https://github.com/heartcombo/devise/blob/f26e05c20079c9acded3c0ee16da0df435a28997/lib/devise.rb#L492)
- Unique et sécurisé

En général, vous n'avez pas besoin de connaître ni d'utiliser ce mot de passe. Cependant, vous pourriez avoir besoin de le saisir pour créer une clé d'accès ou dans d'autres situations similaires.

Si vous devez saisir votre mot de passe GitLab, vous pouvez suivre le [processus de réinitialisation du mot de passe](#reset-your-password) pour en créer un nouveau que vous pourrez utiliser.

Cela n'affecte pas le mot de passe de votre fournisseur d'identité externe.

## Modifier votre mot de passe {#change-your-password}

Vous pouvez modifier votre mot de passe. Le nouveau mot de passe doit satisfaire aux exigences relatives aux mots de passe.

Pour modifier votre mot de passe :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Mot de passe et authentification**.
1. Sélectionnez **Changer le mot de passe**.
1. Dans la zone de texte **Mot de passe actuel**, saisissez votre mot de passe actuel.
1. Dans les zones de texte **Nouveau mot de passe** et **Confirmation du mot de passe**, saisissez votre nouveau mot de passe.
1. Sélectionnez **Enregistrer le mot de passe**.

## Réinitialiser votre mot de passe {#reset-your-password}

Si vous oubliez votre mot de passe, vous pouvez soumettre une demande de réinitialisation de votre mot de passe.

Pour réinitialiser votre mot de passe :

1. Accédez à la page de connexion GitLab.
   - Sur GitLab.com, celle-ci est disponible à l'adresse [https://gitlab.com/users/sign_in](https://gitlab.com/users/sign_in/).
   - Sur GitLab Self-Managed et GitLab Dedicated, utilisez votre domaine. Par exemple, `gitlab.example.com/users/sign_in`.
1. Sélectionnez **Mot de passe oublié ?**.
1. Saisissez votre adresse e-mail.
1. Sélectionnez **Réinitialiser le mot de passe**.

Vous êtes redirigé vers la page de connexion. Si l'adresse e-mail fournie est vérifiée et associée à un compte existant, GitLab envoie un e-mail de réinitialisation du mot de passe.

> [!note]
> Votre compte peut avoir plusieurs adresses e-mail vérifiées, et toute adresse e-mail associée à votre compte peut être vérifiée. Cependant, seule l'adresse e-mail principale peut être utilisée pour se connecter une fois le mot de passe réinitialisé.

## Stockage des identifiants {#credential-storage}

GitLab stocke les mots de passe des utilisateurs dans un format haché, et non en texte brut. Pour hacher les mots de passe, GitLab utilise la bibliothèque d'authentification [Devise](https://github.com/heartcombo/devise).

Les hachages de mots de passe utilisent les mesures de sécurité suivantes :

- Algorithme de hachage :
  - Bcrypt : utilisé par défaut.
  - PBKDF2+SHA512 : utilisé lorsque le mode FIPS est activé.
- Étirement : les mots de passe sont [étirés](https://en.wikipedia.org/wiki/Key_stretching) pour se protéger contre les attaques par force brute. Le facteur d'étirement dépend de l'algorithme de hachage :
  - Bcrypt : 10
  - PBKDF2+SHA512 : 20 000
- Salage : un [sel cryptographique](https://en.wikipedia.org/wiki/Salt_(cryptography)) aléatoire est généré pour chaque mot de passe afin de se protéger contre les attaques par hachage précalculé et par dictionnaire. Chaque mot de passe possède un sel unique.

Les jetons d'accès OAuth sont également stockés dans la base de données au format PBKDF2+SHA512 et étirés 20 000 fois.
