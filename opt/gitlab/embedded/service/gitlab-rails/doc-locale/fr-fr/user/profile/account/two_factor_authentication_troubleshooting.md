---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
gitlab_dedicated: yes
title: "Dépannage de l'authentification à deux facteurs"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

## Erreur : `HTTP Basic: Access denied. If a password was provided for Git authentication ...` {#error-http-basic-access-denied-if-a-password-was-provided-for-git-authentication-}

Lors d'une requête, vous pouvez obtenir une erreur indiquant :

```plaintext
HTTP Basic: Access denied. If a password was provided for Git authentication,
the password was incorrect or you're required to use a token instead of a password.
If a token was provided, it was either incorrect, expired, or improperly scoped.
```

Cette erreur se produit dans les cas suivants :

- Vous avez activé la 2FA et tenté de vous authentifier avec un nom d'utilisateur et un mot de passe.
- Vous n'avez pas activé la 2FA, mais elle est obligatoire pour l'instance GitLab. Cela s'applique à GitLab.com. Pour plus d'informations, voir [Mandatory MFA Changes](https://support.gitlab.com/hc/en-us/articles/26704344871452-Upcoming-Mandatory-MFA-Changes) et [dépannage de l'OTP par e-mail](#email-otp-troubleshooting).
- Vous n'avez pas activé la 2FA et avez tenté de vous authentifier avec un nom d'utilisateur ou un mot de passe incorrect.
- Vous n'avez pas activé la 2FA et le paramètre [enforce 2FA for all users](../../../security/two_factor_authentication.md#enforce-2fa-for-all-users) est actif.
- Vous n'avez pas activé la 2FA et la case [**Autoriser l'authentification par mot de passe pour Git en HTTP(S)**](../../../administration/settings/sign_in_restrictions.md#allow-password-authentication-for-git-over-https) n'est pas cochée.

Pour résoudre cette erreur :

- Utilisez un [jeton d'accès personnel](../personal_access_tokens.md) avec les portées appropriées :
  - Pour les requêtes Git via HTTP(S) : `read_repository` ou `write_repository`
  - Pour les requêtes du [registre de conteneurs GitLab](../../packages/container_registry/authenticate_with_container_registry.md) : `read_registry` ou `write_registry`
  - Pour les requêtes du [proxy de dépendances](../../packages/dependency_proxy/_index.md#authenticate-with-the-dependency-proxy-for-container-images) : `read_registry` et `write_registry`

  Ces portées s'appliquent aux jetons d'accès personnels classiques. Les jetons d'accès personnels à granularité fine utilisent des ressources et des permissions à la place. Pour les équivalents à granularité fine, voir [permissions à granularité fine pour Git et autres opérations](../../../auth/tokens/fine_grained_access_tokens_other.md). Vous ne pouvez pas utiliser des jetons d'accès personnels à granularité fine pour pousser des images de conteneurs.
- Si vous avez configuré LDAP, utilisez un [mot de passe LDAP](../../../administration/auth/ldap/_index.md).
- Utilisez un [assistant d'accréditation OAuth](two_factor_authentication.md#oauth-credential-helpers).

## Erreur : `invalid pin code` {#error-invalid-pin-code}

Une erreur `invalid pin code` peut indiquer un problème de synchronisation de l'heure entre l'application d'authentification et l'instance GitLab elle-même.

Pour résoudre ce problème, activez la synchronisation de l'heure sur l'appareil qui génère vos codes 2FA.

{{< tabs >}}

{{< tab title="Android" >}}

1. Accédez à **Paramètres** > **Système** > **Date et heure**.
1. Activez **Définir l'heure automatiquement**. Si le paramètre est déjà activé, désactivez-le, attendez quelques secondes, puis réactivez-le.

{{< /tab >}}

{{< tab title="iOS" >}}

1. Accédez à **Paramètres** > **Général** > **Date et heure**.
1. Activez **Réglage automatique**. Si le paramètre est déjà activé, désactivez-le, attendez quelques secondes, puis réactivez-le.

{{< /tab >}}

{{< /tabs >}}

## Erreur : `Permission denied (publickey)` lors de la génération des codes de récupération {#error-permission-denied-publickey-when-generating-recovery-codes}

Vous pouvez obtenir une erreur indiquant `Permission denied (publickey)`.

Ce problème se produit si vous utilisez un chemin de fichier de paire de clés SSH non défini par défaut et que vous tentez de [générer des codes de récupération via SSH](#regenerate-recovery-codes-with-ssh).

Pour résoudre ce problème, [configurez SSH pour pointer vers un répertoire différent](../../ssh_advanced.md#use-ssh-keys-in-another-directory) en utilisant `ssh-agent`.

## Dépannage de l'OTP par e-mail {#email-otp-troubleshooting}

Lorsque vous utilisez l'OTP par e-mail, vous pouvez rencontrer les problèmes suivants.

> [!note]
> À partir d'avril 2026, l'authentification multifacteur est obligatoire sur GitLab.com pour toute connexion ou requête API utilisant un nom d'utilisateur et un mot de passe. [L'OTP par e-mail](two_factor_authentication.md#sign-in-with-email-otp) est le second facteur obligatoire sur GitLab.com si aucun autre facteur n'est configuré.

### Bannière d'authentification améliorée et exigence de code d'accès {#enhanced-authentication-banner-and-passcode-requirement}

La bannière **Authentification améliorée bientôt disponible** signale que GitLab commencera à appliquer les [codes d'accès à usage unique par e-mail](two_factor_authentication.md#sign-in-with-email-otp) pour votre compte lors de la connexion par mot de passe. Les utilisateurs qui se connectent via SSO ou qui ont déjà configuré la 2FA ne sont pas concernés.

Cette bannière apparaît 14 jours avant l'application de la mesure. 7 jours avant l'application de la mesure, GitLab vous envoie un code d'accès à usage unique à chaque connexion par mot de passe. Vous pouvez ignorer la saisie du code d'accès durant cette période.

Une fois la date d'application passée, vous devez saisir un code d'accès à usage unique à chaque connexion par mot de passe. Pour éviter d'être bloqué, assurez-vous de pouvoir accéder à votre adresse e-mail principale ou [modifiez votre adresse e-mail principale](../_index.md#change-your-primary-email).

### Code de vérification par e-mail non reçu ou code expiré {#didnt-receive-email-verification-code-or-code-has-expired}

Attendez une minute que l'e-mail arrive, puis vérifiez votre dossier spam. Sur GitLab.com, les e-mails sont envoyés depuis `gitlab@mg.gitlab.com` et peuvent être [vérifiés comme authentiques](https://handbook.gitlab.com/handbook/security/corporate/systems/google/mail/verification/#verify-an-email-from-gitlabcom-is-genuine).

Si le code n'arrive pas ou a expiré, sélectionnez **Renvoyer le code** depuis l'écran de connexion. Chaque renvoi génère un nouveau code et invalide le précédent ; attendez donc chaque e-mail avant d'en demander un autre.

### Impossible d'accéder à votre adresse e-mail {#cannot-access-your-email-address}

Si vous ne pouvez pas accéder à votre adresse e-mail principale, vous pouvez envoyer le code à une autre adresse associée à votre compte.

Si vous ne pouvez accéder à aucune adresse e-mail associée :

- Si vous avez précédemment configuré SSO, connectez-vous avec SSO plutôt qu'avec un nom d'utilisateur et un mot de passe.
- Si vous êtes un utilisateur entreprise GitLab.com, demandez à votre propriétaire de groupe de [modifier votre adresse e-mail](../../enterprise_user/_index.md#change-the-email-addresses-for-an-enterprise-user).
- Sur GitLab Self-Managed, contactez votre administrateur GitLab.
- [Contactez le support GitLab](https://support.gitlab.com/).

### Impossible d'activer ou de désactiver l'OTP par e-mail {#email-otp-cannot-be-enabled-or-disabled}

Vous ne pouvez pas désactiver l'OTP par e-mail si :

- Votre instance exige la 2FA et vous n'avez pas enregistré d'[authentificateur OTP](two_factor_authentication.md#register-an-otp-authenticator) ni d'[appareil WebAuthn](two_factor_authentication.md#register-a-webauthn-device).
- Votre compte est programmé pour une activation automatique à une date ultérieure.

Vous ne pouvez pas activer l'OTP par e-mail si :

- Votre groupe, votre instance ou la politique d'administration vous oblige à utiliser un authentificateur OTP ou un appareil WebAuthn.
- Votre compte utilise un fournisseur d'identité externe.
- Votre compte est programmé pour une activation automatique à une date ultérieure.

## Options de récupération et réinitialisation de la 2FA {#recovery-options-and-2fa-reset}

### Utiliser un code de récupération {#use-a-recovery-code}

Lorsque vous avez activé un authentificateur à mot de passe à usage unique (OTP), GitLab vous a fourni une série de [codes de récupération](two_factor_authentication.md#recovery-codes). Vous pouvez utiliser ces codes pour vous connecter à votre compte.

Pour utiliser un code de récupération :

1. Sur la page de connexion GitLab, saisissez votre nom d'utilisateur ou votre adresse e-mail, ainsi que votre mot de passe.
1. Sur l'écran de vérification en deux étapes, sélectionnez **Récupérer votre compte**.
1. Sur l'écran **Saisir le code de récupération du compte**, saisissez un code de récupération, puis sélectionnez **Vérifier le code**.

Après avoir utilisé un code de récupération, vous ne pouvez pas utiliser le même code à nouveau. Vos autres codes de récupération restent valides.

### Régénérer les codes de récupération via l'interface utilisateur {#regenerate-recovery-codes-with-the-ui}

Si vous pouvez toujours accéder à votre compte, vous pouvez régénérer vos codes de récupération via vos paramètres utilisateur.

Pour régénérer les codes de récupération via l'interface utilisateur :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Mot de passe et authentification**.
1. Dans la section **Codes de récupération**, sélectionnez **Régénérer les codes de récupération**.
1. Dans la boîte de dialogue, saisissez votre mot de passe actuel et sélectionnez **Régénérer les codes de récupération**.

> [!note]
> Chaque fois que vous régénérez des codes de récupération 2FA, enregistrez-les. Vous ne pouvez pas utiliser les codes 2FA précédemment créés.

### Régénérer les codes de récupération via SSH {#regenerate-recovery-codes-with-ssh}

Si vous avez [ajouté une clé SSH à votre compte GitLab](../../ssh.md#add-an-ssh-key-to-your-gitlab-account), vous pouvez régénérer vos codes de récupération via SSH.

Prérequis :

- Accès à la clé SSH privée associée à la clé SSH publique enregistrée dans votre compte GitLab.

> [!note]
> Vous ne pouvez pas utiliser `gitlab-sshd` pour régénérer les codes de récupération.

Pour régénérer les codes de récupération via SSH :

1. Dans le terminal, vérifiez que l'agent SSH est en cours d'exécution sur votre appareil.
   - Sur macOS et Linux, exécutez la commande suivante :

     ```shell
     eval "$(ssh-agent -s)"
     ```

   - Sur Microsoft Windows, exécutez la commande suivante dans PowerShell :

     ```pwsh
     Set-Service -Name ssh-agent -StartupType Automatic; Start-Service ssh-agent
     ```

     Pour plus d'informations, voir [Instructions de configuration SSH pour Windows](../../ssh_advanced.md#use-ssh-on-microsoft-windows).

1. Chargez la clé privée dans l'agent SSH avec la commande suivante :
   - Sur macOS et Linux, exécutez la commande suivante :

     ```shell
     ssh-add <path to private SSH key file>
     ```

   Pour plus d'informations, voir [Utiliser des clés SSH dans un autre répertoire](../../ssh_advanced.md#use-ssh-keys-in-another-directory).

1. Ouvrez une connexion SSH avec la commande suivante :

   ```shell
   ssh git@gitlab.com 2fa_recovery_codes
   ```

   Sur les instances GitLab Self-Managed, remplacez `gitlab.com` par le nom d'hôte du serveur GitLab (`gitlab.example.com`).

1. Sur le message de confirmation, saisissez `yes`.
1. Enregistrez les codes de récupération générés par GitLab. Vos codes de récupération précédents ne sont plus valides.
1. Sur la page de connexion, saisissez votre nom d'utilisateur ou votre adresse e-mail, ainsi que votre mot de passe.
1. Sur l'écran de vérification en deux étapes, sélectionnez **Récupérer votre compte**.
1. Sur l'écran **Saisir le code de récupération du compte**, saisissez un code de récupération, puis sélectionnez **Vérifier le code**.

Après la connexion, configurez immédiatement la 2FA avec un nouvel appareil.

### Restaurer les codes 2FA à partir d'une sauvegarde de l'application d'authentification {#restore-2fa-codes-from-authenticator-backup}

En plus des codes de récupération GitLab, de nombreuses applications d'authentification proposent leurs propres méthodes de sauvegarde et de récupération. Si vous perdez votre appareil, vous pourrez peut-être restaurer vos codes 2FA en vous connectant à votre application d'authentification sur un nouvel appareil, à condition d'avoir activé les fonctionnalités de sauvegarde au préalable.

Prérequis :

- Vous devez activer les fonctionnalités de sauvegarde de votre application d'authentification avant de perdre l'accès à votre appareil.

> [!note]
> GitLab recommande d'utiliser les codes de récupération comme méthode de récupération principale. Assurez-vous d'enregistrer vos codes de récupération lorsque vous activez la 2FA.

Le support GitLab ne peut pas vous aider en cas de problèmes de récupération liés à des applications d'authentification tierces.

Pour plus d'informations, consultez la documentation de votre application d'authentification spécifique. La documentation des authentificateurs courants est disponible aux emplacements suivants :

- [Microsoft Authenticator](https://support.microsoft.com/en-US/authenticator/restore-account-credentials-from-microsoft-authenticator)
- [Google Authenticator](https://support.google.com/accounts/answer/1066447)
- [Authy](https://www.twilio.com/en-us/blog/how-the-authy-two-factor-backups-work)
- [1Password](https://support.1password.com/recovery-codes/?mac#recover-your-account)

### Réinitialiser la 2FA sur votre compte {#reset-2fa-on-your-account}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Si les options de récupération précédentes ne fonctionnent pas, vous pouvez créer une demande d'assistance pour désactiver la 2FA sur votre compte. Ce service est uniquement disponible pour les comptes avec un abonnement GitLab.com.

Le support GitLab ne peut pas réinitialiser la 2FA pour les comptes Gratuite. Si vous ne pouvez pas récupérer votre méthode 2FA, vous serez définitivement bloqué hors de votre compte et devrez en créer un nouveau. Pour plus d'informations, voir l'[annonce du blog](https://about.gitlab.com/blog/gitlab-support-no-longer-processing-mfa-resets-for-free-users/).

Pour créer une demande d'assistance :

1. Accédez au [support GitLab](https://support.gitlab.com).
1. Sélectionnez **Soumettre un ticket**.
1. Connectez-vous avec votre compte de support GitLab. Votre compte de support est différent de votre compte GitLab et n'est pas affecté par votre problème de 2FA.
1. Dans la liste déroulante du ticket, sélectionnez **GitLab.com user accounts and login issues**.
1. Renseignez les champs du formulaire d'assistance.
1. Sélectionnez **Envoyer**.

Après avoir retrouvé l'accès à votre compte, réactivez la 2FA dès que possible pour sécuriser votre compte.

### Réinitialiser la 2FA pour les utilisateurs entreprise {#reset-2fa-for-enterprise-users}

Si vous êtes propriétaire d'un groupe principal sur un plan payant, vous pouvez désactiver la 2FA pour les utilisateurs entreprise. Pour plus d'informations, voir [désactiver la 2FA pour les utilisateurs entreprise](../../../security/two_factor_authentication.md#enterprise-users).
