---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
gitlab_dedicated: yes
title: Authentification à deux facteurs
description: "Activez l'authentification multifacteur pour une protection renforcée de votre compte."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'authentification à deux facteurs (2FA) apporte un niveau de sécurité supplémentaire à votre compte GitLab. Pour accéder à votre compte, d'autres personnes auraient besoin de votre nom d'utilisateur, de votre mot de passe et d'un accès à votre second facteur d'authentification.

GitLab prend en charge les méthodes 2FA suivantes :

- Clés d'accès. Lors de la connexion, GitLab vous invite à vous authentifier avec votre clé d'accès. Après avoir activé la 2FA, les clés d'accès deviennent une option 2FA supplémentaire et par défaut. Pour plus d'informations, consultez [les clés d'accès](../../../auth/passkeys.md).
- Authentificateurs à mot de passe unique ([OTP](https://datatracker.ietf.org/doc/html/rfc6238)). Lors de la connexion, GitLab vous invite à saisir un code généré par votre authentificateur OTP.
- Périphériques WebAuthn. Lors de la connexion, GitLab vous invite à prouver que vous êtes bien le propriétaire de votre périphérique WebAuthn. Il s'agit généralement d'un périphérique physique tel qu'une YubiKey, votre téléphone ou votre ordinateur portable.
- OTP par email. Lors de la connexion, GitLab vous invite à saisir un code envoyé à votre adresse email.

Si vous configurez un périphérique, configurez également un OTP afin de pouvoir toujours accéder à votre compte si vous perdez le périphérique.

## Activer l'authentification à deux facteurs {#enable-two-factor-authentication}

Pour activer la 2FA, vérifiez votre adresse email et enregistrez un authentificateur OTP, un périphérique WebAuthn ou l'OTP par email.

### Enregistrer un authentificateur OTP {#register-an-otp-authenticator}

> [!warning]
> Si vous perdez l'accès à votre authentificateur OTP, vous risquez d'être bloqué hors de votre compte.
>
> Pour minimiser ce risque :
>
> - Activez la sauvegarde cloud dans votre application d'authentification.
> - Enregistrez vos mots de passe de sauvegarde, vos clés secrètes ou vos identifiants de récupération dans un endroit sécurisé.
> - Consultez la documentation de votre authentificateur OTP spécifique.
>
> Si vous êtes déjà bloqué, consultez [les options de récupération et la réinitialisation de la 2FA](two_factor_authentication_troubleshooting.md#recovery-options-and-2fa-reset).

Pour enregistrer un authentificateur OTP :

1. Configurez GitLab.
   1. Dans le coin supérieur droit, sélectionnez votre avatar.
   1. Sélectionnez **Modifier le profil**.
   1. Dans la barre latérale gauche, sélectionnez **Accès** > **Mot de passe et authentification**.
   1. Dans la section **Authentificateur à mot de passe unique**, sélectionnez **Enregistrer un authentificateur**. Un code QR et vos informations OTP sont affichés.
1. Configurez votre périphérique.
   1. Installez une application OTP compatible sur votre périphérique. Par exemple :
      - Basée sur le cloud (recommandée, car vous pouvez restaurer l'accès si vous perdez le périphérique matériel) :
        - [Authy](https://authy.com/).
        - [Cisco Duo](https://duo.com/).
      - Autres (propriétaires) :
        - [Google Authenticator](https://support.google.com/accounts/answer/1066447?hl=en).
        - [Microsoft Authenticator](https://www.microsoft.com/en-us/security/mobile-authenticator-app).
      - Autres (logiciels libres)
        - [Aegis Authenticator](https://getaegis.app/).
        - [FreeOTP](https://freeotp.github.io/).
   1. Dans l'application, ajoutez une nouvelle entrée de l'une des deux façons suivantes :
      - Scannez le code affiché par GitLab avec l'appareil photo de votre périphérique pour ajouter l'entrée automatiquement.
      - Saisissez les informations fournies pour ajouter l'entrée manuellement.
1. Terminez l'enregistrement :
   1. Saisissez votre mot de passe actuel.
   1. Saisissez le code PIN à six chiffres généré par votre authentificateur.
   1. Sélectionnez **S'inscrire avec l'application 2FA**.

Si vous avez saisi le bon code PIN, GitLab affiche une liste de [codes de récupération](#recovery-codes). Téléchargez-les et conservez-les en lieu sûr.

Si votre authentificateur OTP prend en charge les sauvegardes cloud, envisagez de configurer cette fonctionnalité maintenant. Pour plus d'informations, consultez la documentation de votre authentificateur spécifique.

### Enregistrer un périphérique WebAuthn {#register-a-webauthn-device}

{{< history >}}

- Authentification à mot de passe unique optionnelle pour les périphériques WebAuthn [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/378844) dans GitLab 15.10 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `webauthn_without_totp`.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/396931) dans GitLab 17.6. Suppression du feature flag `webauthn_without_totp`.

{{< /history >}}

WebAuthn est [pris en charge par](https://caniuse.com/#search=webauthn) les éléments suivants :

- Navigateurs de bureau :
  - Chrome
  - Edge
  - Firefox
  - Opera
  - Safari
- Navigateurs mobiles :
  - Chrome pour Android
  - Firefox pour Android
  - iOS Safari (depuis iOS 13.3)

Pour enregistrer un périphérique compatible WebAuthn :

1. Si vous utilisez un périphérique physique, branchez-le sur votre ordinateur.
1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Mot de passe et authentification**.
1. Dans la section **Périphériques WebAuthn**, sélectionnez **Enregistrer un appareil**.
1. Sélectionnez **Configurer un nouvel appareil**.
1. Suivez les instructions affichées dans la fenêtre de votre navigateur.
1. Selon votre périphérique, vous devrez peut-être appuyer sur un bouton ou toucher un capteur.
1. Saisissez le mot de passe de votre compte GitLab et un nom de périphérique. Il est possible que vous n'ayez pas besoin de saisir ce mot de passe si vous vous êtes connecté via votre fournisseur d'identité.
1. Sélectionnez **Enregistrer un appareil**.

Vous devriez recevoir un message indiquant que vous avez correctement configuré votre périphérique.

Lorsque vous configurez la 2FA avec un périphérique compatible WebAuthn, ce périphérique est associé à un navigateur spécifique sur un ordinateur spécifique. Selon le navigateur et le périphérique WebAuthn, vous pourrez peut-être configurer des paramètres pour utiliser le périphérique WebAuthn sur un autre navigateur ou un autre ordinateur.

S'il s'agit de la première fois que vous configurez la 2FA, vous devez [télécharger les codes de récupération](#recovery-codes) pour pouvoir récupérer l'accès à votre compte si vous perdez l'accès.

> [!warning]
> Vous risquez de perdre l'accès à votre compte si vous effacez les données de votre navigateur.

### Activer l'OTP par email {#enable-email-otp}

{{< history >}}

- Introduit dans GitLab 18.7 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `email_based_mfa`. Fonctionnalité désactivée par défaut.
- Activé sur GitLab.com dans GitLab 18.7, avec un déploiement progressif pour tous les utilisateurs tout au long de 2026.
- Nouveau paramètre d'application `email_otp_enabled` [introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/599948) dans GitLab 19.1. Fonctionnalité désactivée par défaut.
- [Suppression](https://gitlab.com/gitlab-org/gitlab/-/work_items/599948) du feature flag `email_based_mfa` dans GitLab 19.2. L'OTP par email est désormais contrôlé par le paramètre d'application `email_otp_enabled`.

{{< /history >}}

L'OTP par email vous permet de [vérifier votre identité](../../../security/email_verification.md) en envoyant un code de vérification à six chiffres à votre adresse email.

Prérequis :

- L'OTP par email doit être activé pour votre instance.

Pour activer l'OTP par email pour votre compte :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Mot de passe et authentification**.
1. Sélectionnez **Activer l'OTP par email**.
1. Saisissez votre mot de passe actuel et sélectionnez **Mettre à jour les paramètres d'OTP par email**.

### Ajouter un authentificateur Cisco Duo {#add-a-cisco-duo-authenticator}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

Vous pouvez utiliser Cisco Duo comme fournisseur OTP dans GitLab.

DUO® est une marque déposée de Cisco Systems, Inc., et/ou de ses affiliés aux États-Unis et dans certains autres pays.

Prérequis :

- Votre compte doit exister à la fois dans Cisco Duo et dans GitLab, avec le même nom d'utilisateur dans les deux applications.
- Vous devez avoir [configuré Cisco Duo](https://admin.duosecurity.com/) et disposer d'une clé d'intégration, d'une clé secrète et d'un nom d'hôte API.

Pour plus d'informations, consultez la [documentation de l'API Cisco Duo](https://duo.com/docs/authapi).

1. Ouvrez le fichier de configuration de GitLab.

   Pour les installations de paquets Linux :

   ```shell
   sudo editor /etc/gitlab/gitlab.rb
   ```

   Pour les installations compilées manuellement :

   ```shell
   cd /home/git/gitlab
   sudo -u git -H editor config/gitlab.yml
   ```

1. Ajoutez la configuration du fournisseur.

   Pour les installations de paquets Linux :

   ```ruby
    gitlab_rails['duo_auth_enabled'] = true
    gitlab_rails['duo_auth_integration_key'] = '<duo_integration_key_value>'
    gitlab_rails['duo_auth_secret_key'] = '<duo_secret_key_value>'
    gitlab_rails['duo_auth_hostname'] = '<duo_api_hostname>'
   ```

   Pour les installations compilées manuellement :

   ```yaml
   duo_auth:
     enabled: true
     hostname: <duo_api_hostname>
     integration_key: <duo_integration_key_value>
     secret_key: <duo_secret_key_value>
   ```

1. Enregistrez le fichier de configuration.
1. Pour les installations avec le paquet Linux, [reconfigurez GitLab](../../../administration/restart_gitlab.md#reconfigure-a-linux-package-installation). Pour les installations compilées manuellement, [redémarrez GitLab](../../../administration/restart_gitlab.md#self-compiled-installations).

### Ajouter un authentificateur FortiAuthenticator {#add-a-fortiauthenticator-authenticator}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

> [!flag]
> Sur GitLab Self-Managed, cette fonctionnalité n'est pas disponible par défaut. Pour le rendre disponible par utilisateur, un administrateur peut [activer le feature flag](../../../administration/feature_flags/_index.md) nommé `forti_authenticator`. Sur GitLab.com et GitLab Dedicated, cette fonctionnalité n'est pas disponible.

Vous pouvez utiliser FortiAuthenticator comme fournisseur OTP dans GitLab. Les utilisateurs doivent :

- Exister à la fois dans FortiAuthenticator et dans GitLab avec le même nom d'utilisateur.
- Avoir FortiToken configuré dans FortiAuthenticator.

Vous avez besoin d'un nom d'utilisateur et d'un jeton d'accès pour FortiAuthenticator. Le `access_token` indiqué ci-dessous est la clé d'accès FortiAuthenticator. Pour obtenir le jeton, consultez le guide de solution d'API REST sur la [Bibliothèque de documents Fortinet](https://docs.fortinet.com/document/fortiauthenticator/6.2.0/rest-api-solution-guide/158294/the-fortiauthenticator-api). Testé avec FortiAuthenticator version 6.2.0.

Configurez FortiAuthenticator dans GitLab. Sur votre serveur GitLab :

1. Ouvrez le fichier de configuration.

   Pour les installations de paquets Linux :

   ```shell
   sudo editor /etc/gitlab/gitlab.rb
   ```

   Pour les installations compilées manuellement :

   ```shell
   cd /home/git/gitlab
   sudo -u git -H editor config/gitlab.yml
   ```

1. Ajoutez la configuration du fournisseur.

   Pour les installations de paquets Linux :

   ```ruby
   gitlab_rails['forti_authenticator_enabled'] = true
   gitlab_rails['forti_authenticator_host'] = 'forti_authenticator.example.com'
   gitlab_rails['forti_authenticator_port'] = 443
   gitlab_rails['forti_authenticator_username'] = '<some_username>'
   gitlab_rails['forti_authenticator_access_token'] = 's3cr3t'
   ```

   Pour les installations compilées manuellement :

   ```yaml
   forti_authenticator:
     enabled: true
     host: forti_authenticator.example.com
     port: 443
     username: <some_username>
     access_token: s3cr3t
   ```

1. Enregistrez le fichier de configuration.
1. [Reconfigurez](../../../administration/restart_gitlab.md#reconfigure-a-linux-package-installation) (installations à partir du package Linux) ou [redémarrez](../../../administration/restart_gitlab.md#self-compiled-installations) (installations compilées manuellement).

### Ajouter un authentificateur FortiToken Cloud {#add-a-fortitoken-cloud-authenticator}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

> [!flag]
> Sur GitLab Self-Managed, cette fonctionnalité n'est pas disponible par défaut. Pour le rendre disponible par utilisateur, un administrateur peut [activer le feature flag](../../../administration/feature_flags/_index.md) nommé `forti_token_cloud`. Sur GitLab.com et GitLab Dedicated, cette fonctionnalité n'est pas disponible. Cette fonctionnalité n'est pas prête pour une utilisation en production.

Vous pouvez utiliser FortiToken Cloud comme fournisseur OTP dans GitLab. Les utilisateurs doivent :

- Exister à la fois dans FortiToken Cloud et dans GitLab avec le même nom d'utilisateur.
- Avoir FortiToken configuré dans FortiToken Cloud.

Vous avez besoin d'un `client_id` et d'un `client_secret` pour configurer FortiToken Cloud. Pour les obtenir, consultez le guide d'API REST sur la [Bibliothèque de documents Fortinet](https://docs.fortinet.com/document/fortitoken-cloud/latest/rest-api/456035/overview).

Configurez FortiToken Cloud dans GitLab. Sur votre serveur GitLab :

1. Ouvrez le fichier de configuration.

   Pour les installations de paquets Linux :

   ```shell
   sudo editor /etc/gitlab/gitlab.rb
   ```

   Pour les installations compilées manuellement :

   ```shell
   cd /home/git/gitlab
   sudo -u git -H editor config/gitlab.yml
   ```

1. Ajoutez la configuration du fournisseur.

   Pour les installations de paquets Linux :

   ```ruby
   gitlab_rails['forti_token_cloud_enabled'] = true
   gitlab_rails['forti_token_cloud_client_id'] = '<your_fortinet_cloud_client_id>'
   gitlab_rails['forti_token_cloud_client_secret'] = '<your_fortinet_cloud_client_secret>'
   ```

   Pour les installations compilées manuellement :

   ```yaml
   forti_token_cloud:
     enabled: true
     client_id: YOUR_FORTI_TOKEN_CLOUD_CLIENT_ID
     client_secret: YOUR_FORTI_TOKEN_CLOUD_CLIENT_SECRET
   ```

1. Enregistrez le fichier de configuration.
1. [Reconfigurez](../../../administration/restart_gitlab.md#reconfigure-a-linux-package-installation) (installations à partir du package Linux) ou [redémarrez](../../../administration/restart_gitlab.md#self-compiled-installations) (installations compilées manuellement).

## Codes de récupération {#recovery-codes}

Immédiatement après avoir activé la 2FA avec un authentificateur OTP, vous êtes invité à télécharger un ensemble de codes de récupération générés. Si vous perdez l'accès à votre authentificateur OTP, vous pouvez utiliser l'un de ces codes de récupération pour vous connecter à votre compte.

Vous devriez copier et imprimer les codes, ou utiliser **Télécharger les codes** pour les télécharger et les stocker dans un endroit sûr. Si vous choisissez de les télécharger, le fichier s'appelle `gitlab-recovery-codes.txt`.

> [!note]
>
> - Vous ne pouvez utiliser chaque code qu'une seule fois pour vous connecter à votre compte.
> - Les codes de récupération ne sont pas générés pour les périphériques WebAuthn.

Pour obtenir des informations sur la régénération ou la restauration de vos codes de récupération, consultez [les options de récupération et la réinitialisation de la 2FA](two_factor_authentication_troubleshooting.md#recovery-options-and-2fa-reset).

## Se connecter avec l'authentification à deux facteurs {#sign-in-with-two-factor-authentication}

Lorsque la 2FA est activée, vous saisissez votre nom d'utilisateur et votre mot de passe, puis utilisez une méthode d'authentification supplémentaire pour confirmer votre identité. Si vous disposez de plusieurs méthodes 2FA, vous pouvez passer de l'une à l'autre lors de la connexion.

### Se connecter avec un authentificateur OTP {#sign-in-with-an-otp-authenticator}

Sur l'écran **Saisir le code de l'application d'authentification**, saisissez le code à six chiffres généré par votre authentificateur OTP, puis sélectionnez **Vérifier le code**.

Pour vous connecter avec un code de récupération à la place, sélectionnez **Récupérer votre compte**, puis saisissez un code de récupération sur l'écran **Saisir le code de récupération du compte**.

### Se connecter avec un périphérique WebAuthn {#sign-in-with-a-webauthn-device}

Sur l'écran **Vérifier avec l'appareil de sécurité**, votre navigateur ou gestionnaire de mots de passe vous invite à activer votre périphérique WebAuthn, par exemple en le touchant ou en appuyant sur son bouton. Une fois que votre périphérique a répondu à la demande d'authentification, vous êtes connecté.

Si le périphérique ne répond pas, sélectionnez **Veuillez réessayer**.

### Se connecter avec l'OTP par email {#sign-in-with-email-otp}

Sur l'écran **Connectez-vous avec votre adresse email**, GitLab envoie un code de vérification à six chiffres à votre adresse email. Saisissez le code, puis sélectionnez **Vérifier le code**. Le code reste valide pendant 60 minutes.

Si le code n'arrive pas ou a expiré, sélectionnez **Renvoyer le code** pour en demander un nouveau. Pour d'autres problèmes, consultez [le dépannage de l'OTP par email](two_factor_authentication_troubleshooting.md#email-otp-troubleshooting).

### Se connecter avec un jeton d'accès personnel {#sign-in-with-a-personal-access-token}

Lorsque la 2FA est activée, vous ne pouvez pas utiliser votre mot de passe pour vous authentifier avec Git via HTTPS ou l'[API REST GitLab](../../../api/rest/_index.md). Vous devez utiliser un [jeton d'accès personnel](../personal_access_tokens.md) à la place.

## Désactiver l'authentification à deux facteurs {#disable-two-factor-authentication}

{{< history >}}

- Possibilité de désactiver l'authentificateur OTP et les périphériques WebAuthn individuellement ou simultanément [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/393419) dans GitLab 17.6.

{{< /history >}}

Vous pouvez désactiver l'authentificateur OTP et les périphériques WebAuthn individuellement ou simultanément. Pour les désactiver simultanément :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Mot de passe et authentification**.
1. Sélectionnez **Désactiver l’authentification à deux facteurs**.
1. Dans la boîte de dialogue, saisissez votre mot de passe actuel et sélectionnez **Désactiver l’authentification à deux facteurs**.

Les paramètres du groupe ou de l'instance peuvent exiger que votre compte utilise la 2FA. Sur GitLab.com, les connexions basées sur un mot de passe doivent effectuer une vérification OTP par email.

## Assistants d'identifiants OAuth {#oauth-credential-helpers}

Les assistants d'identifiants Git suivants s'authentifient auprès de GitLab via OAuth. Cela est compatible avec l'authentification à deux facteurs. Lors de la première authentification, l'assistant ouvre le navigateur web et GitLab vous demande d'autoriser l'application. Les authentifications suivantes ne nécessitent aucune interaction.

### Git Credential Manager {#git-credential-manager}

[Git Credential Manager](https://github.com/git-ecosystem/git-credential-manager) (GCM) s'authentifie par défaut via OAuth. GCM prend en charge GitLab.com sans aucune configuration manuelle. Pour utiliser GCM avec GitLab Self-Managed, consultez [le support GitLab](https://github.com/git-ecosystem/git-credential-manager/blob/main/docs/gitlab.md).

Pour éviter de devoir vous réauthentifier à chaque push, GCM prend en charge la mise en cache ainsi qu'une variété de magasins d'identifiants spécifiques à chaque plateforme qui persistent entre les sessions. Cette fonctionnalité est utile que vous utilisiez des jetons d'accès personnels ou OAuth.

Git pour Windows inclut Git Credential Manager.

Git Credential Manager est développé principalement par GitHub, Inc. Il s'agit d'un projet open source soutenu par la communauté.

### git-credential-oauth {#git-credential-oauth}

[git-credential-oauth](https://github.com/hickford/git-credential-oauth) prend en charge GitLab.com et plusieurs hôtes publics populaires sans aucune configuration manuelle. Pour l'utiliser avec GitLab Self-Managed, consultez la [documentation sur les hôtes personnalisés de git-credential-oauth](https://github.com/hickford/git-credential-oauth#custom-hosts).

De nombreuses distributions Linux incluent git-credential-oauth en tant que package.

git-credential-oauth est un projet open source soutenu par la communauté.

## Informations pour les administrateurs GitLab {#information-for-gitlab-administrators}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

- Veillez à ce que la 2FA continue de fonctionner après [la restauration d'une sauvegarde GitLab](../../../administration/backup_restore/_index.md).
- Pour vous assurer que la 2FA s'autorise correctement avec un serveur OTP, synchronisez l'heure de votre serveur GitLab à l'aide d'un service tel que NTP. Sinon, l'autorisation peut toujours échouer en raison de différences d'heure.
- L'implémentation WebAuthn de GitLab ne fonctionne pas lorsque l'instance GitLab est accessible depuis plusieurs noms d'hôte ou noms de domaine complets (FQDN). Chaque enregistrement WebAuthn est associé au nom d'hôte actuel au moment de l'enregistrement et ne peut pas être utilisé pour d'autres noms d'hôte ou FQDN.

  Par exemple, si un utilisateur tente d'accéder à une instance GitLab depuis `first.host.xyz` et `second.host.xyz` :

  - L'utilisateur se connecte en utilisant `first.host.xyz` et enregistre sa clé WebAuthn.
  - L'utilisateur se déconnecte et tente de se connecter en utilisant `first.host.xyz` : l'authentification WebAuthn réussit.
  - L'utilisateur se déconnecte et tente de se connecter en utilisant `second.host.xyz` : l'authentification WebAuthn échoue, car la clé WebAuthn n'a été enregistrée que sur `first.host.xyz`.

- Pour appliquer la 2FA au niveau du système ou du groupe, consultez [Appliquer l'authentification à deux facteurs](../../../security/two_factor_authentication.md).
