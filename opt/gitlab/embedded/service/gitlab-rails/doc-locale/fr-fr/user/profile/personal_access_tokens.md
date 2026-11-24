---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Utilisez des jetons d'accès personnel pour vous authentifier avec l'API GitLab ou Git via HTTPS. Inclut les paramètres de création, de remplacement, de révocation, de portées et d'expiration."
title: "Jetons d'accès personnels"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les jetons d'accès personnel fournissent un accès authentifié à GitLab. Ils constituent une alternative aux [jetons OAuth2](../../api/oauth2.md) et sont similaires aux jetons d'accès de groupe et aux jetons d'accès au projet, mais sont associés à un utilisateur plutôt qu'à un groupe ou un projet.

Vous pouvez utiliser un jeton d'accès personnel pour vous authentifier :

- Avec l'[API GitLab](../../api/rest/authentication.md#personal-project-and-group-access-tokens).
- Avec Git via HTTPS. Utilisez :
  - Toute valeur non vide comme nom d'utilisateur.
  - Le jeton d'accès personnel comme mot de passe.

> [!note]
> Vous devez vous authentifier avec un jeton d'accès personnel si l'[authentification à deux facteurs (2FA)](account/two_factor_authentication.md) ou le [SAML](../../integration/saml.md#password-generation-for-users-created-through-saml) est activé.

Certaines fonctionnalités de GitLab qui nécessitent un nom d'utilisateur, comme le [backend d'état Terraform géré par GitLab](../infrastructure/iac/terraform_state.md#use-your-gitlab-backend-as-a-remote-data-source) et le [registre de conteneurs](../packages/container_registry/authenticate_with_container_registry.md), utilisent un jeton d'accès personnel avec un nom d'utilisateur GitLab. Dans ces cas, le nom d'utilisateur est requis mais n'est pas évalué dans le cadre de l'authentification. Pour plus d'informations, consultez le [ticket 212953](https://gitlab.com/gitlab-org/gitlab/-/issues/212953).

Sur les instances GitLab Self-Managed et GitLab Dedicated, les administrateurs peuvent utiliser l'[API des jetons utilisateur](../../api/user_tokens.md#create-an-impersonation-token) pour créer des jetons d'usurpation d'identité afin de s'authentifier en tant qu'utilisateur spécifique.

## Créer un jeton d'accès personnel {#create-a-personal-access-token}

{{< history >}}

- La limite maximale de durée de vie autorisée [étendue à 400 jours](https://gitlab.com/gitlab-org/gitlab/-/issues/461901) dans GitLab 17.6 [avec un feature flag](../../administration/feature_flags/list.md) nommé `buffered_token_expiration_limit`. Fonctionnalité désactivée par défaut.
- La description du jeton d'accès personnel [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/443819) dans GitLab 17.7.

{{< /history >}}

> [!flag]
> Un feature flag contrôle la disponibilité de l'extension de la limite de durée de vie maximale autorisée. Pour plus d'informations, consultez l'historique.

Pour créer un jeton d'accès personnel :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Jetons d'accès personnel**.
1. Dans la liste déroulante **Générer un jeton**, sélectionnez **Ancien jeton**.
1. Dans **Nom du jeton**, saisissez un nom pour le jeton.
1. Facultatif. Dans **Description du jeton**, saisissez une description pour le jeton.
1. Dans **Date d'expiration**, saisissez une date d'expiration pour le jeton.
   - Le jeton expire à minuit UTC à cette date.
   - Si vous ne saisissez pas de date, la date d'expiration est fixée à 365 jours à compter d'aujourd'hui.
   - Par défaut, la date d'expiration ne peut pas dépasser 365 jours à compter d'aujourd'hui. Dans GitLab 17.6 et les versions ultérieures, les administrateurs peuvent [modifier la durée de vie maximale des jetons d'accès](../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens).
1. Sélectionnez une ou plusieurs [portées de jeton d'accès personnel](../../security/tokens/access_token_scopes.md).
1. Sélectionnez **Générer un jeton**.

Un jeton d'accès personnel s'affiche. Enregistrez le jeton d'accès personnel dans un endroit sûr. Après avoir quitté ou actualisé la page, vous ne pourrez plus le consulter.

Tous les jetons d'accès héritent du [paramètre de préfixe par défaut](../../administration/settings/account_and_limit_settings.md#personal-access-token-prefix) configuré pour les jetons d'accès personnel.

### Préremplir les détails du jeton d'accès personnel {#prefill-personal-access-token-details}

Vous pouvez préremplir les détails d'un jeton d'accès personnel en ajoutant les paramètres `name`, `description` et `scopes` à l'URL. Par exemple :

```plaintext
https://gitlab.example.com/-/user_settings/personal_access_tokens?name=Example+Access+token&description=My+description&scopes=api,read_user
```

L'URL doit inclure au moins une portée valide. Les paramètres `name` et `description` sont facultatifs dans l'URL, mais vous devez saisir un nom de jeton dans le formulaire de création si l'URL n'en inclut pas.

> [!note]
> Les jetons d'accès personnel doivent être traités avec précaution. Pour obtenir des conseils sur la gestion des jetons d'accès personnel, consultez les [considérations de sécurité relatives aux jetons](../../security/tokens/_index.md#security-considerations).

## S'authentifier avec un jeton d'accès {#authenticate-with-an-access-token}

Utilisez un jeton d'accès pour vous authentifier avec l'API REST GitLab, Git via HTTPS et les outils tiers qui s'intègrent à GitLab.

### Utiliser l'API REST {#use-rest-api}

Transmettez votre jeton dans l'en-tête `PRIVATE-TOKEN` :

```shell
curl --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/projects"
```

Pour tous les détails, consultez [l'authentification de l'API REST](../../api/rest/authentication.md#personal-project-and-group-access-tokens).

### Utiliser Git via HTTPS {#use-git-over-https}

Utilisez votre jeton comme mot de passe lorsque Git vous demande des identifiants :

- Nom d'utilisateur : toute chaîne non vide (GitLab ne valide pas cette valeur).
- Mot de passe : votre jeton d'accès personnel.

Par exemple :

```shell
git clone https://oauth2:<your_access_token>@gitlab.example.com/gitlab-org/gitlab.git
```

### Utiliser des outils tiers et des extensions IDE {#use-third-party-tools-and-ide-extensions}

Les outils qui s'intègrent à GitLab, tels que les extensions IDE, les outils CI/CD et les scripts d'automatisation, acceptent un jeton d'accès personnel pour l'authentification. La documentation de chaque outil décrit les portées requises et la manière de saisir votre jeton :

- [Interface de ligne de commande GitLab (`glab`)](https://docs.gitlab.com/cli/#authenticate-with-gitlab)
- [Extension GitLab pour VS Code](../../editor_extensions/visual_studio_code/setup.md#authenticate-with-gitlab)
- [Plugin GitLab Duo pour les IDE JetBrains](../../editor_extensions/jetbrains_ide/setup.md#authenticate-with-gitlab)
- [Extension GitLab pour Visual Studio](../../editor_extensions/visual_studio/setup.md#authenticate-with-gitlab)
- [GitLab pour Eclipse](../../editor_extensions/eclipse/setup.md#authenticate-with-gitlab)
- [Plugin GitLab pour Neovim](../../editor_extensions/neovim/setup.md#authenticate-with-gitlab)

Pour les pipelines CI/CD, il est recommandé d'utiliser plutôt des [jetons de job CI/CD](../../ci/jobs/ci_job_token.md).

Pour les conseils de sécurité relatifs aux jetons d'accès personnel, consultez les [considérations de sécurité relatives aux jetons](../../security/tokens/_index.md#security-considerations).

## Afficher les informations d'utilisation des jetons {#view-token-usage-information}

{{< history >}}

- Possibilité d'afficher les adresses IP [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/428577) dans GitLab 17.8 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `pat_ip`. Activé par défaut dans la version 17.9.
- Possibilité d'afficher les adresses IP rendue [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/513302) dans GitLab 17.10. Le feature flag `pat_ip` a été supprimé.

{{< /history >}}

La page des jetons d'accès personnel affiche des informations sur vos jetons d'accès.

À partir de cette page, vous pouvez effectuer les actions suivantes :

- Créer, remplacer et révoquer des jetons d'accès personnel.
- Afficher tous les jetons d'accès personnel actifs et inactifs.
- Afficher les informations sur les jetons, notamment les portées, les rôles attribués et les dates d'expiration.
- Afficher les informations d'utilisation, notamment les dates d'utilisation et les cinq dernières adresses IP de connexion distinctes.
  > [!note]
  > GitLab met régulièrement à jour les informations d'utilisation des jetons lorsque le jeton effectue une opération Git ou authentifie une opération avec l'API [REST](../../api/rest/_index.md) ou [GraphQL](../../api/graphql/_index.md). Les heures d'utilisation des jetons sont mises à jour toutes les 10 minutes. Les adresses IP d'utilisation des jetons sont mises à jour toutes les minutes.

Pour afficher vos jetons d'accès personnel :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Jetons d'accès personnel**.

Sélectionnez le nom d'un jeton pour ouvrir le panneau de détails. Par défaut, seuls les jetons actifs sont affichés. Utilisez la barre de recherche pour filtrer la liste des jetons d'accès.

## Remplacer un jeton d'accès personnel {#rotate-a-personal-access-token}

{{< history >}}

- Possibilité d'utiliser l'interface utilisateur pour remplacer un jeton d'accès personnel [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/241523) dans GitLab 17.7.
- [Interface utilisateur mise à jour](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/194582) dans GitLab 18.1.

{{< /history >}}

Remplacez un jeton pour créer un nouveau jeton avec les mêmes autorisations et la même portée que le jeton d'origine. Le jeton d'origine devient immédiatement inactif, et GitLab conserve les deux versions à des fins d'audit.

> [!warning]
> Cette action est irréversible. Les outils qui reposent sur un jeton d'accès remplacé cesseront de fonctionner jusqu'à ce que vous référenciez votre nouveau jeton.

Pour remplacer un jeton d'accès personnel :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Jetons d'accès personnel**.
1. En regard d'un jeton actif, sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}).
1. Sélectionnez **Remplacer** ({{< icon name="retry" >}}).
1. Dans la boîte de dialogue de confirmation, sélectionnez **Remplacer**.

## Révoquer un jeton d'accès personnel {#revoke-a-personal-access-token}

{{< history >}}

- [Interface utilisateur mise à jour](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/194582) dans GitLab 18.1.

{{< /history >}}

Révoquez un jeton pour l'invalider immédiatement et empêcher toute utilisation ultérieure. GitLab conserve le jeton à des fins d'audit. Vous ne pouvez pas supprimer définitivement les jetons, mais vous pouvez filtrer les listes de jetons pour n'afficher que les jetons actifs.

> [!warning]
> Cette action est irréversible. Les outils qui reposent sur un jeton d'accès révoqué cesseront de fonctionner jusqu'à ce que vous ajoutiez un nouveau jeton.

Pour révoquer un jeton d'accès personnel :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Jetons d'accès personnel**.
1. En regard d'un jeton actif, sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}).
1. Sélectionnez **Révoquer** ({{< icon name="remove" >}}).
1. Dans la boîte de dialogue de confirmation, sélectionnez **Révoquer**.

## Expiration des jetons d'accès {#access-token-expiration}

Les jetons d'accès personnels, de groupe, au projet et d'usurpation d'identité expirent à minuit UTC à la date d'expiration. Les jetons expirés ne peuvent plus être utilisés pour authentifier les requêtes et ne peuvent pas être réactivés. Vous devez créer un nouveau jeton à la place.

Par défaut, les nouveaux jetons d'accès doivent avoir une date d'expiration. Si une date d'expiration n'est pas explicitement définie lors de la création du jeton, une date d'expiration de 365 jours à compter de la date actuelle est appliquée. Si un administrateur [désactive cette exigence](../../administration/settings/account_and_limit_settings.md#require-expiration-dates-for-new-access-tokens), les nouveaux jetons créés sans date d'expiration n'expirent jamais.

Dans GitLab Ultimate, les administrateurs peuvent configurer une [durée de vie maximale autorisée](../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens) pour les jetons d'accès.

Selon votre version et votre offre GitLab, une date d'expiration peut être automatiquement appliquée à vos jetons d'accès existants lors de la mise à niveau des versions de GitLab. Pour plus d'informations, consultez [les jetons d'accès sans expiration](../../update/deprecations.md#non-expiring-access-tokens).

### E-mails d'expiration des jetons d'accès personnel {#personal-access-token-expiry-emails}

{{< history >}}

- Notifications d'expiration à 60 et 30 jours [introduites](https://gitlab.com/gitlab-org/gitlab/-/issues/464040) dans GitLab 17.6 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `expiring_pats_30d_60d_notifications`. Fonctionnalité désactivée par défaut.
- Notifications à 60 et 30 jours [généralement disponibles](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/173792) dans GitLab 17.7. Le feature flag `expiring_pats_30d_60d_notifications` a été supprimé.

{{< /history >}}

GitLab effectue une vérification quotidienne à 1 h 00 UTC pour identifier les jetons d'accès personnel qui expirent prochainement. Les utilisateurs sont notifiés par e-mail sept jours avant l'expiration d'un jeton. Dans GitLab 17.6 et versions ultérieures, des notifications sont également envoyées 30 et 60 jours avant l'expiration d'un jeton.

### Calendrier d'expiration des jetons d'accès personnel {#personal-access-token-expiry-calendar}

Vous pouvez vous abonner à un endpoint iCalendar qui contient des événements à la date d'expiration pour chaque jeton. Après connexion, cet endpoint est disponible à l'adresse `/-/user_settings/personal_access_tokens.ics`.

### Créer un jeton d'accès personnel de compte de service sans date d'expiration {#create-a-service-account-personal-access-token-with-no-expiry-date}

Vous pouvez [créer un jeton d'accès personnel pour un compte de service](../../api/service_accounts.md#create-a-personal-access-token-for-a-group-service-account) sans date d'expiration. Ces jetons d'accès personnel n'expirent jamais.

> [!note]
> Autoriser la création de jetons d'accès personnel pour les comptes de service sans date d'expiration n'affecte que les jetons créés après la modification de ce paramètre. Cela n'affecte pas les jetons existants.

#### GitLab.com {#gitlabcom}

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe principal.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**.
1. Développez **Permissions et fonctionnalités du groupe**.
1. Sous **Jetons d'accès personnel**, décochez la case **Exiger des dates d'expiration pour les comptes de service**.

Vous pouvez désormais créer des jetons d'accès personnel pour un utilisateur de compte de service sans date d'expiration.

#### GitLab Self-Managed {#gitlab-self-managed}

Prérequis :

- Vous devez être administrateur de votre instance GitLab Self-Managed.

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**.
1. Développez la section **Limitations du compte**.
1. Décochez la case **Exiger une date d'expiration pour les comptes de service**.

Vous pouvez désormais créer des jetons d'accès personnel pour un utilisateur de compte de service sans date d'expiration.

Sur GitLab Self-Managed Community Edition (CE), la case **Exiger une date d'expiration pour les comptes de service** n'est pas disponible. Utilisez plutôt le paramètre [**Exiger une date d’expiration**](../../administration/settings/account_and_limit_settings.md#require-expiration-dates-for-new-access-tokens).

## Cloner un dépôt à l'aide d'un jeton d'accès personnel {#clone-repository-using-personal-access-token}

Pour cloner un dépôt lorsque SSH est désactivé, clonez-le à l'aide d'un jeton d'accès personnel en exécutant la commande suivante :

```shell
git clone https://<username>:<personal_token>@gitlab.com/gitlab-org/gitlab.git
```

Cette méthode enregistre votre jeton d'accès personnel dans votre historique bash. Pour éviter cela, exécutez la commande suivante :

```shell
git clone https://<username>@gitlab.com/gitlab-org/gitlab.git
```

Lorsqu'un mot de passe vous est demandé pour `https://gitlab.com`, saisissez votre jeton d'accès personnel.

Le `username` dans la commande `clone` :

- Peut être n'importe quelle valeur de chaîne.
- Ne doit pas être une chaîne vide.

Gardez cela à l'esprit si vous configurez un pipeline d'automatisation qui dépend de l'authentification.

## Désactiver les jetons d'accès {#disable-access-tokens}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/436991) du paramètre `Disable access tokens` dans GitLab 17.3.

{{< /history >}}

Prérequis :

- Disposer d'un accès administrateur.

Vous pouvez empêcher les utilisateurs de s'authentifier avec des jetons d'accès sur l'ensemble de votre instance GitLab. Ce paramètre affecte les jetons d'accès personnel, les jetons d'accès de groupe, les jetons d'accès au projet et les jetons d'usurpation d'identité. Ce paramètre s'applique également aux jetons d'accès personnel pour les comptes de service.

Lorsque vous désactivez les jetons d'accès, les règles suivantes s'appliquent :

- Les utilisateurs ne peuvent pas se connecter à GitLab avec des jetons d'accès personnel.
- La page des jetons d'accès personnel renvoie une erreur `404 Not Found`.
- Les jetons de flux pour les flux RSS, Atom et les flux de calendrier cessent de fonctionner.
- Les requêtes API authentifiées avec des jetons d'accès personnel sont rejetées.

Pour désactiver les jetons d'accès pour l'instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**.
1. Développez la section **Limitations du compte**.
1. Cochez la case **Désactiver les jetons d'accès**.
1. Sélectionnez **Enregistrer les modifications**.

Vous pouvez également utiliser l'[attribut `disable_personal_access_tokens`](../../api/settings.md#available-settings) dans l'API des paramètres d'application.

## Désactiver les jetons d'accès personnel pour les utilisateurs et utilisatrices professionnels {#disable-personal-access-tokens-for-enterprise-users}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/369504) dans GitLab 16.11 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `enterprise_disable_personal_access_tokens`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/369504) dans GitLab 17.2
- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/369504) dans GitLab 17.3. Le feature flag `enterprise_disable_personal_access_tokens` a été supprimé.

{{< /history >}}

Prérequis :

- Le rôle Propriétaire pour le groupe auquel appartient l'utilisateur ou l'utilisatrice professionnelle.

La désactivation des jetons d'accès personnel des [utilisateurs et utilisatrices professionnels](../enterprise_user/_index.md) d'un groupe :

- Empêche les utilisateurs et utilisatrices professionnels de créer de nouveaux jetons d'accès personnel. Ce comportement s'applique même si un utilisateur ou une utilisatrice professionnelle est également administrateur du groupe.
- Désactive les jetons d'accès personnel existants des utilisateurs et utilisatrices professionnels.

> [!warning]
> La désactivation des jetons d'accès personnel pour les utilisateurs et utilisatrices professionnels ne désactive pas les jetons d'accès personnel pour les [comptes de service](service_accounts.md).

Pour désactiver les jetons d'accès personnel des utilisateurs et utilisatrices professionnels :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Général**.
1. Développez **Permissions et fonctionnalités du groupe**.
1. Sous **Utilisateurs et utilisatrices professionnels**, sélectionnez **Désactiver les jetons d'accès personnels**.
1. Sélectionnez **Enregistrer les modifications**.

Lorsque vous supprimez ou bloquez un compte d'utilisateur ou d'utilisatrice professionnelle, leurs jetons d'accès personnel sont automatiquement révoqués.

## Créer un jeton d'accès personnel par programmation {#create-a-personal-access-token-programmatically}

{{< details >}}

- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez créer un jeton d'accès personnel prédéfini dans le cadre de vos tests ou de votre automatisation.

Prérequis :

- Vous devez disposer d'un accès suffisant pour exécuter une [session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session) pour votre instance GitLab.

Pour créer un jeton d'accès personnel par programmation :

1. Ouvrez une console Rails :

   ```shell
   sudo gitlab-rails console
   ```

1. Exécutez les commandes suivantes pour référencer le nom d'utilisateur, le jeton et les portées.

   Le jeton doit comporter 20 caractères. Les portées doivent être valides et sont visibles [dans le code source](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/auth.rb).

   Par exemple, pour créer un jeton appartenant à un utilisateur avec le nom d'utilisateur `automation-bot` et expirant dans un an :

   ```ruby
   user = User.find_by_username('automation-bot')
   token = user.personal_access_tokens.create(scopes: ['read_user', 'read_repository'], name: 'Automation token', expires_at: 365.days.from_now)
   token.set_token('token-string-here123')
   token.save!
   ```

Ce code peut être raccourci en une commande shell sur une seule ligne en utilisant le [runner Rails](../../administration/operations/rails_console.md#using-the-rails-runner) :

```shell
sudo gitlab-rails runner "token = User.find_by_username('automation-bot').personal_access_tokens.create(scopes: ['read_user', 'read_repository'], name: 'Automation token', expires_at: 365.days.from_now); token.set_token('token-string-here123'); token.save!"
```

## Révoquer un jeton d'accès personnel par programmation {#revoke-a-personal-access-token-programmatically}

{{< details >}}

- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez révoquer par programmation un jeton d'accès personnel dans le cadre de vos tests ou de votre automatisation.

Prérequis :

- Vous devez disposer d'un accès suffisant pour exécuter une [session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session) pour votre instance GitLab.

Pour révoquer un jeton par programmation :

1. Ouvrez une console Rails :

   ```shell
   sudo gitlab-rails console
   ```

1. Pour révoquer un jeton `token-string-here123`, exécutez les commandes suivantes :

   ```ruby
   token = PersonalAccessToken.find_by_token('token-string-here123')
   token.revoke!
   ```

Ce code peut être raccourci en une commande shell sur une seule ligne en utilisant le [runner Rails](../../administration/operations/rails_console.md#using-the-rails-runner) :

```shell
sudo gitlab-rails runner "PersonalAccessToken.find_by_token('token-string-here123').revoke!"
```

## Utiliser DPoP avec des jetons d'accès personnel {#use-dpop-with-personal-access-tokens}

{{< details >}}

- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/181053) dans GitLab 17.10 [avec le feature flag](../../administration/feature_flags/_index.md) `dpop_authentication`. Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique. Cette fonctionnalité est disponible à des fins de test, mais n'est pas prête pour une utilisation en production.

La démonstration de preuve de possession (DPoP) renforce la sécurité de vos jetons d'accès personnel et minimise les effets des fuites de jetons involontaires. Lorsque vous activez cette fonctionnalité sur votre compte, toutes les requêtes d'API REST et GraphQL contenant un PAT doivent également fournir un en-tête DPoP signé. La création d'un en-tête DPoP signé nécessite votre clé SSH privée correspondante.

> [!note]
> Si vous activez cette fonctionnalité, toutes les requêtes API sans en-tête DPoP valide renvoient une erreur `DpopValidationError`.
>
> L'en-tête DPoP n'est pas requis pour les opérations Git via HTTPS qui incluent un jeton d'accès.

Prérequis :

- Vous devez [ajouter au moins une clé SSH publique](../ssh.md#add-an-ssh-key-to-your-gitlab-account) à votre compte, avec un **Type d'utilisation** défini sur **Signature** ou **Authentification et signature**.
  - Le type de votre clé SSH doit être RSA.
- Vous devez avoir installé et configuré l'[interface de ligne de commande GitLab](../../editor_extensions/gitlab_cli/_index.md) pour votre compte GitLab.

Pour exiger DPoP sur tous les appels aux API REST et GraphQL :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Jetons d'accès personnel**.
1. Accédez à la section **Utiliser la preuve de possession (DPoP)** et sélectionnez **Activer DPoP**.
1. Sélectionnez **Enregistrer les modifications**.
1. Pour générer un en-tête DPoP avec l'[interface de ligne de commande GitLab](../../editor_extensions/gitlab_cli/_index.md), exécutez cette commande dans votre terminal. Remplacez `<your_access_token>` par votre jeton d'accès et `~/.ssh/id_rsa` par l'emplacement de votre clé privée :

   ```shell
    glab auth dpop-gen --pat "<your_access_token>" --private-key ~/.ssh/id_rsa
   ```

L'en-tête DPoP que vous avez généré dans l'interface de ligne de commande peut être utilisé :

- Avec l'API REST :

  ```shell
  curl --header "PRIVATE-TOKEN: <your_access_token>" \
    --header "DPoP: <dpop-from-glab>" \
    "https://gitlab.example.com/api/v4/projects"
  ```

- Avec GraphQL :

  ```shell
   curl --request POST \
   --header "Content-Type: application/json" \
   --header "PRIVATE-TOKEN: <your_access_token>" \
   --header "DPoP: <dpop-from-glab>" \
   --data '{
   "query": "query { currentUser { id } }"
   }' \
   "https://gitlab.example.com/api/graphql"
  ```

Pour en savoir plus sur DPoP, consultez le plan directeur [Contrainte de l'expéditeur pour les jetons d'accès personnel](https://gitlab.com/gitlab-com/gl-security/product-security/appsec/security-feature-blueprints/-/tree/main/sender_constraining_access_tokens).

## Alternatives aux jetons d'accès personnel {#alternatives-to-personal-access-tokens}

Pour Git via HTTPS, une alternative aux jetons d'accès personnel est d'utiliser un assistant d'identifiants OAuth.

Pour l'authentification dans les jobs CI/CD, envisagez :

- [Jetons de job CI/CD](../../ci/jobs/ci_job_token.md) avec [autorisations affinées](../../ci/jobs/fine_grained_permissions.md) pour l'authentification de pipeline
- [Jetons d'accès au projet](../project/settings/project_access_tokens.md) avec les autorisations minimales requises pour l'automatisation spécifique au projet

## Sujets connexes {#related-topics}

- [Jetons d'accès de groupe](../group/settings/group_access_tokens.md)
- [Jetons d'accès au projet](../project/settings/project_access_tokens.md)
- [API des jetons d'accès personnel](../../api/personal_access_tokens.md)
- [Jetons d'accès personnel affinés](../../auth/tokens/fine_grained_access_tokens.md)
- [Permissions Assistant](../duo_agent_platform/agents/foundational_agents/permissions_assistant.md), un agent GitLab Duo qui vous aide à sélectionner des autorisations affinées lors de la création d'un jeton
