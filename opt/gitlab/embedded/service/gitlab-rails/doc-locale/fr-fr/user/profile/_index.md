---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Compte utilisateur
description: "Paramètres du profil, préférences, authentification et notifications."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Chaque compte GitLab dispose d'un profil utilisateur qui contient des informations vous concernant et sur votre activité GitLab.

Votre profil inclut également des paramètres que vous utilisez pour personnaliser votre expérience GitLab.

## Accéder à votre profil utilisateur {#access-your-user-profile}

{{< history >}}

- L'accès au profil via l'ID utilisateur a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/185387) dans GitLab 17.11.

{{< /history >}}

Pour accéder à votre profil :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez votre nom ou votre nom d'utilisateur.

Vous pouvez également accéder à la page de profil d'un utilisateur en utilisant l'ID à la place du nom d'utilisateur à l'adresse `https://gitlab.example.com/-/u/<id>`. Par exemple, si votre nom d'utilisateur est `gitlab-user` et votre ID est `12345`, vous pouvez accéder à la page de profil via `https://gitlab.example.com/gitlab-user` ou `https://gitlab.example.com/-/u/12345`.

## Trouver l'ID utilisateur {#find-the-user-id}

Vous pourriez avoir besoin de l'ID utilisateur si vous souhaitez interagir avec lui via l'[API GitLab](../../api/_index.md).

Pour trouver l'ID utilisateur :

1. Accédez à la page de profil de l'utilisateur.
1. Sur la page de profil, dans le coin supérieur droit, sélectionnez **Actions** ({{< icon name="ellipsis_v" >}}).
1. Sélectionnez **Copier l'ID utilisateur**.

## Accéder à vos paramètres utilisateur {#access-your-user-settings}

Pour accéder à vos paramètres utilisateur :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.

## Générer ou modifier votre code PIN d'assistance {#generate-or-change-your-support-pin}

L'assistance GitLab peut vous demander un numéro d'identification personnel (PIN) pour valider votre identité. Le code PIN expire sept jours après sa création.

Pour générer un nouveau code PIN d'assistance :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Compte**.
1. Sélectionnez **Générer un nouveau code PIN**.

## Accéder à votre code PIN d'assistance {#access-your-support-pin}

Si vous avez déjà créé un code PIN d'assistance, celui-ci est accessible dans votre profil et expire sept jours après sa création.

Pour accéder à votre code PIN d'assistance :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Compte**.

## Modifier votre nom d'utilisateur {#change-your-username}

Votre nom d'utilisateur possède un [espace de nommage](../namespace/_index.md) unique, qui est mis à jour lorsque vous modifiez votre nom d'utilisateur. Avant de modifier votre nom d'utilisateur, consultez les informations sur [le comportement des redirections](../project/repository/_index.md#repository-path-changes). Si vous ne souhaitez pas mettre à jour l'espace de nommage, vous pouvez créer un nouvel utilisateur ou groupe et y transférer des projets.

Prérequis :

- Votre espace de nommage ne doit pas :
  - Contenir un projet avec des tags du [registre de conteneurs](../packages/container_registry/_index.md).
  - Héberger un projet utilisant [GitLab Pages](../project/pages/_index.md).
- Votre nom d'utilisateur :
  - Doit comporter entre 2 et 255 caractères.
  - Ne doit contenir que des lettres non accentuées, des chiffres, `_`, `-` et `.`.
  - Ne doit pas :
    - Commencer par `_`, `-` ou `.`.
    - Contenir des emoji.
    - Se terminer par `.` ou `.<reserved file extension>`, par exemple `jon.png`, `jon.git` ou `jon.atom`. En revanche, `jonpng` est valide.

Pour modifier votre nom d'utilisateur :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Compte**.
1. Dans la section **Changer le nom d'utilisateur**, saisissez un nouveau nom d'utilisateur comme chemin.
1. Sélectionnez **Mettre à jour le nom d'utilisateur**.

## Ajouter des adresses de courriel à votre profil utilisateur {#add-emails-to-your-user-profile}

Pour ajouter une nouvelle adresse de courriel à votre compte :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Courriels**.
1. Sélectionnez **Ajouter une nouvelle adresse de courriel**.
1. Dans la zone de texte **Courriel**, saisissez la nouvelle adresse de courriel.
1. Sélectionnez **Ajouter une adresse de courriel**.
1. Vérifiez votre adresse de courriel à l'aide de l'e-mail de vérification reçu.

La nouvelle adresse de courriel est ajoutée comme adresse de courriel secondaire. Vous pouvez utiliser les adresses de courriel secondaires pour réinitialiser les mots de passe, mais pas pour vous authentifier. Vous pouvez mettre à jour votre [adresse de courriel principale](#change-your-primary-email).

> [!note]
> [Rendre votre adresse de courriel non publique](#set-your-public-email) n'empêche pas son utilisation pour la correspondance des commits ni pour les [importations de groupes et de projets](../import/_index.md).

## Supprimer des adresses de courriel de votre profil utilisateur {#delete-email-addresses-from-your-user-profile}

{{< history >}}

- La suppression automatique des adresses de courriel secondaires non vérifiées a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/151562) dans GitLab 17.0.

{{< /history >}}

Vous pouvez supprimer une adresse de courriel secondaire de votre compte. Vous ne pouvez pas supprimer votre adresse de courriel principale.

Si l'adresse de courriel supprimée est utilisée pour des e-mails utilisateur, ces e-mails seront envoyés à l'adresse de courriel principale à la place.

Les adresses de courriel secondaires non vérifiées sont automatiquement supprimées après trois jours.

Pour supprimer une adresse de courriel de votre compte :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Courriels**.
1. Sélectionnez **Supprimer** ({{< icon name="remove" >}}) et confirmez que vous souhaitez **Supprimer**.

Vous pouvez également [utiliser l'API pour supprimer une adresse de courriel secondaire](../../api/user_email_addresses.md#delete-an-email-address).

## Rendre votre page de profil utilisateur privée {#make-your-user-profile-page-private}

Vous pouvez rendre votre profil utilisateur visible uniquement par vous et les administrateurs GitLab.

> [!note]
> Un administrateur GitLab peut [désactiver](../../administration/settings/account_and_limit_settings.md#prevent-users-from-making-their-profiles-private) ce paramètre, forçant tous les profils à être rendus publics.

Pour rendre votre profil privé :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Cochez la case **Profil privé**.
1. Sélectionnez **Mettre à jour les paramètres du profil**.

Les éléments suivants sont masqués sur votre page de profil utilisateur (`https://gitlab.example.com/username`) :

- Flux Atom
- Date de création du compte
- Onglets pour l'activité, les groupes, les projets contribués, les projets personnels, les projets favoris, les extraits de code

> [!note]
> Rendre votre page de profil utilisateur privée ne masque pas toutes vos ressources publiques depuis les API REST ou GraphQL. Par exemple, l'adresse de courriel associée à votre signature de commit est accessible, sauf si vous [utilisez une adresse de courriel de commit privée générée automatiquement](#use-an-automatically-generated-private-commit-email).

### Visibilité des utilisateurs {#user-visibility}

La page publique d'un utilisateur, accessible à l'adresse `/username`, est toujours visible, que vous soyez connecté ou non.

Lorsque vous visitez la page publique d'un utilisateur, vous ne pouvez voir que les projets auxquels vous avez accès.

Si le [niveau public est restreint](../../administration/settings/visibility_and_access_controls.md#restrict-visibility-levels), les profils utilisateurs ne sont visibles que par les utilisateurs authentifiés.

## Ajouter des informations à votre profil avec un fichier README {#add-details-to-your-profile-with-a-readme}

Vous pouvez ajouter davantage d'informations à votre page de profil grâce à un fichier README. Lorsque vous renseignez le fichier README avec des informations, celles-ci apparaissent sur votre page de profil.

### À partir d'un nouveau projet {#from-a-new-project}

Pour créer un nouveau projet et ajouter son fichier README à votre profil :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) puis **Nouveau projet/dépôt**.
1. Sélectionnez **Créer un projet vide**.
1. Saisissez les informations du projet :
   - Dans le champ **Nom du projet**, saisissez le nom de votre nouveau projet.
   - Dans le champ **URL du projet**, sélectionnez votre nom d'utilisateur GitLab.
   - Dans le champ **Identifiant « slug » du projet**, saisissez votre nom d'utilisateur GitLab. Tous ces champs sont sensibles à la casse. Si votre nom d'utilisateur contient des majuscules, saisissez-le dans le champ de l'identifiant « slug » du projet en incluant les majuscules.
1. Pour **Niveau de visibilité**, sélectionnez **Public**. ![Chemin de projet correct pour un individu sur le produit hébergé](img/personal_readme_setup_v14_5.png)
1. Pour **Configuration du Projet**, assurez-vous que **Initialiser le dépôt avec un README** est sélectionné.
1. Sélectionnez **Créer le projet**.
1. Créez un fichier README dans ce projet. Le fichier peut être tout [fichier README ou index valide](../project/repository/files/_index.md#readme-and-index-files).
1. Renseignez le fichier README avec du [Markdown](../markdown.md) ou un autre [langage de balisage pris en charge](../project/repository/files/_index.md#supported-markup-languages).

GitLab affiche le contenu de votre fichier README en dessous de votre graphique de contributions.

### À partir d'un projet existant {#from-an-existing-project}

Pour ajouter le fichier README d'un projet existant à votre profil, [mettez à jour le chemin](../project/working_with_projects.md#rename-a-repository) du projet pour qu'il corresponde à votre nom d'utilisateur.

## Ajouter des comptes externes à votre page de profil utilisateur {#add-external-accounts-to-your-user-profile-page}

Vous pouvez ajouter des liens vers certains autres comptes externes que vous possédez, comme Discord et X (anciennement Twitter). Ces liens peuvent aider d'autres utilisateurs à vous retrouver sur d'autres plateformes.

Pour ajouter des liens vers d'autres comptes :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la section **Paramètres principaux**, ajoutez votre :
   - [ID utilisateur](https://support.discord.com/hc/en-us/articles/206346498-Where-can-I-find-my-User-Server-Message-ID) Discord.
   - Identifiant [`did:plc`](https://atproto.com/specs/did) BlueSky. Pour trouver votre identifiant, [résolvez votre pseudo utilisateur](https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=USER_HANDLE).
   - [ID utilisateur](https://support.discord.com/hc/en-us/articles/206346498-Where-can-I-find-my-User-Server-Message-ID) Discord.
   - Nom d'utilisateur GitHub.
   - Nom de profil LinkedIn.
   - [Pseudo Mastodon](#add-a-mastodon-handle).
   - [ORCID](https://orcid.org/).
   - @pseudo X (anciennement Twitter).

   Votre ID utilisateur ou nom d'utilisateur doit comporter 500 caractères ou moins.
1. Sélectionnez **Mettre à jour les paramètres du profil**.

### Ajouter un pseudo Mastodon {#add-a-mastodon-handle}

{{< history >}}

- La possibilité de vérifier un compte Mastodon à l'aide de votre profil utilisateur GitLab a été [ajoutée](https://gitlab.com/gitlab-org/gitlab/-/issues/433391) dans GitLab 17.4 [avec un feature flag](../../administration/feature_flags/list.md) nommé `verify_mastodon_user`. Fonctionnalité désactivée par défaut.
- La possibilité de vérifier un compte Mastodon à l'aide de votre profil utilisateur GitLab est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/work_items/504194) dans GitLab 18.8. Le feature flag `verify_mastodon_user` a été supprimé.

{{< /history >}}

Pour ajouter un pseudo Mastodon :

1. Ajoutez votre pseudo Mastodon à votre profil GitLab.
   1. Connectez-vous à GitLab.
   1. Dans le coin supérieur droit, sélectionnez votre avatar.
   1. Sélectionnez **Modifier le profil**.
   1. Dans la section **Comptes sociaux**, accédez à **Mastodon** et saisissez votre pseudo. Par exemple : `@alex.garcia@exampleServer`.
   1. Sélectionnez **Mettre à jour les paramètres du profil**.
1. Obtenez l'URI de vérification.
   1. Dans le coin supérieur droit, sélectionnez votre avatar.
   1. Sélectionnez votre nom ou votre nom d'utilisateur.
   1. Sur le côté droit, sélectionnez votre pseudo Mastodon.
   1. Copiez l'URI de la page qui s'ouvre.
1. Ajoutez la vérification à Mastodon.
   1. Accédez aux paramètres de votre profil Mastodon.
   1. Dans la section **Champs supplémentaires**, saisissez l'URI obtenu précédemment.
   1. Enregistrez les modifications de votre profil Mastodon.

Vérifiez qu'une coche verte s'affiche à côté du champ supplémentaire de votre site GitLab dans Mastodon. Si aucune coche verte n'est affichée, vous devrez peut-être effectuer des opérations de dépannage supplémentaires.

## Afficher les contributions privées sur votre page de profil utilisateur {#show-private-contributions-on-your-user-profile-page}

Dans le graphique du calendrier de contributions et la liste des activités récentes, vous pouvez voir vos [actions de contribution](contributions_calendar.md#user-contribution-events) aux projets privés.

Pour afficher les contributions privées :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la section **Paramètres principaux**, cochez la case **Inclure les contributions privées sur mon profil**.
1. Sélectionnez **Mettre à jour les paramètres du profil**.

## Ajouter vos pronoms {#add-your-gender-pronouns}

Vous pouvez ajouter vos pronoms à votre compte GitLab pour qu'ils s'affichent à côté de votre nom dans votre profil.

Pour spécifier vos pronoms :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la zone de texte **Pronoms**, saisissez vos pronoms. Le texte doit comporter 50 caractères ou moins.
1. Sélectionnez **Mettre à jour les paramètres du profil**.

## Ajouter la prononciation de votre nom {#add-your-name-pronunciation}

Vous pouvez ajouter la prononciation de votre nom à votre compte GitLab. Celle-ci s'affiche dans votre profil, sous votre nom.

Pour ajouter la prononciation de votre nom :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la zone de texte **Prononciation**, saisissez la prononciation de votre nom. La prononciation doit être en texte brut et comporter 255 caractères ou moins.
1. Sélectionnez **Mettre à jour les paramètres du profil**.

## Définir votre statut {#set-your-status}

Définissez votre statut pour informer les autres de votre disponibilité. Les autres utilisateurs peuvent voir votre statut lorsqu'ils survolent votre avatar, votre nom ou votre nom d'utilisateur. Votre statut est visible publiquement même si vous avez [rendu votre page de profil utilisateur privée](#make-your-user-profile-page-private).

Votre statut se compose des éléments suivants. Vous pouvez utiliser chacun d'eux séparément pour indiquer votre statut.

- Un emoji pour indiquer votre statut.
- Un message décrivant votre disponibilité. Vous pouvez inclure des codes emoji tels que `:palm_tree:` ou `:bulb:`. Maximum de 100 caractères.
- Une case à cocher qui ajoute un badge `Busy` à votre statut.

Pour définir votre statut actuel :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Définir le statut**. Si vous avez déjà défini un statut, sélectionnez plutôt **Modifier le statut**.
1. Facultatif. Saisissez un message de statut.
1. Facultatif. Cochez la case **Mettre votre statut sur occupé**.
1. Facultatif. Sélectionnez une valeur dans la liste déroulante **Effacer le statut après**.
1. Sélectionnez **Définir le statut**.

Votre statut est mis à jour. Vous pouvez également définir votre statut depuis la page des [paramètres utilisateur](#access-your-user-settings) ou via l'[API Users](../../api/users.md#set-your-user-status).

## Définir votre fuseau horaire {#set-your-time-zone}

Vous pouvez définir votre fuseau horaire local pour :

- Afficher votre heure locale sur votre profil et aux endroits où survoler votre nom affiche des informations vous concernant.
- Aligner votre calendrier de contributions avec votre heure locale pour mieux refléter le moment où vos contributions ont été effectuées

Pour définir votre fuseau horaire :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la section **Paramètres de l'heure**, sélectionnez votre fuseau horaire dans la liste déroulante.

## Modifier l'adresse de courriel affichée sur vos commits {#change-the-email-displayed-on-your-commits}

Une adresse de courriel de commit est une adresse de courriel affichée dans chaque action liée à Git effectuée via l'interface GitLab.

N'importe laquelle de vos propres adresses de courriel vérifiées peut être utilisée comme adresse de courriel de commit. Votre adresse de courriel principale est utilisée par défaut.

Pour modifier votre adresse de courriel de commit :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la liste déroulante **Adresse de courriel de validation**, sélectionnez une adresse de courriel.
1. Sélectionnez **Mettre à jour les paramètres du profil**.

## Modifier votre adresse de courriel principale {#change-your-primary-email}

Votre adresse de courriel principale est l'adresse de courriel par défaut pour votre connexion, vos commits et vos notifications. Si votre adresse de courriel principale change, votre ancienne adresse de courriel principale est ajoutée comme adresse secondaire. Cette fonctionnalité permet aux commits effectués avec votre ancienne adresse de courriel principale de rester associés à votre compte.

Pour modifier votre adresse de courriel principale :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans le champ **Courriel**, saisissez votre nouvelle adresse de courriel.
1. Sélectionnez **Mettre à jour les paramètres du profil**.
1. Facultatif. Sélectionnez l'e-mail de confirmation si vous n'avez pas encore ajouté cette adresse de courriel à votre compte GitLab.com.

## Définir votre adresse de courriel publique {#set-your-public-email}

Vous pouvez sélectionner l'une de vos [adresses de courriel configurées](#add-emails-to-your-user-profile) pour l'afficher sur votre profil public :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans le champ **Adresse de courriel publique**, sélectionnez l'une des adresses de courriel disponibles.
1. Sélectionnez **Mettre à jour les paramètres du profil**.

### Utiliser une adresse de courriel de commit privée générée automatiquement {#use-an-automatically-generated-private-commit-email}

GitLab fournit une adresse de courriel de commit privée générée automatiquement, afin que vous puissiez garder vos informations de courriel privées.

Pour utiliser une adresse de courriel de commit privée :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la liste déroulante **Adresse de courriel de validation**, sélectionnez **Utiliser une adresse de courriel privée**.
1. Sélectionnez **Mettre à jour les paramètres du profil**.

Toutes les actions liées à Git utilisent l'adresse de courriel de commit privée.

Pour rester totalement anonyme, vous pouvez également copier l'adresse de courriel de commit privée et la configurer sur votre machine locale à l'aide de la commande suivante :

```shell
git config --global user.email <your email address>
```

## Suivre des utilisateurs {#follow-users}

Vous pouvez suivre ou ne plus suivre des utilisateurs depuis :

- Leur [profil utilisateur](#access-your-user-profile).
- La petite fenêtre contextuelle qui apparaît lorsque vous survolez le nom d'un utilisateur.

Le nombre maximum d'utilisateurs que vous pouvez suivre est de 300.

Les utilisateurs bloqués n'apparaissent pas dans la liste des abonnés sur les profils utilisateurs.

### Désactiver le suivi et le fait d'être suivi par d'autres utilisateurs {#disable-following-and-being-followed-by-other-users}

Vous pouvez désactiver le suivi et le fait d'être suivi par d'autres utilisateurs.

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Sélectionnez **Préférences**.
1. Décochez la case **Activer le suivi des utilisateurs**.
1. Sélectionnez **Enregistrer les modifications**.

> [!note]
> Lorsque cette fonctionnalité est désactivée, toutes les connexions de suivi actuelles sont supprimées.

## Afficher l'activité d'un utilisateur {#view-a-users-activity}

GitLab suit l'[activité de contribution des utilisateurs](contributions_calendar.md). Pour afficher l'activité d'un utilisateur :

1. Accédez au profil de l'utilisateur.
1. Dans le menu GitLab, sélectionnez **Activité**.

Une liste des contributions de l'**Activité la plus récente** s'affiche.

## Afficher votre activité {#view-your-activity}

Pour afficher votre activité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**.
1. Sélectionnez **Votre travail**.
1. Sélectionnez **Activité**.
1. Facultatif. Pour filtrer votre activité par type de contribution, dans l'onglet **Votre activité**, sélectionnez un onglet :

   - **Tous** : toutes les contributions que vous avez effectuées dans vos groupes et projets.
   - **Événements poussés** : les événements de push que vous avez effectués dans vos projets.
   - **Événements de fusion** : les merge requests que vous avez acceptées dans vos projets.
   - **Événements liés à un ticket** : les tickets que vous avez ouverts et fermés dans vos projets.
   - **Commentaires** : les commentaires que vous avez publiés dans vos projets.
   - **Wiki** : les pages Wiki que vous avez créées et mises à jour dans vos projets.
   - **Designs** : les designs que vous avez ajoutés, mis à jour et supprimés dans vos projets.
   - **Équipe** : les projets que vous avez rejoints et quittés.
1. Facultatif. Pour vous abonner à un flux RSS de cette activité, dans le coin supérieur droit, sélectionnez le symbole de flux ({{< icon name="rss" >}}).

Le flux contient toujours toute l'activité des projets dont vous êtes membre, quel que soit l'onglet ou le filtre sélectionné. L'URL du flux contient un [jeton de flux](../../security/tokens/_index.md#feed-token) qui vous authentifie.

## Services de connexion {#sign-in-services}

Au lieu d'utiliser un nom d'utilisateur et un mot de passe classiques pour vous connecter à GitLab, vous pouvez utiliser un service de connexion.

### Connecter un service de connexion {#connect-a-sign-in-service}

Pour connecter un service de connexion à utiliser pour vous connecter à GitLab :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Mot de passe et authentification**.
1. Localisez la section **Connexion via un service tiers**.
1. Dans la section **Comptes connectés**, sélectionnez le bouton correspondant au service avec lequel vous souhaitez vous connecter.
1. Suivez les instructions du service sélectionné pour commencer à vous y connecter.

### Déconnecter un service de connexion {#disconnect-a-sign-in-service}

Pour déconnecter un service de connexion utilisé pour vous connecter à GitLab :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Mot de passe et authentification**.
1. Localisez la section **Connexion via un service tiers**.
1. Dans la section **Comptes connectés**, sélectionnez **Déconnecter** en regard du bouton correspondant au service avec lequel vous ne souhaitez plus vous connecter.

## Durée de session {#session-duration}

### Rester connecté pendant une semaine {#stay-signed-in-for-one-week}

Par défaut, vous êtes déconnecté de GitLab après sept jours (10 080 minutes) d'inactivité ou lorsque vous fermez votre fenêtre de navigateur, selon ce qui se produit en premier.

Les administrateurs GitLab peuvent [modifier cette valeur par défaut](../../administration/settings/account_and_limit_settings.md#customize-the-default-session-duration).

### Rester connecté indéfiniment {#stay-signed-in-indefinitely}

Pour rester connecté indéfiniment, cochez la case **Se souvenir de moi** sur la page de connexion GitLab.

Vous restez connecté car, bien que le serveur définisse une durée de session d'une semaine, votre navigateur stocke un jeton sécurisé qui permet la réauthentification automatique.

Les administrateurs GitLab peuvent [désactiver le paramètre **Se souvenir de moi**](../../administration/settings/account_and_limit_settings.md#session-duration) pour les environnements qui nécessitent l'expiration périodique des sessions à des fins de sécurité ou de conformité.

### Cookies utilisés pour la connexion {#cookies-used-for-sign-in}

Lors de votre connexion, trois cookies sont définis :

- Un cookie de session appelé `_gitlab_session`. Ce cookie n'a pas de date d'expiration définie. Cependant, il expire en fonction de son paramètre `session_expire_delay`.
- Un cookie de session appelé `gitlab_user`. Ce cookie est utilisé par le [site marketing](https://about.gitlab.com/) pour déterminer si un utilisateur dispose d'une session GitLab active. Aucune information utilisateur n'est transmise au cookie, et celui-ci expire deux semaines après la connexion.
- Un cookie persistant appelé `remember_user_token`, qui n'est défini que si vous avez sélectionné **Se souvenir de moi** sur la page de connexion.

Lorsque vous fermez votre navigateur, les cookies `_gitlab_session` et `gitlab_user` sont généralement supprimés côté client. Lorsqu'il expire ou n'est pas disponible, GitLab :

- Utilise le cookie `remember_user_token` pour vous obtenir un nouveau cookie `_gitlab_session` et vous maintenir connecté, même si vous fermez votre navigateur.
- Définit `gitlab_user` sur `true`.

Lorsque les cookies `remember_user_token` et `_gitlab_session` sont supprimés ou expirés, vous devez vous reconnecter.

> [!note]
> Lorsqu'une session est déconnectée ou révoquée depuis la [liste des sessions actives](active_sessions.md), tous les jetons **Se souvenir de moi** sont révoqués. Lorsque d'autres sessions restent actives, la fonctionnalité **Se souvenir de moi** ne restaure pas une session si le navigateur est fermé ou si la session existante expire.

## Sujets connexes {#related-topics}

- [Créer des utilisateurs](account/create_accounts.md)
- [Se connecter à votre compte GitLab](../../administration/auth/_index.md)
- [Comptes utilisateurs verrouillés](../../security/unlock_user.md)
- [Modifier votre mot de passe](user_passwords.md)
- Recevoir des e-mails pour :
  - [Connexions depuis des adresses IP ou des appareils inconnus](notifications.md#notifications-for-unknown-sign-ins)
  - [Tentatives de connexion avec des codes de vérification incorrects](notifications.md#notifications-for-attempted-sign-ins-using-incorrect-verification-codes)
- Gérer les applications pouvant [utiliser GitLab comme fournisseur OAuth](../../integration/oauth_provider.md)
- Gérer les [jetons d'accès personnels](personal_access_tokens.md) pour accéder à votre compte via l'API et les applications autorisées
- Gérer les [clés SSH](../ssh.md) pour accéder à votre compte via SSH
- [Modifier le thème de coloration syntaxique](preferences.md#change-the-syntax-highlighting-theme)
- [Afficher vos sessions actives](active_sessions.md) et révoquer l'une d'entre elles si nécessaire
