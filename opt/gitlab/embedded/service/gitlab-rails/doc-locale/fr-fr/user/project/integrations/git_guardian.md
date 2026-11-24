---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Intégrez GitLab à GitGuardian pour recevoir des alertes concernant les violations de politique et les problèmes de sécurité avant qu'ils ne puissent être exploités."
title: GitGuardian
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/435706) dans GitLab 16.9 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `git_guardian_integration`. Activés par défaut. Désactivé sur GitLab.com.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/438695#note_2226917025) dans GitLab 17.7.
- [Disponible de manière générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/176391) dans GitLab 17.8. Le feature flag `git_guardian_integration` a été supprimé.
- Le paramètre `api_url` a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/599742) dans GitLab 19.1.

{{< /history >}}

[GitGuardian](https://www.gitguardian.com/) est un service de détection des secrets qui identifie les identifiants codés en dur, tels que les clés d'API, les mots de passe et les jetons, dans les dépôts de code source. Lorsque vous activez cette intégration, GitLab envoie chaque push à GitGuardian pour analyse. Si GitGuardian détecte un secret, GitLab bloque le push.

Vous pouvez configurer GitLab pour rejeter les commits en fonction des politiques de GitGuardian.

Pour configurer l'intégration GitGuardian :

1. [Créez un jeton d'API GitGuardian](#create-a-gitguardian-api-token).
1. [Configurez l'intégration GitGuardian pour votre projet](#set-up-the-gitguardian-integration-for-your-project).

## Créer un jeton d'API GitGuardian {#create-a-gitguardian-api-token}

Prérequis :

- Vous devez disposer d'un compte GitGuardian.

Pour créer un jeton d'API :

1. Connectez-vous à votre compte GitGuardian.
1. Accédez à la section **API** dans la barre latérale.
1. Dans la barre latérale de la section API, accédez à la page **Jetons d'accès personnel**.
1. Sélectionnez **Créer un jeton**. La boîte de dialogue de création de jeton s'ouvre.
1. Renseignez les informations de votre jeton :
   - Donnez à votre jeton d'API un nom explicite permettant d'identifier son utilisation. Par exemple, `GitLab integration token`.
   - Sélectionnez une expiration appropriée.
   - Cochez la case **scan scope**. C'est la seule portée nécessaire pour l'intégration.
1. Sélectionnez **Créer un jeton**.
1. Après avoir généré un jeton, copiez-le dans votre presse-papiers. Ce jeton est une information sensible ; conservez-le en lieu sûr.

Vous avez maintenant créé avec succès un jeton d'API GitGuardian que vous pouvez utiliser pour notre intégration.

## Configurer l'intégration GitGuardian pour votre projet {#set-up-the-gitguardian-integration-for-your-project}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Après avoir créé et copié votre jeton d'API, configurez GitLab pour rejeter les commits :

Pour activer l'intégration pour votre projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **GitGuardian**.
1. Dans **Activer l'intégration**, cochez la case **Actif**.
1. Facultatif. Dans la zone de texte **Point d'arrivée de l'API**, saisissez l'URL de base de votre instance GitGuardian :
   - Pour GitGuardian EU SaaS, saisissez `https://api.eu1.gitguardian.com`.
   - Pour GitGuardian auto-hébergé, saisissez l'URL de votre instance (par exemple, `https://gitguardian.example.com`).

   Si vous laissez ce champ vide, GitLab utilise le point d'arrivée SaaS US par défaut ( `https://api.gitguardian.com`).

1. Dans **Jeton d'API**, [collez la valeur du jeton provenant de GitGuardian](#create-a-gitguardian-api-token).
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

GitLab est maintenant prêt à rejeter les commits en fonction des politiques de GitGuardian.

## Ignorer la détection des secrets {#skip-secret-detection}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/152064) dans GitLab 17.0.

{{< /history >}}

Vous pouvez ignorer la détection des secrets GitGuardian si nécessaire. Les options permettant d'ignorer la détection des secrets pour tous les commits d'un push sont identiques aux options de [détection native des secrets](../../application_security/secret_detection/secret_push_protection/_index.md#skip-secret-push-protection). L'une ou l'autre des options :

- Ajoutez `[skip secret push protection]` à l'un des messages de commit.
- Utilisez `secret_push_protection.skip_all` comme [option de push](../../../topics/git/commit.md#push-options-for-gitguardian-integration).

## Problèmes connus {#known-issues}

- Les pushs peuvent être retardés ou expirer. Avec l'intégration GitGuardian :
  - Les pushs sont envoyés à un service tiers.
  - GitLab n'a aucun contrôle sur la connexion avec GitGuardian ni sur le processus GitGuardian.
- En raison d'une [limitation de l'API GitGuardian](https://api.gitguardian.com/docs#operation/multiple_scan), l'intégration ignore les fichiers dont la taille dépasse 1 Mo. Ils ne sont pas analysés.
- Si le nom d'un fichier poussé dépasse 256 caractères, le push échoue.
- Pour plus d'informations, consultez la [documentation de l'API GitGuardian](https://api.gitguardian.com/docs#operation/multiple_scan).

Les étapes de résolution des problèmes ci-dessous indiquent comment atténuer certains de ces problèmes.

## Dépannage {#troubleshooting}

Lorsque vous utilisez l'intégration GitGuardian, vous pouvez rencontrer les problèmes suivants.

### Erreurs HTTP `500` {#500-http-errors}

Vous pouvez obtenir une erreur HTTP `500`.

Ce problème survient lorsque les requêtes expirent pour des commits comportant un grand nombre de fichiers modifiés.

Si ce problème survient lorsque vous modifiez plus de 50 fichiers dans un commit :

1. Divisez vos modifications en commits plus petits.
1. Poussez les commits plus petits un par un.

### Erreur : `Filename: ensure this value has at most 256 characters` {#error-filename-ensure-this-value-has-at-most-256-characters}

Vous pouvez obtenir une erreur HTTP `400` indiquant `Filename: ensure this value has at most 256 characters`.

Ce problème survient lorsque certains des fichiers modifiés que vous poussez dans ce commit ont un nom de fichier (et non le chemin) supérieur à 256 caractères.

La solution de contournement consiste à raccourcir le nom du fichier si possible. Par exemple, si le nom du fichier ne peut pas être raccourci parce qu'il a été généré automatiquement par un framework, désactivez l'intégration et essayez de pousser à nouveau. N'oubliez pas de réactiver l'intégration par la suite si nécessaire.
