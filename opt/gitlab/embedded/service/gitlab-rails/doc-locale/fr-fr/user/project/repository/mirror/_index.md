---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Utilisez la mise en miroir de dépôt pour pousser ou tirer le contenu d'un dépôt Git vers un autre dépôt."
title: Mise en miroir de dépôt
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez mettre en miroir un dépôt vers et depuis des sources externes. Vous pouvez choisir quel dépôt sert de source. Les branches, les tags et les commits sont synchronisés automatiquement.

Plusieurs méthodes de mise en miroir existent :

- [Push](push.md) : mettre en miroir un dépôt depuis GitLab vers un autre emplacement.
- [Pull](pull.md) : mettre en miroir un dépôt depuis un autre emplacement. Disponible dans les éditions Premium et Ultimate.
- La mise en miroir [bidirectionnelle](bidirectional.md) est également disponible, mais peut provoquer des conflits.

Mettez un dépôt en miroir dans les cas suivants :

- La version canonique de votre projet a migré vers GitLab. Pour continuer à fournir une copie de votre projet à son emplacement précédent, configurez votre dépôt GitLab en tant que [miroir push](push.md). Les modifications que vous apportez à votre dépôt GitLab sont copiées vers l'ancien emplacement.
- Votre instance GitLab est privée, mais vous souhaitez rendre certains projets open-source.
- Vous avez migré vers GitLab, mais la version canonique de votre projet se trouve ailleurs. Configurez votre dépôt GitLab en tant que [miroir pull](pull.md) de l'autre projet. Votre dépôt GitLab tire des copies des commits, des tags et des branches du projet. Ils deviennent disponibles à l'utilisation sur GitLab.

Les éléments suivants ne sont pas pris en charge :

- Les URL de style SCP. La mise en œuvre des URL de style SCP est en cours. Pour plus d'informations et pour suivre sa progression, consultez [l'issue 18993](https://gitlab.com/gitlab-org/gitlab/-/issues/18993).
- La mise en miroir de dépôts via le [protocole HTTP simple](https://git-scm.com/book/en/v2/Git-on-the-Server-The-Protocols#_dumb_http).
- La mise en miroir entre des dépôts utilisant des formats d'objets différents. Par exemple, entre des dépôts SHA-1 et [SHA-256](../../_index.md#create-a-project-that-uses-sha-256-hashing).

## Créer un miroir de dépôt {#create-a-repository-mirror}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.
- Si votre miroir se connecte via `ssh://`, la clé d'hôte doit être détectable sur le serveur, ou vous devez disposer d'une copie locale de la clé.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Dépôts miroirs**.
1. Sélectionnez **Ajouter nouveau**.
1. Saisissez une **URL du dépôt Git**. Le dépôt doit être accessible via `http://`, `https://`, `ssh://` ou `git://`.
1. Sélectionnez un **Sens du miroir**. Pour plus d'informations, consultez [la mise en miroir pull](pull.md) et [la mise en miroir push](push.md).
1. Si vous avez saisi une URL `ssh://`, sélectionnez l'une des options suivantes :
   - **Détecter les clés de l'hôte** : GitLab récupère les clés d'hôte depuis le serveur et affiche les empreintes.
   - **Entrer les clés d'hôte manuellement**, et saisissez la clé d'hôte dans **Clé d'hôte SSH**.

   Lors de la mise en miroir du dépôt, GitLab vérifie qu'au moins une des clés d'hôte stockées correspond avant de se connecter. Cette vérification protège votre miroir contre les injections de code malveillant et votre mot de passe contre le vol.

   - Pour créer un miroir de dépôt avec l'authentification SSH, consultez l'exemple [créer un miroir avec l'authentification SSH](#example-create-mirror-with-ssh-authentication).

1. Sélectionnez une **Méthode d'authentification**. Pour plus d'informations, consultez [les méthodes d'authentification pour les miroirs](#authentication-methods-for-mirrors).
1. Si vous vous authentifiez avec des clés d'hôte SSH, [vérifiez la clé d'hôte](#verify-a-host-key) pour vous assurer qu'elle est correcte.
1. Pour empêcher les push forcés sur des refs divergentes, sélectionnez **Conserver les références divergentes**. Pour plus d'informations, consultez [Conserver les références divergentes](push.md#keep-divergent-refs).
1. Facultatif. Pour limiter le nombre de branches mises en miroir, sélectionnez **Mettre en miroir les branches protégées uniquement** ou saisissez une expression régulière dans **Répliquer en miroir des branches spécifiques**.
1. Sélectionnez **Dépôt miroir**.

### Exemple : créer un miroir avec l'authentification SSH {#example-create-mirror-with-ssh-authentication}

Si vous sélectionnez `SSH public key` comme méthode d'authentification, GitLab génère une clé publique pour votre dépôt GitLab. Vous devez fournir cette clé au serveur non-GitLab. Pour plus d'informations, consultez [obtenir votre clé publique SSH](#get-your-ssh-public-key).

Pour mettre en miroir un dépôt avec l'authentification SSH :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Dépôts miroirs**.
1. Sélectionnez **Ajouter nouveau**.
1. Saisissez une **URL du dépôt Git**. Fournissez une URL au format `ssh://gitlab.com/gitlab-org/gitlab.git`.

   > [!note]
   > Les URL SSH doivent utiliser le format `ssh://host/path/to/repo.git` au lieu des URL de style SCP (`git@host:path/to/repo.git`). Remplacez le deux-points (`:`) par une barre oblique (`/`) et ajoutez le préfixe `ssh://`.

1. Sélectionnez un **Sens du miroir**. Pour plus d'informations, consultez [la mise en miroir pull](pull.md) et [la mise en miroir push](push.md).
1. Sélectionnez **Détecter les clés de l'hôte** ou **Entrer les clés d'hôte manuellement**.
1. Dans le champ **Méthode d'authentification**, sélectionnez **Clé SSH publique**
1. Dans le champ **Nom d'utilisateur**, ajoutez `git`.
1. Facultatif. Configurez les paramètres **Répliquer des branches en miroir**.
1. Sélectionnez **Dépôt miroir**.
1. Copiez la clé publique SSH et fournissez-la à votre serveur non-GitLab.

### Mettre en miroir les branches protégées uniquement {#mirror-only-protected-branches}

Vous pouvez choisir de mettre en miroir uniquement les [branches protégées](../branches/protected.md) dans le projet de mise en miroir, que ce soit depuis ou vers votre dépôt distant. Pour la [mise en miroir pull](pull.md), les branches non protégées du projet de mise en miroir ne sont pas mises en miroir et peuvent diverger.

Pour utiliser cette option, sélectionnez **Mettre en miroir les branches protégées uniquement** lors de la création d'un miroir de dépôt.

### Répliquer en miroir des branches spécifiques {#mirror-specific-branches}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour mettre en miroir uniquement les branches dont le nom correspond à une [expression régulière RE2](https://github.com/google/re2/wiki/Syntax), saisissez une expression régulière dans le champ **Répliquer en miroir des branches spécifiques**. Les branches dont le nom ne correspond pas à l'expression régulière ne sont pas mises en miroir.

## Mettre à jour un miroir {#update-a-mirror}

Lorsque le dépôt miroir est mis à jour, toutes les nouvelles branches, tous les nouveaux tags et tous les nouveaux commits sont visibles dans le flux d'activité du projet. Un miroir de dépôt sur GitLab se met à jour automatiquement. Vous pouvez également déclencher manuellement une mise à jour :

- Au maximum une fois toutes les cinq minutes sur GitLab.com.
- Conformément à la [limite d'intervalle de mise en miroir pull](../../../../administration/instance_limits.md#pull-mirroring-interval) définie par l'administrateur sur les instances GitLab Self-Managed.

> [!note]
> [Le mode silencieux de GitLab](../../../../administration/silent_mode/_index.md) désactive les mises à jour push et pull.

### Forcer une mise à jour {#force-an-update}

Bien que les miroirs soient planifiés pour se mettre à jour automatiquement, vous pouvez forcer une mise à jour immédiate, sauf si :

- Le miroir est déjà en cours de mise à jour.
- L'[intervalle, en secondes](../../../../administration/instance_limits.md#pull-mirroring-interval), pour les limites de mise en miroir pull ne s'est pas écoulé depuis sa dernière mise à jour.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Dépôts miroirs**.
1. Faites défiler jusqu'à **Dépôts mis en miroir** et identifiez le miroir à mettre à jour.
1. Sélectionnez **Mettre à jour maintenant** ({{< icon name="retry" >}}).

## Méthodes d'authentification pour les miroirs {#authentication-methods-for-mirrors}

Lorsque vous créez un miroir, vous devez configurer la méthode d'authentification associée. GitLab prend en charge ces méthodes d'authentification :

- [Authentification SSH](#ssh-authentication).
- Nom d'utilisateur et mot de passe.

Pour un [jeton d'accès au projet](../../settings/project_access_tokens.md) ou un [jeton d'accès au groupe](../../../group/settings/group_access_tokens.md), utilisez une valeur non vide comme nom d'utilisateur et le jeton comme mot de passe.

### Authentification SSH {#ssh-authentication}

L'authentification SSH est mutuelle :

- Vous devez prouver au serveur que vous êtes autorisé à accéder au dépôt.
- Le serveur doit également vous prouver qu'il est bien celui qu'il prétend être.

Pour l'authentification SSH, vous fournissez vos informations d'identification sous forme de mot de passe ou de clé publique. Le serveur sur lequel réside l'autre dépôt fournit ses informations d'identification sous forme de clé d'hôte. Vous devez [vérifier l'empreinte](#verify-a-host-key) de cette clé d'hôte manuellement.

Si vous effectuez la mise en miroir via SSH (en utilisant une URL `ssh://`), vous pouvez vous authentifier à l'aide de :

- L'authentification par mot de passe, comme avec HTTPS.
- L'authentification par clé publique. Cette méthode est souvent plus sécurisée que l'authentification par mot de passe, notamment lorsque l'autre dépôt prend en charge les [clés de déploiement](../../deploy_keys/_index.md).

### Obtenir votre clé publique SSH {#get-your-ssh-public-key}

Lorsque vous mettez en miroir un dépôt et sélectionnez **Clé SSH publique** comme méthode d'authentification, GitLab génère une clé publique pour vous. Le serveur non-GitLab a besoin de cette clé pour établir une relation de confiance avec votre dépôt GitLab. Pour copier votre clé publique SSH :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Dépôts miroirs**.
1. Faites défiler jusqu'à **Dépôts mis en miroir**.
1. Identifiez le dépôt approprié et sélectionnez **Copier la clé publique SSH** ({{< icon name="copy-to-clipboard" >}}).
1. Ajoutez la clé SSH publique à la configuration de l'autre dépôt :
   - Si l'autre dépôt est hébergé sur GitLab, ajoutez la clé SSH publique en tant que [clé de déploiement](../../deploy_keys/_index.md).
   - Si l'autre dépôt est hébergé ailleurs, ajoutez la clé au fichier `authorized_keys` de votre utilisateur. Collez l'intégralité de la clé SSH publique dans le fichier sur sa propre ligne et enregistrez-le.

Si vous devez changer la clé à tout moment, vous pouvez supprimer et rajouter le miroir pour en générer une nouvelle. Mettez à jour l'autre dépôt avec la nouvelle clé pour maintenir le fonctionnement du miroir.

> [!note]
> Les clés générées sont stockées dans la base de données GitLab, et non dans le système de fichiers. Par conséquent, l'authentification par clé publique SSH pour les miroirs ne peut pas être utilisée dans un hook pre-receive.

### Vérifier une clé d'hôte {#verify-a-host-key}

Lors de l'utilisation d'une clé d'hôte, vérifiez toujours que les empreintes correspondent à ce que vous attendez. GitLab.com et d'autres sites d'hébergement de code publient leurs empreintes pour vous permettre de les vérifier :

- [AWS CodeCommit](https://docs.aws.amazon.com/codecommit/latest/userguide/regions.html#regions-fingerprints)
- [Bitbucket](https://support.atlassian.com/bitbucket-cloud/docs/configure-ssh-and-two-step-verification/)
- [Codeberg](https://docs.codeberg.org/security/ssh-fingerprint/)
- [GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)
- [GitLab.com](../../../gitlab_com/_index.md#ssh-host-keys-fingerprints)
- [Launchpad](https://documentation.ubuntu.com/launchpad/user/reference/ssh-fingerprints/)
- [Savannah](https://savannah.gnu.org/maintenance/SshAccess/)
- [SourceForge](https://sourceforge.net/p/forge/documentation/SSH%20Key%20Fingerprints/)

Les autres fournisseurs varient. Vous pouvez recueillir les empreintes de clés de manière sécurisée avec la commande suivante si vous :

- Utilisez GitLab Self-Managed.
- Avez accès au serveur de l'autre dépôt.

```shell
$ cat /etc/ssh/ssh_host*pub | ssh-keygen -E md5 -l -f -
256 MD5:f4:28:9f:23:99:15:21:1b:bf:ed:1f:8e:a0:76:b2:9d root@example.com (ECDSA)
256 MD5:e6:eb:45:8a:3c:59:35:5f:e9:5b:80:12:be:7e:22:73 root@example.com (ED25519)
2048 MD5:3f:72:be:3d:62:03:5c:62:83:e8:6e:14:34:3a:85:1d root@example.com (RSA)
```

Les versions plus anciennes de SSH peuvent nécessiter la suppression de `-E md5` de la commande.

## Sujets connexes {#related-topics}

- [Dépannage](troubleshooting.md) de la mise en miroir de dépôt.
- Configurer un [intervalle de mise en miroir pull](../../../../administration/instance_limits.md#pull-mirroring-interval)
- [Désactiver les miroirs pour un projet](../../../../administration/settings/visibility_and_access_controls.md#enable-project-mirroring)
- [Fichier de secrets et mise en miroir](../../../../administration/backup_restore/troubleshooting_backup_gitlab.md#when-the-secrets-file-is-lost)
