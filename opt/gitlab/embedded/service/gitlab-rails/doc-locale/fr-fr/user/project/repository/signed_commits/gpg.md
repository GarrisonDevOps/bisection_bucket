---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Signez les commits et les tags dans votre dépôt GitLab avec des clés GPG (GNU Privacy Guard).
title: Signer les commits et les tags avec GPG
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez signer les commits que vous effectuez dans un dépôt GitLab avec une clé [GPG (GNU Privacy Guard)](https://gnupg.org/).

> [!note]
> GitLab utilise le terme GPG pour tous les éléments et implémentations liés à OpenPGP, PGP et GPG.

Pour que GitLab considère un commit comme vérifié :

- Le validateur doit disposer d'une paire de clés publique/privée GPG.
- La clé publique du validateur doit être importée dans son compte GitLab.
- L'une des adresses e-mail de la clé publique GPG doit correspondre à une adresse e-mail vérifiée utilisée par le validateur dans GitLab. GitLab ignore les adresses e-mail provenant d'identifiants utilisateur révoqués. Pour garder cette adresse privée, utilisez l'[adresse e-mail de commit privée générée automatiquement](../../../profile/_index.md#use-an-automatically-generated-private-commit-email) que GitLab fournit dans votre profil.
- L'adresse e-mail du validateur doit correspondre à l'adresse e-mail vérifiée associée à la clé GPG.

GitLab utilise son propre trousseau de clés pour vérifier la signature GPG. Il n'accède à aucun serveur de clés public.

Pour plus d'informations sur GPG, consultez la [liste des sujets connexes](#related-topics).

## Afficher la clé GPG publique d'un utilisateur {#view-a-users-public-gpg-key}

Pour afficher la clé GPG publique d'un utilisateur, vous pouvez :

- Accédez à `https://gitlab.example.com/<USERNAME>.gpg`. GitLab affiche la clé GPG, si l'utilisateur en a configuré une, ou une page vide pour les utilisateurs sans clé GPG configurée.
- Accédez au profil de l'utilisateur (par exemple `https://gitlab.example.com/<USERNAME>`). Dans le coin supérieur droit du profil de l'utilisateur, sélectionnez **Afficher la clé GPG publique** ({{< icon name="key" >}}). Ce bouton s'affiche uniquement si l'utilisateur a configuré la clé.

## Configurer la signature des commits {#configure-commit-signing}

Pour signer des commits, vous devez configurer à la fois votre machine locale et votre compte GitLab :

1. [Créer une clé GPG](#create-a-gpg-key).
1. [Ajouter une clé GPG à votre compte](#add-a-gpg-key-to-your-account).
1. [Associer votre clé GPG à Git](#associate-your-gpg-key-with-git).
1. [Signer vos commits Git](#sign-your-git-commits).

### Créer une clé GPG {#create-a-gpg-key}

Si vous ne disposez pas encore d'une clé GPG, créez-en une :

1. [Installez GPG](https://www.gnupg.org/download/) pour votre système d'exploitation. Si votre système d'exploitation dispose de `gpg2` installé, remplacez `gpg` par `gpg2` dans les commandes de cette page.
1. Pour générer votre paire de clés, exécutez la commande appropriée à votre version de `gpg` :

   ```shell
   # Use this command for the default version of GPG, including
   # Gpg4win on Windows, and most macOS versions:
   gpg --gen-key

   # Use this command for versions of GPG later than 2.1.17:
   gpg --full-gen-key
   ```

1. Sélectionnez l'algorithme que votre clé doit utiliser, ou appuyez sur <kbd>Entrée</kbd> pour sélectionner l'option par défaut, `RSA and RSA`.
1. Sélectionnez la longueur de la clé, en bits. GitLab recommande des clés de 4096 bits.
1. Spécifiez la période de validité de votre clé. Cette valeur est subjective, et la valeur par défaut est sans expiration.
1. Pour confirmer vos réponses, entrez `y`.
1. Entrez votre nom.
1. Entrez votre adresse e-mail. Elle doit correspondre à une [adresse e-mail vérifiée](../../../profile/_index.md#change-the-email-displayed-on-your-commits) dans votre compte GitLab.
1. Facultatif. Entrez un commentaire à afficher entre parenthèses après votre nom.
1. GPG affiche les informations que vous avez saisies jusqu'à présent. Modifiez les informations ou appuyez sur <kbd>O</kbd> (pour `Okay`) pour continuer.
1. Entrez un mot de passe fort, puis entrez-le à nouveau pour le confirmer.
1. Pour lister votre clé GPG privée, exécutez cette commande en remplaçant `<EMAIL>` par l'adresse e-mail que vous avez utilisée lors de la génération de la clé :

   ```shell
   gpg --list-secret-keys --keyid-format LONG <EMAIL>
   ```

1. Dans la sortie, identifiez la ligne `sec` et copiez l'identifiant de la clé GPG. Il commence après le caractère `/`. Dans cet exemple, l'identifiant de la clé est `30F2B65B9246B6CA` :

   ```plaintext
   sec   rsa4096/30F2B65B9246B6CA 2017-08-18 [SC]
         D5E4F29F3275DC0CDA8FFC8730F2B65B9246B6CA
   uid                   [ultimate] Mr. Robot <your_email>
   ssb   rsa4096/B7ABC0813E4028C0 2017-08-18 [E]
   ```

1. Pour afficher la clé publique associée, exécutez cette commande en remplaçant `<ID>` par l'identifiant de la clé GPG de l'étape précédente :

   ```shell
   gpg --armor --export <ID>
   ```

1. Copiez la clé publique, y compris les lignes `BEGIN PGP PUBLIC KEY BLOCK` et `END PGP PUBLIC KEY BLOCK`. Vous aurez besoin de cette clé à l'étape suivante.

### Ajouter une clé GPG à votre compte {#add-a-gpg-key-to-your-account}

Pour ajouter une clé GPG à vos paramètres utilisateur :

1. Connectez-vous à GitLab.
1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Clés GPG**.
1. Sélectionnez **Ajouter une nouvelle clé**.
1. Dans **Clé**, collez votre clé publique.
1. Pour ajouter la clé à votre compte, sélectionnez **Ajouter une clé**.

GitLab affiche l'empreinte de la clé, l'adresse e-mail et la date de création. Si vous révoquez un identifiant utilisateur dans votre clé GPG, GitLab n'affiche pas son adresse e-mail. Les commits qui utilisent cette adresse comme e-mail du validateur sont marqués comme non vérifiés.

Une fois une clé ajoutée, vous ne pouvez pas la modifier. À la place, supprimez la clé problématique et ajoutez-la à nouveau.

### Associer votre clé GPG à Git {#associate-your-gpg-key-with-git}

Après avoir [créé votre clé GPG](#create-a-gpg-key) et [ajouté celle-ci à votre compte](#add-a-gpg-key-to-your-account), vous devez configurer Git pour utiliser cette clé :

1. Exécutez cette commande pour lister la clé GPG privée que vous venez de créer, en remplaçant `<EMAIL>` par l'adresse e-mail associée à votre clé :

   ```shell
   gpg --list-secret-keys --keyid-format LONG <EMAIL>
   ```

1. Copiez l'identifiant de la clé GPG privée qui commence par `sec`. Dans cet exemple, l'identifiant de la clé privée est `30F2B65B9246B6CA` :

   ```plaintext
   sec   rsa4096/30F2B65B9246B6CA 2017-08-18 [SC]
         D5E4F29F3275DC0CDA8FFC8730F2B65B9246B6CA
   uid                   [ultimate] Mr. Robot <your_email>
   ssb   rsa4096/B7ABC0813E4028C0 2017-08-18 [E]
   ```

1. Exécutez cette commande pour configurer Git afin de signer vos commits avec votre clé, en remplaçant `<KEY ID>` par votre identifiant de clé GPG :

   ```shell
   git config --global user.signingkey <KEY ID>
   ```

### Signer vos commits Git {#sign-your-git-commits}

Après avoir [ajouté votre clé publique à votre compte](#add-a-gpg-key-to-your-account), vous pouvez signer des commits individuels manuellement ou configurer Git pour utiliser les commits signés par défaut :

- Signer des commits Git individuels manuellement :
  1. Ajoutez l'indicateur `-S` à tout commit que vous souhaitez signer :

     ```shell
     git commit -S -m "My commit message"
     ```

  1. Entrez la phrase secrète de votre clé GPG lorsqu'elle est demandée.
  1. Effectuez un push vers GitLab et vérifiez que vos commits [sont vérifiés](_index.md#verify-commits).
- Signer tous les commits Git par défaut en exécutant cette commande :

  ```shell
  git config --global commit.gpgsign true
  ```

#### Définir la clé de signature de manière conditionnelle {#set-signing-key-conditionally}

Si vous gérez des clés de signature à des fins distinctes, comme le travail et l'usage personnel, utilisez une instruction `IncludeIf` dans votre fichier `.gitconfig` pour définir la clé avec laquelle vous signez les commits.

Prérequis :

- Nécessite Git version 2.13 ou ultérieure.

1. Dans le même répertoire que votre fichier principal `~/.gitconfig`, créez un second fichier, tel que `.gitconfig-gitlab`.
1. Dans votre fichier principal `~/.gitconfig`, ajoutez vos paramètres Git pour les projets non-GitLab.
1. Ajoutez ces informations à la fin de votre fichier principal `~/.gitconfig` :

   ```ini
   # The contents of this file are included only for GitLab.com URLs
   [includeIf "hasconfig:remote.*.url:https://gitlab.com/**"]

   # Edit this line to point to your alternative configuration file
   path = ~/.gitconfig-gitlab
   ```

1. Dans votre fichier alternatif `.gitconfig-gitlab`, ajoutez les remplacements de configuration à utiliser lorsque vous validez dans un dépôt GitLab. Tous les paramètres de votre fichier principal `~/.gitconfig` sont conservés, sauf si vous les remplacez explicitement. Dans cet exemple :

   ```ini
   # Alternative ~/.gitconfig-gitlab file
   # These values are used for repositories matching the string 'gitlab.com',
   # and override their corresponding values in ~/.gitconfig

   [user]
   email = you@example.com
   signingkey = <KEY ID>

   [commit]
   gpgsign = true
   ```

## Signer et vérifier les tags {#sign-and-verify-tags}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/19260) dans GitLab 18.3 [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `render_gpg_signed_tags_verification_status`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/560619) dans GitLab 19.0.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/599765) dans GitLab 19.1. Le feature flag `render_gpg_signed_tags_verification_status` a été supprimé.

{{< /history >}}

Après avoir [associé votre clé GPG à Git](#associate-your-gpg-key-with-git), vous pouvez signer vos tags :

1. Lorsque vous créez un tag Git, ajoutez l'indicateur `-s` :

   ```shell
   git tag -s v1.1.1 -m "My signed tag"
   ```

1. Effectuez un push de votre tag vers GitLab.
1. Pour vérifier la signature localement, exécutez :

   ```shell
   git tag --verify v1.1.1
   ```

1. Facultatif. Pour signer tous les tags automatiquement, exécutez :

   ```shell
   git config --global tag.gpgsign true
   ```

## Révoquer une clé GPG {#revoke-a-gpg-key}

Si une clé GPG est compromise, révoquez-la. La révocation d'une clé affecte à la fois les commits futurs et passés :

- Les commits passés signés avec cette clé sont marqués comme non vérifiés.
- Les commits futurs signés avec cette clé sont marqués comme non vérifiés.

La révocation d'une clé dans GitLab n'est pas la même chose que la révocation de l'un des identifiants utilisateur de la clé avec GnuPG. Si vous révoquez un identifiant utilisateur, seuls les commits qui utilisent l'adresse e-mail de cet identifiant utilisateur comme e-mail du validateur sont marqués comme non vérifiés.

Pour révoquer une clé GPG :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Clés GPG**.
1. Sélectionnez **Révoquer** à côté de la clé GPG que vous souhaitez révoquer.

## Supprimer une clé GPG {#remove-a-gpg-key}

Lorsque vous supprimez une clé GPG de votre compte GitLab :

- Les commits précédents signés avec cette clé restent vérifiés.
- Les commits futurs (y compris les commits créés mais pas encore poussés) qui tentent d'utiliser cette clé ne sont pas vérifiés.

Pour supprimer une clé GPG de votre compte :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Clés GPG**.
1. Sélectionnez **Supprimer** ({{< icon name="remove" >}}) à côté de la clé GPG que vous souhaitez supprimer.

Si vous devez dévérifier à la fois les commits futurs et passés, [révoquez la clé GPG associée](#revoke-a-gpg-key) à la place.

## Sujets connexes {#related-topics}

- [Configurer la signature des commits pour les commits effectués dans l'interface web](../../../../administration/gitaly/configure_gitaly.md#configure-commit-signing-for-gitlab-ui-commits)
- Ressources GPG :
  - [Git Tools - Signing Your Work](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)
  - [Gestion des clés OpenPGP](https://riseup.net/en/security/message-security/openpgp/gpg-keys)
  - [Bonnes pratiques OpenPGP](https://riseup.net/en/security/message-security/openpgp/best-practices)
  - [Créer une nouvelle clé GPG avec des sous-clés](https://www.void.gr/kargig/blog/2013/12/02/creating-a-new-gpg-key-with-subkeys/) (avancé)
  - [Afficher les clés GPG dans votre instance](../../../../administration/credentials_inventory.md#view-the-credentials-inventory)
  - [Intégration Beyond Identity](../../integrations/beyond_identity.md)

## Dépannage {#troubleshooting}

### Clé secrète non disponible {#secret-key-not-available}

Si vous recevez les erreurs `secret key not available` ou `gpg: signing failed: secret key not available`, essayez d'utiliser `gpg2` à la place de `gpg` :

```shell
git config --global gpg.program gpg2
```

Si votre clé GPG est protégée par un mot de passe et que l'invite de saisie du mot de passe n'apparaît pas, ajoutez `export GPG_TTY=$(tty)` au fichier `rc` de votre shell (généralement `~/.bashrc` ou `~/.zshrc`)

### Échec de GPG lors de la signature des données {#gpg-fails-to-sign-data}

Si votre clé GPG est protégée par un mot de passe et que vous recevez l'une des erreurs suivantes :

```plaintext
error: gpg failed to sign the data
fatal: failed to write commit object
gpg: signing failed: Inappropriate ioctl for device
```

Si l'invite de saisie du mot de passe n'apparaît pas :

1. Ouvrez le fichier de configuration de votre shell, généralement `~/.bashrc` ou `~/.zshrc`, dans un éditeur de texte.
1. Ajoutez la ligne suivante au fichier :

   ```shell
   export GPG_TTY=$(tty)
   ```

1. Enregistrez le fichier et quittez l'éditeur de texte.
1. Appliquez les modifications. Choisissez l'une des options suivantes :

   - Redémarrez votre terminal.
   - Exécutez `source ~/.bashrc` ou `source ~/.zshrc`.

> [!note]
> Les étapes exactes peuvent varier en fonction de votre système d'exploitation et de la configuration de votre shell.
