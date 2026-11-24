---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Apprenez à cloner des dépôts Git depuis un serveur GitLab en utilisant différents protocoles (SSH ou HTTPS) et divers IDE.
title: Cloner un dépôt Git sur votre ordinateur local
---

Vous pouvez cloner un dépôt Git sur votre ordinateur local. Cette action crée une copie du dépôt et établit une connexion qui synchronise les modifications entre votre ordinateur et le serveur GitLab. Cette connexion nécessite que vous ajoutiez des identifiants. Vous pouvez soit [cloner avec SSH](#clone-with-ssh) soit [cloner avec HTTPS](#clone-with-https). SSH est la méthode d'authentification recommandée.

Cloner un dépôt :

- Télécharge tous les fichiers du projet, l'historique et les métadonnées sur votre machine locale.
- Crée un répertoire de travail avec la dernière version des fichiers.
- Configure le suivi distant pour synchroniser les modifications futures.
- Fournit un accès hors ligne à la base de code complète.
- Établit la base pour contribuer du code au projet.

## Cloner avec SSH {#clone-with-ssh}

Clonez avec SSH lorsque vous souhaitez vous authentifier une seule fois.

1. Authentifiez-vous auprès de GitLab en suivant les instructions de la [documentation SSH](../../user/ssh.md).
1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet que vous souhaitez cloner.
1. Sur la page de présentation du projet, dans le coin supérieur droit, sélectionnez **Code**, puis copiez l'URL pour **Cloner avec SSH**.
1. Ouvrez un terminal et accédez au répertoire où vous souhaitez cloner les fichiers. Git crée automatiquement un dossier portant le nom du dépôt et y télécharge les fichiers.
1. Exécutez cette commande :

   ```shell
   git clone <copied URL>
   ```

1. Pour afficher les fichiers, accédez au nouveau répertoire :

   ```shell
   cd <new directory>
   ```

## Cloner avec HTTPS {#clone-with-https}

Clonez avec HTTPS lorsque vous souhaitez vous authentifier à chaque opération entre votre ordinateur et GitLab. Les [assistants d'identifiants OAuth](../../user/profile/account/two_factor_authentication.md#oauth-credential-helpers) peuvent réduire le nombre de fois où vous devez vous authentifier manuellement, rendant HTTPS une expérience transparente.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet que vous souhaitez cloner.
1. Sur la page de présentation du projet, dans le coin supérieur droit, sélectionnez **Code**, puis copiez l'URL pour **Cloner avec HTTPS**.
1. Ouvrez un terminal et accédez au répertoire où vous souhaitez cloner les fichiers.
1. Exécutez la commande suivante. Git crée automatiquement un dossier portant le nom du dépôt et y télécharge les fichiers.

   ```shell
   git clone <copied URL>
   ```

1. Authentifiez votre requête.

   > [!note]
   > Si vous avez activé l'authentification à deux facteurs (2FA), vous ne pouvez pas utiliser l'authentification par nom d'utilisateur et mot de passe. À la place :
   >
   > - [Utilisez un jeton](#clone-using-a-token) avec les permissions `read_repository` ou `write_repository`.
   > - Installez un [assistant d'identifiants OAuth](../../user/profile/account/two_factor_authentication.md#oauth-credential-helpers)

1. Pour afficher les fichiers, accédez au nouveau répertoire :

   ```shell
   cd <new directory>
   ```

> [!note]
> Sur Windows, si vous saisissez votre mot de passe incorrectement plusieurs fois et qu'un message `Access denied` apparaît, ajoutez votre espace de nommage (nom d'utilisateur ou groupe) au chemin : `git clone https://namespace@gitlab.com/gitlab-org/gitlab.git`.

### Cloner à l'aide d'un jeton {#clone-using-a-token}

Clonez avec HTTPS à l'aide d'un jeton si :

- Vous souhaitez utiliser la 2FA.
- Vous souhaitez disposer d'un ensemble d'identifiants révocables dont la portée est limitée à un ou plusieurs dépôts.

Vous pouvez utiliser l'un de ces jetons pour vous authentifier lors d'un clonage via HTTPS :

- [Jetons d'accès personnels](../../user/profile/personal_access_tokens.md).
- [Jetons de déploiement](../../user/project/deploy_tokens/_index.md).
- [Jetons d'accès au projet](../../user/project/settings/project_access_tokens.md).
- [Jetons d'accès au groupe](../../user/group/settings/group_access_tokens.md).

Par exemple :

```shell
git clone https://<username>:<token>@gitlab.example.com/tanuki/awesome_project.git
```

## Cloner et ouvrir dans Apple Xcode {#clone-and-open-in-apple-xcode}

Les projets contenant un répertoire `.xcodeproj` ou `.xcworkspace` peuvent être clonés dans Xcode sur macOS.

1. Depuis l'interface de GitLab, accédez à la page de présentation du projet.
1. Dans le coin supérieur droit, sélectionnez **Code**.
1. Sélectionnez **Xcode**.

Le projet est cloné sur votre ordinateur et vous êtes invité à ouvrir Xcode.

## Cloner et ouvrir dans Visual Studio Code {#clone-and-open-in-visual-studio-code}

Tous les projets peuvent être clonés dans Visual Studio Code depuis l'interface utilisateur de GitLab, mais vous pouvez également installer l'[extension GitLab pour VS Code](../../editor_extensions/visual_studio_code/_index.md) pour cloner depuis Visual Studio Code.

Prérequis :

- [Visual Studio Code](https://code.visualstudio.com/) doit être installé sur votre machine locale. Les autres versions de VS Code, comme VS Code Insiders et VSCodium, ne sont pas prises en charge.
- [Configurez votre navigateur pour les protocoles IDE](#configure-browsers-for-ide-protocols).
- Depuis l'interface GitLab :
  1. Accédez à la page de présentation du projet.
  1. Dans le coin supérieur droit, sélectionnez **Code**.
  1. Sous **Ouvrir dans votre IDE**, sélectionnez **Visual Studio Code (SSH)** ou **Visual Studio Code (HTTPS)**.
  1. Sélectionnez un dossier dans lequel cloner le projet.

     Une fois que Visual Studio Code a cloné votre projet, il ouvre le dossier.
- Depuis Visual Studio Code, avec l'[extension](../../editor_extensions/visual_studio_code/_index.md) installée, utilisez la commande [`Git: Clone`](../../editor_extensions/visual_studio_code/remote_urls.md#clone-a-git-project) de l'extension.

## Cloner et ouvrir dans IntelliJ IDEA {#clone-and-open-in-intellij-idea}

Tous les projets peuvent être clonés dans [IntelliJ IDEA](https://www.jetbrains.com/idea/) depuis l'interface utilisateur de GitLab.

Prérequis :

- [IntelliJ IDEA](https://www.jetbrains.com/idea/) doit être installé sur votre machine locale.
- [Configurez votre navigateur pour les protocoles IDE](#configure-browsers-for-ide-protocols).

Pour cela :

1. Accédez à la page de présentation du projet.
1. Dans le coin supérieur droit, sélectionnez **Code**.
1. Sous **Ouvrir dans votre IDE**, sélectionnez **IntelliJ IDEA (SSH)** ou **IntelliJ IDEA (HTTPS)**.

## Configurer les navigateurs pour les protocoles IDE {#configure-browsers-for-ide-protocols}

Pour vous assurer que la fonctionnalité **Ouvrir dans l'IDE** fonctionne, vous devez configurer vos navigateurs pour gérer les protocoles d'application personnalisés, tels que `vscode://` ou `jetbrains://`.

### Firefox {#firefox}

Firefox gère automatiquement les protocoles personnalisés si l'application requise est installée sur votre système. Lorsque vous sélectionnez pour la première fois un lien avec un protocole personnalisé, une boîte de dialogue s'ouvre et vous demande si vous souhaitez ouvrir l'application. Sélectionnez **Ouvrir le lien** pour autoriser Firefox à ouvrir l'application.

Si vous ne souhaitez plus être invité, cochez la case pour mémoriser votre choix.

Si la boîte de dialogue ne s'ouvre pas, vous devez configurer Firefox manuellement :

1. Ouvrez Firefox.
1. En haut à droite, sélectionnez le **menu d'ouverture de l'application** ({{< icon name="hamburger" >}}).
1. Recherchez ou accédez à la section **Applications**.
1. Trouvez et sélectionnez l'application souhaitée dans la liste. Par exemple, `vscode` ou `jetbrains`.
1. Sélectionnez Visual Studio Code ou IntelliJ IDEA dans la liste déroulante, ou sélectionnez **Utiliser un autre...** pour localiser l'exécutable.

Si votre IDE préféré n'est pas répertorié, vous êtes invité à choisir une application la première fois que vous sélectionnez le lien correspondant.

### Chrome {#chrome}

Chrome gère automatiquement les protocoles personnalisés si l'application requise est installée sur votre système. Lorsque vous sélectionnez pour la première fois un lien avec un protocole personnalisé dans Chrome, une boîte de dialogue s'ouvre et vous demande si vous souhaitez ouvrir l'application. Sélectionnez **Ouvrir** pour autoriser Chrome à ouvrir l'application.

Si vous ne souhaitez plus être invité, cochez la case pour mémoriser votre choix.

## Réduire la taille du clone {#reduce-clone-size}

Au fur et à mesure que les dépôts Git grossissent, ils peuvent devenir difficiles à utiliser en raison de :

- La grande quantité d'historique à télécharger.
- La grande quantité d'espace disque qu'ils requièrent.

Le [clone partiel](https://git-scm.com/docs/partial-clone) est une optimisation des performances qui permet à Git de fonctionner sans disposer d'une copie complète du dépôt. L'objectif de ce travail est de permettre à Git de mieux gérer les dépôts extrêmement volumineux.

Git 2.22.0 ou une version ultérieure est requise.

### Filtrer par taille de fichier {#filter-by-file-size}

Le stockage de fichiers binaires volumineux dans Git est généralement déconseillé, car chaque fichier volumineux ajouté est téléchargé par toutes les personnes qui clonent ou récupèrent les modifications par la suite. Ces téléchargements sont lents et problématiques, notamment lors d'une connexion internet lente ou instable.

L'utilisation du clone partiel avec un filtre de taille de fichier résout ce problème en excluant les fichiers volumineux problématiques des clones et des récupérations. Lorsque Git rencontre un fichier manquant, il est téléchargé à la demande.

Lors du clonage d'un dépôt, utilisez l'argument `--filter=blob:limit=<size>`. Par exemple, pour cloner le dépôt en excluant les fichiers de plus d'1 mégaoctet :

```shell
git clone --filter=blob:limit=1m git@gitlab.com:gitlab-com/www-gitlab-com.git
```

Cela produirait la sortie suivante :

```shell
Cloning into 'www-gitlab-com'...
remote: Enumerating objects: 832467, done.
remote: Counting objects: 100% (832467/832467), done.
remote: Compressing objects: 100% (207226/207226), done.
remote: Total 832467 (delta 585563), reused 826624 (delta 580099), pack-reused 0
Receiving objects: 100% (832467/832467), 2.34 GiB | 5.05 MiB/s, done.
Resolving deltas: 100% (585563/585563), done.
remote: Enumerating objects: 146, done.
remote: Counting objects: 100% (146/146), done.
remote: Compressing objects: 100% (138/138), done.
remote: Total 146 (delta 8), reused 144 (delta 8), pack-reused 0
Receiving objects: 100% (146/146), 471.45 MiB | 4.60 MiB/s, done.
Resolving deltas: 100% (8/8), done.
Updating files: 100% (13008/13008), done.
Filtering content: 100% (3/3), 131.24 MiB | 4.65 MiB/s, done.
```

La sortie est plus longue car Git :

1. Clone le dépôt en excluant les fichiers de plus d'1 mégaoctet.
1. Télécharge tous les fichiers volumineux manquants nécessaires pour extraire la branche par défaut.

Lors du changement de branche, Git peut télécharger davantage de fichiers manquants.

### Filtrer par type d'objet {#filter-by-object-type}

Pour les dépôts contenant des millions de fichiers et un historique long, vous pouvez exclure tous les fichiers et utiliser [`git sparse-checkout`](https://git-scm.com/docs/git-sparse-checkout) pour réduire la taille de votre copie de travail.

```shell
# Clone the repo excluding all files
$ git clone --filter=blob:none --sparse git@gitlab.com:gitlab-com/www-gitlab-com.git
Cloning into 'www-gitlab-com'...
remote: Enumerating objects: 678296, done.
remote: Counting objects: 100% (678296/678296), done.
remote: Compressing objects: 100% (165915/165915), done.
remote: Total 678296 (delta 472342), reused 673292 (delta 467476), pack-reused 0
Receiving objects: 100% (678296/678296), 81.06 MiB | 5.74 MiB/s, done.
Resolving deltas: 100% (472342/472342), done.
remote: Enumerating objects: 28, done.
remote: Counting objects: 100% (28/28), done.
remote: Compressing objects: 100% (25/25), done.
remote: Total 28 (delta 0), reused 12 (delta 0), pack-reused 0
Receiving objects: 100% (28/28), 140.29 KiB | 341.00 KiB/s, done.
Updating files: 100% (28/28), done.

$ cd www-gitlab-com

$ git sparse-checkout set data --cone
remote: Enumerating objects: 301, done.
remote: Counting objects: 100% (301/301), done.
remote: Compressing objects: 100% (292/292), done.
remote: Total 301 (delta 16), reused 102 (delta 9), pack-reused 0
Receiving objects: 100% (301/301), 1.15 MiB | 608.00 KiB/s, done.
Resolving deltas: 100% (16/16), done.
Updating files: 100% (302/302), done.
```

Pour plus de détails, consultez la documentation Git pour [`sparse-checkout`](https://git-scm.com/docs/git-sparse-checkout).

### Filtrer par chemin de fichier {#filter-by-file-path}

Une intégration plus poussée entre le clone partiel et le sparse checkout est possible grâce au filtre spec `--filter=sparse:oid=<blob-ish>`. Ce mode de filtrage utilise un format similaire à un fichier `.gitignore` pour spécifier les fichiers à inclure lors du clonage et de la récupération.

> [!warning]
> Le clone partiel utilisant des filtres `sparse` est encore expérimental. Il peut être lent et augmenter considérablement l'utilisation des ressources de [Gitaly](../../administration/gitaly/_index.md) lors du clonage et de la récupération. [Filtrez tous les blobs et utilisez sparse-checkout](#filter-by-object-type) à la place, car [`git-sparse-checkout`](https://git-scm.com/docs/git-sparse-checkout) simplifie ce type d'utilisation du clone partiel et en surmonte les limitations.

Pour plus de détails, consultez la documentation Git pour [`rev-list-options`](https://git-scm.com/docs/git-rev-list#Documentation/git-rev-list.txt---filterltfilter-specgt).

1. Créez un filtre spec. Par exemple, considérez un dépôt monolithique contenant de nombreuses applications, chacune dans un sous-répertoire différent à la racine. Créez un fichier `shiny-app/.filterspec` :

   ```plaintext
   # Only the paths listed in the file will be downloaded when performing a
   # partial clone using `--filter=sparse:oid=shiny-app/.gitfilterspec`

   # Explicitly include filterspec needed to configure sparse checkout with
   # git config --local core.sparsecheckout true
   # git show master:snazzy-app/.gitfilterspec >> .git/info/sparse-checkout
   shiny-app/.gitfilterspec

   # Shiny App
   shiny-app/

   # Dependencies
   shimmery-app/
   shared-component-a/
   shared-component-b/
   ```

1. Clonez et filtrez par chemin. La prise en charge de `--filter=sparse:oid` à l'aide de la commande clone n'est pas entièrement intégrée au sparse checkout.

   ```shell
   # Clone the filtered set of objects using the filterspec stored on the
   # server. WARNING: this step may be very slow!
   git clone --sparse --filter=sparse:oid=master:shiny-app/.gitfilterspec <url>

   # Optional: Check for missing objects that have not been fetched
   git rev-list --all --quiet --objects --missing=print | wc -l
   ```

   > [!warning]
   > Les intégrations Git avec `bash`, Zsh, etc. et les éditeurs qui affichent automatiquement les informations de statut Git exécutent souvent `git fetch`, ce qui récupère l'intégralité du dépôt. Il peut être nécessaire de désactiver ou de reconfigurer ces intégrations.

### Supprimer le filtrage du clone partiel {#remove-partial-clone-filtering}

Il est possible de supprimer le filtrage des dépôts Git avec filtrage de clone partiel. Pour supprimer le filtrage :

1. Récupérez tout ce qui a été exclu par les filtres, afin de vous assurer que le dépôt est complet. Si `git sparse-checkout` a été utilisé, utilisez `git sparse-checkout disable` pour le désactiver. Consultez la [documentation sur `disable`](https://git-scm.com/docs/git-sparse-checkout#Documentation/git-sparse-checkout.txt-emdisableem) pour plus d'informations.

   Effectuez ensuite un `fetch` standard pour vous assurer que le dépôt est complet. Pour vérifier s'il manque des objets à récupérer, puis les récupérer, notamment lorsque `git sparse-checkout` n'est pas utilisé, les commandes suivantes peuvent être employées :

   ```shell
   # Show missing objects
   git rev-list --objects --all --missing=print | grep -e '^\?'

   # Show missing objects without a '?' character before them (needs GNU grep)
   git rev-list --objects --all --missing=print | grep -oP '^\?\K\w+'

   # Fetch missing objects
   git fetch origin $(git rev-list --objects --all --missing=print | grep -oP '^\?\K\w+')

   # Show number of missing objects
   git rev-list --objects --all --missing=print | grep -e '^\?' | wc -l
   ```

1. Repackagez tout. Cela peut être effectué à l'aide de `git repack -a -d`, par exemple. Cela ne devrait laisser que trois fichiers dans `.git/objects/pack/` :
   - Un fichier `pack-<SHA1>.pack`.
   - Son fichier `pack-<SHA1>.idx` correspondant.
   - Un fichier `pack-<SHA1>.promisor`.

1. Supprimez le fichier `.promisor`. L'étape précédente n'aurait dû laisser qu'un seul fichier `pack-<SHA1>.promisor`, qui doit être vide et doit être supprimé.
1. Supprimez la configuration du clone partiel. Les variables de configuration liées au clone partiel doivent être supprimées des fichiers de configuration Git. Généralement, seule la configuration suivante doit être supprimée :
   - `remote.origin.promisor`.
   - `remote.origin.partialclonefilter`.
