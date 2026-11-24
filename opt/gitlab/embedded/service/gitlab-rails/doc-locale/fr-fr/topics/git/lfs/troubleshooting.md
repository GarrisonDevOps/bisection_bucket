---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Dépannage de Git LFS
---

Lorsque vous travaillez avec Git LFS, vous pouvez rencontrer les problèmes suivants.

- L'API Git LFS originale v1 n'est pas prise en charge.
- Les requêtes Git LFS utilisent des identifiants HTTPS, ce qui signifie que vous devez utiliser un [magasin d'identifiants](https://git-scm.com/book/en/v2/Git-Tools-Credential-Storage) Git.
- Les [wikis de groupe](../../../user/project/wiki/group.md) ne prennent pas en charge Git LFS.

## Erreur : dépôt ou objet introuvable {#error-repository-or-object-not-found}

Cette erreur peut se produire pour plusieurs raisons, notamment :

- Vous ne disposez pas des autorisations nécessaires pour accéder à un certain objet LFS. Vérifiez que vous avez l'autorisation d'effectuer un push vers le projet ou un fetch depuis le projet.
- Le projet n'est pas autorisé à accéder à l'objet LFS. L'objet LFS que vous souhaitez envoyer (ou récupérer) n'est plus disponible pour le projet. Dans la plupart des cas, l'objet a été supprimé du serveur.
- Le dépôt Git local utilise une version obsolète de l'API Git LFS. Mettez à jour votre copie locale de Git LFS et réessayez.

## Statut invalide pour `<url>` : 501 {#invalid-status-for-url--501}

Git LFS enregistre les échecs dans un fichier de log. Pour afficher ce fichier de log :

1. Dans votre fenêtre de terminal, accédez au répertoire de votre projet.
1. Exécutez cette commande pour afficher les fichiers de log récents :

   ```shell
   git lfs logs last
   ```

Ces problèmes peuvent provoquer des erreurs `501` :

- Git LFS n'est pas activé dans les paramètres de votre projet. Vérifiez les paramètres de votre projet et activez Git LFS.
- La prise en charge de Git LFS n'est pas activée sur le serveur GitLab. Vérifiez auprès de votre administrateur GitLab pourquoi Git LFS n'est pas activé sur le serveur. Consultez la [documentation d'administration LFS](../../../administration/lfs/_index.md) pour obtenir des instructions sur l'activation de la prise en charge de Git LFS.
- La version du client Git LFS n'est pas prise en charge par le serveur GitLab. Vous devez :
  1. Vérifiez votre version de Git LFS avec `git lfs version`.
  1. Vérifiez la configuration Git de votre projet pour détecter des traces de l'API obsolète avec `git lfs -l`. Si votre configuration définit `batch = false`, supprimez la ligne, puis mettez à jour votre client Git LFS. GitLab prend uniquement en charge les versions 1.0.1 et ultérieures.

## Les identifiants sont toujours requis lors d'un push d'un objet {#credentials-are-always-required-when-pushing-an-object}

Git LFS authentifie l'utilisateur avec l'authentification HTTP Basic à chaque push pour chaque objet, ce qui nécessite des identifiants HTTPS. Par défaut, Git prend en charge la mémorisation des identifiants pour chaque dépôt que vous utilisez. Pour plus d'informations, consultez la [documentation officielle de Git](https://git-scm.com/docs/gitcredentials).

Par exemple, vous pouvez demander à Git de mémoriser votre mot de passe pendant une période durant laquelle vous prévoyez d'effectuer des pushs d'objets. Cet exemple mémorise vos identifiants pendant une heure (3 600 secondes), et vous devrez vous authentifier à nouveau au bout d'une heure :

```shell
git config --global credential.helper 'cache --timeout=3600'
```

Pour stocker et chiffrer les identifiants, consultez :

- MacOS : utilisez `osxkeychain`.
- Windows : utilisez `wincred` ou le [Git Credential Manager for Windows](https://github.com/Microsoft/Git-Credential-Manager-for-Windows/releases) de Microsoft.

Pour en savoir plus sur le stockage de vos identifiants, consultez la [documentation Git Credential Storage](https://git-scm.com/book/en/v2/Git-Tools-Credential-Storage).

## Des objets LFS manquent lors d'un push {#lfs-objects-are-missing-on-push}

GitLab vérifie les fichiers lors d'un push pour détecter les pointeurs LFS. S'il détecte des pointeurs LFS, GitLab tente de vérifier que ces fichiers existent déjà dans LFS. Si vous utilisez un serveur distinct pour Git LFS et que vous rencontrez ce problème :

1. Vérifiez que Git LFS est installé localement.
1. Envisagez un push manuel avec `git lfs push --all`.

Si vous stockez des fichiers Git LFS en dehors de GitLab, vous pouvez [désactiver Git LFS](_index.md#enable-or-disable-git-lfs-for-a-project) sur votre projet.

## Hébergement d'objets LFS en externe {#hosting-lfs-objects-externally}

Vous pouvez héberger des objets LFS en externe en définissant une URL LFS personnalisée :

```shell
git config -f .lfsconfig lfs.url https://example.com/<project>.git/info/lfs
```

Vous pourriez faire cela si vous stockez des données LFS sur un appliance, comme un Nexus Repository. Si vous utilisez un magasin LFS externe, GitLab ne peut pas vérifier les objets LFS. Les pushs échouent alors si la prise en charge de GitLab LFS est activée.

Pour éviter les échecs de push, vous pouvez désactiver la prise en charge de Git LFS dans les [paramètres de votre projet](_index.md#enable-or-disable-git-lfs-for-a-project). Cependant, cette approche peut ne pas être souhaitable, car elle désactive également les fonctionnalités GitLab LFS telles que :

- La vérification des objets LFS.
- L'intégration de l'interface GitLab pour LFS.

## Délai d'expiration E/S lors d'un push d'objets LFS {#io-timeout-when-pushing-lfs-objects}

Si vos conditions réseau sont instables, le client Git LFS peut expirer lors de la tentative d'envoi de fichiers. Vous pouvez rencontrer des erreurs telles que :

```shell
LFS: Put "http://example.com/root/project.git/gitlab-lfs/objects/<OBJECT-ID>/15":
read tcp your-instance-ip:54544->your-instance-ip:443: i/o timeout
error: failed to push some refs to 'ssh://example.com:2222/root/project.git'
```

Pour résoudre ce problème, définissez le délai d'expiration d'activité du client sur une valeur plus élevée. Par exemple, pour définir le délai d'expiration à 60 secondes :

```shell
git config lfs.activitytimeout 60
```

## Détection de `n` fichiers devant être des pointeurs, mais qui ne l'étaient pas {#encountered-n-files-that-should-have-been-pointers-but-werent}

Cette erreur indique que le dépôt devrait suivre un fichier avec Git LFS, mais ne le fait pas.

Pour résoudre le problème, migrez les fichiers concernés et envoyez-les dans le dépôt :

1. Migrez le fichier vers LFS :

   ```shell
   git lfs migrate import --yes --no-rewrite "<your-file>"
   ```

1. Effectuez un push vers votre dépôt :

   ```shell
   git push
   ```

1. Facultatif. Nettoyez votre dossier `.git` :

   ```shell
   git reflog expire --expire-unreachable=now --all
   git gc --prune=now
   ```

## Les objets LFS ne sont pas extraits automatiquement {#lfs-objects-not-checked-out-automatically}

Vous pouvez rencontrer un problème où les objets Git LFS ne sont pas extraits automatiquement. Lorsque cela se produit, les fichiers existent mais contiennent des références de pointeurs au lieu du contenu réel. Si vous ouvrez ces fichiers, au lieu d'afficher le contenu attendu, vous pouvez voir un pointeur LFS qui ressemble à ceci :

```plaintext
version https://git-lfs.github.com/spec/v1
oid sha256:d276d250bc645e27a1b0ab82f7baeb01f7148df7e4816c4b333de12d580caa29
size 2323563
```

Ce problème se produit lorsque les noms de fichiers ne correspondent à aucune règle dans le fichier `.gitattributes`. Les fichiers LFS ne sont extraits automatiquement que lorsqu'ils correspondent à une règle dans `.gitattributes`.

Dans `git-lfs` v3.6.0, ce comportement a changé et [la correspondance des fichiers LFS a été optimisée](https://github.com/git-lfs/git-lfs/pull/5699).

GitLab Runner v17.7.0 a mis à niveau l'image d'aide par défaut pour utiliser `git-lfs` v3.6.0.

Pour un comportement cohérent sur différents systèmes d'exploitation avec des sensibilités à la casse différentes, ajustez votre fichier `.gitattributes` pour correspondre à différents modèles de capitalisation.

Par exemple, si vous avez des fichiers LFS nommés `image.jpg` et `wombat.JPG`, utilisez des expressions régulières insensibles à la casse dans votre fichier `.gitattributes` :

```plaintext
*.[jJ][pP][gG] filter=lfs diff=lfs merge=lfs -text
*.[jJ][pP][eE][gG] filter=lfs diff=lfs merge=lfs -text
```

Si vous travaillez exclusivement sur des systèmes de fichiers sensibles à la casse, comme la plupart des distributions Linux, vous pouvez utiliser des modèles plus simples. Par exemple :

```plaintext
*.jpg filter=lfs diff=lfs merge=lfs -text
*.jpeg filter=lfs diff=lfs merge=lfs -text
```

## Attention : problème de configuration LFS possible {#warning-possible-lfs-configuration-issue}

Vous pouvez voir un avertissement dans l'interface GitLab indiquant :

```plaintext
Possible LFS configuration issue. This project contains LFS objects but there is no .gitattributes file.
You can ignore this message if you recently added a .gitattributes file.
```

Cet avertissement se produit lorsque Git LFS est activé et contient des objets LFS, mais qu'aucun fichier `.gitattributes` n'est détecté dans le répertoire racine de votre projet. Git prend en charge le placement des fichiers `.gitattributes` dans des sous-répertoires, mais GitLab vérifie uniquement ce fichier dans le répertoire racine.

La solution de contournement consiste à créer un fichier `.gitattributes` vide dans le répertoire racine :

{{< tabs >}}

{{< tab title="With Git" >}}

1. Clonez votre dépôt :

   ```shell
   git clone <repository>
   cd repository
   ```

1. Créez un fichier `.gitattributes` vide :

   ```shell
   touch .gitattributes
   git add .gitattributes
   git commit -m "Add empty .gitattributes file to root directory"
   git push
   ```

{{< /tab >}}

{{< tab title="In the UI" >}}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Sélectionnez l'icône plus (**+**) et **Nouveau fichier**.
1. Dans le champ **Nom du fichier**, saisissez `.gitattributes`.
1. Sélectionnez **Valider les modifications**.
1. Dans le champ **Message de commit**, saisissez un message de commit.
1. Sélectionnez **Valider les modifications**.

{{< /tab >}}

{{< /tabs >}}
