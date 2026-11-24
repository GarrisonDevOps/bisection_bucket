---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Commandes et workflows courants.
title: Gestion des fichiers
---

Git fournit des fonctionnalités de gestion de fichiers qui vous aident à suivre les modifications, à collaborer avec d'autres personnes et à gérer efficacement les fichiers volumineux.

## Historique des fichiers {#file-history}

Utilisez `git log` pour consulter l'historique complet d'un fichier et comprendre comment il a évolué au fil du temps. L'historique des fichiers vous indique :

- L'auteur de chaque modification.
- La date et l'heure de chaque modification.
- Les changements spécifiques effectués dans chaque commit.

Par exemple, pour consulter les informations `history` sur le fichier `CONTRIBUTING.md` à la racine du dépôt `gitlab`, exécutez :

```shell
git log CONTRIBUTING.md
```

Exemple de résultat :

```shell
commit b350bf041666964c27834885e4590d90ad0bfe90
Author: Nick Malcolm <nmalcolm@gitlab.com>
Date:   Fri Dec 8 13:43:07 2023 +1300

    Update security contact and vulnerability disclosure info

commit 8e4c7f26317ff4689610bf9d031b4931aef54086
Author: Brett Walker <bwalker@gitlab.com>
Date:   Fri Oct 20 17:53:25 2023 +0000

    Fix link to Code of Conduct

    and condense some of the verbiage
```

## Vérifier les modifications précédentes apportées à un fichier {#check-previous-changes-to-a-file}

Utilisez `git blame` pour voir qui a effectué la dernière modification sur un fichier et quand. Cela permet de comprendre le contexte du contenu d'un fichier, de résoudre les conflits et d'identifier la personne responsable d'une modification spécifique.

Si vous souhaitez trouver des informations `blame` sur un fichier `README.md` dans le répertoire local :

1. Ouvrez un terminal ou une invite de commande.
1. Accédez à votre dépôt Git.
1. Exécutez la commande suivante :

   ```shell
   git blame README.md
   ```

1. Pour naviguer dans la page de résultats, appuyez sur <kbd>Espace</kbd>.
1. Pour quitter les résultats, appuyez sur <kbd>Q</kbd>.

Cette sortie affiche le contenu du fichier avec des annotations indiquant le SHA du commit, l'auteur et la date pour chaque ligne. Par exemple :

```shell
58233c4f1054c (Dan Rhodes           2022-05-13 07:02:20 +0000  1) ## Contributor License Agreement
b87768f435185 (Jamie Hurewitz       2017-10-31 18:09:23 +0000  2)
8e4c7f26317ff (Brett Walker         2023-10-20 17:53:25 +0000  3) Contributions to this repository are subject to the
58233c4f1054c (Dan Rhodes           2022-05-13 07:02:20 +0000  4)
```

## Git LFS {#git-lfs}

Git Large File Storage (LFS) est une extension qui vous aide à gérer les fichiers volumineux dans les dépôts Git. Elle remplace les fichiers volumineux par des pointeurs texte dans Git et stocke le contenu des fichiers sur un serveur distant.

Prérequis :

- Téléchargez et installez la version appropriée de l'[extension CLI pour Git LFS](https://git-lfs.com) pour votre système d'exploitation.
- [Configurez votre projet pour utiliser Git LFS](lfs/_index.md).
- Installez le hook pre-push de Git LFS. Pour ce faire, exécutez `git lfs install` dans le répertoire racine de votre dépôt.

### Ajouter et suivre des fichiers {#add-and-track-files}

Pour ajouter un fichier volumineux dans votre dépôt Git et le suivre avec Git LFS :

1. Configurez le suivi pour tous les fichiers d'un certain type. Remplacez `iso` par le type de fichier souhaité :

   ```shell
   git lfs track "*.iso"
   ```

   Cette commande crée un fichier `.gitattributes` avec des instructions pour gérer tous les fichiers ISO avec Git LFS. La ligne suivante est ajoutée à votre fichier `.gitattributes` :

   ```plaintext
   *.iso filter=lfs -text
   ```

1. Ajoutez un fichier de ce type, `.iso`, à votre dépôt.
1. Suivez les modifications apportées au fichier `.gitattributes` et au fichier `.iso` :

   ```shell
   git add .
   ```

1. Vérifiez que vous avez ajouté les deux fichiers :

   ```shell
   git status
   ```

   Le fichier `.gitattributes` doit être inclus dans votre commit. S'il n'est pas inclus, Git ne suit pas le fichier ISO avec Git LFS.

   > [!note]
   > Vérifiez que les fichiers que vous modifiez ne sont pas répertoriés dans un fichier `.gitignore`. Si c'est le cas, Git valide la modification localement mais ne la pousse pas vers votre dépôt en amont.
1. Validez les deux fichiers dans votre copie locale du dépôt :

   ```shell
   git commit -m "Add an ISO file and .gitattributes"
   ```

1. Poussez vos modifications en amont. Remplacez `main` par le nom de votre branche :

   ```shell
   git push origin main
   ```

1. Créez une merge request.

> [!note]
> Lorsque vous ajoutez un nouveau type de fichier au suivi Git LFS, les fichiers existants de ce type ne sont pas convertis vers Git LFS. Seuls les fichiers de ce type ajoutés après le début du suivi sont ajoutés à Git LFS. Utilisez `git lfs migrate` pour convertir les fichiers existants afin qu'ils utilisent Git LFS.

### Arrêter le suivi d'un fichier {#stop-tracking-a-file}

Lorsque vous arrêtez le suivi d'un fichier avec Git LFS, le fichier reste sur le disque car il fait toujours partie de l'historique de votre dépôt.

Pour arrêter le suivi d'un fichier avec Git LFS :

1. Exécutez la commande `git lfs untrack` et indiquez le chemin d'accès au fichier :

   ```shell
   git lfs untrack doc/example.iso
   ```

1. Utilisez la commande `touch` pour le reconvertir en fichier standard :

   ```shell
   touch doc/example.iso
   ```

1. Suivez les modifications apportées au fichier :

   ```shell
   git add .
   ```

1. Validez et poussez vos modifications.
1. Créez une merge request et demandez une révision.
1. Fusionnez la merge request dans la branche cible.

> [!note]
> Si vous supprimez un objet suivi par Git LFS sans l'avoir retiré du suivi avec `git lfs untrack`, l'objet apparaît comme `modified` dans `git status`.

### Arrêter le suivi de tous les fichiers d'un seul type {#stop-tracking-all-files-of-a-single-type}

Pour arrêter le suivi de tous les fichiers d'un type particulier dans Git LFS :

1. Exécutez la commande `git lfs untrack` et indiquez le type de fichier dont vous souhaitez arrêter le suivi :

   ```shell
   git lfs untrack "*.iso"
   ```

1. Utilisez la commande `touch` pour reconvertir les fichiers en fichiers standard :

   ```shell
   touch *.iso
   ```

1. Suivez les modifications apportées aux fichiers :

   ```shell
   git add .
   ```

1. Validez et poussez vos modifications.
1. Créez une merge request et demandez une révision.
1. Fusionnez la merge request dans la branche cible.

## Verrous de fichiers exclusifs {#exclusive-file-locks}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les verrous de fichiers exclusifs aident à prévenir les conflits et garantissent qu'une seule personne peut modifier un fichier à la fois. C'est une bonne option pour :

- Les fichiers binaires qui ne peuvent pas être fusionnés. Par exemple, les fichiers de conception et les vidéos.
- Les fichiers nécessitant un accès exclusif lors de la modification.

Les verrous de fichiers exclusifs s'appliquent à toutes les branches d'un dépôt. Si vous devez verrouiller des fichiers uniquement sur la branche par défaut, utilisez plutôt les [verrous de fichiers et de répertoires de la branche par défaut](../../user/project/file_lock.md#default-branch-file-and-directory-locks).

Prérequis :

- Vous devez avoir [Git LFS installé](lfs/_index.md).
- Vous devez avoir le rôle Chargé de maintenance pour le projet.

### Configurer les verrous de fichiers {#configure-file-locks}

Pour configurer les verrous de fichiers pour un type de fichier spécifique :

1. Utilisez la commande `git lfs track` avec l'option `--lockable`. Par exemple, pour configurer les fichiers PNG :

   ```shell
   git lfs track "*.png" --lockable
   ```

   Cette commande crée ou met à jour votre fichier `.gitattributes` avec le contenu suivant :

    ```plaintext
    *.png filter=lfs diff=lfs merge=lfs -text lockable
    ```

1. Poussez le fichier `.gitattributes` vers le dépôt distant pour que les modifications prennent effet.

> [!note]
> Une fois qu'un type de fichier est enregistré comme verrouillable, il est automatiquement marqué comme étant en lecture seule.

#### Configurer les verrous de fichiers sans LFS {#configure-file-locks-without-lfs}

Pour enregistrer un type de fichier comme verrouillable sans utiliser Git LFS :

1. Modifiez manuellement le fichier `.gitattributes` :

   ```shell
   *.pdf lockable
   ```

1. Poussez le fichier `.gitattributes` vers le dépôt distant.

### Verrouiller et déverrouiller des fichiers {#lock-and-unlock-files}

Pour verrouiller ou déverrouiller un fichier avec le verrouillage exclusif de fichiers :

1. Ouvrez une fenêtre de terminal dans le répertoire de votre dépôt.
1. Exécutez l'une des commandes suivantes :

   {{< tabs >}}

   {{< tab title="Verrouiller un fichier" >}}

   ```shell
   git lfs lock path/to/file.png
   ```

   {{< /tab >}}

   {{< tab title="Déverrouiller un fichier" >}}

   ```shell
   git lfs unlock path/to/file.png
   ```

   {{< /tab >}}

   {{< tab title="Déverrouiller un fichier par ID" >}}

   ```shell
   git lfs unlock --id=123
   ```

   {{< /tab >}}

   {{< tab title="Forcer le déverrouillage d'un fichier" >}}

   ```shell
   git lfs unlock --id=123 --force
   ```

   {{< /tab >}}

   {{< /tabs >}}

### Afficher les fichiers verrouillés {#view-locked-files}

Pour afficher les fichiers verrouillés :

1. Ouvrez une fenêtre de terminal dans votre dépôt.
1. Exécutez la commande suivante :

   ```shell
   git lfs locks
   ```

   La sortie répertorie les fichiers verrouillés, les utilisateurs qui les ont verrouillés et les identifiants des fichiers.

Dans l'interface GitLab :

- L'arborescence des fichiers du dépôt affiche un badge LFS pour les fichiers suivis par Git LFS.
- Les fichiers verrouillés exclusivement affichent une icône de cadenas.

> [!note]
> Lorsque vous renommez un fichier verrouillé exclusivement, le verrou est perdu. Vous devez le verrouiller à nouveau pour qu'il reste verrouillé.

### Verrouiller et modifier un fichier {#lock-and-edit-a-file}

Pour verrouiller un fichier, le modifier et éventuellement le déverrouiller :

1. Verrouillez le fichier :

   ```shell
   git lfs lock <file_path>
   ```

1. Modifiez le fichier.
1. Facultatif. Déverrouillez le fichier lorsque vous avez terminé :

   ```shell
   git lfs unlock <file_path>
   ```

## Sujets connexes {#related-topics}

- [Gestion des fichiers avec l'interface utilisateur GitLab](../../user/project/repository/files/_index.md)
- [Documentation de Git Large File Storage (LFS)](lfs/_index.md)
- [Verrouillage de fichiers](../../user/project/file_lock.md)
