---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 'Tutoriel : mettre à jour les messages de commit Git'
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Parfois, après avoir effectué quelques commits sur votre branche, vous réalisez que vous devez mettre à jour un ou plusieurs messages de commit. Peut-être avez-vous trouvé une faute de frappe, ou une automatisation vous a averti que votre message de commit n'était pas totalement conforme aux [directives de message de commit](../../topics/git/commit.md#write-a-good-commit-message) d'un projet.

La mise à jour du message peut s'avérer délicate si vous n'avez pas beaucoup d'expérience avec Git via l'interface de ligne de commande (CLI). Mais ne vous inquiétez pas : même si vous avez toujours travaillé dans l'interface utilisateur GitLab, vous pouvez suivre ces étapes pour utiliser la CLI.

Ce tutoriel explique comment réécrire des messages de commit. Si vous travaillez uniquement dans l'interface utilisateur GitLab, commencez depuis le début. Si votre dépôt est déjà cloné localement, vous pouvez passer directement à l'étape consistant à récupérer et extraire votre branche.

## Avant de commencer {#before-you-begin}

Vous devez disposer :

- D'un projet GitLab avec une branche Git contenant des commits que vous souhaitez mettre à jour.
- De Git [installé sur votre machine locale](../../topics/git/how_to_install_git/_index.md).
- D'un accès à l'interface de ligne de commande (CLI) de votre machine locale. Sous macOS, vous pouvez utiliser Terminal. Sous Windows, vous pouvez utiliser PowerShell. Les utilisateurs Linux sont probablement déjà familiarisés avec la CLI de leur système.
- D'une connaissance de l'éditeur par défaut de votre système. Ce tutoriel suppose que votre éditeur est Vim, mais tout éditeur de texte devrait fonctionner. Si vous n'êtes pas familiarisé avec Vim, les étapes 1 et 2 de [Prise en main de Vim](https://opensource.com/article/19/3/getting-started-vim) expliquent toutes les commandes utilisées plus loin dans ce tutoriel.
- De l'autorisation de remplacer les messages de commit. Si vous travaillez avec plusieurs personnes sur la même branche, vous devez d'abord vérifier avec elles qu'il est acceptable de mettre à jour les commits. Certaines organisations peuvent avoir des règles interdisant la réécriture de commits, car elle est considérée comme une modification destructive.

Vous devez vous authentifier auprès de GitLab pour remplacer les messages de commit à la dernière étape. Si votre compte GitLab utilise l'authentification de base par nom d'utilisateur et mot de passe, vous devez avoir l'[authentification à deux facteurs (2FA)](../../user/profile/account/two_factor_authentication.md) désactivée pour vous authentifier depuis la CLI. Vous pouvez également [utiliser une clé SSH pour vous authentifier auprès de GitLab](../../user/ssh.md).

## Cloner votre dépôt sur votre machine locale {#clone-your-repository-to-your-local-machine}

Pour commencer, créez une copie locale de votre dépôt sur votre machine.

{{< guide >}}

1. Copiez l'URL du dépôt.

   Dans GitLab, sur la page de présentation de votre projet, dans le coin supérieur droit, sélectionnez **Code**. Dans la liste déroulante, copiez l'URL de votre dépôt en sélectionnant {{< icon name="copy-to-clipboard" >}} à côté de :

   - **Cloner avec HTTPS** si votre compte GitLab utilise l'authentification de base par nom d'utilisateur et mot de passe.
   - **Cloner avec SSH** si vous utilisez SSH pour vous authentifier auprès de GitLab.

1. Clonez le dépôt.

   Passez à la CLI (Terminal, PowerShell ou équivalent) sur votre machine locale, et accédez au répertoire dans lequel vous souhaitez cloner le dépôt. Par exemple, `/users/my-username/my-projects/`. Exécutez `git clone` et collez l'URL que vous avez copiée précédemment :

   ```shell
   git clone https://gitlab.com/my-username/my-awesome-project.git
   ```

   Cette commande clone le dépôt dans un nouveau répertoire appelé `my-awesome-project/`.

{{< /guide >}}

Votre dépôt est maintenant sur votre ordinateur, prêt pour vos commandes Git CLI.

## Récupérer et extraire votre branche {#fetch-and-check-out-your-branch}

Ensuite, basculez vers la branche qui contient les commits que vous souhaitez mettre à jour.

{{< guide >}}

1. Accédez au répertoire de votre projet.

   En supposant que vous vous trouvez toujours au même emplacement dans la CLI qu'à l'étape précédente, accédez au répertoire de votre projet avec `cd` :

   ```shell
   cd my-awesome-project
   ```

1. Récupérez votre branche si nécessaire.

   Si vous venez de cloner le dépôt, votre branche devrait déjà être présente sur votre ordinateur. Cependant, si vous avez précédemment cloné le dépôt et avez sauté jusqu'à cette étape, vous devrez peut-être récupérer votre branche :

   ```shell
   git fetch origin my-branch-name
   ```

1. Extrayez la branche.

   Maintenant que la branche est sur votre système local, basculez vers elle :

   ```shell
   git checkout my-branch-name
   ```

1. Vérifiez que vous êtes sur la bonne branche.

   Exécutez `git log` et vérifiez que les commits les plus récents correspondent aux commits de votre branche sur GitLab. Pour quitter le journal, utilisez `q`.

{{< /guide >}}

## Mettre à jour les messages de commit {#update-the-commit-messages}

Vous êtes maintenant prêt à réécrire les messages de commit à l'aide d'un rebase interactif.

{{< guide >}}

1. Déterminez le nombre de commits à mettre à jour.

   Dans GitLab, vérifiez jusqu'où dans l'historique des commits vous devez remonter :

   - Si vous avez déjà une merge request ouverte pour votre branche, vous pouvez consulter l'onglet **Validation** et utiliser le nombre total de commits.
   - Si vous travaillez uniquement depuis une branche :
     1. Accédez à **Code** > **Validation**.
     1. Sélectionnez la liste déroulante en haut à gauche et trouvez votre branche.
     1. Trouvez le commit le plus ancien que vous souhaitez mettre à jour et comptez jusqu'à quel point ce commit se trouve dans l'historique. Par exemple, si vous souhaitez mettre à jour le deuxième et le quatrième commit, le nombre serait 4.

1. Démarrez un rebase interactif.

   Depuis la CLI, lancez le processus de rebase en ajoutant le nombre de commits de l'étape précédente à la fin de `HEAD~` :

   ```shell
   git rebase -i HEAD~4
   ```

   Dans cet exemple, Git sélectionne les quatre commits les plus récents de la branche à mettre à jour.
1. Indiquez les commits à reformuler.

   Git lance un éditeur de texte et liste les commits sélectionnés. Par exemple, le résultat devrait ressembler à :

   ```shell
   pick a0cea50 Fix broken link
   pick bb84712 Update milestone-plan.md
   pick ce11fad Add list of maintainers
   pick d211d03 update template.md

   # Rebase 1f5ec88..d211d03 onto 1f5ec88 (4 commands)
   #
   # Commands:
   # p, pick <commit> = use commit
   # r, reword <commit> = use commit, but edit the commit message
   # e, edit <commit> = use commit, but stop for amending
   # s, squash <commit> = use commit, but meld into previous commit
   # f, fixup [-C | -c] <commit> = like "squash" but keep only the previous
   #                    commit's log message, unless -C is used, in which case
   # [and so on...]
   ```

   La commande `pick` indique à Git d'utiliser les commits sans modification. Remplacez la commande `pick` par `reword` pour les commits que vous souhaitez mettre à jour. Saisissez `i` pour passer en mode `INSERT`, puis commencez à modifier le texte.

   Par exemple, pour mettre à jour le texte des deuxième et quatrième commits de l'exemple précédent, modifiez-le pour qu'il ressemble à :

   ```shell
   pick a0cea50 Fix broken link
   reword bb84712 Update milestone-plan.md
   pick ce11fad Add list of maintainers
   reword d211d03 update template.md
   ```

1. Enregistrez vos modifications.

   Appuyez sur <kbd>Escape</kbd> pour quitter le mode `INSERT`, puis saisissez `:wq` et appuyez sur <kbd>Enter</kbd> pour enregistrer et quitter.
1. Mettez à jour chaque message de commit.

   Git traite maintenant chaque commit un par un. Les commits avec `pick` sont rajoutés à la branche sans modification. Lorsque Git atteint un commit avec `reword`, il s'arrête et rouvre l'éditeur de texte.

   Mettez à jour le message de commit selon vos besoins :

   - Pour un message de commit sur une seule ligne, mettez à jour le texte. Par exemple :

   ```plaintext
   Update the monthly milestone plan
   ```

   - Pour un message de commit avec un titre et un corps, séparez-les par une ligne vide. Par exemple :

   ```plaintext
   Update the monthly milestone plan

   Make the milestone plan clearer by listing the responsibilities
   of each maintainer.
   ```

   Après avoir enregistré et quitté, Git met à jour le message de commit et traite les commits suivants dans l'ordre. Vous devriez voir le message `Successfully rebased and update refs/heads/my-branch-name` une fois terminé.

1. Vérifiez les mises à jour.

   Pour confirmer que les messages de commit ont été mis à jour, exécutez `git log` et faites défiler vers le bas pour voir les messages de commit.

{{< /guide >}}

## Envoyer les modifications vers GitLab {#push-the-changes-to-gitlab}

Enfin, envoyez vos commits mis à jour vers GitLab.

{{< guide >}}

1. Effectuez un push forcé des modifications.

   Depuis la CLI, envoyez les modifications vers GitLab. Vous devez utiliser l'option `-f` « force push », car les commits ont été mis à jour et un push forcé remplace les anciens commits dans GitLab :

   ```shell
   git push -f origin
   ```

   Votre terminal peut vous demander votre nom d'utilisateur et votre mot de passe avant de remplacer les messages de commit dans GitLab.
1. Vérifiez les modifications dans GitLab.

   Dans votre projet dans GitLab, confirmez que les commits ont été mis à jour :

   - Si vous avez déjà une merge request ouverte pour votre branche, consultez l'onglet **Validation**.
   - Si vous travaillez uniquement depuis une branche :
     1. Accédez à **Code** > **Validation**.
     1. Sélectionnez la liste déroulante en haut à gauche et trouvez votre branche.
     1. Vérifiez que les commits concernés dans la liste sont maintenant mis à jour.

{{< /guide >}}

Félicitations, vous avez mis à jour avec succès vos messages de commit et les avez envoyés vers GitLab !
