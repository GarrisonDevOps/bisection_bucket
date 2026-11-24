---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Créer un projet avec `git push`
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez utiliser `git push` pour ajouter un dépôt de projet local à GitLab. Après avoir ajouté un dépôt, GitLab crée votre projet dans l'espace de nommage de votre choix.

> [!note]
> Vous ne pouvez pas utiliser `git push` pour créer des projets avec des chemins qui ont déjà été utilisés ou [renommés](../../user/project/working_with_projects.md#rename-a-repository). Les chemins de projet précédemment utilisés font l'objet d'une redirection. Au lieu de créer un nouveau projet, la redirection entraîne la redirection des tentatives de push vers l'emplacement du projet renommé. Pour créer un nouveau projet pour un projet précédemment utilisé ou renommé, utilisez l'interface utilisateur ou l'[API Projects](../../api/projects.md#create-a-project).

Prérequis :

<!--- To push with SSH, you must have [an SSH key](../ssh.md) that is
  [added to your GitLab account](../ssh.md#add-an-ssh-key-to-your-gitlab-account).
-->
- Vous devez disposer de l'autorisation d'ajouter de nouveaux projets à un [espace de nommage](../../user/namespace/_index.md). Pour vérifier vos autorisations :

  1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
  1. Dans le coin supérieur droit, confirmez que **Nouveau projet** est visible.

  Si vous ne disposez pas des autorisations nécessaires, contactez votre administrateur GitLab.

Pour créer un projet avec `git push` :

1. Effectuez un push de votre dépôt local vers GitLab à l'aide de l'une des méthodes suivantes :

   - Avec SSH :

     - Si votre projet utilise le port standard 22, exécutez :

       ```shell
       git push --set-upstream git@gitlab.example.com:namespace/myproject.git main
       ```

     - Si votre projet nécessite un numéro de port non standard, exécutez :

       ```shell
       git push --set-upstream ssh://git@gitlab.example.com:00/namespace/myproject.git main
       ```

   - Avec HTTP, exécutez :

     ```shell
     git push --set-upstream https://gitlab.example.com/namespace/myproject.git master
     ```

     Remplacez les valeurs suivantes :

     - `gitlab.example.com` par le nom de domaine de la machine qui héberge votre dépôt Git.
     - `namespace` par le nom de votre [espace de nommage](../../user/namespace/_index.md).
     - `myproject` par le nom de votre projet.
     - Si vous spécifiez un port, remplacez `00` par le numéro de port requis pour votre projet.
     - Facultatif. Pour exporter les tags du dépôt existant, ajoutez l'indicateur `--tags` à votre commande `git push`.

1. Facultatif. Configurez le remote :

   ```shell
   git remote add origin https://gitlab.example.com/namespace/myproject.git
   ```

Lorsque l'opération `git push` est terminée, GitLab affiche le message suivant :

```shell
remote: The private project namespace/myproject was created.
```

Pour afficher votre nouveau projet, accédez à `https://gitlab.example.com/namespace/myproject`. Par défaut, la visibilité de votre projet est définie sur **Privé**, mais vous pouvez [modifier la visibilité du projet](../../user/public_access.md#change-project-visibility).

## Sujets connexes {#related-topics}

- [Créer un projet vide](../../user/project/_index.md)
- [Créer un projet à partir d'un modèle](../../user/project/_index.md#create-a-project-from-a-built-in-template)
- [Cloner un dépôt sur votre machine locale](clone.md)
