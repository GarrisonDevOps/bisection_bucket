---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Comment créer, cloner et utiliser des dépôts GitLab."
title: Dépôt
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Votre [dépôt](https://git-scm.com/book/en/v2/Git-Basics-Getting-a-Git-Repository) est un composant de votre projet GitLab. Vous stockez votre code dans votre dépôt et suivez les modifications apportées à celui-ci grâce au contrôle de version.

Chaque dépôt fait partie d'un [projet GitLab](../_index.md) et ne peut pas exister sans projet GitLab. Votre projet fournit les options de configuration de votre dépôt.

## créer un dépôt {#create-a-repository}

Pour créer un dépôt :

- [Créer un projet](../_index.md) ou
- [Dupliquer un projet existant](forking_workflow.md).

## Ajouter des fichiers à un dépôt {#add-files-to-a-repository}

Vous pouvez ajouter des fichiers à un dépôt :

- Lorsque vous [créez un projet](../_index.md), ou
- Après avoir créé un projet, en utilisant les options suivantes :
  - [Éditeur web](web_editor.md#upload-a-file).
  - [Interface utilisateur (UI)](#add-a-file-from-the-ui).
  - [Ligne de commande](../../../topics/git/add_files.md).

### Ajouter un fichier depuis l'interface utilisateur {#add-a-file-from-the-ui}

Pour ajouter ou téléverser un fichier depuis l'interface utilisateur GitLab :

<!-- Original source for this list: doc/user/project/repository/web_editor.md#upload-a-file -->
<!-- For why we duplicated the info, see <https://gitlab.com/gitlab-org/gitlab/-/merge_requests/111072#note_1267429478> -->

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez au répertoire dans lequel vous souhaitez téléverser le fichier.
1. À côté du nom du répertoire, sélectionnez l'icône plus ({{< icon name="plus" >}}) > **Téléverser un fichier**.
1. Déposez ou téléversez votre fichier.
1. Saisissez un message de commit.
1. Facultatif. Pour créer une merge request avec vos modifications, dans **Branche cible**, saisissez un nom de branche qui n'est pas la [branche par défaut](branches/default.md) de votre dépôt.
1. Sélectionnez **Téléverser un fichier**.

## Commiter des modifications dans un dépôt {#commit-changes-to-a-repository}

Vous pouvez commiter vos modifications dans une branche du dépôt. Lorsque vous utilisez la ligne de commande, utilisez [`git commit`](../../../topics/git/commands.md#git-commit).

Pour en savoir plus sur l'utilisation des commits pour améliorer la communication et la collaboration, déclencher ou ignorer des pipelines, et annuler des modifications, consultez [commits](../merge_requests/commits.md).

## Cloner un dépôt {#clone-a-repository}

Vous pouvez cloner un dépôt à l'aide des éléments suivants :

- Ligne de commande :
  - [Cloner avec SSH](../../../topics/git/clone.md#clone-with-ssh) : utilisez SSH si vous avez des clés SSH configurées et souhaitez vous authentifier sans saisir vos identifiants pour chaque opération.
  - [Cloner avec HTTPS](../../../topics/git/clone.md#clone-with-https) : utilisez HTTPS si vous préférez vous authentifier avec un jeton d'accès personnel ou si votre réseau bloque les connexions SSH.
- Interface GitLab :
  - [Cloner et ouvrir dans Apple Xcode](../../../topics/git/clone.md#clone-and-open-in-apple-xcode)
  - [Cloner et ouvrir dans Visual Studio Code](../../../topics/git/clone.md#clone-and-open-in-visual-studio-code)
  - [Cloner et ouvrir dans IntelliJ IDEA](../../../topics/git/clone.md#clone-and-open-in-intellij-idea)

## Télécharger le code source du dépôt {#download-repository-source-code}

Pour télécharger le code source d'un dépôt sous forme de fichier compressé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Au-dessus de la liste de fichiers, sélectionnez **Code**.
1. Dans les options, sélectionnez les fichiers que vous souhaitez télécharger :

   - **Code source** :

     Téléchargez le code source de la branche actuelle que vous consultez. Extensions disponibles : `zip`, `tar`, `tar.gz` et `tar.bz2`.

   - **Répertoire** :

     Téléchargez un répertoire spécifique. Visible uniquement lorsque vous consultez un sous-répertoire. Extensions disponibles : `zip`, `tar`, `tar.gz` et `tar.bz2`.

   - **Artéfacts** :

     Téléchargez les artéfacts du dernier job CI/CD.

Les sommes de contrôle des archives générées peuvent changer même si le dépôt lui-même ne change pas. Par exemple, cela se produit si Git ou une bibliothèque tierce utilisée par GitLab change.

> [!note]
> N'utilisez pas une somme de contrôle d'archive pour confirmer que deux téléchargements contiennent le même contenu de dépôt. Vérifiez plutôt le contenu à l'aide des [commits et tags signés](signed_commits/_index.md).

## Afficher le dépôt par révision Git {#view-repository-by-git-revision}

Pour afficher tous les fichiers et dossiers du dépôt à une révision Git donnée, par exemple un SHA de commit, un nom de branche ou un tag :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. En haut de la page, ouvrez la liste déroulante **Sélectionner une révision Git**.
1. Sélectionnez ou recherchez une révision Git.

Vous pouvez également afficher et parcourir les fichiers à une révision Git spécifique depuis la page [commits](commits/_index.md).

## Langages du dépôt {#repository-languages}

GitLab détecte les langages de programmation utilisés dans la branche par défaut. Ces informations sont affichées sur la page **Vue d'ensemble du projet**.

![Barre des langages du dépôt](img/repository_languages_v15_2.png)

Lorsque de nouveaux fichiers sont ajoutés, la mise à jour de ces informations peut prendre jusqu'à cinq minutes.

### Ajouter des langages au dépôt {#add-repository-languages}

Tous les fichiers ne sont pas détectés et listés sur la page **Vue d'ensemble du projet**. La documentation, le code des fournisseurs et [la plupart des langages de balisage](files/_index.md#supported-markup-languages) sont exclus. Pour consulter la liste des fichiers et langages pris en charge, voir [types de données pris en charge](https://github.com/github/linguist/blob/master/lib/linguist/languages.yml).

Pour modifier ce comportement et inclure des types de fichiers supplémentaires dans les paramètres par défaut :

1. Dans le répertoire racine de votre dépôt, créez un fichier nommé `.gitattributes`.
1. Ajoutez une ligne indiquant à GitLab d'inclure un type de fichier spécifique. Par exemple, pour activer les fichiers `.proto`, ajoutez ce qui suit :

   ```plaintext
   *.proto linguist-detectable=true
   ```

Cette fonctionnalité peut entraîner une utilisation excessive du CPU. Si vous rencontrez un problème, consultez la section de dépannage [utilisation excessive du CPU](files/_index.md#repository-languages-excessive-cpu-use).

## Analytique des contributeurs du dépôt {#repository-contributor-analytics}

Vous pouvez afficher un graphique en courbes indiquant le nombre de commits sur la branche de projet sélectionnée au fil du temps, ainsi que des graphiques en courbes indiquant le nombre de commits par membre du projet. Pour plus d'informations, consultez [l'analytique des contributeurs](../../analytics/contributor_analytics.md).

## Graphe d'historique du dépôt {#repository-history-graph}

Un graphe de dépôt affiche un historique visuel du réseau du dépôt, y compris les branches et les fusions. Ce graphe vous aide à visualiser le flux des modifications dans le dépôt.

Pour afficher le graphe d'historique du dépôt, accédez à **Code** > **Graphe du dépôt** dans votre projet.

![Un graphe représentant le flux des commits dans un dépôt.](img/repo_graph_v17_9.png)

## Modifications du chemin du dépôt {#repository-path-changes}

Lorsqu'un chemin de dépôt change, GitLab gère la transition de l'ancien emplacement vers le nouveau à l'aide d'une redirection.

Lorsque vous [renommez un utilisateur](../../profile/_index.md#change-your-username), [modifiez le chemin d'un groupe](../../group/manage.md#change-a-groups-path) ou [renommez un dépôt](../working_with_projects.md#rename-a-repository) :

- Les URL de l'espace de nommage et de tout ce qui en dépend, comme les projets, sont redirigées vers les nouvelles URL.
- Les URL Git distantes des projets de l'espace de nommage sont redirigées vers la nouvelle URL distante. Lorsque vous effectuez un push ou un pull vers un dépôt dont l'emplacement a changé, un message d'avertissement vous invite à mettre à jour votre remote. Les scripts d'automatisation et les clients Git continuent de fonctionner après un renommage.
- Les redirections sont disponibles tant que le chemin d'origine n'est pas revendiqué par un autre groupe, utilisateur ou projet.
- Les [redirections API](../../../api/rest/_index.md#redirects) peuvent nécessiter d'être suivies explicitement.

Après avoir modifié un chemin, vous devez mettre à jour l'URL existante dans les ressources suivantes :

- Les [instructions include](../../../ci/yaml/includes.md) sauf [`include:component`](../../../ci/components/_index.md), sinon les pipelines échouent avec une erreur de syntaxe. Les références de composants CI/CD peuvent suivre les redirections.
- Les appels API avec espace de nommage qui utilisent le [chemin encodé](../../../api/rest/_index.md#namespaced-paths) à la place de l'espace de nommage numérique et des ID de projet.
- [Références d'images Docker](../../../ci/yaml/_index.md#image).
- Variables qui spécifient un projet ou un espace de nommage.
- [Fichier `CODEOWNERS`](../codeowners/_index.md#codeowners-file).

## Sujets connexes {#related-topics}

- [Extension GitLab pour VS Code](../../../editor_extensions/visual_studio_code/_index.md)
- [Verrouiller des fichiers et éviter les conflits de modification](../file_lock.md)
- [API de dépôt](../../../api/repositories.md)
- [Fichiers](files/_index.md)
- [Branches](branches/_index.md)
- [Créer un répertoire](web_editor.md#create-a-directory)
- [Trouver l'historique d'un fichier](files/git_history.md)
- [Identifier les modifications par ligne (Git blame)](files/git_blame.md)

## Dépannage {#troubleshooting}

### Rechercher la séquence de pushs vers un dépôt {#search-sequence-of-pushes-to-a-repository}

Si un commit semble avoir « disparu », recherchez la séquence de pushs vers un dépôt. Ce [fil de discussion Stack Overflow](https://stackoverflow.com/questions/13468027/the-mystery-of-the-missing-commit-across-merges) décrit comment vous pouvez vous retrouver dans cet état sans force push. Une autre cause peut être un [hook serveur](../../../administration/server_hooks.md) mal configuré qui modifie une référence HEAD lors d'une opération `git reset`.

Si vous examinez la sortie du code d'exemple ci-dessous pour la branche cible, vous observez une discontinuité dans les commits de/vers au fil de la lecture de la sortie. Le `commit_from` de chaque nouveau push doit être égal au `commit_to` du push précédent. Une rupture dans cette séquence indique qu'un ou plusieurs commits ont été « perdus » dans l'historique du dépôt.

En utilisant la [console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session), l'exemple suivant vérifie les 100 derniers pushs et affiche les entrées `commit_from` et `commit_to` :

```ruby
p = Project.find_by_full_path('project/path')
p.events.pushed_action.last(100).each do |e|
  printf "%-20.20s %8s...%8s (%s)", e.push_event_payload[:ref], e.push_event_payload[:commit_from], e.push_event_payload[:commit_to], e.author.try(:username)
end ; nil
```

Exemple de sortie montrant une rupture de séquence à la ligne 4 :

```plaintext
master f21b07713251e04575908149bdc8ac1f105aabc3...6bc56c1f46244792222f6c85b11606933af171de root
master 6bc56c1f46244792222f6c85b11606933af171de...132da6064f5d3453d445fd7cb452b148705bdc1b root
master 132da6064f5d3453d445fd7cb452b148705bdc1b...a62e1e693150a2e46ace0ce696cd4a52856dfa65 root
master 58b07b719a4b0039fec810efa52f479ba1b84756...f05321a5b5728bd8a89b7bf530aa44043c951dce root
master f05321a5b5728bd8a89b7bf530aa44043c951dce...7d02e575fd790e76a3284ee435368279a5eb3773 root
```

### Erreur : Xcode ne parvient pas à cloner le dépôt {#error-xcode-fails-to-clone-repository}

GitLab fournit une option pour [restreindre la liste des clés SSH autorisées](../../../security/ssh_keys_restrictions.md). Si votre clé SSH ne figure pas dans la liste autorisée, vous pourriez rencontrer une erreur telle que `The repository rejected the provided credentials`.

Pour résoudre ce problème, créez une nouvelle paire de clés SSH conforme aux recommandations relatives aux [types de clés SSH pris en charge](../../ssh.md#supported-ssh-key-types). Après avoir généré une clé SSH prise en charge, essayez à nouveau de cloner le dépôt.
