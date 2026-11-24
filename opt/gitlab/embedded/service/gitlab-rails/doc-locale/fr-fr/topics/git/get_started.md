---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Utiliser le système de contrôle de version Git.
title: Premiers pas avec Git
---

Git est un système de contrôle de version que vous utilisez pour suivre les modifications apportées à votre code et collaborer avec d'autres personnes. GitLab est un gestionnaire de dépôt Git web qui fournit des fonctionnalités CI/CD et d'autres fonctionnalités pour vous aider à gérer votre cycle de vie de développement logiciel.

Vous pouvez utiliser l'interface web de GitLab pour de nombreuses opérations Git, mais la compréhension des commandes Git vous offre une flexibilité et un contrôle supplémentaires.

L'apprentissage de Git fait partie d'un workflow plus large :

![Utiliser Git dans l'étape Create du cycle de vie DevOps de GitLab.](img/get_started_git_v16_11.png)

Choisissez votre parcours d'apprentissage :

- [Installer Git](how_to_install_git/_index.md)
- [Tutoriel : effectuer votre premier commit Git](../../tutorials/make_first_git_commit/_index.md)
- Comprendre les concepts Git : continuer la lecture

## Dépôts {#repositories}

Un dépôt Git est un répertoire qui contient tous les fichiers, dossiers et l'historique des versions de votre projet. Il sert de hub central où Git gère et suit les modifications apportées à votre code.

Lorsque vous initialisez un dépôt Git ou que vous en clonez un existant, Git crée un répertoire caché, `.git`, dans le répertoire du projet. Le répertoire contient toutes les métadonnées et tous les objets essentiels que Git utilise pour gérer votre dépôt, y compris l'historique complet de toutes les modifications apportées aux fichiers. Git suit les modifications au niveau des fichiers, ce qui vous permet de consulter les modifications apportées à des fichiers individuels au fil du temps.

Pour plus d'informations, consultez [les dépôts](../../user/project/repository/_index.md).

## Répertoires de travail {#working-directories}

Votre répertoire de travail est l'endroit où vous apportez des modifications à votre code. Lorsque vous clonez un dépôt Git, vous créez une copie locale du dépôt dans votre répertoire de travail. Vous pouvez modifier des fichiers, en ajouter de nouveaux et tester votre code. Pour collaborer, vous pouvez :

- Commit : après avoir apporté des modifications dans votre répertoire de travail, effectuez un commit de ces modifications dans votre dépôt local.
- Push : poussez vos modifications vers un dépôt Git distant hébergé sur GitLab. Cela rend vos modifications disponibles pour les autres membres de l'équipe.
- Pull : récupérez les modifications apportées par d'autres personnes depuis le dépôt distant et assurez-vous que votre dépôt local est mis à jour avec les dernières modifications.

Pour plus d'informations, consultez [les commandes Git courantes](commands.md).

## Branches {#branches}

Dans Git, vous pouvez utiliser des branches pour travailler simultanément sur différentes fonctionnalités, corrections de bugs ou expérimentations sans interférer avec le travail des autres. La création de branches vous permet de créer un environnement isolé dans lequel vous pouvez effectuer et tester des modifications sans affecter la branche par défaut. Dans GitLab, la branche par défaut s'appelle généralement `main`.

### Fusionner une branche {#merge-a-branch}

Lorsqu'une fonctionnalité est terminée ou qu'un bug est corrigé, vous pouvez fusionner votre branche dans la branche par défaut. Vous pouvez effectuer cette opération dans une [merge request](../../user/project/merge_requests/_index.md). La fusion est un moyen sûr d'intégrer les modifications d'une branche dans une autre tout en préservant l'historique des modifications.

S'il existe des conflits entre les branches, par exemple si vous modifiez les mêmes lignes de code dans les deux branches, GitLab les signale comme des [conflits de merge](../../user/project/merge_requests/conflicts.md). Ces conflits doivent être résolus manuellement en révisant et en modifiant le code.

### Supprimer une branche {#delete-a-branch}

Après une fusion réussie, vous pouvez supprimer la branche si elle n'est plus nécessaire. La suppression des branches inutiles permet de maintenir votre dépôt organisé et gérable.

> [!note]
> Pour vous assurer qu'aucun travail n'est perdu, vérifiez que toutes les modifications sont intégrées dans la branche par défaut avant de supprimer la branche après la fusion finale.

Pour plus d'informations, consultez [les branches](../../user/project/repository/branches/_index.md).

## Comprendre le workflow Git {#understand-the-git-workflow}

Vous pouvez gérer votre code, collaborer avec d'autres personnes et maintenir votre projet organisé grâce à un workflow Git. Un workflow Git standard comprend les étapes suivantes :

1. Cloner un dépôt : créez une copie locale du dépôt en le clonant sur votre machine. Vous pouvez travailler sur le projet sans affecter le dépôt d'origine.
1. Créer une nouvelle branche : avant d'apporter des modifications, il est recommandé de créer une nouvelle branche. Cela garantit que vos modifications sont isolées et n'interfèrent pas avec le travail des autres sur la branche par défaut.
1. Apporter des modifications : apportez des modifications aux fichiers dans votre répertoire de travail. Vous pouvez ajouter de nouvelles fonctionnalités, corriger des bugs ou apporter d'autres modifications.
1. Indexer les modifications : après avoir apporté des modifications à vos fichiers, indexez les modifications que vous souhaitez inclure dans le commit. L'indexation indique à Git quelles modifications doivent être incluses dans le prochain commit.
1. Effectuer un commit des modifications : effectuez un commit de vos modifications indexées dans votre dépôt local. Un commit enregistre un instantané de votre travail et crée un historique des modifications apportées à vos fichiers.
1. Pousser les modifications : pour partager vos modifications avec d'autres personnes, poussez-les vers le dépôt distant. Cela rend vos modifications disponibles pour les autres collaborateurs.
1. Fusionner votre branche : une fois vos modifications examinées et approuvées, fusionnez votre branche dans la branche par défaut. Par exemple, `main`. Cette étape intègre vos modifications dans le projet.

## Duplications {#forks}

Certaines organisations, en particulier celles qui travaillent sur des projets open source, peuvent utiliser des workflows différents. Par exemple, les [duplications](../../user/project/repository/forking_workflow.md).

Une duplication est une copie personnelle du dépôt qui existe dans votre propre espace de nommage. Utilisez ce workflow lorsque vous contribuez à des projets open source ou lorsque votre équipe utilise un dépôt centralisé.

## Installer Git {#install-git}

Pour utiliser les commandes Git et contribuer aux projets GitLab, vous devez télécharger et installer le client Git sur votre ordinateur.

Le processus d'installation varie en fonction de votre système d'exploitation. Par exemple, Windows, macOS ou Linux. Pour plus d'informations sur l'installation de Git, consultez [installer Git](how_to_install_git/_index.md).

## Commandes Git {#git-commands}

Pour interagir avec Git depuis la ligne de commande, vous pouvez utiliser les commandes Git :

- `git clone` : cloner un dépôt sur votre machine locale.
- `git branch` : lister, créer ou supprimer des branches dans votre dépôt local.
- `git checkout` : basculer entre différentes branches dans votre dépôt local.
- `git add` : indexer les modifications pour le commit.
- `git commit` : effectuer un commit des modifications indexées dans votre dépôt local.
- `git push` : pousser les commits locaux vers le dépôt distant.
- `git pull` : récupérer les modifications depuis le dépôt distant et les fusionner dans votre branche locale.

Pour des informations plus complètes et des explications détaillées, consultez le guide des [commandes Git courantes](commands.md).

### Utiliser SSH avec Git {#use-ssh-with-git}

Lorsque vous travaillez avec des dépôts distants, vous devez utiliser SSH pour des communications sécurisées.

GitLab utilise le protocole SSH pour communiquer de manière sécurisée avec Git. Lorsque vous utilisez des clés SSH pour vous authentifier auprès du serveur distant GitLab, vous n'avez pas besoin de fournir votre nom d'utilisateur et votre mot de passe à chaque fois.

Pour utiliser SSH avec GitLab, vous devez :

1. Générer une paire de clés SSH sur votre système local.
1. Ajouter votre clé SSH à votre compte GitLab.
1. Vérifier votre connexion SSH à GitLab.

Pour plus d'informations, consultez [utiliser des clés SSH avec GitLab](../../user/ssh.md).

## Sujets connexes {#related-topics}

- [Tutoriels : apprendre Git](../../tutorials/learn_git.md)
