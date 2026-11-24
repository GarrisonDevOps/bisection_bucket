---
stage: Solutions Architecture
group: Solutions Architecture
info: This page is owned by the Solutions Architecture team.
title: AWS CodePipeline
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Vous pouvez utiliser votre projet GitLab pour compiler, tester et déployer des modifications de code à l'aide d'[AWS CodePipeline](https://aws.amazon.com/codepipeline/). Pour ce faire, vous utilisez :

- AWS CodeStar Connections pour connecter votre compte GitLab.com à AWS.
- Cette connexion pour démarrer automatiquement un pipeline en fonction des modifications apportées à votre code.

## Créer une connexion d'AWS CodePipeline vers GitLab {#create-a-connection-from-aws-codepipeline-to-gitlab}

Prérequis :

- Vous devez disposer du rôle Owner sur le projet GitLab que vous connectez à AWS CodePipeline.
- Vous devez disposer des autorisations appropriées pour créer une connexion dans AWS.
- Vous devez utiliser une région AWS prise en charge. Les régions non prises en charge (également répertoriées dans la [documentation AWS](https://docs.aws.amazon.com/codepipeline/latest/userguide/connections-gitlab.html)) sont :
  - Asie-Pacifique (Hong Kong).
  - Afrique (Le Cap).
  - Moyen-Orient (Bahreïn).
  - Europe (Zurich).
  - AWS GovCloud (US-West et US-East).

Pour créer une connexion à un projet sur GitLab.com, vous pouvez utiliser la console AWS Management Console ou l'interface de ligne de commande AWS (AWS CLI).

### Utiliser la console AWS Management Console {#use-the-aws-management-console}

Pour connecter un pipeline nouveau ou existant dans AWS CodePipeline à GitLab.com, autorisez d'abord la connexion AWS à utiliser votre compte GitLab.

1. Connectez-vous à la console AWS Management Console et ouvrez la [console AWS Developer Tools](https://console.aws.amazon.com/codesuite/settings/connections).
1. Sélectionnez **Paramètres** > **Connexions** > **Créer une connexion**.
1. Dans **Sélectionner un fournisseur**, sélectionnez **GitLab**.
1. Dans **Nom de la connexion**, saisissez le nom de la connexion que vous souhaitez créer et sélectionnez **Se connecter à GitLab**.
1. Sur la page de connexion GitLab, saisissez vos identifiants et sélectionnez **Connexion**.
1. Une page d'autorisation s'affiche avec un message demandant l'autorisation pour que la connexion accède à votre compte GitLab. Sélectionnez **Autoriser**.
1. Le navigateur revient à la page de la console des connexions. Dans la section **Créer une connexion GitLab**, la nouvelle connexion est affichée dans **Nom de la connexion**.
1. Sélectionnez **Se connecter à GitLab**. Une fois la connexion créée avec succès, une bannière de confirmation s'affiche. Les détails de la connexion sont affichés sur la page **Paramètres de connexion**.

Maintenant que vous avez connecté AWS CodeSuite à GitLab.com, vous pouvez créer ou modifier un pipeline dans AWS CodePipeline qui exploite vos projets GitLab.

1. Connectez-vous à la [console AWS CodePipeline](https://console.aws.amazon.com/codesuite/codepipeline/start).
1. Créez ou modifiez un pipeline :
   - Si vous créez un pipeline :
     - Renseignez les champs du premier écran et sélectionnez **Suivant**.
     - Sur la page **Source**, dans la section **Fournisseur source**, sélectionnez **GitLab**.
   - Si vous modifiez un pipeline existant :
     - Sélectionnez **Modifier** > **Modifier l'étape** pour ajouter ou modifier votre action source.
     - Sur la page **Modifier l'action**, dans la section **Nom de l'action**, saisissez le nom de votre action.
     - Dans **Fournisseur d'action**, sélectionnez **GitLab**.
1. Dans **Connexion**, sélectionnez la connexion que vous avez créée précédemment.
1. Dans **Nom du dépôt**, pour choisir le nom de votre projet GitLab, spécifiez le chemin complet du projet avec l'espace de nommage et tous les sous-groupes. Par exemple, pour un projet au niveau d'un groupe, saisissez le nom du projet au format suivant : `group-name/subgroup-name/project-name`. Le chemin du projet avec l'espace de nommage figure dans l'URL dans GitLab. Ne copiez pas les URL depuis le Web IDE ou les vues brutes, car elles contiennent d'autres segments d'URL spéciaux. Vous pouvez également sélectionner une option dans la boîte de dialogue ou saisir manuellement un nouveau chemin. Pour en savoir plus sur :
   - Le chemin et l'espace de nommage, consultez le champ `path_with_namespace` dans l'[API projects](../../../api/projects.md#retrieve-a-project).
   - L'espace de nommage dans GitLab, consultez [les espaces de nommage](../../namespace/_index.md).

1. Dans **Nom de la branche**, sélectionnez la branche sur laquelle vous souhaitez que votre pipeline détecte les modifications de la source. Si le nom de la branche ne se renseigne pas automatiquement, cela peut être dû à l'une des raisons suivantes :
   - Vous ne disposez pas du rôle Owner pour le projet.
   - Le nom du projet n'est pas valide.
   - La connexion utilisée n'a pas accès au projet.

1. Dans **Format des artefacts de sortie**, sélectionnez le format de vos artefacts. Pour stocker :
   - Les artefacts de sortie de l'action GitLab en utilisant la méthode par défaut, sélectionnez **Par défaut CodePipeline**. L'action accède aux fichiers du dépôt GitLab et stocke les artefacts dans un fichier ZIP dans le magasin d'artefacts du pipeline.
   - Un fichier JSON contenant une référence URL vers le dépôt afin que les actions en aval puissent exécuter des commandes Git directement, sélectionnez **Clonage complet**. Cette option ne peut être utilisée que par les actions en aval de CodeBuild. Pour choisir cette option :
     - [Mettez à jour les autorisations pour le rôle de service de votre projet CodeBuild](https://docs.aws.amazon.com/codepipeline/latest/userguide/troubleshooting.html#codebuild-role-connections).
     - Suivez le [tutoriel AWS CodePipeline sur l'utilisation du clonage complet avec une source de pipeline GitHub](https://docs.aws.amazon.com/codepipeline/latest/userguide/tutorials-github-gitclone.html).
1. Enregistrez l'action source et continuez.

### Utiliser l'AWS CLI {#use-the-aws-cli}

Pour utiliser l'AWS CLI afin de créer une connexion :

- Utilisez la commande `create-connection`.
- Accédez à la console AWS pour vous authentifier avec votre compte GitLab.com.
- Connectez votre projet GitLab à AWS CodePipeline.

Pour utiliser la commande `create-connection` :

1. Ouvrez un terminal (Linux, macOS ou Unix) ou une invite de commandes (Windows). Utilisez l'AWS CLI pour exécuter la commande `create-connection`, en spécifiant `--provider-type` et `--connection-name` pour votre connexion. Dans cet exemple, le nom du fournisseur tiers est `GitLab` et le nom de connexion spécifié est `MyConnection`.

   ```shell
   aws codestar-connections create-connection --provider-type GitLab --connection-name MyConnection
   ```

   En cas de succès, cette commande renvoie les informations Amazon Resource Name (ARN) de la connexion. Par exemple :

   ```json
   {
   "ConnectionArn": "arn:aws:codestar-connections:us-west-2:account_id:connection/aEXAMPLE-8aad-4d5d-8878-dfcab0bc441f"
   }
   ```

1. La nouvelle connexion est créée avec le statut `PENDING` par défaut. Utilisez la console pour passer le statut de la connexion à `AVAILABLE`.
1. [Utilisez la console AWS pour finaliser la connexion](#use-the-aws-management-console). Assurez-vous de sélectionner votre connexion GitLab en attente. Ne sélectionnez pas **Créer une connexion**.

## Sujets connexes {#related-topics}

- [Annonce de la prise en charge de GitLab par AWS CodePipeline](https://aws.amazon.com/about-aws/whats-new/2023/08/aws-codepipeline-supports-gitlab/)
- [Connexions GitLab - AWS CodePipeline](https://docs.aws.amazon.com/codepipeline/latest/userguide/connections-gitlab.html)
- [Créer une connexion à GitLab - Console Developer Tools](https://docs.aws.amazon.com/dtconsole/latest/userguide/connections-create-gitlab.html)
- [CodeStarSourceConnection pour les actions Bitbucket, GitHub, GitHub Enterprise Server et GitLab - AWS CodePipeline](https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-CodestarConnectionSource.html)
