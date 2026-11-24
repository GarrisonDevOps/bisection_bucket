---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Migrer depuis Bitbucket Cloud
description: "Migrer depuis Bitbucket Cloud vers GitLab."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Un badge **Importé** sur certains éléments importés [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/461210) dans GitLab 17.2.

{{< /history >}}

Importez vos projets depuis Bitbucket Cloud vers GitLab.

L'importateur Bitbucket Cloud importe un sous-ensemble d'éléments depuis Bitbucket Cloud.

| Élément Bitbucket Cloud              | Importé |
|:----------------------------------|:---------|
| Description du dépôt            | {{< yes >}} |
| Données du dépôt Git               | {{< yes >}} |
| Tickets, y compris les commentaires        | {{< yes >}} |
| Pull requests, y compris les commentaires | {{< yes >}} |
| Les jalons                        | {{< yes >}} |
| Wiki                              | {{< yes >}} |
| Labels                            | {{< yes >}} |
| Les jalons                        | {{< yes >}} |
| Objets LFS                       | {{< yes >}} |
| Images intégrées et pièces jointes en Markdown | {{< no >}} |
| Approbations de pull requests            | {{< no >}} |
| Règles d'approbation                    | {{< no >}} |

## Problèmes connus {#known-issues}

- Les images et les pièces jointes intégrées dans les tickets, les commentaires de tickets et les pull requests ne sont pas copiées vers GitLab. Elles restent sous forme de liens externes pointant vers les URL Bitbucket d'origine (par exemple, `bitbucket.org` ou `bbuseruploads.s3.amazonaws.com`). Si le dépôt Bitbucket source est supprimé, toutes les images intégrées et tous les liens de pièces jointes sont définitivement rompus. Avant de supprimer le dépôt Bitbucket source, vérifiez que toutes les images intégrées et les pièces jointes sont accessibles ou conservez-les séparément. La prise en charge de l'importation des images et des pièces jointes est proposée dans le [ticket de travail 623235](https://gitlab.com/gitlab-org/gitlab/-/work_items/623235).

## Workflow de l'importateur {#importer-workflow}

Lorsque des éléments Bitbucket Cloud sont importés :

- Les références aux pull requests et aux tickets sont conservées.
- L'accès public au dépôt est conservé. Si un dépôt est privé dans Bitbucket Cloud, il est créé comme privé dans GitLab.
- Les tickets, les merge requests et les commentaires importés disposent d'un badge **Importé** dans GitLab.

Lors de l'importation des tickets, des pull requests et des commentaires, l'importateur Bitbucket Cloud :

- Utilise le pseudo Bitbucket de l'auteur/de la personne assignée et tente de trouver la même identité Bitbucket dans GitLab.
- Si les identités ne correspondent pas ou si l'utilisateur n'est pas trouvé dans la base de données GitLab, définit le créateur du projet (généralement l'utilisateur actuel qui a lancé le processus d'importation) comme auteur et conserve une référence dans le ticket concernant l'auteur Bitbucket d'origine.

Pour les pull requests, l'importateur :

- Utilise le SHA source et, s'il n'existe pas dans le dépôt, tente de définir le commit source sur le SHA du commit de fusion.
- Définit la personne assignée à la merge request comme auteur et définit les relecteurs dont les noms d'utilisateur correspondent aux identités Bitbucket dans GitLab.
- Définit les merge requests dans GitLab comme étant `opened`, `closed` ou `merged`.

Pour les tickets, l'importateur :

- Ajoute un label correspondant au type de ticket sur Bitbucket. Soit `bug`, `enhancement`, `proposal` ou `task`.
- Si le ticket sur Bitbucket était de type `resolved`, `invalid`, `duplicate`, `wontfix` ou `closed`, ferme le ticket sur GitLab.

L'importateur Bitbucket Cloud crée les nouveaux espaces de nommage (groupes) s'ils n'existent pas. Si l'espace de nommage est déjà utilisé, le dépôt est importé sous l'espace de nommage de l'utilisateur qui a lancé le processus d'importation.

## Prérequis {#prerequisites}

- Vous devez activer l'[intégration Bitbucket Cloud](../../integration/bitbucket.md) ou demander à votre administrateur GitLab de l'activer. Activée par défaut sur GitLab.com.
- Vous devez activer la [source d'importation Bitbucket Cloud](../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources) ou demander à votre administrateur GitLab de l'activer. Activée par défaut sur GitLab.com.
- Vous devez disposer du rôle Maintainer ou Owner sur le groupe de destination vers lequel vous importez.
- Les pull requests dans Bitbucket doivent avoir le même projet source et de destination et ne pas provenir d'une duplication d'un projet. Dans le cas contraire, les pull requests sont importées comme des merge requests vides.

Pour que les contributions des utilisateurs soient associées, chaque utilisateur doit effectuer les étapes suivantes avant l'importation du projet :

1. Vérifiez que le nom d'utilisateur dans les [paramètres du compte Bitbucket](https://bitbucket.org/account/settings/) correspond au nom public dans les [paramètres du compte Atlassian](https://id.atlassian.com/manage-profile/profile-and-visibility). S'ils ne correspondent pas, modifiez le nom public dans les paramètres du compte Atlassian pour qu'il corresponde au nom d'utilisateur dans les paramètres du compte Bitbucket.
1. Connectez votre compte Bitbucket dans la [connexion au service de profil GitLab](https://gitlab.com/-/profile/account).

### Générer un jeton d'API Bitbucket Cloud {#generate-a-bitbucket-cloud-api-token}

Pour utiliser l'API d'importation afin d'importer un dépôt Bitbucket Cloud, vous devez créer un jeton d'API Bitbucket Cloud.

Pour générer un jeton d'API Bitbucket Cloud :

1. Accédez à <https://id.atlassian.com/manage-profile/security/api-tokens>.
1. Sélectionnez **Create API token with scopes**.
1. Saisissez un nom de jeton et une date d'expiration, puis sélectionnez **Suivant**.
1. Sélectionnez **Bitbucket**, puis **Suivant**.
1. Sélectionnez au moins les portées suivantes :

   - `read:repository:bitbucket`
   - `read:pullrequest:bitbucket`
   - `read:issue:bitbucket`
   - `read:wiki:bitbucket`

1. Sélectionnez **Créer un jeton** et copiez le jeton.

## Importer vos dépôts Bitbucket Cloud {#import-your-bitbucket-cloud-repositories}

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Importer un projet**.
1. Sélectionnez **Bitbucket Cloud**.
1. Connectez-vous à Bitbucket, puis sélectionnez **Accorder l'accès** pour autoriser GitLab à accéder à votre compte Bitbucket.
1. Sélectionnez les projets que vous souhaitez importer ou importez tous les projets. Vous pouvez filtrer les projets par nom et sélectionner l'espace de nommage dans lequel chaque projet est importé.
1. Pour importer un projet :
   - Pour la première fois, sélectionnez **Importer**.
   - Pour les fois suivantes, sélectionnez **Réimporter**. Spécifiez un nouveau nom et sélectionnez à nouveau **Réimporter**. La réimportation crée une nouvelle copie du projet source.

## Dépannage {#troubleshooting}

Ces sections contiennent des solutions possibles aux problèmes que vous pourriez rencontrer lors de l'importation depuis Bitbucket Cloud.

### Le processus d'importation a utilisé un mauvais compte {#import-process-used-wrong-account}

Assurez-vous de vous connecter au bon compte. Si vous avez accidentellement démarré le processus d'importation avec le mauvais compte, suivez ces étapes :

1. Révoquez l'accès GitLab à votre compte Bitbucket, en annulant essentiellement le processus lorsque vous avez [importé vos dépôts Bitbucket Cloud](#import-your-bitbucket-cloud-repositories).
1. Déconnectez-vous du compte Bitbucket et [importez à nouveau vos dépôts Bitbucket Cloud](#import-your-bitbucket-cloud-repositories).

### L'association des utilisateurs échoue malgré la correspondance des noms {#user-mapping-fails-despite-matching-names}

[Pour que l'association des utilisateurs fonctionne](mapping/post_migration_mapping.md), le nom d'utilisateur dans les paramètres du compte Bitbucket doit correspondre au nom public dans les paramètres du compte Atlassian.

Si ces noms correspondent mais que l'association des utilisateurs échoue encore, l'utilisateur a peut-être modifié son nom d'utilisateur Bitbucket après avoir connecté son compte Bitbucket dans la [connexion au service de profil GitLab](https://gitlab.com/-/profile/account).

Pour résoudre ce problème, l'utilisateur doit vérifier que son UID externe Bitbucket dans la base de données GitLab correspond à son nom public Bitbucket actuel, et se reconnecter en cas de discordance :

1. [Utilisez l'API pour obtenir l'utilisateur authentifié](../../api/users.md#retrieve-the-current-user).
1. Dans la réponse de l'API, l'attribut `identities` contient le compte Bitbucket qui existe dans la base de données GitLab. Si `extern_uid` ne correspond pas au nom public Bitbucket actuel, l'utilisateur doit reconnecter son compte Bitbucket dans la [connexion au service de profil GitLab](https://gitlab.com/-/profile/account).
1. Après la reconnexion, l'utilisateur doit utiliser à nouveau l'API pour vérifier que son `extern_uid` dans la base de données GitLab correspond désormais à son nom public Bitbucket actuel.

L'utilisateur qui a importé le projet doit ensuite [supprimer le projet importé](../project/working_with_projects.md#delete-a-project) et l'importer à nouveau.

## Sujets connexes {#related-topics}

- [Migrer depuis Bitbucket Server](bitbucket_server.md)
- [API d'importation](../../api/import.md)
- [Paramètres d'importation et d'exportation](../../administration/settings/import_and_export_settings.md).
- [Configuration Sidekiq pour les importations](../../administration/sidekiq/configuration_for_imports.md).
- [Exécution de plusieurs processus Sidekiq](../../administration/sidekiq/extra_sidekiq_processes.md).
- [Traitement de classes de jobs spécifiques](../../administration/sidekiq/processing_specific_job_classes.md).
