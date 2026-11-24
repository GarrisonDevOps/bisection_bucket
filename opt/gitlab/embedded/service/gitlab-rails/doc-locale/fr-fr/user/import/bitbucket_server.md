---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Migrer depuis Bitbucket Server
description: "Migrez depuis Bitbucket Server vers GitLab."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/153041) : mappage des utilisateurs uniquement par adresse e-mail dans GitLab 17.1.
- Un badge **Importé** sur certains éléments importés [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/461211) dans GitLab 17.2.
- [Modification sur GitLab.com](https://gitlab.com/groups/gitlab-org/-/work_items/14667) vers le [mappage post-migration des contributions et des appartenances des utilisateurs](mapping/post_migration_mapping.md) dans GitLab 17.8.
- Mappage post-migration des utilisateurs et des appartenances aux contributions [activé sur GitLab.com et GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/176675) dans GitLab 17.8.

{{< /history >}}

Importez vos projets depuis Bitbucket Server vers GitLab.

L'importateur Bitbucket Server importe un sous-ensemble d'éléments depuis Bitbucket Server.

| Élément Bitbucket Server                                                         | Importé |
|:------------------------------------------------------------------------------|:---------|
| Description du dépôt                                                        | {{< yes >}} |
| Données du dépôt Git                                                           | {{< yes >}} |
| Pull requests, y compris les commentaires, les mentions d'utilisateurs, les relecteurs et les événements de fusion | {{< yes >}} |
| Objets LFS                                                                   | {{< yes >}} |
| Commentaires sur le code[^doesn-allow-comments]                                                  | {{< yes >}} |
| Fils de discussion[^multiple-threading-levels]                                                           | {{< yes >}} |
| Filtres de projet[^project-filtering-doesn]                                                   | {{< yes >}} |
| Pièces jointes en Markdown                                                       | {{< no >}} |
| Listes de tâches                                                                    | {{< no >}} |
| Réactions emoji                                                               | {{< no >}} |
| Approbations de pull request                                                        | {{< no >}} |
| Règles d'approbation pour les pull requests                                              | {{< no >}} |

[^doesn-allow-comments] : GitLab n'autorise pas les commentaires sur des lignes de code arbitraires. Les commentaires Bitbucket hors limites sont insérés en tant que commentaires dans la merge request. [^multiple-threading-levels] : les niveaux de fil de discussion multiples sont regroupés en un seul fil de discussion et les citations sont ajoutées dans le cadre du commentaire d'origine. [^project-filtering-doesn] : le filtrage de projet ne prend pas en charge la recherche approximative. Seules les chaînes commençant par ou correspondant exactement sont prises en charge.

## Problèmes connus {#known-issues}

- Les images et les pièces jointes incorporées dans les descriptions et les commentaires des pull requests ne sont pas copiées vers GitLab. Elles restent sous forme de liens externes pointant vers les URL d'origine hébergées sur Bitbucket. Si l'instance source Bitbucket Server est mise hors service ou si le dépôt est supprimé, toutes les images incorporées et tous les liens de pièces jointes sont définitivement rompus. Avant de mettre hors service l'instance source Bitbucket Server, vérifiez que toutes les images incorporées et toutes les pièces jointes sont accessibles ou conservez-les séparément. La prise en charge de l'importation des images et des pièces jointes est proposée dans [le ticket de travail 623235](https://gitlab.com/gitlab-org/gitlab/-/work_items/623235).

## Workflow de l'importateur {#importer-workflow}

L'importateur Bitbucket Server prend en charge le [mappage post-migration](mapping/post_migration_mapping.md) des contributions des utilisateurs pour GitLab.com et GitLab Self-Managed. L'importateur prend également en charge une [méthode alternative](#alternative-method-of-mapping) de mappage.

Lorsque des éléments Bitbucket Server sont importés :

- L'accès public au dépôt est conservé. Si un dépôt est privé dans Bitbucket, il est créé comme privé dans GitLab.
- Les merge requests et commentaires importés ont un badge **Importé** dans GitLab.

Lorsque des pull requests fermées ou fusionnées sont importées, les SHA de commit qui n'existent pas dans le dépôt sont récupérés depuis Bitbucket Server pour s'assurer que les pull requests ont des commits associés :

- Les SHA de commit source sont enregistrés avec des références au format `refs/merge-requests/<iid>/head`.
- Les SHA de commit cible sont enregistrés avec des références au format `refs/keep-around/<SHA>`.

Si le commit source n'existe pas dans le dépôt, un commit contenant le SHA dans le message de commit est utilisé à la place.

## Estimation de la durée d'importation {#estimating-import-duration}

Chaque importation depuis Bitbucket Server est différente, ce qui affecte la durée des importations que vous effectuez. Cependant, pour estimer la durée de votre importation, un projet composé des données suivantes prendra vraisemblablement 8 heures à importer :

- 13 000 pull requests
- 7 000 tags
- Dépôt de 500 Gio

## Prérequis {#prerequisites}

- Bitbucket Server doit être accessible depuis l'instance GitLab. L'URL de Bitbucket Server doit être résolvable publiquement ou accessible sur le réseau sur lequel GitLab s'exécute.
- Vous devez activer la [source d'importation Bitbucket Server](../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources) ou demander à votre administrateur GitLab de l'activer. Activée par défaut sur GitLab.com.
- Le rôle Maintainer ou Owner sur le groupe de destination vers lequel importer.
- Jeton d'authentification Bitbucket Server avec accès administrateur. Sans accès administrateur, certaines données [ne sont pas importées](https://gitlab.com/gitlab-org/gitlab/-/issues/446218).

## Importer vos dépôts Bitbucket Server {#import-your-bitbucket-server-repositories}

Pour importer vos dépôts Bitbucket Server :

1. Connectez-vous à GitLab.
1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Importer un projet**.
1. Sélectionnez **Bitbucket Server**.
1. Connectez-vous à Bitbucket et accordez à GitLab l'accès à votre compte Bitbucket.
1. Sélectionnez les projets à importer, ou importez tous les projets. Vous pouvez filtrer les projets par nom et sélectionner l'espace de nommage dans lequel importer chaque projet.
1. Pour importer un projet :
   - Pour la première fois, sélectionnez **Importer**.
   - Pour les fois suivantes, sélectionnez **Réimporter**. Spécifiez un nouveau nom et sélectionnez à nouveau **Réimporter**. La réimportation crée une nouvelle copie du projet source.

## Méthode alternative de mappage {#alternative-method-of-mapping}

Vous pouvez désactiver le feature flag `bitbucket_server_user_mapping` pour utiliser la méthode alternative de mappage des contributions des utilisateurs pour les importations.

Pour les importations vers GitLab.com, vous devez utiliser la [méthode post-migration](mapping/post_migration_mapping.md) à la place.

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Cette fonctionnalité n'est pas recommandée et n'est pas disponible pour les migrations vers GitLab.com. Les problèmes identifiés dans cette méthode de mappage ne seront probablement pas corrigés. Utilisez plutôt la [méthode post-migration](mapping/post_migration_mapping.md), qui ne présente pas ces limitations.
>
> Pour plus d'informations, consultez le [ticket 512213](https://gitlab.com/gitlab-org/gitlab/-/work_items/512213).

En utilisant la méthode alternative, l'importateur tente de faire correspondre l'adresse e-mail d'un utilisateur Bitbucket Server avec une adresse e-mail confirmée dans la base de données des utilisateurs GitLab. Si aucun utilisateur correspondant n'est trouvé :

- Le créateur du projet est utilisé à la place. L'importateur ajoute une note dans le commentaire pour identifier le créateur d'origine.
- Pour les relecteurs de pull request, aucun relecteur n'est assigné.
- Pour les approbateurs de pull request, aucune approbation n'est ajoutée.

Les mentions dans les descriptions et les notes des pull requests sont associées aux profils d'utilisateurs sur un Bitbucket Server à l'aide de l'adresse e-mail de l'utilisateur. Si un utilisateur avec la même adresse e-mail n'est pas trouvé sur GitLab, la mention est rendue statique. Pour qu'un utilisateur soit associé, il doit avoir un rôle GitLab qui fournit au moins un accès en lecture au projet.

Si le projet est public, GitLab associe uniquement les utilisateurs invités au projet.

L'importateur crée tout nouvel espace de nommage (groupe) s'il n'existe pas. Si l'espace de nommage est déjà utilisé, le dépôt est importé sous l'espace de nommage de l'utilisateur qui a démarré le processus d'importation.

## Dépannage {#troubleshooting}

Les sections suivantes contiennent des solutions aux problèmes que vous pourriez rencontrer.

### Général {#general}

Si l'outil d'importation basé sur l'interface graphique ne fonctionne pas, vous pouvez essayer de :

- Utiliser l'[API d'importation](../../api/import.md#import-repository-from-bitbucket-server) avec l'endpoint Bitbucket Server.
- Configurer la [mise en miroir du dépôt](../project/repository/mirror/_index.md). Elle fournit une sortie d'erreur détaillée.

Consultez la [section de dépannage](bitbucket_cloud.md#troubleshooting) pour Bitbucket Cloud.

### Objets LFS non importés {#lfs-objects-not-imported}

Si l'importation du projet se termine mais que les objets LFS ne peuvent pas être téléchargés ou clonés, vous utilisez peut-être un mot de passe ou un jeton d'accès personnel contenant des caractères spéciaux. Pour plus d'informations, consultez le [ticket 337769](https://gitlab.com/gitlab-org/gitlab/-/issues/337769).

### L'importation échoue en raison d'une adresse d'hôte invalide/non résolue, ou l'URL d'importation est bloquée {#import-fails-due-to-invalidunresolved-host-address-or-the-import-url-is-blocked}

Si l'importation d'un projet échoue avec un message d'erreur tel que `Importing the project failed: Import URL is blocked`, même si la connexion initiale au serveur Bitbucket a réussi, le serveur Bitbucket ou un proxy inverse n'est peut-être pas configuré correctement.

Pour résoudre ce problème, utilisez l'[API Projects](../../api/projects.md) pour vérifier le projet nouvellement créé et localiser la valeur `import_url` du projet.

Cette valeur indique l'URL fournie par le serveur Bitbucket à utiliser pour l'importation. Si cette URL n'est pas résolvable publiquement, vous pouvez obtenir des erreurs d'adresse non résolvable.

Pour résoudre ce problème, assurez-vous que le serveur Bitbucket a connaissance des serveurs proxy, car les serveurs proxy peuvent avoir un impact sur la façon dont Bitbucket construit et utilise les URL. Pour plus d'informations, consultez [proxy et sécurisation de Bitbucket](https://confluence.atlassian.com/bitbucketserver/proxy-and-secure-bitbucket-776640099.html).

### L'importation échoue avec JSON::NestingError {#import-fails-with-jsonnestingerror}

Si l'importation d'un projet échoue avec un message d'erreur contenant `JSON::NestingError`, la réponse de Bitbucket Server contient des objets profondément imbriqués qui dépassent le paramètre `max_http_response_json_depth`.

Pour résoudre ce problème, augmentez la [profondeur d'imbrication maximale autorisée dans les réponses HTTP JSON des requêtes sortantes](../../administration/instance_limits.md#maximum-allowed-nesting-depth-in-json-http-responses-from-outbound-requests).

## Sujets connexes {#related-topics}

- [Migrer depuis Bitbucket Cloud](bitbucket_cloud.md).
- [Paramètres d'importation et d'exportation](../../administration/settings/import_and_export_settings.md).
- [Configuration Sidekiq pour les importations](../../administration/sidekiq/configuration_for_imports.md).
- [Exécution de plusieurs processus Sidekiq](../../administration/sidekiq/extra_sidekiq_processes.md).
- [Traitement de classes de job spécifiques](../../administration/sidekiq/processing_specific_job_classes.md).
