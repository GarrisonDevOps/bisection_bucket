---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Migrer des groupes et des projets par transfert hors ligne
description: "Migrez des groupes et des projets GitLab via le stockage d'objets."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed
- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/8985) en tant que [version expérimentale](../../../policy/development_stages_support.md#experiment) dans GitLab 19.3 [avec des feature flags](../../../administration/feature_flags/_index.md) nommés `offline_transfer_exports`, `offline_transfer_imports` et `offline_transfer_ui`. Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par des feature flags. Pour plus d'informations, consultez l'historique. Cette fonctionnalité est disponible à des fins de test, mais n'est pas prête pour une utilisation en production.

Le transfert hors ligne copie les groupes et les projets GitLab entre des instances via le stockage d'objets, sans connexion réseau directe entre les instances source et de destination. L'instance source exporte les données vers un bucket de stockage, et l'instance de destination importe les données depuis un bucket qu'elle peut lire.

Contrairement à la [migration par transfert direct](../../group/import/direct_transfer_migrations.md), qui nécessite que l'instance de destination se connecte à l'instance source, le transfert hors ligne dissocie l'export et l'import. Le bucket d'export et le bucket d'import n'ont pas à être le même bucket, ni à utiliser le même fournisseur de stockage d'objets. Si l'instance de destination ne peut pas accéder au bucket d'export, déplacez les fichiers d'export vers un bucket auquel la destination peut accéder. GitLab ne déplace pas ces fichiers pour vous.

Préservez la structure des clés d'objet lorsque vous déplacez les fichiers. Le transfert hors ligne construit chaque clé d'objet à partir du préfixe d'export :

- `<export_prefix>/metadata.json.gz`
- `<export_prefix>/<entity_prefix>/<relation>.<extension>`
- `<export_prefix>/<entity_prefix>/<relation>/batch_<number>.<extension>`

Par exemple, `2026-04-16_19-39-00_export_dJtnb3CV/project_1/repository.tar.gz`.

Vous pouvez renommer le préfixe d'export de niveau supérieur, car vous le fournissez au démarrage de l'import. Tout ce qui se trouve sous le préfixe d'export doit conserver la même structure et les mêmes noms de fichiers.

L'absence de connexion directe entre les instances ne signifie pas qu'une instance est hors ligne. Les instances source et de destination ont toujours besoin d'un accès réseau à un magasin d'objets pour effectuer l'export ou l'import.

Le transfert hors ligne est conditionné par des feature flags et des paramètres d'application. Tous sont désactivés par défaut, et pour une opération donnée, les deux couches doivent être activées :

- Exports : le paramètre d'application `offline_transfer_exports_enabled`.
- Imports : le paramètre d'application `offline_transfer_imports_enabled`.

Pour effectuer des exports et des imports, utilisez l'[API REST de transfert hors ligne](https://api.gitlab.com/rest/#gitlab/tag/offline-transfers). La prise en charge des transferts hors ligne dans l'interface GitLab est proposée dans le [work item 19870](https://gitlab.com/groups/gitlab-org/-/work_items/19870).

## Exigences de version {#version-requirements}

Pour créer un export de transfert hors ligne, l'instance source doit exécuter GitLab 19.3 ou une version ultérieure. Pour importer un export, l'instance de destination doit exécuter GitLab 19.3 ou une version ultérieure.

Chaque export enregistre la version de l'instance source qui l'a créé. Si cette version est antérieure à la version minimale prise en charge par l'instance de destination, l'import échoue avec une erreur `Unsupported GitLab version`.

## Fournisseurs de stockage d'objets pris en charge {#supported-object-storage-providers}

Le transfert hors ligne prend en charge les fournisseurs de stockage d'objets suivants :

| Fournisseur | Description |
| -------- | ----------- |
| AWS S3 | Stockage d'objets Amazon S3. |
| Compatible S3 | MinIO et autres fournisseurs compatibles S3. Nécessite qu'un administrateur [active le stockage d'objets compatible S3](../../../administration/settings/import_and_export_settings.md#allow-s3-compatible-object-storage-for-offline-transfer). |
| Google Cloud Storage (compte de service) | Google Cloud Storage authentifié avec une clé JSON de compte de service. |
| Google Cloud Storage (HMAC) | Google Cloud Storage authentifié avec des clés HMAC d'interopérabilité S3. |
| Google Cloud Storage avec les identifiants par défaut de l'application | Google Cloud Storage authentifié avec les identifiants par défaut de l'application (ADC). Restreint aux administrateurs et à des buckets spécifiques, et non disponible sur GitLab.com. Pour plus d'informations, consultez [les identifiants par défaut de l'application](#application-default-credentials). |

### Autorisations requises {#required-permissions}

Les identifiants de stockage d'objets que vous fournissez doivent disposer des autorisations suivantes.

Pour AWS S3 :

- Export : `s3:PutObject` et `s3:ListBucket`
- Import : `s3:GetObject` et `s3:ListBucket`

Pour Google Cloud Storage avec un compte de service :

- Export : `storage.buckets.get`, `storage.objects.create` et `storage.objects.list`
- Import : `storage.objects.get`

Google Cloud Storage avec ADC nécessite les mêmes autorisations, détenues par le compte de service de l'instance plutôt que par une clé que vous fournissez.

Les clés HMAC de Google Cloud Storage s'authentifient via l'API d'interopérabilité S3, elles nécessitent donc les autorisations AWS S3 listées ci-dessus plutôt que les autorisations `storage.*`.

Les autorisations pour les autres fournisseurs compatibles S3 varient selon le fournisseur. Configurez votre fournisseur avec des autorisations de lecture et d'écriture équivalentes aux autorisations AWS S3 listées ci-dessus.

### Identifiants par défaut de l'application {#application-default-credentials}

Google Cloud Storage avec ADC s'authentifie en tant que compte de service de l'instance qui exécute GitLab, et non en tant qu'utilisateur qui démarre le transfert. Étant donné que ce compte de service est généralement plus privilégié que n'importe quel utilisateur individuel, GitLab limite les transferts ADC aux administrateurs et aux buckets dont le nom commence par `gitlab-offline-transfer-`.

Un administrateur doit également activer ADC pour l'instance. Pour les implications en matière de sécurité et la liste complète des restrictions, consultez [Autoriser les identifiants par défaut de l'application pour le transfert hors ligne](../../../administration/settings/import_and_export_settings.md#allow-application-default-credentials-for-offline-transfer).

## Éléments migrés {#migrated-items}

{{< history >}}

- L'import des appartenances aux groupes et aux projets a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/538356) dans GitLab 19.5.

{{< /history >}}

Le transfert hors ligne importe les mêmes éléments de groupe et de projet que la migration par transfert direct. Pour la liste complète, consultez [les éléments de groupe migrés](../../group/import/migrated_items.md#migrated-group-items) et [les éléments de projet migrés](../../group/import/migrated_items.md#migrated-project-items).

Les éléments suivants ne sont pas importés par le transfert hors ligne :

- Wikis. La prise en charge de l'import des wikis est proposée dans le [work item 538858](https://gitlab.com/gitlab-org/gitlab/-/work_items/538858).
- Snippets. La prise en charge de l'import des snippets est proposée dans le [work item 538347](https://gitlab.com/gitlab-org/gitlab/-/work_items/538347).
- Badges. La prise en charge de l'import des badges est proposée dans le [work item 538355](https://gitlab.com/gitlab-org/gitlab/-/work_items/538355).

Lorsque vous importez un groupe, ses sous-groupes et projets sont toujours importés s'ils sont présents dans l'export.

## Correspondance des contributions utilisateur {#user-contribution-mapping}

Le transfert hors ligne ne crée jamais de véritables utilisateurs sur l'instance de destination. Au lieu de cela, les contributions importées sont associées à des [utilisateurs de substitution](../../import/mapping/post_migration_mapping.md#placeholder-users). Une fois l'import terminé, [réaffectez les utilisateurs de substitution](../../import/mapping/reassignment.md) aux utilisateurs de l'instance de destination.

Le transfert hors ligne importe les appartenances aux groupes et aux projets en tant qu'appartenances de substitution. Lorsque vous réaffectez des utilisateurs de substitution, GitLab réaffecte leurs appartenances aux utilisateurs correspondants.

## Règles de visibilité {#visibility-rules}

Le transfert hors ligne applique les mêmes règles de visibilité que la migration par transfert direct. Pour plus d'informations, consultez [les règles de visibilité](../../group/import/_index.md#visibility-rules).

## Portée de l'export et de l'import de groupe {#group-export-and-import-scope}

GitLab exporte des structures de groupes entières, chaque sous-groupe et projet descendant, quel que soit le niveau d'imbrication. Vous ne pouvez pas exporter un sous-ensemble des sous-groupes ou des projets d'un groupe.

GitLab peut importer un sous-ensemble d'un groupe exporté. Si vous souhaitez migrer un groupe en plusieurs vagues :

1. Exportez le groupe entier une seule fois.
1. Choisissez quels sous-groupes et projets inclure pour chaque vague lors de l'import.

Vous pouvez également exporter des projets individuels au lieu de leur groupe parent, en indiquant le chemin complet de chaque projet comme entité distincte dans la requête d'export.

## Migrer un groupe ou un projet {#migrate-a-group-or-project}

Prérequis :

- Pour exporter un projet, vous devez disposer au minimum du rôle Maintainer pour le projet.
- Pour exporter un groupe, vous devez disposer du rôle Owner pour le groupe.
- Pour importer dans un groupe, vous devez disposer du rôle Owner pour le groupe de destination.
- Pour importer un groupe en tant que groupe principal, vous devez disposer de l'autorisation de créer des groupes.
- Pour utiliser les identifiants par défaut de l'application pour un export ou un import, vous devez disposer d'un accès administrateur.

Pour migrer un groupe ou un projet :

1. Sur l'instance source, utilisez l'API REST pour [créer un export de transfert hors ligne](https://api.gitlab.com/rest/#gitlab/tag/offline-transfers/POST/api/v4/offline_exports) vers un bucket de stockage d'objets.
1. Une fois l'export terminé, GitLab vous envoie un e-mail avec le préfixe d'export. Vous avez besoin de ce préfixe pour démarrer l'import. Si vous ne recevez pas l'e-mail, le préfixe d'export peut être consulté dans le service de stockage d'objets.
1. Si l'instance de destination ne peut pas accéder au bucket d'export, déplacez les fichiers d'export vers un bucket auquel la destination peut accéder.
1. Sur l'instance de destination, [créez un import de transfert hors ligne](https://api.gitlab.com/rest/#gitlab/tag/offline-transfers/POST/api/v4/offline_imports) depuis le bucket et le préfixe d'export.
1. Surveillez l'import avec l'[API de migration de groupes et de projets par transfert direct](../../../api/bulk_imports.md#retrieve-a-group-or-project-migration).

## Importer un export entier {#import-an-entire-export}

Par défaut, un import de transfert hors ligne nécessite un tableau `entities` qui liste chaque groupe ou projet à importer et où le placer. Vous pouvez à la place passer un objet `import_all` pour importer chaque groupe principal de l'export, avec ses sous-groupes et projets, en recréant la structure de l'instance source sous un espace de nommage de destination. Exactement l'un de `entities` ou `import_all` est requis.

Pour importer un export entier, passez `import_all` avec un attribut `destination_namespace` à l'API [créer un import de transfert hors ligne](https://api.gitlab.com/rest/#tag/offline-transfers/POST/api/v4/offline_imports) :

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --header "Content-Type: application/json" \
  --url "https://gitlab.example.com/api/v4/offline_imports" \
  --data '{
    "bucket": "example-bucket",
    "export_prefix": "example-export-prefix",
    "aws_s3_configuration": {
      "aws_access_key_id": "<aws_access_key_id>",
      "aws_secret_access_key": "<aws_secret_access_key>",
      "region": "us-east-1"
    },
    "import_all": {
      "destination_namespace": "dest-group"
    }
  }'
```

Définissez `destination_namespace` sur le chemin complet d'un groupe existant, par exemple `dest-group/subgroup`, pour recréer la structure sous ce groupe. Définissez-le sur une chaîne vide (`""`) pour recréer la structure en tant que nouveaux groupes principaux.

Seuls les groupes principaux sont importés :

- Si l'export contient un chemin dont le groupe principal n'a pas lui-même été exporté (par exemple, l'export contient `group-a/subgroup-b` mais pas `group-a`), GitLab ignore ce chemin au lieu de créer le groupe parent manquant.
- Si le chemin d'un groupe principal est en conflit avec un groupe existant dans l'espace de nommage de destination, GitLab ignore ce groupe et tout ce qui se trouve en dessous. Le reste de l'export est tout de même importé.
- Si chaque groupe principal entre en conflit avec un chemin de destination existant, l'import échoue.
- Si l'export ne contient aucun groupe principal, l'import échoue.

Surveillez l'import avec l'[API de migration de groupes et de projets par transfert direct](../../../api/bulk_imports.md#retrieve-a-group-or-project-migration).

## Limites de débit {#rate-limits}

Les exports et imports de transfert hors ligne sont soumis à des limites de débit. Pour plus d'informations, consultez [les limites de débit non configurables](../../../rate_limits/non_configurable.md).

## Limites de taille de fichier {#file-size-limits}

Les imports de transfert hors ligne appliquent la même taille maximale de téléchargement de fichier que la migration par transfert direct. Cette limite s'applique à chaque fichier de relation individuellement, de sorte qu'un bundle de dépôt volumineux peut l'atteindre même lorsque le reste de la migration est en dessous de la limite. Étant donné que GitLab vérifie la limite lors de l'import, un fichier qui la dépasse échoue uniquement après que vous avez déjà déplacé l'export vers l'environnement de destination.

Si votre migration inclut des dépôts volumineux, demandez à un administrateur sur l'instance de destination d'augmenter cette limite avant de démarrer l'import. Pour plus d'informations, consultez [la taille maximale de téléchargement de fichier pour les imports par transfert direct ou hors ligne](../../../administration/settings/import_and_export_settings.md#maximum-download-file-size-for-imports-by-direct-or-offline-transfer).

## Cycle de vie du bucket de stockage d'objets {#object-storage-bucket-lifecycle}

GitLab ne supprime pas les fichiers d'export du bucket après la fin d'un import. Les exports incluent des bundles de dépôt, des objets LFS, des fichiers téléversés et des bundles de conception, ainsi que des fichiers JSON délimités par des sauts de ligne (NDJSON) contenant les descriptions et les notes des tickets et des merge requests. Traitez le bucket avec les mêmes contrôles de gestion des données et de résidence que ceux que vous appliquez au reste de vos données GitLab.

La conservation et la suppression des fichiers d'export après une migration sont de votre responsabilité.

## Sujets connexes {#related-topics}

- [Migrer des groupes et des projets par transfert direct](../../group/import/direct_transfer_migrations.md)

## Dépannage {#troubleshooting}

Si vous rencontrez des problèmes avec une migration effectuée par transfert hors ligne, consultez les sections suivantes pour des solutions possibles.

### Effacer les données d'export du stockage d'objets {#clear-export-data-from-object-storage}

Chaque export génère un nouveau préfixe dans le stockage d'objets, de sorte qu'un export n'en écrase pas un autre. La suppression des données stockées des exports ayant échoué n'est pas nécessaire pour réessayer l'export, mais peut réduire vos coûts de stockage d'objets.

Pour supprimer les données d'export du stockage d'objets, utilisez le bucket que vous avez fourni et le `export_prefix` retourné par l'API d'export pour identifier et supprimer les données. En fonction de votre configuration de stockage d'objets, cette opération peut être irréversible.

### Identifier les erreurs d'import {#identify-import-errors}

- Examinez `exceptions_json.log` et `importer.log` pour détecter les erreurs pertinentes.
- Consultez [Dépannage des migrations par transfert direct](../../group/import/troubleshooting.md) pour obtenir des conseils sur l'extraction des erreurs depuis la console Rails.

### Réessayer un import {#retry-an-import}

Pour réessayer un import :

1. Supprimez les groupes ou les projets que vous souhaitez réessayer. Vous pouvez réessayer l'import entier ou cibler un sous-ensemble de groupes ou de projets :

   - [Supprimer un groupe immédiatement](../../group/_index.md#delete-a-group-immediately)
   - [Supprimer un projet immédiatement](../../project/working_with_projects.md#delete-a-project-immediately)

1. Utilisez l'API REST pour réessayer l'import entier ou spécifier uniquement les entités ayant précédemment échoué dans le paramètre `entities`.
