---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Migrer des groupes et des projets par transfert direct
description: "Migrer des groupes et des projets entre des instances GitLab par transfert direct."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour migrer des groupes et des projets GitLab par transfert direct :

1. Assurez-vous de remplir les [prérequis](#prerequisites).
1. Consultez le mappage des [contributions des utilisateurs](../../import/mapping/post_migration_mapping.md) et des [appartenances des utilisateurs](#user-membership-mapping).
1. [Connectez l'instance GitLab source](#connect-the-source-gitlab-instance).
1. [Sélectionnez les groupes et les projets à importer](#select-the-groups-and-projects-to-import) et lancez la migration.
1. [Consultez les résultats de l'importation](#review-results-of-the-import).

En cas de problème, vous pouvez :

1. [Annuler](#cancel-a-running-migration) ou [réessayer](#retry-failed-or-partially-successful-migrations) la migration.
1. Consultez la [documentation de dépannage](troubleshooting.md).

## Prérequis {#prerequisites}

{{< history >}}

- Le renommage des titres de jalons pour éviter les conflits sur les instances de destination a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/221447) dans GitLab 18.6.7 et versions ultérieures, 18.7.5 et versions ultérieures, et 18.8.5 et versions ultérieures.

{{< /history >}}

Avant de migrer par transfert direct, consultez les prérequis suivants.

### Réseau et espace de stockage {#network-and-storage-space}

- La connexion réseau entre les instances ou GitLab.com doit prendre en charge HTTPS.
- Les pare-feux ne doivent pas bloquer la connexion entre les instances GitLab source et de destination.
- Les instances GitLab source et de destination doivent disposer de suffisamment d'espace libre dans le répertoire `/tmp` pour créer et extraire les archives des projets et des groupes transférés.

### Versions {#versions}

Pour maximiser les chances d'une migration réussie et performante :

- Mettez à niveau les instances source et de destination vers GitLab 16.8 ou une version ultérieure. Pour plus d'informations, consultez l'[epic 9036](https://gitlab.com/groups/gitlab-org/-/epics/9036).
- Effectuez la migration entre des versions aussi récentes que possible pour bénéficier des corrections de bugs et des autres améliorations.

Si les instances source et de destination ne sont pas à la même version, l'instance source ne doit pas être antérieure de plus de deux versions [mineures](../../../policy/maintenance.md#versioning) par rapport à l'instance de destination. Cette exigence ne s'applique pas aux migrations de GitLab.com vers GitLab Dedicated.

### Configuration {#configuration}

- Assurez-vous que [Sidekiq est correctement configuré](../../../administration/sidekiq/configuration_for_imports.md).
- Les deux instances GitLab doivent avoir la migration de groupe par transfert direct [activée dans les paramètres de l'application](../../../administration/settings/import_and_export_settings.md#enable-migration-of-groups-and-projects-by-direct-transfer) par un administrateur d'instance.
- Vous devez disposer d'un [jeton d'accès personnel](../../profile/personal_access_tokens.md) pour l'instance GitLab source avec la portée `api`.
- Vous devez disposer des autorisations requises sur les instances source et de destination. Pour :
  - La plupart des utilisateurs, vous avez besoin :
    - Du rôle Owner sur le groupe source à partir duquel effectuer la migration.
    - D'un rôle dans l'espace de nommage de destination qui vous permet de [créer un sous-groupe](../subgroups/_index.md#create-a-subgroup) dans cet espace de nommage.
  - Pour les administrateurs des deux instances ne disposant pas des rôles requis, vous pouvez à la place démarrer l'importation en utilisant [l'API](../../../api/bulk_imports.md#start-a-group-or-project-migration).
- Pour importer des extraits de code de projet, assurez-vous que les extraits de code sont [activés dans le projet source](../../snippets.md#change-default-visibility-of-snippets).
- Pour importer des éléments stockés dans un système de stockage d'objets, vous devez soit :
  - [Configurer `proxy_download`](../../../administration/object_storage.md#configure-the-common-parameters).
  - Vous assurer que l'instance GitLab de destination a accès au stockage d'objets de l'instance GitLab source.
- Vous ne pouvez pas importer des groupes avec des projets lorsque l'instance ou le groupe source a le paramètre **Rôle minimal par défaut requis pour créer des projets** défini sur **Personne**. Si nécessaire, ce paramètre peut être modifié :
  - Pour [une instance entière](../../../administration/settings/visibility_and_access_controls.md#define-which-roles-can-create-projects).
  - Pour [des groupes spécifiques](../_index.md#specify-who-can-add-projects-to-a-group).
- Les jalons importés dont les titres [correspondent à des jalons existants](../../project/milestones/_index.md#milestone-title-rules) dans l'espace de nommage de destination auront leurs titres mis à jour lors de l'importation. Le nouveau titre sera complété par un suffixe unique, par exemple `18.0` deviendra `18.0
  (imported-3d-1770206299)`. Pour éviter cela, renommez le jalon dans le groupe ou le projet source avant de lancer un transfert direct.
- Assurez-vous que :
  - Les espaces de nommage source et de destination appartiennent à la même organisation.
  - Lorsque les espaces de nommage source et de destination appartiennent à des organisations différentes, qu'aucune des organisations n'est marquée comme isolée.

## Mappage des appartenances des utilisateurs {#user-membership-mapping}

{{< history >}}

- Le mappage des membres hérités a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/458834) dans GitLab 17.1.
- Le mappage initial des appartenances des utilisateurs vers des utilisateurs de substitution a été [introduit](https://gitlab.com/groups/gitlab-org/-/epics/12378) dans GitLab 17.3 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `bulk_import_importer_user_mapping`. Fonctionnalité désactivée par défaut.
- Le mappage initial des appartenances des utilisateurs vers des utilisateurs de substitution a été [activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/478054) dans GitLab 17.5.
- Le mappage initial des appartenances des utilisateurs vers des utilisateurs de substitution a été [activé sur GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/478054) dans GitLab 17.7.
- Le mappage initial des appartenances des utilisateurs vers des utilisateurs de substitution est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/508945) dans GitLab 18.4. Le feature flag `bulk_import_importer_user_mapping` a été supprimé.

{{< /history >}}

Les utilisateurs ne sont jamais créés lors d'une migration. À la place, les appartenances des utilisateurs sur l'instance source sont mappées aux utilisateurs de l'instance de destination. Le type de mappage des appartenances des utilisateurs dépend du [type d'appartenance](../../project/members/_index.md#membership-types) sur l'instance source :

- Les appartenances importées sont initialement mappées à des [utilisateurs de substitution](../../import/mapping/post_migration_mapping.md#placeholder-users).
- Les appartenances directes sont mappées en tant qu'appartenances directes sur l'instance de destination.
- Les appartenances héritées sont mappées en tant qu'appartenances héritées sur l'instance de destination.
- Les appartenances partagées sont mappées en tant qu'appartenances directes sur l'instance de destination, sauf si l'utilisateur dispose déjà d'une appartenance partagée. La prise en charge complète du mappage des appartenances partagées est proposée dans l'[issue 458345](https://gitlab.com/gitlab-org/gitlab/-/issues/458345).

[Dans GitLab 18.4 et versions ultérieures](https://gitlab.com/gitlab-org/gitlab/-/issues/559224), lorsque vous créez des appartenances directes lors de l'importation d'un projet directement dans un groupe existant, le [paramètre **Les utilisateurs ne peuvent pas être ajoutés aux projets de ce groupe**](../access_and_permissions.md#prevent-members-from-being-added-to-projects-in-a-group) est respecté.

Lors du mappage des appartenances [héritées et partagées](../../project/members/_index.md#membership-types), si l'utilisateur dispose d'une appartenance existante dans l'espace de nommage de destination avec un [rôle supérieur](../../permissions.md#roles) à celui qui est mappé, l'appartenance est mappée en tant qu'appartenance directe à la place. Cela garantit que le membre n'obtient pas de permissions élevées.

> [!note]
> Il existe un [problème connu](_index.md#known-issues) affectant le mappage des appartenances partagées.

### Configurer les utilisateurs sur l'instance de destination {#configure-users-on-destination-instance}

Pour vous assurer que GitLab mappe correctement les utilisateurs et leurs contributions entre les instances source et de destination :

1. Créez les utilisateurs requis sur l'instance GitLab de destination. Vous pouvez créer des utilisateurs avec l'API uniquement sur les instances GitLab Self-Managed, car cela nécessite un accès administrateur. Lors de la migration vers GitLab.com ou GitLab Self-Managed, vous pouvez :
   - Créer des utilisateurs manuellement.
   - Configurer ou utiliser votre [fournisseur SSO SAML](../saml_sso/_index.md) existant et tirer parti de la synchronisation des utilisateurs des groupes SSO SAML prise en charge via [SCIM](../saml_sso/scim_setup.md). Vous pouvez [contourner la vérification du compte utilisateur GitLab avec des domaines de messagerie vérifiés](../saml_sso/_index.md#bypass-user-email-confirmation-with-verified-domains).
1. Assurez-vous que les utilisateurs disposent d'une [adresse e-mail publique](../../profile/_index.md#set-your-public-email) sur l'instance GitLab source qui correspond à toute adresse e-mail confirmée sur l'instance GitLab de destination. La plupart des utilisateurs reçoivent un e-mail leur demandant de confirmer leur adresse e-mail.
1. Si des utilisateurs existent déjà sur l'instance de destination et que vous utilisez [SSO SAML pour les groupes GitLab.com](../saml_sso/_index.md), tous les utilisateurs doivent [lier leur identité SAML à leur compte GitLab.com](../saml_sso/_index.md#link-saml-to-your-existing-gitlabcom-account).

Il n'existe aucun moyen dans l'interface utilisateur GitLab ou l'API de définir automatiquement des adresses e-mail publiques pour les utilisateurs. Si vous devez configurer un grand nombre de comptes utilisateurs avec des adresses e-mail publiques, consultez l'[issue 284495](https://gitlab.com/gitlab-org/gitlab/-/issues/284495#note_1910159855) pour une solution de contournement potentielle.

## Connecter l'instance GitLab source {#connect-the-source-gitlab-instance}

Sur l'instance GitLab de destination, créez le groupe vers lequel vous souhaitez importer et connectez l'instance GitLab source :

1. Créez :
   - Un nouveau groupe. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau groupe**. Puis sélectionnez **Importer un groupe**.
   - Un nouveau sous-groupe. Sur la page du groupe existant, soit :
     - Sélectionnez **Créer un sous-groupe**.
     - Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau sous-groupe**. Puis sélectionnez le lien **importer un groupe existant**.
1. Saisissez l'URL de base d'une instance GitLab.
1. Saisissez le [jeton d'accès personnel](../../profile/personal_access_tokens.md) de votre instance GitLab source.
1. Sélectionnez **Se connecter à l'instance**.

## Sélectionner les groupes et les projets à importer {#select-the-groups-and-projects-to-import}

{{< history >}}

- La case à cocher **Importer les appartenances des utilisateurs** a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/477734) dans GitLab 17.6.

{{< /history >}}

Une fois que vous avez autorisé l'accès à l'instance GitLab source, vous êtes redirigé vers la page d'importation de groupe GitLab. Vous pouvez y voir la liste des groupes principaux sur l'instance source connectée où vous avez le rôle Owner.

Si vous ne souhaitez pas importer toutes les appartenances des utilisateurs depuis l'instance source, assurez-vous que la case **Importer les appartenances des utilisateurs** est décochée. Par exemple, l'instance source peut avoir 200 membres, mais vous ne souhaitez peut-être en importer que 50. Une fois l'importation terminée, vous pouvez ajouter d'autres membres aux groupes et aux projets.

1. Par défaut, les espaces de nommage de groupe proposés correspondent aux noms tels qu'ils existent dans l'instance source, mais selon vos autorisations, vous pouvez choisir de modifier ces noms avant de procéder à leur importation. Les chemins des groupes et des projets doivent être conformes aux [règles de nommage](../../reserved_names.md#rules-for-usernames-project-and-group-names-and-slugs) et sont normalisés si nécessaire pour éviter les échecs d'importation.
1. En regard des groupes que vous souhaitez importer, sélectionnez :
   - **Importer avec les projets**. Si cette option n'est pas disponible, consultez les [prérequis](#prerequisites).
   - **Importer sans les projets**.
1. La colonne **Statut** affiche le statut d'importation de chaque groupe. Si vous laissez la page ouverte, elle se met à jour en temps réel.
1. Une fois qu'un groupe a été importé, sélectionnez son chemin GitLab pour ouvrir son URL GitLab.

## Consulter les résultats de l'importation {#review-results-of-the-import}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/443492) dans GitLab 17.0, un badge **Importé** pour indiquer que les designs, les epics, les tickets, les merge requests, les notes (notes système et commentaires), les extraits de code et l'activité du profil utilisateur ont été importés.

{{< /history >}}

Pour consulter les résultats d'une importation :

1. Accédez à la [page d'historique d'importation de groupe](#group-import-history).
1. Pour voir les détails d'une importation ayant échoué, sélectionnez le lien **Afficher les erreurs** sur toute importation ayant un statut **Échec** ou **Terminé partiellement**.
1. Si l'importation a un statut **Terminé partiellement** ou **Terminé**, pour voir quels éléments ont été importés et lesquels ne l'ont pas été, sélectionnez **Afficher les détails**.

Vous pouvez également voir qu'un élément a été importé lorsque vous voyez un badge **Importé** sur certains éléments de l'interface utilisateur GitLab.

## Historique d'importation de groupe {#group-import-history}

Vous pouvez consulter tous les groupes migrés par vous par transfert direct répertoriés sur la page d'historique d'importation de groupe. Cette liste comprend :

- Les chemins des groupes source.
- Les chemins des groupes de destination.
- La date de début de chaque importation.
- Le statut de chaque importation.
- Les détails des erreurs si des erreurs se sont produites.

Pour consulter l'historique d'importation de groupe :

1. Connectez-vous à GitLab.
1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau groupe**.
1. Sélectionnez **Importer un groupe**.
1. Dans le coin supérieur droit, sélectionnez **Afficher l'historique des importations**.
1. S'il y a des erreurs pour une importation particulière, sélectionnez **Afficher les erreurs** pour voir leurs détails.

## Annuler une migration en cours {#cancel-a-running-migration}

Si nécessaire, vous pouvez annuler une migration en cours en utilisant soit l'API REST, soit une console Rails.

### Annuler avec l'API REST {#cancel-with-the-rest-api}

Pour obtenir des informations sur l'annulation d'une migration en cours avec l'API REST, consultez [annuler une migration](../../../api/bulk_imports.md#cancel-a-migration).

### Annuler avec une console Rails {#cancel-with-a-rails-console}

Pour annuler une migration en cours avec une console Rails :

1. Démarrez une [session de console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session) sur l'instance GitLab de destination.
1. Trouvez la dernière importation en exécutant la commande suivante. Remplacez `USER_ID` par l'identifiant utilisateur de l'utilisateur qui a lancé l'importation :

   ```ruby
   bulk_import = BulkImport.where(user_id: USER_ID).last
   ```

1. Faites échouer l'importation et tous les éléments qui lui sont associés en exécutant la commande suivante :

   ```ruby
   bulk_import.entities.each do |entity|
     entity.trackers.each do |tracker|
       tracker.batches.each(&:fail_op!)
     end
     entity.trackers.each(&:fail_op!)
     entity.fail_op!
   end
   bulk_import.fail_op!
   ```

L'annulation d'un `bulk_import` n'arrête pas les workers qui exportent le projet sur l'instance source, mais empêche l'instance de destination de :

- Demander à l'instance source d'exporter d'autres projets.
- Effectuer d'autres appels API à l'instance source pour diverses vérifications et informations.

## Réessayer les migrations ayant échoué ou partiellement réussies {#retry-failed-or-partially-successful-migrations}

Si vos migrations échouent, ou réussissent partiellement mais que des éléments sont manquants, vous pouvez réessayer la migration. Pour réessayer la migration d'un groupe principal et de tous ses sous-groupes et projets, ou de sous-groupes ou projets spécifiques, utilisez l'interface utilisateur GitLab ou l'[API de migration de groupes et de projets par transfert direct](../../../api/bulk_imports.md).
