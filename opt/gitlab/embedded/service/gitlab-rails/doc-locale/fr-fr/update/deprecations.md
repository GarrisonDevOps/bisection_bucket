---
stage: none
group: none
info: "To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>"
toc: false
title: Dépréciations et suppressions par version
---

Les fonctionnalités GitLab suivantes sont dépréciées et ne sont plus recommandées.

- Chaque fonctionnalité dépréciée sera supprimée dans une prochaine release.
- Certaines fonctionnalités entraînent des changements importants lors de leur suppression.
- Sur GitLab.com, les fonctionnalités dépréciées peuvent être supprimées à tout moment durant le mois précédant la release.
- Pour consulter la documentation d'une fonctionnalité supprimée, voir [l'archive GitLab Docs](https://docs.gitlab.com/archives/).
- Pour les dépréciations de l'API GraphQL, vous devriez [vérifier que vos appels API fonctionnent sans les éléments dépréciés](../api/graphql/_index.md#verify-against-the-future-breaking-change-schema).

Pour effectuer des recherches et des filtrages avancés de ces informations de dépréciation, essayez [un outil conçu par notre équipe Customer Success](https://gitlab-com.gitlab.io/cs-tools/gitlab-cs-tools/what-is-new-since/?tab=deprecations).

[Les dépréciations de l'API REST](../api/rest/deprecations.md) sont documentées séparément.

{{< icon name="rss" >}} **Pour être notifié des prochains changements importants**, ajoutez cette URL à votre lecteur de flux RSS : `https://docs.gitlab.com/releases/breaking-changes.xml`

<!-- vale off -->
<!--
DO NOT EDIT THIS PAGE DIRECTLY

This page is automatically generated from the template located at
`data/deprecations/templates/_deprecation_template.md.erb`, using
the YAML files in `/data/deprecations` by the Rake task
located at `lib/tasks/gitlab/docs/compile_deprecations.rake`,

For deprecation authors (usually Product Managers and Engineering Managers):

- To add a deprecation, use the example.yml file in `/data/deprecations/templates` as a template.
- For more information about authoring deprecations, check the deprecation item guidance:
  <https://handbook.gitlab.com/handbook/marketing/blog/release-posts/#update-the-deprecations-doc>

For deprecation reviewers (Technical Writers only):

- To update the deprecation doc, run: `bin/rake gitlab:docs:compile_deprecations`
- To verify the deprecations doc is up to date, run: `bin/rake gitlab:docs:check_deprecations`
- For more information about updating the deprecation doc, see the deprecation doc update guidance:
  <https://handbook.gitlab.com/handbook/marketing/blog/release-posts/#update-the-deprecations-doc>
-->

## GitLab 21.0 {#gitlab-210}

### Points de terminaison de la passerelle d'IA Code Suggestions v2 et v3 {#code-suggestions-v2-and-v3-ai-gateway-endpoints}

- Annoncé dans GitLab 19.5
- Suppression dans GitLab 21.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/605661).

Les points de terminaison de la passerelle d'IA `/v2/completions`, `/v2/code/completions`, `/v2/code/generations` et `/v3/code/completions` sont dépréciés dans GitLab 19.5 et seront supprimés dans GitLab 21.0. Les requêtes Code Suggestions doivent utiliser `/v4/code/suggestions` à la place.

GitLab.com utilise `/v4/code/suggestions` depuis GitLab 19.1. Aucune action n'est requise pour GitLab.com.

GitLab Self-Managed, GitLab Dedicated et les extensions d'éditeur GitLab passeront au point de terminaison v4 dans les prochaines releases. Pour suivre les versions qui incluent ce changement, voir le [ticket 605661](https://gitlab.com/gitlab-org/gitlab/-/issues/605661). Si vous exécutez une passerelle d'IA auto-hébergée, l'image de la passerelle d'IA pour GitLab 21.0 supprime également ces points de terminaison.

Pour éviter toute interruption, avant la sortie de GitLab 21.0 :

- Mettez à niveau votre instance vers la dernière version de GitLab.
- Mettez à jour vos extensions d'éditeur vers la dernière version.
- Mettez à jour tous les clients personnalisés qui appellent directement la passerelle d'IA pour utiliser `/v4/code/suggestions`.

## GitLab 20.0 {#gitlab-200}

### Pipelines de conformité {#compliance-pipelines}

- Annoncé dans GitLab 17.3
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/epics/11275).

Actuellement, il existe deux façons de s'assurer que les jobs liés à la conformité ou à la sécurité sont exécutés dans un pipeline de projet :

- [Pipelines de conformité](https://docs.gitlab.com/user/compliance/compliance_pipelines/).
- [Politiques de sécurité](https://docs.gitlab.com/user/application_security/policies/).

Pour fournir un emplacement unique permettant de garantir que les jobs requis sont exécutés dans tous les pipelines d'un projet, nous avons déprécié les pipelines de conformité dans GitLab 17.3 et supprimerons la fonctionnalité dans GitLab 20.0.

Les clients doivent migrer des pipelines de conformité vers le nouveau [type de politique d'exécution de pipeline](https://docs.gitlab.com/user/application_security/policies/pipeline_execution_policies/) dès que possible.

Pour plus d'informations, consultez les éléments pertinents :

- [Guide de migration](https://docs.gitlab.com/user/compliance/compliance_pipelines/#pipeline-execution-policies-migration).
- [Article de blog](https://about.gitlab.com/blog/why-gitlab-is-deprecating-compliance-pipelines-in-favor-of-security-policies/).

### Le proxy de dépendances pour les paquets est déprécié {#dependency-proxy-for-packages-is-deprecated}

- Annoncé dans GitLab 19.1
- Suppression dans GitLab 20.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/601255).

Le proxy de dépendances pour les paquets est déprécié et sera supprimé dans une prochaine release. Cette fonctionnalité a été remplacée par le **registre virtuel Maven**, qui offre de meilleures performances, de meilleures capacités de proxy et de mise en cache en amont, ainsi qu'une intégration plus poussée avec les workflows de gestion des paquets de GitLab.

**Action requise :** Migrez la configuration de votre gestionnaire de paquets des points de terminaison du proxy de dépendances vers le registre virtuel Maven. Consultez la [documentation du registre virtuel Maven](https://docs.gitlab.com/user/packages/virtual_registry/maven/) pour les instructions de configuration.

### Dépréciation de `previousStageJobs` dans GraphQL {#deprecate-previousstagejobs-from-graphql}

- Annoncé dans GitLab 19.2
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/603950).

Le champ `previousStageJobs` dans le type GraphQL `CiJob` est déprécié et sera supprimé dans GitLab 20.0. Aucune alternative côté serveur n'est nécessaire, car l'interface utilisateur de GitLab n'a plus besoin de `previousStageJobs` pour calculer les dépendances.

### Design Management déprécié {#design-management-deprecated}

- Annoncé dans GitLab 18.6
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/work_items/20375).

Dans GitLab 20.0, GitLab commencera la dépréciation de Design Management. Design Management permet aux utilisateurs de charger des ressources de conception telles que des maquettes et des prototypes dans des tickets GitLab à des fins de collaboration. Nous avons pris cette décision après un examen attentif de l'utilisation existante et de l'impact estimé sur les clients. La maintenance continue requise pour Design Management surpassait l'utilisation actuelle, et nous concentrons nos efforts sur des solutions mieux adaptées aux workflows des concepteurs modernes. Dans GitLab 20.0 et les versions ultérieures, les utilisateurs ne pourront plus charger de nouveaux designs. Les designs existants resteront disponibles en mode lecture seule jusqu'à GitLab 21.0, laissant aux utilisateurs le temps de sauvegarder leurs designs si nécessaire. GitLab explore des alternatives qui s'intègrent mieux aux outils que les concepteurs utilisent déjà.

### Imposer la pagination par jeu de clés sur l'API des événements d'audit {#enforce-keyset-pagination-on-audit-event-api}

- Annoncé dans GitLab 17.8
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/382338).

Les API Événement d'audit pour les instances, les groupes et les projets prennent actuellement en charge la pagination par jeu de clés en option. Dans GitLab 20.0, nous imposerons la pagination par jeu de clés sur ces API.

### Valeur du chart Helm GitLab `gitlab.kas.ingress.grpc.enabled` {#gitlab-helm-chart-value-gitlabkasingressgrpcenabled}

- Annoncé dans GitLab 19.5
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/charts/gitlab/-/work_items/6663).

Dans le chart Helm GitLab, l'entrée gRPC KAS est désormais contrôlée par `global.kas.ingress.grpc.enabled`, qui décide également si l'adresse annoncée à l'agent pour Kubernetes utilise le gRPC natif (`grpcs://`) ou WebSocket (`wss://`).

La valeur locale `gitlab.kas.ingress.grpc.enabled` du chart `kas` est dépréciée et sera supprimée dans le chart 11.0 (GitLab 20.0). Elle contrôle toujours si l'entrée gRPC est rendue, mais les autres charts ne peuvent pas la voir lors du calcul de l'adresse annoncée, ce qui peut entraîner un désaccord entre l'entrée et l'adresse.

Si vous définissez `gitlab.kas.ingress.grpc.enabled`, déplacez la valeur vers `global.kas.ingress.grpc.enabled` avant de mettre à niveau vers le chart 11.0. Laisser les deux non définis conserve la valeur par défaut. L'entrée gRPC est rendue pour le fournisseur d'entrée NGINX, et les agents sont dirigés vers `grpcs://` lorsque le chart achemine le gRPC vers KAS.

### Le proxy de module Go (expérimental) est déprécié {#go-module-proxy-experimental-is-deprecated}

- Annoncé dans GitLab 19.1
- Suppression dans GitLab 20.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/592132).

Le proxy de module Go expérimental dans le registre de paquets GitLab est déprécié et sera supprimé dans GitLab 20.0. Cette fonctionnalité n'a jamais dépassé le statut expérimental.

Elle sera remplacée par un **registre virtuel Go**, qui offrira une expérience plus complète et plus fiable pour la résolution des modules Go via GitLab.

**Action requise :** Si vous utilisez GitLab comme proxy de module Go, prévoyez de migrer vers le registre virtuel Go dès qu'il sera disponible. En attendant, vous pouvez configurer un proxy alternatif (tel que `proxy.golang.org` ou une solution auto-hébergée) en mettant à jour votre variable d'environnement `GOPROXY`.

### Préférence utilisateur GraphQL `useWorkItemsView` {#graphql-useworkitemsview-user-preference}

- Annoncé dans GitLab 19.5
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/550770).

Le champ `useWorkItemsView` sur le type `UserPreferences` et l'argument `useWorkItemsView` sur la mutation `userPreferencesUpdate` sont dépréciés dans GitLab 19.5 et seront supprimés dans GitLab 20.0. La migration des tickets vers les éléments de travail est terminée et la vue des éléments de travail est toujours utilisée, rendant cette préférence inutile. Depuis GitLab 19.5, l'argument est accepté mais ignoré, et le champ retourne toujours `true`. Supprimez l'argument de vos mutations et le champ de vos requêtes. Il n'existe pas de remplacement.

### Les raisons d'échec héritées `retry:when` `stuck_or_timeout_failure` et `job_execution_timeout` sont dépréciées {#legacy-retrywhen-failure-reasons-stuck_or_timeout_failure-and-job_execution_timeout-are-deprecated}

- Annoncé dans GitLab 19.1
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/602133).

Dans GitLab 19.0, les raisons d'échec de job génériques `stuck_or_timeout_failure` et `job_execution_timeout` ont été divisées en un ensemble de raisons plus spécifiques (par exemple, `stuck_pending_no_matching_runners`, `no_updates_running` et `server_timeout_running`). Les nouvelles constructions ne sont plus enregistrées avec les anciennes raisons.

Ces anciennes raisons restent des valeurs valides pour [`retry:when`](https://docs.gitlab.com/ci/yaml/#retrywhen) dans `.gitlab-ci.yml`. Pour éviter de casser silencieusement la configuration existante, lorsque vous listez `stuck_or_timeout_failure` ou `job_execution_timeout` sous `retry:when`, GitLab les traite comme des alias correspondant à l'ensemble complet des raisons spécifiques qui les ont remplacés. GitLab affiche également un avertissement non bloquant dans la sortie du lint CI et dans l'éditeur de pipeline lorsque ces valeurs sont utilisées.

Les deux valeurs sont dépréciées et prévues pour suppression dans GitLab 20.0.

**Action requise :** Mettez à jour `retry:when` pour utiliser les raisons d'échec spécifiques à la place :

- Remplacez `stuck_or_timeout_failure` par le sous-ensemble pertinent de `stuck_pending_with_matching_runners`, `stuck_pending_no_matching_runners`, `no_updates_running` et `no_updates_canceling`.
- Remplacez `job_execution_timeout` par `server_timeout_running` et/ou `server_timeout_canceling`.

### API GraphQL héritées pour les destinations de streaming d'événements d'audit au niveau du groupe {#legacy-group-level-audit-event-streaming-destination-graphql-apis}

- Annoncé dans GitLab 18.10
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/work_items/12339).

Les API GraphQL de niveau groupe suivantes pour les destinations de streaming d'événements d'audit sont dépréciées et seront supprimées dans GitLab 20.0.

Mutations dépréciées :

- `externalAuditEventDestinationCreate` - utilisez `groupAuditEventStreamingDestinationsCreate` à la place.
- `externalAuditEventDestinationDestroy` - utilisez `groupAuditEventStreamingDestinationsDelete` à la place.
- `externalAuditEventDestinationUpdate` - utilisez `groupAuditEventStreamingDestinationsUpdate` à la place.
- `googleCloudLoggingConfigurationCreate` - utilisez `groupAuditEventStreamingDestinationsCreate` avec la catégorie `gcpLogging` à la place.
- `googleCloudLoggingConfigurationDestroy` - utilisez `groupAuditEventStreamingDestinationsDelete` à la place.
- `googleCloudLoggingConfigurationUpdate` - utilisez `groupAuditEventStreamingDestinationsUpdate` à la place.
- `auditEventsAmazonS3ConfigurationCreate` - utilisez `groupAuditEventStreamingDestinationsCreate` avec la catégorie `amazonS3` à la place.
- `auditEventsAmazonS3ConfigurationDelete` - utilisez `groupAuditEventStreamingDestinationsDelete` à la place.
- `auditEventsAmazonS3ConfigurationUpdate` - utilisez `groupAuditEventStreamingDestinationsUpdate` à la place.
- `auditEventsStreamingHeadersCreate` - configurez les en-têtes en utilisant la configuration de destination de streaming via `groupAuditEventStreamingDestinationsUpdate`.
- `auditEventsStreamingHeadersDestroy` - configurez les en-têtes en utilisant la configuration de destination de streaming via `groupAuditEventStreamingDestinationsUpdate`.
- `auditEventsStreamingHeadersUpdate` - configurez les en-têtes en utilisant la configuration de destination de streaming via `groupAuditEventStreamingDestinationsUpdate`.
- `auditEventsStreamingDestinationEventsAdd` - utilisez `auditEventsGroupDestinationEventsAdd` à la place.
- `auditEventsStreamingDestinationEventsRemove` - utilisez `auditEventsGroupDestinationEventsRemove` à la place.
- `auditEventsStreamingHttpNamespaceFiltersAdd` - utilisez `auditEventsGroupDestinationNamespaceFilterCreate` à la place.
- `auditEventsStreamingHttpNamespaceFiltersDelete` - utilisez `auditEventsGroupDestinationNamespaceFilterDelete` à la place.

Champs de groupe dépréciés :

- `Group.externalAuditEventDestinations` - utilisez `Group.externalAuditEventStreamingDestinations` à la place.
- `Group.googleCloudLoggingConfigurations` - utilisez `Group.externalAuditEventStreamingDestinations` avec la catégorie `gcpLogging` à la place.
- `Group.amazonS3Configurations` - utilisez `Group.externalAuditEventStreamingDestinations` avec la catégorie `amazonS3` à la place.

Les nouvelles API unifiées de destination de streaming prennent en charge toutes les catégories de destinations (HTTP, Google Cloud Logging, Amazon S3) via un ensemble unique de points de terminaison avec un paramètre `category`.

### API GraphQL héritées pour les destinations de streaming d'événements d'audit au niveau de l'instance {#legacy-instance-level-audit-event-streaming-destination-graphql-apis}

- Annoncé dans GitLab 18.10
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/work_items/12339).

Les API GraphQL de niveau instance suivantes pour les destinations de streaming d'événements d'audit sont dépréciées et seront supprimées dans GitLab 20.0.

Mutations dépréciées :

- `instanceExternalAuditEventDestinationCreate` - utilisez `instanceAuditEventStreamingDestinationsCreate` à la place.
- `instanceExternalAuditEventDestinationDestroy` - utilisez `instanceAuditEventStreamingDestinationsDelete` à la place.
- `instanceExternalAuditEventDestinationUpdate` - utilisez `instanceAuditEventStreamingDestinationsUpdate` à la place.
- `instanceGoogleCloudLoggingConfigurationCreate` - utilisez `instanceAuditEventStreamingDestinationsCreate` avec la catégorie `gcpLogging` à la place.
- `instanceGoogleCloudLoggingConfigurationDestroy` - utilisez `instanceAuditEventStreamingDestinationsDelete` à la place.
- `instanceGoogleCloudLoggingConfigurationUpdate` - utilisez `instanceAuditEventStreamingDestinationsUpdate` à la place.
- `auditEventsInstanceAmazonS3ConfigurationCreate` - utilisez `instanceAuditEventStreamingDestinationsCreate` avec la catégorie `amazonS3` à la place.
- `auditEventsInstanceAmazonS3ConfigurationDelete` - utilisez `instanceAuditEventStreamingDestinationsDelete` à la place.
- `auditEventsInstanceAmazonS3ConfigurationUpdate` - utilisez `instanceAuditEventStreamingDestinationsUpdate` à la place.
- `auditEventsStreamingInstanceHeadersCreate` - configurez les en-têtes en utilisant la configuration de destination de streaming via `instanceAuditEventStreamingDestinationsUpdate`.
- `auditEventsStreamingInstanceHeadersDestroy` - configurez les en-têtes en utilisant la configuration de destination de streaming via `instanceAuditEventStreamingDestinationsUpdate`.
- `auditEventsStreamingInstanceHeadersUpdate` - configurez les en-têtes en utilisant la configuration de destination de streaming via `instanceAuditEventStreamingDestinationsUpdate`.
- `auditEventsStreamingDestinationInstanceEventsAdd` - utilisez `auditEventsInstanceDestinationEventsAdd` à la place.
- `auditEventsStreamingDestinationInstanceEventsRemove` - utilisez `auditEventsInstanceDestinationEventsRemove` à la place.

Champs de requête dépréciés :

- `instanceExternalAuditEventDestinations` - utilisez `auditEventsInstanceStreamingDestinations` à la place.
- `instanceGoogleCloudLoggingConfigurations` - utilisez `auditEventsInstanceStreamingDestinations` avec la catégorie `gcpLogging` à la place.
- `auditEventsInstanceAmazonS3Configurations` - utilisez `auditEventsInstanceStreamingDestinations` avec la catégorie `amazonS3` à la place.

Les nouvelles API unifiées de destination de streaming prennent en charge toutes les catégories de destinations (HTTP, Google Cloud Logging, Amazon S3) via un ensemble unique de points de terminaison avec un paramètre `category`.

### Prise en charge des charts NGINX Ingress, HAProxy et Traefik {#support-for-nginx-ingress-haproxy-and-traefik-charts}

- Annoncé dans GitLab 18.9
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/590799).

Le chart Helm GitLab intègre plusieurs contrôleurs d'entrée comme alternative à la passerelle Envoy par défaut qui utilise l'API Kubernetes Gateway.

Ces contrôleurs d'entrée intégrés, à savoir NGINX Ingress, HAProxy et Traefik, seront supprimés du chart Helm GitLab et du GitLab Operator. L'utilisation des entrées sera toujours prise en charge par le chart Helm GitLab et le GitLab Operator, mais un contrôleur d'entrée externe devra être déployé à cet effet.

Nous recommandons de migrer vers la passerelle Envoy intégrée et l'API Gateway. Vous pouvez également déployer et configurer un [contrôleur d'entrée et une classe externes](https://docs.gitlab.com/charts/charts/globals/#configure-ingress-settings).

### Option `--master` pour `gitlab-ctl patroni failover` et `switchover` {#--master-option-for-gitlab-ctl-patroni-failover-and-switchover}

- Annoncé dans GitLab 19.4
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/9467).

L'option `--master` des commandes `gitlab-ctl patroni failover` et `gitlab-ctl patroni switchover` est dépréciée et sera supprimée dans GitLab 20.0. Les deux commandes acceptent `--leader` depuis GitLab 19.4, ce qui correspond au nom de l'option utilisé par `patronictl`.

Pour migrer, remplacez `--master` par `--leader` dans les scripts et les runbooks qui appellent ces commandes. L'option accepte la même valeur : le nom du nœud leader actuel. Jusqu'à sa suppression, `--master` conserve son comportement et affiche un avertissement de dépréciation.

### `kpt`-based `agentk` est déprécié {#kpt-based-agentk-is-deprecated}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 20.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/issues/656).

Nous supprimerons la prise en charge de l'installation de l'agent pour Kubernetes basée sur `kpt`. Le paquet `kpt` est défaillant et obsolète. Il n'est plus maintenu depuis 2022, ne dispose pas des fonctionnalités ajoutées au chart Helm depuis lors, et n'a aucun utilisateur connu. À la place, vous devriez installer l'agent avec l'une des méthodes d'installation prises en charge :

- Helm (recommandé)
- GitLab CLI
- Flux

Pour migrer de `kpt` vers Helm, suivez [la documentation d'installation de l'agent](https://docs.gitlab.com/user/clusters/agent/install/) pour remplacer votre instance `agentk` déployée avec `kpt`.

## GitLab 19.6 {#gitlab-196}

### Import des tickets et wikis Bitbucket Cloud {#bitbucket-cloud-issue-and-wiki-import}

- Annoncé dans GitLab 19.1
- Suppression dans GitLab 19.6 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/601061).

Atlassian [met fin à Bitbucket Cloud Issues et Wikis](https://community.atlassian.com/forums/Bitbucket-articles/Announcing-sunset-of-Bitbucket-Issues-and-Wikis/ba-p/3193882) le 20 août 2026. Après cette date, les points de terminaison d'API sous-jacents seront supprimés et GitLab ne pourra plus importer de tickets ou de wikis depuis Bitbucket Cloud.

Dans GitLab 19.3, l'importateur Bitbucket Cloud est prévu pour gérer la suppression de l'API de manière transparente et ignorer les tickets et les wikis. Dans GitLab 19.6, le code d'import pour les tickets et les wikis est prévu pour être supprimé.

Les utilisateurs qui ont besoin de leurs données de tickets Bitbucket doivent effectuer les imports avant la date limite du 20 août 2026, ou utiliser l'[import CSV](https://docs.gitlab.com/user/project/issues/csv_import/) après exportation depuis Bitbucket. Pour les wikis, clonez le dépôt wiki Bitbucket localement avant la date limite.

## GitLab 19.5 {#gitlab-195}

### Mutations GraphQL `secretPermissionUpdate` et `secretPermissionDelete` {#graphql-secretpermissionupdate-and-secretpermissiondelete-mutations}

- Annoncé dans GitLab 19.5
- Suppression dans GitLab 19.5 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/630579).

Dans le cadre du passage du GitLab Secrets Manager de la version bêta à la disponibilité générale, GitLab supprime les mutations GraphQL `secretPermissionUpdate` et `secretPermissionDelete` dans GitLab 19.5. Utilisez `projectSecretsPermissionUpdate` et `projectSecretsPermissionDelete` à la place. Les mutations de remplacement appellent les mêmes services que les anciennes mutations.

Les nouvelles mutations prennent un argument `actions` à la place de l'ancien argument `permissions`, qui acceptait des valeurs de chaîne en minuscules. Le nouvel argument `actions` prend une énumération `SecretsManagementAction`. Chaque valeur de cette énumération est en majuscules. Associez chaque ancienne valeur à une nouvelle valeur :

- `"read"` correspond à `READ`.
- `"create"` seul correspond à `CREATE`.
- `"update"`, avec ou sans `"create"`, correspond à `WRITE`.
- `"delete"` correspond à `DELETE`.

La forme de la réponse change également. Mettez à jour votre code pour refléter ces changements :

- Le champ de charge utile change de nom, de `secretPermission` à `secretsPermission`.
- Le type de charge utile change de nom, de `SecretPermission` à `ProjectSecretsPermission`.
- Le nouveau type n'a pas de champ `permissions`. Lisez plutôt le champ `actions`.

## GitLab 19.3 {#gitlab-193}

### L'API REST retourne 400 pour les identifiants non numériques sur les paramètres de chemin de type entier {#rest-api-returns-400-for-non-numeric-ids-on-integer-path-parameters}

- Annoncé dans GitLab 19.3
- Suppression dans GitLab 19.3 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/605824).

Plusieurs points de terminaison de l'API REST acceptaient auparavant des entrées non numériques ou multi-valeurs sur des paramètres de chemin de type entier sans les valider au préalable. Au lieu d'une erreur claire, ces requêtes retournaient des réponses incohérentes (`401 Unauthorized`, `404 Not Found`, ou dans de rares cas de bogues latents `200 OK`). Ils valident désormais le type du paramètre et retournent `400 Bad Request`.

Pour migrer, envoyez un seul identifiant numérique avec chaque requête. Les clients légitimes le font déjà, donc aucune action n'est requise pour les requêtes bien formées.

## GitLab 19.2 {#gitlab-192}

### La recherche avancée est requise pour l'édition Ultimate Self-Managed {#advanced-search-is-required-for-self-managed-ultimate-tier}

- Annoncé dans GitLab 18.11
- Suppression dans GitLab 19.2
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/582417).

Nous **_exigeons_** désormais que les clients de l'édition Ultimate Self-Managed utilisent la [recherche avancée](https://docs.gitlab.com/integration/advanced_search/elasticsearch/) pour bénéficier d'un accès complet à l'ensemble des fonctionnalités de l'édition Ultimate. GitLab ne sera pas interrompu sans la recherche avancée, mais toutes les fonctionnalités de l'édition Ultimate ne seront pas disponibles si elle n'est pas activée.

Nous avions auparavant **_recommandé_** d'activer la recherche avancée comme moyen d'améliorer les performances des requêtes pour certaines fonctionnalités. Nous avons désormais établi que la création de fonctionnalités complètes nécessitant la recherche avancée est fondamentale pour atteindre le rythme et la qualité de livraison que nous exigeons.

Aucune fonctionnalité existante ne sera dégradée ou interrompue si la recherche avancée n'est pas utilisée. Il s'agit uniquement d'un changement prospectif : les nouvelles fonctionnalités pourraient ne pas être prises en charge sans la recherche avancée. Les fonctionnalités GA de l'édition Ultimate peuvent désormais avoir une dépendance obligatoire à la recherche avancée pour une fonctionnalité complète ou partielle.

Des instructions pour activer la recherche avancée sont [disponibles dans notre documentation](https://docs.gitlab.com/user/search/advanced_search/).

## GitLab 19.1 {#gitlab-191}

### Elasticsearch 7.x n'est plus pris en charge pour la recherche avancée {#elasticsearch-7x-no-longer-supported-for-advanced-search}

- Annoncé dans GitLab 18.10
- Suppression dans GitLab 19.1 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/583544).

La [période de maintenance d'Elasticsearch 7.x](https://www.elastic.co/support/eol) a pris fin le 15 janvier 2026. Pour GitLab Self-Managed, les administrateurs doivent mettre à niveau leur instance Elasticsearch pour utiliser la recherche avancée.

### Prise en charge du paquet Linux pour Amazon Linux 2 {#linux-package-support-for-amazon-linux-2}

- Annoncé dans GitLab 18.9
- Suppression dans GitLab 19.1 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/590802).

Dans GitLab 19.1, nous supprimons les builds de paquets Amazon Linux 2 (AL2) pour le paquet Linux.

Amazon Linux 2 atteint sa fin de vie en juin 2026 et ne recevra plus de mises à jour de sécurité après cette date. Conformément à notre [politique des plateformes prises en charge pour le paquet Linux](https://docs.gitlab.com/install/package/#supported-platforms), nous supprimons les builds de paquets lorsqu'un éditeur cesse de prendre en charge le système d'exploitation, avec une période d'annonce d'au moins six mois.

Si vous exécutez actuellement GitLab sur Amazon Linux 2, vous devez migrer vers Amazon Linux 2023 (AL2023) ou un autre [système d'exploitation pris en charge](https://docs.gitlab.com/install/package/#supported-platforms) avant de mettre à niveau vers GitLab 19.1. Amazon fournit une [documentation de migration](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.migration-al.generic.from-al2.html) pour vous aider à passer d'AL2 à AL2023.

## GitLab 19.0 {#gitlab-190}

### Pilote de stockage Azure pour le registre de conteneurs {#azure-storage-driver-for-the-container-registry}

- Annoncé dans GitLab 17.10
- Suppression dans GitLab 19.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/523096).

Le pilote de stockage Azure hérité pour le registre de conteneurs est déprécié dans GitLab 17.10 et sera supprimé dans GitLab 19.0. Si vous utilisez le stockage d'objets Azure pour votre registre de conteneurs et souhaitez utiliser le nouveau pilote plus tôt, vous devrez mettre à jour votre configuration pour utiliser le nouveau pilote `azure_v2`. Dans GitLab 19.0, le pilote Azure déprécié deviendra un alias pour le pilote `azure_v2` et aucune action manuelle ne sera nécessaire.

Le pilote de stockage `azure_v2` offre une fiabilité améliorée, de meilleures performances et utilise une base de code plus facile à maintenir par rapport au pilote hérité. Ces améliorations contribuent à prévenir les problèmes de performance à mesure que l'utilisation de votre registre augmente.

Pour migrer vers le pilote `azure_v2` :

1. Mettez à jour votre fichier de configuration du registre pour utiliser le pilote `azure_v2` à la place du pilote hérité `azure`.
1. Ajustez vos paramètres de configuration selon les besoins du nouveau pilote.
1. Testez la nouvelle configuration dans un environnement hors production avant de déployer en production.

Pour plus d'informations sur la mise à jour de la configuration de votre pilote de stockage, consultez [utiliser le stockage d'objets](https://docs.gitlab.com/administration/packages/container_registry/#use-object-storage).

### Prise en charge de la version 2 de la signature AWS S3 pour le registre de conteneurs {#container-registry-aws-s3-signature-version-2-support}

- Annoncé dans GitLab 17.8
- Suppression dans GitLab 19.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/container-registry/-/issues/1449).

La prise en charge de l'authentification des requêtes via Amazon S3 Signature Version 2 dans le registre de conteneurs est dépréciée dans GitLab 17.8 et prévue pour suppression dans GitLab 19.0.

Le nouveau pilote de stockage S3v2 basé sur AWS SDK v2 (disponible à partir de GitLab 17.10 en version bêta, devenant le pilote par défaut dans la version 19.0) ne prend en charge que la version 4 de la signature. Une fois que le pilote S3v2 sera devenu le pilote par défaut, tous les paramètres de configuration de la version 2 de la signature (tels que `v4auth: false`) seront ignorés de manière transparente.

Vous pouvez migrer vers la version 4 de la signature avant de mettre à niveau vers la version de GitLab où S3v2 devient le pilote par défaut. Ce changement nécessite de mettre à jour les paramètres de configuration de votre bucket S3 et de s'assurer que vos paramètres du registre de conteneurs GitLab sont compatibles avec la version 4 de la signature.

Pour migrer :

1. Vérifiez la [configuration du backend de stockage S3 dans les paramètres du registre de conteneurs GitLab](https://docs.gitlab.com/administration/packages/container_registry/#use-object-storage).
1. Si `v4auth` est défini sur `false`, supprimez l'option.
1. Vérifiez que vos identifiants existants fonctionnent avec l'authentification v4.

Si vous rencontrez des problèmes après avoir apporté ces modifications, essayez de régénérer vos identifiants AWS.

### Imposer une limite de pages pour les requêtes non authentifiées à l'API Projects {#enforce-page-limit-for-unauthenticated-projects-api-requests}

- Annoncé dans GitLab 18.9
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/585176).

Pour maintenir la stabilité de la plateforme et garantir des performances optimales pour tous les clients, nous imposons une limite d'offset maximale sur les requêtes non authentifiées à l'API Projects. La limite d'offset s'applique uniquement à GitLab.com. Sur GitLab Self-Managed et GitLab Dedicated, la limite d'offset sera désactivée par défaut via un feature flag.

**Ce qui change**

Une limite d'offset maximale de 50 000 sera imposée pour toutes les requêtes non authentifiées à l'API REST Liste de projets. Par exemple, le paramètre `page` sera limité à 2 500 pages lors de la récupération de 20 résultats par page.

Les workflows nécessitant l'accès à davantage de données doivent utiliser les paramètres de pagination basée sur un jeu de clés.

**Pourquoi c'est important**

Cette limite garantit une qualité de service et des performances cohérentes sur GitLab.com en gérant efficacement l'utilisation des ressources.

### Prise en charge du paquet Linux pour les distributions SUSE {#linux-package-support-for-suse-distributions}

- Annoncé dans GitLab 18.9
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/590801).

Nous mettons fin à la prise en charge des distributions SUSE dans GitLab 19.0. Cela concerne :

- openSUSE Leap 15.6
- SUSE Linux Enterprise Server 12.5
- SUSE Linux Enterprise Server 15.6

openSUSE Leap 15.6 approche de sa fin de vie. Bien que SUSE Linux Enterprise Server reste pris en charge par SUSE via un service de support à long terme, son adoption parmi les clients GitLab est trop faible pour justifier la poursuite d'une prise en charge commercialement viable.

Les clients utilisant des distributions SUSE avec le paquet Linux ne pourront pas mettre à niveau GitLab au-delà de la version `18.11.x`.

Pour les clients utilisant l'une de ces distributions, nous recommandons de migrer vers un [déploiement Docker de GitLab](https://docs.gitlab.com/install/docker/installation/) sur votre distribution existante. Cela évite d'avoir à migrer vers une autre distribution Linux pour continuer à recevoir les mises à niveau de GitLab.

**Mettre à jour** : en raison des [contraintes de taille des paquets RPM sur SLES 12.5](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/9716), [Mattermost](https://docs.gitlab.com/update/deprecations/#mattermost-bundled-with-linux-package) et [Spamcheck](https://docs.gitlab.com/update/deprecations/#spamcheck-support-in-the-linux-package-and-gitlab-helm-chart) ont été supprimés des paquets SLES 12.5 dans GitLab 18.11, en avance sur leur suppression planifiée de toutes les distributions dans GitLab 19.0.

### Prise en charge du paquet Linux pour Ubuntu 20.04 {#linux-package-support-for-ubuntu-2004}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8915).

Le support standard d'Ubuntu pour Ubuntu 20.04 [a pris fin en mai 2025](https://wiki.ubuntu.com/Releases).

Conformément à notre [politique des plateformes prises en charge pour le paquet Linux](https://docs.gitlab.com/install/package/#supported-platforms), nous supprimons les builds de paquets lorsqu'un éditeur cesse de prendre en charge le système d'exploitation.

À partir de GitLab 19.0, nous ne fournirons plus de paquets pour la distribution Ubuntu 20.04 pour les installations via le paquet Linux. GitLab 18.11 sera la dernière version de GitLab avec des paquets Linux pour Ubuntu 20.04.

Si vous exécutez actuellement GitLab sur Ubuntu 20.04, vous devez mettre à niveau vers Ubuntu 22.04 ou un autre [système d'exploitation pris en charge](https://docs.gitlab.com/install/package/#supported-platforms) avant de mettre à niveau vers GitLab 19.0. Canonical fournit un [guide de mise à niveau](https://documentation.ubuntu.com/server/how-to/software/upgrade-your-release/) pour vous aider à migrer.

### Mattermost intégré au paquet Linux {#mattermost-bundled-with-linux-package}

- Annoncé dans GitLab 18.9
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/590798).

Dans GitLab 19.0, nous prévoyons de supprimer Mattermost intégré du paquet Linux.

Mattermost a été intégré à GitLab pour la première fois en 2015 en tant que solution de messagerie d'équipe open source, avec le SSO GitLab inclus pour prendre en charge l'intégration. Depuis lors, Mattermost a considérablement amélioré ses propres options de packaging et de déploiement, et l'adoption de Mattermost intégré parmi les clients GitLab est restée relativement faible.

Avec Mattermost v11, [Mattermost a déprécié le SSO GitLab de son offre gratuite](https://forum.mattermost.com/t/mattermost-v11-changes-in-free-offerings/25126). Compte tenu de ce changement, de la maturité des options de déploiement autonome de Mattermost et de la faible adoption dans notre base de clients, nous supprimons Mattermost du paquet Linux.

Si vous utilisez actuellement Mattermost intégré à GitLab, consultez la page [Migration de GitLab Omnibus vers Mattermost autonome](https://docs.mattermost.com/administration-guide/onboard/migrate-gitlab-omnibus.html) dans la documentation Mattermost pour les instructions de migration et les éditions Mattermost disponibles.

### L'octroi des informations d'identification par mot de passe du propriétaire de la ressource est déprécié {#resource-owner-password-credentials-grant-is-deprecated}

- Annoncé dans GitLab 18.0
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/457353).

L'utilisation de l'octroi des informations d'identification par mot de passe du propriétaire de la ressource (ROPC) comme flux OAuth est dépréciée, et la prise en charge sera entièrement supprimée dans GitLab 19.0. Nous avons ajouté un paramètre que les administrateurs peuvent activer ou désactiver pour utiliser ce type d'octroi uniquement avec des identifiants clients dans leurs instances. Cela permet aux utilisateurs qui souhaitent ne plus utiliser ROPC sans identifiants clients de le faire avant la version 19.0. ROPC sera entièrement supprimé dans la version 19.0 et ne pourra plus être utilisé, même avec des identifiants clients, après ce point.

GitLab [a rendu l'authentification client obligatoire pour ROPC sur GitLab.com](https://about.gitlab.com/blog/improving-oauth-ropc-security-on-gitlab-com/) depuis le 8 avril 2025 pour des raisons de sécurité. La suppression complète de la prise en charge de ROPC maintient la sécurité en conformité avec la version 2.1 de la RFC OAuth.

### Pilote de stockage S3 (AWS SDK v1) pour le registre de conteneurs {#s3-storage-driver-aws-sdk-v1-for-the-container-registry}

- Annoncé dans GitLab 17.10
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/523095).

Le pilote de stockage S3 pour le registre de conteneurs utilisant AWS SDK v1 est déprécié et sera supprimé dans GitLab 19.0. Si vous utilisez le stockage d'objets S3 pour votre registre de conteneurs et souhaitez utiliser le nouveau pilote plus tôt, vous devez mettre à jour votre configuration pour utiliser le nouveau pilote `s3_v2`. Dans GitLab 19.0, le pilote s3 déprécié deviendra un alias pour le pilote `s3_v2`, et aucune action manuelle ne sera nécessaire.

Le pilote de stockage `s3_v2` est basé sur AWS SDK v2 et offre de meilleures performances, une sécurité renforcée et un support continu d'AWS. Il sera disponible à partir de mai 2025 pour remplacer l'[AWS SDK v1](https://aws.amazon.com/blogs/developer/announcing-end-of-support-for-aws-sdk-for-go-v1-on-july-31-2025/) déprécié, dont le support prend fin le 31 juillet 2025.

Le pilote `s3_v2` ne prend plus en charge l'algorithme de signature v2. Si l'option `v4auth: false` est définie dans la configuration, elle sera ignorée de manière transparente par le pilote `s3_v2` et l'algorithme V4 plus sécurisé sera utilisé. Pour migrer vers le pilote `s3_v2` :

1. Mettez à jour votre fichier de configuration du registre pour utiliser la configuration `s3_v2` à la place de `s3`.
1. Passez de la version 2 de la signature à la version 4 pour l'authentification si ce n'est pas encore fait, car AWS SDK v2 ne prend en charge que la version 4 de la signature.
1. Testez la configuration dans un environnement hors production avant de déployer en production.

Sur AWS S3, le changement de pilote peut également modifier le nom d'hôte dans les URL pré-signées que les clients utilisent pour télécharger des blobs du registre. AWS SDK v2 résout le point de terminaison S3 pour votre région configurée, de sorte que les URL pré-signées peuvent utiliser un nom d'hôte régional tel que `s3.us-east-1.amazonaws.com` à la place du nom d'hôte global `s3.amazonaws.com`. Si votre réseau restreint le trafic sortant, mettez à jour la liste d'autorisation de votre proxy ou pare-feu pour inclure le nom d'hôte régional avant de procéder à la mise à niveau. Sinon, les extractions d'images échouent avec des réponses `403 Forbidden`.

Pour plus d'informations sur la mise à jour de la configuration de votre pilote de stockage, consultez [utiliser le stockage d'objets](https://docs.gitlab.com/administration/packages/container_registry/#use-object-storage).

### Commandes slash Slack {#slack-slash-commands}

- Annoncé dans GitLab 18.7
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/569345).

L'intégration des commandes slash Slack est dépréciée au profit de l'[application GitLab pour Slack](https://docs.gitlab.com/user/project/integrations/gitlab_slack_application/), qui offre une méthode d'intégration plus sécurisée avec les mêmes capacités.

À partir de GitLab 19.0, les utilisateurs ne pourront plus configurer ni utiliser l'intégration des commandes slash Slack. Cette intégration n'est disponible que sur les instances GitLab Self-Managed et GitLab Dedicated. Si vous êtes sur GitLab.com, vous n'avez rien à faire.

Si vous êtes sur GitLab Self-Managed ou GitLab Dedicated, pour savoir si vous êtes concerné, consultez le [ticket 569345](https://gitlab.com/gitlab-org/gitlab/-/work_items/569345#am-i-impacted).

### Prise en charge de Spamcheck dans le paquet Linux et le chart Helm GitLab {#spamcheck-support-in-the-linux-package-and-gitlab-helm-chart}

- Annoncé dans GitLab 18.9
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/590796).

Dans GitLab 19.0, nous supprimons [Spamcheck](https://docs.gitlab.com/administration/reporting/spamcheck/) du paquet Linux et du chart Helm GitLab.

Spamcheck est un service destiné à lutter contre le spam sur les instances GitLab accessibles au public. Par nature, cette fonctionnalité est principalement pertinente pour les grandes instances publiques, ce qui représente un cas particulier dans notre base de clients.

Compte tenu de la faible adoption et de la disponibilité d'options de déploiement autonome, nous supprimons Spamcheck du paquet Linux et du chart Helm GitLab. Les clients n'utilisant pas Spamcheck ne seront pas impactés par ce changement. La suppression réduira la taille du paquet et l'empreinte des dépendances (et donc la sécurité) pour la majorité des clients.

Si vous utilisez actuellement Spamcheck intégré, vous pouvez le déployer séparément en utilisant [Docker](https://gitlab.com/gitlab-org/gl-security/security-engineering/security-automation/spam/spamcheck).

Aucune migration de données n'est requise. Des instructions de configuration sont disponibles dans la documentation liée.

### Prise en charge de NGINX Ingress {#support-for-nginx-ingress}

- Annoncé dans GitLab 18.9
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/590800).

Le chart Helm GitLab intègre actuellement NGINX Ingress comme composant réseau par défaut. NGINX Ingress atteignant sa fin de vie en mars 2026, nous passons à l'API Gateway avec Envoy Gateway.

À partir de GitLab 19.0, l'API Gateway et la passerelle Envoy intégrée deviennent la configuration par défaut. Si la migration vers Envoy Gateway n'est pas faisable pour votre déploiement, vous pouvez réactiver explicitement NGINX Ingress intégré, qui reste disponible jusqu'à sa suppression planifiée dans GitLab 20.0.

Ce changement n'impacte pas NGINX dans le paquet Linux, ni les instances du chart Helm GitLab et du GitLab Operator qui utilisent un contrôleur Ingress ou API Gateway géré en externe.

Nous fournirons une maintenance de sécurité au mieux de nos capacités pour notre chart NGINX Ingress forké et les builds jusqu'à la suppression complète. Pour assurer une transition en douceur, nous recommandons de planifier votre migration vers la solution API Gateway fournie ou vers un contrôleur Ingress géré en externe. Pour des instructions étape par étape, consultez le [guide de migration Envoy Gateway](https://docs.gitlab.com/charts/installation/migration/envoy_gateway_migration/).

### Prise en charge de PostgreSQL 16 {#support-for-postgresql-16}

- Annoncé dans GitLab 18.9
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/589774).

GitLab suit un [calendrier de mise à niveau annuel pour PostgreSQL](https://handbook.gitlab.com/handbook/engineering/data-engineering/database-excellence/database-frameworks/postgresql-upgrade-cadence/).

La prise en charge de PostgreSQL 16 est prévue pour suppression dans GitLab 19.0. Dans GitLab 19.0, PostgreSQL 17 devient la version minimale requise de PostgreSQL.

PostgreSQL 17 est disponible depuis GitLab 18.9, et vous pouvez effectuer la mise à niveau à tout moment avant la suppression de PostgreSQL 16 dans GitLab 19.0.

Si vous exécutez une instance PostgreSQL unique installée via le paquet Linux, une mise à niveau automatique pourrait être tentée avec la version 18.11. Assurez-vous de disposer de suffisamment d'espace disque pour accueillir la mise à niveau.

Pour plus d'informations, consultez [Mettre à niveau le serveur PostgreSQL intégré](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server).

### Prise en charge de Redis 6 {#support-for-redis-6}

- Annoncé dans GitLab 18.10
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/585839).

Dans GitLab 19.0, nous prévoyons de supprimer la prise en charge de Redis 6 dans le cadre de notre engagement à maintenir une infrastructure sécurisée et maintenable.

Avant de mettre à niveau vers GitLab 19.0, migrez vers Redis 7.0 ou une version supérieure, ou Valkey 7.2. Redis 7.2 ou Valkey 7.2 est recommandé. Redis 7.0 a atteint sa fin de vie (EOL) en amont, mais est dans certains cas activement maintenu par des éditeurs, comme Amazon ElastiCache pour Redis 7.1, qui est basé sur Redis 7.0.

Le Redis inclus dans le paquet Linux utilise Redis 7 depuis GitLab 16.2 et n'est pas affecté. Seules les instances GitLab Self-Managed utilisant un déploiement Redis 6 externe doivent migrer.

Consultez les ressources suivantes pour migrer un déploiement Redis 6 externe :

- **AWS ElastiCache** : ElastiCache pour Redis 7.2 n'est pas disponible sur AWS. Migrez vers [Amazon ElastiCache pour Valkey 7.2](https://aws.amazon.com/elasticache/what-is-valkey/), qui est recommandé. ElastiCache pour Redis 7.1 est basé sur Redis 7.0 et est connu pour fonctionner. Pour les chemins de mise à niveau disponibles, consultez la [documentation AWS ElastiCache](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/engine-versions.html).
- **GCP Memorystore** : mettez à niveau votre instance Redis 6 vers Redis 7.2 ou Valkey 7.2. Pour les chemins de mise à niveau disponibles, consultez la [documentation GCP Memorystore](https://docs.cloud.google.com/memorystore/docs/redis/supported-versions).
- **Azure Cache pour Redis** : une option Redis 7.2 ou Valkey 7.2 managée n'est pas actuellement disponible sur Azure. Vous pouvez auto-héberger Redis 7.2 ou Valkey 7.2 sur des VM Azure ou AKS. Vous pouvez également utiliser la méthode d'installation via le paquet Linux GitLab, qui prend en charge Valkey 7.2.
- **Auto-hébergé** : mettez à niveau votre instance Redis 6 vers Redis 7.2 ou Valkey 7.2.

Pour plus d'informations, consultez la [documentation sur les prérequis](https://docs.gitlab.com/install/requirements/).

### Prise en charge de PostgreSQL, Redis et MinIO intégrés dans le chart Helm GitLab {#support-for-bundled-postgresql-redis-and-minio-in-gitlab-helm-chart}

- Annoncé dans GitLab 18.9
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/590797).

Le chart Helm GitLab intègre un chart Bitnami PostgreSQL, Bitnami Redis, et un fork du chart MinIO officiel pour faciliter la configuration de GitLab. En raison de plusieurs changements concernant les licences, la maintenance du projet et la disponibilité des images publiques, ces composants seront supprimés du chart Helm GitLab et du GitLab Operator sans remplacement.

Ces charts sont actuellement activés par défaut, mais sont explicitement documentés comme non recommandés pour une utilisation en production. Leur seul objectif était de permettre une configuration rapide pour des environnements de preuve de concept et de test.

Si vous exécutez une instance avec PostgreSQL, Redis ou MinIO intégrés, consultez le [guide de migration](https://docs.gitlab.com/charts/installation/migration/bundled_chart_migration/).

Redis et PostgreSQL fournis par le paquet Linux ne sont pas impactés par ce changement.

### L'attribut `ci_job_token_scope_enabled` de l'API projects est déprécié {#the-ci_job_token_scope_enabled-projects-api-attribute-is-deprecated}

- Annoncé dans GitLab 16.4
- Suppression dans GitLab 19.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/423091).

Le paramètre de projet du jeton de job CI/CD [Limiter l'accès depuis ce projet](https://docs.gitlab.com/update/deprecations/#cicd-job-token---limit-access-from-your-project-setting-removal) a été supprimé dans la version 18.0. L'attribut `ci_job_token_scope_enabled` associé dans l'[API projects](https://docs.gitlab.com/api/projects/) est désormais déprécié et retourne toujours `false`, il sera donc supprimé dans la version 19.0. Pour contrôler l'accès au jeton de job, utilisez les [paramètres de projet du jeton de job CI/CD](https://docs.gitlab.com/ci/jobs/ci_job_token/#control-job-token-access-to-your-project).

### L'image `heroku/builder:22` est dépréciée {#the-herokubuilder22-image-is-deprecated}

- Annoncé dans GitLab 17.4
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/cluster-integration/auto-build-image/-/issues/79).

L'image du builder de buildpack natif cloud (CNB) a été mise à jour vers `heroku/builder:24` dans le projet Auto DevOps Build. Bien que nous ne nous attendions pas à ce que les changements soient perturbateurs dans la plupart des cas, il pourrait s'agir d'un changement important pour certains utilisateurs d'Auto DevOps, et notamment les utilisateurs d'Auto Build. Pour mieux comprendre l'impact sur vos charges de travail, consultez les éléments suivants :

- [Notes de release de la stack Heroku-24](https://devcenter.heroku.com/articles/heroku-24-stack#what-s-new)
- [Notes de mise à niveau de la stack Heroku-24](https://devcenter.heroku.com/articles/heroku-24-stack#upgrade-notes)
- [Paquets de la stack Heroku](https://devcenter.heroku.com/articles/stack-packages)

Ces changements vous concernent si vos pipelines utilisent le [`auto-build-image`](https://gitlab.com/gitlab-org/cluster-integration/auto-build-image) fourni par [l'étape Auto Build d'Auto DevOps](https://docs.gitlab.com/topics/autodevops/stages/#auto-build).

Pour continuer à utiliser `heroku/builder:22` après GitLab 19.0, définissez `AUTO_DEVOPS_BUILD_IMAGE_CNB_BUILDER` sur `heroku/builder:22`.

### L'onglet Trending de la page Explorer les projets est déprécié {#trending-tab-in-explore-projects-page-is-deprecated}

- Annoncé dans GitLab 18.8
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/work_items/18493).

L'onglet **Trending** dans **Explorer** > **Projets** et ses arguments GraphQL associés sont dépréciés dans GitLab 18.8 et seront supprimés dans GitLab 19.0. Durant le mois précédant la release de GitLab 19.0, l'onglet **Trending** redirige vers l'onglet **Actif** trié par nombre d'étoiles en ordre décroissant sur GitLab.com.

**Ce qui est supprimé**

- L'onglet **Trending** sur la page **Explorer** > **Projets**
- L'argument trending dans les types GraphQL suivants :
  - `Query.adminProjects`
  - `Query.projects`
  - `Organization.projects`

**Pourquoi nous effectuons ce changement**

L'algorithme de tendance ne prend en compte que les projets publics, ce qui le rend inefficace pour les instances GitLab Self-Managed qui utilisent principalement une visibilité interne ou privée. Les limitations de l'algorithme et l'absence de fonctionnalité de recherche ont conduit à des demandes explicites de suppression de la part des utilisateurs Self-Managed. Plutôt que d'investir dans des améliorations significatives, nous concentrons nos ressources sur l'amélioration des mécanismes de découverte existants.

**Action requise**

Utilisateurs de l'interface : l'onglet **Trending** sera inaccessible durant la prochaine fenêtre de changements importants avant la suppression complète dans la version 19.0. Nous recommandons d'utiliser l'onglet **Actif** pour afficher les projets récemment mis à jour ou les plus étoilés.

### Utilisation des mots de passe d'application avec l'API GitLab d'import Bitbucket Cloud {#using-app-passwords-with-bitbucket-cloud-import-gitlab-api}

- Annoncé dans GitLab 18.9
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/work_items/588961).

Atlassian a déprécié les mots de passe d'application (authentification par nom d'utilisateur et mot de passe) pour Bitbucket Cloud et a [annoncé](https://www.atlassian.com/blog/bitbucket/bitbucket-cloud-transitions-to-api-tokens-enhancing-security-with-app-password-deprecation) que cette méthode d'authentification cessera de fonctionner le 09 juin 2026.

À partir de GitLab 19.0, si vous souhaitez importer des dépôts depuis Bitbucket Cloud via l'API GitLab, vous devez utiliser les [jetons d'API utilisateur](https://support.atlassian.com/organization-administration/docs/understand-user-api-tokens/) à la place.

Les utilisateurs qui importent des dépôts depuis Bitbucket Server, ou depuis Bitbucket Cloud via l'interface GitLab, ne sont pas concernés.

### La mutation GraphQL `ciJobTokenScopeAddProject` est dépréciée {#cijobtokenscopeaddproject-graphql-mutation-is-deprecated}

- Annoncé dans GitLab 17.5
- Suppression dans GitLab 19.0 ([changement important](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/474175).

Avec le [prochain changement de comportement par défaut du jeton de job CI/CD](https://docs.gitlab.com/update/deprecations/#default-cicd-job-token-ci_job_token-scope-changed) dans GitLab 18.0, nous déprécions également la mutation GraphQL `ciJobTokenScopeAddProject` associée au profit de `ciJobTokenScopeAddGroupOrProject`.

## GitLab 18.8 {#gitlab-188}

### Rapport statique des violations de conformité {#static-compliance-violations-report}

- Annoncé dans GitLab 18.2
- Suppression dans GitLab 18.8 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/epics/12774).

Le rapport statique existant des violations de conformité est déprécié dans GitLab 18.2 et sera supprimé dans GitLab 18.8.

Pour remplacer le rapport statique des violations de conformité :

- Dans GitLab 17.11, nous avons publié les [frameworks de conformité personnalisés](https://docs.gitlab.com/user/compliance/compliance_frameworks/).
- Dans GitLab 18.2, nous avons publié le nouveau [rapport dynamique des violations de conformité](https://docs.gitlab.com/user/compliance/compliance_center/compliance_violations_report/).

Ces fonctionnalités offrent toutes les mêmes fonctions que le rapport statique des violations, mais vous pouvez configurer les violations dont vous avez besoin.

Dans GitLab 18.8, nous remplacerons le rapport statique des violations de conformité par le rapport dynamique utilisant des frameworks de conformité, pour un reporting plus précis sur les exigences et les contrôles.

## GitLab 18.6 {#gitlab-186}

### Modèles Mistral anciens dépréciés pour GitLab Duo Self-Hosted {#early-mistral-models-deprecated-for-gitlab-duo-self-hosted}

- Annoncé dans GitLab 18.3
- Fin de support dans GitLab 18.6
- Suppression dans GitLab 18.6
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/557156).

Dans GitLab 18.6, GitLab supprimera la prise en charge des modèles Mistral 7B-it, Mixtral 8x7B et Mixtral 8x22B pour une utilisation avec GitLab Duo Self-Hosted. Les clients GitLab Duo Enterprise pourront continuer à utiliser ces modèles avec GitLab Duo Self-Hosted, mais ne bénéficieront plus d'un support technique pour les configurations avec ces modèles. GitLab Duo Self-Hosted continuera à prendre en charge Mistral Small 24B Instruct 2506, qui a été [validé comme entièrement compatible](https://docs.gitlab.com/administration/gitlab_duo_self_hosted/supported_models_and_hardware_requirements/) avec toutes les fonctionnalités généralement disponibles de GitLab Duo Self-Hosted.

### Prometheus 2.x fourni avec le package Omnibus Linux {#prometheus-2x-bundled-with-the-omnibus-linux-package}

- Annoncé dans GitLab 18.3
- Suppression dans GitLab 18.6
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/9196).

Prometheus 2.x fourni avec le package Linux est déprécié et sera mis à jour vers la dernière version Prometheus 3.x dans GitLab 18.6.

Prometheus 3 contient certains changements potentiellement majeurs, tels qu'un nouveau format de journaux et une validation des en-têtes plus stricte. Pour plus d'informations, consultez le [guide de migration de Prometheus](https://prometheus.io/docs/prometheus/latest/migration/).

Ce changement n'a pas d'impact sur les installations GitLab Helm chart.

### Remplacement du tableau de bord d'adhésion aux normes de conformité par le tableau de bord du statut de conformité {#replace-compliance-standards-adherence-dashboard-with-compliance-status-dashboard}

- Annoncé dans GitLab 17.11
- Suppression dans GitLab 18.6
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/470834).

Dans GitLab 17.11, nous avons publié :

- [Frameworks de conformité personnalisés](https://docs.gitlab.com/user/compliance/compliance_frameworks/).
- Le [rapport du statut de conformité](https://docs.gitlab.com/user/compliance/compliance_center/compliance_status_report/).

Ces fonctionnalités offrent toutes les mêmes fonctions que le tableau de bord d'adhésion aux normes de conformité, mais vous pouvez configurer l'adhésion dont vous avez besoin.

Dans GitLab 18.6, nous remplacerons le tableau de bord d'adhésion aux normes de conformité par le tableau de bord du statut de conformité, pour un reporting plus précis sur les exigences et les contrôles.

### Paramètre utilisateur pour désactiver la recherche exacte de code {#user-setting-to-disable-exact-code-search}

- Annoncé dans GitLab 18.3
- Suppression dans GitLab 18.6
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/554933).

Le paramètre utilisateur permettant de désactiver la recherche exacte de code est désormais déprécié. Sur GitLab.com, vous ne pouvez plus désactiver la recherche exacte de code dans les préférences de profil.

La recherche exacte de code offre une meilleure expérience utilisateur et est compatible avec les API de recherche existantes. Ce paramètre utilisateur est prévu pour suppression dans GitLab 18.6 afin que tous les utilisateurs bénéficient des améliorations des fonctionnalités de recherche.

## GitLab 18.5 {#gitlab-185}

### Prise en charge d'OpenSearch 1.x dans la recherche avancée {#support-for-opensearch-1x-in-advanced-search}

- Annoncé dans GitLab 18.2
- Suppression dans GitLab 18.5
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/554530).

La [fenêtre de maintenance pour OpenSearch 1.x](https://opensearch.org/releases/#maintenance-policy) est terminée. Pour GitLab Self-Managed et GitLab Dedicated, les administrateurs doivent mettre à niveau leur instance OpenSearch pour utiliser la recherche avancée.

## GitLab 18.4 {#gitlab-184}

### Images Bitnami PostgreSQL et Redis dans le chart GitLab {#bitnami-postgresql-and-redis-images-in-gitlab-chart}

- Annoncé dans GitLab 18.4
- Suppression dans GitLab 18.4 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/6089).

La configuration par défaut du chart Helm GitLab repose sur les charts et images de conteneurs Bitnami pour PostgreSQL et Redis. Bitnami supprimera ces images de ses catalogues gratuits le 29 septembre 2025. Des coupures temporaires des images ont commencé le 28 août 2025.

Le chart GitLab intègre PostgreSQL et Redis de Bitnami à des fins de démonstration et de test uniquement. Ils ne font partie d'aucune [architecture de référence GitLab prise en charge](https://docs.gitlab.com/administration/reference_architectures/). Si vous utilisez une architecture de référence ou si vous avez déployé PostgreSQL et Redis externes avec les packages ou images d'un autre fournisseur, vous n'êtes **pas concerné** par ce changement.

À titre de solution temporaire, GitLab a migré la configuration du chart vers le dépôt Bitnami legacy. Cependant, les environnements GitLab chart non corrigés (GitLab 17.11, GitLab 18.0.5. GitLab 18.1.4 et GitLab 18.2.1 ou versions antérieures) continueront à extraire des images du dépôt Bitnami déprécié, ce qui entraînera des échecs de déploiement après le 29 septembre et peut provoquer des échecs de déploiement durant la phase de coupure.

Si vous utilisez une configuration GitLab chart concernée, vous devez effectuer l'une des actions suivantes :

- Migrer vers une architecture de référence GitLab prise en charge.
- Mettre à niveau vers une version corrigée du chart.
- Configurer le dépôt legacy dans vos valeurs de chart. Pour un exemple, consultez la [merge request 4421](https://gitlab.com/gitlab-org/charts/gitlab/-/merge_requests/4421).

Pour la suite, [nous évaluerons des alternatives](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/6089) pour remplacer ou supprimer entièrement les composants Bitnami du chart GitLab. Pour plus d'informations, consultez l'[annonce officielle de Bitnami](https://github.com/bitnami/charts/issues/35164).

## GitLab 18.3 {#gitlab-183}

### Mise à jour du chart Helm cert-manager {#cert-manager-helm-chart-update}

- Annoncé dans GitLab 18.0
- Suppression dans GitLab 18.3 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/5928).

Pour permettre la validation de schéma des charts cert-manager plus récents, la valeur `certmanager.install` du chart Helm GitLab est dépréciée en faveur de `installCertmanager`. La définition du schéma n'accepte pas la propriété supplémentaire que nous avons ajoutée dans la section `certmanager` du chart GitLab.

Dans GitLab 18.3 (chart GitLab 9.3), nous supprimerons la valeur dépréciée et mettrons à jour le cert-manager intégré.

Si vous avez précédemment utilisé le paramètre `certmanager.install` :

1. Transférez la valeur de `certmanager.install` vers `installCertmanager`.
1. Supprimez entièrement le paramètre `certmanager.install`.

Consultez également les notes de release de cert-manager :

- [Notes de release 1.12 - 1.16](https://cert-manager.io/docs/releases/upgrading/upgrading-1.12/)
- [Notes de release 1.17](https://cert-manager.io/docs/releases/upgrading/upgrading-1.16-1.17/)

## GitLab 18.1 {#gitlab-181}

### Les limites des jobs de pipeline étendues à l'API Commits {#pipeline-job-limits-extended-to-the-commits-api}

- Annoncé dans GitLab 17.7
- Suppression dans GitLab 18.1 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/436361).

À partir de GitLab 18.0, le [nombre maximum de jobs dans les pipelines actifs](https://docs.gitlab.com/administration/instance_limits/#number-of-jobs-in-active-pipelines) s'appliquera également lors de la création de jobs via l'[API Commits](https://docs.gitlab.com/api/commits/#set-the-pipeline-status-of-a-commit). Vérifiez votre intégration pour vous assurer qu'elle respecte les limites de jobs configurées.

## GitLab 18.0 {#gitlab-180}

### API Discovery utilisera les pipelines de branche par défaut {#api-discovery-will-use-branch-pipelines-by-default}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/515487).

Dans GitLab 18.0, nous mettrons à jour le comportement par défaut du template CI/CD pour API Discovery (`API-Discovery.gitlab-ci.yml`).

Avant GitLab 18.0, ce template configure les jobs pour s'exécuter dans les [pipelines de merge request (MR)](https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/) par défaut lorsqu'une MR est ouverte. À partir de GitLab 18.0, nous alignerons le comportement de ce template avec celui des [éditions de template Stable](https://docs.gitlab.com/user/application_security/detect/roll_out_security_scanning/#template-editions) pour les autres scanners AST :

- Par défaut, le template exécutera les jobs de scan dans les pipelines de branche.
- Vous pourrez définir la variable CI/CD `AST_ENABLE_MR_PIPELINES: true` pour utiliser les pipelines MR à la place lorsqu'une MR est ouverte. L'implémentation de cette nouvelle variable est suivie dans le [ticket 410880](https://gitlab.com/gitlab-org/gitlab/-/issues/410880).

### Mise à jour de la version majeure des analyseurs de test de sécurité des applications {#application-security-testing-analyzers-major-version-update}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/513417).

Dans GitLab 18.0, nous mettrons à jour la version majeure de toutes les images de conteneurs des analyseurs de test de sécurité des applications.

Si vous n'utilisez pas les templates inclus par défaut, ou si vous avez épinglé les versions de vos analyseurs, vous devez mettre à jour la définition de votre job CI/CD pour soit supprimer la version épinglée, soit mettre à jour la dernière version majeure.

Les utilisateurs de GitLab 17.0 à GitLab 17.11 continueront à recevoir des mises à jour des analyseurs jusqu'à la release de GitLab 18.0, après quoi tous les nouveaux correctifs de bugs et fonctionnalités publiés le seront uniquement dans la nouvelle version majeure des analyseurs. Cependant, nous ne supprimerons aucune image de conteneur publiée du registre de conteneurs.

Nous n'effectuons pas de backport des bugs et fonctionnalités vers les versions dépréciées, conformément à notre politique de maintenance. Si nécessaire, les correctifs de sécurité feront l'objet d'un backport dans les 3 dernières versions mineures.

Plus précisément, les analyseurs suivants ne seront plus mis à jour après la release GitLab 18.0 :

- GitLab Advanced SAST : version 1
- Container scanning : version 7
- Gemnasium : version 5
- DAST : version 5
- DAST API : version 4
- Fuzz API : version 4
- IaC scanning : version 5
- Pipeline secret detection : version 6
- Test statique de sécurité des applications (SAST) : version 5 de [tous les analyseurs](https://docs.gitlab.com/user/application_security/sast/analyzers/)
  - `kics`
  - `kubesec`
  - `pmd-apex`
  - `semgrep`
  - `sobelow`
  - `spotbugs`

### Changement de comportement des filtres de jalon À venir et Démarré {#behavior-change-for-upcoming-and-started-milestone-filters}

- Annoncé dans GitLab 17.7
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/501294).

Le comportement des filtres spéciaux « À venir » et « Démarré » est prévu pour changer dans la prochaine version majeure GitLab 18.0. Le nouveau comportement des deux filtres est décrit dans le [ticket 429728](https://gitlab.com/gitlab-org/gitlab/-/issues/429728#proposed-issue-filter-logic-for-upcoming-and-started-milestones).

Ce changement n'a pas d'impact sur l'API REST GitLab, qui continuera à utiliser la logique de filtrage par jalon existante. L'API GraphQL GitLab sera mise à jour pour respecter la nouvelle logique de filtrage.

### Jeton de job CI/CD - Application de la liste d'autorisations **Groupes et projets autorisés** {#cicd-job-token---authorized-groups-and-projects-allowlist-enforcement}

- Annoncé dans GitLab 16.5
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/383084).

Avec le [paramètre **Groupes et projets autorisés**](https://docs.gitlab.com/ci/jobs/ci_job_token/#add-a-group-or-project-to-the-job-token-allowlist) introduit dans GitLab 15.9 (renommé depuis **Limiter l'accès _à_ ce projet** dans GitLab 16.3), vous pouvez contrôler l'accès par jeton de job CI/CD à votre projet. Lorsque le paramètre est défini sur **Uniquement ce projet et les groupes et projets de la liste d'autorisations**, seuls les groupes ou projets ajoutés à la liste d'autorisations peuvent utiliser des jetons de job pour accéder à votre projet.

Pour les projets créés avant GitLab 15.9, la liste d'autorisations était désactivée par défaut (paramètre d'accès [**Tous les groupes et projets**](https://docs.gitlab.com/ci/jobs/ci_job_token/#allow-any-project-to-access-your-project) sélectionné), permettant l'accès par jeton de job depuis n'importe quel projet. La liste d'autorisations est désormais activée par défaut dans tous les nouveaux projets. Dans les projets plus anciens, elle peut encore être désactivée ou vous avez peut-être manuellement sélectionné l'option **Tous les groupes et projets** pour rendre l'accès non restreint.

À partir de GitLab 17.6, les administrateurs des instances GitLab Self-Managed et GitLab Dedicated peuvent optionnellement [appliquer ce paramètre plus sécurisé à tous les projets](https://docs.gitlab.com/administration/settings/continuous_integration/#job-token-permissions). Ce paramètre empêche les mainteneurs de projet de sélectionner **Tous les groupes et projets**. Ce changement garantit un niveau de sécurité plus élevé entre les projets.

Dans GitLab 18.0, ce paramètre d'instance sera activé par défaut sur GitLab.com, GitLab Self-Managed et GitLab Dedicated. Les administrateurs de GitLab Self-Managed et GitLab Dedicated peuvent désactiver le paramètre après la mise à niveau vers GitLab 18.0 pour rétablir le comportement antérieur à la mise à niveau. Aucun paramètre de projet ne sera modifié dans GitLab 18.0 pour GitLab Self-Managed et GitLab Dedicated, bien que le statut du paramètre d'instance affecte tous les projets de l'instance.

Pour vous préparer à ce changement, les mainteneurs de projet utilisant des jetons de job pour l'authentification inter-projets doivent renseigner les listes d'autorisations **Groupes et projets autorisés** de leur projet. Ils doivent ensuite modifier le paramètre sur **Uniquement ce projet et les groupes et projets de la liste d'autorisations**.

Pour aider à identifier les projets qui ont besoin d'accéder à votre projet en s'authentifiant avec un jeton de job CI/CD, dans GitLab 17.6 nous avons également introduit une méthode pour [suivre les authentifications par jeton de job](https://docs.gitlab.com/releases/17/gitlab-17-6-released/#track-cicd-job-token-authentications) vers vos projets. Vous pouvez utiliser ces données pour renseigner votre liste d'autorisations de jeton de job CI/CI.

De GitLab 17.10 à 18.6, vous pouvez utiliser les [outils de migration](https://archives.docs.gitlab.com/18.6/ci/jobs/ci_job_token/#auto-populate-a-projects-allowlist) pour renseigner automatiquement la liste d'autorisations de jeton de job CI/CD à partir du journal d'authentification par jeton de job. Nous vous encourageons à utiliser cet outil de migration pour renseigner et utiliser la liste d'autorisations avant l'[application générale des listes d'autorisations dans GitLab 18.0](https://docs.gitlab.com/update/deprecations/?removal_milestone=18.0#cicd-job-token-authorized-groups-and-projects-allowlist-enforcement). Dans GitLab 18.0, le renseignement automatique et l'application de la liste d'autorisations se produiront sur GitLab.com comme annoncé précédemment.

Cet outil de migration [a été supprimé](https://gitlab.com/gitlab-org/gitlab/-/work_items/498305) dans GitLab 18.7.

### Jeton de job CI/CD - Suppression du paramètre **Limiter l'accès depuis votre projet** {#cicd-job-token---limit-access-from-your-project-setting-removal}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/395708).

Dans GitLab 14.4, nous avons introduit un paramètre pour [limiter l'accès _depuis_ les jetons de job CI/CD de votre projet (`CI_JOB_TOKEN`)](https://docs.gitlab.com/ci/jobs/ci_job_token/#limit-your-projects-job-token-access) afin de le rendre plus sécurisé. Ce paramètre s'appelait **Limiter l'accès CI_JOB_TOKEN**. Dans GitLab 16.3, nous avons renommé ce paramètre en **Limiter l'accès _depuis_ ce projet** pour plus de clarté.

Dans GitLab 15.9, nous avons introduit un paramètre alternatif appelé [**Groupes et projets autorisés**](https://docs.gitlab.com/ci/jobs/ci_job_token/#add-a-group-or-project-to-the-job-token-allowlist). Ce paramètre contrôle l'accès par jeton de job _à_ votre projet via une liste d'autorisations. Ce nouveau paramètre représente une nette amélioration par rapport à l'original. La première itération a été dépréciée dans GitLab 16.0 et planifiée pour suppression dans GitLab 18.0.

Le paramètre **Limiter l'accès _depuis_ ce projet** est désactivé par défaut pour tous les nouveaux projets. Dans GitLab 16.0 et versions ultérieures, vous ne pouvez pas réactiver ce paramètre une fois qu'il est désactivé dans un projet. Utilisez plutôt le paramètre **Groupes et projets autorisés** pour contrôler l'accès par jeton de job à vos projets.

### Variables DAST `dast_crawl_extract_element_timeout` et `dast_crawl_search_element_timeout` {#dast-dast_crawl_extract_element_timeout-and-dast_crawl_search_element_timeout-variables}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/517250).

Les variables DAST `DAST_CRAWL_EXTRACT_ELEMENT_TIMEOUT` et `DAST_CRAWL_SEARCH_ELEMENT_TIMEOUT` sont dépréciées et seront supprimées dans GitLab 18.0. Lors de leur introduction, les variables fournissaient des contrôles de délai d'attente granulaires pour des interactions spécifiques du navigateur. Ces interactions sont désormais régies par une valeur de délai d'attente commune, ce qui rend les variables inutiles. De plus, en raison d'un problème d'implémentation sous-jacent, les variables n'ont pas été fonctionnelles depuis l'introduction de l'analyseur DAST basé sur le navigateur. La suppression de ces deux variables simplifiera la configuration DAST et offrira une meilleure expérience d'intégration aux utilisateurs.

### DAST `dast_devtools_api_timeout` aura une valeur par défaut inférieure {#dast-dast_devtools_api_timeout-will-have-a-lower-default-value}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/517254).

La variable d'environnement `DAST_DEVTOOLS_API_TIMEOUT` détermine combien de temps un scan DAST attend une réponse du navigateur. Avant GitLab 18.0, la variable a une valeur statique de 45 secondes. Après GitLab 18.0, la variable d'environnement `DAST_DEVTOOLS_API_TIMEOUT` a une valeur dynamique, calculée en fonction d'autres configurations de délai d'attente. Dans la plupart des cas, la valeur de 45 secondes était supérieure à la valeur de délai d'attente de nombreuses fonctions du scanner. La valeur calculée dynamiquement rend la variable `DAST_DEVTOOLS_API_TIMEOUT` plus utile en augmentant le nombre de cas auxquels elle s'applique.

Pour limiter les perturbations potentielles, nous ajusterons progressivement la valeur du délai d'attente par défaut selon le calendrier suivant :

| Valeur du délai d'attente | Jalon         |
|:--------------|:------------------|
| 45            | 17.11 et antérieur |
| 30            | 18.0              |
| 20            | 18.1              |
| 10            | 18.2              |
| 5             | 18.3              |

### Application de la portée du jeton du proxy de dépendances {#dependency-proxy-token-scope-enforcement}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/426887).

Le proxy de dépendances pour les conteneurs accepte les requêtes `docker login` et `docker pull` en utilisant des jetons d'accès personnel ou des jetons d'accès de groupe sans valider leurs portées.

Dans GitLab 18.0, le proxy de dépendances exigera les portées `read_registry` et `write_registry` pour l'authentification. Après ce changement, les tentatives d'authentification utilisant des jetons sans ces portées seront rejetées.

Il s'agit d'un changement majeur. Avant de mettre à niveau, créez de nouveaux jetons d'accès avec les [portées requises](https://docs.gitlab.com/user/packages/dependency_proxy/#authenticate-with-the-dependency-proxy-for-container-images) et mettez à jour vos variables de workflow et vos scripts avec ces nouveaux jetons.

Pour évaluer l'impact de ce changement sur votre instance GitLab Self-Managed, vous pouvez surveiller les journaux d'authentification pour les messages d'avertissement dans GitLab 17.10 et versions ultérieures. Dans votre fichier `auth_json.log`, recherchez les entrées contenant `Dependency proxy missing authentication abilities`. Si vous utilisez les charts Helm GitLab ou GitLab Dedicated, les journaux se trouveront dans `component: "gitlab"` et `subcomponent: "auth_json"`. Ces entrées montrent les tentatives d'authentification utilisant des jetons sans les portées requises, qui échoueront après la mise à niveau vers GitLab 18.0.

### Dépréciation des templates CI/CD Terraform {#deprecate-terraform-cicd-templates}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/438010).

Les templates CI/CD Terraform sont dépréciés et seront supprimés dans GitLab 18.0. Cela affecte les templates suivants :

- `Terraform.gitlab-ci.yml`
- `Terraform.latest.gitlab-ci.yml`
- `Terraform/Base.gitlab-ci.yml`
- `Terraform/Base.latest.gitlab-ci.yml`

Dans GitLab 16.9, un nouveau job est ajouté aux templates pour informer les utilisateurs de la dépréciation. L'avertissement peut être désactivé en remplaçant le job `deprecated-and-will-be-removed-in-18.0` par un job de substitution dans les pipelines concernés.

GitLab ne pourra pas mettre à jour le binaire `terraform` dans les images de job vers une version sous licence BSL.

Pour continuer à utiliser Terraform, clonez les templates et l'[image Terraform](https://gitlab.com/gitlab-org/terraform-images), et maintenez-les selon vos besoins. GitLab fournit des [instructions détaillées](https://gitlab.com/gitlab-org/terraform-images) pour migrer vers une image construite sur mesure.

Comme alternative, nous recommandons d'utiliser le nouveau composant CI/CD OpenTofu sur GitLab.com ou le nouveau template CI/CD OpenTofu sur GitLab Self-Managed. Les composants CI/CD ne sont pas encore disponibles sur GitLab Self-Managed, mais le [ticket #415638](https://gitlab.com/gitlab-org/gitlab/-/issues/415638) propose d'ajouter cette fonctionnalité. Si les composants CI/CD deviennent disponibles sur GitLab Self-Managed, le template CI/CD OpenTofu sera supprimé.

En savoir plus sur le [nouveau composant CI/CD OpenTofu](https://gitlab.com/components/opentofu).

### Dépréciation du format de métadonnées de licence V1 {#deprecate-license-metadata-format-v1}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/438477).

Le jeu de données du format de métadonnées de licence V1 est déprécié et sera supprimé dans GitLab 18.0.

Les utilisateurs ayant le feature flag `package_metadata_synchronization` activé sont invités à mettre à niveau vers GitLab 16.3 ou supérieur, et à supprimer la configuration du feature flag.

### Dépréciation de l'enum `STORAGE` dans l'API GraphQL `NamespaceProjectSortEnum` {#deprecation-of-storage-enum-in-namespaceprojectsortenum-graphql-api}

- Annoncé dans GitLab 17.7
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/396284).

L'enum `STORAGE` dans `NamespaceProjectSortEnum` de l'API GraphQL GitLab sera supprimé dans GitLab 18.0.

Pour vous préparer à ce changement, nous vous recommandons de vérifier et mettre à jour vos requêtes GraphQL qui interagissent avec `NamespaceProjectSortEnum`. Remplacez toute référence au champ `STORAGE` par `EXCESS_REPO_STORAGE_SIZE_DESC`.

### Dépréciation du champ `name` dans l'API GraphQL `ProjectMonthlyUsageType` {#deprecation-of-name-field-in-projectmonthlyusagetype-graphql-api}

- Annoncé dans GitLab 17.7
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/381894).

Le champ `name` dans `ProjectMonthlyUsageType` de l'API GraphQL GitLab sera supprimé dans GitLab 18.0.

Pour vous préparer à ce changement, nous vous recommandons de vérifier et mettre à jour vos requêtes GraphQL qui interagissent avec `ProjectMonthlyUsageType`. Remplacez toute référence au champ `name` par `project.name`.

### Prise en charge de repli pour l'image du contrôleur de chart NGINX GitLab v1.3.1 {#fallback-support-for-gitlab-nginx-chart-controller-image-v131}

- Annoncé dans GitLab 17.6
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/5794).

> [!note]
> Ce changement vous concerne uniquement si vous utilisez le [chart NGINX GitLab](https://docs.gitlab.com/charts/charts/nginx/) et que vous avez défini vos propres règles RBAC NGINX.
>
> Si vous utilisez votre propre [chart NGINX externe](https://docs.gitlab.com/charts/advanced/external-nginx/), ou si vous utilisez le chart NGINX GitLab sans aucune modification des règles RBAC NGINX, cette dépréciation ne vous concerne pas.

Dans GitLab 17.6 (chart Helm 8.6), le chart GitLab a mis à jour l'image du contrôleur NGINX par défaut de la version 1.3.1 à la version 1.11.2. Cette nouvelle version nécessite de nouvelles règles RBAC qui ont été ajoutées à notre chart NGINX GitLab, vous devrez donc créer ces règles. Ce changement est également reporté vers :

- GitLab 17.5.1 (chart Helm 8.5.1)
- GitLab 17.4.3 (chart Helm 8.4.3)
- GitLab 17.3.6 (chart Helm 8.3.6)

> [!note]
> Les dernières versions patch des charts Helm 8.3 à 8.7 contiennent la version 1.11.2 du contrôleur NGINX. Les versions de chart ultérieures incluent la version 1.11.5, car elle contient divers correctifs de sécurité. GitLab 18.0 utilisera par défaut la version 1.11.5 du contrôleur.

Si vous gérez vos propres règles RBAC NGINX, cela signifie que vous avez défini `nginx-ingress.rbac.create` sur `false`. Dans ce cas, de GitLab 17.3 (chart Helm 8.3) jusqu'à GitLab 17.11 (chart Helm 8.11), il existe un mécanisme de repli qui détecte ce changement et utilise l'ancienne image du contrôleur, ce qui signifie que vous n'avez pas besoin de modifier vos règles RBAC.

À partir de GitLab 18.0 (chart Helm 9.0), ce mécanisme de repli sera supprimé, la nouvelle image du contrôleur sera donc utilisée et les nouvelles règles RBAC devront exister.

Si vous souhaitez profiter de la nouvelle image du contrôleur NGINX avant qu'elle ne soit imposée dans GitLab 18.0 :

1. Ajoutez les nouvelles règles RBAC à votre cluster ([voir un exemple](https://gitlab.com/gitlab-org/charts/gitlab/-/merge_requests/3901/diffs?commit_id=93a3cbdb5ad83db95e12fa6c2145df0800493d8b)).
1. Attribuez la valeur `true` à `nginx-ingress.controller.image.disableFallback`.

Pour plus d'informations, consultez la [page de release des charts](https://docs.gitlab.com/charts/releases/8_0/#upgrade-to-86x-851-843-836).

### Limitation de débit Gitaly {#gitaly-rate-limiting}

- Annoncé dans GitLab 17.7
- Suppression dans GitLab 18.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitaly/-/issues/5011).

En raison de la nature très variable des opérations Git et des latences des dépôts, la [limitation de débit basée sur les RPC](https://docs.gitlab.com/administration/gitaly/monitoring/#monitor-gitaly-rate-limiting) de Gitaly est inefficace. La configuration de limites de débit appropriées est difficile et devient souvent obsolète rapidement, car les actions nuisibles génèrent rarement suffisamment de requêtes par seconde pour se démarquer.

Gitaly prend déjà en charge la [limitation de la concurrence](https://docs.gitlab.com/administration/gitaly/concurrency_limiting/) et un [module complémentaire de limitation adaptative](https://docs.gitlab.com/administration/gitaly/concurrency_limiting/#adaptive-concurrency-limiting), qui ont fait leurs preuves en production.

Comme Gitaly n'est pas directement exposé aux réseaux externes et que les couches de protection externes, telles que les équilibreurs de charge, offrent de meilleures protections, la limitation de débit est moins efficace.

C'est pourquoi nous déprécions la limitation de débit au profit de la limitation de la concurrence, plus fiable. La limitation de débit basée sur les RPC de Gitaly sera supprimée dans GitLab 18.0.

### L'IDE Web legacy est déprécié {#legacy-web-ide-is-deprecated}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/513938).

L'implémentation legacy de l'IDE Web GitLab basée sur Vue sera supprimée de GitLab. Ce changement fait suite à notre transition réussie vers l'IDE Web basé sur le fork GitLab VSCode, qui est l'expérience IDE Web par défaut depuis GitLab 15.11.

Cette suppression affecte les utilisateurs qui accèdent encore à l'implémentation legacy de l'IDE Web.

Pour vous préparer à cette suppression, activez le feature flag `vscode_web_ide` sur votre instance GitLab s'il était précédemment désactivé sur l'instance GitLab.

### Limiter le nombre d'actions de politique d'exécution de scan autorisées par politique {#limit-number-of-scan-execution-policy-actions-allowed-per-policy}

- Annoncé dans GitLab 17.5
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/510897).

De nouvelles limites ont été ajoutées pour le nombre maximum d'actions de politique d'exécution de scan autorisées par politique. Ce changement a été introduit dans la version 17.4 derrière les feature flags `scan_execution_policy_action_limit` et `scan_execution_policy_action_limit_group`. Lorsqu'ils sont activés, seules les 10 premières actions d'une politique d'exécution de scan sont traitées.

En ajoutant des limites, nous pouvons garantir les performances et l'évolutivité des politiques de sécurité.

Si des actions supplémentaires sont nécessaires, limitez les politiques existantes à 10 actions maximum. Ensuite, créez de nouvelles politiques d'exécution de scan avec des actions supplémentaires, dans la limite de 5 politiques d'exécution de scan par projet de politique de sécurité.

Pour les administrateurs de GitLab Self-Managed et GitLab Dedicated, vous pouvez configurer une limite personnalisée avec le paramètre d'application `scan_execution_policies_action_limit`.

### Actions `scan` limitées dans une politique d'exécution de scan {#limited-scan-actions-in-a-scan-execution-policy}

- Annoncé dans GitLab 17.5
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/472213).

Sur GitLab.com, à partir de GitLab 18.0, les [politiques d'exécution de scan](https://docs.gitlab.com/user/application_security/policies/scan_execution_policies/) sont limitées à 10 actions `scan` par politique. Vous ne pouvez pas créer de nouvelles politiques dépassant la limite, ni mettre à jour des politiques existantes si elles dépassent la limite. Pour toute politique existante dépassant la limite, seules les 10 premières actions `scan` de la politique sont exécutées.

Sur les instances GitLab Self-Managed et GitLab Dedicated, vous pouvez configurer une limite personnalisée avec le paramètre d'application `scan_execution_policies_action_limit`. Pour ces instances, les limites sont par défaut à zéro action. Nous recommandons de configurer une limite de 10 actions.

### Mise à jour majeure du sous-chart Prometheus {#major-update-of-the-prometheus-subchart}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/5927).

Avec GitLab 18.0 et le chart GitLab 9.0, le sous-chart Prometheus sera mis à jour de la version 15.3 à la version 27.3. Avec cette mise à jour, Prometheus 3 sera livré par défaut.

Des étapes manuelles sont nécessaires pour effectuer la mise à niveau. Si vous avez Alertmanager, Node Exporter ou Pushgateway activé, vous devrez également mettre à jour vos valeurs Helm.

Veuillez consulter le [guide de migration](https://docs.gitlab.com/charts/releases/9_0/#prometheus-upgrade) pour plus d'informations.

### Nouvelles limites de conservation des données pour les vulnérabilités sur GitLab.com {#new-data-retention-limits-for-vulnerabilities-on-gitlabcom}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/epics/16629).

Dans GitLab 18.0, nous introduisons une nouvelle limite de conservation des données pour les clients GitLab.com Ultimate afin d'améliorer les performances et la fiabilité du système. La limite de conservation des données affecte la durée de stockage de vos données de vulnérabilité. Les vulnérabilités datant de plus de 12 mois qui n'ont pas été mises à jour sont automatiquement déplacées vers des archives de stockage froid. Ces archives :

- Restent accessibles et téléchargeables via l'interface GitLab.
- Sont conservées pendant 3 ans.
- Sont définitivement supprimées après 3 ans.

### PostgreSQL 14 et 15 ne sont plus pris en charge {#postgresql-14-and-15-no-longer-supported}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/521663).

GitLab suit un [calendrier de mise à niveau annuel pour PostgreSQL](https://handbook.gitlab.com/handbook/engineering/data-engineering/database-excellence/database-frameworks/postgresql-upgrade-cadence/).

La prise en charge de PostgreSQL 14 et 15 est prévue pour suppression dans GitLab 18.0. Dans GitLab 18.0, PostgreSQL 16 devient la version minimale requise de PostgreSQL.

PostgreSQL 14 et 15 seront pris en charge pour l'intégralité du cycle de release GitLab 17. PostgreSQL 16 sera également pris en charge pour les instances qui souhaitent mettre à niveau avant GitLab 18.0.

Si vous exécutez une instance PostgreSQL unique installée à l'aide d'un package Omnibus Linux, une mise à niveau automatique peut être tentée avec la version 17.11. Assurez-vous de disposer de suffisamment d'espace disque pour accueillir la mise à niveau. Pour plus d'informations, consultez la [documentation de base de données Omnibus](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server).

### La page Projets dans les paramètres de groupe est dépréciée {#project-page-in-group-settings-is-deprecated}

- Annoncé dans GitLab 17.0
- Fin de support dans GitLab 17.9
- Suppression dans GitLab 18.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/443347).

Les propriétaires de groupe peuvent accéder à une page de projets dans les paramètres de groupe qui répertorie les projets contenus dans le groupe, avec des options pour créer, modifier ou supprimer un projet, ainsi qu'un lien vers la page Membres de chaque projet. Toutes ces fonctionnalités sont disponibles sur la page de présentation du groupe et les pages Membres respectives des projets. En raison du faible usage de la page des projets dans les paramètres de groupe et de son accessibilité limitée, cette page sera dépréciée. Ce changement n'affecte que l'interface utilisateur. L'API sous-jacente restera disponible, de sorte que la création, la modification et la suppression de projets pourront toujours être effectuées via l'[API Projects](https://docs.gitlab.com/api/projects/). Dans la version 17.9, nous implémenterons une redirection vers la page de présentation du groupe depuis cette page. La page des projets sera entièrement supprimée des paramètres de groupe dans la version 18.0.

### Le point de terminaison de l'API REST `pre_receive_secret_detection_enabled` est déprécié {#rest-api-endpoint-pre_receive_secret_detection_enabled-is-deprecated}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/514413).

Le point de terminaison de l'API REST `pre_receive_secret_detection_enabled` est déprécié en faveur de `secret_push_protection_enabled`. Nous renommons certains champs d'API pour refléter le changement de nom de la fonctionnalité `pre_receive_secret_detection` en `secret_push_protection`.

Nous avons ajouté le nouveau nom de champ d'API, mais ne supprimerons plus l'ancien nom de champ dans GitLab 18.0 comme annoncé initialement.

Nous mettrons tout de même à jour la base de données pour [supprimer](https://gitlab.com/gitlab-org/gitlab/-/issues/512996) l'ancienne colonne de base de données `pre_receive_secret_detection_enabled`, mais vous pourrez utiliser l'un ou l'autre nom de champ d'API. Les deux refléteront la valeur de la nouvelle colonne de base de données `secret_push_protection_enabled`.

### Les packages Raspberry Pi 32 bits sont dépréciés {#raspberry-pi-32-bit-packages-are-deprecated}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/519113).

À partir de la version 18.0 de GitLab, nous ne fournirons plus de packages 32 bits pour Raspberry Pi. Vous devez utiliser Raspberry Pi OS 64 bits et [installer les packages Debian `arm64`](https://about.gitlab.com/install/#debian). Pour obtenir des informations sur la sauvegarde des données sur un système d'exploitation 32 bits et leur restauration sur un système d'exploitation 64 bits, voir [Mise à niveau des systèmes d'exploitation pour PostgreSQL](https://docs.gitlab.com/administration/postgresql/upgrading_os/).

### Rejeter les politiques d'extraction d'images de conteneurs absentes de `allowed_pull_policies` {#reject-container-image-pull-policies-not-in-allowed_pull_policies}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/516107).

Toutes les politiques d'extraction configurées doivent être présentes dans la [configuration `allowed_pull_policies`](https://docs.gitlab.com/runner/executors/docker/#allow-docker-pull-policies) spécifiée dans le fichier `config.toml` du runner. Dans le cas contraire, le job doit échouer avec une erreur `incompatible pull policy`.

Dans l'implémentation actuelle, lorsque plusieurs politiques d'extraction sont définies, les jobs réussissent si au moins une politique d'extraction correspond à celles dans `allowed-pull-policies`, même si d'autres politiques ne sont pas incluses.

Dans GitLab 18.0, les jobs échoueront uniquement si aucune des politiques d'extraction ne correspond à celles dans `allowed-pull-policies`. Cependant, contrairement au comportement actuel, les jobs n'utiliseront que les politiques d'extraction répertoriées dans `allowed-pull-policies`. Cette distinction peut entraîner l'échec dans GitLab 18.0 de jobs qui réussissent actuellement.

### Suppression du champ GraphQL duoProAssignedUsersCount {#remove-duoproassigneduserscount-graphql-field}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/498671).

Dans la version 18.0, nous supprimons le champ GraphQL `duoProAssignedUsersCount`. Les utilisateurs peuvent rencontrer des problèmes s'ils utilisent ce champ avec l'[API `aiMetrics`](https://docs.gitlab.com/api/graphql/reference/objects/#aimetrics), et peuvent utiliser à la place `duoAssignedUsersCount`. Cette suppression fait partie du [correctif pour comptabiliser les utilisateurs assignés à GitLab Duo Pro et aux sièges Duo](https://gitlab.com/gitlab-org/gitlab/-/issues/485510).

### Renommer la mutation GraphQL `setPreReceiveSecretDetection` en `setSecretPushProtection` {#rename-setprereceivesecretdetection-graphql-mutation-to-setsecretpushprotection}

- Annoncé dans GitLab 17.7
- Suppression dans GitLab 18.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/514414).

La mutation GraphQL `setPreReceiveSecretDetection` a été renommée en `setSecretPushProtection`. Nous renommons également certains champs dans la réponse de la mutation pour refléter le changement de nom de la fonctionnalité `pre_receive_secret_detection` en `secret_push_protection`.

Nous avons ajouté le nouveau nom de mutation, mais ne supprimerons plus l'ancien nom de mutation dans GitLab 18.0 comme annoncé initialement.

Nous mettrons tout de même à jour la base de données pour [supprimer](https://gitlab.com/gitlab-org/gitlab/-/issues/512996) l'ancienne colonne de base de données `pre_receive_secret_detection_enabled`, mais vous pourrez utiliser l'un ou l'autre nom de mutation. Les deux refléteront la valeur de la nouvelle colonne de base de données `secret_push_protection_enabled`.

### Renommer les options pour ignorer la détection des secrets GitGuardian {#rename-options-to-skip-gitguardian-secret-detection}

- Annoncé dans GitLab 17.3
- Suppression dans GitLab 18.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/470119).

Les options pour ignorer la détection des secrets GitGuardian, `[skip secret detection]` et `secret_detection.skip_all`, sont dépréciées. Vous devez utiliser `[skip secret push protection]` et `secret_push_protection.skip_all` à la place.

Bien que nous recommandions d'utiliser la nouvelle formulation, nous ne supprimerons plus l'ancienne option dans GitLab 18.0.

### Remplacer le champ GraphQL `add_on_purchase` par `add_on_purchases` {#replace-add_on_purchase-graphql-field-with-add_on_purchases}

- Annoncé dans GitLab 17.4
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/476858).

Le champ GraphQL `add_on_purchase` sera déprécié dans GitLab 17.4 et supprimé dans GitLab 18.0. Utilisez plutôt le champ `add_on_purchases`.

### Remplacer le champ GraphQL d'espace de nommage `add_on_purchase` par `add_on_purchases` {#replace-namespace-add_on_purchase-graphql-field-with-add_on_purchases}

- Annoncé dans GitLab 17.5
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/489850).

Le champ GraphQL d'espace de nommage `add_on_purchase` sera déprécié dans GitLab 17.5 et supprimé dans GitLab 18.0. Utilisez plutôt le champ racine `add_on_purchases`.

### Prise en charge de SUSE Linux Enterprise Server 15 SP2 {#support-for-suse-linux-enterprise-server-15-sp2}

- Annoncé dans GitLab 17.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8888).

Le support à long terme (LTSS) de SUSE Linux Enterprise Server (SLES) 15 SP2 a pris fin en décembre 2024.

Par conséquent, nous ne prendrons plus en charge la distribution SLES SP2 pour les installations de packages Linux. Vous devez mettre à niveau vers SLES 15 SP6 pour bénéficier d'un support continu.

### L'argument GraphQL `direction` pour `ciJobTokenScopeRemoveProject` est déprécié {#the-direction-graphql-argument-for-cijobtokenscoperemoveproject-is-deprecated}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/383084).

L'argument GraphQL `direction` pour la mutation `ciJobTokenScopeRemoveProject` est déprécié. Suite au [changement de portée du jeton de job CI/CD par défaut](https://docs.gitlab.com/update/deprecations/#default-cicd-job-token-ci_job_token-scope-changed) annoncé dans GitLab 15.9, l'argument `direction` sera par défaut `INBOUND` et `OUTBOUND` ne sera plus valide dans GitLab 17.0. Nous supprimerons l'argument `direction` dans GitLab 18.0.

Si vous utilisez `OUTBOUND` avec l'argument `direction` pour contrôler la direction de l'accès par jeton de votre projet, vos pipelines qui utilisent des jetons de job risquent d'échouer à l'authentification. Pour garantir que les pipelines continuent à s'exécuter comme prévu, vous devrez explicitement [ajouter les autres projets à la liste d'autorisations de votre projet](https://docs.gitlab.com/ci/jobs/ci_job_token/#add-a-group-or-project-to-the-job-token-allowlist).

### Basculer la confidentialité des notes sur les API {#toggle-notes-confidentiality-on-apis}

- Annoncé dans GitLab 14.10
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/350670).

La modification de la confidentialité des notes via les API REST et GraphQL est en cours de dépréciation. La mise à jour de l'attribut de confidentialité des notes n'est plus prise en charge par aucun moyen. Nous effectuons ce changement pour simplifier l'expérience et empêcher que des informations privées ne soient exposées involontairement.

### `git_data_dirs` pour la configuration des stockages Gitaly {#git_data_dirs-for-configuring-gitaly-storages}

- Annoncé dans GitLab 16.0
- Suppression dans GitLab 18.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8786).

La prise en charge de l'utilisation de `git_data_dirs` pour configurer les stockages Gitaly pour les instances du package Linux est dépréciée [depuis la version 16.0](https://docs.gitlab.com/update/versions/gitlab_16_changes/#gitaly-configuration-structure-change) et sera supprimée dans la version 18.0.

Pour les instructions de migration, consultez [Migration depuis `git_data_dirs`](https://docs.gitlab.com/omnibus/settings/configuration/#migrating-from-git_data_dirs).

## GitLab 17.11 {#gitlab-1711}

### L'octroi OAuth ROPC sans informations d'identification client est déprécié {#oauth-ropc-grant-without-client-credentials-is-deprecated}

- Annoncé dans GitLab 17.11
- Suppression dans GitLab 17.11 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/535298).

GitLab.com exige l'authentification client pour l'octroi OAuth Resource Owner Password Credentials (ROPC) depuis le 8 avril 2025. ROPC a été omis par le groupe de travail OAuth dans la version RFC 2.1. Les intégrations ROPC existantes sans informations d'identification client connaîtront une interruption de service après cette date. Si vous rencontrez une interruption, mettez à jour vos intégrations pour inclure les informations d'identification client avant la date limite. Plus d'informations sont disponibles [sur notre blog](https://about.gitlab.com/blog/improving-oauth-ropc-security-on-gitlab-com/).

## GitLab 17.9 {#gitlab-179}

### Prise en charge d'openSUSE Leap 15.5 {#support-for-opensuse-leap-155}

- Annoncé dans GitLab 17.6
- Suppression dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8778).

Le support à long terme (LTSS) pour [openSUSE Leap se termine en décembre 2024](https://en.opensuse.org/Lifetime#openSUSE_Leap).

Par conséquent, nous ne prendrons plus en charge la distribution openSUSE Leap 15.5 pour les installations de packages Linux. Les utilisateurs doivent mettre à niveau vers openSUSE Leap 15.6 pour bénéficier d'un support continu.

## GitLab 17.8 {#gitlab-178}

### Prise en charge de CentOS 7 {#support-for-centos-7}

- Annoncé dans GitLab 17.6
- Suppression dans GitLab 17.8
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8714).

Le support à long terme (LTSS) pour [CentOS 7 a pris fin en juin 2024](https://www.redhat.com/en/topics/linux/centos-linux-eol).

Par conséquent, nous ne prendrons plus en charge la distribution CentOS 7 pour les installations de packages Linux. Les utilisateurs doivent mettre à niveau vers un autre système d'exploitation pour bénéficier d'un support continu.

### Prise en charge d'Oracle Linux 7 {#support-for-oracle-linux-7}

- Annoncé dans GitLab 17.6
- Suppression dans GitLab 17.8
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8746).

Le support à long terme (LTSS) pour [Oracle Linux 7 se termine en décembre 2024](https://wiki.debian.org/LTS).

Par conséquent, nous ne prendrons plus en charge la distribution Oracle Linux 7 pour les installations de packages Linux. Les utilisateurs doivent mettre à niveau vers Oracle Linux 8 pour bénéficier d'un support continu.

### Prise en charge de Raspberry Pi OS Buster {#support-for-raspberry-pi-os-buster}

- Annoncé dans GitLab 17.6
- Suppression dans GitLab 17.8
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8734).

Le support à long terme (LTSS) de Raspberry Pi OS Buster (anciennement connu sous le nom de Raspbian Buster) a pris fin en juin 2024.

Par conséquent, nous ne prendrons plus en charge la distribution PiOS Buster pour les installations de packages Linux. Les utilisateurs doivent mettre à niveau vers PiOS Bullseye pour bénéficier d'un support continu.

### Prise en charge de Red Hat Enterprise Linux 7 {#support-for-red-hat-enterprise-linux-7}

- Annoncé dans GitLab 17.6
- Suppression dans GitLab 17.8
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8714).

Red Hat Enterprise Linux (RHEL) 7 a atteint [la fin du support de maintenance en juin 2024](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux/rhel-7-end-of-maintenance).

Par conséquent, nous ne publierons plus de packages Linux pour RHEL 7 et les systèmes d'exploitation compatibles RHEL 7. Les utilisateurs doivent mettre à niveau vers RHEL 8 pour bénéficier d'un support continu.

### Prise en charge de Scientific Linux 7 {#support-for-scientific-linux-7}

- Annoncé dans GitLab 17.6
- Suppression dans GitLab 17.8
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8745).

Le support à long terme (LTSS) pour [Scientific Linux 7 a pris fin en juin 2024](https://scientificlinux.org/downloads/sl-versions/sl7/).

Par conséquent, nous ne prendrons plus en charge la distribution Scientific Linux pour les installations de packages Linux. Les utilisateurs doivent mettre à niveau vers un autre système d'exploitation compatible RHEL.

## GitLab 17.7 {#gitlab-177}

### La gestion des erreurs pour le point de terminaison de l'API REST `/repository/tree` renvoie `404` {#error-handling-for-repositorytree-rest-api-endpoint-returns-404}

- Annoncé dans GitLab 16.5
- Suppression dans GitLab 17.7 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/420865).

Dans GitLab 17.7, le comportement de gestion des erreurs pour le point de terminaison de l'API listant l'arborescence du dépôt, `/projects/:id/repository/tree`, est mis à jour lorsqu'un chemin demandé est introuvable. Le point de terminaison renvoie désormais un code de statut `404 Not Found`. Auparavant, le code de statut était `200 OK`.

Cette modification a été activée sur GitLab.com dans GitLab 16.5 et sera disponible pour les instances self-managed dans GitLab 17.7.

Si votre implémentation repose sur la réception d'un code de statut `200` avec un tableau vide pour les chemins manquants, vous devez mettre à jour votre gestion des erreurs afin de prendre en charge les nouvelles réponses `404`.

### TLS 1.0 et 1.1 ne sont plus pris en charge {#tls-10-and-11-no-longer-supported}

- Annoncé dans GitLab 17.4
- Suppression dans GitLab 17.7
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/164512).

La prise en charge à long terme (LTS) d'[OpenSSL version 1.1.1 a pris fin en septembre 2023](https://endoflife.date/openssl). Par conséquent, OpenSSL 3 sera la version par défaut dans GitLab 17.7. GitLab intègre OpenSSL 3, vous n'êtes donc pas tenu d'apporter des modifications à votre système d'exploitation.

Avec la mise à niveau vers OpenSSL 3 :

- GitLab requiert TLS 1.2 ou une version supérieure pour toutes les connexions TLS entrantes et sortantes.
- Les certificats TLS/SSL doivent présenter au moins 112 bits de sécurité. Les clés RSA, DSA et DH de moins de 2 048 bits, ainsi que les clés ECC de moins de 224 bits, sont interdites.

Consultez les [modifications de GitLab 17.5](https://docs.gitlab.com/update/versions/gitlab_17_changes/#1750) pour plus de détails.

## GitLab 17.6 {#gitlab-176}

### Prise en charge de Debian 10 {#support-for-debian-10}

- Annoncé dans GitLab 17.3
- Suppression dans GitLab 17.6
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8607).

La prise en charge à long terme (LTSS) de [Debian 10 a pris fin en juin 2024](https://wiki.debian.org/LTS).

Par conséquent, nous ne prendrons plus en charge la distribution Debian 10 pour les installations de paquets Linux. Les utilisateurs sont invités à mettre à niveau vers Debian 11 ou Debian 12 pour continuer à bénéficier du support.

## GitLab 17.4 {#gitlab-174}

### Suppression de l'onglet Needs de la vue pipeline {#removed-needs-tab-from-the-pipeline-view}

- Annoncé dans GitLab 17.1
- Suppression dans GitLab 17.4
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/336560).

Nous supprimons l'onglet Needs de la vue pipeline, car il duplique les informations affichées dans la vue pipeline standard avec l'option de regroupement **Dépendances des jobs**. Nous continuerons à améliorer les vues dans le graphe de pipeline principal à l'avenir.

## GitLab 17.3 {#gitlab-173}

### Les analyseurs Secure conformes à FIPS passeront d'UBI Minimal à UBI Micro {#fips-compliant-secure-analyzers-will-change-from-ubi-minimal-to-ubi-micro}

- Annoncé dans GitLab 17.2
- Suppression dans GitLab 17.3
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/471869).

Nous mettons à jour l'image de base de certains analyseurs utilisés pour analyser votre code à la recherche de vulnérabilités de sécurité. Nous modifions uniquement les images d'analyseurs déjà basées sur Red Hat Universal Base Image (UBI). Cette modification ne vous concerne donc que si vous avez spécifiquement activé le [mode FIPS](https://docs.gitlab.com/development/fips_compliance/) pour l'analyse de sécurité. Les images par défaut utilisées par les analyses de sécurité GitLab ne sont pas affectées, car elles ne sont pas basées sur UBI.

Dans GitLab 17.3, nous allons remplacer l'image de base des analyseurs basés sur UBI, en passant d'UBI Minimal à [UBI Micro](https://www.redhat.com/en/blog/introduction-ubi-micro), qui inclut moins de paquets inutiles et ne comporte pas de gestionnaire de paquets. Les images mises à jour seront plus légères et seront affectées par moins de vulnérabilités dans les paquets fournis par le système d'exploitation.

La [Déclaration de support](https://about.gitlab.com/support/statement-of-support/#ci-cd-templates) de l'équipe Support GitLab exclut les personnalisations non documentées, y compris celles qui reposent sur le contenu spécifique de l'image de l'analyseur. Par exemple, l'installation de paquets supplémentaires dans un `before_script` n'est pas une modification prise en charge. Néanmoins, si vous dépendez de ce type de personnalisation, consultez le [ticket de dépréciation de cette modification](https://gitlab.com/gitlab-org/gitlab/-/issues/471869#action-required) pour savoir comment réagir à ce changement ou pour nous faire part de vos personnalisations actuelles.

## GitLab 17.0 {#gitlab-170}

### L'option `ca-cert-file` de l'agent pour Kubernetes a été renommée {#agent-for-kubernetes-option-ca-cert-file-renamed}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/437728).

Dans l'agent GitLab pour Kubernetes (agentk), l'option de ligne de commande `--ca-cert-file` et la valeur de chart Helm correspondante `config.caCert` ont été renommées respectivement en `--kas-ca-cert-file` et `config.kasCaCert`.

Les anciennes options `--ca-cert-file` et `config.caCert` sont dépréciées et seront supprimées dans GitLab 17.0.

### La prise en charge d'Herokuish par Auto DevOps est dépréciée {#auto-devops-support-for-herokuish-is-deprecated}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/211643).

La prise en charge d'Herokuish par Auto DevOps est dépréciée au profit de [Cloud Native Buildpacks](https://docs.gitlab.com/topics/autodevops/stages/#auto-build-using-cloud-native-buildpacks). Vous devriez [migrer vos builds d'Herokuish vers Cloud Native Buildpacks](https://docs.gitlab.com/topics/autodevops/stages/#moving-from-herokuish-to-cloud-native-buildpacks). Depuis GitLab 14.0, Auto Build utilise Cloud Native Buildpacks par défaut.

Étant donné que Cloud Native Buildpacks ne prend pas en charge les tests automatiques, la fonctionnalité Auto Test d'Auto DevOps est également dépréciée.

### Liens d'ancrage Markdown autogénérés avec des caractères tiret (`-`) {#autogenerated-markdown-anchor-links-with-dash---characters}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/440733).

GitLab crée automatiquement des liens d'ancrage pour tous les titres, afin que vous puissiez créer un lien vers un endroit spécifique dans un document Markdown ou une page wiki. Cependant, dans certains cas particuliers, l'ancre autogénérée est créée avec moins de caractères tiret (`-`) que ce à quoi la plupart des utilisateurs s'attendent. Par exemple, avec un titre contenant `## Step - 1`, la plupart des autres outils et linters Markdown s'attendraient à `#step---1`. Mais GitLab génère une ancre `#step-1`, les tirets consécutifs étant compressés en un seul.

Dans GitLab 17.0, nous alignerons nos ancres autogénérées sur la norme du secteur en ne supprimant plus les tirets consécutifs. Si vous avez des documents Markdown avec des liens vers des titres susceptibles de contenir plusieurs tirets dans la version 17.0, vous devez mettre à jour le titre pour éviter ce cas particulier. Dans l'exemple ci-dessus, vous pouvez remplacer `## Step - 1` par `## Step 1` pour vous assurer que les liens internes à la page continuent de fonctionner.

### Le tri par défaut de CiRunner.projects est modifié en `id_desc` {#cirunnerprojects-default-sort-is-changing-to-id_desc}

- Annoncé dans GitLab 16.0
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/372117).

La valeur de l'ordre de tri par défaut du champ `CiRunner.projects` passera de `id_asc` à `id_desc`. Si vous dépendez de l'ordre des projets retournés, à savoir `id_asc`, modifiez vos scripts pour rendre ce choix explicite.

### Framework de conformité dans les paramètres généraux {#compliance-framework-in-general-settings}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/422783).

Nous avons déplacé la gestion du framework de conformité vers les rapports de frameworks et de projets dans le [Centre de conformité](https://docs.gitlab.com/user/compliance/compliance_center/).

Par conséquent, dans GitLab 17.0, nous supprimons la gestion des frameworks de conformité de la page de paramètres **Général** des groupes et des projets.

### Prise en charge des pilotes de stockage Swift et OSS par le registre de conteneurs {#container-registry-support-for-the-swift-and-oss-storage-drivers}

- Annoncé dans GitLab 16.6
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/container-registry/-/issues/1141).

Le registre de conteneurs utilise des pilotes de stockage pour fonctionner avec diverses plateformes de stockage d'objets. Bien que le code de chaque pilote soit relativement autonome, ces pilotes représentent une charge de maintenance importante. Chaque implémentation de pilote est unique et apporter des modifications à un pilote requiert un haut niveau d'expertise dans ce pilote spécifique.

Dans notre démarche de réduction des coûts de maintenance, nous déprécions la prise en charge d'OSS (Object Storage Service) et d'OpenStack Swift. Ces deux pilotes ont déjà été supprimés de la distribution Docker en amont. Cela contribue à aligner le registre de conteneurs sur l'offre produit plus large de GitLab en ce qui concerne la [prise en charge du stockage d'objets](https://docs.gitlab.com/administration/object_storage/#supported-object-storage-providers).

OSS dispose d'un [mode de compatibilité S3](https://www.alibabacloud.com/help/en/oss/developer-reference/compatibility-with-amazon-s3). Envisagez de l'utiliser si vous ne pouvez pas migrer vers un pilote pris en charge. Swift est [compatible avec les opérations de l'API S3](https://docs.openstack.org/swift/latest/s3_compat.html), requises également par le pilote de stockage S3.

### Dépréciation des variables de configuration avancée DAST ZAP {#dast-zap-advanced-configuration-variables-deprecation}

- Annoncé dans GitLab 15.7
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/383467).

Avec la disponibilité générale du nouvel analyseur DAST basé sur navigateur dans GitLab 15.7, nous travaillons à en faire l'analyseur DAST par défaut à un moment donné dans le futur. En préparation de cette transition, les variables DAST héritées suivantes sont dépréciées et leur suppression est planifiée dans GitLab 17.0 : `DAST_ZAP_CLI_OPTIONS` et `DAST_ZAP_LOG_CONFIGURATION`. Ces variables permettaient la configuration avancée de l'analyseur DAST hérité, qui était basé sur OWASP ZAP. Le nouvel analyseur basé sur navigateur n'inclura pas les mêmes fonctionnalités, car celles-ci étaient spécifiques au fonctionnement de ZAP.

Ces trois variables seront supprimées dans GitLab 17.0.

### Propriétés de métadonnées SBOM incorrectes dans l'analyse des dépendances {#dependency-scanning-incorrect-sbom-metadata-properties}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/438779).

GitLab 17.0 supprime la prise en charge des propriétés de métadonnées suivantes dans les rapports SBOM CycloneDX :

- `gitlab:dependency_scanning:input_file`
- `gitlab:dependency_scanning:package_manager`

Ces propriétés ont été ajoutées dans GitLab 15.7 au SBOM produit par l'analyse des dépendances. Cependant, ces propriétés étaient incorrectes et ne correspondaient pas à la [taxonomie des propriétés CycloneDX de GitLab](https://docs.gitlab.com/development/sec/cyclonedx_property_taxonomy/). Les propriétés correctes suivantes ont été ajoutées dans GitLab 15.11 pour remédier à ce problème :

- `gitlab:dependency_scanning:input_file:path`
- `gitlab:dependency_scanning:package_manager:name`

Les propriétés incorrectes ont été conservées pour des raisons de compatibilité ascendante. Elles sont désormais dépréciées et seront supprimées dans la version 17.0.

### Prise en charge de sbt 1.0.X dans l'analyse des dépendances {#dependency-scanning-support-for-sbt-10x}

- Annoncé dans GitLab 16.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/415835).

La prise en charge de versions très anciennes de sbt nous empêche d'améliorer notre support pour d'autres cas d'usage avec ce gestionnaire de paquets sans augmenter notre coût de maintenance.

La version 1.1.0 de sbt a été publiée il y a 6 ans et les utilisateurs sont invités à mettre à niveau depuis la version 1.0.x, car l'analyse des dépendances ne fonctionnera plus.

### Déprécier les champs GraphQL liés à l'augmentation temporaire de stockage {#deprecate-graphql-fields-related-to-the-temporary-storage-increase}

- Annoncé dans GitLab 16.7
- Suppression dans GitLab 17.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/385720).

Les champs GraphQL `isTemporaryStorageIncreaseEnabled` et `temporaryStorageIncreaseEndsOn` ont été dépréciés. Ces champs GraphQL sont liés au projet d'augmentation temporaire de stockage. Le projet a été annulé et les champs n'étaient pas utilisés.

### Dépréciation du scanner Grype pour l'analyse de conteneurs {#deprecate-grype-scanner-for-container-scanning}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/439164).

La prise en charge du scanner Grype dans l'analyseur d'analyse de conteneurs GitLab est dépréciée dans GitLab 16.9.

À partir de GitLab 17.0, l'analyseur Grype ne sera plus maintenu, à l'exception de corrections limitées, comme expliqué dans notre [déclaration de support](https://about.gitlab.com/support/statement-of-support/#version-support).

Les utilisateurs sont invités à utiliser le paramètre par défaut pour `CS_ANALYZER_IMAGE`, qui utilise le scanner Trivy.

La version majeure actuelle de l'image de l'analyseur Grype continuera à être mise à jour avec la dernière base de données d'avis et les paquets du système d'exploitation jusqu'à GitLab 19.0, date à laquelle l'analyseur cessera de fonctionner.

Pour continuer à utiliser Grype après la version 19.0, consultez la [documentation d'intégration du scanner de sécurité](https://docs.gitlab.com/development/integrations/secure/) pour savoir comment créer votre propre intégration avec GitLab.

### Dépréciation des templates CI de License Scanning {#deprecate-license-scanning-ci-templates}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/439157).

GitLab 17.0 supprime les templates CI de License Scanning :

- [`Jobs/License-Scanning.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/6d9956863d3cd066edc50a29767c2cd4a939c6fd/lib/gitlab/ci/templates/Jobs/License-Scanning.gitlab-ci.yml)
- [`Jobs/License-Scanning.latest.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/6d9956863d3cd066edc50a29767c2cd4a939c6fd/lib/gitlab/ci/templates/Jobs/License-Scanning.latest.gitlab-ci.yml)
- [`Security/License-Scanning.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/6d9956863d3cd066edc50a29767c2cd4a939c6fd/lib/gitlab/ci/templates/Security/License-Scanning.gitlab-ci.yml)

Les configurations CI incluant l'un des templates ci-dessus cesseront de fonctionner dans GitLab 17.0.

Les utilisateurs sont invités à utiliser à la place [l'analyse des licences des fichiers CycloneDX](https://docs.gitlab.com/user/compliance/license_scanning_of_cyclonedx_files/).

### Dépréciation de Python 3.9 dans l'analyse des dépendances et l'analyse des licences {#deprecate-python-39-in-dependency-scanning-and-license-scanning}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/441201).

À partir de GitLab 16.9, la prise en charge de Python 3.9 dans l'analyse des dépendances et l'analyse des licences est dépréciée. Dans GitLab 17.0, Python 3.10 est la version par défaut pour le job CI/CD d'analyse des dépendances.

À partir de GitLab 17.0, les fonctionnalités d'analyse des dépendances et d'analyse des licences ne prendront plus en charge les projets nécessitant Python 3.9 sans un [fichier de verrouillage compatible](https://docs.gitlab.com/user/application_security/dependency_scanning/#obtaining-dependency-information-by-parsing-lockfiles).

### Dépréciation de Windows CMD dans GitLab Runner {#deprecate-windows-cmd-in-gitlab-runner}

- Annoncé dans GitLab 16.1
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/414864).

Dans GitLab 11.11, l'exécuteur Windows Batch, le shell CMD, a été déprécié dans GitLab Runner au profit de PowerShell. Depuis lors, le shell CMD a continué à être pris en charge dans GitLab Runner. Cela a cependant engendré une complexité supplémentaire, tant pour l'équipe d'ingénierie que pour les clients utilisant le runner sur Windows. Nous prévoyons de supprimer complètement la prise en charge de Windows CMD dans GitLab Runner dans la version 17.0. Les clients doivent prévoir d'utiliser PowerShell lorsqu'ils utilisent le runner sur Windows avec l'exécuteur shell. Les clients peuvent fournir des commentaires ou poser des questions dans le ticket de suppression, [ticket 29479](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/29479).

### Dépréciation des champs GraphQL `CiRunner` dupliqués dans `CiRunnerManager` {#deprecate-cirunner-graphql-fields-duplicated-in-cirunnermanager}

- Annoncé dans GitLab 16.2
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/415185).

Ces champs (`architectureName`, `ipAddress`, `platformName`, `revision`, `version`) sont désormais dépréciés dans le type GraphQL [`CiRunner`](https://docs.gitlab.com/api/graphql/reference/objects/#cirunner), car ils sont dupliqués suite à l'introduction des gestionnaires de runners regroupés au sein d'une configuration de runner.

### Dépréciation du job `fmt` dans le template CI/CD du module Terraform {#deprecate-fmt-job-in-terraform-module-cicd-template}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/440249).

Le job `fmt` dans les templates CI/CD du module Terraform est déprécié et sera supprimé dans GitLab 17.0. Cela affecte les templates suivants :

- `Terraform-Module.gitlab-ci.yml`
- `Terraform/Module-Base.gitlab-ci.yml`

Vous pouvez rajouter manuellement un job Terraform `fmt` à votre pipeline en utilisant :

```yaml
fmt:
  image: hashicorp/terraform
  script: terraform fmt -chdir "$TF_ROOT" -check -diff -recursive
```

Vous pouvez également utiliser le template `fmt` du [composant CI/CD OpenTofu](https://gitlab.com/components/opentofu).

### Dépréciation du champ `message` des fonctionnalités de gestion des vulnérabilités {#deprecate-message-field-from-vulnerability-management-features}

- Annoncé dans GitLab 16.1
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/411573).

Cette merge request déprécie le champ `message` sur la mutation GraphQL `VulnerabilityCreate` et dans la colonne `AdditionalInfo` de l'export de vulnérabilités. Le champ message a été supprimé du schéma des rapports de sécurité dans GitLab 16.0 et n'est plus utilisé ailleurs.

### Dépréciation de `terminationGracePeriodSeconds` dans l'exécuteur Kubernetes de GitLab Runner {#deprecate-terminationgraceperiodseconds-in-the-gitlab-runner-kubernetes-executor}

- Annoncé dans GitLab 16.3
- Fin de support dans GitLab 17.0
- Suppression dans GitLab 17.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/28165).

Le paramètre `terminationGracePeriodSeconds` de l'exécuteur Kubernetes de GitLab Runner est déprécié et sera supprimé dans GitLab 17.0. Pour gérer le nettoyage et la fin des pods worker GitLab Runner sur Kubernetes, les clients doivent plutôt configurer `cleanupGracePeriodSeconds` et `podTerminationGracePeriodSeconds`. Pour plus d'informations sur l'utilisation de `cleanupGracePeriodSeconds` et `podTerminationGracePeriodSeconds`, consultez la [documentation de l'exécuteur GitLab Runner](https://docs.gitlab.com/runner/executors/kubernetes/#other-configtoml-settings).

### Dépréciation du champ `version` dans l'API de feature flag {#deprecate-version-field-in-feature-flag-api}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/437986).

Le champ `version` dans l'[API REST de feature flag](https://docs.gitlab.com/api/feature_flags/) est déprécié et sera supprimé dans GitLab 17.0.

Une fois le champ `version` supprimé, il ne sera plus possible de créer des feature flags hérités.

### Dépréciation de la modification du statut des vulnérabilités depuis le rôle Développeur {#deprecate-change-vulnerability-status-from-the-developer-role}

- Annoncé dans GitLab 16.4
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/424133).

La possibilité pour les Développeurs de modifier le statut des vulnérabilités est désormais dépréciée. Nous prévoyons d'apporter un changement majeur dans la prochaine version GitLab 17.0 pour supprimer cette possibilité du rôle Développeur. Les utilisateurs souhaitant continuer à accorder cette permission aux développeurs peuvent [créer un rôle personnalisé](https://docs.gitlab.com/user/permissions/#custom-roles) pour leurs développeurs et y ajouter la permission `admin_vulnerability` pour leur donner cet accès.

### Dépréciation de la création de rôles personnalisés pour les propriétaires de groupes sur GitLab Self-Managed {#deprecate-custom-role-creation-for-group-owners-on-gitlab-self-managed}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/439284).

Dans GitLab Self-Managed 17.0, la création de rôles personnalisés sera supprimée pour les propriétaires de groupes. Cette fonctionnalité sera déplacée au niveau de l'instance, réservée aux administrateurs uniquement. Les propriétaires de groupes pourront attribuer des rôles personnalisés au niveau du groupe.

Les propriétaires de groupes sur GitLab.com pourront continuer à gérer les rôles personnalisés et à les attribuer au niveau du groupe.

Si vous utilisez l'API pour gérer les rôles personnalisés sur GitLab Self-Managed, un nouvel endpoint d'instance a été ajouté et est requis pour continuer les opérations via l'API.

- Lister tous les rôles membres sur l'instance - `GET /api/v4/member_roles`
- Ajouter un rôle membre à l'instance - `POST /api/v4/member_roles`
- Supprimer un rôle membre de l'instance - `DELETE /api/v4/member_roles/:id`

### Dépréciation du champ `hasSolutions` du type GraphQL VulnerabilityType {#deprecate-field-hassolutions-from-graphql-vulnerabilitytype}

- Annoncé dans GitLab 16.3
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/414895).

Le champ GraphQL `Vulnerability.hasSolutions` est déprécié et sera supprimé dans GitLab 17.0. Utilisez plutôt `Vulnerability.hasRemediations`.

### Dépréciation des mécanismes hérités d'échappement et de citation de l'exécuteur shell du runner {#deprecate-legacy-shell-escaping-and-quoting-runner-shell-executor}

- Annoncé dans GitLab 15.11
- Suppression dans GitLab 17.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/406679).

Le mécanisme d'échappement hérité du runner pour gérer l'expansion des variables implémente une version sous-optimale de la citation Ansi-C. Cette méthode signifie que le runner développerait les arguments inclus entre guillemets doubles. À partir de la version 15.11, nous déprécions les méthodes d'échappement et de citation héritées dans l'exécuteur shell du runner.

### Paramètres dépréciés liés au texte personnalisé dans la page de connexion {#deprecated-parameters-related-to-custom-text-in-the-sign-in-page}

- Annoncé dans GitLab 16.2
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/124461).

Les paramètres `sign_in_text` et `help_text` sont dépréciés dans l'[API Settings](https://docs.gitlab.com/api/settings/). Pour ajouter un texte personnalisé aux pages de connexion et de création de nouveau compte utilisateur, utilisez le champ `description` dans l'[API Appearance](https://docs.gitlab.com/api/appearance/).

### Dépréciation de Windows Server 2019 au profit de 2022 {#deprecating-windows-server-2019-in-favor-of-2022}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/438554).

Nous avons récemment annoncé la sortie de Windows Server 2022 pour nos runners GitLab.com sur Windows (version bêta). Parallèlement, nous déprécions Windows 2019 dans GitLab 17.0.

Pour plus d'informations sur la migration vers Windows 2022, consultez [Prise en charge de Windows 2022 pour les runners GitLab.com désormais disponible](https://about.gitlab.com/blog/windows-2022-support-for-gitlab-saas-runners/).

### Fournisseur OmniAuth DingTalk {#dingtalk-omniauth-provider}

- Annoncé dans GitLab 15.10
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/390855).

Le gem `omniauth-dingtalk` qui fournit à GitLab le fournisseur OmniAuth DingTalk sera supprimé dans notre prochaine version majeure, GitLab 17.0. Ce gem est très peu utilisé et convient mieux à l'édition JiHu.

### Stockages en double dans la configuration Gitaly {#duplicate-storages-in-gitaly-configuration}

- Annoncé dans GitLab 16.10
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitaly/-/issues/5598).

La prise en charge de la configuration de plusieurs stockages Gitaly pointant vers le même chemin de stockage est dépréciée et sera supprimée dans GitLab 17.0\. Dans GitLab 17.0 et les versions ultérieures, ce type de configuration provoquera une erreur.

Nous supprimons la prise en charge de ce type de configuration, car elle peut causer des problèmes avec la maintenance des dépôts en arrière-plan et ne sera pas compatible avec les futures implémentations de stockage Gitaly.

Les administrateurs d'instance doivent mettre à jour les entrées `storage` de la section `gitaly['configuration']` dans le fichier de configuration `gitlab.rb` pour s'assurer que chaque stockage est configuré avec un chemin unique.

### Expansion des variables de type fichier corrigée dans les pipelines downstream {#file-type-variable-expansion-fixed-in-downstream-pipelines}

- Annoncé dans GitLab 16.6
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/419445).

Auparavant, si vous tentiez de référencer une [variable CI/CD de type fichier](https://docs.gitlab.com/ci/variables/#use-file-type-cicd-variables) dans une autre variable CI/CD, la variable CI/CD s'étendait pour contenir le contenu du fichier. Ce comportement était incorrect, car il ne respectait pas les règles habituelles d'expansion des variables shell. La référence à la variable CI/CD doit se développer pour ne contenir que le chemin vers le fichier, et non le contenu du fichier lui-même. Ce problème a été [corrigé pour la plupart des cas d'utilisation dans GitLab 15.7](https://gitlab.com/gitlab-org/gitlab/-/issues/29407). Malheureusement, la transmission de variables CI/CD aux pipelines downstream constituait un cas particulier qui n'avait pas encore été corrigé, mais qui le sera dans GitLab 17.0.

Avec cette modification, une variable configurée dans le fichier `.gitlab-ci.yml` peut référencer une variable de type fichier et être transmise à un pipeline downstream, et la variable de type fichier sera également transmise au pipeline downstream. Le pipeline downstream développera la référence de variable vers le chemin du fichier, et non vers le contenu du fichier.

Ce changement majeur pourrait perturber les workflows utilisateurs qui dépendent du développement d'une variable de type fichier dans un pipeline downstream.

### Geo : routes héritées de détails de réplication pour les designs et les projets dépréciées {#geo-legacy-replication-details-routes-for-designs-and-projects-deprecated}

- Annoncé dans GitLab 16.4
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/424002).

Dans le cadre de la migration des types de données hérités vers le [framework Geo en libre-service](https://docs.gitlab.com/development/geo/framework/), les routes de détails de réplication suivantes sont dépréciées :

- Designs `/admin/geo/replication/designs` remplacé par `/admin/geo/sites/<Geo Node/Site ID>/replication/design_management_repositories`
- Projets `/admin/geo/replication/projects` remplacé par `/admin/geo/sites/<Geo Node/Site ID>/replication/projects`

De GitLab 16.4 à 17.0, les recherches effectuées sur les routes héritées seront automatiquement redirigées vers les nouvelles routes. Nous supprimerons les redirections dans la version 17.0. Veuillez mettre à jour tous les favoris ou scripts susceptibles d'utiliser les routes héritées.

### Les valeurs du chart Helm GitLab `gitlab.kas.privateApi.tls.*` sont dépréciées {#gitlab-helm-chart-values-gitlabkasprivateapitls-are-deprecated}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/4097).

Nous avons introduit les valeurs Helm `global.kas.tls.*` pour faciliter la communication TLS entre KAS et les composants de votre chart Helm. Les anciennes valeurs `gitlab.kas.privateApi.tls.enabled` et `gitlab.kas.privateApi.tls.secretName` sont dépréciées et leur suppression est planifiée dans GitLab 17.0.

Étant donné que les nouvelles valeurs offrent une méthode rationalisée et complète pour activer TLS pour KAS, vous devriez utiliser `global.kas.tls.*` à la place de `gitlab.kas.privateApi.tls.*`. La valeur `gitlab.kas.privateApi.tls.*`. Pour plus d'informations, consultez :

- La [merge request](https://gitlab.com/gitlab-org/charts/gitlab/-/merge_requests/2888) qui introduit les valeurs `global.kas.tls.*`.
- La [documentation dépréciée de `gitlab.kas.privateApi.tls.*`](https://docs.gitlab.com/charts/charts/gitlab/kas/#enable-tls-communication-through-the-gitlabkasprivateapi-attributes-deprecated).
- La [nouvelle documentation de `global.kas.tls.*`](https://docs.gitlab.com/charts/charts/globals/#tls-settings-1).

### Déclaration SLSA v0.2 des métadonnées de provenance de GitLab Runner {#gitlab-runner-provenance-metadata-slsa-v02-statement}

- Annoncé dans GitLab 16.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/36869).

Les runners génèrent des métadonnées de provenance et génèrent actuellement par défaut des déclarations conformes à SLSA v0.2. Étant donné que SLSA v1.0 a été publié et est désormais pris en charge par GitLab, la déclaration v0.2 est désormais dépréciée et sa suppression est prévue dans GitLab 17.0. La déclaration SLSA v1.0 est prévue pour devenir le nouveau format de déclaration par défaut dans GitLab 17.0.

### Accès à l'API GraphQL via des méthodes non prises en charge {#graphql-api-access-through-unsupported-methods}

- Annoncé dans GitLab 17.0
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/442520).

À partir de GitLab 17.0, nous limitons l'accès à GraphQL aux seuls [types de jetons pris en charge déjà documentés](https://docs.gitlab.com/api/graphql/#token-authentication).

Pour les clients utilisant déjà des types de jetons documentés et pris en charge, il n'y a pas de changements majeurs.

### Ressource GraphQL `networkPolicies` dépréciée {#graphql-networkpolicies-resource-deprecated}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/421440).

La [ressource GraphQL](https://docs.gitlab.com/api/graphql/reference/#projectnetworkpolicies) `networkPolicies` a été dépréciée et sera supprimée dans GitLab 17.0. Depuis GitLab 15.0, ce champ ne retourne aucune donnée.

### Le champ GraphQL `confidential` a été renommé en `internal` dans les notes {#graphql-field-confidential-changed-to-internal-on-notes}

- Annoncé dans GitLab 15.5
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/371485).

Le champ `confidential` d'une `Note` sera déprécié et renommé en `internal`.

### Le champ GraphQL `registrySizeEstimated` a été déprécié {#graphql-field-registrysizeestimated-has-been-deprecated}

- Annoncé dans GitLab 16.2
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/416509).

Pour plus de clarté, le champ GraphQL `registrySizeEstimated` a été renommé en `containerRegistrySizeIsEstimated`, afin de correspondre à son homologue. `registrySizeEstimated` a été déprécié dans GitLab 16.2 et sera supprimé dans GitLab 17.0. Utilisez à la place `containerRegistrySizeIsEstimated`, introduit dans GitLab 16.2.

### Le champ GraphQL `totalWeight` est déprécié {#graphql-field-totalweight-is-deprecated}

- Annoncé dans GitLab 16.3
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/416219).

Vous pouvez utiliser GraphQL pour interroger le poids total des tickets dans un tableau des tickets. Cependant, le champ `totalWeight` est limité à la taille maximale de 2 147 483 647. Par conséquent, `totalWeight` est déprécié et sera supprimé dans GitLab 17.0.

Utilisez plutôt `totalIssueWeight`, introduit dans GitLab 16.2.

### Le type GraphQL `RunnerMembershipFilter` renommé en `CiRunnerMembershipFilter` {#graphql-type-runnermembershipfilter-renamed-to-cirunnermembershipfilter}

- Annoncé dans GitLab 16.0
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/409333).

Le type GraphQL `RunnerMembershipFilter` a été renommé en `CiRunnerMembershipFilter`. Dans GitLab 17.0, l'alias du type `RunnerMembershipFilter` sera supprimé.

### GraphQL : la valeur `DISABLED_WITH_OVERRIDE` de l'enum `SharedRunnersSetting` est dépréciée {#graphql-the-disabled_with_override-value-for-the-sharedrunnerssetting-enum-is-deprecated}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/385636).

Dans GitLab 17.0, la valeur `DISABLED_WITH_OVERRIDE` du type d'enum GraphQL `SharedRunnersSetting` sera supprimée. Utilisez plutôt `DISABLED_AND_OVERRIDABLE`.

### GraphQL : dépréciation de la prise en charge de `canDestroy` et `canDelete` {#graphql-deprecate-support-for-candestroy-and-candelete}

- Annoncé dans GitLab 16.6
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/390754).

L'interface utilisateur du registre de paquets repose sur l'API GraphQL de GitLab. Pour faciliter la contribution de tous, il est important que le frontend soit codé de manière cohérente dans toutes les zones du produit GitLab. Avant GitLab 16.6, cependant, l'interface du registre de paquets gérait les permissions différemment des autres zones du produit.

Dans la version 16.6, nous avons ajouté un nouveau champ `UserPermissions` sous le type `Types::PermissionTypes::Package` pour aligner le registre de paquets avec le reste de GitLab. Ce nouveau champ remplace le champ `canDestroy` sous les types `Package`, `PackageBase` et `PackageDetailsType`. Il remplace également le champ `canDelete` pour `ContainerRepository`, `ContainerRepositoryDetails` et `ContainerRepositoryTag`. Dans GitLab 17.0, les champs `canDestroy` et `canDelete` seront supprimés.

Il s'agit d'un changement majeur qui sera finalisé dans la version 17.0.

### L'intégration HashiCorp Vault n'utilisera plus le jeton de job CI/CD `CI_JOB_JWT` par défaut {#hashicorp-vault-integration-will-no-longer-use-the-ci_job_jwt-cicd-job-token-by-default}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/366798).

Dans le cadre de nos efforts pour améliorer la sécurité de vos workflows CI avec JWT et OIDC, l'intégration native de HashiCorp est également mise à jour dans GitLab 16.0. Tous les projets utilisant le mot-clé [`secrets:vault`](https://docs.gitlab.com/ci/yaml/#secretsvault) pour récupérer des secrets depuis Vault devront être [configurés pour utiliser les jetons d'identifiant](https://docs.gitlab.com/ci/secrets/id_token_authentication/#configure-automatic-id-token-authentication). Les jetons d'identifiant ont été introduits dans la version 15.7.

Pour préparer cette transition, utilisez le nouveau mot-clé [`id_tokens`](https://docs.gitlab.com/ci/yaml/#id_tokens) et configurez la déclaration `aud`. Assurez-vous que l'audience liée est préfixée par `https://`.

Dans GitLab 15.9 à 15.11, vous pouvez [activer le paramètre **Limiter l'accès JSON Web Token (JWT)**](https://docs.gitlab.com/ci/secrets/id_token_authentication/#enable-automatic-id-token-authentication), ce qui empêche les anciens jetons d'être exposés dans les jobs et active [l'authentification par jeton d'identifiant pour le mot-clé `secrets:vault`](https://docs.gitlab.com/ci/secrets/id_token_authentication/#configure-automatic-id-token-authentication).

Dans GitLab 16.0 et les versions ultérieures :

- Ce paramètre sera supprimé.
- Les jobs CI/CD utilisant le mot-clé `id_tokens` peuvent utiliser des jetons d'identifiant avec `secrets:vault` et n'auront plus aucun jeton `CI_JOB_JWT*` disponible.
- Les jobs n'utilisant pas le mot-clé `id_tokens` continueront à disposer des jetons `CI_JOB_JWT*` jusqu'à GitLab 17.0.

### Mise à niveau de l'image Heroku dans le build Auto DevOps {#heroku-image-upgrade-in-auto-devops-build}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/437937).

Dans GitLab 17.0, le projet `auto-build-image` passera de l'image `heroku/builder:20` à `heroku/builder:22`.

Pour tester le comportement de la nouvelle image, définissez la variable CI/CD `AUTO_DEVOPS_BUILD_IMAGE_CNB_BUILDER` sur `heroku/builder:22`.

Pour continuer à utiliser `heroku/builder:20` après GitLab 17.0, définissez `AUTO_DEVOPS_BUILD_IMAGE_CNB_BUILDER` sur `heroku/builder:20`.

### Endpoint interne de suppression de tags de l'API du registre de conteneurs {#internal-container-registry-api-tag-deletion-endpoint}

- Annoncé dans GitLab 16.4
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/container-registry/-/issues/1094).

La spécification Docker Registry HTTP API V2, remplacée ultérieurement par la [spécification OCI Distribution](https://github.com/opencontainers/distribution-spec/blob/main/spec.md), ne comprenait pas d'opération de suppression de tags, et une solution de contournement peu sûre et lente (impliquant la suppression de manifestes et non de tags) devait être utilisée pour parvenir au même résultat.

La suppression de tags étant une fonctionnalité importante, nous avons ajouté une opération de suppression de tags au registre de conteneurs GitLab, étendant ainsi l'API V2 au-delà de la portée de la spécification de distribution Docker et OCI.

Depuis lors, la spécification OCI Distribution a fait l'objet de mises à jour et dispose désormais d'une opération de suppression de tags, via l'[endpoint `DELETE /v2/<name>/manifests/<tag>`](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#deleting-tags).

Le registre de conteneurs dispose ainsi de deux endpoints offrant exactement la même fonctionnalité. `DELETE /v2/<name>/tags/reference/<tag>` est l'endpoint de suppression de tags personnalisé de GitLab et `DELETE /v2/<name>/manifests/<tag>` est l'endpoint de suppression de tags conforme à OCI introduit dans GitLab 16.4.

La prise en charge de l'endpoint de suppression de tags personnalisé de GitLab est dépréciée dans GitLab 16.4 et sera supprimée dans GitLab 17.0.

Cet endpoint est utilisé par l'API d'application **interne** du registre de conteneurs, et non par l'[API publique du registre de conteneurs GitLab](https://docs.gitlab.com/api/container_registry/). Aucune action ne devrait être requise de la part de la majorité des utilisateurs du registre de conteneurs. L'ensemble des fonctionnalités de l'interface utilisateur et de l'API GitLab relatives à la suppression de tags resteront intactes lors de notre transition vers le nouvel endpoint conforme à OCI.

Si vous accédez à l'API interne du registre de conteneurs et utilisez l'endpoint de suppression de tags d'origine, vous devez effectuer la mise à jour vers le nouvel endpoint.

### L'endpoint d'instance JWT `/-/jwks` est déprécié {#jwt--jwks-instance-endpoint-is-deprecated}

- Annoncé dans GitLab 16.7
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/221031).

Avec la [dépréciation des anciennes versions des jetons JSON Web](https://docs.gitlab.com/update/deprecations/?removal_milestone=17.0#old-versions-of-json-web-tokens-are-deprecated) dans GitLab 17.0, l'endpoint `/-/jwks` associé, qui est un alias de `/oauth/discovery/keys`, n'est plus nécessaire et sera supprimé. Si vous avez spécifié `jwks_url` dans votre configuration d'authentification, mettez à jour votre configuration en utilisant `oauth/discovery/keys` à la place et supprimez toutes les occurrences de `/-/jwks` dans vos endpoints. Si vous utilisez déjà `oauth_discovery_keys` dans votre configuration d'authentification et l'alias `/-/jwks` dans vos endpoints, supprimez `/-/jwks` de vos endpoints. Par exemple, remplacez `https://gitlab.example.com/-/jwks` par `https://gitlab.example.com`.

### Métriques Prometheus Geo héritées {#legacy-geo-prometheus-metrics}

- Annoncé dans GitLab 16.6
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/430192).

Suite à la migration des projets vers le [framework Geo en libre-service](https://docs.gitlab.com/development/geo/framework/), nous avons déprécié un certain nombre de métriques [Prometheus](https://docs.gitlab.com/administration/monitoring/prometheus/). Les métriques Prometheus suivantes relatives à Geo sont dépréciées et seront supprimées dans la version 17.0. Le tableau ci-dessous répertorie les métriques dépréciées et leurs remplacements respectifs. Les remplacements sont disponibles dans GitLab 16.3.0 et les versions ultérieures.

| Métrique dépréciée                        |  Métrique de remplacement                            |
| ---------------------------------------- | ---------------------------------------------- |
| `geo_repositories_synced`                | `geo_project_repositories_synced`              |
| `geo_repositories_failed`                | `geo_project_repositories_failed`              |
| `geo_repositories_checksummed`           | `geo_project_repositories_checksummed`         |
| `geo_repositories_checksum_failed`       | `geo_project_repositories_checksum_failed`     |
| `geo_repositories_verified`              | `geo_project_repositories_verified`            |
| `geo_repositories_verification_failed`   | `geo_project_repositories_verification_failed` |
| `geo_repositories_checksum_mismatch`     |  Aucune disponible                                |
| `geo_repositories_retrying_verification` |  Aucune disponible                                |

### La liste des licences est dépréciée {#license-list-is-deprecated}

- Annoncé dans GitLab 16.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/436100).

Actuellement dans GitLab, vous pouvez consulter la liste de toutes les licences de votre projet et des composants qui utilisent ces licences dans la liste des licences. À partir de la version 16.8, la liste des licences est dépréciée et sa suppression est planifiée dans la version 17.0 en tant que changement majeur. Vous pouvez désormais accéder à toutes les licences utilisées par votre projet ou groupe dans la liste des dépendances, y compris la possibilité de filtrer par licence.

### Prise en charge de sbt 1.0.X dans l'analyse des licences {#license-scanning-support-for-sbt-10x}

- Annoncé dans GitLab 16.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/437591).

GitLab 17.0 supprime la prise en charge de sbt 1.0.x par l'analyse des licences.

Les utilisateurs sont invités à mettre à niveau depuis sbt 1.0.x.

### Paquets Linux pour Ubuntu 18.04 {#linux-packages-for-ubuntu-1804}

- Annoncé dans GitLab 16.8
- Suppression dans GitLab 17.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8082).

Le support standard d'Ubuntu 18.04 [a pris fin en juin 2023](https://wiki.ubuntu.com/Releases).

À partir de GitLab 17.0, nous ne fournirons plus de paquets Linux pour Ubuntu 18.04.

Pour préparer la mise à niveau vers GitLab 17.0 et les versions ultérieures :

1. Migrez les serveurs exécutant des instances GitLab d'Ubuntu 18.04 vers Ubuntu 20.04 ou Ubuntu 22.04.
1. Mettez à niveau vos instances GitLab en utilisant le paquet Linux correspondant à la version d'Ubuntu que vous utilisez désormais.

### Tâche Rake de listage des répertoires de dépôts {#list-repository-directories-rake-task}

- Annoncé dans GitLab 16.7
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/384361).

La tâche Rake `gitlab-rake gitlab:list_repos` ne fonctionne pas et sera supprimée dans GitLab 17.0. Si vous migrez GitLab, utilisez plutôt [la sauvegarde et la restauration](https://docs.gitlab.com/administration/operations/moving_repositories/#recommended-approach-in-all-cases).

### Le rôle Maintainer permettant de modifier les paramètres des paquets via l'API GraphQL {#maintainer-role-providing-the-ability-to-change-package-settings-using-graphql-api}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/370471).

La possibilité pour les utilisateurs ayant le rôle Maintainer de modifier les paramètres de **Paquets et registres** pour un groupe via l'API GraphQL est dépréciée dans GitLab 15.8 et sera supprimée dans GitLab 17.0. Ces paramètres incluent :

- [Autoriser ou interdire les téléversements de paquets en double](https://docs.gitlab.com/user/packages/maven_repository/#do-not-allow-duplicate-maven-packages).
- [Transfert des requêtes de paquets](https://docs.gitlab.com/user/packages/maven_repository/#request-forwarding-to-maven-central).
- [Activation des règles de cycle de vie pour le proxy de dépendances](https://docs.gitlab.com/user/packages/dependency_proxy/reduce_dependency_proxy_storage/).

Dans GitLab 17.0 et les versions ultérieures, vous devez avoir le rôle Propriétaire pour un groupe afin de modifier les paramètres de **Paquets et registres** pour le groupe, que ce soit via l'interface utilisateur GitLab ou l'API GraphQL.

### Prise en charge des versions Maven inférieures à 3.8.8 dans l'analyse des dépendances et l'analyse des licences {#maven-versions-below-388-support-in-dependency-scanning-and-license-scanning}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/438772).

GitLab 17.0 abandonne la prise en charge de l'analyse des dépendances et de l'analyse des licences pour les versions de Maven inférieures à 3.8.8.

Les utilisateurs sont invités à mettre à niveau vers la version 3.8.8 ou une version supérieure.

### Concurrence minimale et maximale dans les options Sidekiq {#min-concurrency-and-max-concurrency-in-sidekiq-options}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/439687).

Pour les installations de paquets Linux (Omnibus), les paramètres [`sidekiq['min_concurrency']` et `sidekiq['max_concurrency']`](https://docs.gitlab.com/administration/sidekiq/extra_sidekiq_processes/#manage-thread-counts-explicitly) sont dépréciés dans GitLab 16.9 et seront supprimés dans GitLab 17.0.

Vous pouvez utiliser `sidekiq['concurrency']` dans GitLab 16.9 et les versions ultérieures pour définir explicitement le nombre de threads dans chaque processus.

La modification ci-dessus s'applique uniquement aux installations de paquets Linux (Omnibus).

Pour les installations du chart Helm GitLab, la transmission de `SIDEKIQ_CONCURRENCY_MIN` et/ou `SIDEKIQ_CONCURRENCY_MAX` en tant que `extraEnv` au sous-chart `sidekiq` est dépréciée dans GitLab 16.10 et sera supprimée dans GitLab 17.0.

Vous pouvez utiliser l'option `concurrency` pour définir explicitement le nombre de threads dans chaque processus.

### La pagination par décalage pour l'endpoint API REST `/users` est dépréciée {#offset-pagination-for-users-rest-api-endpoint-is-deprecated}

- Annoncé dans GitLab 16.5
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/426547).

La pagination par décalage pour l'API REST `/users` est dépréciée dans GitLab 16.5 et sera supprimée dans GitLab 17.0. Utilisez plutôt la [pagination par jeu de clés](https://docs.gitlab.com/api/rest/#keyset-based-pagination).

### Les anciennes versions des jetons JSON Web sont dépréciées {#old-versions-of-json-web-tokens-are-deprecated}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/366798).

Les [jetons d'identifiant](https://docs.gitlab.com/ci/secrets/id_token_authentication/) avec prise en charge OIDC ont été introduits dans GitLab 15.7. Ces jetons sont plus configurables que les anciens jetons JSON Web (JWT), sont conformes à OIDC et ne sont disponibles que dans les jobs CI/CD qui ont explicitement des jetons d'identifiant configurés. Les jetons d'identifiant sont plus sécurisés que les anciens jetons JSON Web `CI_JOB_JWT*` qui sont exposés dans chaque job. Par conséquent, ces anciens jetons JSON Web sont dépréciés :

- `CI_JOB_JWT`
- `CI_JOB_JWT_V1`
- `CI_JOB_JWT_V2`

Pour préparer cette modification, configurez vos pipelines pour utiliser les [jetons d'identifiant](https://docs.gitlab.com/ci/yaml/#id_tokens) à la place des jetons dépréciés. Pour la conformité OIDC, la déclaration `iss` utilise désormais le nom de domaine complet, par exemple `https://example.com`, introduit précédemment avec le jeton `CI_JOB_JWT_V2`.

Dans GitLab 15.9 à 15.11, vous pouvez [activer le paramètre **Limiter l'accès JSON Web Token (JWT)**](https://docs.gitlab.com/ci/secrets/id_token_authentication/#enable-automatic-id-token-authentication), ce qui empêche les anciens jetons d'être exposés dans les jobs et active [l'authentification par jeton d'identifiant pour le mot-clé `secrets:vault`](https://docs.gitlab.com/ci/secrets/id_token_authentication/#configure-automatic-id-token-authentication).

Dans GitLab 16.0 et les versions ultérieures :

- Ce paramètre sera supprimé.
- Les jobs CI/CD utilisant le mot-clé `id_tokens` peuvent utiliser des jetons d'identifiant avec `secrets:vault` et n'auront plus aucun jeton `CI_JOB_JWT*` disponible.
- Les jobs n'utilisant pas le mot-clé `id_tokens` continueront à disposer des jetons `CI_JOB_JWT*` jusqu'à GitLab 17.0.

Dans GitLab 17.0, les jetons dépréciés seront complètement supprimés et ne seront plus disponibles dans les jobs CI/CD.

### OmniAuth Facebook est déprécié {#omniauth-facebook-is-deprecated}

- Annoncé dans GitLab 16.2
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/416000).

La prise en charge d'OmniAuth Facebook sera supprimée dans GitLab 17.0. La dernière publication du gem date de 2021 et il n'est actuellement plus maintenu. L'utilisation actuelle est inférieure à 0,1 %. Si vous utilisez OmniAuth Facebook, passez à un [fournisseur pris en charge](https://docs.gitlab.com/integration/omniauth/#supported-providers) avant la suppression du support.

### Les pipelines de paquets dans la charge utile de l'API sont paginés {#package-pipelines-in-api-payload-is-paginated}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/289956).

Une requête à l'API pour `/api/v4/projects/:id/packages` renvoie un résultat paginé de paquets. Chaque paquet liste tous ses pipelines dans cette réponse. Cela pose un problème de performances, car un paquet peut avoir des centaines ou des milliers de pipelines associés.

Dans le jalon 17.0, nous supprimerons l'attribut `pipelines` de la réponse de l'API.

### PostgreSQL 13 n'est plus pris en charge {#postgresql-13-no-longer-supported}

- Annoncé dans GitLab 16.0
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/epics/9065).

GitLab suit un [calendrier de mise à niveau annuel pour PostgreSQL](https://handbook.gitlab.com/handbook/engineering/data-engineering/database-excellence/database-frameworks/postgresql-upgrade-cadence/).

La prise en charge de PostgreSQL 13 est prévue pour suppression dans GitLab 17.0. Dans GitLab 17.0, PostgreSQL 14 devient la version minimale requise de PostgreSQL.

PostgreSQL 13 sera pris en charge pour l'intégralité du cycle de release GitLab 16. PostgreSQL 14 sera également pris en charge pour les instances souhaitant effectuer la mise à niveau avant GitLab 17.0. Si vous exécutez une instance PostgreSQL unique installée via un paquet Linux Omnibus, une mise à niveau automatique pourrait être tentée avec la version 16.11. Assurez-vous de disposer de suffisamment d'espace disque pour accueillir la mise à niveau. Pour plus d'informations, consultez la [documentation de base de données Omnibus](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server).

### DAST basé sur proxy déprécié {#proxy-based-dast-deprecated}

- Annoncé dans GitLab 16.6
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/430966).

À partir de GitLab 17.0, le DAST basé sur proxy ne sera plus pris en charge. Veuillez migrer vers le DAST basé sur navigateur pour continuer à analyser vos projets à la recherche de résultats de sécurité via une analyse dynamique. **Breach and Attack Simulation**, une fonctionnalité en incubation construite sur le DAST basé sur proxy, est également incluse dans cette dépréciation et ne sera plus prise en charge après la version 17.0.

### Le sélecteur de file d'attente pour l'exécution de Sidekiq est déprécié {#queue-selector-for-running-sidekiq-is-deprecated}

- Annoncé dans GitLab 15.9
- Fin de support dans GitLab 16.0
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/390787).

L'exécution de Sidekiq avec un [sélecteur de file d'attente](https://docs.gitlab.com/administration/sidekiq/processing_specific_job_classes/#queue-selectors) (plusieurs processus écoutant un ensemble de files d'attente) et des [paramètres de négation](https://docs.gitlab.com/administration/sidekiq/processing_specific_job_classes/#negate-settings) est dépréciée et sera entièrement supprimée dans la version 17.0.

Vous pouvez migrer depuis les sélecteurs de file d'attente vers [l'écoute de toutes les files d'attente dans tous les processus](https://docs.gitlab.com/administration/sidekiq/extra_sidekiq_processes/#start-multiple-processes). Par exemple, si Sidekiq s'exécute actuellement avec 4 processus (indiqués par 4 éléments dans `sidekiq['queue_groups']` dans `/etc/gitlab/gitlab.rb`) avec le sélecteur de file d'attente (`sidekiq['queue_selector'] = true`), vous pouvez configurer Sidekiq pour écouter toutes les files d'attente dans les 4 processus, par exemple `sidekiq['queue_groups'] = ['*'] * 4`. Cette approche est également recommandée dans notre [Architecture de référence](https://docs.gitlab.com/administration/reference_architectures/5k_users/#configure-sidekiq). Notez que Sidekiq peut effectivement exécuter autant de processus que le nombre de CPU de la machine.

Bien que l'approche ci-dessus soit recommandée pour la plupart des instances, Sidekiq peut également être exécuté en utilisant des [règles de routage](https://docs.gitlab.com/administration/sidekiq/processing_specific_job_classes/#routing-rules), qui sont également utilisées sur GitLab.com. Vous pouvez suivre le [guide de migration des sélecteurs de file d'attente vers les règles de routage](https://docs.gitlab.com/administration/sidekiq/processing_specific_job_classes/#migrating-from-queue-selectors-to-routing-rules). Vous devez faire attention lors de la migration pour éviter de perdre des jobs entièrement.

### Suppression des tags des petits runners GitLab.com sur Linux {#removal-of-tags-from-small-gitlabcom-runners-on-linux}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/30829).

Pour des raisons historiques, les petits runners GitLab.com sur Linux avaient de nombreux tags associés car ils étaient utilisés comme labels. Nous souhaitons simplifier les tags pour n'utiliser que `saas-linux-small-amd64` et assurer la cohérence entre tous les runners GitLab.com.

Nous déprécions les tags suivants : `docker`, `east-c`, `gce`, `git-annex`, `linux`, `mongo`, `mysql`, `postgres`, `ruby`, `shared`.

Pour plus d'informations, voir [Suppression des tags de notre petit runner SaaS sur Linux](https://about.gitlab.com/blog/removing-tags-from-small-saas-runner-on-linux/).

### La configuration de pipeline obligatoire est dépréciée {#required-pipeline-configuration-is-deprecated}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/389467).

La configuration de pipeline obligatoire sera supprimée dans GitLab 17.0. Cette modification concerne les utilisateurs de GitLab Self-Managed avec l'édition Ultimate.

Vous devez remplacer la configuration de pipeline obligatoire par l'une des solutions suivantes :

- [Politiques de sécurité limitées aux frameworks de conformité](https://docs.gitlab.com/user/application_security/policies/scan_execution_policies/#security-policy-scopes), qui sont expérimentales.
- [Pipelines de conformité](https://docs.gitlab.com/user/group/compliance_pipelines/), qui sont disponibles dès maintenant.

Nous recommandons ces solutions alternatives car elles offrent une plus grande flexibilité, permettant d'assigner les pipelines obligatoires à des labels de framework de conformité spécifiques.

Les pipelines de conformité seront dépréciés à l'avenir et migrés vers les politiques de sécurité. Pour plus d'informations, consultez l'[epic de migration et de dépréciation](https://gitlab.com/groups/gitlab-org/-/epics/11275).

### Modification de la couverture de l'analyseur SAST dans GitLab 17.0 {#sast-analyzer-coverage-changing-in-gitlab-170}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/412060).

Nous réduisons le nombre d'[analyseurs](https://docs.gitlab.com/user/application_security/sast/analyzers/) pris en charge utilisés par défaut dans GitLab SAST. Cela s'inscrit dans notre stratégie à long terme visant à offrir une expérience utilisateur plus rapide et plus cohérente dans différents langages de programmation.

Dans GitLab 17.0, nous allons :

1. Supprimer un ensemble d'analyseurs spécifiques à certains langages du [modèle CI/CD SAST](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml) et remplacer leur couverture par des [règles de détection prises en charge par GitLab](https://docs.gitlab.com/user/application_security/sast/rules/) dans l'[analyseur basé sur Semgrep](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep). Les analyseurs suivants sont désormais dépréciés et atteindront la fin de support dans GitLab 17.0 :
   1. [Brakeman](https://gitlab.com/gitlab-org/security-products/analyzers/brakeman) (Ruby, Ruby on Rails)
   1. [Flawfinder](https://gitlab.com/gitlab-org/security-products/analyzers/flawfinder) (C, C++)
   1. [MobSF](https://gitlab.com/gitlab-org/security-products/analyzers/mobsf) (Android, iOS)
   1. [NodeJS Scan](https://gitlab.com/gitlab-org/security-products/analyzers/nodejs-scan) (Node.js)
   1. [PHPCS Security Audit](https://gitlab.com/gitlab-org/security-products/analyzers/phpcs-security-audit) (PHP)
1. Modifier le [modèle CI/CD SAST](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml) pour arrêter l'exécution de l'[analyseur basé sur SpotBugs](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs) pour le code Kotlin et Scala. Ces langages seront à la place analysés à l'aide des [règles de détection prises en charge par GitLab](https://docs.gitlab.com/user/application_security/sast/rules/) dans l'[analyseur basé sur Semgrep](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep).

Avec effet immédiat, les analyseurs dépréciés ne recevront que des mises à jour de sécurité ; les autres améliorations ou mises à jour de routine ne sont pas garanties. Une fois que les analyseurs auront atteint la fin de support dans GitLab 17.0, aucune mise à jour supplémentaire ne sera fournie. Cependant, nous ne supprimerons pas les images de conteneurs précédemment publiées pour ces analyseurs ni la possibilité de les exécuter à l'aide de définitions de jobs de pipeline CI/CD personnalisées.

Le système de gestion des vulnérabilités mettra à jour la plupart des résultats existants afin qu'ils correspondent aux nouvelles règles de détection. Les résultats qui ne sont pas migrés vers le nouvel analyseur seront [résolus automatiquement](https://docs.gitlab.com/user/application_security/sast/#automatic-vulnerability-resolution). Consultez la [documentation sur la traduction des vulnérabilités](https://docs.gitlab.com/user/application_security/sast/analyzers/#vulnerability-translation) pour plus de détails.

Si vous avez appliqué des personnalisations aux analyseurs supprimés, ou si vous désactivez actuellement l'analyseur basé sur Semgrep dans vos pipelines, vous devez effectuer les actions détaillées dans le [ticket de dépréciation pour ce changement](https://gitlab.com/gitlab-org/gitlab/-/issues/412060#action-required).

### Les politiques d'exécution de scan utilisant la variable `_EXCLUDED_ANALYZERS` remplacent les variables du projet {#scan-execution-policies-using-_excluded_analyzers-variable-override-project-variables}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/424513).

Après la livraison et la vérification de [l'application des variables SEP avec la priorité la plus élevée](https://gitlab.com/gitlab-org/gitlab/-/issues/424028), nous avons découvert un comportement non intentionnel, permettant aux utilisateurs de définir `_EXCLUDED_PATHS` dans la configuration du pipeline et les empêchant de définir `_EXCLUDED_ANALYZERS` à la fois dans la configuration de la politique et du pipeline.

Pour assurer une application correcte des variables d'exécution de scan, lorsque des variables `_EXCLUDED_ANALYZERS` ou `_EXCLUDED_PATHS` sont spécifiées pour une politique d'exécution de scan utilisant l'action de scan GitLab, la variable remplacera désormais toutes les variables du projet définies pour les analyseurs exclus.

Les utilisateurs peuvent activer le feature flag pour appliquer ce comportement avant la version 17.0. Dans la version 17.0, les projets utilisant la variable `_EXCLUDED_ANALYZERS`/`_EXCLUDED_PATHS` pour lesquels une politique d'exécution de scan avec cette variable est définie seront remplacés par défaut.

### Mise à jour de la version majeure des analyseurs Secure {#secure-analyzers-major-version-update}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/438123).

L'étape Secure va incrémenter les versions majeures de ses analyseurs en même temps que la release de GitLab 17.0.

Si vous n'utilisez pas les modèles inclus par défaut ou si vous avez épinglé les versions de vos analyseurs, vous devez mettre à jour votre définition de job CI/CD pour soit supprimer la version épinglée, soit mettre à jour la dernière version majeure.

Les utilisateurs de GitLab 16.0 à 16.11 continueront de recevoir les mises à jour des analyseurs normalement jusqu'à la release de GitLab 17.0, après quoi tous les bugs corrigés et fonctionnalités publiés seront disponibles uniquement dans la nouvelle version majeure des analyseurs.

Nous n'effectuons pas de backport des bugs et fonctionnalités vers les versions dépréciées, conformément à notre politique de maintenance. Si nécessaire, les correctifs de sécurité feront l'objet d'un backport dans les 3 dernières versions mineures.

Plus précisément, les analyseurs suivants sont dépréciés et ne seront plus mis à jour après la release de GitLab 17.0 :

- Analyse de conteneurs : version 6
- Analyse des dépendances : version 4
- DAST : version 4
- DAST API : version 3
- Fuzz API : version 3
- Analyse IaC : version 4
- Détection des secrets : version 5
- Test statique de sécurité des applications (SAST) : version 4 de [tous les analyseurs](https://docs.gitlab.com/user/application_security/sast/analyzers/)
  - `brakeman`
  - `flawfinder`
  - `kubesec`
  - `mobsf`
  - `nodejs-scan`
  - `phpcs-security-audit`
  - `pmd-apex`
  - `semgrep`
  - `sobelow`
  - `spotbugs`

### Le champ de politique de sécurité `match_on_inclusion` est déprécié {#security-policy-field-match_on_inclusion-is-deprecated}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/424513).

Dans [Support de filtres supplémentaires pour les politiques de résultat de scan](https://gitlab.com/groups/gitlab-org/-/epics/6826#note_1341377224), nous avons divisé le champ `newly_detected` en deux options : `new_needs_triage` et `new_dismissed`. En incluant les deux options dans le YAML de politique de sécurité, vous obtiendrez le même résultat que le champ `newly_detected` d'origine. Cependant, vous pouvez maintenant affiner votre filtre pour ignorer les résultats qui ont été rejetés en utilisant uniquement `new_needs_triage`. Sur la base de la discussion dans l'[epic 10203](https://gitlab.com/groups/gitlab-org/-/epics/10203#note_1545826313), nous avons changé le nom du champ `match_on_inclusion` en `match_on_inclusion_license` pour plus de clarté dans la définition YAML.

### Le champ de politique de sécurité `newly_detected` est déprécié {#security-policy-field-newly_detected-is-deprecated}

- Annoncé dans GitLab 16.5
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/422414).

Dans [Support de filtres supplémentaires pour les politiques de résultat de scan](https://gitlab.com/groups/gitlab-org/-/epics/6826#note_1341377224), nous avons divisé le champ `newly_detected` en deux options : `new_needs_triage` et `new_dismissed`. En incluant les deux options dans le YAML de politique de sécurité, vous obtiendrez le même résultat que le champ `newly_detected` d'origine. Cependant, vous pouvez maintenant affiner votre filtre pour ignorer les résultats qui ont été rejetés en utilisant uniquement `new_needs_triage`.

### Prise en charge des versions Sentry auto-hébergées 21.4.1 et antérieures {#support-for-self-hosted-sentry-versions-2141-and-earlier}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/435791).

La prise en charge des versions Sentry auto-hébergées 21.4.1 et antérieures est dépréciée et sera supprimée dans GitLab 17.0.

Si votre version Sentry auto-hébergée est 21.4.1 ou antérieure, il se peut que vous ne puissiez plus collecter les erreurs de votre instance GitLab après la mise à niveau vers GitLab 17.0 ou une version ultérieure. Pour continuer à envoyer les erreurs de votre instance GitLab vers votre instance Sentry, mettez à niveau Sentry vers la version 21.5.0 ou une version ultérieure. Pour plus d'informations, consultez la [documentation Sentry](https://develop.sentry.dev/self-hosted/releases/).

> [!note]
> La prise en charge dépréciée concerne les [fonctionnalités de suivi des erreurs de l'instance GitLab](https://docs.gitlab.com/omnibus/settings/configuration/#error-reporting-and-logging-with-sentry) pour les administrateurs. La prise en charge dépréciée ne concerne pas le [suivi des erreurs GitLab](https://docs.gitlab.com/operations/error_tracking/#sentry-error-tracking) pour les propres applications déployées par les développeurs.

### La prise en charge de la définition d'un schéma personnalisé pour la sauvegarde est dépréciée {#support-for-setting-custom-schema-for-backup-is-deprecated}

- Annoncé dans GitLab 16.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/435210).

Vous pouviez configurer GitLab pour utiliser un schéma personnalisé pour la sauvegarde, en définissant `gitlab_rails['backup_pg_schema'] = '<schema_name>'` dans `/etc/gitlab/gitlab.rb` pour les installations de paquets Linux, ou en modifiant `config/gitlab.yml` pour les installations auto-compilées.

Bien que le paramètre de configuration était disponible, il n'avait aucun effet et ne servait pas l'objectif pour lequel il avait été prévu. Ce paramètre de configuration sera supprimé dans GitLab 17.0.

### La tâche Rake de l'importateur GitHub {#the-github-importer-rake-task}

- Annoncé dans GitLab 16.6
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/428225).

Dans GitLab 16.6, la tâche Rake de l'importateur GitHub a été dépréciée. La tâche Rake manque de plusieurs fonctionnalités prises en charge par l'API et n'est pas activement maintenue.

Dans GitLab 17.0, la tâche Rake sera supprimée.

À la place, les dépôts GitHub peuvent être importés en utilisant l'[API](https://docs.gitlab.com/api/import/#import-repository-from-github) ou l'[interface utilisateur](https://docs.gitlab.com/user/project/import/github/).

### L'outil Visual Reviews est déprécié {#the-visual-reviews-tool-is-deprecated}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/387751).

En raison d'une utilisation client limitée et de capacités réduites, la fonctionnalité Visual Reviews pour les environnements éphémères est dépréciée et sera supprimée. Aucun remplacement n'est prévu et les utilisateurs doivent cesser d'utiliser Visual Reviews avant GitLab 17.0.

### La commande `gitlab-runner exec` est dépréciée {#the-gitlab-runner-exec-command-is-deprecated}

- Annoncé dans GitLab 15.7
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/385235).

La commande `gitlab-runner exec` est dépréciée et sera entièrement supprimée de GitLab Runner dans la version 16.0. La fonctionnalité `gitlab-runner exec` a été initialement développée pour permettre de valider un pipeline GitLab CI en local sans avoir à soumettre les mises à jour vers une instance GitLab. Cependant, avec l'évolution continue de GitLab CI, la réplication de toutes les fonctionnalités GitLab CI dans `gitlab-runner exec` n'était plus viable. La syntaxe du pipeline et la [simulation](https://docs.gitlab.com/ci/pipeline_editor/#simulate-a-cicd-pipeline) de validation sont disponibles dans l'éditeur de pipeline GitLab.

### Les fonctionnalités de déploiement par extraction de l'agent GitLab pour Kubernetes sont dépréciées {#the-pull-based-deployment-features-of-the-gitlab-agent-for-kubernetes-is-deprecated}

- Annoncé dans GitLab 16.2
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/406545).

Nous déprécions les fonctionnalités de déploiement par extraction intégrées à l'agent GitLab pour Kubernetes en faveur de Flux et des intégrations associées.

L'agent GitLab pour Kubernetes **n'est pas déprécié**. Cette modification concerne uniquement la fonctionnalité d'extraction de l'agent. Toutes les autres fonctionnalités resteront intactes et GitLab continuera à prendre en charge l'agent pour Kubernetes.

Si vous utilisez l'agent pour les déploiements par extraction, vous devez [migrer vers Flux](https://docs.gitlab.com/user/clusters/agent/gitops/agent/#migrate-to-flux). Étant donné que Flux est un projet CNCF mature pour GitOps, nous avons décidé d'[intégrer Flux à GitLab en février 2023](https://about.gitlab.com/blog/why-did-we-choose-to-integrate-fluxcd-with-gitlab/).

### L'option de connexion Twitter OmniAuth est dépréciée pour GitLab Self-Managed {#twitter-omniauth-login-option-is-deprecated-from-gitlab-self-managed}

- Annoncé dans GitLab 16.3
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-com/Product/-/issues/11417).

Twitter OAuth 1.0a OmniAuth est déprécié et sera supprimé pour GitLab Self-Managed dans GitLab 17.0 en raison d'une faible utilisation et d'un manque de prise en charge du gem. Utilisez [un autre fournisseur OmniAuth pris en charge](https://docs.gitlab.com/integration/omniauth/#supported-providers) à la place.

### Les règles d'approbation unifiées sont dépréciées {#unified-approval-rules-are-deprecated}

- Annoncé dans GitLab 16.1
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/epics/9662).

Les règles d'approbation unifiées sont dépréciées au profit des règles d'approbation multiples, qui offrent plus de flexibilité. Il se peut que vous ne puissiez pas migrer vos règles d'approbation unifiées vers des règles d'approbation multiples sans changements majeurs. Pour vous aider à migrer manuellement, nous avons introduit une documentation de migration.

Si vous ne migrez pas manuellement avant la suppression des règles d'approbation unifiées, GitLab migrera automatiquement vos paramètres. Étant donné que les règles d'approbation multiples permettent une configuration plus granulaire des règles d'approbation, si vous laissez GitLab effectuer la migration, les migrations automatiques pourraient aboutir à des règles plus restrictives que vous ne le souhaitez. Vérifiez vos règles de migration si vous rencontrez un problème nécessitant plus d'approbations que prévu.

Dans GitLab 15.11, la prise en charge de l'interface utilisateur pour les règles d'approbation unifiées a été supprimée. Vous pouvez toujours accéder aux règles d'approbation unifiées via l'API.

### Mise à niveau de la version du système d'exploitation des runners GitLab.com sur Linux {#upgrading-the-operating-system-version-of-gitlabcom-runners-on-linux}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/ci-cd/shared-runners/infrastructure/-/issues/60).

GitLab met à niveau le système d'exploitation optimisé pour les conteneurs (COS) des machines virtuelles éphémères utilisées pour exécuter des jobs pour les runners GitLab.com sur Linux. Cette mise à niveau du COS comprend une mise à niveau du moteur Docker de la version 19.03.15 vers la version 23.0.5, ce qui introduit un problème de compatibilité connu.

Docker-in-Docker antérieur à la version 20.10 ou les images Kaniko plus anciennes que v1.9.0 ne pourront pas détecter l'environnement d'exécution de conteneur et échoueront.

Pour plus d'informations, voir [Mise à niveau de la version du système d'exploitation de nos runners SaaS sur Linux](https://about.gitlab.com/blog/updating-the-os-version-of-saas-runners-on-linux/).

### Champ de confiance des vulnérabilités {#vulnerability-confidence-field}

- Annoncé dans GitLab 15.4
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/372332).

Dans GitLab 15.3, [les schémas de rapports de sécurité antérieurs à la version 15 ont été dépréciés](https://docs.gitlab.com/update/deprecations/#security-report-schemas-version-14xx). L'attribut `confidence` sur les résultats de vulnérabilités n'existe que dans les versions de schéma antérieures à `15-0-0`, et est donc effectivement déprécié car GitLab 15.4 prend en charge la version de schéma `15-0-0`. Pour maintenir la cohérence entre les rapports et nos API publiques, l'attribut `confidence` sur tout composant lié aux vulnérabilités de notre API GraphQL est désormais déprécié et sera supprimé dans la version 17.0.

### Le mot-clé `after_script` s'exécutera pour les jobs annulés {#after_script-keyword-will-run-for-canceled-jobs}

- Annoncé dans GitLab 16.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/437789).

Le mot-clé CI/CD [`after_script`](https://docs.gitlab.com/ci/yaml/#after_script) est utilisé pour exécuter des commandes supplémentaires après la section principale `script` d'un job. Il est souvent utilisé pour nettoyer les environnements ou d'autres ressources utilisées par le job. Pour de nombreux utilisateurs, le fait que les commandes `after_script` ne s'exécutent pas si un job est annulé était inattendu et indésirable. Dans la version 17.0, le mot-clé sera mis à jour pour exécuter également des commandes après l'annulation d'un job. Assurez-vous que votre configuration CI/CD qui utilise le mot-clé `after_script` est capable de gérer l'exécution pour des jobs annulés également.

### `dependency_files` est déprécié {#dependency_files-is-deprecated}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/396376).

Actuellement dans GitLab, la liste des dépendances d'un projet est générée à partir du contenu de `dependency_files` dans le rapport d'analyse des dépendances. Cependant, pour maintenir la cohérence avec la liste des dépendances du groupe, à partir de GitLab 17.0, la liste des dépendances du projet utilisera les artefacts de rapport SBOM CycloneDX, stockés dans la base de données PostgreSQL. En conséquence, la propriété `dependency_files` du schéma de rapport d'analyse des dépendances est dépréciée et sera supprimée dans la version 17.0.

Dans le cadre de cette dépréciation, le [`dependency_path`](https://docs.gitlab.com/user/application_security/dependency_list/#dependency-paths) sera également déprécié et supprimé dans la version 17.0. GitLab avancera avec l'implémentation du [graphe de dépendances utilisant la spécification CycloneDX](https://gitlab.com/gitlab-org/gitlab/-/issues/441118) pour fournir des informations similaires.

De plus, le job CI d'analyse de conteneurs [ne produira plus de rapport d'analyse des dépendances](https://gitlab.com/gitlab-org/gitlab/-/issues/439782) pour fournir la liste des composants du système d'exploitation, car celui-ci est remplacé par le rapport SBOM CycloneDX. La variable d'environnement `CS_DISABLE_DEPENDENCY_LIST` pour l'analyse de conteneurs n'est plus utilisée et sera également supprimée dans la version 17.0.

### Filtre `metric` et champ `value` pour l'API DORA {#metric-filter-and-value-field-for-dora-api}

- Annoncé dans GitLab 16.8
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/393172).

Plusieurs métriques DORA peuvent désormais être interrogées simultanément à l'aide d'un nouveau champ de métriques. Le filtre `metric` et le champ `value` pour l'API GraphQL DORA seront supprimés dans GitLab 17.0.

### Le gem `omniauth-azure-oauth2` est déprécié {#omniauth-azure-oauth2-gem-is-deprecated}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/408989).

Les utilisateurs GitLab peuvent utiliser le gem `omniauth-azure-oauth2` pour s'authentifier auprès de GitLab. Dans la version 17.0, ce gem sera remplacé par le gem `omniauth_openid_connect`. Le nouveau gem contient toutes les mêmes fonctionnalités que l'ancien gem, mais bénéficie également d'une maintenance en amont et est plus adapté à la sécurité et à la maintenance centralisée.

Cette modification nécessite que les utilisateurs se reconnectent au fournisseur OAuth 2.0 au moment de la migration. Pour éviter toute interruption, [ajoutez `omniauth_openid_connect` en tant que nouveau fournisseur](https://docs.gitlab.com/administration/auth/oidc/#configure-multiple-openid-connect-providers) à tout moment avant la version 17.0. Les utilisateurs verront un nouveau bouton de connexion et devront reconnecter manuellement leurs identifiants. Si vous n'implémentez pas le gem `omniauth_openid_connect` avant la version 17.0, les utilisateurs ne pourront plus se connecter via le bouton de connexion Azure et devront se connecter avec leur nom d'utilisateur et leur mot de passe, jusqu'à ce que le gem correct soit implémenté par l'administrateur.

### L'élément de configuration `omnibus_gitconfig` est déprécié {#omnibus_gitconfig-configuration-item-is-deprecated}

- Annoncé dans GitLab 16.10
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitaly/-/issues/5132).

L'élément de configuration `omnibus_gitconfig['system']` a été déprécié. Si vous utilisez `omnibus_gitconfig['system']` pour définir une configuration Git personnalisée pour Gitaly, vous devez configurer Git directement via la configuration Gitaly sous `gitaly[:configuration][:git][:config]` avant de mettre à niveau vers GitLab 17.0.

Par exemple :

```ruby
  gitaly[:configuration][:git][:config] = [
    {
      key: 'fetch.fsckObjects',
      value: 'true',
    },
    # ...
  ]
```

Le format des clés de configuration doit correspondre à ce qui est transmis à `git` via l'indicateur CLI `git -c <configuration>`.

Si vous avez des difficultés à convertir les clés existantes au format attendu, consultez les clés existantes dans le bon format dans le fichier de configuration généré par le paquet Linux de Gitaly. Par défaut, le fichier de configuration se trouve à l'emplacement `/var/opt/gitlab/gitaly/config.toml`.

Les options de configuration suivantes gérées par Gitaly doivent être supprimées. Ces clés n'ont pas besoin d'être migrées vers Gitaly :

- `pack.threads=1`
- `receive.advertisePushOptions=true`
- `receive.fsckObjects=true`
- `repack.writeBitmaps=true`
- `transfer.hideRefs=^refs/tmp/`
- `transfer.hideRefs=^refs/keep-around/`
- `transfer.hideRefs=^refs/remotes/`
- `core.alternateRefsCommand="exit 0 #"`
- `core.fsyncObjectFiles=true`
- `fetch.writeCommitGraph=true`

### Paramètre de configuration `postgres_exporter['per_table_stats']` {#postgres_exporterper_table_stats-configuration-setting}

- Annoncé dans GitLab 16.4
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8164).

Le paquet Linux fournit des requêtes personnalisées pour l'exportateur PostgreSQL inclus, notamment une requête `per_table_stats` contrôlée par le paramètre de configuration `postgres_exporter['per_table_stats']`.

L'exportateur PostgreSQL fournit désormais un collecteur `stat_user_tables` qui offre les mêmes métriques. Si vous aviez `postgres_exporter['per_table_stats']` activé, activez `postgres_exporter['flags']['collector.stat_user_tables']` à la place.

### Champ GraphQL `projectFingerprint` {#projectfingerprint-graphql-field}

- Annoncé dans GitLab 15.1
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/343475).

L'attribut [`project_fingerprint`](https://gitlab.com/groups/gitlab-org/-/epics/2791) des résultats de vulnérabilités est déprécié au profit d'un attribut `uuid`. En utilisant des valeurs UUIDv5 pour identifier les résultats, nous pouvons facilement associer toute entité liée à un résultat. L'attribut `project_fingerprint` n'est plus utilisé pour suivre les résultats et sera supprimé dans GitLab 17.0. À partir de la version 16.1, la sortie de `project_fingerprint` retourne la même valeur que le champ `uuid`.

### Type d'événement d'audit `repository_download_operation` pour les projets publics {#repository_download_operation-audit-event-type-for-public-projects}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/383218).

Le type d'événement d'audit `repository_download_operation` est actuellement enregistré dans la base de données pour tous les téléchargements de projets, qu'il s'agisse de projets publics ou privés. Pour les projets publics, cet événement d'audit n'est pas le plus utile à des fins d'audit car il peut être déclenché par des utilisateurs non authentifiés.

À partir de GitLab 17.0, le type d'événement d'audit `repository_download_operation` sera déclenché uniquement pour les projets privés ou internes. Nous ajouterons un nouveau type d'événement d'audit appelé `public_repository_download_operation` pour les téléchargements de projets publics. Ce nouveau type d'événement d'audit sera uniquement transmis en streaming.

### Les chargements de paquets npm s'effectuent désormais de manière asynchrone {#npm-package-uploads-now-occur-asynchronously}

- Annoncé dans GitLab 16.9
- Suppression dans GitLab 17.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/433009).

Le registre de paquets GitLab prend en charge npm et Yarn. Lorsque vous chargez un paquet npm ou Yarn, le chargement est synchrone. Cependant, il existe des problèmes connus avec les chargements synchrones. Par exemple, GitLab ne prend pas en charge des fonctionnalités telles que les [remplacements](https://gitlab.com/gitlab-org/gitlab/-/issues/432876).

À partir de la version 17.0, les paquets npm et Yarn seront chargés de manière asynchrone. Il s'agit d'un changement majeur car vous pourriez avoir des pipelines qui s'attendent à ce que le paquet soit disponible dès qu'il est publié.

Pour contourner ce problème, vous devez utiliser l'[API des paquets](https://docs.gitlab.com/api/packages/) pour vérifier la présence des paquets.

## GitLab 16.9 {#gitlab-169}

### Dépréciation du feature flag `lfs_check` {#deprecation-of-lfs_check-feature-flag}

- Annoncé dans GitLab 16.6
- Suppression dans GitLab 16.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/233550).

Dans GitLab 16.9, nous supprimerons le feature flag `lfs_check`. Ce feature flag a été [introduit il y a 4 ans](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/60588) et contrôle si la vérification d'intégrité LFS est activée. Le feature flag est activé par défaut, mais certains clients ont rencontré des problèmes de performances avec la vérification d'intégrité LFS et l'ont explicitement désactivé.

Après avoir [considérablement amélioré les performances](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/61355) de la vérification d'intégrité LFS, nous sommes prêts à supprimer le feature flag. Une fois le flag supprimé, la fonctionnalité sera automatiquement activée pour tout environnement dans lequel elle est actuellement désactivée.

Si ce feature flag est désactivé dans votre environnement et que vous êtes préoccupé par des problèmes de performances, veuillez l'activer et surveiller les performances avant sa suppression dans la version 16.9. Si vous constatez des problèmes de performances après son activation, veuillez nous en informer dans [ce ticket de retour d'information](https://gitlab.com/gitlab-org/gitlab/-/issues/233550).

## GitLab 16.8 {#gitlab-168}

### Paquets openSUSE Leap 15.4 {#opensuse-leap-154-packages}

- Annoncé dans GitLab 16.5
- Suppression dans GitLab 16.8
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8212).

Le support et les mises à jour de sécurité pour openSUSE Leap 15.4 [prennent fin en novembre 2023](https://en.opensuse.org/Lifetime#openSUSE_Leap).

GitLab 15.4 a fourni des paquets pour openSUSE Leap 15.5. GitLab 15.8 et les versions ultérieures ne fourniront pas de paquets pour openSUSE Leap 15.4.

Pour préparer GitLab 15.8 et les versions ultérieures, vous devez :

1. Migrer les instances d'openSUSE Leap 15.4 vers openSUSE Leap 15.5.
1. Passer des paquets GitLab fournis pour openSUSE Leap 15.4 aux paquets GitLab fournis pour openSUSE Leap 15.5.

## GitLab 16.7 {#gitlab-167}

### Intégration Shimo {#shimo-integration}

- Annoncé dans GitLab 15.7
- Suppression dans GitLab 16.7 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/377824).

L'**intégration Shimo Workspace** a été dépréciée et sera déplacée vers le codebase JiHu GitLab.

### Champ API `user_email_lookup_limit` {#user_email_lookup_limit-api-field}

- Annoncé dans GitLab 14.9
- Suppression dans GitLab 16.7 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Le [champ API](https://docs.gitlab.com/api/settings/) `user_email_lookup_limit` est déprécié dans GitLab 14.9 et supprimé dans GitLab 16.7. Jusqu'à la suppression de la fonctionnalité, `user_email_lookup_limit` est un alias de `search_rate_limit` et les workflows existants continuent de fonctionner.

Tout appel API visant à modifier les limites de débit pour `user_email_lookup_limit` doit utiliser `search_rate_limit` à la place.

## GitLab 16.6 {#gitlab-166}

### La liste d'autorisation des jetons de job couvre les projets publics et internes {#job-token-allowlist-covers-public-and-internal-projects}

- Annoncé dans GitLab 16.3
- Suppression dans GitLab 16.6 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/420678).

À partir de la version 16.6, les projets **publics** ou **internes** n'autoriseront plus les requêtes de jeton de job provenant de projets qui ne figurent pas dans la liste d'autorisation du projet lorsque [**Limiter l'accès à ce projet**](https://docs.gitlab.com/ci/jobs/ci_job_token/#add-a-group-or-project-to-the-job-token-allowlist) est activé.

Si vous avez des projets [publics ou internes](https://docs.gitlab.com/user/public_access/#change-project-visibility) avec le paramètre **Limiter l'accès à ce projet** activé, vous devez ajouter tous les projets qui effectuent des requêtes de jeton de job à la liste d'autorisation de votre projet pour maintenir l'autorisation.

## GitLab 16.5 {#gitlab-165}

### L'ajout de membres non synchronisés LDAP à un groupe LDAP verrouillé est déprécié {#adding-non-ldap-synced-members-to-a-locked-ldap-group-is-deprecated}

- Annoncé dans GitLab 16.0
- Suppression dans GitLab 16.5
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/213311).

L'activation du feature flag `ldap_settings_unlock_groups_by_owners` permettait d'ajouter des utilisateurs non synchronisés LDAP à un groupe LDAP verrouillé. Cette [fonctionnalité](https://gitlab.com/gitlab-org/gitlab/-/issues/1793) a toujours été désactivée par défaut et placée derrière un feature flag. Nous supprimons cette fonctionnalité pour maintenir la cohérence avec notre intégration SAML et parce qu'autoriser des membres de groupe non synchronisés contredit le principe de « source unique de vérité » inhérent à l'utilisation d'un service d'annuaire. Une fois cette fonctionnalité supprimée, tous les membres du groupe LDAP qui ne sont pas synchronisés avec LDAP perdront l'accès à ce groupe.

### Geo : tâches Rake de maintenance {#geo-housekeeping-rake-tasks}

- Annoncé dans GitLab 16.3
- Suppression dans GitLab 16.5 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/416384).

Dans le cadre de la migration de la réplication et de la vérification vers le [framework de service autonome Geo (SSF)](https://docs.gitlab.com/development/geo/framework/), la réplication héritée pour les dépôts de projets a été [supprimée](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/130565). En conséquence, les tâches Rake suivantes qui dépendaient du code hérité ont également été supprimées. Les opérations invoquées par ces tâches Rake sont désormais déclenchées automatiquement, soit périodiquement, soit en fonction d'événements déclencheurs.

| Tâche Rake | Remplacement |
| --------- | ----------- |
| `geo:git:housekeeping:full_repack` | [Déplacé vers l'interface utilisateur](https://docs.gitlab.com/administration/housekeeping/#heuristical-housekeeping). Aucune tâche Rake équivalente dans le SSF. |
| `geo:git:housekeeping:gc` | Toujours exécuté pour les nouveaux dépôts, puis lorsque nécessaire. Aucune tâche Rake équivalente dans le SSF. |
| `geo:git:housekeeping:incremental_repack` | Exécuté lorsque nécessaire. Aucune tâche Rake équivalente dans le SSF. |
| `geo:run_orphaned_project_registry_cleaner` | Exécuté régulièrement par un [worker de cohérence du registre](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/app/workers/geo/secondary/registry_consistency_worker.rb) qui supprime les registres orphelins. Aucune tâche Rake équivalente dans le SSF. |
| `geo:verification:repository:reset` | Déplacé vers l'interface utilisateur. Aucune tâche Rake équivalente dans le SSF. |
| `geo:verification:wiki:reset` | Déplacé vers l'interface utilisateur. Aucune tâche Rake équivalente dans le SSF. |

## GitLab 16.3 {#gitlab-163}

### Grafana intégré déprécié et désactivé {#bundled-grafana-deprecated-and-disabled}

- Annoncé dans GitLab 16.0
- Suppression dans GitLab 16.3 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7772).

La version de Grafana intégrée à Omnibus GitLab est [dépréciée et désactivée](https://docs.gitlab.com/administration/monitoring/performance/grafana_configuration/#deprecation-of-bundled-grafana) dans la version 16.0 et sera supprimée dans la version 16.3. Si vous utilisez Grafana intégré, vous devez migrer vers l'une des options suivantes :

- Une autre implémentation de Grafana. Pour plus d'informations, consultez [Passer à une nouvelle instance Grafana](https://docs.gitlab.com/administration/monitoring/performance/grafana_configuration/#switch-to-new-grafana-instance).
- Une autre plateforme d'observabilité de votre choix.

La version de Grafana actuellement fournie n'est plus une version prise en charge.

Dans les versions GitLab 16.0 à 16.2, vous pouvez encore [réactiver Grafana intégré](https://docs.gitlab.com/administration/monitoring/performance/grafana_configuration/#temporary-workaround). Cependant, l'activation de Grafana intégré ne fonctionnera plus à partir de GitLab 16.3.

### Limites de taille des clés RSA {#rsa-key-size-limits}

- Annoncé dans GitLab 16.3
- Suppression dans GitLab 16.3 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/epics/11186).

Les versions Go 1.20.7 et ultérieures ajoutent une constante `maxRSAKeySize` qui limite les clés RSA à un maximum de 8 192 bits. En conséquence, les clés RSA de plus de 8 192 bits ne fonctionneront plus avec GitLab. Toutes les clés RSA de plus de 8 192 bits doivent être régénérées avec une taille inférieure.

Vous pouvez remarquer ce problème car vos journaux contiennent une erreur telle que `tls: server sent certificate containing RSA key larger than 8192 bits`. Pour tester la longueur de votre clé, utilisez cette commande : `openssl rsa -in <your-key-file> -text -noout | grep "Key:"`.

### L'option de connexion Twitter OmniAuth est supprimée de GitLab.com {#twitter-omniauth-login-option-is-removed-from-gitlabcom}

- Annoncé dans GitLab 16.3
- Suppression dans GitLab 16.3 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-com/Product/-/issues/11417).

Twitter OAuth 1.0a OmniAuth est déprécié et supprimé sur GitLab.com dans GitLab 16.3 en raison d'une faible utilisation, d'un manque de prise en charge du gem et de l'absence d'une option de connexion fonctionnelle pour cette fonctionnalité. Si vous vous connectez à GitLab.com avec Twitter, vous pouvez vous connecter avec un mot de passe ou un autre [fournisseur OmniAuth pris en charge](https://gitlab.com/users/sign_in).

### Modèle CI de conformité des licences {#license-compliance-ci-template}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.3 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/387561).

**Mettre à jour** : nous avions précédemment annoncé que nous supprimerions le modèle CI/CD de conformité des licences existant dans GitLab 16.0. Cependant, en raison de problèmes de performances liés à l'[analyse de licences des fichiers CycloneDX](https://docs.gitlab.com/user/compliance/license_scanning_of_cyclonedx_files/), nous le ferons dans la version 16.3 à la place.

Le modèle CI/CD de [conformité des licences](https://docs.gitlab.com/user/compliance/license_approval_policies/) GitLab est désormais déprécié et est prévu pour suppression dans la release GitLab 16.3.

Pour continuer à utiliser GitLab pour la conformité des licences, supprimez le modèle de conformité des licences de votre pipeline CI/CD et ajoutez le modèle d'analyse des dépendances. Le modèle d'analyse des dépendances est désormais capable de collecter les informations de licence requises, il n'est donc plus nécessaire d'exécuter un job de conformité des licences séparé.

Avant de supprimer le modèle CI/CD de conformité des licences, vérifiez que l'instance a été mise à niveau vers une version qui prend en charge la nouvelle méthode d'analyse des licences.

Pour commencer rapidement à utiliser l'analyseur de dépendances à grande échelle, vous pouvez configurer une politique d'exécution de scan au niveau du groupe pour appliquer l'analyse de licences basée sur SBOM à tous les projets du groupe. Vous pouvez ensuite supprimer l'inclusion du modèle `Jobs/License-Scanning.gitlab-ci.yml` de votre configuration CI/CD.

Si vous souhaitez continuer à utiliser l'ancienne fonctionnalité de conformité des licences, vous pouvez le faire en définissant la variable `LICENSE_MANAGEMENT_VERSION CI` sur `4`. Cette variable peut être définie au niveau du projet, du groupe ou de l'instance. Ce changement de configuration vous permettra de continuer à utiliser une version existante de la conformité des licences sans avoir à adopter la nouvelle approche.

Les bugs et les vulnérabilités dans cet analyseur hérité ne seront plus corrigés.

| Inclusions dans les pipelines CI | GitLab <= 15.8 | 15.9 <= GitLab < 16.3 | GitLab >= 16.3 |
| ------------- | ------------- | ------------- | ------------- |
| Modèles DS et LS tous deux inclus | Les données de licence du job LS sont utilisées | Les données de licence du job LS sont utilisées | Les données de licence du job DS sont utilisées |
| Le modèle DS est inclus mais pas le modèle LS | Aucune donnée de licence | Les données de licence du job DS sont utilisées | Les données de licence du job DS sont utilisées |
| Le modèle LS est inclus mais pas le modèle DS | Les données de licence du job LS sont utilisées | Les données de licence du job LS sont utilisées | Aucune donnée de licence |

## GitLab 16.1 {#gitlab-161}

### Images GitLab Runner basées sur Alpine 3.12, 3.13, 3.14 {#gitlab-runner-images-based-on-alpine-312-313-314}

- Annoncé dans GitLab 15.11
- Fin de support dans GitLab 16.1
- Suppression dans GitLab 16.1
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/29639).

Nous cesserons de publier des images de runner basées sur les versions Alpine suivantes, en fin de vie :

- Alpine 3.12
- Alpine 3.13
- Alpine 3.14 (fin de vie le 23/05/2023)

## GitLab 16.0 {#gitlab-160}

### Auto DevOps ne provisionne plus de base de données PostgreSQL par défaut {#auto-devops-no-longer-provisions-a-postgresql-database-by-default}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/343988).

Actuellement, Auto DevOps provisionne par défaut une base de données PostgreSQL en cluster. Dans GitLab 16.0, les bases de données seront provisionnées uniquement pour les utilisateurs qui en font la demande. Cette modification prend en charge les déploiements en production nécessitant une gestion de base de données plus robuste.

Si vous souhaitez qu'Auto DevOps provisionne une base de données en cluster, définissez la variable CI/CD `POSTGRES_ENABLED` sur `true`.

### Le pilote de stockage Azure utilise désormais le préfixe racine correct par défaut {#azure-storage-driver-defaults-to-the-correct-root-prefix}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/container-registry/-/issues/854).

Le pilote de stockage Azure du registre de conteneurs écrit dans `//` comme répertoire racine par défaut. Ce répertoire racine par défaut apparaît à certains endroits dans l'interface Azure sous la forme `/<no-name>/`. Nous avons maintenu ce comportement hérité pour prendre en charge les déploiements plus anciens utilisant ce pilote de stockage. Cependant, lors du passage à Azure depuis un autre pilote de stockage, ce comportement masque toutes vos données jusqu'à ce que vous configuriez le pilote de stockage pour construire les chemins racines sans barre oblique initiale supplémentaire en définissant `trimlegacyrootprefix: true`.

La nouvelle configuration par défaut du pilote de stockage définira `trimlegacyrootprefix: true`, et `/` sera le répertoire racine par défaut. Vous pouvez ajouter `trimlegacyrootprefix: false` à votre configuration actuelle pour éviter toute interruption.

Ce changement majeur aura lieu dans GitLab 16.0.

### Le chart Helm Grafana intégré est déprécié {#bundled-grafana-helm-chart-is-deprecated}

- Annoncé dans GitLab 15.10
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/4353).

Le chart Helm Grafana intégré au chart Helm GitLab est déprécié et sera supprimé dans la version 7.0 du chart Helm GitLab (sortant en même temps que GitLab 16.0).

Le chart Helm Grafana intégré est un service optionnel qui peut être activé pour fournir l'interface Grafana connectée aux métriques Prometheus du chart Helm GitLab.

La version de Grafana actuellement fournie par le chart Helm GitLab n'est plus une version Grafana prise en charge. Si vous utilisez Grafana intégré, vous devez passer à la [version plus récente du chart de Grafana Labs](https://artifacthub.io/packages/helm/grafana/grafana) ou à un opérateur Grafana d'un fournisseur de confiance.

Dans votre nouvelle instance Grafana, vous pouvez [configurer le Prometheus fourni par GitLab comme source de données](https://docs.gitlab.com/administration/monitoring/performance/grafana_configuration/#configure-grafana) et [connecter Grafana à l'interface GitLab](https://docs.gitlab.com/administration/monitoring/performance/grafana_configuration/#integrate-with-gitlab-ui).

### Fournisseur OmniAuth CAS {#cas-omniauth-provider}

- Annoncé dans GitLab 15.3
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/369127).

Le gem `omniauth-cas3` qui fournit à GitLab le fournisseur OmniAuth CAS sera supprimé dans notre prochaine version majeure, GitLab 16.0. Ce gem est très peu utilisé et son absence de maintenance en amont empêche GitLab de [passer à OmniAuth 2.0](https://gitlab.com/gitlab-org/gitlab/-/issues/30073).

### Les jobs CI/CD échoueront lorsqu'aucun secret n'est retourné par HashiCorp Vault {#cicd-jobs-will-fail-when-no-secret-is-returned-from-hashicorp-vault}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/353080).

Lors de l'utilisation de l'intégration native HashiCorp Vault, les jobs CI/CD échoueront lorsqu'aucun secret n'est retourné par Vault. Assurez-vous que votre configuration retourne toujours un secret, ou mettez à jour votre pipeline pour gérer ce changement, avant GitLab 16.0.

### Modification du comportement de l'analyseur SAST basé sur MobSF dans les projets Android multi-modules {#changing-mobsf-based-sast-analyzer-behavior-in-multi-module-android-projects}

- Annoncé dans GitLab 16.0
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/408396).

**Mettre à jour** : nous avions précédemment annoncé une modification de la façon dont l'analyseur GitLab SAST basé sur MobSF analyserait les projets Android multi-modules. Nous avons annulé cette modification et aucune action n'est requise.

Au lieu de changer quel module unique serait analysé, nous avons [amélioré la prise en charge multi-modules](https://gitlab.com/gitlab-org/security-products/analyzers/mobsf/-/merge_requests/73).

### Modification des approbations de merge request avec le point de terminaison API `/approvals` {#changing-merge-request-approvals-with-the-approvals-api-endpoint}

- Annoncé dans GitLab 14.0
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/353097).

Pour modifier les approbations requises pour une merge request, vous ne devez plus utiliser le point de terminaison API `/approvals`, qui a été déprécié dans GitLab 14.0.

Utilisez plutôt le [point de terminaison `/approval_rules`](https://docs.gitlab.com/api/merge_request_approvals/#merge-request-level-mr-approvals) pour [créer](https://docs.gitlab.com/api/merge_request_approvals/#create-merge-request-level-rule) ou [mettre à jour](https://docs.gitlab.com/api/merge_request_approvals/#update-merge-request-level-rule) les règles d'approbation pour une merge request.

### Le point de terminaison de recherche au niveau du projet Conan renvoie des résultats spécifiques au projet {#conan-project-level-search-endpoint-returns-project-specific-results}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/384455).

Vous pouvez utiliser le dépôt Conan GitLab avec des points de terminaison au [niveau du projet](https://docs.gitlab.com/user/packages/conan_repository/#add-a-remote-for-your-project) ou au [niveau de l'instance](https://docs.gitlab.com/user/packages/conan_repository/#add-a-remote-for-your-instance). Chaque niveau prend en charge la commande de recherche Conan. Cependant, le point de terminaison de recherche au niveau du projet retourne également des paquets provenant de l'extérieur du projet cible.

Cette fonctionnalité non intentionnelle est dépréciée dans GitLab 15.8 et sera supprimée dans GitLab 16.0. Le point de terminaison de recherche au niveau du projet ne retournera que les paquets du projet cible.

### Champs de configuration dans le chart Helm de GitLab Runner {#configuration-fields-in-gitlab-runner-helm-chart}

- Annoncé dans GitLab 15.6
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/379064).

Depuis GitLab 13.6, les utilisateurs peuvent [spécifier toute configuration de runner dans le chart Helm de GitLab Runner](https://docs.gitlab.com/runner/install/kubernetes/). Lorsque nous avons implémenté cette fonctionnalité, nous avons déprécié les valeurs dans la configuration du chart Helm GitLab spécifiques à GitLab Runner. Les valeurs dépréciées seront supprimées dans GitLab 16.0.

### La configuration des chemins de fichier de configuration Redis à l'aide de variables d'environnement est dépréciée {#configuring-redis-config-file-paths-using-environment-variables-is-deprecated}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/388255).

Vous ne pouvez plus spécifier les emplacements des fichiers de configuration Redis à l'aide de variables d'environnement telles que `GITLAB_REDIS_CACHE_CONFIG_FILE` ou `GITLAB_REDIS_QUEUES_CONFIG_FILE`. Utilisez plutôt les emplacements de fichier de configuration par défaut, par exemple `config/redis.cache.yml` ou `config/redis.queues.yml`.

### Cache pull-through du registre de conteneurs {#container-registry-pull-through-cache}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/container-registry/-/issues/842).

Le [cache pull-through](https://docs.docker.com/docker-hub/image-library/mirror/) du registre de conteneurs est déprécié dans GitLab 15.8 et sera supprimé dans GitLab 16.0. Le cache pull-through fait partie du projet upstream [Docker Distribution](https://github.com/distribution/distribution). Cependant, nous supprimons le cache pull-through au profit du proxy de dépendances GitLab, qui vous permet de proxifier et de mettre en cache les images de conteneurs depuis Docker Hub. La suppression du cache pull-through nous permet également de supprimer le code client upstream sans sacrifier de fonctionnalités.

### Variables d'analyse de conteneurs faisant référence à Docker {#container-scanning-variables-that-reference-docker}

- Annoncé dans GitLab 15.4
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/371840).

Toutes les variables de scan de conteneurs dont le nom comporte le préfixe `DOCKER_` sont dépréciées. Cela inclut les variables `DOCKER_IMAGE`, `DOCKER_PASSWORD`, `DOCKER_USER` et `DOCKERFILE_PATH`. La prise en charge de ces variables sera supprimée dans la release GitLab 16.0. Utilisez les [nouveaux noms de variables](https://docs.gitlab.com/user/application_security/container_scanning/#available-cicd-variables) `CS_IMAGE`, `CS_REGISTRY_PASSWORD`, `CS_REGISTRY_USER` et `CS_DOCKERFILE_PATH` à la place des noms dépréciés.

### Autorisation par cookie dans l'application GitLab for Jira Cloud {#cookie-authorization-in-the-gitlab-for-jira-cloud-app}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/387299).

L'authentification par cookie dans l'application GitLab for Jira Cloud est désormais dépréciée au profit de l'authentification OAuth. Sur GitLab Self-Managed, vous devez [configurer l'authentification OAuth](https://docs.gitlab.com/integration/jira/connect-app/#set-up-oauth-authentication-for-self-managed-instances) pour continuer à utiliser l'application GitLab for Jira Cloud. Sans OAuth, vous ne pouvez pas gérer les espaces de nommage liés.

### Les scans d'API DAST utilisant le template DAST sont dépréciés {#dast-api-scans-using-dast-template-is-deprecated}

- Annoncé dans GitLab 15.7
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/384198).

Avec le passage au nouvel analyseur DAST API et le template `DAST-API.gitlab-ci.yml` pour les scans DAST API, nous allons supprimer la possibilité de scanner des API avec l'analyseur DAST. L'utilisation des templates `DAST.gitlab-ci.yml` ou `DAST-latest.gitlab-ci.yml` pour les scans d'API est dépréciée depuis GitLab 15.7 et ne fonctionnera plus dans GitLab 16.0. Veuillez utiliser le template `DAST-API.gitlab-ci.yml` et vous référer à la documentation de l'[analyseur DAST API](https://docs.gitlab.com/user/application_security/dast_api/#configure-dast-api-with-an-openapi-specification) pour les détails de configuration.

### Variables DAST API {#dast-api-variables}

- Annoncé dans GitLab 15.7
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/383467).

Avec le passage au nouvel analyseur DAST API dans GitLab 15.6, deux variables DAST API héritées sont dépréciées. Les variables `DAST_API_HOST_OVERRIDE` et `DAST_API_SPECIFICATION` ne seront plus utilisées pour les scans DAST API.

`DAST_API_HOST_OVERRIDE` a été déprécié au profit de l'utilisation de `DAST_API_TARGET_URL` pour remplacer automatiquement l'hôte dans la spécification OpenAPI.

`DAST_API_SPECIFICATION` a été déprécié au profit de `DAST_API_OPENAPI`. Pour continuer à utiliser une spécification OpenAPI comme guide de test, les utilisateurs doivent remplacer la variable `DAST_API_SPECIFICATION` par la variable `DAST_API_OPENAPI`. La valeur peut rester identique, mais le nom de la variable doit être remplacé.

Ces deux variables seront supprimées dans GitLab 16.0.

### Dépréciation des variables de rapport DAST {#dast-report-variables-deprecation}

- Annoncé dans GitLab 15.7
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/384340).

Avec la disponibilité générale du nouvel analyseur DAST basé sur navigateur dans GitLab 15.7, nous travaillons à en faire l'analyseur DAST par défaut à un moment donné dans le futur. En préparation à cela, les variables DAST héritées suivantes sont dépréciées et planifiées pour suppression dans GitLab 16.0 : `DAST_HTML_REPORT`, `DAST_XML_REPORT` et `DAST_MARKDOWN_REPORT`. Ces rapports reposaient sur l'analyseur DAST hérité et nous ne prévoyons pas de les implémenter dans le nouvel analyseur basé sur navigateur. À partir de GitLab 16.0, ces artefacts de rapport ne seront plus générés.

Ces trois variables seront supprimées dans GitLab 16.0.

### Prise en charge de l'analyse des dépendances pour Java 13, 14, 15 et 16 {#dependency-scanning-support-for-java-13-14-15-and-16}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/387560).

GitLab a déprécié la prise en charge de l'analyse des dépendances pour les versions Java 13, 14, 15 et 16, et prévoit de supprimer cette prise en charge dans la prochaine release GitLab 16.0. Ceci est cohérent avec la [politique de support d'Oracle](https://www.oracle.com/java/technologies/java-se-support-roadmap.html), car le support Premier et Extended d'Oracle pour ces versions a pris fin. Cela permet également à GitLab de concentrer la prise en charge Java de l'analyse des dépendances sur les versions LTS à l'avenir.

### L'API de déploiement renvoie une erreur lorsque `updated_at` et `updated_at` ne sont pas utilisés ensemble {#deployment-api-returns-error-when-updated_at-and-updated_at-are-not-used-together}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/328500).

L'API de déploiement renvoie désormais une erreur lorsque le filtrage par `updated_at` et le tri par `updated_at` ne sont pas utilisés ensemble. Certains utilisateurs utilisaient le filtrage par `updated_at` pour obtenir le déploiement « le plus récent » sans utiliser le tri par `updated_at`, ce qui peut produire des résultats incorrects. Vous devriez plutôt les utiliser ensemble, ou migrer vers le filtrage par `finished_at` et le tri par `finished_at`, ce qui vous donnera les « derniers déploiements » de manière cohérente.

### Dépréciation des méthodes de configuration Gitaly héritées {#deprecate-legacy-gitaly-configuration-methods}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352609).

L'utilisation des variables d'environnement `GIT_CONFIG_SYSTEM` et `GIT_CONFIG_GLOBAL` pour configurer Gitaly est [dépréciée](https://gitlab.com/gitlab-org/gitlab/-/issues/352609). Ces variables sont remplacées par la [configuration Gitaly `config.toml` standard](https://docs.gitlab.com/administration/gitaly/).

Les instances GitLab qui utilisent `GIT_CONFIG_SYSTEM` et `GIT_CONFIG_GLOBAL` pour configurer Gitaly doivent passer à la configuration via `config.toml`.

### Métriques HTTP Consul dépréciées {#deprecated-consul-http-metrics}

- Annoncé dans GitLab 15.10
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7278).

Le Consul fourni dans le package Linux ne fournira plus les anciennes métriques Consul dépréciées à partir de GitLab 16.0.

Dans GitLab 14.0, [Consul a été mis à jour vers la version 1.9.6](https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/5344), ce qui a déprécié certaines métriques de télémétrie du chemin `consul.http`. Dans GitLab 16.0, le chemin `consul.http` sera supprimé.

Si vous disposez d'une surveillance qui consomme des métriques Consul, mettez-la à jour pour utiliser `consul.api.http` au lieu de `consul.http`. Pour plus d'informations, consultez [les notes de dépréciation de Consul 1.9.0](https://github.com/hashicorp/consul/releases/tag/v1.9.0).

### Dépréciation et suppression planifiée de la variable `CI_PRE_CLONE_SCRIPT` sur GitLab.com {#deprecation-and-planned-removal-for-ci_pre_clone_script-variable-on-gitlabcom}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/391896).

La [variable `CI_PRE_CLONE_SCRIPT`](https://docs.gitlab.com/ci/runners/saas/linux_saas_runner/#pre-clone-script) prise en charge par les runners GitLab.com est dépréciée depuis GitLab 15.9 et sera supprimée dans la version 16.0. La variable `CI_PRE_CLONE_SCRIPT` vous permet d'exécuter des commandes dans votre job CI/CD avant que le runner n'exécute Git init et get fetch. Pour plus d'informations sur le fonctionnement de cette fonctionnalité, consultez [Pre-clone script](https://docs.gitlab.com/ci/runners/saas/linux_saas_runner/#pre-clone-script). Vous pouvez également utiliser [`pre_get_sources_script`](https://docs.gitlab.com/ci/yaml/#hookspre_get_sources_script).

### Rôle Developer permettant d'importer des projets dans un groupe {#developer-role-providing-the-ability-to-import-projects-to-a-group}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/387891).

La possibilité pour les utilisateurs disposant du rôle Developer dans un groupe d'importer des projets dans ce groupe est dépréciée dans GitLab 15.8 et sera supprimée dans GitLab 16.0. À partir de GitLab 16.0, seuls les utilisateurs disposant du rôle Maintainer ou Owner dans un groupe pourront importer des projets dans ce groupe.

### Dépendances de développement signalées pour PHP et Python {#development-dependencies-reported-for-php-and-python}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/375505).

Dans GitLab 16.0, l'analyseur d'analyse des dépendances GitLab commencera à signaler les dépendances de développement pour les projets Python/pipenv et PHP/composer. Les utilisateurs qui ne souhaitent pas que ces dépendances de développement soient signalées doivent définir `DS_INCLUDE_DEV_DEPENDENCIES: false` dans leur fichier CI/CD.

### L'intégration de panneaux Grafana dans Markdown est dépréciée {#embedding-grafana-panels-in-markdown-is-deprecated}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/389477).

La possibilité d'ajouter des panneaux Grafana dans le Markdown GitLab Flavored est dépréciée dans la version 15.9 et sera supprimée dans la version 16.0. Nous prévoyons de remplacer cette fonctionnalité par la possibilité d'[intégrer des graphiques](https://gitlab.com/groups/gitlab-org/opstrace/-/epics/33) avec l'[interface utilisateur GitLab Observability](https://gitlab.com/gitlab-org/opstrace/opstrace-ui).

### Validation forcée des longueurs de caractères des paramètres CI/CD {#enforced-validation-of-cicd-parameter-character-lengths}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/372770).

Alors que les [noms de jobs](https://docs.gitlab.com/ci/jobs/#job-name) CI/CD ont une limite stricte de 255 caractères, les autres paramètres CI/CD ne disposent pas encore de validations garantissant qu'ils restent également en dessous de cette limite.

Dans GitLab 16.0, une validation sera ajoutée pour limiter strictement les éléments suivants à 255 caractères également :

- Le mot-clé `stage`.
- Le `ref`, qui correspond au nom de la branche ou du tag Git pour le pipeline.
- Le paramètre `description` et `target_url`, utilisé par les intégrations CI/CD externes.

Les utilisateurs de GitLab Self-Managed doivent mettre à jour leurs pipelines pour s'assurer qu'ils n'utilisent pas de paramètres dépassant 255 caractères. Les utilisateurs de GitLab.com n'ont aucune modification à apporter, car ces valeurs sont déjà limitées dans cette base de données.

### La requête de recherche d'environnement nécessite au moins trois caractères {#environment-search-query-requires-at-least-three-characters}

- Annoncé dans GitLab 15.10
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/382532).

À partir de GitLab 16.0, lorsque vous recherchez des environnements via l'API, vous devez utiliser au moins trois caractères. Cette modification nous aide à garantir la scalabilité de l'opération de recherche.

### Champ externe dans le type GraphQL ReleaseAssetLink {#external-field-in-graphql-releaseassetlink-type}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Dans l'[API GraphQL](https://docs.gitlab.com/api/graphql/), le champ `external` du [type `ReleaseAssetLink`](https://docs.gitlab.com/api/graphql/reference/objects/#releaseassetlink) était utilisé pour indiquer si un [lien de release](https://docs.gitlab.com/user/project/releases/release_fields/#links) est interne ou externe à votre instance GitLab. Depuis GitLab 15.9, nous traitons tous les liens de release comme externes et, par conséquent, ce champ est déprécié dans GitLab 15.9 et sera supprimé dans GitLab 16.0. Pour éviter toute perturbation de votre workflow, veuillez cesser d'utiliser le champ `external`, car il sera supprimé et ne sera pas remplacé.

### Champ externe dans les API Releases et Release Links {#external-field-in-releases-and-release-links-apis}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Dans l'[API Releases](https://docs.gitlab.com/api/releases/) et l'[API Release Links](https://docs.gitlab.com/api/releases/links/), le champ `external` était utilisé pour indiquer si un [lien de release](https://docs.gitlab.com/user/project/releases/release_fields/#links) est interne ou externe à votre instance GitLab. Depuis GitLab 15.9, nous traitons tous les liens de release comme externes et, par conséquent, ce champ est déprécié dans GitLab 15.9 et sera supprimé dans GitLab 16.0. Pour éviter toute perturbation de votre workflow, veuillez cesser d'utiliser le champ `external`, car il sera supprimé et ne sera pas remplacé.

### Geo : le retéléchargement de dépôt de projet est déprécié {#geo-project-repository-redownload-is-deprecated}

- Annoncé dans GitLab 15.11
- Suppression dans GitLab 16.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/388868).

Sur les sites Geo secondaires, le bouton « Retélécharger » un dépôt de projet est déprécié. La logique de retéléchargement présente des problèmes inhérents de cohérence des données qui sont difficiles à résoudre lorsqu'ils surviennent. Le bouton sera supprimé dans GitLab 16.0.

### Les administrateurs GitLab doivent disposer de l'autorisation pour modifier les branches ou tags protégés {#gitlab-administrators-must-have-permission-to-modify-protected-branches-or-tags}

- Annoncé dans GitLab 16.0
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/12776).

Les administrateurs GitLab ne peuvent plus effectuer d'actions sur les branches ou tags protégés, sauf si cette autorisation leur a été explicitement accordée. Ces actions incluent le push et la fusion dans une [branche protégée](https://docs.gitlab.com/user/project/repository/branches/protected/), la déprotection d'une branche et la création de [tags protégés](https://docs.gitlab.com/user/project/protected_tags/).

### Projet d'auto-surveillance GitLab {#gitlab-self-monitoring-project}

- Annoncé dans GitLab 14.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/348909).

L'auto-surveillance GitLab fournit aux administrateurs d'instances les outils nécessaires pour surveiller l'état de santé de leurs instances. Cette fonctionnalité est dépréciée dans GitLab 14.9 et est planifiée pour suppression dans la version 16.0.

### Importateur GitLab.com {#gitlabcom-importer}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0

L'importateur GitLab.com a été déprécié dans GitLab 15.8 et sera supprimé dans GitLab 16.0.

L'importateur GitLab.com a été introduit en 2015 pour importer un projet de GitLab.com vers une instance GitLab Self-Managed via l'interface utilisateur. Cette fonctionnalité est disponible uniquement sur GitLab Self-Managed. [La migration des groupes et projets GitLab par transfert direct](https://docs.gitlab.com/user/group/import/#migrate-groups-by-direct-transfer-recommended) remplace l'importateur GitLab.com et offre une fonctionnalité d'importation plus cohérente.

Consultez les [éléments de groupe migrés](https://docs.gitlab.com/user/group/import/#migrated-group-items) et les [éléments de projet migrés](https://docs.gitlab.com/user/group/import/#migrated-project-items) pour une vue d'ensemble.

### Le statut du runner dans l'API GraphQL ne renverra plus `paused` {#graphql-api-runner-status-will-not-return-paused}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/344648).

Les endpoints de l'API GraphQL de GitLab Runner ne renverront plus `paused` ou `active` comme statut dans GitLab 16.0. Dans une future version v5 de l'API REST, les endpoints pour GitLab Runner ne renverront également plus `paused` ou `active`.

Le statut d'un runner sera uniquement lié à l'état de contact du runner, par exemple : `online`, `offline` ou `not_connected`. Le statut `paused` ou `active` n'apparaîtra plus.

Pour vérifier si un runner est `paused`, les utilisateurs de l'API sont invités à vérifier que l'attribut booléen `paused` vaut `true` à la place. Pour vérifier si un runner est `active`, vérifiez que `paused` vaut `false`.

### Connecteur Jira DVCS pour Jira Cloud {#jira-dvcs-connector-for-jira-cloud}

- Annoncé dans GitLab 15.1
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/epics/7508).

Le [connecteur Jira DVCS](https://docs.gitlab.com/integration/jira/dvcs/) pour Jira Cloud a été déprécié et sera supprimé dans GitLab 16.0. Si vous utilisez le connecteur Jira DVCS avec Jira Cloud, migrez vers l'[application GitLab for Jira Cloud](https://docs.gitlab.com/integration/jira/connect-app/).

Le connecteur Jira DVCS est également déprécié pour Jira 8.13 et les versions antérieures. Vous pouvez uniquement utiliser le connecteur Jira DVCS avec Jira Server ou Jira Data Center dans Jira 8.14 et les versions ultérieures.

### Port de métriques KAS dans le chart Helm GitLab {#kas-metrics-port-in-gitlab-helm-chart}

- Annoncé dans GitLab 15.7
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/383039).

Le `gitlab.kas.metrics.port` a été déprécié au profit du nouveau champ de configuration `gitlab.kas.observability.port` pour le [chart Helm GitLab](https://gitlab.com/gitlab-org/charts/gitlab/-/merge_requests/2839). Ce port est utilisé pour bien plus que les seules métriques, ce qui a justifié cette modification pour éviter toute confusion dans la configuration.

### Méthode de configuration Gitaly héritée {#legacy-gitaly-configuration-method}

- Annoncé dans GitLab 15.10
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/393574).

La configuration de Gitaly dans Omnibus GitLab a été mise à jour de telle sorte que toutes les clés de configuration liées à Gitaly se trouvent dans une structure de configuration unique correspondant à la configuration Gitaly standard. Par conséquent, la structure de configuration précédente est dépréciée.

La structure de configuration unique est disponible depuis GitLab 15.10, bien que la compatibilité ascendante soit maintenue. Une fois supprimée, Gitaly devra être configuré à l'aide de la structure de configuration unique. Vous devriez mettre à jour la configuration de Gitaly dès que possible.

Cette modification améliore la cohérence entre Omnibus GitLab et les installations à partir des sources, et nous permet de fournir une meilleure documentation et des meilleurs outils pour les deux.

Vous devriez migrer vers la nouvelle structure de configuration dès que possible en suivant [les instructions de mise à niveau](https://docs.gitlab.com/update/#gitaly-omnibus-gitlab-configuration-structure-change).

### Méthode de configuration Praefect héritée {#legacy-praefect-configuration-method}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/390291).

Auparavant, les clés de configuration Praefect étaient dispersées dans le fichier de configuration. Désormais, elles se trouvent dans une structure de configuration unique correspondant à la configuration Praefect, ce qui rend la méthode de configuration précédente dépréciée.

La structure de configuration unique est disponible depuis GitLab 15.9, bien que la compatibilité ascendante soit maintenue. Une fois supprimée, Praefect devra être configuré à l'aide de la structure de configuration unique. Vous devriez mettre à jour votre configuration Praefect dès que possible en suivant [les instructions de mise à niveau](https://docs.gitlab.com/update/#praefect-omnibus-gitlab-configuration-structure-change).

Cette modification aligne la configuration de Praefect dans Omnibus GitLab sur la structure de configuration de Praefect. Auparavant, les hiérarchies et les clés de configuration ne correspondaient pas. Cette modification améliore la cohérence entre Omnibus GitLab et les installations à partir des sources, et nous permet de fournir une meilleure documentation et des meilleurs outils pour les deux.

### URLs héritées remplacées ou supprimées {#legacy-urls-replaced-or-removed}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/214217).

GitLab 16.0 supprime les URLs héritées de l'application GitLab.

Lors de l'introduction des sous-groupes dans GitLab 9.0, un délimiteur `/-/` a été ajouté aux URLs pour signifier la fin d'un chemin de groupe. Toutes les URLs GitLab utilisent désormais ce délimiteur pour les fonctionnalités au niveau du projet, du groupe et de l'instance.

Les URLs n'utilisant pas le délimiteur `/-/` sont planifiées pour suppression dans GitLab 16.0. Pour la liste complète de ces URLs, ainsi que leurs remplacements, consultez le [ticket 28848](https://gitlab.com/gitlab-org/gitlab/-/issues/28848#release-notes).

Mettez à jour tous les scripts ou signets faisant référence aux URLs héritées. Les API GitLab ne sont pas affectées par cette modification.

### License-Check et l'onglet Politiques sur la page de conformité des licences {#license-check-and-the-policies-tab-on-the-license-compliance-page}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/390417).

La **fonctionnalité License-Check** est désormais dépréciée et planifiée pour suppression dans GitLab 16.0. De plus, l'onglet Politiques sur la page de conformité des licences et toutes les API liées à la fonctionnalité License-Check sont dépréciés et planifiés pour suppression dans GitLab 16.0. Les utilisateurs souhaitant continuer à appliquer des approbations basées sur les licences détectées sont encouragés à créer une nouvelle [politique d'approbation de licences](https://docs.gitlab.com/user/compliance/license_approval_policies/).

### Limiter l'accès des jetons d'accès personnel et des jetons de déploiement avec l'autorisation externe {#limit-personal-access-token-and-deploy-tokens-access-with-external-authorization}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/387721).

Lorsque l'autorisation externe est activée, les jetons d'accès personnel (PAT) et les jetons de déploiement ne doivent plus pouvoir accéder aux registres de conteneurs ou de packages. Cette mesure de sécurité en profondeur sera déployée dans la version 16.0. Pour les utilisateurs qui utilisent des PAT et des jetons de déploiement pour accéder à ces registres, cette mesure rompt cet usage de ces jetons. Désactivez l'autorisation externe pour utiliser des jetons avec les registres de conteneurs ou de packages.

### Mises à jour majeures des charts Helm intégrés pour le chart Helm GitLab {#major-bundled-helm-chart-updates-for-the-gitlab-helm-chart}

- Annoncé dans GitLab 15.10
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/3442).

Conjointement avec GitLab 16.0, le chart Helm GitLab publiera la version majeure 7.0. Les mises à jour majeures suivantes des charts intégrés seront incluses :

- Dans GitLab 16.0, [la prise en charge de PostgreSQL 12 est supprimée et PostgreSQL 13 devient le nouveau minimum](#postgresql-12-deprecated).
  - Les installations utilisant des bases de données externes prêtes pour la production devront effectuer leur migration vers une version PostgreSQL plus récente avant la mise à niveau.
  - Les installations utilisant le [chart PostgreSQL 12 intégré non destiné à la production](https://docs.gitlab.com/charts/installation/tools/#postgresql) verront le chart mis à niveau vers la nouvelle version. Pour plus d'informations, [consultez le ticket 4118](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/4118)
- Les installations utilisant le [chart Redis intégré non destiné à la production](https://docs.gitlab.com/charts/installation/tools/#redis) verront le chart mis à niveau vers une version plus récente. Pour plus d'informations, [consultez le ticket 3375](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/3375)
- Les installations utilisant le [chart cert-manager intégré](https://docs.gitlab.com/charts/installation/tls/#option-1-cert-manager-and-lets-encrypt) verront le chart mis à niveau vers une version plus récente. Pour plus d'informations, [consultez le ticket 4313](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/4313)

Les étapes complètes de mise à niveau du chart Helm GitLab 7.0 seront disponibles dans la [documentation de mise à niveau](https://docs.gitlab.com/charts/installation/upgrade/).

### API des licences gérées {#managed-licenses-api}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/390417).

L'API des licences gérées est désormais dépréciée et planifiée pour suppression dans GitLab 16.0.

### Limite du nombre maximum de pipelines actifs par projet (`ci_active_pipelines`) {#maximum-number-of-active-pipelines-per-project-limit-ci_active_pipelines}

- Annoncé dans GitLab 15.3
- Suppression dans GitLab 16.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/368195).

La [limite du **Nombre maximum de pipelines actifs par projet**](https://docs.gitlab.com/administration/settings/continuous_integration/#set-cicd-limits) n'a jamais été activée par défaut et sera supprimée dans GitLab 16.0. Cette limite peut également être configurée dans la console Rails sous [`ci_active_pipelines`](https://docs.gitlab.com/administration/instance_limits/#number-of-pipelines-running-concurrently). Utilisez plutôt les autres limites de débit recommandées qui offrent une protection similaire :

- [**Limites de débit des pipelines**](https://docs.gitlab.com/administration/settings/rate_limit_on_pipelines_creation/).
- [**Nombre total de jobs dans les pipelines actuellement actifs**](https://docs.gitlab.com/administration/settings/continuous_integration/#set-cicd-limits).

### Surveiller les métriques de performance via Prometheus {#monitor-performance-metrics-through-prometheus}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/346541).

En affichant les données stockées dans une instance Prometheus, GitLab permet aux utilisateurs de visualiser les métriques de performance. GitLab affiche également des visualisations de ces métriques dans des tableaux de bord. L'utilisateur peut se connecter à une instance Prometheus externe précédemment configurée, ou configurer Prometheus en tant qu'application gérée par GitLab. Cependant, étant donné que l'intégration basée sur des certificats avec les clusters Kubernetes est dépréciée dans GitLab, la fonctionnalité de métriques dans GitLab qui repose sur Prometheus est également dépréciée. Cela inclut les visualisations de métriques dans les tableaux de bord. GitLab travaille à développer une expérience utilisateur unifiée basée sur [Opstrace](https://about.gitlab.com/press/releases/2021-12-14-gitlab-acquires-opstrace-to-expand-its-devops-platform-with-open-source-observability-solution/). Un [ticket existe](https://gitlab.com/groups/gitlab-org/-/epics/6976) pour vous permettre de suivre l'avancement de l'intégration Opstrace.

### Jetons d'accès sans expiration {#non-expiring-access-tokens}

- Annoncé dans GitLab 15.4
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/369122).

La question de savoir si des dates d'expiration sont automatiquement appliquées à vos jetons d'accès au projet existants dépend de votre offre GitLab et de la date à laquelle vous avez effectué la mise à niveau vers GitLab 16.0 ou une version ultérieure :

- Sur GitLab.com, pendant le jalon 16.0, les jetons d'accès au projet existants sans date d'expiration ont automatiquement reçu une date d'expiration fixée à 365 jours après la date actuelle.
- Sur GitLab Self-Managed, si vous avez effectué une mise à niveau depuis GitLab 15.11 ou une version antérieure vers GitLab 16.0 ou une version ultérieure :
  - Le 23 juillet 2024 ou avant, les jetons d'accès au projet existants sans date d'expiration ont automatiquement reçu une date d'expiration fixée à 365 jours après la date actuelle. Il s'agit d'un changement majeur.
  - Le 24 juillet 2024 ou après, les jetons d'accès au projet existants sans date d'expiration n'ont pas reçu de date d'expiration.

Sur GitLab Self-Managed, si vous effectuez une nouvelle installation de l'une des versions GitLab suivantes, vos jetons d'accès au projet existants ne se voient pas automatiquement appliquer de dates d'expiration :

- 16.0.9
- 16.1.7
- 16.2.10
- 16.3.8
- 16.4.6
- 16.5.9
- 16.6.9
- 16.7.9
- 16.8.9
- 16.9.10
- 16.10.9
- 16.11.7
- 17.0.5
- 17.1.3
- 17.2.1

Les jetons d'accès sans date d'expiration sont valides indéfiniment, ce qui représente un risque de sécurité si le jeton d'accès est divulgué. Parce que les jetons d'accès avec date d'expiration sont préférables, depuis GitLab 15.3, nous [définissons une date d'expiration par défaut](https://gitlab.com/gitlab-org/gitlab/-/issues/348660).

Dans GitLab 16.0, tout jeton d'accès [personnel](https://docs.gitlab.com/user/profile/personal_access_tokens/), [de projet](https://docs.gitlab.com/user/project/settings/project_access_tokens/) ou [de groupe](https://docs.gitlab.com/user/group/settings/group_access_tokens/) sans date d'expiration se verra automatiquement attribuer une date d'expiration d'un an.

Nous vous recommandons de définir une date d'expiration pour vos jetons d'accès conformément aux politiques de sécurité de votre entreprise, avant que la valeur par défaut ne soit appliquée :

- Sur GitLab.com pendant le jalon 16.0.
- Sur GitLab Self-Managed lors de la mise à niveau vers la version 16.0.

### Les ports Redis par défaut non standard sont dépréciés {#non-standard-default-redis-ports-are-deprecated}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/388269).

Si GitLab démarre sans aucun fichier de configuration Redis présent, GitLab suppose qu'il peut se connecter à trois serveurs Redis aux adresses `localhost:6380`, `localhost:6381` et `localhost:6382`. Nous modifions ce comportement afin que GitLab suppose qu'il existe un seul serveur Redis à l'adresse `localhost:6379`.

Les administrateurs souhaitant conserver les trois serveurs doivent configurer les URLs Redis en modifiant les fichiers `config/redis.cache.yml`, `config/redis.queues.yml` et `config/redis.shared_state.yml`.

### L'option de suppression immédiate des projets est dépréciée dans les paramètres de protection contre la suppression {#option-to-delete-projects-immediately-is-deprecated-from-deletion-protection-settings}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/389557).

Le paramètre de protection contre la suppression de groupes et de projets dans la zone **Admin** incluait une option permettant de supprimer immédiatement les groupes et les projets. À partir de la version 16.0, cette option ne sera plus disponible et la suppression différée des groupes et des projets deviendra le comportement par défaut.

L'option n'apparaîtra plus en tant que paramètre de groupe. Les utilisateurs de GitLab Self-Managed auront toujours la possibilité de définir la période de délai de suppression, et les utilisateurs de GitLab.com disposent d'une période de rétention par défaut non ajustable de 7 jours. Les utilisateurs peuvent toujours supprimer immédiatement le projet depuis les paramètres du projet, et le groupe depuis les paramètres du groupe.

L'option de suppression immédiate des groupes et des projets par défaut a été dépréciée pour éviter que les utilisateurs ne prennent cette action accidentellement et ne perdent définitivement des groupes et des projets.

### PostgreSQL 12 déprécié {#postgresql-12-deprecated}

- Annoncé dans GitLab 15.0
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/349185).

La prise en charge de PostgreSQL 12 est planifiée pour suppression dans GitLab 16.0. Dans GitLab 16.0, PostgreSQL 13 devient la version minimale requise de PostgreSQL.

PostgreSQL 12 sera pris en charge pendant tout le cycle de release de GitLab 15. PostgreSQL 13 sera également pris en charge pour les instances souhaitant effectuer la mise à niveau avant GitLab 16.0.

La prise en charge de PostgreSQL 13 a été ajoutée à Geo dans GitLab 15.2.

### Le champ `operations_access_level` de l'API Projects est déprécié {#projects-api-field-operations_access_level-is-deprecated}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/385798).

Nous déprécions le champ `operations_access_level` dans l'API Projects. Ce champ a été remplacé par des champs permettant de contrôler des fonctionnalités spécifiques : `releases_access_level`, `environments_access_level`, `feature_flags_access_level`, `infrastructure_access_level` et `monitor_access_level`.

### Tâche Rake pour l'importation de dépôts nus {#rake-task-for-importing-bare-repositories}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0

La tâche Rake pour l'importation de dépôts nus (`gitlab:import:repos`) est dépréciée dans GitLab 15.8 et sera supprimée dans GitLab 16.0.

Cette tâche Rake importe une arborescence de dépôts dans une instance GitLab. Ces dépôts doivent avoir été gérés par GitLab précédemment, car la tâche Rake repose sur une structure de répertoires spécifique ou un paramètre Git personnalisé spécifique pour fonctionner (`gitlab.fullpath`).

L'importation de dépôts à l'aide de cette tâche Rake présente des limitations. La tâche Rake :

- Ne reconnaît que les dépôts de projets et de wikis de projets, et ne prend pas en charge les dépôts pour les designs, les wikis de groupes ou les snippets.
- Vous permet d'importer des projets avec un stockage non haché, même si ceux-ci ne sont pas pris en charge.
- Nécessite que la configuration Git `gitlab.fullpath` soit définie. L'[Epic 8953](https://gitlab.com/groups/gitlab-org/-/epics/8953) propose de supprimer la prise en charge de ce paramètre.

Les alternatives à l'utilisation de la tâche Rake `gitlab:import:repos` incluent :

- La migration de projets à l'aide d'un [fichier d'export](https://docs.gitlab.com/user/project/settings/import_export/) ou du [transfert direct](https://docs.gitlab.com/user/group/import/#migrate-groups-by-direct-transfer-recommended) migre également les dépôts.
- L'importation d'un [dépôt par URL](https://docs.gitlab.com/user/project/import/repo_by_url/).
- L'importation de [dépôts depuis une source non-GitLab](https://docs.gitlab.com/user/import/).

### Redis 5 déprécié {#redis-5-deprecated}

- Annoncé dans GitLab 15.3
- Fin de prise en charge dans GitLab 15.6
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/331468).

Avec GitLab 13.9, dans le package Omnibus GitLab et le chart Helm GitLab 4.9, la version Redis [a été mise à jour vers Redis 6](https://about.gitlab.com/releases/2021/02/22/gitlab-13-9-released/#omnibus-improvements). Redis 5 a atteint sa fin de vie en avril 2022 et ne sera plus pris en charge à partir de GitLab 15.6. Si vous utilisez votre propre instance Redis 5.0, vous devez la mettre à niveau vers Redis 6.0 ou une version supérieure avant de passer à GitLab 16.0 ou une version supérieure.

### Supprimer le paramètre `job_age` du endpoint Runner `POST /jobs/request` {#remove-job_age-parameter-from-post-jobsrequest-runner-endpoint}

- Annoncé dans GitLab 15.2
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/334253).

Le paramètre `job_age`, renvoyé par le endpoint API `POST /jobs/request` utilisé dans la communication avec GitLab Runner, n'a jamais été utilisé par aucune fonctionnalité de GitLab ou de Runner. Ce paramètre sera supprimé dans GitLab 16.0.

Cela pourrait constituer un changement majeur pour quiconque a développé son propre runner qui repose sur ce paramètre renvoyé par le endpoint. Cela ne constitue pas un changement majeur pour quiconque utilise une version officielle de GitLab Runner, y compris les runners partagés publics sur GitLab.com.

### La couverture de l'analyseur SAST change dans GitLab 16.0 {#sast-analyzer-coverage-changing-in-gitlab-160}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/390416).

GitLab SAST utilise divers [analyseurs](https://docs.gitlab.com/user/application_security/sast/analyzers/) pour scanner le code à la recherche de vulnérabilités.

Nous réduisons le nombre d'analyseurs pris en charge utilisés par défaut dans GitLab SAST. Cela s'inscrit dans notre stratégie à long terme visant à offrir une expérience utilisateur plus rapide et plus cohérente dans différents langages de programmation.

À partir de GitLab 16.0, le template CI/CD GitLab SAST n'utilisera plus l'analyseur basé sur [Security Code Scan](https://gitlab.com/gitlab-org/security-products/analyzers/security-code-scan) pour .NET, et entrera en statut Fin de prise en charge. Nous supprimerons cet analyseur du [template CI/CD SAST](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/SAST.gitlab-ci.yml) et le remplacerons par des règles de détection gérées par GitLab pour C# dans l'[analyseur basé sur Semgrep](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep).

Avec effet immédiat, cet analyseur ne recevra que des mises à jour de sécurité ; les autres améliorations ou mises à jour de routine ne sont pas garanties. Une fois que cet analyseur aura atteint la Fin de prise en charge dans GitLab 16.0, aucune mise à jour supplémentaire ne sera fournie. Cependant, nous ne supprimerons pas les images de conteneurs précédemment publiées pour cet analyseur et ne retirerons pas la possibilité de l'exécuter via un job de pipeline CI/CD personnalisé.

Si vous avez déjà ignoré une vulnérabilité trouvée par l'analyseur déprécié, le remplacement tentera de respecter votre précédent rejet. Le comportement du système dépend de :

- si vous avez exclu l'analyseur basé sur Semgrep de l'exécution dans le passé.
- quel analyseur a découvert en premier les vulnérabilités affichées dans le rapport de vulnérabilités du projet.

Consultez la [documentation sur la traduction des vulnérabilités](https://docs.gitlab.com/user/application_security/sast/analyzers/#vulnerability-translation) pour plus de détails.

Si vous avez appliqué des personnalisations à l'analyseur concerné, ou si vous désactivez actuellement l'analyseur basé sur Semgrep dans vos pipelines, vous devez prendre les mesures détaillées dans le [ticket de dépréciation pour cette modification](https://gitlab.com/gitlab-org/gitlab/-/issues/390416#breaking-change).

**Mettre à jour** : nous avons réduit le périmètre de cette modification. Nous n'apporterons plus les modifications suivantes dans GitLab 16.0 :

1. Supprimer la prise en charge de l'analyseur basé sur [PHPCS Security Audit](https://gitlab.com/gitlab-org/security-products/analyzers/phpcs-security-audit) et le remplacer par des règles de détection gérées par GitLab dans l'[analyseur basé sur Semgrep](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep).
1. Supprimer Scala du périmètre de l'[analyseur basé sur SpotBugs](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs) et le remplacer par des règles de détection gérées par GitLab dans l'[analyseur basé sur Semgrep](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep).

Le travail visant à remplacer l'analyseur basé sur PHPCS Security Audit est suivi dans le [ticket 364060](https://gitlab.com/gitlab-org/gitlab/-/issues/364060) et le travail visant à migrer le scan Scala vers l'analyseur basé sur Semgrep est suivi dans le [ticket 362958](https://gitlab.com/gitlab-org/gitlab/-/issues/362958).

### Mise à jour de la version majeure des analyseurs Secure {#secure-analyzers-major-version-update-1}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/390912).

L'étape Secure incrémentera les versions majeures de ses analyseurs parallèlement à la release GitLab 16.0. Cette incrémentation permettra une distinction claire pour les analyseurs, entre :

- Ceux publiés avant le 22 mai 2023
- Ceux publiés après le 22 mai 2023

Si vous n'utilisez pas les templates inclus par défaut, ou si vous avez épinglé vos versions d'analyseurs, vous devrez mettre à jour la définition de votre job CI/CD pour soit supprimer la version épinglée, soit mettre à jour la dernière version majeure. Les utilisateurs de GitLab 13.0 à 15.10 continueront à recevoir les mises à jour des analyseurs normalement jusqu'à la release de GitLab 16.0, après quoi tous les nouveaux correctifs de bugs et fonctionnalités publiés ne seront disponibles que dans la nouvelle version majeure des analyseurs. Nous ne rétroportons pas les bugs et fonctionnalités vers les versions dépréciées conformément à notre [politique de maintenance](https://docs.gitlab.com/policy/maintenance/). Si nécessaire, les correctifs de sécurité feront l'objet d'un backport dans les 3 dernières versions mineures. Plus précisément, les éléments suivants sont dépréciés et ne seront plus mis à jour après la release de GitLab 16.0 :

- Fuzzing d'API : version 2
- Scan de conteneurs : version 5
- Test de fuzzing guidé par la couverture : version 3
- Analyse des dépendances : version 3
- Test dynamique de sécurité des applications (DAST) : version 3
- DAST API : version 2
- Scan IaC : version 3
- Scan de licences : version 4
- Détection des secrets : version 4
- Test statique de sécurité des applications (SAST) : version 3 de [tous les analyseurs](https://docs.gitlab.com/user/application_security/sast/#supported-languages-and-frameworks)
  - `brakeman` : version 3
  - `flawfinder` : version 3
  - `kubesec` : version 3
  - `mobsf` : version 3
  - `nodejs-scan` : version 3
  - `phpcs-security-audit` : version 3
  - `pmd-apex` : version 3
  - `security-code-scan` : version 3
  - `semgrep` : version 3
  - `sobelow` : version 3
  - `spotbugs` : version 3

### Les templates CI/CD de scan de sécurité utiliseront de nouvelles `rules` de job {#secure-scanning-cicd-templates-will-use-new-job-rules}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/391822).

Les templates CI/CD gérés par GitLab pour le scan de sécurité seront mis à jour dans la release GitLab 16.0. Les mises à jour incluront les améliorations déjà publiées dans les versions Latest des templates CI/CD. Nous avons publié ces modifications dans les versions Latest des templates car elles sont susceptibles de perturber les configurations de pipeline CI/CD personnalisées.

Dans tous les templates mis à jour, nous mettons à jour la définition de variables telles que `SAST_DISABLED` et `DEPENDENCY_SCANNING_DISABLED` pour désactiver le scan uniquement si la valeur est `"true"`. Auparavant, même si la valeur était `"false"`, le scan était désactivé.

Les templates suivants seront mis à jour :

- Fuzzing d'API : [`API-Fuzzing.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/API-Fuzzing.gitlab-ci.yml)
- Scan de conteneurs : [`Container-Scanning.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Container-Scanning.gitlab-ci.yml)
- Fuzzing guidé par la couverture : [`Coverage-Fuzzing.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/Coverage-Fuzzing.gitlab-ci.yml)
- DAST : [`DAST.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/DAST.gitlab-ci.yml)
- DAST API : [`DAST-API.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/DAST-API.gitlab-ci.yml)
- Analyse des dépendances : [`Dependency-Scanning.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Dependency-Scanning.gitlab-ci.yml)
- Scan IaC : [`SAST-IaC.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/SAST-IaC.gitlab-ci.yml)
- SAST : [`SAST.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml)
- Détection des secrets : [`Secret-Detection.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Secret-Detection.gitlab-ci.yml)

Nous vous recommandons de tester vos pipelines avant la release 16.0 si vous utilisez l'un des templates listés ci-dessus et que vous utilisez les variables `_DISABLED` avec une valeur autre que `"true"`.

**Mettre à jour** : nous avions précédemment annoncé que nous mettrions à jour les `rules` sur les templates concernés pour qu'ils s'exécutent dans des [pipelines de merge request](https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/) par défaut. Cependant, en raison de problèmes de compatibilité [discutés dans le ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/388988#note_1372629948), nous n'apporterons plus cette modification dans GitLab 16.0. Nous publierons tout de même les modifications apportées aux variables `_DISABLED` décrites ci-dessus.

### Schémas de rapport de sécurité version 14.x.x {#security-report-schemas-version-14xx}

- Annoncé dans GitLab 15.3
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/366477).

Les [schémas de rapport de sécurité](https://gitlab.com/gitlab-org/security-products/security-report-schemas) version 14.x.x sont dépréciés.

Dans GitLab 15.8 et les versions ultérieures, les [intégrations de scanners de rapports de sécurité](https://docs.gitlab.com/development/integrations/secure/) utilisant la version de schéma 14.x.x affichent un avertissement de dépréciation dans l'onglet **Sécurité** du pipeline.

Dans GitLab 16.0 et les versions ultérieures, la fonctionnalité sera supprimée. Les rapports de sécurité utilisant la version de schéma 14.x.x provoqueront une erreur dans l'onglet **Sécurité** du pipeline.

Pour plus d'informations, consultez la [validation des rapports de sécurité](https://docs.gitlab.com/user/application_security/#security-report-validation).

### Directive Starboard dans la configuration de l'agent GitLab pour Kubernetes {#starboard-directive-in-the-configuration-of-the-gitlab-agent-for-kubernetes}

- Annoncé dans GitLab 15.4
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/368828).

Les capacités de scan de conteneurs GitLab ne nécessitent plus l'installation de starboard. Par conséquent, l'utilisation de la directive `starboard:` dans le fichier de configuration de l'agent GitLab pour Kubernetes est désormais dépréciée et planifiée pour suppression dans GitLab 16.0. Mettez à jour votre fichier de configuration pour utiliser la directive `container_scanning:`.

### Arrêt de la publication des images GitLab Runner basées sur Windows Server 2004 et 20H2 {#stop-publishing-gitlab-runner-images-based-on-windows-server-2004-and-20h2}

- Annoncé dans GitLab 16.0
- Suppression dans GitLab 16.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/31001).

À partir de GitLab 16.0, les images GitLab Runner basées sur Windows Server 2004 et 20H2 ne seront plus fournies, car ces systèmes d'exploitation ont atteint leur fin de vie.

### Prise en charge de la configuration d'endpoint de métriques personnalisées Praefect {#support-for-praefect-custom-metrics-endpoint-configuration}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/390266).

La prise en charge de l'utilisation de la valeur de configuration `prometheus_exclude_database_from_default_metrics` est dépréciée dans GitLab 15.9 et sera supprimée dans GitLab 16.0. Nous supprimons cette valeur de configuration car son utilisation est non performante. Cette modification signifie que les métriques suivantes ne seront plus disponibles sur `/metrics` :

- `gitaly_praefect_unavailable_repositories`.
- `gitaly_praefect_verification_queue_depth`.
- `gitaly_praefect_replication_queue_depth`.

Cela peut nécessiter la mise à jour de vos cibles de collecte de métriques pour également scraper `/db_metrics`.

### La prise en charge des points (`.`) dans les noms d'états Terraform pourrait rompre les états existants {#support-for-periods--in-terraform-state-names-might-break-existing-states}

- Annoncé dans GitLab 15.7
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/385564).

Auparavant, les noms d'états Terraform contenant des points n'étaient pas pris en charge. Cependant, vous pouviez toujours utiliser des noms d'états avec des points via une solution de contournement.

GitLab 15.7 [ajoute la prise en charge complète](https://docs.gitlab.com/user/infrastructure/iac/troubleshooting/#state-not-found-if-the-state-name-contains-a-period) des noms d'états contenant des points. Si vous avez utilisé une solution de contournement pour gérer ces noms d'états, vos jobs pourraient échouer, ou il pourrait sembler que vous exécutez Terraform pour la première fois.

Pour résoudre le problème :

1. Modifiez toutes les références au fichier d'état en excluant le point et les caractères qui suivent.
   - Par exemple, si votre nom d'état est `state.name`, modifiez toutes les références en `state`.
1. Exécutez vos commandes Terraform.

Pour utiliser le nom d'état complet, y compris le point, [migrez vers le fichier d'état complet](https://docs.gitlab.com/user/infrastructure/iac/terraform_state/#migrate-to-a-gitlab-managed-terraform-state).

### L'API ne renvoie plus les jetons révoqués pour l'agent pour Kubernetes {#the-api-no-longer-returns-revoked-tokens-for-the-agent-for-kubernetes}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/382129).

Actuellement, les requêtes GET vers les endpoints de l'[API Cluster Agents](https://docs.gitlab.com/api/cluster_agents/#list-tokens-for-an-agent) peuvent renvoyer des jetons révoqués. Dans GitLab 16.0, les requêtes GET ne renverront plus de jetons révoqués.

Vous devriez examiner vos appels à ces endpoints et vous assurer que vous n'utilisez pas de jetons révoqués.

Cette modification affecte les endpoints d'API REST et GraphQL suivants :

- API REST :
  - [Lister les jetons](https://docs.gitlab.com/api/cluster_agents/#list-tokens-for-an-agent)
  - [Obtenir un jeton unique](https://docs.gitlab.com/api/cluster_agents/#get-a-single-agent-token)
- GraphQL :
  - [`ClusterAgent.tokens`](https://docs.gitlab.com/api/graphql/reference/#clusteragenttokens)

### L'importateur de tâches Phabricator est déprécié {#the-phabricator-task-importer-is-deprecated}

- Annoncé dans GitLab 15.7
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

L'importateur de tâches Phabricator est en cours de dépréciation. Phabricator lui-même, en tant que projet, n'est plus activement maintenu depuis le 1er juin 2021. Nous n'avons observé aucune importation effectuée avec cet outil. Aucune activité n'a été constatée sur les tickets ouverts associés dans GitLab.

### Les derniers templates Terraform écraseront les templates stables actuels {#the-latest-terraform-templates-will-overwrite-current-stable-templates}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/386001).

À chaque version majeure de GitLab, nous mettons à jour les templates Terraform stables avec les derniers templates disponibles. Ce changement affecte le [template de démarrage rapide](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Terraform.gitlab-ci.yml) et les [templates de base](https://docs.gitlab.com/update/deprecations/#deprecate-terraform-cicd-templates).

Étant donné que les nouveaux templates sont livrés avec des règles par défaut, cette mise à jour pourrait interrompre vos pipelines Terraform. Par exemple, si vos jobs Terraform sont déclenchés en tant que pipeline downstream, les règles ne déclencheront pas vos jobs dans GitLab 16.0.

Pour vous adapter aux changements, vous devrez peut-être ajuster les [`rules`](https://docs.gitlab.com/ci/yaml/#rules) dans votre fichier `.gitlab-ci.yml`.

### Comportement de basculement de l'action rapide `/draft` dans les merge requests {#toggle-behavior-of-draft-quick-action-in-merge-requests}

- Annoncé dans GitLab 15.4
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/365365).

Afin de clarifier le comportement de basculement du statut brouillon d'une merge request via une action rapide, nous déprécions et supprimons le comportement de basculement de l'action rapide `/draft`. À partir de la version 16.0 de GitLab, `/draft` ne pourra que définir une merge request comme brouillon (Draft), et une nouvelle action rapide `/ready` sera utilisée pour supprimer le statut brouillon.

### Utilisation du champ `id` dans la mutation `vulnerabilityFindingDismiss` {#use-of-id-field-in-vulnerabilityfindingdismiss-mutation}

- Annoncé dans GitLab 15.3
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/367166).

Vous pouvez utiliser la mutation GraphQL `vulnerabilityFindingDismiss` pour définir le statut d'un résultat de vulnérabilité sur `Dismissed`. Auparavant, cette mutation utilisait le champ `id` pour identifier les résultats de manière unique. Cependant, cette approche ne fonctionnait pas pour ignorer les résultats depuis l'onglet de sécurité du pipeline. Par conséquent, l'utilisation du champ `id` comme identifiant a été abandonnée au profit du champ `uuid`. L'utilisation du champ 'uuid' comme identifiant vous permet d'ignorer le résultat depuis l'onglet de sécurité du pipeline.

### L'utilisation de registres de conteneurs tiers est dépréciée {#use-of-third-party-container-registries-is-deprecated}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/376216).

L'utilisation de registres de conteneurs tiers avec GitLab en tant que point de terminaison d'authentification est dépréciée dans GitLab 15.8 et la [fin du support](https://docs.gitlab.com/development/deprecation_guidelines/#terminology) est prévue pour GitLab 16.0. Cela concerne les utilisateurs de GitLab Self-Managed qui ont connecté leur registre externe à l'interface utilisateur GitLab pour rechercher, afficher et supprimer des images de conteneurs.

La prise en charge simultanée du registre de conteneurs GitLab et des registres de conteneurs tiers est complexe sur le plan de la maintenance, de la qualité du code et de la compatibilité ascendante, et entrave notre capacité à rester efficaces. En conséquence, nous ne prendrons plus en charge cette fonctionnalité à l'avenir.

Ce changement n'impactera pas votre capacité à récupérer (pull) et envoyer (push) des images de conteneurs vers des registres externes via des pipelines.

Depuis la mise à disposition de la nouvelle version du [registre de conteneurs GitLab](https://gitlab.com/groups/gitlab-org/-/epics/5523) pour GitLab.com, nous avons commencé à implémenter des fonctionnalités supplémentaires qui ne sont pas disponibles dans les registres de conteneurs tiers. Ces nouvelles fonctionnalités nous ont permis d'obtenir des améliorations de performance significatives, comme les [politiques de nettoyage](https://gitlab.com/groups/gitlab-org/-/epics/8379). Nous nous concentrons sur la livraison de [nouvelles fonctionnalités](https://gitlab.com/groups/gitlab-org/-/epics/5136), dont la plupart nécessiteront des capacités uniquement disponibles dans le registre de conteneurs GitLab. Cette dépréciation nous permet de réduire la fragmentation et la frustration des utilisateurs à long terme, en nous concentrant sur la fourniture d'une expérience de registre intégré plus robuste et d'un ensemble de fonctionnalités enrichi.

À l'avenir, nous continuerons à investir dans le développement et la publication de nouvelles fonctionnalités qui seront uniquement disponibles dans le registre de conteneurs GitLab.

### Le chemin des éléments de travail avec l'ID global en fin de chemin est déprécié {#work-items-path-with-global-id-at-the-end-of-the-path-is-deprecated}

- Annoncé dans GitLab 15.10
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/393836).

L'utilisation d'ID globaux dans les URL des éléments de travail est dépréciée. À l'avenir, seuls les ID internes (IID) seront pris en charge.

Comme GitLab prend en charge plusieurs types d'éléments de travail, un chemin tel que `https://gitlab.com/gitlab-org/gitlab/-/work_items/<global_id>` peut afficher, par exemple, une [tâche](https://docs.gitlab.com/user/tasks/) ou un [OKR](https://docs.gitlab.com/user/okrs/).

Dans GitLab 15.10, nous avons ajouté la prise en charge des ID internes (IID) dans ce chemin en ajoutant un paramètre de requête à la fin (`iid_path`) au format suivant : `https://gitlab.com/gitlab-org/gitlab/-/work_items/<iid>?iid_path=true`.

Dans GitLab 16.0, nous supprimerons la possibilité d'utiliser un ID global dans le chemin des éléments de travail. Le nombre en fin de chemin sera considéré comme un ID interne (IID) sans qu'il soit nécessaire d'ajouter un paramètre de requête à la fin. Seul le format suivant sera pris en charge : `https://gitlab.com/gitlab-org/gitlab/-/work_items/<iid>`.

### Variables prédéfinies `CI_BUILD_*` {#ci_build_-predefined-variables}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352957).

Les variables CI/CD prédéfinies commençant par `CI_BUILD_*` ont été dépréciées dans GitLab 9.0 et seront supprimées dans GitLab 16.0. Si vous utilisez encore ces variables, veillez à passer aux [variables prédéfinies](https://docs.gitlab.com/ci/variables/predefined_variables/) de remplacement qui sont fonctionnellement identiques :

| Variable supprimée      | Variable de remplacement    |
| --------------------- |------------------------ |
| `CI_BUILD_BEFORE_SHA` | `CI_COMMIT_BEFORE_SHA`  |
| `CI_BUILD_ID`         | `CI_JOB_ID`             |
| `CI_BUILD_MANUAL`     | `CI_JOB_MANUAL`         |
| `CI_BUILD_NAME`       | `CI_JOB_NAME`           |
| `CI_BUILD_REF`        | `CI_COMMIT_SHA`         |
| `CI_BUILD_REF_NAME`   | `CI_COMMIT_REF_NAME`    |
| `CI_BUILD_REF_SLUG`   | `CI_COMMIT_REF_SLUG`    |
| `CI_BUILD_REPO`       | `CI_REPOSITORY_URL`     |
| `CI_BUILD_STAGE`      | `CI_JOB_STAGE`          |
| `CI_BUILD_TAG`        | `CI_COMMIT_TAG`         |
| `CI_BUILD_TOKEN`      | `CI_JOB_TOKEN`          |
| `CI_BUILD_TRIGGERED`  | `CI_PIPELINE_TRIGGERED` |

### Point de terminaison d'API `POST ci/lint` déprécié {#post-cilint-api-endpoint-deprecated}

- Annoncé dans GitLab 15.7
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/381669).

Le point de terminaison d'API `POST ci/lint` est déprécié dans la version 15.7 et sera supprimé dans la version 16.0. Ce point de terminaison ne valide pas l'ensemble complet des options de configuration CI/CD. Utilisez plutôt [`POST /projects/:id/ci/lint`](https://docs.gitlab.com/api/lint/#validate-a-ci-yaml-configuration-with-a-namespace), qui valide correctement la configuration CI/CD.

### Paramètre `environment_tier` pour l'API DORA {#environment_tier-parameter-for-dora-api}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/365939).

Afin d'éviter toute confusion et duplication, le paramètre `environment_tier` est déprécié au profit du paramètre `environment_tiers`. Le nouveau paramètre `environment_tiers` permet aux API DORA de renvoyer des données agrégées pour plusieurs niveaux simultanément. Le paramètre `environment_tier` sera supprimé dans GitLab 16.0.

### Champ `name` pour le type GraphQL `PipelineSecurityReportFinding` {#name-field-for-pipelinesecurityreportfinding-graphql-type}

- Annoncé dans GitLab 15.1
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/346335).

Précédemment, [le type GraphQL `PipelineSecurityReportFinding` a été mis à jour](https://gitlab.com/gitlab-org/gitlab/-/issues/335372) pour inclure un nouveau champ `title`. Ce champ est un alias du champ actuel `name`, ce qui rend le champ moins spécifique `name` redondant. Le champ `name` sera supprimé du type `PipelineSecurityReportFinding` dans GitLab 16.0.

### État d'itération `started` {#started-iteration-state}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/334018).

L'état d'itération `started` dans l'[API GraphQL des itérations](https://docs.gitlab.com/api/graphql/reference/enums/#iterationstate) et l'[API REST des itérations](https://docs.gitlab.com/api/iterations/#list-project-iterations) est déprécié.

La version API GraphQL sera supprimée dans GitLab 16.0. Cet état est remplacé par l'état `current` (déjà disponible), qui s'aligne avec la nomenclature utilisée pour d'autres entités basées sur le temps, comme les jalons.

Nous prévoyons de continuer à prendre en charge l'état `started` dans la version REST API jusqu'à la prochaine version v5 de l'API REST.

### Mutation GraphQL `vulnerabilityFindingDismiss` {#vulnerabilityfindingdismiss-graphql-mutation}

- Annoncé dans GitLab 15.5
- Suppression dans GitLab 16.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/375645).

La mutation GraphQL `VulnerabilityFindingDismiss` est en cours de dépréciation et sera supprimée dans GitLab 16.0. Cette mutation était peu utilisée car l'ID de résultat de vulnérabilité n'était pas accessible aux utilisateurs (ce champ a été [déprécié en 15.3](https://docs.gitlab.com/update/deprecations/#use-of-id-field-in-vulnerabilityfindingdismiss-mutation)). Les utilisateurs doivent plutôt utiliser `VulnerabilityDismiss` pour ignorer les vulnérabilités dans le rapport de vulnérabilités, ou `SecurityFindingDismiss` pour les résultats de sécurité dans l'onglet Sécurité du pipeline CI.

## GitLab 15.11 {#gitlab-1511}

### Paquets openSUSE Leap 15.3 {#opensuse-leap-153-packages}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 15.11
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7371).

Le support de la distribution et les mises à jour de sécurité pour openSUSE Leap 15.3 [ont pris fin en décembre 2022](https://en.opensuse.org/Lifetime#Discontinued_distributions).

À partir de GitLab 15.7, nous avons commencé à fournir des paquets pour openSUSE Leap 15.4, et nous cesserons de fournir des paquets pour openSUSE Leap 15.3 au jalon 15.11.

- Passez des paquets openSUSE Leap 15.3 aux paquets 15.4 fournis.

## GitLab 15.10 {#gitlab-1510}

### Téléversement automatique de sauvegarde via les API OpenStack Swift et Rackspace {#automatic-backup-upload-using-openstack-swift-and-rackspace-apis}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 15.10 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/387976).

Nous déprécions la prise en charge du **téléversement de sauvegardes vers un stockage distant** à l'aide des API OpenStack Swift et Rackspace. La prise en charge de ces API dépend de bibliothèques tierces qui ne sont plus activement maintenues et n'ont pas été mises à jour pour Ruby 3. GitLab passe à Ruby 3 avant la fin de vie de Ruby 2 afin de rester à jour sur les correctifs de sécurité.

- Si vous utilisez OpenStack, vous devez modifier votre configuration pour utiliser l'API S3 à la place de Swift.
- Si vous utilisez le stockage Rackspace, vous devez passer à un autre fournisseur ou téléverser manuellement le fichier de sauvegarde une fois la tâche de sauvegarde terminée.

## GitLab 15.9 {#gitlab-159}

### L'aperçu en direct (Live Preview) n'est plus disponible dans le Web IDE {#live-preview-no-longer-available-in-the-web-ide}

- Annoncé dans GitLab 15.8
- Suppression dans GitLab 15.9 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/383889).

La fonctionnalité d'aperçu en direct (Live Preview) du Web IDE était destinée à fournir un aperçu côté client d'applications web statiques. Cependant, la complexité des étapes de configuration et un ensemble limité de types de projets pris en charge ont réduit son utilité. Avec l'introduction de la version bêta du Web IDE dans GitLab 15.7, vous pouvez désormais vous connecter à un environnement d'exécution complet côté serveur. Grâce à la prise en charge prochaine de l'installation d'extensions dans le Web IDE, nous prendrons également en charge des workflows plus avancés que ceux disponibles avec l'aperçu en direct. À partir de GitLab 15.9, l'aperçu en direct (Live Preview) n'est plus disponible dans le Web IDE.

### Le gem `omniauth-authentiq` n'est plus disponible {#omniauth-authentiq-gem-no-longer-available}

- Annoncé dans GitLab 15.9
- Suppression dans GitLab 15.9 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/389452).

`omniauth-authentiq` est un gem de stratégie OmniAuth qui faisait partie de GitLab. La société fournissant les services d'authentification, Authentiq, a cessé ses activités. Par conséquent, le gem est en cours de suppression.

## GitLab 15.7 {#gitlab-157}

### Expansion des variables de type File dans `.gitlab-ci.yml` {#file-type-variable-expansion-in-gitlab-ciyml}

- Annoncé dans GitLab 15.5
- Suppression dans GitLab 15.7 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/29407).

Auparavant, les variables qui référençaient ou appliquaient des variables de fichiers alias développaient la valeur de la variable de type `File`. Par exemple, le contenu du fichier. Ce comportement était incorrect, car il ne respectait pas les règles habituelles d'expansion des variables shell. Pour divulguer des secrets ou des informations sensibles stockés dans des variables de type `File`, un utilisateur pouvait exécuter une commande $echo avec la variable comme paramètre d'entrée.

Ce changement majeur corrige ce problème, mais pourrait perturber les workflows des utilisateurs qui contournent ce comportement. Avec ce changement, les expansions de variables de job qui référencent ou appliquent des variables de fichiers alias se développent vers le nom de fichier ou le chemin de la variable de type `File`, au lieu de sa valeur, comme le contenu du fichier.

### Intégration Flowdock {#flowdock-integration}

- Annoncé dans GitLab 15.7
- Suppression dans GitLab 15.7
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/379197).

À compter du 22 décembre 2022, nous supprimons l'intégration Flowdock car le service a été arrêté le 15 août 2022.

## GitLab 15.6 {#gitlab-156}

### NFS pour le stockage des dépôts Git {#nfs-for-git-repository-storage}

- Annoncé dans GitLab 14.0
- Suppression dans GitLab 15.6

Avec la disponibilité générale du cluster Gitaly ([introduit dans GitLab 13.0](https://about.gitlab.com/releases/2020/05/22/gitlab-13-0-released/)), nous avons déprécié le développement (correctifs de bugs, améliorations des performances, etc.) du support NFS pour le stockage des dépôts Git dans GitLab 14.0. Nous continuerons à fournir un support technique pour NFS pour les dépôts Git tout au long de la version 14.x, mais nous supprimerons tout support pour NFS le 22 novembre 2022. Cela était initialement prévu pour le 22 mai 2022, mais afin de permettre une maturité continue du cluster Gitaly, nous avons choisi de prolonger notre date de dépréciation du support. Veuillez consulter notre [déclaration de support](https://about.gitlab.com/support/statement-of-support/#gitaly-and-nfs) officielle pour plus d'informations.

Le cluster Gitaly offre de nombreux avantages à nos clients, tels que :

- [Facteurs de réplication variables](https://docs.gitlab.com/administration/gitaly/#replication-factor).
- [Cohérence forte](https://docs.gitlab.com/administration/gitaly/#strong-consistency).
- [Capacités de lecture distribuées](https://docs.gitlab.com/administration/gitaly/#distributed-reads).

Nous encourageons les clients utilisant actuellement NFS pour les dépôts Git à planifier leur migration en consultant notre documentation sur la [migration vers le cluster Gitaly](https://docs.gitlab.com/administration/gitaly/#migrate-to-gitaly-cluster).

## GitLab 15.4 {#gitlab-154}

### Grafana intégré déprécié {#bundled-grafana-deprecated}

- Annoncé dans GitLab 15.3
- Suppression dans GitLab 15.4
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/6972).

Dans GitLab 15.4, nous remplacerons le Grafana intégré par un fork de Grafana maintenu par GitLab.

Une [CVE identifiée pour Grafana](https://nvd.nist.gov/vuln/detail/CVE-2022-31107) a été découverte, et pour atténuer cette vulnérabilité de sécurité, nous devons passer à notre propre fork car l'ancienne version de Grafana que nous intégrions ne reçoit plus de support à long terme.

Aucune incompatibilité avec la version précédente de Grafana n'est attendue. Ni lors de l'utilisation de notre version intégrée, ni lors de l'utilisation d'une instance externe de Grafana.

### Consolidation des analyseurs SAST et modifications des templates CI/CD {#sast-analyzer-consolidation-and-cicd-template-changes}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.4 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352554).

GitLab SAST utilise divers [analyseurs](https://docs.gitlab.com/user/application_security/sast/analyzers/) pour scanner le code à la recherche de vulnérabilités.

Nous réduisons le nombre d'analyseurs utilisés dans le SAST GitLab dans le cadre de notre stratégie à long terme visant à offrir une expérience utilisateur meilleure et plus cohérente. La rationalisation de l'ensemble des analyseurs permettra également d'accélérer les itérations, d'obtenir de meilleurs résultats et d'améliorer l'efficacité (notamment en réduisant l'utilisation des runners CI dans la plupart des cas).

Dans GitLab 15.4, le SAST GitLab n'utilisera plus les analyseurs suivants :

- [ESLint](https://gitlab.com/gitlab-org/security-products/analyzers/eslint) (JavaScript, TypeScript, React)
- [Gosec](https://gitlab.com/gitlab-org/security-products/analyzers/gosec) (Go)
- [Bandit](https://gitlab.com/gitlab-org/security-products/analyzers/bandit) (Python)

> [!note]
> Ce changement était initialement prévu pour GitLab 15.0 et a été reporté à GitLab 15.4.

Ces analyseurs seront supprimés du [template CI/CD SAST géré par GitLab](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/SAST.gitlab-ci.yml) et remplacés par l'[analyseur basé sur Semgrep](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep). Avec effet immédiat, ils ne recevront que des mises à jour de sécurité ; les autres améliorations ou mises à jour de routine ne sont pas garanties. Une fois que ces analyseurs auront atteint la fin du support, aucune autre mise à jour ne sera fournie. Nous ne supprimerons pas les images de conteneurs précédemment publiées pour ces analyseurs ; tout changement de ce type serait annoncé en tant que dépréciation, suppression ou annonce de changement majeur.

Nous supprimerons également Java du périmètre de l'analyseur [SpotBugs](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs) et le remplacerons par l'[analyseur basé sur Semgrep](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep). Ce changement simplifiera l'analyse du code Java ; la compilation ne sera plus nécessaire. Ce changement sera reflété dans la partie de détection automatique des langages du [template CI/CD SAST géré par GitLab](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/SAST.gitlab-ci.yml). Notez que l'analyseur basé sur SpotBugs continuera à couvrir Groovy, Kotlin et Scala.

Si vous avez déjà ignoré un résultat de vulnérabilité provenant de l'un des analyseurs dépréciés, le remplacement tentera de respecter votre rejet précédent. Le comportement du système dépend de :

- si vous avez exclu l'analyseur basé sur Semgrep de l'exécution dans le passé.
- quel analyseur a découvert en premier les vulnérabilités affichées dans le rapport de vulnérabilités du projet.

Consultez la [documentation sur la traduction des vulnérabilités](https://docs.gitlab.com/user/application_security/sast/analyzers/#vulnerability-translation) pour plus de détails.

Si vous avez appliqué des personnalisations à l'un des analyseurs concernés ou si vous désactivez actuellement l'analyseur Semgrep dans vos pipelines, vous devez prendre les mesures décrites dans le [ticket de dépréciation de ce changement](https://gitlab.com/gitlab-org/gitlab/-/issues/352554#breaking-change).

## GitLab 15.3 {#gitlab-153}

### Tri du rapport de vulnérabilités par état {#vulnerability-report-sort-by-state}

- Annoncé dans GitLab 15.0
- Suppression dans GitLab 15.3
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/360516).

La possibilité de trier le rapport de vulnérabilités par la colonne `State` a été désactivée et placée derrière un feature flag dans GitLab 14.10 en raison d'une refactorisation du modèle de données sous-jacent. Le feature flag est resté désactivé par défaut car une refactorisation supplémentaire sera nécessaire pour garantir que le tri par cette valeur reste performant. En raison d'une utilisation très faible de la colonne `State` pour le tri, le feature flag sera plutôt supprimé afin de simplifier la base de code et d'éviter toute dégradation de performance non souhaitée.

### Tri du rapport de vulnérabilités par outil {#vulnerability-report-sort-by-tool}

- Annoncé dans GitLab 15.1
- Suppression dans GitLab 15.3
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/362962).

La possibilité de trier le rapport de vulnérabilités par la colonne `Tool` (type d'analyse) a été désactivée et placée derrière un feature flag dans GitLab 14.10 en raison d'une refactorisation du modèle de données sous-jacent. Le feature flag est resté désactivé par défaut car une refactorisation supplémentaire sera nécessaire pour garantir que le tri par cette valeur reste performant. En raison d'une utilisation très faible de la colonne `Tool` pour le tri, le feature flag sera supprimé dans GitLab 15.3 afin de simplifier la base de code et d'éviter toute dégradation de performance non souhaitée.

## GitLab 15.1 {#gitlab-151}

### Dépréciation du support de Debian 9 {#deprecate-support-for-debian-9}

- Annoncé dans GitLab 14.9
- Suppression dans GitLab 15.1

Le support à long terme (LTSS) pour [Debian 9 Stretch prend fin en juillet 2022](https://wiki.debian.org/LTS). Par conséquent, nous ne prendrons plus en charge la distribution Debian 9 pour le paquet GitLab. Les utilisateurs peuvent mettre à niveau vers Debian 10 ou Debian 11.

## GitLab 15.0 {#gitlab-150}

### Événements d'audit pour les événements de push dans les dépôts {#audit-events-for-repository-push-events}

- Annoncé dans GitLab 14.3
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/337993).

Les événements d'audit pour les **événements de dépôt** sont désormais dépréciés et seront supprimés dans GitLab 15.0.

Ces événements ont toujours été désactivés par défaut et devaient être activés manuellement à l'aide d'un feature flag. Leur activation peut générer un trop grand nombre d'événements, ce qui peut considérablement ralentir les instances GitLab. Pour cette raison, ils sont supprimés.

### Téléversement en arrière-plan pour le stockage d'objets {#background-upload-for-object-storage}

- Annoncé dans GitLab 14.9
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/26600).

Afin de réduire la complexité globale et la charge de maintenance de la [fonctionnalité de stockage d'objets](https://docs.gitlab.com/administration/object_storage/), la prise en charge de l'utilisation de `background_upload` pour téléverser des fichiers est dépréciée et sera entièrement supprimée dans GitLab 15.0. Consultez les [modifications spécifiques à la version 15.0](https://docs.gitlab.com/omnibus/update/gitlab_15_changes/) concernant les [paramètres de téléversement en arrière-plan supprimés pour le stockage d'objets](https://docs.gitlab.com/omnibus/update/gitlab_15_changes/#removed-background-uploads-settings-for-object-storage).

Cela concerne un sous-ensemble limité de fournisseurs de stockage d'objets :

- **OpenStack** Les clients utilisant OpenStack doivent modifier leur configuration pour utiliser l'API S3 à la place de Swift.
- **RackSpace** Les clients utilisant le stockage d'objets basé sur RackSpace doivent migrer leurs données vers un autre fournisseur.

GitLab publiera des directives supplémentaires pour aider les clients concernés dans leur migration.

### Limite de longueur des noms de jobs CI/CD {#cicd-job-name-length-limit}

- Annoncé dans GitLab 14.6
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/342800).

Dans GitLab 15.0, nous allons limiter le nombre de caractères dans les noms de jobs CI/CD à 255. Tout pipeline dont les noms de jobs dépassent la limite de 255 caractères cessera de fonctionner après la release 15.0.

### Conversion d'un runner d'instance (partagé) en runner de projet (spécifique) {#changing-an-instance-shared-runner-to-a-project-specific-runner}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/345347).

Dans GitLab 15.0, il n'est plus possible de convertir un runner d'instance (partagé) en runner de projet (spécifique).

Les utilisateurs convertissent souvent accidentellement des runners d'instance en runners de projet, et ils ne peuvent pas les reconvertir. GitLab ne permet pas de convertir un runner de projet en runner partagé pour des raisons de sécurité. Un runner destiné à un projet pourrait être configuré pour exécuter des jobs pour l'ensemble d'une instance.

Les administrateurs souhaitant ajouter des runners pour plusieurs projets peuvent enregistrer un runner pour un projet, puis accéder à la vue d'administration et sélectionner des projets supplémentaires.

### Sécurité réseau et hôte des conteneurs {#container-network-and-host-security}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Toutes les fonctionnalités liées aux catégories GitLab Container Network Security et Container Host Security sont dépréciées dans GitLab 14.8 et leur suppression est prévue dans GitLab 15.0. Les utilisateurs ayant besoin d'un remplacement pour cette fonctionnalité sont encouragés à évaluer les projets open source suivants comme solutions potentielles pouvant être installées et gérées en dehors de GitLab : [AppArmor](https://gitlab.com/apparmor/apparmor), [Cilium](https://github.com/cilium/cilium), [Falco](https://github.com/falcosecurity/falco), [FluentD](https://github.com/fluent/fluentd), [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/).

Pour intégrer ces technologies dans GitLab, ajoutez les charts Helm souhaités dans votre copie du [modèle de projet de gestion de cluster](https://docs.gitlab.com/user/clusters/management_project_template/). Déployez ces charts Helm en production en appelant des commandes via GitLab [CI/CD](https://docs.gitlab.com/user/clusters/agent/ci_cd_workflow/).

Dans le cadre de ce changement, les capacités spécifiques suivantes dans GitLab sont désormais dépréciées et leur suppression est prévue dans GitLab 15.0 :

- La page **Sécurité et conformité** > **Surveillance des menaces**.
- Le type de politique de sécurité `Network Policy`, tel qu'il apparaît sur la page **Sécurité et conformité** > **Politiques**.
- La possibilité de gérer les intégrations avec les technologies suivantes via GitLab : AppArmor, Cilium, Falco, FluentD et Pod Security Policies.
- Toutes les API liées aux fonctionnalités mentionnées ci-dessus.

Pour obtenir plus de contexte ou pour formuler des commentaires sur ce changement, veuillez consulter notre [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/epics/7476) ouvert.

### Schémas de scan de conteneurs inférieurs à 14.0.0 {#container-scanning-schemas-below-1400}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0

Les [schémas de rapport de scan de conteneurs](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) dont la version est antérieure à 14.0.0 ne seront plus pris en charge dans GitLab 15.0. Les rapports qui ne passent pas la validation par rapport à la version de schéma déclarée dans le rapport ne seront plus pris en charge non plus dans GitLab 15.0.

Les outils tiers qui [s'intègrent à GitLab en produisant un rapport de sécurité de scan de conteneurs](https://docs.gitlab.com/development/integrations/secure/#report) comme artefact de job de pipeline sont concernés. Vous devez vous assurer que tous les rapports produits respectent le schéma correct avec une version minimale de 14.0.0. Les rapports dont la version est inférieure ou qui échouent à la validation par rapport à la version de schéma déclarée ne seront pas traités, et les résultats de vulnérabilités ne s'afficheront pas dans les MR, les pipelines ou les rapports de vulnérabilités.

Pour faciliter la transition, à partir de GitLab 14.10, les rapports non conformes afficheront un [avertissement](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791) dans le rapport de vulnérabilités.

### Schémas de fuzzing guidé par couverture inférieurs à 14.0.0 {#coverage-guided-fuzzing-schemas-below-1400}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0

Les [schémas de rapport de fuzzing guidé par couverture](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) dont la version est inférieure à 14.0.0 ne seront plus pris en charge dans GitLab 15.0. Les rapports qui ne passent pas la validation par rapport à la version de schéma déclarée dans le rapport ne seront plus pris en charge non plus dans GitLab 15.0.

Les outils tiers qui [s'intègrent à GitLab en produisant un rapport de sécurité de fuzzing guidé par couverture](https://docs.gitlab.com/development/integrations/secure/#report) comme artefact de job de pipeline sont concernés. Vous devez vous assurer que tous les rapports produits respectent le schéma correct avec une version minimale de 14.0.0. Tout rapport dont la version est inférieure ou qui échoue à la validation par rapport à la version de schéma déclarée ne sera pas traité, et les résultats de vulnérabilités ne s'afficheront pas dans les MR, les pipelines ou les rapports de vulnérabilités.

Pour faciliter la transition, à partir de GitLab 14.10, les rapports non conformes afficheront un [avertissement](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791) dans le rapport de vulnérabilités.

### Schémas DAST inférieurs à 14.0.0 {#dast-schemas-below-1400}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0

Les [schémas de rapport DAST](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) dont la version est antérieure à 14.0.0 ne seront plus pris en charge dans GitLab 15.0. Les rapports qui ne passent pas la validation par rapport à la version de schéma déclarée dans le rapport ne seront plus pris en charge à partir de GitLab 15.0.

Les outils tiers qui [s'intègrent à GitLab en produisant un rapport de sécurité DAST](https://docs.gitlab.com/development/integrations/secure/#report) comme artefact de job de pipeline sont concernés. Vous devez vous assurer que tous les rapports produits respectent le schéma correct avec une version minimale de 14.0.0. Les rapports dont la version est inférieure ou qui échouent à la validation par rapport à la version de schéma déclarée ne seront pas traités, et les résultats de vulnérabilités ne s'afficheront pas dans les MR, les pipelines ou les rapports de vulnérabilités.

Pour faciliter la transition, à partir de GitLab 14.10, les rapports non conformes provoqueront l'[affichage d'un avertissement](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791) dans le rapport de vulnérabilités.

### Dépréciation des images Python 3.9 et 3.6 pour l'analyse des dépendances {#dependency-scanning-python-39-and-36-image-deprecation}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/334060).

Pour les utilisateurs qui se servent de l'analyse des dépendances pour des projets Python, nous déprécions l'image par défaut `gemnasium-python:2` qui utilise Python 3.6, ainsi que l'image personnalisée `gemnasium-python:2-python-3.9` qui utilise Python 3.9. La nouvelle image par défaut à partir de GitLab 15.0 sera pour Python 3.9, car c'est une [version prise en charge](https://endoflife.date/python) et 3.6 [n'est plus prise en charge](https://endoflife.date/python).

Pour les utilisateurs de Python 3.9 ou de projets compatibles avec Python 3.9, vous ne devriez pas avoir à effectuer d'action et l'analyse des dépendances devrait commencer à fonctionner dans GitLab 15.0. Si vous souhaitez tester le nouveau conteneur dès maintenant, exécutez un pipeline de test dans votre projet avec ce conteneur (qui sera supprimé dans la version 15.0). Utilisez l'image Python 3.9 :

```yaml
gemnasium-python-dependency_scanning:
  image:
    name: registry.gitlab.com/gitlab-org/security-products/analyzers/gemnasium-python:2-python-3.9
```

Pour les utilisateurs de Python 3.6, à partir de GitLab 15.0, vous ne pourrez plus utiliser le template par défaut pour l'analyse des dépendances. Vous devrez passer à l'utilisation de l'image d'analyseur dépréciée `gemnasium-python:2`. Si vous êtes concerné par ce changement, veuillez commenter [ce ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/351503) afin que nous puissions prolonger la suppression si nécessaire.

Pour les utilisateurs utilisant l'image d'exception spéciale 3.9, vous devez à la place utiliser la valeur par défaut et ne plus surcharger votre conteneur. Pour vérifier si vous utilisez l'image d'exception spéciale 3.9, recherchez la référence suivante dans votre fichier `.gitlab-ci.yml` :

```yaml
gemnasium-python-dependency_scanning:
  image:
    name: registry.gitlab.com/gitlab-org/security-products/analyzers/gemnasium-python:2-python-3.9
```

### La version Java par défaut pour l'analyse des dépendances est passée à 17 {#dependency-scanning-default-java-version-changed-to-17}

- Annoncé dans GitLab 14.10
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Dans GitLab 15.0, pour l'analyse des dépendances, la version Java par défaut attendue par le scanner sera mise à jour de la version 11 à la version 17. Java 17 est [la version LTS (Long Term Support) la plus récente](https://en.wikipedia.org/wiki/Java_version_history). L'analyse des dépendances continue de prendre en charge la même [plage de versions (8, 11, 13, 14, 15, 16, 17)](https://docs.gitlab.com/user/application_security/dependency_scanning/#supported-languages-and-package-managers), seule la version par défaut est modifiée. Si votre projet utilise la version par défaut précédente Java 11, veillez à [définir la variable `DS_Java_Version` en conséquence](https://docs.gitlab.com/user/application_security/dependency_scanning/#configuring-specific-analyzers-used-by-dependency-scanning).

### Schémas d'analyse des dépendances inférieurs à 14.0.0 {#dependency-scanning-schemas-below-1400}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0

Les [schémas de rapport d'analyse des dépendances](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) dont la version est antérieure à 14.0.0 ne seront plus pris en charge dans GitLab 15.0. Les rapports qui ne passent pas la validation par rapport à la version de schéma déclarée dans le rapport ne seront plus pris en charge à partir de GitLab 15.0.

Les outils tiers qui [s'intègrent à GitLab en produisant un rapport de sécurité d'analyse des dépendances](https://docs.gitlab.com/development/integrations/secure/#report) comme artefact de job de pipeline sont concernés. Vous devez vous assurer que tous les rapports produits respectent le schéma correct avec une version minimale de 14.0.0. Les rapports dont la version est inférieure ou qui échouent à la validation par rapport à la version de schéma déclarée ne seront pas traités, et les résultats de vulnérabilités ne s'afficheront pas dans les MR, les pipelines ou les rapports de vulnérabilités.

Pour faciliter la transition, à partir de GitLab 14.10, les rapports non conformes provoqueront l'[affichage d'un avertissement](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791) dans le rapport de vulnérabilités.

### Dépréciation des routes de l'interface d'administration Geo {#deprecate-geo-admin-ui-routes}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/351345).

Dans GitLab 13.0, nous avons introduit de nouvelles routes pour les détails de réplication des projets et des designs dans l'interface d'administration Geo. Ces routes sont `/admin/geo/replication/projects` et `/admin/geo/replication/designs`. Nous avons conservé les routes héritées et les avons redirigées vers les nouvelles routes. Dans GitLab 15.0, nous supprimerons la prise en charge des routes héritées `/admin/geo/projects` et `/admin/geo/designs`. Veuillez mettre à jour tous les favoris ou scripts susceptibles d'utiliser les routes héritées.

### Dépréciation des tâches Rake Geo:db:\* personnalisées {#deprecate-custom-geodb-rake-tasks}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/351945).

Dans GitLab 14.8, nous [remplaçons les tâches Rake `geo:db:*` par des tâches intégrées](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/77269/diffs) rendues possibles après le [passage de la base de données de suivi Geo à l'utilisation du support des bases de données multiples de Rails 6](https://gitlab.com/groups/gitlab-org/-/epics/6458). Les tâches `geo:db:*` suivantes seront remplacées par leurs tâches `db:*:geo` correspondantes :

- `geo:db:drop` -> `db:drop:geo`
- `geo:db:create` -> `db:create:geo`
- `geo:db:setup` -> `db:setup:geo`
- `geo:db:migrate` -> `db:migrate:geo`
- `geo:db:rollback` -> `db:rollback:geo`
- `geo:db:version` -> `db:version:geo`
- `geo:db:reset` -> `db:reset:geo`
- `geo:db:seed` -> `db:seed:geo`
- `geo:schema:load:geo` -> `db:schema:load:geo`
- `geo:db:schema:dump` -> `db:schema:dump:geo`
- `geo:db:migrate:up` -> `db:migrate:up:geo`
- `geo:db:migrate:down` -> `db:migrate:down:geo`
- `geo:db:migrate:redo` -> `db:migrate:redo:geo`
- `geo:db:migrate:status` -> `db:migrate:status:geo`
- `geo:db:test:prepare` -> `db:test:prepare:geo`
- `geo:db:test:load` -> `db:test:load:geo`
- `geo:db:test:purge` -> `db:test:purge:geo`

### Dépréciation du feature flag PUSH_RULES_SUPERSEDE_CODE_OWNERS {#deprecate-feature-flag-push_rules_supersede_code_owners}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/262019).

Le feature flag `PUSH_RULES_SUPERSEDE_CODE_OWNERS` est supprimé dans GitLab 15.0. Lors de sa suppression, les règles de push prendront la priorité sur les propriétaires du code. Même si l'approbation du propriétaire du code est requise, une règle de push autorisant explicitement un utilisateur spécifique à pousser du code prend la priorité sur le paramètre des propriétaires du code.

### Elasticsearch 6.8 {#elasticsearch-68}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/350275).

Elasticsearch 6.8 est déprécié dans GitLab 14.8 et sa suppression est prévue dans GitLab 15.0. Les clients utilisant Elasticsearch 6.8 doivent mettre à niveau leur version d'Elasticsearch vers la version 7.x avant de mettre à niveau vers GitLab 15.0. Nous recommandons d'utiliser la dernière version d'Elasticsearch 7 pour bénéficier de toutes les améliorations d'Elasticsearch.

Elasticsearch 6.8 est également incompatible avec Amazon OpenSearch, dont nous [prévoyons d'assurer le support dans GitLab 15.0](https://gitlab.com/gitlab-org/gitlab/-/issues/327560).

### Validation forcée des schémas de rapports de sécurité {#enforced-validation-of-security-report-schemas}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/-/epics/6968).

Les [schémas de rapports de sécurité](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) dont la version est antérieure à 14.0.0 ne seront plus pris en charge dans GitLab 15.0. Les rapports qui ne passent pas la validation par rapport à la version de schéma déclarée dans le rapport ne seront plus pris en charge non plus dans GitLab 15.0.

Les outils de sécurité qui [s'intègrent à GitLab en produisant des rapports de sécurité](https://docs.gitlab.com/development/integrations/secure/#report) comme artefacts de job de pipeline sont concernés. Vous devez vous assurer que tous les rapports produits respectent le schéma correct avec une version minimale de 14.0.0. Les rapports dont la version est inférieure ou qui échouent à la validation par rapport à la version de schéma déclarée ne seront pas traités, et les résultats de vulnérabilités ne s'afficheront pas dans les MR, les pipelines ou les rapports de vulnérabilités.

Pour faciliter la transition, à partir de GitLab 14.10, les rapports non conformes afficheront un [avertissement](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791) dans le rapport de vulnérabilités.

### Modifications majeures de l'API de vérification du statut externe {#external-status-check-api-breaking-changes}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

L'[API de vérification du statut externe](https://docs.gitlab.com/api/status_checks/) a été initialement mise en œuvre pour prendre en charge les requêtes passant par défaut afin de marquer une vérification de statut comme réussie. Les requêtes passant par défaut sont désormais dépréciées. Plus précisément, les éléments suivants sont dépréciés :

- Les requêtes ne contenant pas le champ `status`.
- Les requêtes dont le champ `status` est défini sur `approved`.

À partir de GitLab 15.0, les vérifications de statut ne seront mises à jour vers un état réussi que si le champ `status` est à la fois présent et défini sur `passed`. Les requêtes qui :

- Ne contiennent pas le champ `status` seront rejetées avec une erreur `422`. Pour plus d'informations, consultez [le ticket concerné](https://gitlab.com/gitlab-org/gitlab/-/issues/338827).
- Contiennent toute valeur autre que `passed` entraîneront l'échec de la vérification de statut. Pour plus d'informations, consultez [le ticket concerné](https://gitlab.com/gitlab-org/gitlab/-/issues/339039).

Pour s'aligner sur ce changement, les appels d'API permettant de lister les vérifications de statut externes renverront également la valeur `passed` plutôt que `approved` pour les vérifications de statut ayant réussi.

### GitLab Pages s'exécutant comme démon {#gitlab-pages-running-as-daemon}

- Annoncé dans GitLab 14.9
- Suppression dans GitLab 15.0

Dans la version 15.0, la prise en charge du mode démon pour GitLab Pages sera supprimée.

### GitLab Serverless {#gitlab-serverless}

- Annoncé dans GitLab 14.3
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/configure/-/epics/6).

GitLab Serverless est un ensemble de fonctionnalités destiné à prendre en charge le développement serverless basé sur Knative avec des déploiements automatiques et une supervision.

Nous avons décidé de supprimer les fonctionnalités GitLab Serverless car elles n'ont jamais vraiment répondu aux attentes de nos utilisateurs. De plus, compte tenu du développement continu de Kubernetes et de Knative, nos implémentations actuelles ne fonctionnent même pas avec les versions récentes.

### Support de Godep dans la vérification de conformité des licences {#godep-support-in-license-compliance}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/327057).

Le gestionnaire de dépendances Godep pour Go a été déprécié en 2020 par Go et remplacé par les modules Go. Afin de réduire nos coûts de maintenance, nous déprécions la vérification de conformité des licences pour les projets Godep à partir de la version 14.7 et la supprimerons dans GitLab 15.0.

### Compatibilité GraphQL ID et GlobalID {#graphql-id-and-globalid-compatibility}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/257883).

Nous supprimons une extension non standard de notre processeur GraphQL, que nous avions ajoutée pour la compatibilité ascendante. Cette extension modifie la validation des requêtes GraphQL, permettant l'utilisation du type `ID` pour des arguments où il serait normalement rejeté. Certains arguments avaient initialement le type `ID`. Ils ont été modifiés en types spécifiques de `ID`. Ce changement peut constituer un changement majeur si vous :

- Utilisez GraphQL.
- Utilisez le type `ID` pour un argument dans vos signatures de requête.

Certains arguments de champ conservent encore le type `ID`. Il s'agit généralement de valeurs IID ou de chemins d'espace de nommage. Un exemple est `Query.project(fullPath: ID!)`.

Pour obtenir la liste des arguments de champ concernés et non concernés, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352832).

Vous pouvez tester si ce changement vous affecte en validant vos requêtes localement, à l'aide des données de schéma récupérées depuis un serveur GitLab. Vous pouvez le faire en utilisant l'outil d'exploration GraphQL pour l'instance GitLab concernée. Par exemple : `https://gitlab.com/-/graphql-explorer`.

Par exemple, la requête suivante illustre le changement majeur :

```graphql
# a query using the deprecated type of Query.issue(id:)
# WARNING: This will not work after GitLab 15.0
query($id: ID!) {
  deprecated: issue(id: $id) {
    title, description
  }
}
```

La requête ci-dessus ne fonctionnera plus après la sortie de GitLab 15.0, car le type de `Query.issue(id:)` est en réalité `IssueID!`.

Utilisez plutôt l'une des deux formes suivantes :

```graphql
# This will continue to work
query($id: IssueID!) {
  a: issue(id: $id) {
    title, description
  }
  b: issue(id: "gid://gitlab/Issue/12345") {
    title, description
  }
}
```

Cette requête fonctionne actuellement et continuera de fonctionner après GitLab 15.0. Vous devriez convertir toutes les requêtes dans la première forme (utilisant `ID` comme type nommé dans la signature) vers l'une des deux autres formes (en utilisant le type approprié dans la signature, ou en utilisant une expression d'argument inline).

### Modification des permissions GraphQL pour les paramètres de paquets {#graphql-permissions-change-for-package-settings}

- Annoncé dans GitLab 14.9
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

La phase Packages de GitLab propose un registre de paquets, un registre de conteneurs et un proxy de dépendances pour vous aider à gérer toutes vos dépendances dans GitLab. Chacune de ces catégories de produits dispose de divers paramètres pouvant être ajustés via l'API.

Le modèle de permissions pour GraphQL est en cours de mise à jour. Après la version 15.0, les utilisateurs ayant le rôle Invité, Rapporteur ou Développeur ne pourront plus mettre à jour ces paramètres :

- [Paramètres du registre de paquets](https://docs.gitlab.com/api/graphql/reference/objects/#packagesettings)
- [Politique de nettoyage du registre de conteneurs](https://docs.gitlab.com/api/graphql/reference/objects/#containerexpirationpolicy)
- [Politique de durée de vie du proxy de dépendances](https://docs.gitlab.com/api/graphql/reference/objects/#dependencyproxyimagettlgrouppolicy)
- [Activation du proxy de dépendances pour votre groupe](https://docs.gitlab.com/api/graphql/reference/objects/#dependencyproxysetting)

### Hôte connu requis pour l'exécuteur SSH de GitLab Runner {#known-host-required-for-gitlab-runner-ssh-executor}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/28192).

Dans [GitLab 14.3](https://gitlab.com/gitlab-org/gitlab-runner/-/merge_requests/3074), nous avons ajouté un paramètre de configuration dans le fichier `config.toml` de GitLab Runner. Ce paramètre, [`[runners.ssh.disable_strict_host_key_checking]`](https://docs.gitlab.com/runner/executors/ssh/#security), contrôle si la vérification stricte de la clé d'hôte doit être utilisée ou non avec l'exécuteur SSH.

Dans GitLab 15.0 et versions ultérieures, la valeur par défaut de cette option de configuration passera de `true` à `false`. Cela signifie que la vérification stricte de la clé d'hôte sera appliquée lors de l'utilisation de l'exécuteur SSH de GitLab Runner.

### Noms de statut d'approbation hérités de l'API de conformité des licences {#legacy-approval-status-names-from-license-compliance-api}

- Annoncé dans GitLab 14.6
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/335707).

Nous avons déprécié les anciens noms de statut d'approbation de la politique de licences (`blacklisted`, `approved`) dans l'API `managed_licenses`, mais ils sont encore utilisés dans nos requêtes et réponses API. Ils seront supprimés dans la version 15.0.

Si vous utilisez notre API de conformité des licences, vous devez cesser d'utiliser les paramètres de requête `approved` et `blacklisted` ; ils sont désormais `allowed` et `denied`. Dans la version 15.0, les réponses cesseront également d'utiliser `approved` et `blacklisted`, vous devez donc adapter vos outils personnalisés pour utiliser les anciennes et nouvelles valeurs afin qu'ils ne soient pas interrompus lors de la release 15.0.

### Configuration de base de données héritée {#legacy-database-configuration}

- Annoncé dans GitLab 14.3
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/338182).

La syntaxe de [la configuration de base de données de GitLab](https://docs.gitlab.com/omnibus/settings/database/) située dans `database.yml` est en cours de modification et le format hérité est déprécié. Le format hérité prenait en charge l'utilisation d'un seul adaptateur PostgreSQL, tandis que le nouveau format évolue pour prendre en charge plusieurs bases de données. La base de données `main:` doit être définie comme premier élément de configuration.

Cette dépréciation concerne principalement les utilisateurs qui compilent GitLab depuis les sources, car Omnibus gérera cette configuration automatiquement.

### Journalisation dans GitLab {#logging-in-gitlab}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/346485).

Les fonctionnalités de journalisation de GitLab permettent aux utilisateurs d'installer la pile ELK (Elasticsearch, Logstash et Kibana) pour agréger et gérer les journaux d'application. Les utilisateurs peuvent rechercher des journaux pertinents dans GitLab. Cependant, depuis la dépréciation de l'intégration basée sur des certificats avec les clusters Kubernetes et les applications gérées par GitLab, nous ne disposons pas de solution recommandée pour la journalisation dans GitLab. Pour plus d'informations, vous pouvez suivre le ticket relatif à l'[intégration d'Opstrace avec GitLab](https://gitlab.com/groups/gitlab-org/-/epics/6976).

### Déplacement du paramètre `custom_hooks_dir` de GitLab Shell vers Gitaly {#move-custom_hooks_dir-setting-from-gitlab-shell-to-gitaly}

- Annoncé dans GitLab 14.9
- Suppression dans GitLab 15.0

Le paramètre [`custom_hooks_dir`](https://docs.gitlab.com/administration/server_hooks/#create-a-global-server-hook-for-all-repositories) est désormais configuré dans Gitaly et sera supprimé de GitLab Shell dans GitLab 15.0.

### Octroi implicite OAuth {#oauth-implicit-grant}

- Annoncé dans GitLab 14.0
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Le flux d'autorisation par octroi implicite OAuth sera supprimé dans notre prochaine version majeure, GitLab 15.0. Les applications utilisant l'octroi implicite OAuth doivent passer aux [flux OAuth pris en charge](https://docs.gitlab.com/api/oauth2/) alternatifs.

### Jetons OAuth sans expiration {#oauth-tokens-without-expiration}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Par défaut, toutes les nouvelles applications font expirer les jetons d'accès après 2 heures. Dans GitLab 14.2 et versions antérieures, les jetons d'accès OAuth n'avaient pas de date d'expiration. Dans GitLab 15.0, une date d'expiration sera automatiquement générée pour tout jeton existant qui n'en possède pas déjà une.

Vous devriez [activer](https://docs.gitlab.com/integration/oauth_provider/#access-token-expiration) l'expiration des jetons avant la sortie de GitLab 15.0 :

1. Modifiez l'application.
1. Sélectionnez **Expirer les jetons d'accès** pour les activer. Les jetons doivent être révoqués, sinon ils n'expirent pas.

### Gem OmniAuth Kerberos {#omniauth-kerberos-gem}

- Annoncé dans GitLab 14.3
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/337384).

Le gem `omniauth-kerberos` sera supprimé dans notre prochaine version majeure, GitLab 15.0.

Ce gem n'est plus maintenu et son utilisation est très limitée. Nous prévoyons donc de supprimer la prise en charge de cette méthode d'authentification et recommandons d'utiliser à la place l'intégration Kerberos [SPNEGO](https://en.wikipedia.org/wiki/SPNEGO). Vous pouvez suivre les [instructions de mise à niveau](https://docs.gitlab.com/integration/kerberos/#upgrading-from-password-based-to-ticket-based-kerberos-sign-ins) pour passer de l'intégration `omniauth-kerberos` à l'intégration prise en charge.

Notez que nous ne déprécions pas l'intégration Kerberos SPNEGO, uniquement l'ancienne intégration Kerberos basée sur les mots de passe.

### Application optionnelle de l'expiration des jetons d'accès personnels {#optional-enforcement-of-pat-expiration}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/351962).

La fonctionnalité permettant de désactiver l'application de l'expiration des jetons d'accès personnels est inhabituelle du point de vue de la sécurité. Nous craignons que cette fonctionnalité inhabituelle puisse créer un comportement inattendu pour les utilisateurs. Un comportement inattendu dans une fonctionnalité de sécurité est intrinsèquement dangereux, c'est pourquoi nous avons décidé de supprimer cette fonctionnalité.

### Application optionnelle de l'expiration SSH {#optional-enforcement-of-ssh-expiration}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/351963).

La fonctionnalité permettant de désactiver l'application de l'expiration SSH est inhabituelle du point de vue de la sécurité. Nous craignons que cette fonctionnalité inhabituelle puisse créer un comportement inattendu pour les utilisateurs. Un comportement inattendu dans une fonctionnalité de sécurité est intrinsèquement dangereux, c'est pourquoi nous avons décidé de supprimer cette fonctionnalité.

### Prise en charge SAST prête à l'emploi pour Java 8 {#out-of-the-box-sast-support-for-java-8}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352549).

L'[analyseur GitLab SAST SpotBugs](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs) analyse le [code Java, Scala, Groovy et Kotlin](https://docs.gitlab.com/user/application_security/sast/#supported-languages-and-frameworks) à la recherche de vulnérabilités de sécurité. Pour des raisons techniques, l'analyseur doit d'abord compiler le code avant de procéder à l'analyse. Sauf si vous utilisez la [stratégie de pré-compilation](https://docs.gitlab.com/user/application_security/sast/#pre-compilation), l'analyseur tente de compiler automatiquement le code de votre projet.

Dans les versions de GitLab antérieures à 15.0, l'image de l'analyseur inclut les environnements d'exécution Java 8 et Java 11 pour faciliter la compilation.

Dans GitLab 15.0, nous allons :

- Supprimer Java 8 de l'image de l'analyseur afin de réduire la taille de l'image.
- Ajouter Java 17 à l'image de l'analyseur pour faciliter la compilation avec Java 17.

Si vous dépendez de la présence de Java 8 dans l'environnement de l'analyseur, vous devez prendre les mesures décrites dans le [ticket de dépréciation relatif à ce changement](https://gitlab.com/gitlab-org/gitlab/-/issues/352549#breaking-change).

### Index obsolètes des migrations de recherche avancée {#outdated-indices-of-advanced-search-migrations}

- Annoncé dans GitLab 14.10
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/359133).

Les migrations de recherche avancée nécessitant généralement la prise en charge de plusieurs chemins de code pendant une longue période, il est important de les nettoyer dès que cela est possible en toute sécurité. Nous utilisons les mises à niveau de version majeure de GitLab comme moment opportun pour supprimer la rétrocompatibilité des index qui n'ont pas été entièrement migrés. Consultez la [documentation de mise à niveau](https://docs.gitlab.com/update/#upgrading-to-a-new-major-version) pour plus de détails.

### Pseudonymiseur {#pseudonymizer}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/219952).

La fonctionnalité Pseudonymizer est généralement inutilisée, peut provoquer des problèmes de production avec les grandes bases de données et peut interférer avec le développement de l'object storage. Elle est désormais considérée comme dépréciée et sera supprimée dans GitLab 15.0.

### Interrogation des tendances d'utilisation via le nœud GraphQL `instanceStatisticsMeasurements` {#querying-usage-trends-via-the-instancestatisticsmeasurements-graphql-node}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/332323).

Le nœud GraphQL `instanceStatisticsMeasurements` a été renommé en `usageTrendsMeasurements` dans la version 13.10 et l'ancien nom de champ a été marqué comme déprécié. Pour corriger les requêtes GraphQL existantes, remplacez `instanceStatisticsMeasurements` par `usageTrendsMeasurements`.

### Profilage des requêtes {#request-profiling}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352488).

Le [profilage des requêtes](https://docs.gitlab.com/administration/monitoring/performance/) est déprécié dans GitLab 14.8 et sa suppression est prévue dans GitLab 15.0.

Nous travaillons à [consolider nos outils de profilage](https://gitlab.com/groups/gitlab-org/-/epics/7327) et à les rendre plus facilement accessibles. Nous avons [évalué](https://gitlab.com/gitlab-org/gitlab/-/issues/350152) l'utilisation de cette fonctionnalité et avons constaté qu'elle n'est pas largement utilisée. Elle dépend également de quelques gems tiers qui ne sont plus activement maintenus, n'ont pas été mis à jour pour la dernière version de Ruby, ou plantent fréquemment lors du profilage de pages à charge élevée.

Pour plus d'informations, consultez la [section récapitulative du ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352488#deprecation-summary).

### Configurations de pipeline requises dans l'édition Premium {#required-pipeline-configurations-in-premium-tier}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

La fonctionnalité de [configuration de pipeline requise](https://docs.gitlab.com/administration/settings/continuous_integration/#required-pipeline-configuration-deprecated) est dépréciée dans GitLab 14.8 pour les clients Premium et sa suppression est prévue dans GitLab 15.0. Cette fonctionnalité n'est pas dépréciée pour les clients GitLab Ultimate.

Ce changement visant à déplacer la fonctionnalité vers l'édition GitLab Ultimate est destiné à mieux aligner nos fonctionnalités avec notre philosophie de tarification, car nous constatons que la demande pour cette fonctionnalité provient principalement de cadres dirigeants.

Ce changement contribuera également à maintenir la cohérence de GitLab dans sa stratégie de niveaux avec les autres fonctionnalités Ultimate connexes : [Politiques de sécurité](https://docs.gitlab.com/user/application_security/policies/) et [pipelines de cadre de conformité](https://docs.gitlab.com/user/project/settings/#compliance-pipeline-configuration).

### Outil d'analyse des dépendances Retire-JS {#retire-js-dependency-scanning-tool}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/350510).

Depuis la version 14.8, le job retire.js est déprécié de l'analyse des dépendances. Il continuera à être inclus dans notre template CI/CD pendant la période de dépréciation. Nous supprimons retire.js de l'analyse des dépendances le 22 mai 2022 dans GitLab 15.0. La fonctionnalité d'analyse JavaScript ne sera pas affectée car elle est toujours couverte par Gemnasium.

Si vous avez explicitement exclu retire.js via DS_EXCLUDED_ANALYZERS, vous devrez nettoyer (supprimer la référence) dans la version 15.0. Si vous avez personnalisé la configuration d'analyse des dépendances de votre pipeline en lien avec le job `retire-js-dependency_scanning`, vous devrez passer à gemnasium-dependency_scanning avant la suppression dans la version 15.0, afin d'éviter que votre pipeline ne soit en échec. Si vous n'avez pas utilisé DS_EXCLUDED_ANALYZERS pour référencer retire.js, et que vous n'avez pas personnalisé votre template spécifiquement pour retire.js, vous n'aurez aucune action à entreprendre.

### Schémas SAST inférieurs à 14.0.0 {#sast-schemas-below-1400}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0

Les [schémas de rapport SAST](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) dont la version est antérieure à 14.0.0 ne seront plus pris en charge dans GitLab 15.0. Les rapports qui ne passent pas la validation par rapport à la version de schéma déclarée dans le rapport ne seront plus pris en charge à partir de GitLab 15.0.

Les outils tiers qui [s'intègrent à GitLab en produisant un rapport de sécurité SAST](https://docs.gitlab.com/development/integrations/secure/#report) comme artefact de job de pipeline sont concernés. Vous devez vous assurer que tous les rapports produits respectent le schéma correct avec une version minimale de 14.0.0. Les rapports dont la version est inférieure ou qui échouent à la validation par rapport à la version de schéma déclarée ne seront pas traités, et les résultats de vulnérabilités ne s'afficheront pas dans les MR, les pipelines ou les rapports de vulnérabilités.

Pour faciliter la transition, à partir de GitLab 14.10, les rapports non conformes afficheront un [avertissement](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791) dans le rapport de vulnérabilités.

### Prise en charge SAST pour .NET 2.1 {#sast-support-for-net-21}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352553).

L'analyseur GitLab SAST Security Code Scan analyse le code .NET à la recherche de vulnérabilités de sécurité. Pour des raisons techniques, l'analyseur doit d'abord compiler le code pour l'analyser.

Dans les versions de GitLab antérieures à 15.0, l'image d'analyseur par défaut (version 2) inclut la prise en charge de :

- .NET 2.1
- .NET 3.0 et .NET Core 3.0
- .NET Core 3.1
- .NET 5.0

Dans GitLab 15.0, nous allons changer la version majeure par défaut de cet analyseur de la version 2 à la version 3. Ce changement :

- Ajoute des [valeurs de gravité pour les vulnérabilités](https://gitlab.com/gitlab-org/gitlab/-/issues/350408) ainsi que d'[autres nouvelles fonctionnalités et améliorations](https://gitlab.com/gitlab-org/security-products/analyzers/security-code-scan/-/blob/master/CHANGELOG.md).
- Supprime la prise en charge de .NET 2.1.
- Ajoute la prise en charge de .NET 6.0, Visual Studio 2019 et Visual Studio 2022.

La version 3 a été [annoncée dans GitLab 14.6](https://about.gitlab.com/releases/2021/12/22/gitlab-14-6-released/#sast-support-for-net-6) et rendue disponible en tant que mise à niveau optionnelle.

Si vous dépendez de la présence par défaut de la prise en charge de .NET 2.1 dans l'image de l'analyseur, vous devez prendre les mesures décrites dans le [ticket de dépréciation relatif à ce changement](https://gitlab.com/gitlab-org/gitlab/-/issues/352553#breaking-change).

### Variables de configuration de la détection des secrets dépréciées {#secret-detection-configuration-variables-deprecated}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352565).

Pour simplifier et fiabiliser la [personnalisation de la détection des secrets GitLab](https://docs.gitlab.com/user/application_security/secret_detection/#customizing-settings), nous déprécions certaines des variables que vous pouviez auparavant définir dans votre configuration CI/CD.

Les variables suivantes vous permettent actuellement de personnaliser les options d'analyse historique, mais interagissent mal avec le [template CI/CD géré par GitLab](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/Secret-Detection.gitlab-ci.yml) et sont désormais dépréciées :

- `SECRET_DETECTION_COMMIT_FROM`
- `SECRET_DETECTION_COMMIT_TO`
- `SECRET_DETECTION_COMMITS`
- `SECRET_DETECTION_COMMITS_FILE`

La variable `SECRET_DETECTION_ENTROPY_LEVEL` vous permettait auparavant de configurer des règles qui ne tenaient compte que du niveau d'entropie des chaînes dans votre base de code, et est désormais dépréciée. Ce type de règle basée uniquement sur l'entropie générait un nombre inacceptable de résultats incorrects (faux positifs) et n'est plus pris en charge.

Dans GitLab 15.0, nous mettrons à jour l'[analyseur](https://docs.gitlab.com/user/application_security/terminology/#analyzer) de détection des secrets pour ignorer ces options dépréciées. Vous pourrez toujours configurer l'analyse historique de votre historique de commits en définissant la [variable CI/CD `SECRET_DETECTION_HISTORIC_SCAN`](https://docs.gitlab.com/user/application_security/secret_detection/#available-cicd-variables).

Pour plus de détails, consultez [le ticket de dépréciation relatif à ce changement](https://gitlab.com/gitlab-org/gitlab/-/issues/352565).

### Schémas de détection des secrets inférieurs à 14.0.0 {#secret-detection-schemas-below-1400}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0

Les [schémas de rapport de détection des secrets](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) dont la version est antérieure à 14.0.0 ne seront plus pris en charge dans GitLab 15.0. Les rapports qui ne passent pas la validation par rapport à la version de schéma déclarée dans le rapport ne seront plus pris en charge à partir de GitLab 15.0.

Les outils tiers qui [s'intègrent à GitLab en produisant un rapport de sécurité de détection des secrets](https://docs.gitlab.com/development/integrations/secure/#report) comme artefact de job de pipeline sont concernés. Vous devez vous assurer que tous les rapports produits respectent le schéma correct avec une version minimale de 14.0.0. Les rapports dont la version est inférieure ou qui échouent à la validation par rapport à la version de schéma déclarée ne seront pas traités, et les résultats de vulnérabilités ne s'afficheront pas dans les MR, les pipelines ou les rapports de vulnérabilités.

Pour faciliter la transition, à partir de GitLab 14.10, les rapports non conformes afficheront un [avertissement](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791) dans le rapport de vulnérabilités.

### Images des analyseurs Secure et Protect publiées à un nouvel emplacement {#secure-and-protect-analyzer-images-published-in-new-location}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352564).

GitLab utilise différents [analyseurs](https://docs.gitlab.com/user/application_security/terminology/#analyzer) pour [rechercher des vulnérabilités de sécurité](https://docs.gitlab.com/user/application_security/). Chaque analyseur est distribué sous forme d'image de conteneur.

À partir de GitLab 14.8, les nouvelles versions des analyseurs GitLab Secure et Protect sont publiées dans un nouvel emplacement de registre sous `registry.gitlab.com/security-products`.

Nous mettrons à jour la valeur par défaut des [templates CI/CD gérés par GitLab](https://gitlab.com/gitlab-org/gitlab/-/tree/master/lib/gitlab/ci/templates/Security) pour refléter ce changement :

- Pour tous les analyseurs, à l'exception de la recherche de vulnérabilités dans les conteneurs, nous mettrons à jour la variable `SECURE_ANALYZERS_PREFIX` vers le nouvel emplacement du registre d'images.
- Pour la recherche de vulnérabilités dans les conteneurs, l'adresse de l'image par défaut est déjà mise à jour. Il n'existe pas de variable `SECURE_ANALYZERS_PREFIX` pour la recherche de vulnérabilités dans les conteneurs.

Dans une prochaine release, nous cesserons de publier des images sur `registry.gitlab.com/gitlab-org/security-products/analyzers`. Lorsque cela se produira, vous devrez agir si vous extrayez manuellement des images et les transférez dans un registre distinct. C'est généralement le cas pour les [déploiements hors ligne](https://docs.gitlab.com/user/application_security/offline_deployments/). Dans le cas contraire, vous ne recevrez plus de mises à jour.

Consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352564) pour plus de détails.

### Mise à jour de la version majeure des analyseurs Secure et Protect {#secure-and-protect-analyzer-major-version-update}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/350936).

Les étapes Secure et Protect vont augmenter les versions majeures de leurs analyseurs en même temps que la release GitLab 15.0. Cette augmentation de version majeure permettra une distinction claire entre les analyseurs :

- Ceux publiés avant le 22 mai 2022, qui génèrent des rapports _non soumis_ à une validation stricte du schéma.
- Ceux publiés après le 22 mai 2022, qui génèrent des rapports _soumis_ à une validation stricte du schéma.

Si vous n'utilisez pas les templates d'inclusion par défaut, ou si vous avez épinglé vos versions d'analyseur, vous devrez mettre à jour la définition de votre job CI/CD pour soit supprimer la version épinglée, soit la mettre à jour vers la dernière version majeure. Les utilisateurs de GitLab 12.0 à 14.10 continueront à bénéficier des mises à jour des analyseurs normalement jusqu'à la release de GitLab 15.0, après quoi tous les bugs nouvellement corrigés et toutes les fonctionnalités nouvellement publiées dans les nouvelles versions majeures des analyseurs ne seront pas disponibles dans les versions dépréciées, car nous n'effectuons pas de rétroportage des bugs et des nouvelles fonctionnalités conformément à notre [politique de maintenance](https://docs.gitlab.com/policy/maintenance/). Conformément aux exigences, les correctifs de sécurité seront rétroportés dans les 3 dernières versions mineures. Plus précisément, les éléments suivants sont dépréciés et ne recevront plus de mises à jour après la release GitLab 15.0 :

- Sécurité API : version 1
- Recherche de vulnérabilités dans les conteneurs : version 4
- Test de fuzzing guidé par la couverture : version 2
- Analyse des dépendances : version 2
- Test dynamique de sécurité des applications (DAST) : version 2
- Analyse Infrastructure as Code (IaC) : version 1
- Analyse des licences : version 3
- Détection des secrets : version 3
- Test statique de sécurité des applications (SAST) : version 2 de [tous les analyseurs](https://docs.gitlab.com/user/application_security/sast/#supported-languages-and-frameworks), sauf `gosec` qui est actuellement à la version 3
  - `bandit` : version 2
  - `brakeman` : version 2
  - `eslint` : version 2
  - `flawfinder` : version 2
  - `gosec` : version 3
  - `kubesec` : version 2
  - `mobsf` : version 2
  - `nodejs-scan` : version 2
  - `phpcs-security-audit` : version 2
  - `pmd-apex` : version 2
  - `security-code-scan` : version 2
  - `semgrep` : version 2
  - `sobelow` : version 2
  - `spotbugs` : version 2

### Configuration des métriques et des vérifications de l'état de Sidekiq {#sidekiq-metrics-and-health-checks-configuration}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/347509).

L'exportation des métriques et des vérifications de l'état de Sidekiq via un seul processus et port est dépréciée. La prise en charge sera supprimée dans la version 15.0.

Nous avons mis à jour Sidekiq pour exporter les [métriques et les vérifications de l'état depuis deux processus distincts](https://gitlab.com/groups/gitlab-org/-/epics/6409) afin d'améliorer la stabilité et la disponibilité, et d'éviter toute perte de données dans les cas limites. Ces deux serveurs étant distincts, un changement de configuration sera nécessaire dans la version 15.0 pour définir explicitement des ports séparés pour les métriques et les vérifications de l'état. Les nouveaux paramètres introduits pour `sidekiq['health_checks_*']` doivent toujours être définis dans `gitlab.rb`. Pour plus d'informations, consultez la documentation sur la [configuration de Sidekiq](https://docs.gitlab.com/administration/sidekiq/).

Ces changements nécessitent également des mises à jour dans Prometheus pour récupérer le nouveau point de terminaison, ou dans les vérifications de l'état k8s pour cibler le nouveau port de vérification de l'état afin de fonctionner correctement ; sinon, les métriques ou les vérifications de l'état disparaîtront.

Pendant la période de dépréciation, ces paramètres sont optionnels et GitLab utilisera par défaut le même port que `sidekiq_exporter` pour les vérifications de l'état de Sidekiq, et n'exécutera qu'un seul serveur (sans modifier le comportement actuel). Ce n'est que si les deux sont définis et qu'un port différent est fourni qu'un serveur de métriques distinct démarrera pour servir les métriques Sidekiq, de manière similaire au comportement de Sidekiq dans la version 15.0.

### Éditeur de site statique {#static-site-editor}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/347137).

L'éditeur de site statique ne sera plus disponible à partir de GitLab 15.0. Les améliorations apportées à l'expérience d'édition Markdown dans GitLab offriront des avantages similaires mais avec une portée plus large. Les requêtes entrantes vers l'éditeur de site statique seront redirigées vers l'[IDE Web](https://docs.gitlab.com/user/project/web_ide/).

Les utilisateurs actuels de l'éditeur de site statique peuvent consulter la [documentation](https://docs.gitlab.com/user/project/web_ide/) pour plus d'informations, notamment sur la façon de supprimer les fichiers de configuration des projets existants.

### Prise en charge de SLES 12 SP2 {#support-for-sles-12-sp2}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Le support à long terme (LTSS) pour SUSE Linux Enterprise Server (SLES) 12 SP2 [a pris fin le 31 mars 2021](https://www.suse.com/lifecycle/). Les certificats CA sur SP2 incluent le certificat DST root expiré et ne reçoivent plus de mises à jour du paquet de certificats CA. Nous avons mis en place quelques [contournements](https://gitlab.com/gitlab-org/gitlab-omnibus-builder/-/merge_requests/191), mais nous ne pourrons pas continuer à maintenir la compilation en bon état de fonctionnement.

### Prise en charge d'un proxy compatible gRPC déployé entre Gitaly et le reste de GitLab {#support-for-grpc-aware-proxy-deployed-between-gitaly-and-rest-of-gitlab}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Bien que cela ne soit pas recommandé ni documenté, il était possible de déployer un proxy compatible gRPC entre Gitaly et le reste de GitLab. Par exemple, NGINX et Envoy. La possibilité de déployer un proxy compatible gRPC est [dépréciée](https://gitlab.com/gitlab-org/gitlab/-/issues/352517). Si vous utilisez actuellement un proxy compatible gRPC pour les connexions Gitaly, vous devez modifier la configuration de votre proxy pour utiliser à la place un proxy TCP ou TLS (couche OSI 4).

Gitaly Cluster est devenu incompatible avec les proxies compatibles gRPC dans GitLab 13.12. Désormais, toutes les installations GitLab seront incompatibles avec les proxies compatibles gRPC, même sans Gitaly Cluster.

En faisant passer une partie de notre trafic RPC interne par un protocole personnalisé (au lieu de gRPC), nous augmentons le débit et réduisons la latence du ramasse-miettes Go. Pour plus d'informations, consultez l'[epic correspondant](https://gitlab.com/groups/gitlab-com/gl-infra/-/epics/463).

### Paramètre CI/CD du projet pour la couverture des tests {#test-coverage-project-cicd-setting}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Pour simplifier la définition d'un modèle de couverture de test, dans GitLab 15.0, le [paramètre de projet pour l'analyse de la couverture de test](https://docs.gitlab.com/ci/pipelines/settings/#add-test-coverage-results-using-project-settings-removed) est supprimé.

À la place, en utilisant le fichier `.gitlab-ci.yml` du projet, fournissez une expression régulière avec le mot-clé `coverage` pour définir les résultats de couverture des tests dans les merge requests.

### Traçage dans GitLab {#tracing-in-gitlab}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/346540).

Le traçage dans GitLab est une intégration avec Jaeger, un système de traçage distribué de bout en bout open source. Les utilisateurs de GitLab peuvent accéder à leur instance Jaeger pour obtenir des informations sur les performances d'une application déployée, en suivant chaque fonction ou microservice qui traite une requête donnée. Le traçage dans GitLab est déprécié dans GitLab 14.7 et sa suppression est prévue dans la version 15.0. Pour suivre les travaux sur un éventuel remplacement, consultez le ticket pour l'[intégration d'Opstrace avec GitLab](https://gitlab.com/groups/gitlab-org/-/epics/6976).

### Mise à jour de l'API du registre de conteneurs au niveau du groupe {#update-to-the-container-registry-group-level-api}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/336912).

Dans le jalon 15.0, la prise en charge des paramètres `tags` et `tags_count` sera supprimée de l'API du registre de conteneurs qui [récupère les dépôts du registre d'un groupe](https://docs.gitlab.com/api/container_registry/#within-a-group).

Le point de terminaison `GET /groups/:id/registry/repositories` restera disponible, mais ne renverra aucune information sur les tags. Pour obtenir des informations sur les tags, vous pouvez utiliser le point de terminaison existant `GET /registry/repositories/:id`, qui continuera à prendre en charge les options `tags` et `tag_count` comme aujourd'hui. Ce dernier doit être appelé une fois par dépôt d'images.

### Changement du calcul du filtrage dans Value Stream Analytics {#value-stream-analytics-filtering-calculation-change}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/343210).

Nous modifions le fonctionnement du filtre de dates dans Value Stream Analytics. Au lieu de filtrer par la date de création du ticket ou de la merge request, le filtre de dates filtrera par l'heure de l'événement de fin de l'étape concernée. Cela entraînera des chiffres complètement différents après l'application de ce changement.

Si vous suivez les métriques de Value Stream Analytics et que vous vous appuyez sur le filtre de dates, vous devez sauvegarder les données avant ce changement pour éviter toute perte.

### Vulnerability Check {#vulnerability-check}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

La fonctionnalité Vulnerability Check est dépréciée dans GitLab 14.8 et sa suppression est prévue dans GitLab 15.0. Nous vous encourageons à migrer vers la nouvelle fonctionnalité d'approbations de sécurité. Pour ce faire, accédez à **Sécurité et conformité** > **Politiques** et créez une nouvelle politique de résultats d'analyse.

La nouvelle fonctionnalité d'approbations de sécurité est similaire à Vulnerability Check. Par exemple, les deux peuvent exiger des approbations pour les MR contenant des vulnérabilités de sécurité. Cependant, les approbations de sécurité améliorent l'expérience précédente de plusieurs manières :

- Les utilisateurs peuvent choisir qui est autorisé à modifier les règles d'approbation de sécurité. Une équipe de sécurité ou de conformité indépendante peut donc gérer les règles de manière à empêcher les responsables des projets de développement de les modifier.
- Plusieurs règles peuvent être créées et chaînées afin de permettre le filtrage selon différents seuils de gravité pour chaque type d'analyseur.
- Un processus d'approbation en deux étapes peut être appliqué pour tout changement souhaité des règles d'approbation de sécurité.
- Un ensemble unique de politiques de sécurité peut être appliqué à plusieurs projets de développement pour faciliter la maintenance d'un ensemble de règles unique et centralisé.

### `Versions` sur la base `PackageType` {#versions-on-base-packagetype}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/327453).

Dans le cadre des travaux de création d'une [API GraphQL du registre de paquets](https://gitlab.com/groups/gitlab-org/-/epics/6318), le groupe Package a déprécié le type `Version` pour le type de base `PackageType` et l'a déplacé vers [`PackageDetailsType`](https://docs.gitlab.com/api/graphql/reference/objects/#packagedetailstype).

Dans le jalon 15.0, nous supprimerons complètement `Version` de `PackageType`.

### Mutation GraphQL `apiFuzzingCiConfigurationCreate` {#apifuzzingciconfigurationcreate-graphql-mutation}

- Annoncé dans GitLab 14.6
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/333233).

Le fragment de configuration de fuzzing d'API est désormais généré côté client et ne nécessite plus de requête API. Nous déprécions donc la mutation `apiFuzzingCiConfigurationCreate` qui n'est plus utilisée dans GitLab.

### Mot-clé `artifacts:reports:cobertura` {#artifactsreportscobertura-keyword}

- Annoncé dans GitLab 14.7
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/348980).

Actuellement, les visualisations de couverture de test dans GitLab ne prennent en charge que les rapports Cobertura. À partir de la version 15.0, le mot-clé `artifacts:reports:cobertura` sera remplacé par [`artifacts:reports:coverage_report`](https://gitlab.com/gitlab-org/gitlab/-/issues/344533). Cobertura sera le seul type de fichier de rapport pris en charge dans la version 15.0, mais il s'agit de la première étape vers la prise en charge d'autres types de rapports par GitLab.

### Champ d'API GraphQL `defaultMergeCommitMessageWithDescription` {#defaultmergecommitmessagewithdescription-graphql-api-field}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/345451).

Le champ d'API GraphQL `defaultMergeCommitMessageWithDescription` a été déprécié et sera supprimé dans GitLab 15.0. Pour les projets avec un modèle de message de commit défini, il ignorera le modèle.

### Feature flag `dependency_proxy_for_private_groups` {#dependency_proxy_for_private_groups-feature-flag}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/276777).

Nous avons ajouté un feature flag parce que [GitLab-#11582](https://gitlab.com/gitlab-org/gitlab/-/issues/11582) a modifié la façon dont les groupes publics utilisent le proxy de dépendances. Avant ce changement, vous pouviez utiliser le proxy de dépendances sans authentification. Le changement requiert une authentification pour utiliser le proxy de dépendances.

Dans le jalon 15.0, nous supprimerons entièrement le feature flag. À l'avenir, vous devrez vous authentifier lors de l'utilisation du proxy de dépendances.

### Authentification `htpasswd` pour le registre de conteneurs {#htpasswd-authentication-for-the-container-registry}

- Annoncé dans GitLab 14.9
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Le registre de conteneurs prend en charge l'[authentification](https://gitlab.com/gitlab-org/container-registry/-/blob/master/docs/configuration.md#auth) avec `htpasswd`. Il repose sur un [fichier Apache `htpasswd`](https://httpd.apache.org/docs/2.4/programs/htpasswd.html), avec des mots de passe hachés à l'aide de `bcrypt`.

Comme elle n'est pas utilisée dans le contexte de GitLab (le produit), l'authentification `htpasswd` sera dépréciée dans GitLab 14.9 et supprimée dans GitLab 15.0.

### Champ `pipelines` du champ `version` {#pipelines-field-from-the-version-field}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/342882).

Dans GraphQL, il existe deux champs `pipelines` que vous pouvez utiliser dans un [`PackageDetailsType`](https://docs.gitlab.com/api/graphql/reference/objects/#packagedetailstype) pour obtenir les pipelines des versions de paquets :

- Le champ `pipelines` du champ `versions`. Cela renvoie tous les pipelines associés à toutes les versions du paquet, ce qui peut charger un nombre illimité d'objets en mémoire et créer des problèmes de performances.
- Le champ `pipelines` d'une `version` spécifique. Cela renvoie uniquement les pipelines associés à cette version unique du paquet.

Pour atténuer les éventuels problèmes de performances, nous supprimerons le champ `pipelines` du champ `versions` dans le jalon 15.0. Bien que vous ne puissiez plus obtenir tous les pipelines pour toutes les versions d'un paquet, vous pouvez toujours obtenir les pipelines d'une version unique via le champ `pipelines` restant pour cette version.

### `projectFingerprint` dans GraphQL `PipelineSecurityReportFinding` {#projectfingerprint-in-pipelinesecurityreportfinding-graphql}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Le champ `projectFingerprint` dans l'objet GraphQL [`PipelineSecurityReportFinding`](https://docs.gitlab.com/api/graphql/reference/objects/#pipelinesecurityreportfinding) est en cours de dépréciation. Ce champ contient une « empreinte numérique » des résultats de sécurité utilisée pour déterminer leur unicité. La méthode de calcul des empreintes a changé, ce qui entraîne des valeurs différentes. À l'avenir, les nouvelles valeurs seront exposées dans le champ UUID. Les données précédemment disponibles dans le champ `projectFingerprint` seront finalement supprimées entièrement.

### Commande `promote-db` de `gitlab-ctl` {#promote-db-command-from-gitlab-ctl}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/345207).

Dans GitLab 14.5, nous avons introduit la commande `gitlab-ctl promote` pour promouvoir n'importe quel nœud secondaire Geo en nœud primaire lors d'un basculement. Cette commande remplace `gitlab-ctl promote-db`, qui est utilisée pour promouvoir les nœuds de base de données dans les sites secondaires Geo multi-nœuds. `gitlab-ctl promote-db` continuera à fonctionner tel quel et sera disponible jusqu'à GitLab 15.0. Nous recommandons aux clients Geo de commencer à tester la nouvelle commande `gitlab-ctl promote` dans leurs environnements de pré-production et de l'intégrer dans leurs procédures de basculement.

### Commande `promote-to-primary-node` de `gitlab-ctl` {#promote-to-primary-node-command-from-gitlab-ctl}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/345207).

Dans GitLab 14.5, nous avons introduit la commande `gitlab-ctl promote` pour promouvoir n'importe quel nœud secondaire Geo en nœud primaire lors d'un basculement. Cette commande remplace `gitlab-ctl promote-to-primary-node`, qui n'était utilisable que pour les sites Geo à nœud unique. `gitlab-ctl promote-to-primary-node` continuera à fonctionner tel quel et sera disponible jusqu'à GitLab 15.0. Nous recommandons aux clients Geo de commencer à tester la nouvelle commande `gitlab-ctl promote` dans leurs environnements de pré-production et de l'intégrer dans leurs procédures de basculement.

### Mots-clés `type` et `types` dans la configuration CI/CD {#type-and-types-keyword-in-cicd-configuration}

- Annoncé dans GitLab 14.6
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Les mots-clés CI/CD `type` et `types` seront supprimés dans GitLab 15.0. Les pipelines qui utilisent ces mots-clés cesseront de fonctionner ; vous devez donc passer à `stage` et `stages`, qui ont le même comportement.

### Outil d'analyse des dépendances bundler-audit {#bundler-audit-dependency-scanning-tool}

- Annoncé dans GitLab 14.6
- Suppression dans GitLab 15.0 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/289832).

Depuis la version 14.6, bundler-audit est déprécié de l'analyse des dépendances. Il continuera à être inclus dans notre template CI/CD pendant la période de dépréciation. Nous supprimons bundler-audit de l'analyse des dépendances le 22 mai 2022 dans la version 15.0. Après cette suppression, la fonctionnalité d'analyse Ruby ne sera pas affectée car elle est toujours couverte par Gemnasium.

Si vous avez explicitement exclu bundler-audit via DS_EXCLUDED_ANALYZERS, vous devrez nettoyer (supprimer la référence) dans la version 15.0. Si vous avez personnalisé la configuration d'analyse des dépendances de votre pipeline, par exemple pour modifier le job `bundler-audit-dependency_scanning`, vous devrez passer à gemnasium-dependency_scanning avant la suppression dans la version 15.0, afin d'éviter que votre pipeline ne soit en échec. Si vous n'avez pas utilisé DS_EXCLUDED_ANALYZERS pour référencer bundler-audit, et que vous n'avez pas personnalisé votre template spécifiquement pour bundler-audit, vous n'aurez aucune action à entreprendre.

## GitLab 14.10 {#gitlab-1410}

### Changement de permissions pour le téléchargement des dépendances Composer {#permissions-change-for-downloading-composer-dependencies}

- Annoncé dans GitLab 14.9
- Suppression dans GitLab 14.10 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))

Le dépôt Composer de GitLab peut être utilisé pour publier, rechercher, récupérer des métadonnées et télécharger des dépendances PHP. Toutes ces actions nécessitent une authentification, sauf le téléchargement des dépendances.

Le téléchargement des dépendances Composer sans authentification est déprécié dans GitLab 14.9 et sera supprimé dans GitLab 15.0. À partir de GitLab 15.0, vous devez vous authentifier pour télécharger les dépendances Composer.

## GitLab 14.9 {#gitlab-149}

### Stratégie d'élection Gitaly `per_repository` configurable {#configurable-gitaly-per_repository-election-strategy}

- Annoncé dans GitLab 14.8
- Suppression dans GitLab 14.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/352612).

La configuration de la stratégie d'élection Gitaly `per_repository` est [dépréciée](https://gitlab.com/gitlab-org/gitlab/-/issues/352612). `per_repository` est la seule option disponible depuis GitLab 14.0.

Ce changement fait partie de la maintenance régulière visant à maintenir notre base de code propre.

### Suivi d'erreurs intégré désactivé par défaut {#integrated-error-tracking-disabled-by-default}

- Annoncé dans GitLab 14.9
- Suppression dans GitLab 14.9 ([changement majeur](https://docs.gitlab.com/update/terminology/#breaking-change))
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/353639).

Dans GitLab 14.4, GitLab a publié un backend de suivi d'erreurs intégré qui remplace Sentry. Cette fonctionnalité a provoqué des problèmes de performances sur la base de données. Dans GitLab 14.9, le suivi d'erreurs intégré est supprimé de GitLab.com et désactivé par défaut dans GitLab Self-Managed. Pendant que nous explorons le développement futur de cette fonctionnalité, veuillez envisager de passer au backend Sentry en [changeant votre suivi d'erreurs vers Sentry dans les paramètres de votre projet](https://docs.gitlab.com/operations/error_tracking/#sentry-error-tracking).

Pour plus d'informations sur cette suppression, veuillez consulter [Désactiver le suivi d'erreurs intégré par défaut](https://gitlab.com/groups/gitlab-org/-/epics/7580). Si vous avez des commentaires, veuillez les ajouter à [Commentaires : suppression du suivi d'erreurs intégré](https://gitlab.com/gitlab-org/gitlab/-/issues/355493).

## GitLab 14.8 {#gitlab-148}

### Paquets openSUSE Leap 15.2 {#opensuse-leap-152-packages}

- Annoncé dans GitLab 14.5
- Suppression dans GitLab 14.8
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/6427).

Le support de distribution et les mises à jour de sécurité pour openSUSE Leap 15.2 [se terminent en décembre 2021](https://en.opensuse.org/Lifetime#openSUSE_Leap).

À partir de la version 14.5, nous fournissons des paquets pour openSUSE Leap 15.3 et cesserons de fournir des paquets pour openSUSE Leap 15.2 dans le jalon 14.8.

## GitLab 14.6 {#gitlab-146}

### CLI de release distribué en tant que paquet générique {#release-cli-distributed-as-a-generic-package}

- Annoncé dans GitLab 14.2
- Suppression dans GitLab 14.6

Le [release-cli](https://gitlab.com/gitlab-org/release-cli) sera publié en tant que [paquet générique](https://gitlab.com/gitlab-org/release-cli/-/packages) à partir de GitLab 14.2. Nous continuerons à le déployer en tant que binaire sur S3 jusqu'à GitLab 14.5 et cesserons de le distribuer sur S3 dans GitLab 14.6.

## GitLab 14.5 {#gitlab-145}

### Renommage du pod Task Runner en Toolbox {#rename-task-runner-pod-to-toolbox}

- Annoncé dans GitLab 14.2
- Suppression dans GitLab 14.5

Le pod Task Runner est utilisé pour exécuter des tâches de maintenance périodiques dans l'application GitLab et est souvent confondu avec GitLab Runner. C'est pourquoi [Task Runner sera renommé en Toolbox](https://gitlab.com/groups/gitlab-org/charts/-/epics/25).

Cela entraînera le renommage du sous-chart : `gitlab/task-runner` en `gitlab/toolbox`. Les pods résultants seront nommés selon le modèle `{{ .Release.Name }}-toolbox`, qui sera souvent `gitlab-toolbox`. Ils seront localisables avec le label `app=toolbox`.

## Modifications en attente {#pending-changes}

Les modifications suivantes ont été retirées de leur jalon d'origine et sont en cours de réévaluation.

### L'analyse de la qualité du code basée sur CodeClimate sera supprimée {#codeclimate-based-code-quality-scanning-will-be-removed}

- Annoncé dans GitLab 17.3
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/471677).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Nous supprimerons l'analyse de la qualité du code basée sur CodeClimate dans une prochaine release. Ce changement était précédemment prévu pour GitLab 18.0 et a été retardé.

À la place, vous devez utiliser les outils de qualité directement dans votre pipeline CI/CD et [fournir le rapport de l'outil en tant qu'artefact](https://docs.gitlab.com/ci/testing/code_quality/#import-code-quality-results-from-a-cicd-job). Nous avons déjà documenté la façon d'intégrer de nombreux outils directement, et vous pouvez les intégrer en suivant la [documentation](https://docs.gitlab.com/ci/testing/code_quality/#integrate-common-tools-with-code-quality).

Nous prévoyons d'implémenter ce changement en :

1. Modifiant le [template CI/CD `Code-Quality.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Code-Quality.gitlab-ci.yml) pour qu'il n'exécute plus d'analyses. Aujourd'hui, ce template exécute des analyses basées sur CodeClimate. (Nous prévoyons de modifier le template plutôt que de le supprimer afin de réduire l'impact sur les pipelines qui `include` encore le template après la suppression.)
1. Ne plus exécuter d'analyse basée sur CodeClimate dans le cadre d'Auto DevOps.

À compter d'aujourd'hui, l'analyse basée sur CodeClimate ne recevra plus que des [mises à jour limitées](https://docs.gitlab.com/update/terminology/#deprecation). Après la fin du support, nous ne fournirons plus de mises à jour supplémentaires. Cependant, nous ne supprimerons pas les images de conteneur précédemment publiées ni la possibilité de les exécuter via des définitions de job de pipeline CI/CD personnalisées.

Pour plus de détails, consultez [Analyser le code pour détecter les violations de qualité](https://docs.gitlab.com/ci/testing/code_quality/#scan-code-for-quality-violations).

### Stockage de métadonnées legacy du registre de conteneurs {#container-registry-legacy-metadata-storage}

- Annoncé dans GitLab 18.5
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/571531).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

L'approche de stockage de métadonnées legacy du registre de conteneurs GitLab est dépréciée en faveur de la base de données de métadonnées du registre de conteneurs.

GitLab.com utilise déjà la base de données de métadonnées. Cette dépréciation concerne les instances GitLab Self-Managed utilisant actuellement le registre de conteneurs legacy qui stocke les informations de métadonnées directement dans le backend de stockage (que ce soit un object storage ou un système de fichiers local).

La méthode de stockage de métadonnées legacy restera prise en charge en mode de maintenance, mais ne recevra pas de nouvelles fonctionnalités ni d'améliorations. Nous vous recommandons vivement de migrer vers la base de données de métadonnées du registre de conteneurs dès que possible.

Ce changement n'affecte que la façon dont le registre de conteneurs stocke les métadonnées de vos images et tags. Votre choix de backend de stockage (object storage ou système de fichiers) reste le même. Vous pouvez continuer à utiliser l'[object storage](https://docs.gitlab.com/administration/packages/container_registry/#use-object-storage) ou le stockage sur système de fichiers avec la base de données de métadonnées.

Pour migrer du stockage de métadonnées legacy vers la base de données de métadonnées, suivez le [guide de migration de la base de données de métadonnées du registre de conteneurs](https://docs.gitlab.com/administration/packages/container_registry_metadata_database/). Le processus de migration implique d'activer la fonctionnalité de base de données de métadonnées et d'exécuter l'outil d'importation pour transférer vos données de registre existantes.

La base de données de métadonnées offre de meilleures performances, une meilleure fiabilité et permet de nouvelles fonctionnalités du registre de conteneurs qui ne sont pas disponibles avec l'approche de stockage de métadonnées legacy.

### Le test de fuzzing guidé par la couverture est déprécié {#coverage-guided-fuzz-testing-is-deprecated}

- Annoncé dans GitLab 18.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/517841).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Le test de fuzzing guidé par la couverture est déprécié et ne sera plus pris en charge à partir de GitLab 18.0. La fonctionnalité sera complètement supprimée dans GitLab 19.0.

Le test de fuzzing guidé par la couverture intégrait plusieurs fuzzers open source dans GitLab. Si vous êtes concerné, vous pouvez intégrer vos fuzzers open source en tant qu'applications autonomes, ou migrer vers une autre fonctionnalité de sécurité comme [GitLab Advanced SAST](https://docs.gitlab.com/user/application_security/sast/gitlab_advanced_sast/).

### Analyse des dépendances pour les bibliothèques JavaScript vendored {#dependency-scanning-for-javascript-vendored-libraries}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/501308).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

La fonctionnalité d'[analyse des dépendances pour les bibliothèques JavaScript vendored](https://docs.gitlab.com/user/application_security/dependency_scanning/#javascript) fournie par l'analyseur Gemnasium pour l'analyse des dépendances est dépréciée dans GitLab 17.9.

Bien que cette fonctionnalité continue de fonctionner avec l'analyseur Gemnasium, elle ne sera plus disponible après la migration vers le nouvel analyseur d'analyse des dépendances. Consultez les détails dans [le guide de migration](https://docs.gitlab.com/user/application_security/dependency_scanning/migration_guide_to_sbom_based_scans/)

Une fonctionnalité de remplacement sera développée avec l'[analyse des dépendances pour les bibliothèques vendored](https://gitlab.com/groups/gitlab-org/-/epics/7186), mais aucun calendrier n'a été fixé pour sa livraison.

### L'analyse des dépendances passe au scanner de vulnérabilités GitLab SBOM {#dependency-scanning-upgrades-to-the-gitlab-sbom-vulnerability-scanner}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/501308).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

La fonctionnalité d'analyse des dépendances passe au scanner de vulnérabilités GitLab SBOM. Dans le cadre de ce changement, l'analyseur Gemnasium (précédemment utilisé dans les pipelines CI/CD) est déprécié dans GitLab 17.9.

Il est remplacé par la fonctionnalité d'[analyse des dépendances utilisant SBOM](https://docs.gitlab.com/user/application_security/dependency_scanning/dependency_scanning_sbom/) et le [nouvel analyseur d'analyse des dépendances](https://gitlab.com/gitlab-org/security-products/analyzers/dependency-scanning) qui se concentre sur la détection des dépendances et de leurs relations (graphe de dépendances) et s'appuie sur le scanner de vulnérabilités SBOM intégré de GitLab, déjà utilisé par l'[analyse continue des vulnérabilités](https://docs.gitlab.com/user/application_security/continuous_vulnerability_scanning/), pour identifier leurs vulnérabilités.

Depuis GitLab 18.5, cette nouvelle fonctionnalité est en disponibilité limitée. Tant que la majorité des utilisateurs n'aura pas migré vers la nouvelle fonctionnalité d'analyse des dépendances, GitLab continuera à prendre en charge l'analyseur Gemnasium. Ce n'est qu'à ce moment-là que l'analyseur Gemnasium atteindra la [fin du support](https://docs.gitlab.com/update/terminology/#end-of-support).

En raison des changements importants et des suppressions de fonctionnalités que cette mise à niveau introduit, elle ne sera pas implémentée automatiquement. Les jobs CI/CD existants utilisant l'analyseur Gemnasium continueront à fonctionner par défaut afin d'éviter toute interruption des configurations CI/CD.

Veuillez consulter en détail les changements ci-dessous et vous référer au [guide de migration](https://docs.gitlab.com/user/application_security/dependency_scanning/migration_guide_to_sbom_based_scans/) pour vous aider dans la transition.

- Pour éviter toute interruption de votre configuration CI/CD, lorsque votre application utilise le template CI/CD stable d'analyse des dépendances (`Dependency-Scanning.gitlab-ci.yml`), l'analyse des dépendances utilise uniquement les jobs CI/CD existants basés sur l'analyseur Gemnasium.
- Lorsque votre application utilise le template CI/CD d'analyse des dépendances le plus récent (`Dependency-Scanning.latest.gitlab-ci.yml`), l'analyse des dépendances utilise les jobs CI/CD existants basés sur l'analyseur Gemnasium et le nouvel analyseur d'analyse des dépendances s'exécute également sur les types de fichiers pris en charge. Vous pouvez également opter pour l'application du nouvel analyseur d'analyse des dépendances pour tous les projets.
- D'autres chemins de migration pourront être envisagés à mesure que la fonctionnalité gagne en maturité.
- Le projet de l'[analyseur Gemnasium](https://gitlab.com/gitlab-org/security-products/analyzers/gemnasium/) est déprécié, ainsi que les images de conteneur correspondantes (tous les tags et variantes) : `gemnasium`, `gemnasium-maven`, `gemnasium-python`. Ces images ne seront pas supprimées du registre de conteneurs GitLab.
- Les variables CI/CD suivantes associées à l'analyseur Gemnasium sont également dépréciées. Bien que ces variables continuent de fonctionner avec l'analyseur Gemnasium, elles ne seront pas effectives après la migration vers le nouvel analyseur d'analyse des dépendances. Si une variable est également utilisée dans un autre contexte, la dépréciation s'applique uniquement à la fonctionnalité d'analyse des dépendances (par exemple, `GOOS` et `GOARCH` ne sont pas spécifiques à la fonctionnalité d'analyse des dépendances). `DS_EXCLUDED_ANALYZERS`, `DS_GRADLE_RESOLUTION_POLICY`, `DS_IMAGE_SUFFIX`, `DS_JAVA_VERSION`, `DS_PIP_DEPENDENCY_PATH`, `DS_PIP_VERSION`, `DS_REMEDIATE_TIMEOUT`, `DS_REMEDIATE`, `GEMNASIUM_DB_LOCAL_PATH`, `GEMNASIUM_DB_REF_NAME`, `GEMNASIUM_DB_REMOTE_URL`, `GEMNASIUM_DB_UPDATE_DISABLED`, `GEMNASIUM_LIBRARY_SCAN_ENABLED`, `GOARCH`, `GOFLAGS`, `GOOS`, `GOPRIVATE`, `GRADLE_CLI_OPTS`, `GRADLE_PLUGIN_INIT_PATH`, `MAVEN_CLI_OPTS`, `PIP_EXTRA_INDEX_URL`, `PIP_INDEX_URL`, `PIPENV_PYPI_MIRROR`, `SBT_CLI_OPTS`.
- Les [composants CI/CD](https://gitlab.com/components/dependency-scanning/#components) suivants sont dépréciés : Android, Rust, Swift, CocoaPods. Ils sont remplacés par [le composant CI/CD principal d'analyse des dépendances](https://gitlab.com/components/dependency-scanning/-/tree/main/templates/main?ref_type=heads) qui couvre tous les langages et gestionnaires de paquets pris en charge.
- La fonctionnalité [Résoudre une vulnérabilité](https://docs.gitlab.com/user/application_security/vulnerabilities/#resolve-a-vulnerability) **pour les projets Yarn** est dépréciée dans GitLab 17.9. Bien que cette fonctionnalité continue de fonctionner avec l'analyseur Gemnasium, elle ne sera plus disponible après la migration vers le nouvel analyseur d'analyse des dépendances. Consultez l'[annonce de dépréciation](https://docs.gitlab.com/update/deprecations/#resolve-a-vulnerability-for-dependency-scanning-on-yarn-projects) correspondante pour plus de détails.
- La fonctionnalité d'[analyse des dépendances pour les bibliothèques JavaScript vendored](https://docs.gitlab.com/user/application_security/dependency_scanning/#javascript) est dépréciée dans GitLab 17.9. Bien que cette fonctionnalité continue de fonctionner avec l'analyseur Gemnasium, elle ne sera plus disponible après la migration vers le nouvel analyseur d'analyse des dépendances. Consultez l'[annonce de dépréciation](https://docs.gitlab.com/update/deprecations/#dependency-scanning-for-javascript-vendored-libraries) correspondante pour plus de détails.

### GitLab Advanced SAST sera activé par défaut {#gitlab-advanced-sast-will-be-enabled-by-default}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/513685).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Dans GitLab 19.0, nous mettrons à jour les [templates CI/CD SAST](https://docs.gitlab.com/user/application_security/sast#stable-vs-latest-sast-templates) pour activer [GitLab Advanced SAST](https://docs.gitlab.com/user/application_security/sast/gitlab_advanced_sast/) par défaut dans les projets avec GitLab Ultimate. Avant ce changement, l'analyseur GitLab Advanced SAST n'est activé que si vous définissez la variable CI/CD `GITLAB_ADVANCED_SAST_ENABLED` sur `true`. Ce changement était précédemment prévu pour GitLab 18.0 et a été retardé.

Advanced SAST fournit des résultats plus précis en utilisant une analyse inter-fichiers et inter-fonctions ainsi qu'un nouvel ensemble de règles. Advanced SAST prend en charge la couverture des [langages pris en charge](https://docs.gitlab.com/user/application_security/sast/gitlab_advanced_sast/#supported-languages) et désactive l'analyse pour ce langage dans l'analyseur précédent. Un processus automatisé migre les résultats des analyseurs précédents après la première analyse sur la branche par défaut de chaque projet, s'ils sont encore détectés.

Comme il analyse votre projet plus en détail, Advanced SAST peut prendre plus de temps pour analyser votre projet. Si nécessaire, vous pouvez [désactiver GitLab Advanced SAST](https://docs.gitlab.com/user/application_security/sast/gitlab_advanced_sast/#disable-gitlab-advanced-sast-scanning) en définissant la variable CI/CD `GITLAB_ADVANCED_SAST_ENABLED` sur `false`. Vous pouvez définir cette variable dans votre projet, votre groupe ou votre politique dès maintenant pour empêcher l'activation d'Advanced SAST par défaut dans GitLab 19.0.

### L'exécuteur Docker Machine de GitLab Runner est déprécié {#gitlab-runner-docker-machine-executor-is-deprecated}

- Annoncé dans GitLab 17.5
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/498268).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

L'[exécuteur Docker Machine de GitLab Runner](https://docs.gitlab.com/runner/executors/docker_machine/) est déprécié et sera complètement supprimé du produit en tant que fonctionnalité prise en charge dans GitLab 20.0 (mai 2027). Le remplacement de Docker Machine, [GitLab Runner Autoscaler](https://docs.gitlab.com/runner/runner_autoscale/) avec les plugins développés par GitLab pour les machines virtuelles (VM) Amazon Web Services (AWS) EC2, Google Compute Engine (GCE) et Microsoft Azure, est généralement disponible. Avec cette annonce, l'équipe GitLab Runner n'acceptera plus les contributions de la communauté pour le fork Docker Machine maintenu par GitLab, et ne résoudra plus les nouveaux bugs identifiés.

### Plateformes GitLab Runner et instructions de configuration dans l'API GraphQL {#gitlab-runner-platforms-and-setup-instructions-in-graphql-api}

- Annoncé dans GitLab 15.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/387937).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Les requêtes `runnerPlatforms` et `runnerSetup` permettant d'obtenir les plateformes GitLab Runner et les instructions d'installation sont dépréciées et seront supprimées de l'API GraphQL. Pour les instructions d'installation, consultez la [documentation de GitLab Runner](https://docs.gitlab.com/runner/) plutôt que d'utiliser ces requêtes API.

### Intégration basée sur les certificats de GitLab Self-Managed avec Kubernetes {#gitlab-self-managed-certificate-based-integration-with-kubernetes}

- Annoncé dans GitLab 14.5
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/configure/-/epics/8).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

L'intégration basée sur les certificats avec Kubernetes [sera dépréciée et supprimée](https://about.gitlab.com/blog/deprecating-the-cert-based-kubernetes-integration/).

Pour GitLab Self-Managed, nous introduisons le [feature flag](https://docs.gitlab.com/administration/feature_flags/#enable-or-disable-the-feature) `certificate_based_clusters` dans GitLab 15.0 afin que vous puissiez maintenir votre intégration basée sur les certificats activée. Cependant, le feature flag sera désactivé par défaut, ce qui fait de ce changement une **rupture de compatibilité**.

Pour une intégration plus robuste, sécurisée, évolutive et fiable avec Kubernetes, utilisez l'[agent pour Kubernetes](https://docs.gitlab.com/user/clusters/agent/) pour connecter les clusters Kubernetes à GitLab. Pour plus d'informations sur cette migration, consultez [migrer vers l'agent pour Kubernetes](https://docs.gitlab.com/user/infrastructure/clusters/migrate_to_gitlab_agent/).

GitLab ne supprimera pas cette fonctionnalité tant que la nouvelle solution n'aura pas atteint la parité des fonctionnalités. Pour plus d'informations sur les obstacles à la suppression, consultez le [ticket 199](https://gitlab.com/gitlab-org/configure/general/-/issues/199).

Pour les mises à jour et les détails concernant cette dépréciation, consultez l'[epic 8](https://gitlab.com/groups/gitlab-org/configure/-/epics/8).

### Intégration basée sur les certificats de GitLab.com avec Kubernetes {#gitlabcom-certificate-based-integration-with-kubernetes}

- Annoncé dans GitLab 14.5
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/groups/gitlab-org/configure/-/epics/8).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

L'intégration basée sur les certificats avec Kubernetes sera [dépréciée et supprimée](https://about.gitlab.com/blog/deprecating-the-cert-based-kubernetes-integration/). En tant qu'utilisateur de GitLab.com, pour les nouveaux espaces de nommage, vous ne pourrez plus intégrer GitLab et votre cluster en utilisant l'approche basée sur les certificats à partir de GitLab 15.0. L'intégration pour les utilisateurs actuels sera activée par espace de nommage.

Pour une intégration plus robuste, sécurisée, évolutive et fiable avec Kubernetes, nous vous recommandons d'utiliser l'[agent pour Kubernetes](https://docs.gitlab.com/user/clusters/agent/) pour connecter les clusters Kubernetes à GitLab. [Comment migrer ?](https://docs.gitlab.com/user/infrastructure/clusters/migrate_to_gitlab_agent/)

Pour les mises à jour et les détails concernant cette dépréciation, suivez [cet epic](https://gitlab.com/groups/gitlab-org/configure/-/epics/8).

Les clients de GitLab Self-Managed peuvent toujours utiliser la fonctionnalité [avec un feature flag](https://docs.gitlab.com/update/deprecations/#self-managed-certificate-based-integration-with-kubernetes).

### Dépréciation GraphQL du champ `dependencyProxyTotalSizeInBytes` {#graphql-deprecation-of-dependencyproxytotalsizeinbytes-field}

- Annoncé dans GitLab 16.1
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/414236).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Vous pouvez utiliser GraphQL pour interroger la quantité de stockage utilisée par le proxy de dépendances GitLab. Cependant, le champ `dependencyProxyTotalSizeInBytes` est limité à environ 2 gigaoctets, ce qui n'est pas toujours suffisant pour le proxy de dépendances. En conséquence, `dependencyProxyTotalSizeInBytes` est déprécié.

Utilisez plutôt `dependencyProxyTotalSizeBytes`, introduit dans GitLab 16.1.

### Le regroupement du rapport de vulnérabilités par OWASP top 10 2017 est déprécié {#group-vulnerability-report-by-owasp-top-10-2017-is-deprecated}

- Annoncé dans GitLab 17.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/458835).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Le regroupement du rapport de vulnérabilités par OWASP top 10 2017 est déprécié, remplacé par un regroupement par OWASP top 10 2021. À l'avenir, nous prendrons en charge la version la plus récente de l'OWASP top 10 pour le regroupement dans le rapport de vulnérabilités. En parallèle de ce changement, nous déprécions et supprimons également les enums de l'API GraphQL 2017 utilisés par cette fonctionnalité. Des détails supplémentaires sont disponibles dans [ce ticket](https://gitlab.com/gitlab-org/gitlab/-/issues/488433).

### Renforcement de la sécurité par défaut pour l'utilisation des variables de pipeline {#increased-default-security-for-use-of-pipeline-variables}

- Annoncé dans GitLab 17.7
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/502382).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

GitLab adhère aux pratiques de sécurité par défaut. Pour respecter ce principe, nous apportons des modifications afin de soutenir les principes du moindre privilège en ce qui concerne l'utilisation des variables CI/CD. Aujourd'hui, les utilisateurs disposant du rôle Développeur ou supérieur peuvent utiliser les [variables de pipeline](https://docs.gitlab.com/ci/variables/#use-pipeline-variables) par défaut, sans aucune vérification ni consentement explicite.

Vous pouvez déjà commencer à utiliser une expérience plus sécurisée par défaut pour les variables de pipeline en relevant le rôle minimum au niveau recommandé [Propriétaire uniquement, ou personne](https://docs.gitlab.com/ci/variables/#restrict-pipeline-variables). À partir de la version 17.7, `no one allowed` est la valeur par défaut pour tous les nouveaux projets dans les nouveaux espaces de nommage sur GitLab.com.

### Modèle CI/CD OpenTofu {#opentofu-cicd-template}

- Annoncé dans GitLab 17.1
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/components/opentofu/-/issues/43#note_1913822299).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Nous avons introduit le modèle CI/CD OpenTofu dans la version 16.8, car les composants CI/CD n'étaient pas encore disponibles pour GitLab Self-Managed. Avec l'introduction des [composants CI/CD GitLab pour GitLab Self-Managed](https://docs.gitlab.com/ci/components/#use-a-gitlabcom-component-in-a-self-managed-instance), nous supprimons les modèles CI/CD OpenTofu redondants au profit des composants CI/CD.

Pour plus d'informations sur la migration du modèle CI/CD vers le composant, consultez la [documentation du composant OpenTofu](https://gitlab.com/components/opentofu#usage-on-self-managed).

### La stratégie `inject_ci` des politiques d'exécution de pipeline est remplacée par `inject_policy` {#pipeline-execution-policies-inject_ci-strategy-replaced-by-inject_policy}

- Annoncé dans GitLab 17.11
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/573447).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Avec l'introduction des [étapes personnalisées](https://gitlab.com/gitlab-org/gitlab/-/issues/475152) dans les politiques d'exécution de pipeline (disponibles dans GitLab 17.9), nous avons introduit l'option de configuration `inject_policy` pour remplacer la valeur dépréciée `inject_ci`.

Cette nouvelle stratégie permet un déploiement progressif de la fonctionnalité d'étapes personnalisées pour les utilisateurs ayant des politiques d'exécution de pipeline existantes qui utilisent la stratégie `inject_ci`.

Pour vous préparer à la suppression imminente, mettez à jour toutes les politiques d'exécution de pipeline qui utilisent `inject_ci` pour utiliser `inject_policy` à la place.

### Limites de débit pour les points de terminaison API courants des utilisateurs, des projets et des groupes {#rate-limits-for-common-user-project-and-group-api-endpoints}

- Annoncé dans GitLab 17.4
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/480914).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Les limites de débit seront activées par défaut pour les points de terminaison [Utilisateur](https://docs.gitlab.com/administration/settings/user_and_ip_rate_limits/), [Projet](https://docs.gitlab.com/administration/settings/rate_limit_on_projects_api/) et [Groupe](https://docs.gitlab.com/administration/settings/rate_limit_on_groups_api/) couramment utilisés. L'activation de ces limites de débit par défaut peut contribuer à améliorer la stabilité globale du système en réduisant le risque qu'une utilisation intensive de l'API affecte négativement l'expérience des utilisateurs. Les requêtes dépassant la limite de débit renverront un code d'erreur [HTTP 429](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/429) et des [en-têtes supplémentaires de limite de débit](https://docs.gitlab.com/administration/settings/user_and_ip_rate_limits/#response-headers).

Les limites de débit par défaut ont été intentionnellement fixées à un niveau assez élevé pour ne pas perturber la plupart des usages, en se basant sur les taux de requêtes observés sur GitLab.com. Les administrateurs d'instance peuvent définir des limites plus élevées ou plus basses selon leurs besoins dans la zone d'administration, de la même manière que pour les autres limites de débit déjà en place.

### Suppression du champ `migrationState` dans l'API GraphQL `ContainerRepository` {#removal-of-migrationstate-field-in-containerrepository-graphql-api}

- Annoncé dans GitLab 17.6
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/459869).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Le champ `migrationState` dans le `ContainerRepositoryType` de l'API GraphQL de GitLab est déprécié. Cette dépréciation s'inscrit dans nos efforts pour simplifier et améliorer notre API.

Pour vous préparer à ce changement, nous vous recommandons de vérifier et mettre à jour vos requêtes GraphQL qui interagissent avec `ContainerRepositoryType`. Supprimez toutes les références au champ `migrationState` et adaptez la logique de votre application en conséquence.

### Supprimer `previousStageJobsOrNeeds` de GraphQL {#remove-previousstagejobsorneeds-from-graphql}

- Annoncé dans GitLab 17.0
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/424417).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Le champ `previousStageJobsOrNeeds` dans GraphQL sera supprimé car il a été remplacé par les champs `previousStageJobs` et `needs`.

### Remplacer le champ GraphQL `take_ownership_pipeline_schedule` par `admin_pipeline_schedule` dans PipelineSchedulePermissions {#replace-graphql-field-take_ownership_pipeline_schedule-with-admin_pipeline_schedule-in-pipelineschedulepermissions}

- Annoncé dans GitLab 15.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/391941).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Le champ GraphQL `take_ownership_pipeline_schedule` sera déprécié. Pour déterminer si un utilisateur peut prendre possession d'une planification de pipeline, utilisez plutôt le champ `admin_pipeline_schedule`.

### Résoudre une vulnérabilité pour l'analyse des dépendances sur les projets Yarn {#resolve-a-vulnerability-for-dependency-scanning-on-yarn-projects}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/501308).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

La fonctionnalité [Résoudre une vulnérabilité](https://docs.gitlab.com/user/application_security/vulnerabilities/#resolve-a-vulnerability) pour les projets Yarn fournie par l'analyseur Gemnasium pour l'analyse des dépendances est dépréciée dans GitLab 17.9.

Bien que cette fonctionnalité continue de fonctionner avec l'analyseur Gemnasium, elle ne sera plus disponible après la migration vers le nouvel analyseur d'analyse des dépendances. Consultez les détails dans [le guide de migration](https://docs.gitlab.com/user/application_security/dependency_scanning/migration_guide_to_sbom_based_scans/)

Une fonctionnalité de remplacement est prévue dans le cadre de la [vision de remédiation automatique](https://gitlab.com/groups/gitlab-org/-/epics/7186), mais aucun calendrier n'a été défini pour sa livraison.

### Les points de terminaison API liés aux abonnements dans l'API publique sont dépréciés {#subscription-related-api-endpoints-in-the-public-api-are-deprecated}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/515371#note_2319368251).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Les points de terminaison suivants de l'API REST publique seront supprimés :

- `PUT /api/v4/user/:id/credit_card_validation`
- `POST /api/v4/namespaces/:namespace_id/minutes`
- `PATCH /api/v4/namespaces/:previous_namespace_id/minutes/move/:target_namespace_id`
- `GET /api/v4/namespaces/:namespace_id/subscription_add_on_purchase/:id`
- `PUT /api/v4/namespaces/:namespace_id/subscription_add_on_purchase/:id`
- `POST /api/v4/namespaces/:namespace_id/subscription_add_on_purchase/:id`
- `POST /api/v4/namespaces/:id/gitlab_subscription`
- `PUT /api/v4/namespaces/:id/gitlab_subscription`
- `PUT /api/v4/namespaces/:id`

Ces points de terminaison étaient utilisés par le portail des abonnements pour gérer les informations d'abonnement sur GitLab.com. Leur utilisation a été remplacée par des points de terminaison internes avec authentification JWT pour prendre en charge la future architecture Cells. Les points de terminaison de l'API publique sont supprimés pour éviter qu'ils ne soient réutilisés accidentellement et pour réduire la charge de maintenance à mesure que leurs fonctionnalités divergent.

Vous ne devriez pas être impacté par ce changement, car il s'agit de points de terminaison utilisés en interne.

### Le registre de conteneurs `agentk` migre vers Cloud Native GitLab {#the-agentk-container-registry-is-moving-to-cloud-native-gitlab}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/issues/630).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Nous migrons le registre de conteneurs `agentk` depuis [son registre spécifique au projet](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/container_registry/1223205) vers [le registre Cloud Native GitLab (CNG)](https://gitlab.com/gitlab-org/build/CNG/container_registry/8241772). À partir de GitLab 18.0, les images `agentk` générées dans CNG seront synchronisées dans le registre spécifique au projet. La nouvelle image est équivalente à l'ancienne, à ceci près que la nouvelle image prend uniquement en charge les architectures `amd64` et `arm64`. Elle ne prend pas en charge l'architecture 32 bits `arm`. À partir de GitLab 19.0, le registre spécifique au projet ne recevra plus les mises à jour `agentk`. Si vous synchronisez le conteneur `agentk` vers un registre local, vous devez changer la source de synchronisation vers le [registre CNG](https://gitlab.com/gitlab-org/build/CNG/container_registry/8241772).

Si vous utilisez le [chart Helm officiel de l'agent GitLab](https://gitlab.com/gitlab-org/charts/gitlab-agent/), la nouvelle image `agentk` commencera à être déployée depuis le nouvel emplacement de manière transparente dans GitLab 18.0.

### Mise à jour des jetons de job CI/CD vers le standard JWT {#updating-cicd-job-tokens-to-jwt-standard}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/509578).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Dans GitLab 19.0, les jetons de job CI/CD passeront du format de jeton sous forme de chaîne de caractères au format de jeton JWT. Ce changement concerne les jetons de job CI/CD nouveaux et existants dans tous les projets. Si vous rencontrez des problèmes, vous pouvez toujours [utiliser le format hérité pour vos jetons CI/CD](https://docs.gitlab.com/ci/jobs/ci_job_token#use-legacy-format-for-cicd-tokens) jusqu'à la release GitLab 20.0.

Problèmes connus :

1. Le pilote AWS Fargate 0.5.0 et versions antérieures de GitLab Runner est incompatible avec le standard JWT. Les jobs échoueront avec une erreur `file name too long`. Les utilisateurs du [pilote d'exécuteur personnalisé AWS Fargate](https://docs.gitlab.com/runner/configuration/runner_autoscale_aws_fargate/) doivent effectuer une mise à niveau vers la version 0.5.1 ou ultérieure. Pour les instructions de migration, consultez [la documentation](https://gitlab.com/gitlab-org/ci-cd/custom-executor-drivers/fargate/-/tree/master/docs).
1. La longueur bien plus importante du standard JWT rompt la commande `echo $CI_JOB_TOKEN | base64` utilisée dans certains fichiers de configuration CI/CD. Vous pouvez utiliser la commande `echo $CI_JOB_TOKEN | base64 -w0` à la place.

### Options de configuration `bin_path` et `use_bundled_binaries` dans Gitaly {#bin_path-and-use_bundled_binaries-configuration-options-in-gitaly}

- Annoncé dans GitLab 18.2
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/9181).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

La prise en charge des options de configuration `bin_path` et `use_bundled_binaries` dans Gitaly est dépréciée et sera supprimée dans GitLab 19.0.

Les binaires Git fournis par Gitaly seront le seul moyen pris en charge pour exécuter Git.

### Champs GraphQL `mergeTrainIndex` et `mergeTrainsCount` dépréciés {#mergetrainindex-and-mergetrainscount-graphql-fields-deprecated}

- Annoncé dans GitLab 17.5
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/473759).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Les champs GraphQL `mergeTrainIndex` et `mergeTrainsCount` dans `MergeRequest` sont dépréciés. Pour déterminer la position de la merge request dans le merge train, utilisez plutôt le champ `index` dans `MergeTrainCar`. Pour obtenir le nombre de merge requests dans un merge train, utilisez `count` depuis `cars` dans `MergeTrains::TrainType` à la place.

### Le champ GraphQL `scanResultPolicies` est déprécié {#scanresultpolicies-graphql-field-is-deprecated}

- Annoncé dans GitLab 17.8
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/439199).

> [!note]
> Cette modification a été retirée de son jalon d'origine et est en cours de réévaluation.

Dans la version 16.10, les politiques de résultat d'analyse ont été renommées en politiques d'approbation de merge request afin de mieux refléter l'évolution du périmètre et des capacités du type de politique.

En conséquence, nous avons mis à jour les points de terminaison GraphQL. Utilisez `approvalPolicies` à la place de `scanResultPolicies`.

## Changements annulés {#canceled-changes}

Les changements suivants ont été annulés.

### Seuil de gravité par défaut de l'analyse des conteneurs défini sur `medium` {#container-scanning-default-severity-threshold-set-to-medium}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/515358).

> [!note]
> Ce changement a été annulé.

La fonctionnalité de sécurité d'analyse des conteneurs génère un grand nombre de résultats de sécurité, et ce volume est souvent difficile à gérer pour les équipes d'ingénierie. En changeant le seuil de gravité à `medium`, nous offrons un paramètre par défaut plus raisonnable à nos utilisateurs, où les résultats dont la gravité est inférieure à `medium` ne sont pas signalés. À partir de GitLab 18.0, la valeur par défaut de la variable d'environnement `CS_SEVERITY_THRESHOLD` est définie sur `medium` au lieu de `unknown`. Par conséquent, les résultats de sécurité avec les niveaux de gravité `low` et `unknown` ne seront plus signalés par défaut. Par conséquent, toute vulnérabilité présentant ces niveaux de gravité précédemment signalée sur la branche par défaut sera marquée comme non détectée lors de la prochaine exécution de l'analyse des conteneurs. Pour continuer à afficher ces résultats, vous devez configurer la variable `CS_SEVERITY_THRESHOLD` au niveau souhaité.

### Dépréciation du type de rapport d'artefacts CI/CD de l'analyse des licences {#deprecate-license-scanning-cicd-artifact-report-type}

- Annoncé dans GitLab 16.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/439301).

> [!note]
> Ce changement a été annulé.

Le type de [rapport d'artefacts](https://docs.gitlab.com/ci/yaml/artifacts_reports/) CI/CD est déprécié dans GitLab 16.9 et sera supprimé dans GitLab 18.0. Les configurations CI/CD utilisant ce mot-clé cesseront de fonctionner dans GitLab 18.0.

Le type de rapport d'artefacts n'est plus utilisé en raison de la suppression du job CI/CD hérité d'analyse des licences dans GitLab 16.3. À la place, vous devriez utiliser l'[analyse des licences de fichiers CycloneDX](https://docs.gitlab.com/user/compliance/license_scanning_of_cyclonedx_files/).

### Les jobs SAST en fin de support seront supprimés du modèle CI/CD {#end-of-support-sast-jobs-will-be-removed-from-the-cicd-template}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/519133).

> [!note]
> Ce changement a été annulé.

Dans GitLab 18.0, nous mettrons à jour le modèle CI/CD SAST pour supprimer les jobs d'analyse qui ont atteint la fin du support dans les versions précédentes. Les jobs suivants seront supprimés de `SAST.gitlab-ci.yml` et de `SAST.latest.gitlab-ci.yml` :

- `bandit-sast`, qui [a atteint la fin du support dans la version 15.4](#sast-analyzer-consolidation-and-cicd-template-changes)
- `brakeman-sast`, qui [a atteint la fin du support dans la version 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `eslint-sast`, qui [a atteint la fin du support dans la version 15.4](#sast-analyzer-consolidation-and-cicd-template-changes)
- `flawfinder-sast`, qui [a atteint la fin du support dans la version 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `gosec-sast`, qui [a atteint la fin du support dans la version 15.4](#sast-analyzer-consolidation-and-cicd-template-changes)
- `mobsf-android-sast`, qui [a atteint la fin du support dans la version 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `mobsf-ios-sast`, qui [a atteint la fin du support dans la version 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `nodejs-scan-sast`, qui [a atteint la fin du support dans la version 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `phpcs-security-audit-sast`, qui [a atteint la fin du support dans la version 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `security-code-scan-sast`, qui [a atteint la fin du support dans la version 16.0](#sast-analyzer-coverage-changing-in-gitlab-160)

Au moment où chaque analyseur a atteint la fin du support, nous avons mis à jour ses `rules` de job pour qu'il ne s'exécute pas par défaut et avons cessé de publier des mises à jour. Cependant, il est possible que vous ayez personnalisé le modèle pour continuer à utiliser ces jobs ou que vous dépendiez de leur présence dans vos pipelines. Si vous avez des personnalisations qui dépendent des jobs mentionnés ci-dessus, effectuez les [actions requises](https://gitlab.com/gitlab-org/gitlab/-/issues/519133#actions-required) avant de mettre à niveau vers la version 18.0 afin d'éviter toute interruption de vos pipelines CI/CD.

### L'utilisation publique des registres de conteneurs Secure est dépréciée {#public-use-of-secure-container-registries-is-deprecated}

- Annoncé dans GitLab 17.4
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/470641).

> [!note]
> Ce changement a été annulé.

Les registres de conteneurs sous `registry.gitlab.com/gitlab-org/security-products/` ne sont plus accessibles dans GitLab 18.0. [Depuis GitLab 14.8](https://docs.gitlab.com/update/deprecations/#secure-and-protect-analyzer-images-published-in-new-location), l'emplacement correct se trouve sous `registry.gitlab.com/security-products` (notez l'absence de `gitlab-org` dans l'adresse).

Ce changement améliore la sécurité du processus de release pour les [scanners de vulnérabilités](https://docs.gitlab.com/user/application_security/#vulnerability-scanner-maintenance) GitLab.

Il est conseillé aux utilisateurs d'utiliser le registre équivalent sous `registry.gitlab.com/security-products/`, qui est l'emplacement canonique pour les images de scanners de sécurité GitLab. Les modèles CI GitLab correspondants utilisent déjà cet emplacement, donc aucune modification ne devrait être nécessaire pour les utilisateurs utilisant les modèles non modifiés.

Les déploiements hors ligne doivent consulter les [instructions spécifiques à chaque scanner](https://docs.gitlab.com/user/application_security/offline_deployments/#specific-scanner-instructions) pour s'assurer que les emplacements corrects sont utilisés pour synchroniser les images de scanner requises.

### Les jobs SAST n'utilisent plus les paramètres de cache globaux {#sast-jobs-no-longer-use-global-cache-settings}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/512564).

> [!note]
> Ce changement a été annulé.

Dans GitLab 18.0, nous mettrons à jour les analyses SAST et IaC pour [désactiver explicitement l'utilisation du cache de job CI/CD](https://docs.gitlab.com/ci/caching/#disable-cache-for-specific-jobs) par défaut.

Ce changement affecte les modèles CI/CD pour :

- SAST : `SAST.gitlab-ci.yml`.
- Analyse IaC : `SAST-IaC.gitlab-ci.yml`.

Nous avons déjà mis à jour les modèles `latest` `SAST.latest.gitlab-ci.yml` et `SAST-IaC.latest.gitlab-ci.yml`. Consultez [les modèles stable et latest](https://docs.gitlab.com/user/application_security/sast/#stable-vs-latest-sast-templates) pour plus de détails sur ces versions de modèles.

Les répertoires de cache ne sont généralement pas dans le périmètre d'analyse pour la plupart des projets, si bien que la récupération du cache peut entraîner des délais d'expiration ou des faux positifs.

Si vous avez besoin d'utiliser le cache lors de l'analyse d'un projet, vous pouvez restaurer le comportement précédent en [substituant](https://docs.gitlab.com/user/application_security/sast/#overriding-sast-jobs) la propriété [`cache`](https://docs.gitlab.com/ci/yaml/#cache) dans la configuration CI du projet.

### L'analyseur de détection des secrets ne s'exécute pas en tant qu'utilisateur root par défaut {#secret-detection-analyzer-doesnt-run-as-root-user-by-default}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/476160).

> [!note]
> Ce changement a été annulé.

Ce changement prévu de l'analyseur de détection des secrets est annulé. Vous pouvez toujours utiliser l'utilisateur root par défaut.

### Prise en charge de la compilation de projet dans le cadre des analyses SpotBugs {#support-for-project-build-as-part-of-spotbugs-scans}

- Annoncé dans GitLab 17.9
- Pour discuter de ce changement ou en savoir plus, consultez le [ticket de dépréciation](https://gitlab.com/gitlab-org/gitlab/-/issues/513409).

> [!note]
> Ce changement a été annulé.

L'[analyseur SAST](https://docs.gitlab.com/user/application_security/sast/#supported-languages-and-frameworks) SpotBugs peut effectuer une compilation lorsque les artefacts à analyser ne sont pas présents. Bien que cela fonctionne généralement bien pour les projets simples, cela peut échouer sur des compilations plus complexes.

À partir de GitLab 18.0, pour résoudre les échecs de compilation de l'analyseur SpotBugs, vous devez :

1. [Précompiler](https://docs.gitlab.com/user/application_security/sast/#pre-compilation) le projet.
1. Transmettre les artefacts à analyser à l'analyseur.

Il ne s'agit pas d'un changement fonctionnel, c'est pourquoi nous avons marqué cette annonce comme « Annulée » par souci de clarté.

> [!disclaimer]
