---
stage: Security
group: Security Operations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Comprenez la télémétrie de sécurité que GitLab produit et comment la collecter sur GitLab.com, GitLab Self-Managed et GitLab Dedicated."
title: Télémétrie de sécurité
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

La télémétrie de sécurité correspond aux données que vous collectez depuis GitLab pour détecter et investiguer les incidents de sécurité.

L'équipe GitLab Security Operations a rédigé ces recommandations à l'intention des administrateurs des instances GitLab Self-Managed et GitLab Dedicated, ainsi que des propriétaires d'espaces de nommage sur GitLab.com. Utilisez-les pour comprendre les types de télémétrie de sécurité que GitLab produit, ce que chacun vous indique et ce que vous pouvez collecter selon votre offre et votre édition d'abonnement. Elles complètent les processus de journalisation et de surveillance définis par votre organisation, mais ne les remplacent pas.

Lorsqu'une détection se déclenche, suivez les étapes de [réponse aux incidents de sécurité](responding_to_security_incidents.md) pour contenir et résoudre l'incident.

> [!warning]
> Utilisez ces suggestions et recommandations à vos propres risques. La télémétrie disponible dépend de votre offre, de votre édition d'abonnement et de votre configuration.

## Types de télémétrie de sécurité {#kinds-of-security-telemetry}

GitLab produit deux grands types de télémétrie de sécurité. Ils répondent à des questions différentes et sont collectés de différentes manières ; utilisez donc les deux dans la mesure du possible.

[Événements d'audit](../user/compliance/audit_events.md) : événements structurés que GitLab émet lorsqu'une action pertinente pour la sécurité se produit : un utilisateur se connecte, une permission change, un jeton est créé, un paramètre est modifié. Chaque événement enregistre qui l'a effectué, ce qui a été affecté, depuis quelle adresse IP et à quel moment. Les événements d'audit répondent à la question « Que font les utilisateurs dans GitLab ? » GitLab définit plusieurs centaines de [types d'événements d'audit](../user/compliance/audit_event_types.md).

[Journaux d'application](../administration/logs/_index.md) : fichiers journaux écrits par l'application GitLab Rails et les composants qui l'entourent : Workhorse, Gitaly, GitLab Shell et Sidekiq. Ils enregistrent chaque requête HTTP, opération Git et job en arrière-plan. Une grande partie de cette activité ne donne jamais lieu à un événement d'audit : les requêtes échouées et bloquées, les requêtes vers des points de terminaison non audités, les paramètres exacts d'une requête et les étapes internes que GitLab a suivies pour la traiter. Les journaux d'application répondent à la question « Que s'est-il passé dans GitLab ? » et constituent la seule source permettant de détecter les tentatives d'exploitation contre GitLab lui-même.

En dehors de ces deux types, plusieurs fonctionnalités GitLab enregistrent leurs propres données pertinentes pour la sécurité, telles que les job logs CI/CD et l'inventaire des identifiants. Pour plus d'informations, consultez [les autres sources de données de sécurité](#other-sources-of-security-data).

## Ce que vous pouvez collecter selon votre offre et votre édition {#what-you-can-collect-on-your-offering-and-tier}

Le tableau suivant indique l'édition minimale requise pour chaque méthode de collecte de la télémétrie de sécurité, selon chaque offre. GitLab Dedicated est disponible uniquement avec l'édition Ultimate ; tout ce qui figure dans ce tableau est donc disponible sur GitLab Dedicated.

| Méthode de collecte | GitLab.com | GitLab Self-Managed | GitLab Dedicated |
|-------------------|------------|---------------------|------------------|
| Afficher les événements d'audit dans GitLab ou les récupérer via l'API | GitLab Premium | GitLab Premium | Oui |
| Diffuser les événements d'audit vers un système de gestion des informations et des événements de sécurité (SIEM) ou vers une autre destination | GitLab Ultimate | GitLab Ultimate | Oui |
| Collecter les journaux d'application | Non disponible. GitLab exploite et conserve ces journaux. | Toutes les éditions | Oui |

En pratique, cela signifie :

- Avec l'édition Gratuite, vous pouvez consulter vos propres événements de connexion et examiner les job logs CI/CD, mais vous ne pouvez pas afficher les événements d'audit de groupe, de projet ou d'instance. Sur GitLab Self-Managed, vous pouvez toujours collecter les journaux d'application, qui incluent un petit nombre d'événements d'audit écrits dans `audit_json.log`.
- Avec l'édition Premium, vous pouvez afficher et rechercher des événements d'audit dans GitLab et les récupérer via l'API, mais vous ne pouvez pas les diffuser. Vous n'êtes pas sans savoir ce qui se passe dans GitLab, mais la détection et la rétention à long terme vous incombent.
- Avec l'édition Ultimate, vous pouvez diffuser les événements d'audit vers votre SIEM en quasi-temps réel et recevoir les événements réservés à la diffusion qui ne sont jamais affichés dans GitLab.

## Afficher les événements d'audit {#view-audit-events}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Avec les éditions Premium et Ultimate, vous pouvez afficher les événements d'audit sans aucune configuration :

- Dans l'interface de GitLab, au [niveau du groupe, du projet et de l'instance](../administration/compliance/audit_event_reports.md). Les événements d'audit au niveau de l'instance sont disponibles sur GitLab Self-Managed et GitLab Dedicated.
- Avec l'[API des événements d'audit](../api/audit_events.md), qui renvoie les mêmes événements que l'interface.

Avec l'édition Gratuite, les seuls événements d'audit que vous pouvez consulter sont vos propres [événements de connexion](../user/compliance/audit_events.md#sign-in-audit-events), dans le **Journal d'authentification** de votre profil utilisateur.

La consultation des événements d'audit est suffisante pour des vérifications ponctuelles et pour investiguer un utilisateur ou un projet spécifique après coup. Elle n'est pas suffisante pour la détection, pour plusieurs raisons :

- Chaque requête est limitée à une fenêtre de 30 jours, et l'interface ne permet pas de rechercher dans les détails des événements.
- Certains types d'événements sont [réservés à la diffusion](#streaming-only-events) et ne sont jamais affichés dans GitLab.
- Vous ne pouvez pas créer d'alertes sur les événements, les corréler avec d'autres données, ni contrôler leur durée de rétention.

Si vous ne pouvez pas diffuser les événements d'audit, vous pouvez les récupérer depuis l'API selon un planning et les charger dans votre plateforme de journalisation. Cela vous fournit une copie consultable et une base pour les détections, mais avec un délai et sans les événements réservés à la diffusion.

## Diffuser les événements d'audit {#stream-audit-events}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

La diffusion des événements d'audit envoie chaque événement d'audit vers une destination que vous contrôlez dès qu'il se produit, afin que votre SIEM dispose d'un enregistrement complet en quasi-temps réel. La diffusion est la méthode recommandée pour collecter les événements d'audit sur chaque offre, et le seul moyen de recevoir les événements réservés à la diffusion.

### Événements réservés à la diffusion {#streaming-only-events}

Certains types d'événements d'audit sont réservés à la diffusion : ils ne sont pas enregistrés dans GitLab et vous ne les recevez que si vous disposez d'une destination de diffusion. Beaucoup d'entre eux enregistrent les accès en lecture à des données sensibles, ce qui les rend particulièrement utiles pour la détection. Voici quelques exemples :

| Événement réservé à la diffusion | Ce qu'il vous indique |
|----------------------|-------------------|
| `repository_git_operation` | Qui a cloné, récupéré (fetch) ou poussé (push) vers un dépôt |
| `repository_file_accessed_api` et `repository_file_accessed_web` | Qui a lu un fichier via l'API ou l'interface web |
| `job_artifact_downloaded` | Qui a téléchargé un artefact de job CI/CD |
| `variable_viewed_api` et `variable_viewed_graphql` | Qui a lu une variable CI/CD |
| `personal_access_token_used_from_unseen_ip` | Un jeton a été utilisé depuis une adresse IP jamais vue auparavant |
| `user_authenticated_using_job_token` | Un jeton de job CI/CD a été utilisé pour s'authentifier |

Cette liste n'est pas exhaustive. Pour tous les événements réservés à la diffusion, consultez la colonne **Saved to database** dans la liste des [types d'événements d'audit disponibles](../user/compliance/audit_event_types.md#available-audit-event-types).

### Configurer la diffusion {#set-up-streaming}

L'endroit où vous configurez la diffusion dépend de votre offre :

| Offre | Qui la configure | Portée | Plus d'informations |
|----------|-------------------|-------|------------------|
| GitLab.com | Propriétaire d'un groupe principal | Le groupe principal, ses sous-groupes et ses projets | [Flux d'événements d'audit pour les groupes principaux](../user/compliance/audit_event_streaming.md) |
| GitLab Self-Managed et GitLab Dedicated | Administrateur | L'ensemble de l'instance. Vous pouvez également le configurer par groupe principal pour des destinations différentes au sein de votre organisation. | [Flux d'événements d'audit pour les instances](../administration/compliance/audit_event_streaming.md) |

La diffusion prend en charge trois types de destinations : un point de terminaison HTTP, Google Cloud Logging et Amazon S3. Vous pouvez ajouter plusieurs destinations et [filtrer chacune par type d'événement](../user/compliance/audit_event_streaming.md#update-event-filters).

Lorsque vous concevez le côté récepteur :

- Anticipez les livraisons en double occasionnelles et déduplication sur l'`id` de l'événement.
- Sur GitLab.com, autorisez le trafic provenant de la [plage d'adresses IP de GitLab.com](../user/gitlab_com/_index.md#ip-range) vers votre destination.
- Traitez la destination comme sensible. Les événements diffusés contiennent tous les détails de l'événement.
- Vérifiez les [limites de destination](../administration/instance_limits.md#audit-events-streaming-destination-limits) si vous prévoyez un grand nombre de destinations.

## Collecter les journaux d'application {#collect-application-logs}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les événements d'audit vous indiquent qu'une action s'est produite. Les journaux d'application vous indiquent comment. Ils vous fournissent des détails au niveau de la requête que les événements d'audit résument, et ils enregistrent une grande quantité d'activités pertinentes pour la sécurité qui ne donnent lieu à aucun événement d'audit, telles que les requêtes échouées, les requêtes soumises à des limites de débit, les requêtes vers des points de terminaison non audités et les paramètres complets de chaque requête. Si vous pouvez collecter les journaux d'application, collectez-les.

### Journaux pertinents pour la sécurité {#security-relevant-logs}

Les journaux suivants sont les plus pertinents pour la surveillance de la sécurité. Les chemins sont relatifs à `/var/log/gitlab/` sur les installations de packages Linux. La documentation sur le [système de journalisation](../administration/logs/_index.md#accessing-logs-on-helm-chart-installations) explique où trouver les mêmes journaux sur les installations de charts Helm.

| Journal | Ce qu'il enregistre | Utilisation pour la détection |
|-----|-----------------|------------------|
| [`gitlab-rails/production_json.log`](../administration/logs/_index.md#production_jsonlog) | Chaque requête traitée par l'application web : utilisateur, IP, chemin, statut, paramètres. | Flux de connexion suspects, modifications de paramètres, tentatives d'exploitation contre les points de terminaison web. |
| [`gitlab-rails/api_json.log`](../administration/logs/_index.md#api_jsonlog) | Chaque requête d'API REST : utilisateur, IP, route, statut, paramètres. | Abus de jetons, accès massif aux données via l'API, automatisation par un compte compromis. |
| [`gitlab-rails/graphql_json.log`](../administration/logs/_index.md#graphql_jsonlog) | Requêtes GraphQL et leur complexité. | Énumération et accès massif aux données via GraphQL. |
| [`gitlab-rails/auth_json.log`](../administration/logs/_index.md#auth_jsonlog) | Requêtes bloquées par les limites de débit et les règles de chemin protégé. | Attaques par force brute et credential stuffing. |
| [`gitlab-rails/audit_json.log`](../administration/logs/_index.md#audit_jsonlog) | Événements d'audit écrits dans un fichier. | Une copie locale des événements d'audit, y compris pour les éditions ne pouvant pas effectuer de diffusion. |
| [`gitlab-rails/application_json.log`](../administration/logs/_index.md#application_jsonlog) | Événements d'instance tels que la création d'utilisateurs et la suppression de projets. | Modifications du cycle de vie des comptes et des projets. |
| [`gitlab-shell/gitlab-shell.log`](../administration/logs/_index.md#gitlab-shelllog) | Opérations Git via SSH : utilisateur, projet, commande. | Clonage et push de dépôt via SSH, y compris par des clés de déploiement. |
| [`gitlab-workhorse/current`](../administration/logs/_index.md#workhorse-logs) | Journal d'accès HTTP pour tout le trafic, y compris Git via HTTPS et les téléchargements de fichiers. | Clonage de dépôt via HTTPS, téléchargements d'artefacts et d'exports, analyse web. |
| [`gitaly/current`](../administration/logs/_index.md#gitaly-logs) | Opérations sur les dépôts et hooks Git. | Schémas d'accès inhabituels aux dépôts, échecs de hooks. |
| [`sidekiq/current`](../administration/logs/_index.md#sidekiq-logs) | Jobs en arrière-plan : imports, exports, mises à jour de miroirs, notifications. | Exports de projets et configuration de miroirs utilisés pour l'exfiltration. |

### Suivre une requête dans les journaux {#follow-a-request-across-logs}

Chaque requête traitée par GitLab reçoit un identifiant de corrélation, et le même identifiant apparaît dans chaque journal que la requête touche, de Workhorse à Rails, en passant par Gitaly et Sidekiq. Lorsque vous trouvez une entrée suspecte dans un journal, recherchez son identifiant de corrélation dans tous les journaux pour reconstruire la requête complète. Pour plus d'informations, consultez [trouver les entrées de journal pertinentes avec un identifiant de corrélation](../administration/logs/tracing_correlation_id.md).

### Envoyer les journaux d'application vers votre plateforme {#ship-application-logs-to-your-platform}

Sur GitLab Self-Managed : envoyez les journaux de chaque nœud vers votre plateforme de journalisation à l'aide du collecteur de journaux de votre choix. GitLab effectue une rotation des journaux localement et supprime éventuellement les anciens fichiers ; envoyez-les donc avant que la rotation ne les supprime. Pour ajuster la rotation, consultez la [configuration de la journalisation](https://docs.gitlab.com/omnibus/settings/logs/). Dans les déploiements multi-nœuds, assurez-vous que votre plateforme agrège les journaux de chaque nœud afin qu'une recherche par identifiant de corrélation couvre l'ensemble de la requête.

Sur GitLab Dedicated : GitLab livre les journaux d'application et d'infrastructure vers un compartiment Amazon S3 dans votre compte AWS et les conserve pendant un an. Accordez à votre collecteur de journaux un accès en lecture au compartiment dans Switchboard ; si vous avez besoin des journaux pendant plus d'un an, copiez-les vers votre propre stockage. Pour les étapes de configuration, consultez [les journaux d'application pour GitLab Dedicated](../administration/dedicated/monitor.md).

## Autres sources de données de sécurité {#other-sources-of-security-data}

En dehors des événements d'audit et des journaux d'application, plusieurs fonctionnalités GitLab enregistrent des données pertinentes pour la sécurité que vous pouvez consulter directement ou intégrer à vos détections. La plupart d'entre elles sont disponibles dans l'interface GitLab sans aucune configuration de collecte, et plusieurs sont disponibles sur toutes les éditions.

| Source de données | Disponibilité | Ce qu'elle affiche |
|-------------|--------------|---------------|
| [Événements d'audit de connexion](../user/compliance/audit_events.md#sign-in-audit-events) | Toutes les éditions | Connexions réussies pour un utilisateur, dans le **Journal d'authentification** du profil utilisateur. Les seuls événements d'audit disponibles avec l'édition Gratuite. |
| [Job logs CI/CD](../ci/jobs/job_logs.md) | Toutes les éditions | Commandes exécutées, secrets exposés et pipelines démarrés par un utilisateur inattendu. Pour le stockage et la rétention, consultez [l'administration des job logs](../administration/cicd/job_logs.md). |
| [Journal d'authentification par jeton de job](../ci/jobs/ci_job_token.md#job-token-authentication-log) | Toutes les éditions | Projets qui se sont authentifiés auprès d'un projet avec un jeton de job CI/CD. |
| [Inventaire des identifiants](../administration/credentials_inventory.md) | GitLab Ultimate | Jetons d'accès personnels, de groupe et de projet, clés SSH et clés GPG présents dans votre instance ou votre groupe principal, avec leurs portées et dates d'expiration. |
| [Protection contre les push de secrets](../user/application_security/secret_detection/secret_push_protection/_index.md) et [détection des secrets dans les pipelines](../user/application_security/secret_detection/_index.md) | Protection contre les push de secrets : Ultimate. Détection des secrets dans les pipelines : Toutes les éditions. | Secrets que les utilisateurs tentent de pousser (push), ou qui ont été commités dans un dépôt. |

<!-- Keep this table in sync with the detection data sources table on detecting_security_incidents.md. -->

## Étapes suivantes {#next-steps}

Une fois que votre télémétrie parvient à votre SIEM ou à votre plateforme de journalisation :

- Pour décider quels signaux surveiller et déployer les règles de détection TLDR, consultez [Construire une capacité de détection](detecting_security_incidents.md#build-a-detection-capability).
- Confirmez que les types d'événements sur lesquels reposent vos détections parviennent bien à votre plateforme, en particulier les événements réservés à la diffusion. Si vous collectez les événements d'audit via l'API plutôt que par diffusion, vérifiez quelles détections dépendent des événements que vous ne recevez pas.
- Définissez une période de rétention qui répond à vos besoins d'investigation et de conformité. GitLab conserve les événements d'audit stockés indéfiniment, mais votre destination de diffusion et votre plateforme de journalisation définissent ce que vous pouvez réellement rechercher.

## Sujets connexes {#related-topics}

- [Incidents de sécurité](security_incidents.md)
- [Sécuriser GitLab](_index.md)
