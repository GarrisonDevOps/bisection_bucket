---
stage: Security
group: Security Operations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Détection des incidents de sécurité
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Plus tôt vous détectez un incident de sécurité potentiel, plus vous pouvez en limiter l'impact.

L'équipe GitLab Security Operations a rédigé ces recommandations à l'intention des administrateurs et des mainteneurs des instances GitLab Self-Managed et des groupes sur GitLab.com. Utilisez-les pour développer une couverture de détection des activités relatives à la sécurité dans GitLab et pour identifier les signaux indiquant un incident de sécurité potentiel. Ils complètent les processus de détection et de surveillance définis par votre organisation, sans les remplacer.

Lorsque vous confirmez un incident, suivez [la procédure de réponse aux incidents de sécurité](responding_to_security_incidents.md) pour le contenir et y remédier.

> [!warning]
> Utilisez ces suggestions et recommandations à vos propres risques. La couverture de détection dépend de votre configuration, de votre édition d'abonnement et des outils de journalisation et de surveillance présents dans votre environnement.

## Développer une capacité de détection {#build-a-detection-capability}

Une détection efficace combine des sources de données fiables, un emplacement centralisé pour les analyser et des règles affinées qui transforment l'activité brute en alertes exploitables.

### Sources de données de détection {#detection-data-sources}

GitLab produit plusieurs sources de données relatives à la sécurité que vous pouvez utiliser pour détecter les activités suspectes :

| Source de données | Disponibilité | Ce qu'elle affiche |
|-------------|--------------|---------------|
| [Événements d'audit](../administration/compliance/audit_event_reports.md) | GitLab Premium, GitLab Ultimate | Authentification, modifications des permissions et modifications des projets, groupes et paramètres. La principale source pour détecter les incidents de sécurité dans GitLab. Pour la liste complète, voir [les types d'événements d'audit](../user/compliance/audit_event_types.md). |
| [Événements d'audit de connexion](../user/compliance/audit_events.md#sign-in-audit-events) | Toutes les éditions | Connexions réussies pour un utilisateur, dans le **Journal d'authentification** du profil utilisateur. |
| [Journaux système](../administration/logs/_index.md) | Toutes les éditions, GitLab Self-Managed uniquement | Journaux d'application, d'API, d'authentification et Workhorse. Utilisez l'[ID de corrélation](../administration/logs/tracing_correlation_id.md) pour tracer une requête unique sur plusieurs journaux. |
| [Job logs CI/CD](../ci/jobs/job_logs.md) | Toutes les éditions | Secrets exposés, commandes inattendues ou activité de pipeline initiée par un attaquant. |
| [Inventaire des identifiants](../administration/credentials_inventory.md) | GitLab Ultimate | Jetons d'accès personnels, de groupe et de projet, clés SSH et clés GPG présents dans votre instance ou votre groupe principal. |
| [Protection contre le push de secrets](../user/application_security/secret_detection/secret_push_protection/_index.md) et [détection des secrets](../user/application_security/secret_detection/_index.md) | Protection contre le push de secrets : GitLab Ultimate. Détection des secrets dans les pipelines : Toutes les éditions. | Secrets que les utilisateurs tentent de pousser ou qui ont été commités dans un dépôt. |

Pour plus d'informations sur le contenu de chaque source et sur la manière de la collecter pour chaque offre et édition d'abonnement, consultez la [télémétrie de sécurité](security_telemetry.md).

Pour détecter les authentifications suspectes, telles que des connexions depuis des emplacements inattendus ou des modifications de l'authentification à deux facteurs, consultez les [événements d'audit d'accès système](../user/compliance/audit_event_types.md#system-access).

### Centraliser et diffuser les événements vers un SIEM {#centralize-and-stream-events-to-a-siem}

Pour détecter les incidents en quasi temps réel et conserver les événements à des fins d'investigation, centralisez vos données dans un système de gestion des informations et des événements de sécurité (SIEM) ou une autre plateforme d'analyse de journaux :

- Diffusez les événements d'audit vers une destination externe.
  - GitLab Self-Managed et GitLab Dedicated : [Flux d'événements d'audit pour les instances](../administration/compliance/audit_event_streaming.md) 
  - GitLab.com : [Flux d'événements d'audit pour les groupes principaux](../user/compliance/audit_event_streaming.md)
- Si vous ne diffusez pas les événements, vous pouvez les collecter selon un calendrier défini à l'aide de l'[API des événements d'audit](../api/audit_events.md).
- Acheminez les journaux et les événements vers un datastore indépendant en écriture unique (immuable) afin qu'un attaquant ne puisse pas les modifier ou les supprimer.
- Définissez une période de rétention qui répond à vos exigences d'investigation et de conformité avant d'avoir besoin des données.

### Utiliser les règles de détection GitLab {#use-the-gitlab-detection-rules}

L'équipe GitLab Security Operations maintient [TLDR](https://gitlab.com/gitlab-security-oss/tldr) (Threat, Logs, Detection, Respond), un framework de détection open source pour les environnements GitLab.

Chaque détection TLDR inclut différents types d'informations :

- Détails de la menace : une description de la menace ainsi que son impact technique et métier.
- Journaux : les sources de journaux requises par la détection, avec des exemples d'événements.
- Détection : une règle au format général [Sigma](https://github.com/SigmaHQ/sigma) et une requête de journal brute pour les environnements sans SIEM.
- Test atomique : les étapes pour reproduire l'activité, afin de confirmer que la détection se déclenche.
- Réponse : des conseils sur la manière de gérer un vrai positif.

Les détections sont regroupées en deux types :

- Détections de menaces : activité suspecte ou malveillante enregistrée dans les événements d'audit, telle que la désactivation de l'authentification à deux facteurs, la création de nouveaux comptes administrateur, de nouvelles clés de déploiement ou de jetons d'accès au projet, et les modifications des paramètres d'approbation des merge requests ou des branches protégées.
- Détections de vulnérabilités : tentatives d'exploitation de vulnérabilités connues dans GitLab Self-Managed, enregistrées dans les journaux d'application.

Pour utiliser ces détections :

1. Ingérez les sources de journaux répertoriées dans chaque détection dans votre SIEM.
1. Convertissez les règles Sigma dans le langage de requête de votre SIEM. Utilisez l'outil officiel [Sigma CLI](https://github.com/SigmaHQ/sigma-cli) ou l'outil web [sigconverter.io](https://sigconverter.io/).
1. Déployez d'abord les règles converties en mode surveillance uniquement et examinez le volume d'alertes.
1. Affinez les règles pour les adapter à votre environnement avant d'acheminer les alertes vers les intervenants d'astreinte.

### Cartographier la couverture et affiner les détections {#map-coverage-and-tune-detections}

Après avoir déployé des détections, examinez-les régulièrement pour qu'elles restent précises et couvrent les menaces qui importent à votre organisation :

- Mappez vos détections sur un framework tel que [MITRE ATT&CK](https://attack.mitre.org/) pour comprendre quelles techniques adversariales vous pouvez détecter et où vous avez des lacunes.
- Établissez une base de référence de l'activité normale dans votre environnement afin que les alertes se concentrent sur les déviations significatives.
- Affinez les règles trop sensibles afin que les alertes de gravité élevée restent fiables.
- Testez que chaque détection se déclenche comme prévu et documentez le comportement attendu pour chaque règle. Chaque détection TLDR inclut un test atomique que vous pouvez utiliser à cet effet.

## Que détecter, par scénario {#what-to-detect-by-scenario}

La plupart des scénarios suivants correspondent aux [scénarios d'incidents de sécurité courants](responding_to_security_incidents.md#common-security-incident-scenarios) pour la réponse aux incidents. Pour chaque scénario, surveillez les signaux répertoriés. Lorsqu'une détection se déclenche et que vous confirmez un incident, suivez les étapes de réponse associées.

Le tableau suivant associe chaque scénario à des exemples de techniques MITRE ATT&CK. Utilisez ces mappages comme point de départ et adaptez-les à votre propre modèle de menace.

| Scénario | Signaux clés | Exemples de techniques MITRE ATT&CK |
|----------|-------------|---------------------------------|
| [Exposition des identifiants et abus de jetons](#credential-exposure-and-token-abuse) | Nouveaux jetons, clés ou utilisateurs, et modifications de variables CI/CD | T1552 Unsecured Credentials, T1078 Valid Accounts, T1136 Create Account |
| [Compte utilisateur compromis](#compromised-user-account) | Connexions inhabituelles, modifications de l'authentification à deux facteurs, nouvelles applications OAuth | T1078 Valid Accounts, T1110 Brute Force, T1098 Account Manipulation, T1556 Modify Authentication Process |
| [Abus CI/CD](#cicd-abuse) | Modifications de la configuration de pipeline, des variables ou des runners | T1195.002 Compromise Software Supply Chain, T1552 Unsecured Credentials |
| [Instance compromise](#compromised-instance) | Nouveaux administrateurs, activité de l'utilisateur root, indicateurs au niveau de l'hôte | T1078 Valid Accounts, T1098 Account Manipulation, T1136 Create Account |
| [Paramètres de projet ou de groupe mal configurés](#misconfigured-project-or-group-settings) | Modifications de la visibilité, des approbations et des branches protégées | T1685 Disable or Modify Tools, T1485 Data Destruction |
| [Exfiltration de données](#data-exfiltration) | Clones en masse, exports de projets, nouvelles clés de déploiement ou nouveaux jetons | T1213.003 Code Repositories, T1567 Exfiltration Over Web Service |
| [Abus et utilisation abusive des ressources](#abuse-and-resource-misuse) | Pics de consommation de ressources de calcul, création massive de nouveaux comptes, opérations Git excessives | T1496 Resource Hijacking, T1136 Create Account |

### Exposition des identifiants et abus de jetons {#credential-exposure-and-token-abuse}

Surveillez les activités qui suggèrent qu'un jeton, une clé ou un autre identifiant a été exposé ou utilisé de manière abusive :

- Création de jetons d'accès personnels, de projet ou de groupe, notamment par des utilisateurs inattendus.
- Création de clés SSH ou GPG.
- Création de nouveaux comptes utilisateur que les adversaires pourraient utiliser pour maintenir leur persistance.
- Modifications apportées aux [variables CI/CD](../ci/variables/_index.md) ou à d'autres configurations stockant des secrets. Concentrez-vous sur les [événements d'audit d'intégration continue](../user/compliance/audit_event_types.md#continuous-integration).
- Pipelines exécutés par un utilisateur inattendu. Consultez les [job logs](../administration/cicd/job_logs.md) pour plus de détails.

Pour répondre à cet incident, voir [exposition des identifiants sur l'internet public](responding_to_security_incidents.md#credential-exposure-to-public-internet).

### Compte utilisateur compromis {#compromised-user-account}

Surveillez les signaux indiquant qu'un compte est utilisé par quelqu'un d'autre que son propriétaire :

- Événements de connexion suspects, tels que ceux provenant d'adresses IP, d'emplacements ou d'appareils inattendus.
- Création ou suppression de jetons d'accès personnels, de projet ou de groupe.
- Création ou suppression de clés SSH ou GPG.
- Modifications des paramètres d'authentification à deux facteurs.
- Modifications des adresses e-mail ou des paramètres de notification.
- Ajout ou modification d'applications OAuth autorisées.
- Modifications des fournisseurs d'identité SAML connectés.

Pour répondre à cet incident, voir [compte utilisateur présumé compromis](responding_to_security_incidents.md#suspected-compromised-user-account).

### Abus CI/CD {#cicd-abuse}

Surveillez les modifications susceptibles d'exposer des secrets ou de permettre à un attaquant d'exécuter du code dans vos pipelines :

- Modifications des fichiers de configuration CI/CD ou des définitions de pipeline.
- Modifications des variables CI/CD, notamment les paramètres de [masquage](../ci/variables/_index.md#mask-a-cicd-variable) et de protection.
- Modifications rendant les pipelines ou les artefacts de job accessibles au public.
- Enregistrement de nouveaux runners ou modifications apportées aux runners existants.
- Utilisation inattendue du [jeton de job CI/CD](../ci/jobs/ci_job_token.md#gitlab-cicd-job-token-security).

Pour répondre à cet incident, voir [les incidents de sécurité liés au CI/CD](responding_to_security_incidents.md#cicd-related-security-incidents).

### Instance compromise {#compromised-instance}

Pour GitLab Self-Managed, surveillez les signaux au niveau de l'instance et au niveau de l'hôte :

- Événements d'audit d'accès système indiquant des modifications des paramètres système, des permissions utilisateur ou des événements de connexion.
- Création de nouveaux comptes administrateur ou activité de l'utilisateur root administratif.
- Indicateurs au niveau de l'hôte tels que des processus d'arrière-plan non reconnus, des ports ouverts inattendus ou un trafic réseau inhabituel.

Pour répondre à cet incident, voir [instance présumée compromise](responding_to_security_incidents.md#suspected-compromised-instance).

### Paramètres de projet ou de groupe mal configurés {#misconfigured-project-or-group-settings}

Surveillez les modifications susceptibles d'exposer des données ou d'affaiblir les contrôles d'accès :

- Modifications de la visibilité d'un projet ou d'un groupe.
- Modifications des paramètres d'approbation des merge requests.
- Suppressions de projets.
- Ajout de webhooks suspects ou de [hooks serveur](../administration/server_hooks.md).
- Modifications des paramètres des branches protégées.

Filtrez les événements d'audit par le champ `target_type` pour affiner votre recherche et consultez les événements d'audit de [gestion de la conformité](../user/compliance/audit_event_types.md#compliance-management) et des [groupes et projets](../user/compliance/audit_event_types.md#groups-and-projects).

Pour répondre à cet incident, voir [paramètres de projet ou de groupe mal configurés](responding_to_security_incidents.md#misconfigured-project-or-group-settings).

### Exfiltration de données {#data-exfiltration}

Surveillez les signes indiquant que du code source ou d'autres données sont copiés hors de GitLab, souvent après qu'un attaquant a obtenu un accès via un compte ou un jeton compromis :

- Nombreux téléchargements ou clones de dépôt par un seul utilisateur ou jeton sur une courte période.
- Exports de projets ou de groupes et téléchargements de fichiers d'export, notamment par des utilisateurs qui ne les effectuent pas habituellement.
- Nouvelles clés de déploiement ou nouveaux jetons de déploiement, qui donnent un accès de longue durée aux dépôts.
- Téléchargements d'artefacts de job par des utilisateurs inattendus.
- Modifications rendant des projets ou groupes privés publics.
- Jetons d'accès personnels utilisés depuis une adresse IP jusqu'alors inconnue.

Pour répondre à cet incident, révoquez les identifiants concernés en suivant la procédure d'[exposition des identifiants sur l'internet public](responding_to_security_incidents.md#credential-exposure-to-public-internet), et suivez le processus de réponse aux incidents défini par votre organisation.

### Abus et utilisation abusive des ressources {#abuse-and-resource-misuse}

Surveillez les abus automatisés et la consommation inattendue de ressources, tels que le minage de cryptomonnaie dans le CI/CD :

- Pics d'activité de pipeline, de minutes de calcul ou de nouveaux enregistrements de runners.
- Vagues de création de nouveaux comptes.
- Opérations Git excessives. Avec GitLab Ultimate, vous pouvez configurer la [limite de débit des abus Git](../user/group/reporting/git_abuse_rate_limit.md) pour atténuer automatiquement certains de ces comportements.

Pour répondre à cet incident, suivez le processus de réponse aux incidents défini par votre organisation et consultez les [recommandations de renforcement](hardening.md).

## Lorsqu'une détection se déclenche {#when-a-detection-fires}

Lorsqu'une détection déclenche une alerte, triez-la pour confirmer si un incident de sécurité est en cours :

1. Préservez les preuves. Enregistrez les journaux et événements d'audit pertinents dans un emplacement en écriture unique pour une investigation ultérieure.
1. Déterminez le périmètre, notamment les utilisateurs, projets, groupes, jetons ou hôtes concernés.
1. Suivez les étapes de réponse associées au scénario correspondant pour contenir et remédier à l'incident.
1. Suivez le processus de réponse aux incidents défini par votre organisation.

## Faire appel à GitLab pour obtenir de l'aide {#engaging-gitlab-for-assistance}

Avant de demander de l'aide à GitLab, consultez la [documentation GitLab](https://docs.gitlab.com). Contactez le support GitLab après avoir effectué une investigation préliminaire et si vous avez encore des questions ou si vous avez besoin d'aide. L'éligibilité à l'assistance du support GitLab est [déterminée par votre licence](https://support.gitlab.com/hc/en-us/articles/11626483177756-GitLab-Support#gitlab-support-service-levels).

## Sujets connexes {#related-topics}

- [Incidents de sécurité](security_incidents.md)
- [Télémétrie de sécurité](security_telemetry.md)
- [Sécuriser GitLab](_index.md)
- [Types d'événements d'audit](../user/compliance/audit_event_types.md)
