---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Le scan de la logique métier utilise un agent d'IA pour détecter les vulnérabilités d'autorisation et de contrôle d'accès dans votre code source."
title: Scan de la logique métier
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed
- Statut : version bêta

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257199) dans GitLab 19.5 [avec des feature flags](../../../administration/feature_flags/_index.md) nommés `bl_security_analyzer` (type `experiment`) et `agentic_analyzer_security_ingestion` (type `gitlab_com_derisk`). Fonctionnalité désactivée par défaut.
- Le démarrage d'un scan depuis GitLab Duo Chat nécessite également le [feature flag](../../../administration/feature_flags/_index.md) nommé `duo_chat_flow_commands` (type `wip`). Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

L'analyse de la logique métier utilise un agent d'IA, le Business Logic Security Analyzer (BLSA), pour trouver des vulnérabilités dans la façon dont votre application applique ses propres règles. Les analyseurs basés sur des patterns tels que [SAST](../sast/_index.md) passent souvent à côté de ces vulnérabilités, car le code est valide et seule l'intention est incorrecte.

## Ce que le scan de la logique métier détecte {#what-business-logic-scanning-finds}

Le scan de la logique métier recherche des vulnérabilités telles que :

- Autorisation non fonctionnelle au niveau des objets (BOLA), également appelée références directes non sécurisées aux objets (IDOR). Par exemple, un endpoint charge une facture via l'identifiant présent dans l'URL, sans vérifier que la facture appartient à l'utilisateur authentifié.
- Autorisation manquante. Par exemple, une action administrative vérifie que l'utilisateur est authentifié, mais pas qu'il est administrateur.
- Assignation de masse. Par exemple, un endpoint de mise à jour transmet chaque paramètre de requête au modèle, ce qui permet à un utilisateur de modifier son propre attribut `role` ou `is_admin`.

## Fonctionnement du scan de la logique métier {#how-business-logic-scanning-works}

Le scan de la logique métier s'exécute en tant que flow par défaut de la [GitLab Duo Agent Platform](../../duo_agent_platform/_index.md), et non en tant que job dans votre pipeline CI/CD. Vous n'avez pas à ajouter de template ni de job à votre fichier `.gitlab-ci.yml`.

Un scan peut démarrer de l'une des façons suivantes :

| Mode de démarrage du scan | Ce qui est scanné | Comment l'activer |
|---------------------|---------------|-------------------|
| [Automatiquement sur les merge requests](#automatic-merge-request-scans) | Les fichiers ajoutés ou modifiés par la merge request. Un scan partiel. | Associer le profil de scan de la logique métier au projet. |
| [Depuis GitLab Duo Chat](#start-a-scan-from-gitlab-duo-chat) | L'intégralité du dépôt, sur la branche par défaut. La méthode recommandée pour scanner l'intégralité du dépôt. | Envoyer la commande de flow dans GitLab Duo Chat. |
| [Via l'API](#start-a-scan-with-the-api) | L'intégralité du dépôt, sur la branche par défaut. | Envoyer une requête API. |
| [Sur planification](#scheduled-default-branch-scans) | Pas encore disponible. | Pas encore disponible. |

## Activer le scan de la logique métier {#turn-on-business-logic-scanning}

L'analyse de la logique métier est en version bêta fermée. Sur GitLab.com, GitLab active les feature flags pour les groupes principaux participants. Pour demander l'accès, contactez votre équipe commerciale.

Prérequis :

- Un abonnement GitLab Ultimate.
- [GitLab Duo Agent Platform activée](../../duo_agent_platform/turn_on_off.md) pour le groupe principal.
- Les feature flags `bl_security_analyzer` et `agentic_analyzer_security_ingestion` sont activés pour le groupe principal. Sans `agentic_analyzer_security_ingestion`, les résultats de l'analyse n'apparaissent pas dans le rapport de vulnérabilités. Sur GitLab Self-Managed, un administrateur doit activer ces feature flags.

Pour activer le scan de la logique métier :

1. En tant qu'utilisateur disposant du rôle Propriétaire pour le groupe principal, [activez les flows par défaut](../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off), y compris le flow **Business Logic Security Scan**.
1. [Associez le profil de scan de la logique métier](../configuration/security_configuration_profiles.md#business-logic-profile) à chaque projet que vous souhaitez scanner. Tant que l'interface utilisateur du profil de scan n'est pas disponible, [associez le profil via l'API GraphQL](../configuration/security_configuration_profiles.md#apply-a-profile-with-the-graphql-api).

## Scans automatiques des merge requests {#automatic-merge-request-scans}

Lorsqu'un projet a le profil de scan de la logique métier associé, un scan s'exécute sur chaque merge request :

- Le scan s'exécute sur le pipeline head de la merge request : soit un pipeline de merge request, soit un pipeline de branche d'une merge request ouverte.
- Le scan démarre après la réussite du pipeline. Si le pipeline échoue, ou si le projet ne dispose d'aucun pipeline CI/CD, aucun scan ne s'exécute.
- Le scan vérifie uniquement les fichiers ajoutés ou modifiés par la merge request.
- L'utilisateur ayant exécuté le pipeline doit être un utilisateur humain disposant au minimum du rôle Developer et d'un accès à GitLab Duo Agent Platform.

Ces merge requests ne sont pas scannées :

- Les merge requests issues d'une duplication.
- Les merge requests qui suppriment uniquement des fichiers.
- Les merge requests dont le pipeline a été exécuté par un bot, comme un jeton d'accès au projet ou un compte de service.
- Les pipelines de merge train, et les pipelines de merge request remplacés par un commit plus récent.

Étant donné qu'un scan de merge request vérifie uniquement les fichiers modifiés, il s'agit d'un scan partiel, à l'instar du [scan basé sur les diffs](../sast/gitlab_advanced_sast.md#diff-based-scanning) de GitLab Advanced SAST. Les vulnérabilités présentes dans les fichiers non scannés ne sont pas signalées comme corrigées.

## Scans planifiés de la branche par défaut {#scheduled-default-branch-scans}

Les scans planifiés ne sont pas encore disponibles. Les scans automatiques ne s'exécutent pas sur la branche par défaut. Pour scanner la branche par défaut, [démarrez un scan depuis GitLab Duo Chat](#start-a-scan-from-gitlab-duo-chat) ou [via l'API](#start-a-scan-with-the-api).

## Démarrer un scan depuis GitLab Duo Chat {#start-a-scan-from-gitlab-duo-chat}

Pour scanner l'intégralité du dépôt, démarrez un scan depuis GitLab Duo Chat. Le scan vérifie la branche par défaut et s'exécute en tant que session GitLab Duo Agent Platform que vous pouvez suivre. Les résultats apparaissent dans le [rapport de vulnérabilités](../vulnerability_report/_index.md).

Prérequis :

- Vous devez disposer au minimum du rôle Developer pour le projet.
- Vous devez satisfaire aux [prérequis de GitLab Duo Agent Platform](../../duo_agent_platform/_index.md#prerequisites).
- Les feature flags `bl_security_analyzer`, `agentic_analyzer_security_ingestion` et `duo_chat_flow_commands` doivent être activés, et le flow **Business Logic Security Scan** doit être activé. Le projet n'a pas besoin du profil de scan de la logique métier.

Pour démarrer un scan :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Ouvrez [GitLab Duo Chat](../../gitlab_duo_chat/agentic_chat.md#use-gitlab-duo-chat-in-the-gitlab-ui) et assurez-vous que le bouton **Agentique** est activé.
1. Dans la zone de texte du chat, saisissez `/flow:` et sélectionnez **Business Logic Security Scan**.
1. Envoyez la commande sans aucun autre texte.
1. Suivez le scan dans la session de l'agent. Une fois la session terminée, les résultats apparaissent dans le rapport de vulnérabilités.

Le job CI/CD du scan s'exécute en tant que compte de service du flow.

> [!warning]
> N'ajoutez pas de numéro de merge request ni d'autre texte après la commande. Un scan depuis GitLab Duo Chat s'exécute toujours sur la branche par défaut et scanne donc l'intégralité du dépôt, et non les modifications de la merge request.

## Démarrer un scan via l'API {#start-a-scan-with-the-api}

Vous pouvez démarrer un scan complet de la branche par défaut avec l'[API des flows de GitLab Duo Agent Platform](../../../api/duo_agent_platform_flows.md#trigger-a-flow). Le scan s'exécute en votre nom, avec vos autorisations et votre accès à GitLab Duo Agent Platform, et vérifie l'intégralité du dépôt. Les résultats apparaissent dans le rapport de vulnérabilités.

Prérequis :

- Vous devez disposer au minimum du rôle Developer pour le projet.
- Vous devez disposer d'un jeton d'accès personnel avec la portée `api`.
- Les feature flags `bl_security_analyzer` et `agentic_analyzer_security_ingestion` doivent être activés, et le flow **Business Logic Security Scan** doit être activé. Le projet n'a pas besoin du profil de scan de la logique métier.

Pour démarrer un scan, envoyez une requête :

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --data "project_id=<project_id>" \
  --data "workflow_definition=bl_security/experimental" \
  --data "start_workflow=true" \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows"
```

Au lieu de `workflow_definition`, vous pouvez passer `ai_catalog_item_consumer_id` avec l'identifiant du consommateur du flow **Business Logic Security Scan** du projet. Pour obtenir l'identifiant, utilisez la requête GraphQL `aiCatalogConfiguredItems`, comme décrit dans [rechercher l'identifiant du consommateur](../../../api/duo_agent_platform_flows.md#look-up-the-consumer-id).

Pour scanner uniquement les fichiers modifiés par une merge request, passez l'IID de la merge request en tant que `goal`, et la branche source de la merge request en tant que `source_branch`. La merge request ne doit pas provenir d'une duplication. Sur toute branche autre que la branche par défaut, la variable CI/CD [`BL_TARGET_FILES`](#configure-a-scan), lorsqu'elle est définie, remplace les fichiers modifiés par la merge request. Dans le cas contraire, le scan vérifie l'intégralité du dépôt.

## Afficher les résultats {#view-results}

Le scan de la logique métier signale les vulnérabilités aux mêmes endroits que les autres scanners de sécurité :

- Dans le [widget de sécurité de la merge request](../detect/security_scanning_results.md#merge-request-reports), pour les scans de merge request.
- Dans le rapport de vulnérabilités, pour les scans de la branche par défaut.

## Configurer un scan {#configure-a-scan}

Pour modifier le fonctionnement du scan de la logique métier, ajoutez des [variables CI/CD de projet](../../../ci/variables/_index.md#for-a-project). Définissez la portée d'environnement sur **Tous (par défaut)**. Les variables avec d'autres portées sont ignorées.

Les variables protégées et de type fichier sont ignorées. Définissez ces variables comme des variables normales, non protégées, avec la portée d'environnement `*`.

| Variable CI/CD    | Description |
|-------------------|-------------|
| `BL_SCAN_EFFORT`  | Le niveau d'effort du scan : `low`, `standard` ou `high`. Lorsqu'il n'est pas défini, vide ou avec toute autre valeur, le niveau est `low`. Un niveau plus élevé effectue un scan plus approfondi et consomme davantage d'utilisation de GitLab Duo Agent Platform. |
| `BL_TARGET_FILES` | Une liste de chemins de fichiers à scanner, séparés par des sauts de ligne ou des virgules. S'applique aux scans sur toute branche autre que la branche par défaut, et remplace les fichiers modifiés par la merge request. Ignoré sur la branche par défaut, de sorte que les scans de la branche par défaut vérifient l'intégralité du dépôt. |

Le scan lit ces variables depuis les paramètres CI/CD du projet lors de son démarrage. Les variables définies dans `.gitlab-ci.yml` ou lors de l'exécution d'un pipeline ne s'appliquent pas.

## Problèmes connus {#known-issues}

Le scan de la logique métier présente les problèmes connus suivants :

- Lorsqu'une merge request modifie plus de 400 fichiers, ou que son diff est trop volumineux pour être collecté, le scan ne se limite pas aux fichiers modifiés. Il effectue à la place un scan complet du dépôt, et le résultat n'est pas un scan partiel.
- Un scan analyse jusqu'à une quantité fixe de code. Un scan qui atteint cette limite est tout de même comptabilisé comme un scan complet. Les vulnérabilités présentes dans le code ignoré par le scan peuvent être marquées comme non détectées, et réapparaître lors d'un scan ultérieur.
- Les scans s'exécutent uniquement lorsque les feature flags requis dans les prérequis sont activés. Les scans automatiques s'exécutent uniquement pour les utilisateurs décrits dans [les scans automatiques des merge requests](#automatic-merge-request-scans).
- Les scans planifiés ne sont pas encore disponibles. Pour plus de détails, consultez [les scans planifiés de la branche par défaut](#scheduled-default-branch-scans).
- Un scan depuis GitLab Duo Chat s'exécute toujours sur la branche par défaut. Si vous ajoutez un numéro de merge request ou tout autre texte après la commande de flow, le scan vérifie tout de même l'intégralité du dépôt. Il ne vérifie pas les modifications de la merge request. Envoyez la commande sans aucun autre texte. Pour scanner les modifications d'une merge request, [utilisez l'API](#start-a-scan-with-the-api).

## Coût {#cost}

Chaque scan est une session GitLab Duo Agent Platform et consomme des [GitLab Credits](../../../subscriptions/gitlab_credits.md). Le scan d'une grande merge request ou d'un dépôt entier consomme plus qu'un scan d'une petite modification.
