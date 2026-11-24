---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Dépannage de l'application GitLab pour Slack"
description: "Guide de dépannage de l'application GitLab pour Slack. Couvre les problèmes courants tels que les projets manquants et les problèmes de notifications."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lorsque vous utilisez l'application GitLab pour Slack, vous pouvez rencontrer les problèmes suivants.

## L'application n'apparaît pas dans la liste des intégrations {#app-does-not-appear-in-the-list-of-integrations}

L'application GitLab pour Slack peut ne pas apparaître dans la liste des intégrations. Pour disposer de l'application GitLab pour Slack sur votre instance GitLab Self-Managed, un administrateur doit [activer l'intégration](../../../administration/settings/slack_app.md). Sur GitLab.com, l'application GitLab pour Slack est disponible par défaut.

## Erreur : `Project or alias not found` {#error-project-or-alias-not-found}

Certaines commandes Slack doivent comporter un chemin complet de projet ou un alias et échouent avec l'erreur suivante si le projet est introuvable :

```plaintext
GitLab error: project or alias not found
```

Pour résoudre ce problème, vérifiez que :

- Le chemin complet du projet est correct.
- Si vous utilisez un [alias de projet](gitlab_slack_application.md#create-a-project-alias), l'alias est correct.
- L'application GitLab pour Slack est [activée pour le projet](gitlab_slack_application.md#from-the-project-or-group-settings).

## Les commandes Slash renvoient `dispatch_failed` dans Slack {#slash-commands-return-dispatch_failed-in-slack}

Les commandes Slash peuvent renvoyer `/gitlab failed with the error "dispatch_failed"` dans Slack.

Pour résoudre ce problème, vérifiez qu'un administrateur a correctement configuré les [paramètres de l'application GitLab pour Slack](../../../administration/settings/slack_app.md) sur votre instance GitLab Self-Managed.

## Notifications non reçues sur un canal {#notifications-not-received-to-a-channel}

Si vous ne recevez pas de notifications sur un canal Slack, vérifiez que :

- Le nom du canal que vous avez configuré est correct.
- Si le canal est privé, vous avez [ajouté l'application GitLab pour Slack au canal](gitlab_slack_application.md#receive-notifications-to-a-private-channel).

## L'accueil de l'application ne s'affiche pas correctement {#app-home-does-not-display-properly}

Si l'[accueil de l'application](https://api.slack.com/start/overview#app_home) ne s'affiche pas correctement, vérifiez que votre [application est à jour](gitlab_slack_application.md#reinstall-the-gitlab-for-slack-app).

## Erreur : `This alias has already been taken` {#error-this-alias-has-already-been-taken}

Vous pouvez rencontrer l'erreur `422: The change you requested was rejected` lors de la configuration d'un nouveau projet. L'erreur Rails renvoyée peut être :

```plaintext
"exception.message": "Validation failed: Alias This alias has already been taken"
```

Pour résoudre ce problème :

1. Recherchez dans votre espace de nommage les projets portant des noms similaires pour lesquels l'application GitLab pour Slack est activée.
1. Parmi ces projets, vérifiez ceux qui ont le même nom d'alias que le projet en échec.
1. Modifiez l'alias pour le rendre différent, puis essayez à nouveau d'activer l'application GitLab pour Slack pour le projet en échec.

## Échecs de `@mention` GitLab Duo {#gitlab-duo-mention-failures}

Lorsque vous utilisez `@mention` pour mentionner l'application GitLab dans Slack et déclencher GitLab Duo, l'application publie un message dans le fil de discussion si une erreur se produit. Utilisez le texte du message pour identifier la cause et appliquer le correctif.

| Message Slack | Cause | Correctif |
|---|---|---|
| Emoji cadenas (🔒) et une invite d'autorisation | Votre compte Slack n'est pas lié à un compte GitLab. | Effectuez le flux d'autorisation pour lier vos comptes Slack et GitLab. |
| `"You do not have access to this feature yet"` | Le feature flag `slack_duo_agent` n'est pas activé pour votre compte. | Demandez à un administrateur d'activer le feature flag pour votre utilisateur. |
| `"This feature requires experiment and beta GitLab Duo features to be turned on"` | Les fonctionnalités expérimentales et en version bêta de GitLab Duo sont désactivées. | Activez les [fonctionnalités en version bêta et expérimentales](../../gitlab_duo/turn_on_off.md#turn-on-beta-and-experimental-features). Sur GitLab.com, ce paramètre s'applique au groupe principal. Sur GitLab Self-Managed et GitLab Dedicated, il s'applique à l'instance. |
| `"This feature requires GitLab Duo Agent Platform"` | Votre compte ne dispose pas d'une licence GitLab Duo Agent Platform. | Vérifiez votre droit d'accès à GitLab Duo auprès de votre administrateur. |
| `"Set your default Duo namespace in your preferences"` | Aucun espace de nommage GitLab Duo par défaut n'est configuré pour votre compte GitLab. | Définissez un espace de nommage GitLab Duo par défaut dans vos préférences GitLab. Sur GitLab.com, vous devez disposer d'un siège actif GitLab Duo add-on dans l'espace de nommage. |
| `"The <flow_name> flow is not turned on for your namespace"` | Le flow GitLab Duo fondamental utilisé par GitLab Duo dans Slack n'est pas activé pour votre espace de nommage. | Demandez à un propriétaire de groupe d'activer le flow indiqué dans le message dans les paramètres de GitLab Duo Agent Platform. |
| `"Could not set up the service account…"` | Le compte de service pour votre espace de nommage n'a pas pu être provisionné. | Vérifiez la configuration de GitLab Duo et le provisionnement du compte de service pour votre espace de nommage. |
| `"Could not set up the workspace project…"` | GitLab n'a pas pu trouver ou créer le projet `duo-workspace` dans votre espace de nommage. | Vérifiez que vous pouvez créer des projets dans l'espace de nommage. Votre rôle et le paramètre `project_creation_level` de l'espace de nommage doivent autoriser la création de projets. |
| `"Failed to start the GitLab Duo session"` ou `"Something went wrong…"` | Le déclenchement ou l'exécution du flow GitLab Duo a échoué. | Consultez les job logs CI et les logs d'intégration GitLab pour plus de détails. |

### Conseils de débogage pour GitLab Duo `@mention` {#debugging-tips-for-gitlab-duo-mention}

- Les logs d'intégration sont écrits dans `integrations_json.log`. Chaque entrée inclut le champ `slack_workspace_id`, et souvent `slack_user_id` et `channel_id`. Filtrez par `slack_workspace_id` pour trouver les entrées pertinentes pour votre workspace.
- Les logs du worker Sidekiq (`sidekiq.log`) incluent également `slack_workspace_id` et `slack_user_id` pour les jobs `Integrations::SlackEventWorker`. Utilisez-les pour déterminer si l'événement a été reçu et traité.
- Si le bot ne peut pas réagir ou répondre du tout, le problème vient probablement de la configuration de l'intégration Slack ou du token du bot. Consultez `integrations_json.log` pour les entrées contenant `"message": "SlackInstallation record has no bot token"`. Si le bot réagit mais publie ensuite une erreur, le problème vient des portes d'autorisation côté utilisateur ou de la résolution de l'espace de nommage.
- Le projet `duo-workspace` est créé automatiquement lors de la première exécution d'un flow et réutilisé par la suite. Si la création du projet échoue, utilisez un espace de nommage dans lequel vous disposez au moins du rôle Maintainer, ou demandez à un propriétaire de groupe d'ajuster le paramètre `project_creation_level`.
