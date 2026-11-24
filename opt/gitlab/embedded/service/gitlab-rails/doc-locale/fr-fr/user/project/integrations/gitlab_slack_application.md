---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Application GitLab pour Slack
description: "Configurez l'application GitLab pour Slack pour utiliser les commandes slash, recevoir des notifications et interagir avec GitLab Duo depuis votre espace de travail Slack."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!note]
> Pour la documentation administrateur, consultez [Administration de l'application GitLab pour Slack](../../../administration/settings/slack_app.md).

L'application GitLab pour Slack est une application Slack native qui fournit des [commandes slash](#slash-commands), des [notifications](#slack-notifications) et l'[intégration GitLab Duo](#gitlab-duo) dans votre espace de travail Slack. GitLab associe votre utilisateur Slack à votre utilisateur GitLab, de sorte que toute commande que vous exécutez dans Slack est exécutée par votre utilisateur GitLab associé.

## Installer l'application GitLab pour Slack {#install-the-gitlab-for-slack-app}

Prérequis :

- Vous devez disposer des [autorisations appropriées pour ajouter des applications à votre espace de travail Slack](https://slack.com/help/articles/202035138-Add-apps-to-your-Slack-workspace).
- Sur GitLab Self-Managed, un administrateur doit [activer l'intégration](../../../administration/settings/slack_app.md).

L'application GitLab pour Slack utilise des [autorisations granulaires](https://medium.com/slack-developer-blog/more-precision-less-restrictions-a3550006f9c3). Bien que les fonctionnalités n'aient pas changé, vous devriez [réinstaller l'application](#reinstall-the-gitlab-for-slack-app).

### Depuis les paramètres du projet ou du groupe {#from-the-project-or-group-settings}

{{< history >}}

- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/175803) dans GitLab 17.8. Le feature flag `gitlab_for_slack_app_instance_and_group_level` a été supprimé.

{{< /history >}}

Pour installer l'application GitLab pour Slack depuis les paramètres du projet ou du groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Application GitLab pour Slack**.
1. Sélectionnez **Installer l'application GitLab pour Slack.** Vous êtes redirigé vers la page de confirmation Slack.
1. Sur la page de confirmation Slack :
   1. Facultatif. Si vous êtes connecté à plusieurs espaces de travail Slack, dans le coin supérieur droit, sélectionnez dans la liste déroulante l'espace de travail dans lequel vous souhaitez installer l'application. Sur GitLab Self-Managed et GitLab Dedicated, un administrateur doit d'abord [activer la prise en charge de plusieurs espaces de travail](../../../administration/settings/slack_app.md#enable-support-for-multiple-workspaces) pour que la liste déroulante s'affiche.
   1. Sélectionnez **Autoriser**.

Lorsque vous installez l'application pour un groupe, l'intégration est également activée pour tous les sous-groupes et projets du groupe qui ne l'ont pas encore configurée. Les sous-groupes et les projets qui ont déjà l'intégration configurée ne sont pas affectés, mais peuvent utiliser les paramètres hérités à tout moment. Pour plus d'informations, consultez [gérer les paramètres par défaut du groupe pour une intégration de projet](_index.md#manage-group-default-settings-for-a-project-integration). Chaque projet reçoit un alias spécifique au projet basé sur son chemin de projet, que vous pouvez utiliser dans les [commandes slash](#slash-commands).

### Depuis le répertoire des applications Slack {#from-the-slack-app-directory}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Sur GitLab.com, vous pouvez également installer l'application GitLab pour Slack depuis le [répertoire des applications Slack](https://slack-platform.slack.com/apps/A676ADMV5-gitlab).

Pour installer l'application GitLab pour Slack depuis le répertoire des applications Slack :

1. Accédez à la [page GitLab pour Slack](https://gitlab.com/-/profile/slack/edit).
1. Sélectionnez un projet GitLab à associer à votre espace de travail Slack.

## Réinstaller l'application GitLab pour Slack {#reinstall-the-gitlab-for-slack-app}

Lorsque GitLab publie de nouvelles fonctionnalités pour l'application GitLab pour Slack, vous devrez peut-être réinstaller l'application pour utiliser ces fonctionnalités.

Pour réinstaller l'application GitLab pour Slack :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Application GitLab pour Slack**.
1. Sélectionnez **Installer l'application GitLab pour Slack.** Vous êtes redirigé vers la page de confirmation Slack.
1. Sur la page de confirmation Slack :
   1. Facultatif. Si vous êtes connecté à plusieurs espaces de travail Slack, dans le coin supérieur droit, sélectionnez dans la liste déroulante l'espace de travail dans lequel vous souhaitez réinstaller l'application. Sur GitLab Self-Managed et GitLab Dedicated, un administrateur doit d'abord [activer la prise en charge de plusieurs espaces de travail](../../../administration/settings/slack_app.md#enable-support-for-multiple-workspaces) pour que la liste déroulante s'affiche.
   1. Sélectionnez **Autoriser**.

L'application GitLab pour Slack est mise à jour pour tous les projets qui utilisent l'intégration.

Vous pouvez également [configurer l'intégration](https://about.gitlab.com/solutions/slack/) à nouveau.

## GitLab Duo {#gitlab-duo}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/590434) dans GitLab 19.1 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `slack_duo_agent`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est en [version expérimentale](../../../policy/development_stages_support.md).
- [Activé sur GitLab.com et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/work_items/592185) dans GitLab 19.4.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique. Cette fonctionnalité est disponible à des fins de test, mais n'est pas prête pour une utilisation en production.

<!-- Two distinct notes, so the blank line between them is intentional. -->

> [!note]
> Si vous utilisez plusieurs installations Slack sans Slack Enterprise Grid, Slack applique une limite de débit à GitLab Duo de 15 objets de conversation par minute. Cela empêche l'intégration de fonctionner, car une seule invocation demande 50 messages de l'historique du canal pour les utiliser comme contexte. Pour éviter les limites de débit pour GitLab Duo dans Slack, regroupez tous vos espaces de travail Slack dans une seule organisation Enterprise Grid.

Vous pouvez interagir avec [GitLab Duo](../../gitlab_duo/_index.md) directement depuis Slack en mentionnant le bot GitLab dans n'importe quel canal ou fil de discussion où le bot est présent. GitLab Duo lit l'intégralité du fil de discussion et l'historique récent du canal comme contexte, exécute un flow sur un runner CI/CD et publie le résultat dans le fil de discussion Slack.

Par exemple, vous pouvez demander à GitLab Duo de faire les actions suivantes :

- Transformer une conversation en ticket GitLab.
- Rechercher des tickets ou des merge requests existants.
- Résumer un fil de discussion.
- Répondre à des questions sur vos projets.

Chaque interaction exécute une session GitLab Duo Agent et consomme des GitLab Credits. Les sessions s'exécutent sur un runner CI/CD dans l'espace de nommage Duo par défaut de l'utilisateur appelant, et un projet `duo-workspace` y est automatiquement créé lors de la première utilisation. Si vous interrogez un projet dans un groupe principal différent, GitLab Duo dans Slack échoue.

Lorsqu'il est mentionné dans un canal, l'agent lit les messages récents de ce canal comme contexte pour sa réponse. Les messages publiés après celui auquel il répond ne sont pas inclus. Après que les utilisateurs ont interagi avec GitLab Duo, celui-ci crée une session d'agent visible uniquement par la personne qui l'a invoqué, et non par toutes les personnes ayant accès au projet `duo-workspace`.

> [!note]
> Lorsque vous mentionnez le bot GitLab dans un fil de discussion, l'intégralité du contenu de la conversation (y compris les messages de tous les participants) est envoyée à un grand modèle de langage (LLM) pour générer une réponse. Ne partagez pas d'informations sensibles dans les fils de discussion où vous mentionnez GitLab Duo.

### Prérequis {#prerequisites}

- [Activez la plateforme GitLab Duo Agent](../../duo_agent_platform/turn_on_off.md#turn-gitlab-duo-agent-platform-on-or-off).
- [Activez les fonctionnalités bêta et expérimentales](../../gitlab_duo/turn_on_off.md#turn-on-beta-and-experimental-features).
- Associez un compte Slack à votre compte GitLab. Si vos comptes ne sont pas associés, GitLab vous envoie un message avec un lien pour autoriser la connexion lors de la première mention.
- [Définissez un espace de nommage GitLab Duo par défaut](../../profile/preferences.md#set-a-default-gitlab-duo-namespace).
- Activez le [flow Developer](../merge_requests/developer.md) pour le groupe principal.
- Ajoutez le bot GitLab au canal Slack où vous souhaitez l'utiliser.
- Pour les installations existantes, [réinstallez l'application GitLab pour Slack](#reinstall-the-gitlab-for-slack-app) afin d'accorder les autorisations supplémentaires requises pour GitLab Duo.

### Utiliser GitLab Duo dans Slack {#use-gitlab-duo-in-slack}

Pour utiliser GitLab Duo dans Slack :

1. Invitez l'application dans un canal avec `/invite @GitLab`.
1. Dans le canal Slack ou dans un fil de discussion du canal, saisissez `@GitLab` suivi de votre demande (par exemple, `@GitLab create an issue to track this bug`).
1. La première fois que vous saisissez `@GitLab`, GitLab vous envoie un message avec un lien pour connecter vos comptes Slack et GitLab.
1. GitLab Duo accuse réception de votre demande et commence à travailler sur la tâche.
1. Une fois la tâche terminée, GitLab Duo publie une réponse dans le fil de discussion avec le résultat.

En cas d'erreur, GitLab Duo réagit à votre message avec un emoji de cadenas verrouillé et vous envoie un message avec des détails sur le problème. Ce message n'est visible que par vous.

Pour laisser un retour sur les performances de cette fonctionnalité, utilisez le pouce vers le haut ou le pouce vers le bas sur n'importe quelle réponse.

GitLab Duo dans Slack fonctionne dans les canaux et fils de discussion suivants :

- Les canaux publics et privés dont l'agent est membre.
- Dans les messages directs de groupe entre plus de deux personnes. GitLab Duo ne voit que le message dans lequel il a été mentionné, et non la conversation précédente.

GitLab Duo ne fonctionne pas dans les fils de discussion suivants :

- Les messages directs en tête-à-tête avec l'agent.
- Dans le panneau de l'agent dans la barre supérieure de Slack.

### Projet workspace {#workspace-project}

Lors de votre première utilisation de GitLab Duo depuis Slack, un projet workspace appelé `duo-workspace` est automatiquement créé dans votre espace de nommage GitLab Duo par défaut. Ce projet sert d'environnement d'exécution pour tous les flows déclenchés depuis Slack.

Vous pouvez personnaliser le comportement de l'agent dans le projet workspace. Pour plus d'informations, consultez [flow Developer](../merge_requests/developer.md).

### Autorisations de l'application GitLab pour Slack {#gitlab-for-slack-app-permissions}

GitLab Duo nécessite les autorisations supplémentaires suivantes pour l'application GitLab pour Slack :

| Portée               | Objectif |
|---------------------|---------|
| `app_mentions:read` | Reçoit les événements lorsque des utilisateurs mentionnent le bot dans un canal. |
| `channels:history`  | Lit l'historique des conversations dans les canaux publics pour fournir le contexte du fil de discussion et du canal à l'agent. |
| `groups:history`    | Lit l'historique des conversations dans les canaux privés pour fournir le contexte du fil de discussion et du canal à l'agent. |
| `reactions:write`   | Ajoute des réactions emoji aux messages pour indiquer le statut du cycle de vie de l'agent. |

Les nouvelles installations reçoivent ces autorisations automatiquement. Les installations existantes ne reçoivent ces autorisations qu'après avoir [réinstallé l'application GitLab pour Slack](#reinstall-the-gitlab-for-slack-app).

## Commandes slash {#slash-commands}

Vous pouvez utiliser des commandes slash pour effectuer des opérations GitLab courantes.

Pour l'application GitLab pour Slack :

- Vous devez autoriser votre utilisateur Slack lors de l'exécution de votre première commande slash.
- Vous pouvez remplacer `<project>` par un chemin complet de projet ou [créer un alias de projet](#create-a-project-alias) pour les commandes slash.

Si vous utilisez plutôt les [commandes slash Mattermost](mattermost_slash_commands.md) :

- Remplacez `/gitlab` par le nom de déclencheur que vous avez configuré pour ces intégrations.
- Supprimez `<project>`.

Les commandes slash suivantes sont disponibles pour GitLab :

| Commande | Description |
| ------- | ----------- |
| `/gitlab help` | Affiche toutes les commandes slash disponibles. |
| `/gitlab <project> issue show <id>` | Affiche le ticket avec l'ID `<id>`. |
| `/gitlab <project> issue new <title>` <kbd>Shift</kbd>+<kbd>Entrée</kbd> `<description>` | Crée un ticket avec le titre `<title>` et la description `<description>`. |
| `/gitlab <project> issue search <query>` | Affiche jusqu'à cinq tickets correspondant à `<query>`. |
| `/gitlab <project> issue move <id> to <project>` | Déplace le ticket avec l'ID `<id>` vers `<project>`. |
| `/gitlab <project> issue close <id>` | Ferme le ticket avec l'ID `<id>`. |
| `/gitlab <project> issue comment <id>` <kbd>Shift</kbd>+<kbd>Entrée</kbd> `<comment>` | Ajoute un commentaire avec le corps du commentaire `<comment>` au ticket avec l'ID `<id>`. |
| `/gitlab <project> deploy <from> to <to>` | [Déploie](#deploy-command) depuis l'environnement `<from>` vers l'environnement `<to>`. |
| `/gitlab <project> run <job name> <arguments>` | Exécute le job [ChatOps](../../../ci/chatops/_index.md) `<job name>` sur la branche par défaut. |
| `/gitlab incident declare` | Ouvre une boîte de dialogue pour [créer un incident depuis Slack](../../../operations/incident_management/slack.md). |

### Commande `deploy` {#deploy-command}

Pour déployer dans un environnement, GitLab tente de trouver une action de déploiement manuelle dans le pipeline.

Si une seule action de déploiement est définie pour un environnement, cette action est déclenchée. Si plusieurs actions de déploiement sont définies, GitLab tente de trouver un nom d'action correspondant au nom de l'environnement.

La commande renvoie une erreur si GitLab ne peut pas trouver d'action de déploiement correspondante.

### Créer un alias de projet {#create-a-project-alias}

Dans l'application GitLab pour Slack, les commandes slash utilisent le chemin complet du projet par défaut. Vous pouvez utiliser un alias de projet à la place.

Pour créer un alias de projet pour les commandes slash dans l'application GitLab pour Slack :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Application GitLab pour Slack**.
1. À côté du chemin ou de l'alias du projet, sélectionnez **Modifier**.
1. Saisissez le nouvel alias et sélectionnez **Enregistrer les modifications**.

Si une collision d'alias se produit dans un espace de travail Slack (par exemple, plusieurs projets ou groupes tentent d'utiliser le même alias), GitLab attribue automatiquement un alias de secours au format suivant :

- Pour les projets : `p-<project_id>` (par exemple, `p-12345`)
- Pour les groupes : `g-<group_id>` (par exemple, `g-67890`)

Vous pouvez utiliser ces alias de secours dans les commandes slash lorsque l'alias préféré n'est pas disponible.

## Notifications Slack {#slack-notifications}

Vous pouvez recevoir des notifications dans des canaux Slack pour certains [événements](#notification-events) GitLab.

### Configurer les notifications {#configure-notifications}

Pour configurer les notifications Slack :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Application GitLab pour Slack**.
1. Dans la section **Déclencheur** :
   - Cochez la case correspondant à chaque [événement](#notification-events) GitLab pour lequel vous souhaitez recevoir des notifications dans Slack.
   - Pour chaque case que vous cochez, saisissez les noms des canaux Slack dans lesquels vous souhaitez recevoir les notifications. Vous pouvez saisir jusqu'à 10 noms de canaux séparés par des virgules (par exemple, `#channel-one, #channel-two`).

     > [!note]
     > Si le canal Slack est privé, vous devez [ajouter l'application GitLab pour Slack au canal](#receive-notifications-to-a-private-channel).

1. Facultatif. Dans la section **Paramètres de notification** :
   - Cochez la case **Envoyer une notification uniquement pour les pipelines cassés** pour recevoir des notifications uniquement pour les pipelines en échec.
   - Cochez la case **Envoyer une notification uniquement en cas de changement de statut** pour recevoir des notifications uniquement lorsque le statut du pipeline pour la référence change.
   - Dans la liste déroulante **Branches pour lesquelles des notifications doivent être envoyées**, sélectionnez les branches pour lesquelles vous souhaitez recevoir des notifications.

     Des notifications sont également envoyées pour les pipelines déclenchés par des tags créés à partir de ces branches.

     Les notifications pour les vulnérabilités sont uniquement déclenchées par la branche par défaut, indépendamment des branches sélectionnées. Pour plus de détails, consultez [le ticket 469373](https://gitlab.com/gitlab-org/gitlab/-/issues/469373).
   - Pour **Labels to be notified**, saisissez un ou tous les labels qu'un ticket, une merge request ou un commentaire GitLab doit avoir pour recevoir des notifications. Laissez ce champ vide pour recevoir des notifications pour tous les événements.
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

### Recevoir des notifications dans un canal privé {#receive-notifications-to-a-private-channel}

Pour recevoir des notifications dans un canal Slack privé, vous devez ajouter l'application GitLab pour Slack au canal :

1. Mentionnez l'application dans le canal en saisissant `@GitLab`.
1. Sélectionnez **Ajouter au canal**.

### Événements de notification {#notification-events}

Les événements GitLab suivants peuvent déclencher des notifications dans Slack :

| Événement                                                                 | Description |
| --------------------------------------------------------------------- | ----------- |
| Push                                                                  | Un push est effectué vers le dépôt. |
| Ticket                                                                 | Un élément de travail est créé, fermé ou rouvert. |
| Ticket confidentiel                                                    | Un élément de travail confidentiel est créé, fermé ou rouvert. |
| Demande de fusion                                                         | Une merge request est créée, fusionnée, approuvée, fermée ou rouverte. |
| Note                                                                  | Un commentaire est ajouté. |
| Note confidentielle                                                     | Une note interne ou un commentaire sur un élément de travail confidentiel est ajouté. |
| Push de tag                                                              | Un tag est poussé vers le dépôt ou supprimé. |
| Pipeline                                                              | Le statut d'un pipeline change. |
| Page wiki                                                             | Une page wiki est créée ou mise à jour. |
| Déploiement                                                            | Un déploiement est démarré ou terminé. |
| [Mention de groupe](#trigger-notifications-for-group-mentions) dans un canal public  | Un groupe est mentionné dans un canal public. |
| [Mention de groupe](#trigger-notifications-for-group-mentions) dans un canal privé | Un groupe est mentionné dans un canal privé. |
| [Incident](../../../operations/incident_management/slack.md)          | Un incident est créé, fermé ou rouvert. |
| [Vulnérabilité](../../application_security/vulnerabilities/_index.md) | Une nouvelle vulnérabilité unique est enregistrée sur la branche par défaut. |
| Alerte                                                                 | Une nouvelle alerte unique est enregistrée. |

### Déclencher des notifications pour les mentions de groupe {#trigger-notifications-for-group-mentions}

{{< history >}}

- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/175803) dans GitLab 17.8. Le feature flag `gitlab_for_slack_app_instance_and_group_level` a été supprimé.

{{< /history >}}

Pour déclencher un [événement de notification](#notification-events) pour une mention de groupe, utilisez `@<group_name>` dans :

- Les descriptions de tickets et de merge requests
- Les commentaires sur les tickets, les merge requests et les commits
