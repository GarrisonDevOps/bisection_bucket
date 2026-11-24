---
stage: Software Supply Chain Security
group: AI Governance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Enregistrez les sessions Claude Code, Cursor et Codex avec la CLI GitLab afin qu'elles apparaissent sur le tableau de bord de gouvernance IA en tant qu'agents connectés en externe (ECAs)."
title: Connecter les agents connectés en externe (ECAs) au tableau de bord de gouvernance IA
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Statut : disponibilité limitée

{{< /details >}}

{{< history >}}

- La capture de sessions pour les agents de codage [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245529) dans GitLab 19.3 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `ai_agent_session_tracking`. Fonctionnalité désactivée par défaut.
- Les sessions Cursor et Codex [introduites](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/260978) dans GitLab 19.5.
- [Activé par défaut](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261046) dans GitLab 19.5.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Lorsque des agents de codage tels que Claude Code, Cursor et Codex s'exécutent sur l'ordinateur d'un développeur, le tableau de bord de gouvernance IA peut les afficher en tant qu'agents connectés en externe (ECAs) via la CLI GitLab (`glab`).

La CLI GitLab (`glab`) lit la transcription locale de chaque agent et envoie la session ainsi que ses événements au projet GitLab dans lequel l'agent a travaillé. Les sessions apparaissent ensuite :

- Sur le [tableau de bord de gouvernance IA](governance-dashboard.md).
- Dans le rapport d'événements d'audit IA.

> [!warning]
> Cette fonctionnalité est en [version bêta](../../policy/development_stages_support.md). Elle est susceptible d'être modifiée sans préavis. Pour plus d'informations, consultez la page [GitLab Testing Agreement](https://handbook.gitlab.com/handbook/legal/testing-agreement/).

`glab` trouve le projet à partir du remote Git du dossier dans lequel l'agent s'est exécuté :

- Pour Claude Code, `glab` sélectionne le remote de la même façon que ses autres commandes. C'est-à-dire que `glab` utilise le remote défini avec `glab repo set-default`, sinon `upstream`, puis `gitlab`, puis `origin`. Dans le cas d'un checkout de duplication, les sessions Claude Code sont envoyées au projet upstream.
- Pour Codex, `glab` utilise l'URL du dépôt enregistrée par Codex, sinon `origin`.
- Pour Cursor, `glab` utilise `origin`.

Le remote doit pointer vers une instance GitLab à laquelle `glab` est connecté. Les sessions dans des dossiers sans un tel remote ne sont pas envoyées.

## Prérequis {#prerequisites}

- GitLab Premium ou Ultimate avec GitLab Duo Agent Platform pour le groupe principal.
- [`glab`](../../editor_extensions/gitlab_cli/_index.md) 1.122.0 ou version ultérieure, connecté à votre instance GitLab.
- Au minimum le rôle Developer pour le projet.
- **Autoriser les agents externes** activé pour le groupe principal. Ce paramètre est activé par défaut. Le paramètre appartient aux [agents externes](../duo_agent_platform/agents/external.md#turn-external-agents-on-or-off) du catalogue d'IA qui s'exécutent dans les pipelines CI/CD, et il contrôle également la capture de sessions. Sa désactivation arrête également les sessions des agents de codage locaux.
- [**Stocker les événements d'audit IA**](ai-audit-events.md#enable-ai-audit-event-storage) activé pour le groupe ou le projet. Sans cela, seule la session est enregistrée, pas ses événements ni ses appels d'outils. Ce paramètre est désactivé par défaut. Pour le modifier, vous devez disposer du rôle Owner ou Responsable sécurité.
- Un ordinateur fonctionnant sous macOS ou Linux.

## Configurer la capture de sessions {#set-up-session-capture}

Configurez la capture de sessions une fois pour chaque compte utilisateur sur chaque ordinateur exécutant un agent. Les commandes de cette section sont documentées dans la [référence `glab govern`](https://docs.gitlab.com/cli/govern/).

`glab govern setup` installe toujours les hooks Claude Code. `glab` installe également les hooks Claude Code lorsque vous passez les options `--agents`, et demande une confirmation. Si vous appelez `glab` dans un script, passez `--yes`.

### Capturer les sessions Claude Code {#capture-claude-code-sessions}

Les sessions Claude Code sont capturées via des hooks, qui envoient la session après chaque réponse lorsque `glab` peut se connecter depuis le hook. Le job en arrière-plan envoie tout ce que les hooks ont manqué.

Pour capturer les sessions Claude Code, exécutez :

```shell
glab govern setup
```

Cette commande installe :

- Un hook Stop et un hook SessionEnd dans `~/.claude/settings.json`. Les hooks envoient la session après chaque réponse et la marquent comme terminée lorsque la session se ferme.
- Un job en arrière-plan qui s'exécute toutes les 30 minutes. Le job envoie tout ce que les hooks ont manqué et marque les sessions comme terminées après 24 heures sans activité. Sur macOS, le job est un agent `launchd`, sur Linux un minuteur utilisateur `systemd`.

Les sessions terminées avant l'exécution de la commande ne sont pas envoyées.

### Capturer les sessions Cursor et Codex {#capture-cursor-and-codex-sessions}

`glab` n'installe pas de hooks pour Cursor et Codex. Le job en arrière-plan trouve leurs sessions en analysant `~/.cursor/projects` et `~/.codex/sessions` toutes les 30 minutes.

Pour capturer les sessions Cursor et Codex, exécutez :

```shell
glab govern setup --agents codex,cursor
```

Le job envoie également les sessions antérieures à l'exécution de la commande, si elles ont été actives au cours des 89 derniers jours et appartiennent à un projet sur une instance GitLab à laquelle `glab` est connecté. Une session est marquée comme terminée après 24 heures sans activité. Les sessions Codex stockées dans un dossier `CODEX_HOME` personnalisé ne sont pas trouvées.

Pour modifier les agents capturés, exécutez à nouveau la commande avec une liste `--agents` différente. Pour arrêter la capture des sessions Cursor et Codex, exécutez-la avec `--agents ""`.

### Vérifier la configuration {#verify-the-setup}

Pour vérifier que la capture de sessions est correctement configurée, exécutez :

```shell
glab govern doctor
```

La commande :

- Vérifie que `glab` est connecté à votre hôte GitLab par défaut et qu'il se trouve dans votre `PATH`.
- Vérifie que les hooks Claude Code se trouvent dans `~/.claude/settings.json` et que l'API GitLab est accessible.
- Indique si le job en arrière-plan est installé et comment s'est déroulée sa dernière exécution.
- Pour chaque vérification en échec, décrit comment y remédier.

La ligne de dernière exécution répertorie :

- Les projets pour lesquels la capture de sessions n'est pas activée.
- Les types d'agents rejetés par GitLab.
- Les sessions Cursor que `glab` a ignorées.

La commande lit uniquement le fichier global `~/.claude/settings.json`. Les hooks dans le dossier `.claude` d'un projet sont signalés comme manquants, et le job en arrière-plan ignore les sessions Claude Code tant que le hook Stop global est manquant.

Pour envoyer les sessions immédiatement au lieu d'attendre le job en arrière-plan, exécutez :

```shell
glab govern audit sync --all
```

## Données envoyées {#data-that-is-sent}

Pour chaque session, `glab` envoie :

- Les invites que vous saisissez. Les invites de plus de 8 Ko sont tronquées. La première invite devient également l'objectif de la session.
- Chaque appel d'outil avec ses arguments, tels que les commandes, les chemins de fichiers et les modifications. Les arguments de plus de 8 Ko sont remplacés par un marqueur.
- Le résultat, la durée et le message d'erreur de chaque appel d'outil. Les messages d'erreur sont tronqués à 255 caractères.
- Le modèle et la consommation de jetons de chaque réponse.
- Lorsqu'une session se termine, une somme de contrôle du fichier de transcription.

La sortie des outils et le texte des réponses ne sont pas envoyés, à l'exception des 255 premiers caractères de la sortie d'un appel d'outil ayant échoué, qui sont envoyés en tant que message d'erreur. Pour identifier l'ordinateur, `glab` envoie un identifiant machine haché.

Les différents agents enregistrent des détails différents :

| Agent | Différence par rapport à Claude Code |
|-------|---------------------------|
| Codex | Le résultat de chaque appel d'outil est enregistré comme terminé, sans message d'erreur, car Codex n'enregistre pas si l'appel a réussi. |
| Cursor | Seules les invites et les appels d'outils sont envoyés, car Cursor n'enregistre ni les résultats, ni la consommation de jetons, ni les horodatages. Les événements sont horodatés en fonction de la dernière modification de la transcription. |

## Afficher les sessions ECA {#view-eca-sessions}

Les sessions des agents connectés en externe (ECAs) apparaissent sur le tableau de bord de gouvernance IA lorsque le contrôle **Afficher** est défini sur **Tous les agents** (valeur par défaut) ou **Connectés** :

- La carte **Sessions les plus récentes** nomme chaque session d'après son agent. Par exemple, **Cursor (glab)** ou **Claude Code (glab)**.
- La carte **Agents les plus utilisés** répertorie chaque agent connecté avec le nombre de machines et d'utilisateurs qui l'ont exécuté. Par exemple, **2 machines · 2 utilisateurs**.
- Les tuiles KPI et les autres cartes comptabilisent les sessions et les appels d'outils aux côtés des sessions GitLab Duo Agent Platform.

Les sessions et leurs événements sont également répertoriés dans le rapport d'événements d'audit IA :

- Les sessions Claude Code apparaissent juste après la première réponse et sont marquées comme terminées lorsque vous quittez l'agent. Si le hook de fermeture ne s'est pas exécuté, le job en arrière-plan marque la session comme terminée après 24 heures sans activité.
- Les sessions Cursor et Codex apparaissent généralement dans les 30 minutes suivant l'utilisation de l'agent, lorsque l'ordinateur est allumé et que vous êtes connecté. Sur macOS, la première exécution du job en arrière-plan a lieu 30 minutes après la configuration. Ces sessions sont marquées comme terminées après 24 heures sans activité.
- Les chiffres du tableau de bord se mettent à jour après un court délai.

## Arrêter la capture de sessions {#stop-capturing-sessions}

Pour supprimer le job en arrière-plan et arrêter la capture des sessions Cursor et Codex, exécutez :

```shell
glab govern setup --uninstall
```

Les hooks Claude Code restent en place. Pour arrêter la capture des sessions Claude Code, supprimez les deux entrées `glab govern audit sync` de la section `hooks` de `~/.claude/settings.json`. Sans le hook Stop, le job en arrière-plan ignore également les sessions Claude Code.

Les sessions déjà envoyées à GitLab restent sur le tableau de bord.

## Dépannage {#troubleshooting}

| Problème | Cause | Résolution |
|---------|-------|------------|
| `glab govern doctor` signale une vérification en échec. | La configuration sur cet ordinateur est incomplète. | Suivez la correction indiquée par la vérification. |
| La ligne de dernière exécution de `glab govern doctor` indique que la capture de sessions n'est pas activée pour un projet. | La capture de sessions est désactivée pour ce projet. | Contactez le support GitLab. |
| `glab govern audit sync --all` affiche un avertissement `403 Forbidden`, ou `glab govern doctor` l'affiche en tant qu'erreur de la dernière exécution. | Votre rôle sur le projet est inférieur à Developer, le groupe ne dispose pas de GitLab Duo Agent Platform, **Autoriser les agents externes** est désactivé pour le groupe principal, ou un Owner du groupe a révoqué l'identité d'agent de cet ordinateur. Pour Claude Code dans le cas d'un checkout de duplication, la session a été envoyée au projet upstream. | Vérifiez le rôle et les paramètres avec un Owner du groupe. Dans le cas d'un checkout de duplication, exécutez `glab repo set-default` et choisissez le projet vers lequel les sessions doivent être envoyées. |
| Une session apparaît, mais ne contient aucun événement ni appel d'outil. | **Stocker les événements d'audit IA** est désactivé pour le groupe ou le projet. | Activez le paramètre. Vous devez disposer du rôle Owner ou Responsable sécurité. Les événements antérieurs à la modification ne sont pas enregistrés. |
| Une session a été envoyée, mais n'apparaît pas sur le tableau de bord. | Le tableau de bord lit les données traitées en arrière-plan, ou les filtres excluent la session. | Définissez **Afficher** sur **Tous les agents** ou **Connectés**, vérifiez la plage de dates, puis patientez quelques minutes et rechargez la page. |
| Une session Cursor n'est jamais envoyée. | `glab` n'a pas pu confirmer dans quel dossier la session s'est exécutée. Cela se produit lorsque le dossier a été déplacé, lorsque le chemin d'un autre dossier ne diffère que par la ponctuation (par exemple `code/cli-docs` et `code/cli/docs`), ou lorsque chaque fichier auquel la session a accédé se trouve en dehors du dossier. Cela se produit également lorsque le dossier ne possède pas de remote `origin`. | Exécutez `glab govern doctor` et lisez la raison indiquée pour « non synchronisé ». Conservez le dossier à l'emplacement où il se trouvait lors de l'exécution de la session, renommez les dossiers dont les chemins ne diffèrent que par la ponctuation, et assurez-vous que le dossier possède un remote `origin`. |
| `glab govern doctor` indique qu'un type d'agent n'est pas encore pris en charge par GitLab. | GitLab n'a pas accepté ce type d'agent lorsque `glab` a trouvé la session pour la première fois. Ces sessions ne sont jamais envoyées. | Les sessions que `glab` trouve après que GitLab accepte le type d'agent sont envoyées. Si le message persiste, contactez le support GitLab. |

## Sujets connexes {#related-topics}

- [Tableau de bord de gouvernance de l'IA](governance-dashboard.md)
- [Auditer les événements IA](ai-audit-events.md)
- [GitLab CLI](../../editor_extensions/gitlab_cli/_index.md)
