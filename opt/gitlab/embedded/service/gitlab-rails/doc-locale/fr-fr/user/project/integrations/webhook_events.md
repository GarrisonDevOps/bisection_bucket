---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Événements webhook
description: "Liste des événements webhook GitLab et de leurs payloads. Inclut des exemples JSON."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Le format d'horodatage dans les payloads a [été modifié](https://gitlab.com/gitlab-org/gitlab/-/work_items/622832) de `YYYY-MM-DD HH:MM:SS` avec un fuseau horaire (`2016-08-12 15:23:28 UTC`) vers ISO 8601 avec une précision à la milliseconde et un indicateur de fuseau horaire (`2016-08-12T15:23:28.000Z`) dans GitLab 19.0.

{{< /history >}}

Connectez GitLab à vos applications externes et automatisez votre workflow grâce aux webhooks. Lorsque des événements spécifiques se produisent dans GitLab, les webhooks envoient des requêtes HTTP POST contenant des informations détaillées vers vos endpoints configurés. Créez des processus automatisés qui réagissent aux modifications de code, aux déploiements, aux commentaires et à d'autres activités sans intervention manuelle.

Cette page liste les événements déclenchés pour les [webhooks de projet](webhooks.md) et les [webhooks de groupe](webhooks.md#group-webhooks).

Pour obtenir la liste des événements déclenchés pour les webhooks système, consultez [les webhooks système](../../../administration/system_hooks.md).

## Événements déclenchés pour les webhooks de projet et de groupe {#events-triggered-for-both-project-and-group-webhooks}

| Type d'événement                                                                    | Déclencheur |
|-------------------------------------------------------------------------------|---------|
| [Événement de commentaire](#comment-events)                                              | Un nouveau commentaire est créé ou modifié sur des commits, des merge requests, des tickets ou des extraits de code. |
| [Événement de déploiement](#deployment-events)                                        | Un déploiement démarre, se termine, échoue, est annulé, est en attente d'approbation ou est en attente d'une action manuelle. Avec GitLab Premium et Ultimate, également lorsqu'un déploiement est approuvé ou rejeté. |
| [Événement emoji](#emoji-events)                                                  | Une réaction emoji est ajoutée ou supprimée. |
| [Événement de feature flag](#feature-flag-events)                                    | Un feature flag est activé ou désactivé. |
| [Événement de flow GitLab Duo](#gitlab-duo-flow-events)                              | Un flow GitLab Duo qui référence le webhook démarre, se termine ou échoue. |
| [Événement de job](#job-events)                                                      | Le statut d'un job change. |
| [Événement de merge request](#merge-request-events)                                  | Une merge request est créée, modifiée, fusionnée ou fermée, ou un commit est ajouté dans la branche source. |
| [Événement de jalon](#milestone-events)                                          | Un jalon est créé, fermé, rouvert ou supprimé. |
| [Événement de pipeline](#pipeline-events)                                            | Le statut d'un pipeline change. |
| [Événement de jeton d'accès au projet ou au groupe](#project-and-group-access-token-events) | Un jeton d'accès au projet ou au groupe expire dans 7, 30 ou 60 jours. |
| [Événement push](#push-events)                                                    | Un push est effectué vers le dépôt. |
| [Événement de release](#release-events)                                              | Une release est créée, modifiée ou supprimée. |
| [Événement de tag](#tag-events)                                                      | Des tags sont créés ou supprimés dans le dépôt. |
| [Événement de vulnérabilité](#vulnerability-events)                                  | Une vulnérabilité est créée ou mise à jour. |
| [Événement de page wiki](#wiki-page-events)                                          | Une page wiki est créée, modifiée ou supprimée. |
| [Événement d'élément de travail](#work-item-events)                                          | Un nouvel élément de travail est créé ou un élément existant est modifié, fermé ou rouvert. |

## Événements déclenchés uniquement pour les webhooks de groupe {#events-triggered-for-group-webhooks-only}

| Type d'événement                                 | Déclencheur |
|--------------------------------------------|---------|
| [Événement de membre de groupe](#group-member-events) | Un utilisateur est ajouté ou supprimé d'un groupe, ou le niveau d'accès ou la date d'expiration d'accès d'un utilisateur change. |
| [Événement de projet](#project-events)           | Un projet est créé ou supprimé dans un groupe. |
| [Événement de sous-groupe](#subgroup-events)         | Un sous-groupe est créé ou supprimé d'un groupe. |

> [!note]
> Si un auteur n'a pas d'adresse e-mail publique dans son [profil GitLab](https://gitlab.com/-/user_settings/profile), l'attribut `email` dans le payload du webhook affiche la valeur `[REDACTED]`.

## Événements push {#push-events}

Les événements push sont déclenchés lorsque vous effectuez un push vers le dépôt, sauf dans les cas suivants :

- Vous poussez des tags.
- Un push unique inclut des modifications pour plus de trois branches par défaut (selon le [paramètre `push_event_hooks_limit`](../../../api/settings.md#available-settings)).

Si vous poussez plus de 20 commits à la fois, l'attribut `commits` dans le payload contient uniquement les informations sur les 20 commits les plus récents. Le chargement de données de commit détaillées est coûteux, c'est pourquoi cette restriction existe pour des raisons de performance. L'attribut `total_commits_count` contient le nombre réel de commits.

> [!note]
> Un paramètre distinct, `push_event_activities_limit`, contrôle si GitLab crée des événements push individuels ou un événement push groupé dans le fil d'activité. Pour plus d'informations, consultez [Limite d'activités des événements push](../../../administration/settings/push_event_activities_limit.md).

Si vous créez et poussez une branche sans nouveaux commits, l'attribut `commits` dans le payload est vide.

En-tête de requête :

```plaintext
X-Gitlab-Event: Push Hook
```

Exemple de payload :

```json
{
  "object_kind": "push",
  "event_name": "push",
  "before": "95790bf891e76fee5e1747ab589903a6a1f80f22",
  "after": "da1560886d4f094c3e6c9ef40349f7d38b5d27d7",
  "ref": "refs/heads/master",
  "ref_protected": true,
  "checkout_sha": "da1560886d4f094c3e6c9ef40349f7d38b5d27d7",
  "message": "Hello World",
  "user_id": 4,
  "user_name": "John Smith",
  "user_username": "jsmith",
  "user_email": "john@example.com",
  "user_avatar": "https://s.gravatar.com/avatar/d4c74594d841139328695756648b6bd6?s=8://s.gravatar.com/avatar/d4c74594d841139328695756648b6bd6?s=80",
  "project_id": 15,
  "project": {
    "id": 15,
    "name": "Diaspora",
    "description": "",
    "web_url": "http://example.com/mike/diaspora",
    "avatar_url": null,
    "git_ssh_url": "git@example.com:mike/diaspora.git",
    "git_http_url": "http://example.com/mike/diaspora.git",
    "namespace": "Mike",
    "visibility_level": 0,
    "path_with_namespace": "mike/diaspora",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "http://example.com/mike/diaspora",
    "url": "git@example.com:mike/diaspora.git",
    "ssh_url": "git@example.com:mike/diaspora.git",
    "http_url": "http://example.com/mike/diaspora.git"
  },
  "commits": [
    {
      "id": "b6568db1bc1dcd7f8b4d5a946b0b91f9dacd7327",
      "message": "Update Catalan translation to e38cb41.\n\nSee https://gitlab.com/gitlab-org/gitlab for more information",
      "title": "Update Catalan translation to e38cb41.",
      "timestamp": "2011-12-12T14:27:31+02:00",
      "url": "http://example.com/mike/diaspora/commit/b6568db1bc1dcd7f8b4d5a946b0b91f9dacd7327",
      "author": {
        "name": "Jordi Mallach",
        "email": "jordi@softcatala.org"
      },
      "added": ["CHANGELOG"],
      "modified": ["app/controller/application.rb"],
      "removed": []
    },
    {
      "id": "da1560886d4f094c3e6c9ef40349f7d38b5d27d7",
      "message": "fixed readme",
      "title": "fixed readme",
      "timestamp": "2012-01-03T23:36:29+02:00",
      "url": "http://example.com/mike/diaspora/commit/da1560886d4f094c3e6c9ef40349f7d38b5d27d7",
      "author": {
        "name": "GitLab dev user",
        "email": "gitlabdev@dv6700.(none)"
      },
      "added": ["CHANGELOG"],
      "modified": ["app/controller/application.rb"],
      "removed": []
    }
  ],
  "total_commits_count": 4,
  "push_options": {},
  "repository": {
    "name": "Diaspora",
    "url": "git@example.com:mike/diaspora.git",
    "description": "",
    "homepage": "http://example.com/mike/diaspora",
    "git_http_url": "http://example.com/mike/diaspora.git",
    "git_ssh_url": "git@example.com:mike/diaspora.git",
    "visibility_level": 0
  }
}
```

## Événements de tag {#tag-events}

Les événements de tag sont déclenchés lorsque vous créez ou supprimez des tags dans le dépôt.

Ce hook n'est pas exécuté si un push unique inclut des modifications pour plus de trois tags par défaut. Cette limite est contrôlée par le paramètre `push_event_hooks_limit` (par défaut : `3`), qui s'applique aux tags et aux branches. En cas de dépassement, aucun webhook n'est déclenché pour cet événement push.

Pour les instances GitLab Self-Managed, les administrateurs peuvent modifier cette limite à l'aide de l'[API des paramètres d'application](../../../api/settings.md#available-settings).

En-tête de requête :

```plaintext
X-Gitlab-Event: Tag Push Hook
```

Exemple de payload :

```json
{
  "object_kind": "tag_push",
  "event_name": "tag_push",
  "before": "0000000000000000000000000000000000000000",
  "after": "82b3d5ae55f7080f1e6022629cdb57bfae7cccc7",
  "ref": "refs/tags/v1.0.0",
  "ref_protected": true,
  "checkout_sha": "82b3d5ae55f7080f1e6022629cdb57bfae7cccc7",
  "message": "Tag message",
  "user_id": 1,
  "user_name": "John Smith",
  "user_username": "jsmith",
  "user_email": "john@example.com",
  "user_avatar": "https://s.gravatar.com/avatar/d4c74594d841139328695756648b6bd6?s=8://s.gravatar.com/avatar/d4c74594d841139328695756648b6bd6?s=80",
  "project_id": 1,
  "project": {
    "id": 1,
    "name": "Example",
    "description": "",
    "web_url": "http://example.com/jsmith/example",
    "avatar_url": null,
    "git_ssh_url": "git@example.com:jsmith/example.git",
    "git_http_url": "http://example.com/jsmith/example.git",
    "namespace": "Jsmith",
    "visibility_level": 0,
    "path_with_namespace": "jsmith/example",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "http://example.com/jsmith/example",
    "url": "git@example.com:jsmith/example.git",
    "ssh_url": "git@example.com:jsmith/example.git",
    "http_url": "http://example.com/jsmith/example.git"
  },
  "commits": [],
  "total_commits_count": 0,
  "push_options": {},
  "repository": {
    "name": "Example",
    "url": "ssh://git@example.com/jsmith/example.git",
    "description": "",
    "homepage": "http://example.com/jsmith/example",
    "git_http_url": "http://example.com/jsmith/example.git",
    "git_ssh_url": "git@example.com:jsmith/example.git",
    "visibility_level": 0
  }
}
```

## Événements d'élément de travail {#work-item-events}

{{< history >}}

- L'attribut `type` dans `object_attributes` [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/467415) dans GitLab 17.2.
- Prise en charge des epics [introduite](https://gitlab.com/groups/gitlab-org/-/work_items/13056) dans GitLab 17.3. [Le nouvel affichage des epics](../../group/epics/_index.md#epics-as-work-items) doit être activé.
- Prise en charge des epics [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/468310) dans GitLab 18.1.
- Le champ `start_date` dans `object_attributes` [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/238048) dans GitLab 19.1.

{{< /history >}}

Les événements d'élément de travail sont déclenchés lorsqu'un élément de travail est créé, modifié, fermé ou rouvert. Les types d'éléments de travail pris en charge sont :

- [Les epics](../../group/epics/_index.md)
- [Ticket](../issues/_index.md)
- [Tâches](../../tasks.md)
- [Incidents](../../../operations/incident_management/incidents.md)
- [Cas de test](../../../ci/test_cases/_index.md)
- [Exigences](../requirements/_index.md)
- [Objectifs et résultats clés (OKR)](../../okrs.md)

Pour les tickets et les tickets [Service Desk](../service_desk/_index.md), le champ `object_kind` est `issue` et le champ `type` est `Issue`. Pour tous les autres éléments de travail, le champ `object_kind` est `work_item` et le champ `type` correspond au type d'élément de travail.

Pour le type d'élément de travail `Epic`, afin de recevoir les événements liés aux modifications, le webhook doit être enregistré pour le groupe.

Les valeurs disponibles pour `object_attributes.action` dans le payload sont :

- `open`
- `close`
- `reopen`
- `update`

Les clés `assignee` et `assignee_id` sont dépréciées et contiennent uniquement le premier assigné.

Les champs `escalation_status` et `escalation_policy` sont uniquement disponibles pour les types de tickets qui [prennent en charge les escalades](../../../operations/incident_management/paging.md#paging), comme les incidents.

En-tête de requête :

```plaintext
X-Gitlab-Event: Issue Hook
```

Exemple de payload :

```json
{
  "object_kind": "issue",
  "event_type": "issue",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project": {
    "id": 1,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlabhq/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "git_http_url":"http://example.com/gitlabhq/gitlab-test.git",
    "namespace":"GitlabHQ",
    "visibility_level":20,
    "path_with_namespace":"gitlabhq/gitlab-test",
    "default_branch":"master",
    "ci_config_path": null,
    "homepage":"http://example.com/gitlabhq/gitlab-test",
    "url":"http://example.com/gitlabhq/gitlab-test.git",
    "ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "http_url":"http://example.com/gitlabhq/gitlab-test.git"
  },
  "object_attributes": {
    "id": 301,
    "title": "New API: create/update/delete file",
    "assignee_ids": [51],
    "assignee_id": 51,
    "author_id": 51,
    "project_id": 14,
    "created_at": "2013-12-03T17:15:43.000Z",
    "updated_at": "2013-12-03T17:15:43.000Z",
    "updated_by_id": 1,
    "last_edited_at": null,
    "last_edited_by_id": null,
    "relative_position": 0,
    "description": "Create new API for manipulations with repository",
    "milestone_id": null,
    "state_id": 1,
    "confidential": false,
    "discussion_locked": true,
    "due_date": null,
    "start_date": null,
    "moved_to_id": null,
    "duplicated_to_id": null,
    "time_estimate": 0,
    "total_time_spent": 0,
    "time_change": 0,
    "human_total_time_spent": null,
    "human_time_estimate": null,
    "human_time_change": null,
    "weight": null,
    "health_status": "at_risk",
    "type": "Issue",
    "iid": 23,
    "url": "http://example.com/diaspora/issues/23",
    "state": "opened",
    "action": "open",
    "severity": "high",
    "escalation_status": "triggered",
    "escalation_policy": {
      "id": 18,
      "name": "Engineering On-call"
    },
    "labels": [{
        "id": 206,
        "title": "API",
        "color": "#ffffff",
        "project_id": 14,
        "created_at": "2013-12-03T17:15:43.000Z",
        "updated_at": "2013-12-03T17:15:43.000Z",
        "template": false,
        "description": "API related issues",
        "type": "ProjectLabel",
        "group_id": 41
      }]
  },
  "repository": {
    "name": "Gitlab Test",
    "url": "http://example.com/gitlabhq/gitlab-test.git",
    "description": "Aut reprehenderit ut est.",
    "homepage": "http://example.com/gitlabhq/gitlab-test"
  },
  "assignees": [{
    "name": "User1",
    "username": "user1",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon"
  }],
  "assignee": {
    "name": "User1",
    "username": "user1",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon"
  },
  "labels": [{
    "id": 206,
    "title": "API",
    "color": "#ffffff",
    "project_id": 14,
    "created_at": "2013-12-03T17:15:43.000Z",
    "updated_at": "2013-12-03T17:15:43.000Z",
    "template": false,
    "description": "API related issues",
    "type": "ProjectLabel",
    "group_id": 41
  }],
  "changes": {
    "updated_by_id": {
      "previous": null,
      "current": 1
    },
    "updated_at": {
      "previous": "2017-09-15T16:50:55.000Z",
      "current": "2017-09-15T16:52:00.000Z"
    },
    "labels": {
      "previous": [{
        "id": 206,
        "title": "API",
        "color": "#ffffff",
        "project_id": 14,
        "created_at": "2013-12-03T17:15:43.000Z",
        "updated_at": "2013-12-03T17:15:43.000Z",
        "template": false,
        "description": "API related issues",
        "type": "ProjectLabel",
        "group_id": 41
      }],
      "current": [{
        "id": 205,
        "title": "Platform",
        "color": "#123123",
        "project_id": 14,
        "created_at": "2013-12-03T17:15:43.000Z",
        "updated_at": "2013-12-03T17:15:43.000Z",
        "template": false,
        "description": "Platform related issues",
        "type": "ProjectLabel",
        "group_id": 41
      }]
    }
  }
}
```

## Événements de commentaire {#comment-events}

Les événements de commentaire sont déclenchés lorsqu'un nouveau commentaire est créé ou modifié sur des commits, des merge requests, des tickets ou des extraits de code.

Les données de note sont stockées dans `object_attributes` (par exemple, `note` ou `noteable_type`). Le payload contient des informations sur la cible du commentaire. Par exemple, un commentaire sur un ticket inclut des informations spécifiques au ticket sous la clé `issue`.

Les types de cibles disponibles sont :

- `commit`
- `merge_request`
- `issue`
- `snippet`

Les valeurs disponibles pour `object_attributes.action` dans le payload sont :

- `create`
- `update`

### Commentaire sur un commit {#comment-on-a-commit}

En-tête de requête :

```plaintext
X-Gitlab-Event: Note Hook
```

Exemple de payload :

```json
{
  "object_kind": "note",
  "event_type": "note",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project_id": 5,
  "project":{
    "id": 5,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlabhq/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "git_http_url":"http://example.com/gitlabhq/gitlab-test.git",
    "namespace":"GitlabHQ",
    "visibility_level":20,
    "path_with_namespace":"gitlabhq/gitlab-test",
    "default_branch":"master",
    "homepage":"http://example.com/gitlabhq/gitlab-test",
    "url":"http://example.com/gitlabhq/gitlab-test.git",
    "ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "http_url":"http://example.com/gitlabhq/gitlab-test.git"
  },
  "repository":{
    "name": "Gitlab Test",
    "url": "http://example.com/gitlab-org/gitlab-test.git",
    "description": "Aut reprehenderit ut est.",
    "homepage": "http://example.com/gitlab-org/gitlab-test"
  },
  "object_attributes": {
    "id": 1243,
    "internal": false,
    "note": "This is a commit comment. How does this work?",
    "noteable_type": "Commit",
    "author_id": 1,
    "created_at": "2015-05-17T18:08:09.000Z",
    "updated_at": "2015-05-17T18:08:09.000Z",
    "project_id": 5,
    "attachment":null,
    "line_code": "bec9703f7a456cd2b4ab5fb3220ae016e3e394e3_0_1",
    "commit_id": "cfe32cf61b73a0d5e9f13e774abde7ff789b1660",
    "noteable_id": null,
    "system": false,
    "st_diff": {
      "diff": "--- /dev/null\n+++ b/six\n@@ -0,0 +1 @@\n+Subproject commit 409f37c4f05865e4fb208c771485f211a22c4c2d\n",
      "new_path": "six",
      "old_path": "six",
      "a_mode": "0",
      "b_mode": "160000",
      "new_file": true,
      "renamed_file": false,
      "deleted_file": false
    },
    "action": "create",
    "url": "http://example.com/gitlab-org/gitlab-test/commit/cfe32cf61b73a0d5e9f13e774abde7ff789b1660#note_1243"
  },
  "commit": {
    "id": "cfe32cf61b73a0d5e9f13e774abde7ff789b1660",
    "message": "Add submodule\n\nSigned-off-by: Example User \u003cuser@example.com.com\u003e\n",
    "timestamp": "2014-02-27T10:06:20+02:00",
    "url": "http://example.com/gitlab-org/gitlab-test/commit/cfe32cf61b73a0d5e9f13e774abde7ff789b1660",
    "author": {
      "name": "Example User",
      "email": "user@example.com"
    }
  }
}
```

### Commentaire sur une merge request {#comment-on-a-merge-request}

En-tête de requête :

```plaintext
X-Gitlab-Event: Note Hook
```

Exemple de payload :

```json
{
  "object_kind": "note",
  "event_type": "note",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project_id": 5,
  "project":{
    "id": 5,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlab-org/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "git_http_url":"http://example.com/gitlab-org/gitlab-test.git",
    "namespace":"Gitlab Org",
    "visibility_level":10,
    "path_with_namespace":"gitlab-org/gitlab-test",
    "default_branch":"master",
    "homepage":"http://example.com/gitlab-org/gitlab-test",
    "url":"http://example.com/gitlab-org/gitlab-test.git",
    "ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "http_url":"http://example.com/gitlab-org/gitlab-test.git"
  },
  "repository":{
    "name": "Gitlab Test",
    "url": "http://localhost/gitlab-org/gitlab-test.git",
    "description": "Aut reprehenderit ut est.",
    "homepage": "http://example.com/gitlab-org/gitlab-test"
  },
  "object_attributes": {
    "id": 1244,
    "internal": false,
    "note": "This MR needs work.",
    "noteable_type": "MergeRequest",
    "author_id": 1,
    "created_at": "2015-05-17T18:21:36.000Z",
    "updated_at": "2015-05-17T18:21:36.000Z",
    "project_id": 5,
    "attachment": null,
    "line_code": null,
    "commit_id": "",
    "noteable_id": 7,
    "system": false,
    "st_diff": null,
    "action": "create",
    "url": "http://example.com/gitlab-org/gitlab-test/merge_requests/1#note_1244"
  },
  "merge_request": {
    "id": 7,
    "target_branch": "markdown",
    "source_branch": "master",
    "source_project_id": 5,
    "author_id": 8,
    "assignee_id": 28,
    "title": "Tempora et eos debitis quae laborum et.",
    "created_at": "2015-03-01T20:12:53.000Z",
    "updated_at": "2015-03-21T18:27:27.000Z",
    "milestone_id": 11,
    "state": "opened",
    "merge_status": "cannot_be_merged",
    "target_project_id": 5,
    "iid": 1,
    "description": "Et voluptas corrupti assumenda temporibus. Architecto cum animi eveniet amet asperiores. Vitae numquam voluptate est natus sit et ad id.",
    "position": 0,
    "labels": [
      {
        "id": 25,
        "title": "Afterpod",
        "color": "#3e8068",
        "project_id": null,
        "created_at": "2019-06-05T14:32:20.211Z",
        "updated_at": "2019-06-05T14:32:20.211Z",
        "template": false,
        "description": null,
        "type": "GroupLabel",
        "group_id": 4
      },
      {
        "id": 86,
        "title": "Element",
        "color": "#231afe",
        "project_id": 4,
        "created_at": "2019-06-05T14:32:20.637Z",
        "updated_at": "2019-06-05T14:32:20.637Z",
        "template": false,
        "description": null,
        "type": "ProjectLabel",
        "group_id": null
      }
    ],
    "source":{
      "name":"Gitlab Test",
      "description":"Aut reprehenderit ut est.",
      "web_url":"http://example.com/gitlab-org/gitlab-test",
      "avatar_url":null,
      "git_ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
      "git_http_url":"http://example.com/gitlab-org/gitlab-test.git",
      "namespace":"Gitlab Org",
      "visibility_level":10,
      "path_with_namespace":"gitlab-org/gitlab-test",
      "default_branch":"master",
      "homepage":"http://example.com/gitlab-org/gitlab-test",
      "url":"http://example.com/gitlab-org/gitlab-test.git",
      "ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
      "http_url":"http://example.com/gitlab-org/gitlab-test.git"
    },
    "target": {
      "name":"Gitlab Test",
      "description":"Aut reprehenderit ut est.",
      "web_url":"http://example.com/gitlab-org/gitlab-test",
      "avatar_url":null,
      "git_ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
      "git_http_url":"http://example.com/gitlab-org/gitlab-test.git",
      "namespace":"Gitlab Org",
      "visibility_level":10,
      "path_with_namespace":"gitlab-org/gitlab-test",
      "default_branch":"master",
      "homepage":"http://example.com/gitlab-org/gitlab-test",
      "url":"http://example.com/gitlab-org/gitlab-test.git",
      "ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
      "http_url":"http://example.com/gitlab-org/gitlab-test.git"
    },
    "last_commit": {
      "id": "562e173be03b8ff2efb05345d12df18815438a4b",
      "message": "Merge branch 'another-branch' into 'master'\n\nCheck in this test\n",
      "timestamp": "2015-04-08T21:00:25-07:00",
      "url": "http://example.com/gitlab-org/gitlab-test/commit/562e173be03b8ff2efb05345d12df18815438a4b",
      "author": {
        "name": "John Smith",
        "email": "john@example.com"
      }
    },
    "work_in_progress": false,
    "draft": false,
    "assignee": {
      "name": "User1",
      "username": "user1",
      "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon"
    },
    "detailed_merge_status": "checking"
  }
}
```

### Commentaire sur un ticket {#comment-on-an-issue}

- Le champ `assignee_id` est déprécié et affiche uniquement le premier assigné.
- Le champ `event_type` est défini sur `confidential_note` pour les tickets confidentiels.

En-tête de requête :

```plaintext
X-Gitlab-Event: Note Hook
```

Exemple de payload :

```json
{
  "object_kind": "note",
  "event_type": "note",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project_id": 5,
  "project":{
    "id": 5,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlab-org/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "git_http_url":"http://example.com/gitlab-org/gitlab-test.git",
    "namespace":"Gitlab Org",
    "visibility_level":10,
    "path_with_namespace":"gitlab-org/gitlab-test",
    "default_branch":"master",
    "homepage":"http://example.com/gitlab-org/gitlab-test",
    "url":"http://example.com/gitlab-org/gitlab-test.git",
    "ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "http_url":"http://example.com/gitlab-org/gitlab-test.git"
  },
  "repository":{
    "name":"diaspora",
    "url":"git@example.com:mike/diaspora.git",
    "description":"",
    "homepage":"http://example.com/mike/diaspora"
  },
  "object_attributes": {
    "id": 1241,
    "internal": false,
    "note": "Hello world",
    "noteable_type": "Issue",
    "author_id": 1,
    "created_at": "2015-05-17T17:06:40.000Z",
    "updated_at": "2015-05-17T17:06:40.000Z",
    "project_id": 5,
    "attachment": null,
    "line_code": null,
    "commit_id": "",
    "noteable_id": 92,
    "system": false,
    "st_diff": null,
    "action": "create",
    "url": "http://example.com/gitlab-org/gitlab-test/issues/17#note_1241"
  },
  "issue": {
    "id": 92,
    "title": "test",
    "assignee_ids": [],
    "assignee_id": null,
    "author_id": 1,
    "project_id": 5,
    "created_at": "2015-04-12T14:53:17.000Z",
    "updated_at": "2015-04-26T08:28:42.000Z",
    "position": 0,
    "branch_name": null,
    "description": "test",
    "milestone_id": null,
    "state": "closed",
    "iid": 17,
    "labels": [
      {
        "id": 25,
        "title": "Afterpod",
        "color": "#3e8068",
        "project_id": null,
        "created_at": "2019-06-05T14:32:20.211Z",
        "updated_at": "2019-06-05T14:32:20.211Z",
        "template": false,
        "description": null,
        "type": "GroupLabel",
        "group_id": 4
      },
      {
        "id": 86,
        "title": "Element",
        "color": "#231afe",
        "project_id": 4,
        "created_at": "2019-06-05T14:32:20.637Z",
        "updated_at": "2019-06-05T14:32:20.637Z",
        "template": false,
        "description": null,
        "type": "ProjectLabel",
        "group_id": null
      }
    ]
  }
}
```

### Commentaire sur un extrait de code {#comment-on-a-code-snippet}

En-tête de requête :

```plaintext
X-Gitlab-Event: Note Hook
```

Exemple de payload :

```json
{
  "object_kind": "note",
  "event_type": "note",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project_id": 5,
  "project":{
    "id": 5,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlab-org/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "git_http_url":"http://example.com/gitlab-org/gitlab-test.git",
    "namespace":"Gitlab Org",
    "visibility_level":10,
    "path_with_namespace":"gitlab-org/gitlab-test",
    "default_branch":"master",
    "homepage":"http://example.com/gitlab-org/gitlab-test",
    "url":"http://example.com/gitlab-org/gitlab-test.git",
    "ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "http_url":"http://example.com/gitlab-org/gitlab-test.git"
  },
  "repository":{
    "name":"Gitlab Test",
    "url":"http://example.com/gitlab-org/gitlab-test.git",
    "description":"Aut reprehenderit ut est.",
    "homepage":"http://example.com/gitlab-org/gitlab-test"
  },
  "object_attributes": {
    "id": 1245,
    "internal": false,
    "note": "Is this snippet doing what it's supposed to be doing?",
    "noteable_type": "Snippet",
    "author_id": 1,
    "created_at": "2015-05-17T18:35:50.000Z",
    "updated_at": "2015-05-17T18:35:50.000Z",
    "project_id": 5,
    "attachment": null,
    "line_code": null,
    "commit_id": "",
    "noteable_id": 53,
    "system": false,
    "st_diff": null,
    "action": "create",
    "url": "http://example.com/gitlab-org/gitlab-test/-/snippets/53#note_1245"
  },
  "snippet": {
    "id": 53,
    "title": "test",
    "description": "A snippet description.",
    "content": "puts 'Hello world'",
    "author_id": 1,
    "project_id": 5,
    "created_at": "2015-04-09T02:40:38.000Z",
    "updated_at": "2015-04-09T02:40:38.000Z",
    "file_name": "test.rb",
    "type": "ProjectSnippet",
    "visibility_level": 0,
    "url": "http://example.com/gitlab-org/gitlab-test/-/snippets/53"
  }
}
```

## Événements de merge request {#merge-request-events}

{{< history >}}

- Événement webhook pour la définition ou l'annulation de la fusion automatique [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/515530) dans GitLab 19.2.

{{< /history >}}

Les événements de merge request sont déclenchés lorsque :

- Une nouvelle merge request est créée.
- Une merge request existante est mise à jour, approuvée (par tous les approbateurs requis), désapprouvée, fusionnée ou fermée.
- Un utilisateur ajoute ou supprime son approbation sur une merge request existante.
- Un relecteur est de nouveau sollicité pour relire une merge request.
- Une merge request est configurée pour la fusion automatique, ou la fusion automatique est annulée.
- Un commit est ajouté dans la branche source.
- Tous les fils de discussion sont résolus sur la merge request.

Les événements de merge request peuvent être déclenchés même si le champ `changes` est vide. Les destinataires de webhook doivent toujours inspecter le contenu du champ `changes` pour connaître les modifications réelles d'une merge request.

### Structure du payload {#payload-structure}

La structure JSON du payload du webhook est cohérente pour tous les types d'actions. Les différences portent sur les champs contenant des données et sur la présence ou non de champs conditionnels tels que `oldrev`, `system` et `system_action`.

Les valeurs disponibles pour `object_attributes.action` dans le payload sont :

- `open` : une merge request est créée.
- `close` : une merge request est fermée.
- `reopen` : une merge request fermée est rouverte.
- `update` : une merge request est mise à jour. Cela inclut les mises à jour générales, les actions de nouvelle demande de revue et la définition ou l'annulation de la fusion automatique. Consultez le champ `changes` pour déterminer le type spécifique de mise à jour. Lorsque la fusion automatique est définie ou annulée, le champ `changes` reflète la modification du statut de fusion automatique de la merge request.
- `approval` : un utilisateur ajoute son approbation.
- `approved` : une merge request est entièrement approuvée par tous les approbateurs requis.
- `unapproval` : un utilisateur retire son approbation, manuellement ou par le système.
- `unapproved` : une merge request précédemment approuvée perd son statut d'approbation, manuellement ou par le système.
- `merge` : une merge request est fusionnée.

Le payload du webhook de merge request contient les champs de premier niveau suivants :

| Champ               | Type   | Description |
|---------------------|--------|-------------|
| `object_kind`       | Chaîne | `"merge_request"` |
| `event_type`        | Chaîne | `"merge_request"` |
| `user`              | Objet | Utilisateur ayant déclenché l'événement. |
| `project`           | Objet | Le projet cible. |
| `object_attributes` | Objet | Données de la merge request. |
| `changes`           | Objet | Contient les attributs modifiés lors de l'action. |
| `assignees`         | Tableau  | Utilisateurs actuellement assignés. |
| `reviewers`         | Tableau  | Relecteurs actuellement assignés. |
| `labels`            | Tableau  | Objets de label. |
| `repository`        | Objet | Déprécié. Utilisez plutôt `project`. Informations sur le dépôt. |

### Champs dépréciés {#deprecated-fields}

Les champs suivants sont dépréciés et inclus uniquement pour la compatibilité descendante. Utilisez plutôt les alternatives recommandées :

| Champ déprécié                     | Alternative recommandée |
|--------------------------------------|-------------------------|
| `object_attributes.assignee_id`      | `object_attributes.assignee_ids` |
| `object_attributes.work_in_progress` | `object_attributes.draft` |
| `project.http_url`                   | `project.git_http_url`  |
| `project.homepage`                   | `project.web_url`       |
| `project.ssh_url`                    | `project.git_ssh_url`   |
| `project.url`                        | `project.git_ssh_url` ou `project.git_http_url` |
| `repository`                         | `project`               |

### Champ `object_attributes` {#object_attributes-field}

{{< history >}}

- `actioned_at` [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224849) dans GitLab 18.10.
- `merged_at` [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/235360) dans GitLab 19.1.
- `target_branch_protected` [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/480576) dans GitLab 19.2.

{{< /history >}}

Le champ `object_attributes` contient l'état actuel de la merge request. Il inclut les champs suivants :

| Champ                           | Type    | Description |
|---------------------------------|---------|-------------|
| `action`                        | Chaîne  | L'action qui a déclenché le webhook. Par exemple, `open`, `update` ou `merge`. |
| `actioned_at`                   | Chaîne  | Moment auquel l'action ayant déclenché le webhook s'est produite. |
| `approval_rules`                | Tableau   | Tableau d'objets de règle d'approbation (EE uniquement). |
| `assignee_ids`                  | Tableau   | Tableau d'identifiants d'assignés. |
| `author_id`                     | Entier | L'identifiant de l'auteur de la merge request. |
| `blocking_discussions_resolved` | Booléen | Indique si les discussions bloquantes sont résolues. |
| `created_at`                    | Chaîne  | Date de création de la merge request. |
| `description`                   | Chaîne  | La description de la merge request. |
| `detailed_merge_status`         | Chaîne  | Informations détaillées sur le statut de fusion. Pour obtenir la liste des valeurs potentielles, consultez [le statut de fusion](../../../api/merge_requests.md#merge-status). |
| `draft`                         | Booléen | Indique si la merge request est un brouillon. |
| `first_contribution`            | Booléen | Indique s'il s'agit de la première contribution de l'auteur. |
| `head_pipeline_id`              | Entier | L'identifiant du pipeline principal. |
| `human_time_change`             | Chaîne  | Modification de temps lisible par l'humain. |
| `human_time_estimate`           | Chaîne  | Estimation du temps lisible par l'humain. |
| `human_total_time_spent`        | Chaîne  | Temps total passé lisible par l'humain. |
| `id`                            | Entier | L'identifiant de la merge request. |
| `iid`                           | Entier | L'identifiant interne de la merge request. |
| `labels`                        | Tableau   | Tableau d'objets de label. |
| `last_commit`                   | Objet  | Le dernier objet commit avec ses détails. |
| `last_edited_at`                | Chaîne  | Date de la dernière modification de la merge request. |
| `last_edited_by_id`             | Entier | L'identifiant de l'utilisateur qui l'a modifié en dernier. |
| `merge_commit_sha`              | Chaîne  | Le SHA du commit de fusion. |
| `merged_at`                     | Chaîne  | Date à laquelle la merge request a été fusionnée. `null` si elle n'a pas encore été fusionnée. |
| `merge_error`                   | Chaîne  | Tout message d'erreur de fusion. |
| `merge_params`                  | Objet  | Paramètres de fusion. |
| `merge_status`                  | Chaîne  | Statut de la merge request. |
| `merge_user_id`                 | Entier | L'identifiant de l'utilisateur qui l'a fusionnée. |
| `merge_when_pipeline_succeeds`  | Booléen | Indique si la fusion automatique est activée. |
| `milestone_id`                  | Entier | L'identifiant du jalon. |
| `oldrev`                        | Chaîne  | L'ancien SHA de commit (présent uniquement pour les événements liés aux pushs). |
| `prepared_at`                   | Chaîne  | Horodatage de la préparation de la merge request. Ce champ est renseigné une seule fois, uniquement après l'achèvement de toutes les [étapes de préparation](../../../api/merge_requests.md#preparation-steps), et n'est pas mis à jour si d'autres modifications sont ajoutées. |
| `reviewer_ids`                  | Tableau   | Tableau d'identifiants de relecteurs. |
| `source_branch`                 | Chaîne  | Le nom de la branche source. |
| `source`                        | Objet  | Détails du projet source. Par exemple, le nom et la description. |
| `source_project_id`             | Entier | L'identifiant du projet source. |
| `squash_commit_sha`             | Chaîne  | Le SHA du commit squashé. Présent uniquement lorsque la merge request est fusionnée avec squash. |
| `state_id`                      | Entier | L'identifiant d'état (`1` : ouvert, `2` : fermé, `3` : fusionné, `4` : verrouillé). |
| `state`                         | Chaîne  | L'état de la merge request (`opened`, `closed`, `merged`, `locked`). |
| `system_action`                 | Chaîne  | L'action système (présente uniquement si `system` est `true`). |
| `system`                        | Booléen | Indique si l'événement a été initié par le système. |
| `target_branch`                 | Chaîne  | Le nom de la branche cible. |
| `target_branch_protected`       | Booléen | Indique si la branche cible est une [branche protégée](../repository/branches/protected.md). |
| `target`                        | Objet  | Détails du projet cible. Par exemple, le nom et la description. |
| `target_project_id`             | Entier | L'identifiant du projet cible. |
| `time_change`                   | Entier | Modification du temps passé en secondes. |
| `time_estimate`                 | Entier | L'estimation de temps en secondes. |
| `title`                         | Chaîne  | Le titre de la merge request. |
| `total_time_spent`              | Entier | Temps total passé en secondes. |
| `updated_at`                    | Chaîne  | Date de la dernière mise à jour de la merge request. |
| `updated_by_id`                 | Entier | L'identifiant de l'utilisateur qui l'a mis à jour en dernier. |
| `url`                           | Chaîne  | L'URL de la merge request. |

### Champ `changes` {#changes-field}

Le champ `changes` contient uniquement les champs qui ont été modifiés lors de l'action. Tous les champs de `object_attributes` n'apparaissent pas dans `changes`.

Chaque champ modifié suit ce format :

```json
{
  "field_name": {
    "previous": "old_value",
    "current": "new_value"
  }
}
```

#### Attributs {#attributes}

- `assignees`
- `blocking_discussions_resolved`
- `description`
- `draft`
- `head_pipeline_id`
- `labels`
- `last_edited_at`
- `last_edited_by_id`
- `merge_commit_sha`
- `merge_error`
- `merge_params`
- `merge_status`
- `merge_user_id`
- `merge_when_pipeline_succeeds`
- `milestone_id`
- `prepared_at`
- `reviewer_ids`
- `reviewers`
- `squash_commit_sha`
- `state_id`
- `target_branch`
- `time_change`
- `time_estimate`
- `title`
- `total_time_spent`
- `updated_at`
- `updated_by_id`

### Champs spécifiques à l'action de merge request {#merge-request-action-specific-fields}

Le champ `object_attributes.oldrev` est uniquement disponible pour l'action `update` lorsqu'il y a des modifications de code effectives, par exemple :

- Du nouveau code est poussé vers la branche source.
- Une [suggestion](../merge_requests/reviews/suggestions.md) est appliquée.

L'exemple suivant montre un événement `update` avec `oldrev` (payload partiel) :

```json
{
  "object_kind": "merge_request",
  "event_type": "merge_request",
  "object_attributes": {
    "action": "update",
    "oldrev": "e59094b8de0f2f91abbe4760a52d9137260252d8"
  }
}
```

### Événements de merge request initiés par le système {#system-initiated-merge-request-events}

Certains événements de merge request sont déclenchés automatiquement par le système, par exemple lorsque des approbations sont réinitialisées suite à de nouveaux pushs de commits. Ces événements webhook initiés par le système sont uniquement déclenchés par des événements push et incluent davantage de champs dans le payload :

- `object_attributes.system` : un champ booléen. Si `true`, l'événement a été déclenché par le système. Si `false`, une action utilisateur a déclenché l'événement.
- `object_attributes.system_action` : un champ de type chaîne, présent uniquement lorsque `system` est `true`. Fournit davantage de contexte sur l'action système. Les valeurs disponibles sont :

  - `approvals_reset_on_push` : le projet a activé **Réinitialiser les approbations pour les opérations push**, et de nouveaux commits ont été poussés.
  - `code_owner_approvals_reset_on_push` : le projet a activé **Suppressions sélectives de propriétaires de code**, et les approbations de propriétaire de code ont été réinitialisées en raison de modifications dans des fichiers correspondant aux règles CODEOWNERS.
- `object_attributes.action` : pour les événements de réinitialisation d'approbation, la valeur est :
  - `unapproved` lorsque la merge request passe de approuvée à non approuvée.
  - `unapproval` lorsqu'une approbation est supprimée sans modifier le statut d'approbation global.

Les autres scénarios de réinitialisation d'approbation ne déclenchent pas de webhooks.

L'exemple suivant montre un événement initié par le système (payload partiel) :

```json
{
  "object_kind": "merge_request",
  "event_type": "merge_request",
  "object_attributes": {
    "action": "unapproved",
    "system": true,
    "system_action": "approvals_reset_on_push"
  }
}
```

### Suivi de l'état du relecteur {#reviewer-state-tracking}

Le tableau `reviewers` dans les payloads de webhook de merge request inclut un champ `state` pour chaque relecteur. Le champ `state` indique l'état actuel de revue du relecteur :

- `unreviewed` : le relecteur n'a pas encore examiné la merge request
- `review_started` : le relecteur a commencé sa revue mais ne l'a pas terminée
- `reviewed` : le relecteur a terminé sa revue
- `requested_changes` : le relecteur a demandé des modifications
- `approved` : le relecteur a approuvé la merge request
- `unapproved` : le relecteur avait précédemment approuvé, mais son approbation a été supprimée

L'exemple suivant montre un tableau de relecteurs (payload partiel) :

```json
{
  "reviewers": [
    {
      "id": 6,
      "name": "User1",
      "username": "user1",
      "state": "unreviewed",
      "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
      "email": "user1@example.com"
    }
  ]
}
```

### Événements de nouvelle demande de revue {#re-request-review-events}

Lorsqu'un relecteur est de nouveau sollicité pour une merge request, un webhook est déclenché avec `action: "update"` contenant des informations enrichies dans l'objet `changes`. Le payload des modifications inclut :

- **État précédent** (premier tableau) : affiche l'état du relecteur avant la nouvelle demande, avec `re_requested: false`
- **État actuel** (deuxième tableau) : affiche l'état mis à jour du relecteur après la nouvelle demande, avec `re_requested: true` pour les relecteurs re-sollicités
- **Transitions d'état** : montre comment l'état du relecteur a changé (par exemple, de `approved` à `unreviewed`)

L'exemple suivant montre les modifications d'une nouvelle demande de revue (payload partiel) :

```json
{
  "object_kind": "merge_request",
  "event_type": "merge_request",
  "object_attributes": {
    "action": "update"
  },
  "changes": {
    "reviewers": [
      [
        {
          "id": 6,
          "name": "User1",
          "username": "user1",
          "state": "approved",
          "re_requested": false,
          "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
          "email": "user1@example.com"
        }
      ],
      [
        {
          "id": 6,
          "name": "User1",
          "username": "user1",
          "state": "unreviewed",
          "re_requested": true,
          "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
          "email": "user1@example.com"
        }
      ]
    ]
  }
}
```

### Événements de soumission de revue {#submit-review-events}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/592358) dans GitLab 19.3.

{{< /history >}}

Lorsqu'un relecteur soumet une revue, GitLab déclenche un webhook avec `action: "update"` qui reflète le nouvel état du relecteur. Cela s'applique que le relecteur demande des modifications, marque la revue comme examinée, approuve ou désapprouve. L'objet `changes` contient l'état précédent du relecteur dans le premier tableau et l'état mis à jour dans le deuxième tableau. Par exemple, un relecteur qui demande des modifications passe de `review_started` à `requested_changes`.

Le champ `re_requested` est `false` dans les deux tableaux car une revue soumise n'est pas une nouvelle demande.

L'exemple suivant montre les modifications d'une soumission de revue (payload partiel) :

```json
{
  "object_kind": "merge_request",
  "event_type": "merge_request",
  "object_attributes": {
    "action": "update"
  },
  "changes": {
    "reviewers": [
      [
        {
          "id": 6,
          "name": "User1",
          "username": "user1",
          "state": "review_started",
          "re_requested": false,
          "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
          "email": "user1@example.com"
        }
      ],
      [
        {
          "id": 6,
          "name": "User1",
          "username": "user1",
          "state": "requested_changes",
          "re_requested": false,
          "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
          "email": "user1@example.com"
        }
      ]
    ]
  }
}
```

### Exemple de payload complet {#complete-payload-example}

En-tête de requête :

```plaintext
X-Gitlab-Event: Merge Request Hook
```

L'exemple suivant est un payload complet de webhook de merge request pour une action `open`. Les champs dépréciés sont omis pour plus de clarté. Pour obtenir la liste des champs dépréciés et leurs alternatives recommandées, consultez [les champs dépréciés](#deprecated-fields).

```json
{
  "object_kind": "merge_request",
  "event_type": "merge_request",
  "user": {
    "id": 1,
    "name": "Alex Garcia",
    "username": "agarcia",
    "avatar_url": "https://www.gravatar.com/avatar/1a29da0ccd099482194440fac762f5ccb4ec53227761d1859979367644a889a5?s=80&d=identicon",
    "email": "agarcia@example.com"
  },
  "project": {
    "id": 2,
    "name": "Flight Management",
    "description": "Flight management application for tracking aircraft status.",
    "web_url": "http://gitlab.example.com/flightjs/flight-management",
    "avatar_url": null,
    "git_ssh_url": "ssh://git@gitlab.example.com:flightjs/flight-management.git",
    "git_http_url": "http://gitlab.example.com/flightjs/flight-management.git",
    "namespace": "Flightjs",
    "visibility_level": 0,
    "path_with_namespace": "flightjs/flight-management",
    "default_branch": "main",
    "ci_config_path": null
  },
  "object_attributes": {
    "author_id": 1,
    "created_at": "2026-01-16T05:56:22.000Z",
    "description": "This merge request adds input validation to the booking form.",
    "draft": false,
    "head_pipeline_id": null,
    "id": 93,
    "iid": 16,
    "last_edited_at": null,
    "last_edited_by_id": null,
    "merge_commit_sha": null,
    "merged_at": null,
    "merge_error": null,
    "merge_params": {
      "force_remove_source_branch": "1"
    },
    "merge_status": "checking",
    "merge_user_id": null,
    "merge_when_pipeline_succeeds": false,
    "milestone_id": 8,
    "source_branch": "feature/booking-validation",
    "source_project_id": 2,
    "squash_commit_sha": null,
    "state_id": 1,
    "target_branch": "main",
    "target_branch_protected": true,
    "target_project_id": 2,
    "time_estimate": 0,
    "title": "Add input validation to booking form",
    "updated_at": "2026-01-16T05:56:25.000Z",
    "updated_by_id": null,
    "prepared_at": "2026-01-16T05:56:25.000Z",
    "assignee_ids": [
      1
    ],
    "blocking_discussions_resolved": true,
    "detailed_merge_status": "checking",
    "first_contribution": true,
    "human_time_change": null,
    "human_time_estimate": null,
    "human_total_time_spent": null,
    "labels": [
      {
        "id": 19,
        "title": "enhancement",
        "color": "#adb21a",
        "project_id": null,
        "created_at": "2026-01-07T00:03:52.000Z",
        "updated_at": "2026-01-07T00:03:52.000Z",
        "template": false,
        "description": null,
        "type": "GroupLabel",
        "group_id": 24
      }
    ],
    "last_commit": {
      "id": "e59094b8de0f2f91abbe4760a52d9137260252d8",
      "message": "Add email format validation",
      "title": "Add email format validation",
      "timestamp": "2026-01-16T05:01:10+00:00",
      "url": "http://gitlab.example.com/flightjs/flight-management/-/commit/e59094b8de0f2f91abbe4760a52d9137260252d8",
      "author": {
        "name": "Alex Garcia",
        "email": "agarcia@example.com"
      }
    },
    "reviewer_ids": [
      25
    ],
    "source": {
      "id": 2,
      "name": "Flight Management",
      "description": "Flight management application for tracking aircraft status.",
      "web_url": "http://gitlab.example.com/flightjs/flight-management",
      "avatar_url": null,
      "git_ssh_url": "ssh://git@gitlab.example.com:flightjs/flight-management.git",
      "git_http_url": "http://gitlab.example.com/flightjs/flight-management.git",
      "namespace": "Flightjs",
      "visibility_level": 0,
      "path_with_namespace": "flightjs/flight-management",
      "default_branch": "main",
      "ci_config_path": null
    },
    "state": "opened",
    "system": false,
    "target": {
      "id": 2,
      "name": "Flight Management",
      "description": "Flight management application for tracking aircraft status.",
      "web_url": "http://gitlab.example.com/flightjs/flight-management",
      "avatar_url": null,
      "git_ssh_url": "ssh://git@gitlab.example.com:flightjs/flight-management.git",
      "git_http_url": "http://gitlab.example.com/flightjs/flight-management.git",
      "namespace": "Flightjs",
      "visibility_level": 0,
      "path_with_namespace": "flightjs/flight-management",
      "default_branch": "main",
      "ci_config_path": null
    },
    "time_change": 0,
    "total_time_spent": 0,
    "url": "http://gitlab.example.com/flightjs/flight-management/-/merge_requests/16",
    "approval_rules": [
      {
        "id": 4,
        "approvals_required": 0,
        "name": "All Members",
        "rule_type": "any_approver",
        "report_type": null,
        "merge_request_id": 93,
        "section": null,
        "modified_from_project_rule": false,
        "orchestration_policy_idx": null,
        "vulnerabilities_allowed": 0,
        "scanners": [],
        "severity_levels": [],
        "vulnerability_states": [
          "new_needs_triage",
          "new_dismissed"
        ],
        "security_orchestration_policy_configuration_id": null,
        "scan_result_policy_id": null,
        "applicable_post_merge": null,
        "project_id": 2,
        "approval_policy_rule_id": null,
        "updated_at": "2026-01-16T05:56:22.000Z",
        "created_at": "2026-01-16T05:56:22.000Z"
      }
    ],
    "action": "open",
    "actioned_at": "2026-01-16T05:56:26.000Z"
  },
  "labels": [
    {
      "id": 19,
      "title": "enhancement",
      "color": "#adb21a",
      "project_id": null,
      "created_at": "2026-01-07T00:03:52.000Z",
      "updated_at": "2026-01-07T00:03:52.000Z",
      "template": false,
      "description": null,
      "type": "GroupLabel",
      "group_id": 24
    }
  ],
  "changes": {
    "merge_status": {
      "previous": "preparing",
      "current": "checking"
    },
    "updated_at": {
      "previous": "2026-01-16T05:56:22.000Z",
      "current": "2026-01-16T05:56:25.000Z"
    },
    "prepared_at": {
      "previous": null,
      "current": "2026-01-16T05:56:25.000Z"
    }
  },
  "assignees": [
    {
      "id": 1,
      "name": "Alex Garcia",
      "username": "agarcia",
      "avatar_url": "https://www.gravatar.com/avatar/1a29da0ccd099482194440fac762f5ccb4ec53227761d1859979367644a889a5?s=80&d=identicon",
      "email": "[REDACTED]"
    }
  ],
  "reviewers": [
    {
      "id": 25,
      "name": "Sidney Jones",
      "username": "sjones",
      "avatar_url": "https://www.gravatar.com/avatar/1be419860e7f852e20ca2691e6b55949f7809177e7765181da42e4448491e367?s=80&d=identicon",
      "email": "[REDACTED]",
      "state": "unreviewed",
      "re_requested": false
    }
  ]
}
```

> [!note]
> Les champs `assignee_id` et `merge_status` sont [dépréciés](../../../api/merge_requests.md).

## Événements de page wiki {#wiki-page-events}

Les événements de page wiki sont déclenchés lorsqu'une page wiki est créée, mise à jour ou supprimée.

En-tête de requête :

```plaintext
X-Gitlab-Event: Wiki Page Hook
```

Exemple de payload :

```json
{
  "object_kind": "wiki_page",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project": {
    "id": 1,
    "name": "awesome-project",
    "description": "This is awesome",
    "web_url": "http://example.com/root/awesome-project",
    "avatar_url": null,
    "git_ssh_url": "git@example.com:root/awesome-project.git",
    "git_http_url": "http://example.com/root/awesome-project.git",
    "namespace": "root",
    "visibility_level": 0,
    "path_with_namespace": "root/awesome-project",
    "default_branch": "master",
    "homepage": "http://example.com/root/awesome-project",
    "url": "git@example.com:root/awesome-project.git",
    "ssh_url": "git@example.com:root/awesome-project.git",
    "http_url": "http://example.com/root/awesome-project.git"
  },
  "wiki": {
    "web_url": "http://example.com/root/awesome-project/-/wikis/home",
    "git_ssh_url": "git@example.com:root/awesome-project.wiki.git",
    "git_http_url": "http://example.com/root/awesome-project.wiki.git",
    "path_with_namespace": "root/awesome-project.wiki",
    "default_branch": "master"
  },
  "object_attributes": {
    "title": "Awesome",
    "content": "awesome content goes here",
    "format": "markdown",
    "message": "adding an awesome page to the wiki",
    "slug": "awesome",
    "url": "http://example.com/root/awesome-project/-/wikis/awesome",
    "action": "create",
    "diff_url": "http://example.com/root/awesome-project/-/wikis/home/diff?version_id=78ee4a6705abfbff4f4132c6646dbaae9c8fb6ec",
    "version_id": "3ad67c972065298d226dd80b2b03e0fc2421e731"
  }
}
```

## Événements de pipeline {#pipeline-events}

{{< history >}}

- `object_attributes.default_branch` [introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/606357) dans GitLab 19.3.

{{< /history >}}

Les événements de pipeline sont déclenchés lorsque le statut d'un pipeline change.

Les webhooks de pipeline déclenchés par des utilisateurs bloqués ne sont pas traités.

Les webhooks de pipeline exposent `object_attributes.name`.

En-tête de requête :

```plaintext
X-Gitlab-Event: Pipeline Hook
```

Exemple de payload :

```json
{
  "object_kind": "pipeline",
  "object_attributes": {
    "id": 31,
    "iid": 3,
    "name": "Pipeline for branch: master",
    "ref": "master",
    "tag": false,
    "sha": "bcbb5ec396a2c0f828686f14fac9b80b780504f2",
    "before_sha": "bcbb5ec396a2c0f828686f14fac9b80b780504f2",
    "source": "merge_request_event",
    "status": "success",
    "detailed_status": "passed",
    "stages": [
      "build",
      "test",
      "deploy"
    ],
    "created_at": "2016-08-12T15:23:28.000Z",
    "finished_at": "2016-08-12T15:26:29.000Z",
    "duration": 63,
    "queued_duration": 10,
    "protected_ref": false,
    "default_branch": true,
    "variables": [
      {
        "key": "NESTOR_PROD_ENVIRONMENT",
        "value": "us-west-1"
      }
    ],
    "url": "http://example.com/gitlab-org/gitlab-test/-/pipelines/31"
  },
  "merge_request": {
    "id": 1,
    "iid": 1,
    "title": "Test",
    "source_branch": "test",
    "source_project_id": 1,
    "target_branch": "master",
    "target_project_id": 1,
    "state": "opened",
    "merge_status": "can_be_merged",
    "detailed_merge_status": "mergeable",
    "url": "http://192.168.64.1:3005/gitlab-org/gitlab-test/merge_requests/1"
  },
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
    "email": "user_email@gitlab.com"
  },
  "project": {
    "id": 1,
    "name": "Gitlab Test",
    "description": "Atque in sunt eos similique dolores voluptatem.",
    "web_url": "http://192.168.64.1:3005/gitlab-org/gitlab-test",
    "avatar_url": null,
    "git_ssh_url": "git@192.168.64.1:gitlab-org/gitlab-test.git",
    "git_http_url": "http://192.168.64.1:3005/gitlab-org/gitlab-test.git",
    "namespace": "Gitlab Org",
    "visibility_level": 20,
    "path_with_namespace": "gitlab-org/gitlab-test",
    "default_branch": "master",
    "ci_config_path": null
  },
  "commit": {
    "id": "bcbb5ec396a2c0f828686f14fac9b80b780504f2",
    "message": "test\n",
    "title": "test",
    "timestamp": "2016-08-12T17:23:21+02:00",
    "url": "http://example.com/gitlab-org/gitlab-test/commit/bcbb5ec396a2c0f828686f14fac9b80b780504f2",
    "author": {
      "name": "User",
      "email": "user@gitlab.com"
    }
  },
  "builds": [
    {
      "id": 380,
      "stage": "deploy",
      "name": "production",
      "status": "skipped",
      "created_at": "2016-08-12 15:23:28 UTC",
      "started_at": null,
      "finished_at": null,
      "duration": null,
      "queued_duration": null,
      "failure_reason": null,
      "when": "manual",
      "manual": true,
      "allow_failure": false,
      "user": {
        "id": 1,
        "name": "Administrator",
        "username": "root",
        "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
        "email": "admin@example.com"
      },
      "runner": null,
      "artifacts_file": {
        "filename": null,
        "size": null
      },
      "environment": {
        "name": "production",
        "action": "start",
        "deployment_tier": "production"
      }
    },
    {
      "id": 377,
      "stage": "test",
      "name": "test-image",
      "status": "success",
      "created_at": "2016-08-12 15:23:28 UTC",
      "started_at": "2016-08-12 15:26:12 UTC",
      "finished_at": "2016-08-12 15:26:29 UTC",
      "duration": 17.0,
      "queued_duration": 196.0,
      "failure_reason": null,
      "when": "on_success",
      "manual": false,
      "allow_failure": false,
      "user": {
        "id": 1,
        "name": "Administrator",
        "username": "root",
        "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
        "email": "admin@example.com"
      },
      "runner": {
        "id": 380987,
        "description": "shared-runners-manager-6.gitlab.com",
        "runner_type": "instance_type",
        "active": true,
        "is_shared": true,
        "tags": [
          "linux",
          "docker",
          "shared-runner"
        ]
      },
      "artifacts_file": {
        "filename": null,
        "size": null
      },
      "environment": null
    },
    {
      "id": 378,
      "stage": "test",
      "name": "test-build",
      "status": "failed",
      "created_at": "2016-08-12 15:23:28 UTC",
      "started_at": "2016-08-12 15:26:12 UTC",
      "finished_at": "2016-08-12 15:26:29 UTC",
      "duration": 17.0,
      "queued_duration": 196.0,
      "failure_reason": "script_failure",
      "when": "on_success",
      "manual": false,
      "allow_failure": false,
      "user": {
        "id": 1,
        "name": "Administrator",
        "username": "root",
        "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
        "email": "admin@example.com"
      },
      "runner": {
        "id": 380987,
        "description": "shared-runners-manager-6.gitlab.com",
        "runner_type": "instance_type",
        "active": true,
        "is_shared": true,
        "tags": [
          "linux",
          "docker"
        ]
      },
      "artifacts_file": {
        "filename": null,
        "size": null
      },
      "environment": null
    },
    {
      "id": 376,
      "stage": "build",
      "name": "build-image",
      "status": "success",
      "created_at": "2016-08-12 15:23:28 UTC",
      "started_at": "2016-08-12 15:24:56 UTC",
      "finished_at": "2016-08-12 15:25:26 UTC",
      "duration": 17.0,
      "queued_duration": 196.0,
      "failure_reason": null,
      "when": "on_success",
      "manual": false,
      "allow_failure": false,
      "user": {
        "id": 1,
        "name": "Administrator",
        "username": "root",
        "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
        "email": "admin@example.com"
      },
      "runner": {
        "id": 380987,
        "description": "shared-runners-manager-6.gitlab.com",
        "runner_type": "instance_type",
        "active": true,
        "is_shared": true,
        "tags": [
          "linux",
          "docker"
        ]
      },
      "artifacts_file": {
        "filename": null,
        "size": null
      },
      "environment": null
    },
    {
      "id": 379,
      "stage": "deploy",
      "name": "staging",
      "status": "created",
      "created_at": "2016-08-12 15:23:28 UTC",
      "started_at": null,
      "finished_at": null,
      "duration": null,
      "queued_duration": null,
      "failure_reason": null,
      "when": "on_success",
      "manual": false,
      "allow_failure": false,
      "user": {
        "id": 1,
        "name": "Administrator",
        "username": "root",
        "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
        "email": "admin@example.com"
      },
      "runner": null,
      "artifacts_file": {
        "filename": null,
        "size": null
      },
      "environment": {
        "name": "staging",
        "action": "start",
        "deployment_tier": "staging"
      }
    }
  ],
  "source_pipeline": {
    "project": {
      "id": 41,
      "web_url": "https://gitlab.example.com/gitlab-org/upstream-project",
      "path_with_namespace": "gitlab-org/upstream-project"
    },
    "pipeline_id": 30,
    "job_id": 3401
  }
}
```

## Événements de job {#job-events}

Les événements de job sont déclenchés lorsque le statut d'un job change. Les jobs de déclenchement sont exclus.

Le champ `commit.id` dans le payload correspond à l'identifiant du pipeline, et non à celui du commit.

Les événements de job déclenchés par des utilisateurs bloqués ne sont pas traités.

En-tête de requête :

```plaintext
X-Gitlab-Event: Job Hook
```

Exemple de payload :

```json
{
  "object_kind": "build",
  "ref": "gitlab-script-trigger",
  "tag": false,
  "before_sha": "2293ada6b400935a1378653304eaf6221e0fdb8f",
  "sha": "2293ada6b400935a1378653304eaf6221e0fdb8f",
  "retries_count": 2,
  "build_id": 1977,
  "build_name": "test",
  "build_stage": "test",
  "build_status": "created",
  "build_created_at": "2021-02-23T02:41:37.886Z",
  "build_started_at": null,
  "build_finished_at": null,
  "build_created_at_iso": "2021-02-23T02:41:37Z",
  "build_started_at_iso": null,
  "build_finished_at_iso": null,
  "build_duration": null,
  "build_queued_duration": 1095.588715,
  "build_allow_failure": false,
  "build_failure_reason": "unknown_failure",
  "pipeline_id": 2366,
  "runner": {
    "id": 380987,
    "description": "shared-runners-manager-6.gitlab.com",
    "runner_type": "project_type",
    "active": true,
    "is_shared": false,
    "tags": [
      "linux",
      "docker"
    ]
  },
  "project_id": 380,
  "project_name": "gitlab-org/gitlab-test",
  "user": {
    "id": 3,
    "name": "User",
    "username": "user",
    "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
    "email": "user@gitlab.com"
  },
  "commit": {
    "id": 2366,
    "name": "Build pipeline",
    "sha": "2293ada6b400935a1378653304eaf6221e0fdb8f",
    "message": "test\n",
    "author_name": "User",
    "author_email": "user@gitlab.com",
    "author_url": "http://192.168.64.1:3005/user",
    "status": "created",
    "duration": null,
    "started_at": null,
    "finished_at": null,
    "started_at_iso": null,
    "finished_at_iso": null
  },
  "repository": {
    "name": "gitlab_test",
    "url": "http://192.168.64.1:3005/gitlab-org/gitlab-test",
    "description": "Atque in sunt eos similique dolores voluptatem.",
    "homepage": "http://192.168.64.1:3005/gitlab-org/gitlab-test",
    "git_ssh_url": "git@192.168.64.1:gitlab-org/gitlab-test.git",
    "git_http_url": "http://192.168.64.1:3005/gitlab-org/gitlab-test.git",
    "visibility_level": 20
  },
  "project": {
    "id": 380,
    "name": "Gitlab Test",
    "description": "Atque in sunt eos similique dolores voluptatem.",
    "web_url": "http://192.168.64.1:3005/gitlab-org/gitlab-test",
    "avatar_url": null,
    "git_ssh_url": "git@192.168.64.1:gitlab-org/gitlab-test.git",
    "git_http_url": "http://192.168.64.1:3005/gitlab-org/gitlab-test.git",
    "namespace": "Gitlab Org",
    "visibility_level": 20,
    "path_with_namespace": "gitlab-org/gitlab-test",
    "default_branch": "master",
    "ci_config_path": null
  },
  "environment": null,
  "source_pipeline": {
    "project": {
      "id": 41,
      "web_url": "https://gitlab.example.com/gitlab-org/upstream-project",
      "path_with_namespace": "gitlab-org/upstream-project"
    },
    "pipeline_id": 30,
    "job_id": 3401
  }
}
```

### Nombre de tentatives {#number-of-retries}

`retries_count` est un entier qui indique si le job est une nouvelle tentative. `0` signifie que le job n'a pas été relancé. `1` signifie qu'il s'agit de la première nouvelle tentative.

### Nom du pipeline {#pipeline-name}

Vous pouvez définir des noms personnalisés pour les pipelines avec [`workflow:name`](../../../ci/yaml/_index.md#workflowname). Si le pipeline a un nom, ce nom est la valeur de `commit.name`.

### Raison de l'échec {#failure-reason}

`build_failure_reason` utilise les mêmes valeurs de raison d'échec que [`retry:when`](../../../ci/yaml/_index.md#retrywhen), à l'exception de `always`.

Si le job n'a pas échoué, GitLab retourne `unknown_failure` dans ce champ car aucune raison d'échec ne s'applique. Pour vérifier si un job a réussi, utilisez `build_status` plutôt que `build_failure_reason`.

## Événements de déploiement {#deployment-events}

Les événements de déploiement sont déclenchés lorsqu'un déploiement :

- Démarre
- Réussit
- Échoue
- Est annulé
- Est bloqué, est en attente d'approbation ou est en attente d'une action manuelle
- Est approuvé (GitLab Premium et Ultimate uniquement)
- Est rejeté (GitLab Premium et Ultimate uniquement)

Le champ `status` reflète le nouvel état de l'entité ayant provoqué l'événement :

- Pour les modifications du cycle de vie du déploiement (`running`, `success`, `failed`, `canceled`, `blocked`), le champ correspond à l'état actuel du déploiement.
- Pour les actions d'approbation, le champ correspond à l'état terminal de l'enregistrement d'approbation (`approved` ou `rejected`).

Les champs `deployable_id` et `deployable_url` dans le payload représentent un job CI/CD qui a exécuté le déploiement. Lorsque l'événement de déploiement se produit via une [API](../../../ci/environments/external_deployment_tools.md) ou des [jobs `trigger`](../../../ci/pipelines/downstream_pipelines.md), la valeur de `deployable_url` est `null`.

En-tête de requête :

```plaintext
X-Gitlab-Event: Deployment Hook
```

Exemple de payload :

```json
{
  "object_kind": "deployment",
  "status": "success",
  "status_changed_at":"2021-04-28T21:50:00.000+02:00",
  "deployment_id": 15,
  "deployable_id": 796,
  "deployable_url": "http://10.126.0.2:3000/root/test-deployment-webhooks/-/jobs/796",
  "environment": "staging",
  "environment_tier": "staging",
  "environment_slug": "staging",
  "environment_external_url": "https://staging.example.com",
  "project": {
    "id": 30,
    "name": "test-deployment-webhooks",
    "description": "",
    "web_url": "http://10.126.0.2:3000/root/test-deployment-webhooks",
    "avatar_url": null,
    "git_ssh_url": "ssh://vlad@10.126.0.2:2222/root/test-deployment-webhooks.git",
    "git_http_url": "http://10.126.0.2:3000/root/test-deployment-webhooks.git",
    "namespace": "Administrator",
    "visibility_level": 0,
    "path_with_namespace": "root/test-deployment-webhooks",
    "default_branch": "master",
    "ci_config_path": "",
    "homepage": "http://10.126.0.2:3000/root/test-deployment-webhooks",
    "url": "ssh://vlad@10.126.0.2:2222/root/test-deployment-webhooks.git",
    "ssh_url": "ssh://vlad@10.126.0.2:2222/root/test-deployment-webhooks.git",
    "http_url": "http://10.126.0.2:3000/root/test-deployment-webhooks.git"
  },
  "short_sha": "279484c0",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "https://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
    "email": "admin@example.com"
  },
  "user_url": "http://10.126.0.2:3000/root",
  "commit_url": "http://10.126.0.2:3000/root/test-deployment-webhooks/-/commit/279484c09fbe69ededfced8c1bb6e6d24616b468",
  "commit_title": "Add new file"
}
```

### Événements d'approbation et de rejet de déploiement {#deployment-approval-and-rejection-events}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/441402) dans GitLab 19.3.

{{< /history >}}

Un déploiement vers un [environnement protégé](../../../ci/environments/deployment_approvals.md) nécessitant des approbations déclenche un webhook de déploiement chaque fois qu'un approbateur approuve ou rejette le déploiement. Le payload conserve le même `object_kind` que les autres événements de déploiement et ajoute des champs spécifiques à l'approbation :

- `status` est `approved` ou `rejected` et reflète l'action d'approbation.
- `status_changed_at` est l'heure à laquelle l'approbation a été enregistrée, au format ISO 8601.
- `approver` est l'utilisateur qui a enregistré l'approbation ou le rejet. Le champ `approver.email` est `[REDACTED]` si l'approbateur n'a pas rendu son adresse e-mail publique.
- `approval` décrit l'approbation, y compris la règle d'environnement protégé qui l'a autorisée. Le champ `approval.approval_rule.access_level_description` est le libellé lisible par l'humain de la règle.
  - Pour les règles basées sur les rôles, le champ est un libellé indépendant de la langue, tel que `"Maintainers"`.
  - Pour les règles limitées à un utilisateur ou à un groupe, il s'agit du nom d'affichage de l'utilisateur ou du groupe (une chaîne contrôlée par l'utilisateur). Les destinataires doivent traiter ce champ comme du texte d'affichage non fiable et utiliser `user_id`, `group_id` et `access_level` pour le routage lisible par une machine.

Les champs `approver` et `approval` sont spécifiques aux événements d'approbation et de rejet et ne sont pas présents dans les autres événements du cycle de vie du déploiement. Les destinataires peuvent identifier les événements d'approbation par la valeur de `status` ou par la présence de ces champs.

Exemple de payload :

```json
{
  "object_kind": "deployment",
  "status": "approved",
  "status_changed_at": "2026-05-08T10:30:00.000Z",
  "deployment_id": 15,
  "deployable_id": 796,
  "deployable_url": "http://10.126.0.2:3000/root/test-deployment-webhooks/-/jobs/796",
  "environment": "production",
  "environment_tier": "production",
  "environment_slug": "production",
  "environment_external_url": "https://production.example.com",
  "project": {
    "id": 30,
    "name": "test-deployment-webhooks",
    "web_url": "http://10.126.0.2:3000/root/test-deployment-webhooks",
    "path_with_namespace": "root/test-deployment-webhooks"
  },
  "short_sha": "279484c0",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "https://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
    "email": "admin@example.com"
  },
  "user_url": "http://10.126.0.2:3000/root",
  "commit_url": "http://10.126.0.2:3000/root/test-deployment-webhooks/-/commit/279484c09fbe69ededfced8c1bb6e6d24616b468",
  "commit_title": "Add new file",
  "approver": {
    "id": 5,
    "name": "Ops Lead",
    "username": "ops_lead",
    "avatar_url": "https://www.gravatar.com/avatar/abcdef1234567890?s=80&d=identicon",
    "email": "ops@example.com"
  },
  "approval": {
    "id": 42,
    "status": "approved",
    "comment": "LGTM",
    "created_at": "2026-05-08T10:30:00.000Z",
    "approval_rule": {
      "id": 7,
      "user_id": null,
      "group_id": null,
      "access_level": 40,
      "access_level_description": "Maintainers",
      "required_approvals": 2,
      "group_inheritance_type": 0
    }
  }
}
```

Pour un rejet, `status` et `approval.status` sont tous les deux `rejected`. La valeur de `approval.approval_rule` est `null` lorsque l'environnement protégé n'utilise pas de règles d'approbation.

#### Séquence d'événements autour du rejet et de l'approbation complète {#event-sequence-around-rejection-and-full-approval}

Les webhooks d'approbation et de cycle de vie sont indépendants. Un déploiement qui passe par le workflow d'approbation produit plusieurs webhooks avec le même `deployment_id`. Lorsqu'un déploiement entre dans l'état d'attente d'approbation, un événement `status: "blocked"` se déclenche en premier. Les actions d'approbation ou de rejet suivantes produisent ensuite leurs propres événements.

Les événements se déclenchent dans l'ordre suivant :

1. Lorsque le déploiement entre pour la première fois dans l'état d'attente d'approbation, un événement `status: "blocked"` se déclenche. Il s'agit de l'événement du cycle de vie du déploiement et ne comporte pas de champs d'approbation.
1. Un rejet produit ensuite `status: "rejected"` (avec `approver` et `approval`), suivi de `status: "failed"` pour le même déploiement lorsque le job de déploiement est supprimé. L'événement `failed` est l'événement du cycle de vie hérité existant et ne comporte pas de champs d'approbation.
1. Une approbation finale produit `status: "approved"`, suivi plus tard de `status: "running"` lorsque le job de déploiement démarre, puis d'un événement terminal tel que `status: "success"` ou `status: "failed"`.

Pour obtenir des conseils sur la gestion des alertes d'échec en double causées par un rejet, consultez [Dépannage des webhooks](webhooks_troubleshooting.md#duplicate-deployment-failure-alerts-after-a-rejection).

## Événements de membre de groupe {#group-member-events}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

{{< history >}}

- Événements de demande d'accès [introduits](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163094) dans GitLab 17.4.

{{< /history >}}

Ces événements sont déclenchés uniquement pour les [webhooks de groupe](webhooks.md#group-webhooks).

Les événements de membre sont déclenchés lorsque :

- Un utilisateur est ajouté comme membre d'un groupe.
- Le niveau d'accès d'un utilisateur change.
- La date d'expiration de l'accès utilisateur est mise à jour.
- Un utilisateur est supprimé du groupe.
- Un utilisateur demande l'accès au groupe.
- Une demande d'accès est refusée.

### Ajouter un membre au groupe {#add-member-to-group}

En-tête de requête :

```plaintext
X-Gitlab-Event: Member Hook
```

Exemple de payload :

```json
{
  "created_at": "2020-12-11T04:57:22Z",
  "updated_at": "2020-12-11T04:57:22Z",
  "group_name": "webhook-test",
  "group_path": "webhook-test",
  "group_id": 100,
  "user_username": "test_user",
  "user_name": "Test User",
  "user_email": "testuser@webhooktest.com",
  "user_id": 64,
  "group_access": "Guest",
  "group_plan": null,
  "expires_at": "2020-12-14T00:00:00Z",
  "event_name": "user_add_to_group"
}
```

### Mettre à jour le niveau d'accès ou la date d'expiration d'un membre {#update-member-access-level-or-expiration-date}

En-tête de requête :

```plaintext
X-Gitlab-Event: Member Hook
```

Exemple de payload :

```json
{
  "created_at": "2020-12-11T04:57:22Z",
  "updated_at": "2020-12-12T08:48:19Z",
  "group_name": "webhook-test",
  "group_path": "webhook-test",
  "group_id": 100,
  "user_username": "test_user",
  "user_name": "Test User",
  "user_email": "testuser@webhooktest.com",
  "user_id": 64,
  "group_access": "Developer",
  "group_plan": null,
  "expires_at": "2020-12-20T00:00:00Z",
  "event_name": "user_update_for_group"
}
```

### Supprimer un membre du groupe {#remove-member-from-group}

En-tête de requête :

```plaintext
X-Gitlab-Event: Member Hook
```

Exemple de payload :

```json
{
  "created_at": "2020-12-11T04:57:22Z",
  "updated_at": "2020-12-12T08:52:34Z",
  "group_name": "webhook-test",
  "group_path": "webhook-test",
  "group_id": 100,
  "user_username": "test_user",
  "user_name": "Test User",
  "user_email": "testuser@webhooktest.com",
  "user_id": 64,
  "group_access": "Guest",
  "group_plan": null,
  "expires_at": "2020-12-14T00:00:00Z",
  "event_name": "user_remove_from_group"
}
```

### Un utilisateur demande l'accès {#a-user-requests-access}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163094) dans GitLab 17.4 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `group_access_request_webhooks`. Fonctionnalité désactivée par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/479877) dans GitLab 17.5. Le feature flag `group_access_request_webhooks` a été supprimé.

{{< /history >}}

En-tête de requête :

```plaintext
X-Gitlab-Event: Member Hook
```

Exemple de payload :

```json
{
  "created_at": "2020-12-11T04:57:22Z",
  "updated_at": "2020-12-12T08:52:34Z",
  "group_name": "webhook-test",
  "group_path": "webhook-test",
  "group_id": 100,
  "user_username": "test_user",
  "user_name": "Test User",
  "user_email": "testuser@webhooktest.com",
  "user_id": 64,
  "group_access": "Guest",
  "group_plan": null,
  "expires_at": "2020-12-14T00:00:00Z",
  "event_name": "user_access_request_to_group"
}
```

### Une demande d'accès est refusée {#an-access-request-is-denied}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163094) dans GitLab 17.4 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `group_access_request_webhooks`. Fonctionnalité désactivée par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/479877) dans GitLab 17.5. Le feature flag `group_access_request_webhooks` a été supprimé.

{{< /history >}}

En-tête de requête :

```plaintext
X-Gitlab-Event: Member Hook
```

Exemple de payload :

```json
{
  "created_at": "2020-12-11T04:57:22Z",
  "updated_at": "2020-12-12T08:52:34Z",
  "group_name": "webhook-test",
  "group_path": "webhook-test",
  "group_id": 100,
  "user_username": "test_user",
  "user_name": "Test User",
  "user_email": "testuser@webhooktest.com",
  "user_id": 64,
  "group_access": "Guest",
  "group_plan": null,
  "expires_at": "2020-12-14T00:00:00Z",
  "event_name": "user_access_request_denied_for_group"
}
```

## Événements de projet {#project-events}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/359044) dans GitLab 17.6.

{{< /history >}}

Ces événements sont déclenchés uniquement pour les [webhooks de groupe](webhooks.md#group-webhooks).

Les événements de projet sont déclenchés lorsque :

- Un [projet est créé dans un groupe](#create-a-project-in-a-group).
- Un [projet est supprimé dans un groupe](#delete-a-project-in-a-group).

### Créer un projet dans un groupe {#create-a-project-in-a-group}

En-tête de requête :

```plaintext
X-Gitlab-Event: Project Hook
```

Exemple de payload :

```json
{
  "event_name": "project_create",
  "created_at": "2024-10-07T10:43:48Z",
  "updated_at": "2024-10-07T10:43:48Z",
  "name": "project1",
  "path": "project1",
  "path_with_namespace": "group1/project1",
  "project_id": 22,
  "project_namespace_id": 32,
  "owners": [{
    "name": "John",
    "email": "user1@example.com"
  }],
  "project_visibility": "private"
}
```

### Supprimer un projet dans un groupe {#delete-a-project-in-a-group}

En-tête de requête :

```plaintext
X-Gitlab-Event: Project Hook
```

Exemple de payload :

```json
{
  "event_name": "project_destroy",
  "created_at": "2024-10-07T10:43:48Z",
  "updated_at": "2024-10-07T10:43:48Z",
  "name": "project1",
  "path": "project1",
  "path_with_namespace": "group1/project1",
  "project_id": 22,
  "project_namespace_id": 32,
  "owners": [{
    "name": "John",
    "email": "user1@example.com"
  }],
  "project_visibility": "private"
}
```

## Événements de sous-groupe {#subgroup-events}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

Ces événements sont déclenchés uniquement pour les [webhooks de groupe](webhooks.md#group-webhooks).

Les événements de sous-groupe sont déclenchés lorsque :

- Un [sous-groupe est créé dans un groupe](#create-a-subgroup-in-a-group).
- Un [sous-groupe est supprimé d'un groupe](#remove-a-subgroup-from-a-group).

### Créer un sous-groupe dans un groupe {#create-a-subgroup-in-a-group}

En-tête de requête :

```plaintext
X-Gitlab-Event: Subgroup Hook
```

Exemple de payload :

```json
{

  "created_at": "2021-01-20T09:40:12Z",
  "updated_at": "2021-01-20T09:40:12Z",
  "event_name": "subgroup_create",
  "name": "subgroup1",
  "path": "subgroup1",
  "full_path": "group1/subgroup1",
  "group_id": 10,
  "parent_group_id": 7,
  "parent_name": "group1",
  "parent_path": "group1",
  "parent_full_path": "group1"

}
```

### Supprimer un sous-groupe d'un groupe {#remove-a-subgroup-from-a-group}

Ce webhook n'est pas déclenché lorsqu'un [sous-groupe est transféré vers un nouveau groupe parent](../../group/manage.md#transfer-a-group).

En-tête de requête :

```plaintext
X-Gitlab-Event: Subgroup Hook
```

Exemple de payload :

```json
{

  "created_at": "2021-01-20T09:40:12Z",
  "updated_at": "2021-01-20T09:40:12Z",
  "event_name": "subgroup_destroy",
  "name": "subgroup1",
  "path": "subgroup1",
  "full_path": "group1/subgroup1",
  "group_id": 10,
  "parent_group_id": 7,
  "parent_name": "group1",
  "parent_path": "group1",
  "parent_full_path": "group1"

}
```

## Événements de feature flag {#feature-flag-events}

Les événements de feature flag sont déclenchés lorsqu'un feature flag est activé ou désactivé.

En-tête de requête :

```plaintext
X-Gitlab-Event: Feature Flag Hook
```

Exemple de payload :

```json
{
  "object_kind": "feature_flag",
  "project": {
    "id": 1,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlabhq/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "git_http_url":"http://example.com/gitlabhq/gitlab-test.git",
    "namespace":"GitlabHQ",
    "visibility_level":20,
    "path_with_namespace":"gitlabhq/gitlab-test",
    "default_branch":"master",
    "ci_config_path": null,
    "homepage":"http://example.com/gitlabhq/gitlab-test",
    "url":"http://example.com/gitlabhq/gitlab-test.git",
    "ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "http_url":"http://example.com/gitlabhq/gitlab-test.git"
  },
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "https://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
    "email": "admin@example.com"
  },
  "user_url": "http://example.com/root",
  "object_attributes": {
    "id": 6,
    "name": "test-feature-flag",
    "description": "test-feature-flag-description",
    "active": true
  }
}
```

## Événements de release {#release-events}

Les événements de release sont déclenchés lorsqu'une release est créée, mise à jour ou supprimée.

Les valeurs disponibles pour `object_attributes.action` dans le payload sont :

- `create`
- `update`
- `delete`

En-tête de requête :

```plaintext
X-Gitlab-Event: Release Hook
```

Exemple de payload :

```json
{
  "id": 1,
  "created_at": "2020-11-02T12:55:12.000Z",
  "description": "v1.1 has been released",
  "name": "v1.1",
  "released_at": "2020-11-02T12:55:12.000Z",
  "tag": "v1.1",
  "object_kind": "release",
  "project": {
    "id": 2,
    "name": "release-webhook-example",
    "description": "",
    "web_url": "https://example.com/gitlab-org/release-webhook-example",
    "avatar_url": null,
    "git_ssh_url": "ssh://git@example.com/gitlab-org/release-webhook-example.git",
    "git_http_url": "https://example.com/gitlab-org/release-webhook-example.git",
    "namespace": "Gitlab",
    "visibility_level": 0,
    "path_with_namespace": "gitlab-org/release-webhook-example",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "https://example.com/gitlab-org/release-webhook-example",
    "url": "ssh://git@example.com/gitlab-org/release-webhook-example.git",
    "ssh_url": "ssh://git@example.com/gitlab-org/release-webhook-example.git",
    "http_url": "https://example.com/gitlab-org/release-webhook-example.git"
  },
  "url": "https://example.com/gitlab-org/release-webhook-example/-/releases/v1.1",
  "action": "create",
  "assets": {
    "count": 5,
    "links": [
      {
        "id": 1,
        "link_type": "other",
        "name": "Changelog",
        "url": "https://example.net/changelog"
      }
    ],
    "sources": [
      {
        "format": "zip",
        "url": "https://example.com/gitlab-org/release-webhook-example/-/archive/v1.1/release-webhook-example-v1.1.zip"
      },
      {
        "format": "tar.gz",
        "url": "https://example.com/gitlab-org/release-webhook-example/-/archive/v1.1/release-webhook-example-v1.1.tar.gz"
      },
      {
        "format": "tar.bz2",
        "url": "https://example.com/gitlab-org/release-webhook-example/-/archive/v1.1/release-webhook-example-v1.1.tar.bz2"
      },
      {
        "format": "tar",
        "url": "https://example.com/gitlab-org/release-webhook-example/-/archive/v1.1/release-webhook-example-v1.1.tar"
      }
    ]
  },
  "commit": {
    "id": "ee0a3fb31ac16e11b9dbb596ad16d4af654d08f8",
    "message": "Release v1.1",
    "title": "Release v1.1",
    "timestamp": "2020-10-31T14:58:32+11:00",
    "url": "https://example.com/gitlab-org/release-webhook-example/-/commit/ee0a3fb31ac16e11b9dbb596ad16d4af654d08f8",
    "author": {
      "name": "Example User",
      "email": "user@example.com"
    }
  }
}
```

## Événements de jalon {#milestone-events}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/14213) dans GitLab 18.2.

{{< /history >}}

Les événements de jalon sont déclenchés lorsqu'un jalon est créé, fermé, rouvert ou supprimé.

Les valeurs disponibles pour `object_attributes.action` dans le payload sont :

- `create`
- `close`
- `reopen`

En-tête de requête :

```plaintext
X-Gitlab-Event: Milestone Hook
```

Exemple de payload :

```json
{
  "object_kind": "milestone",
  "event_type": "milestone",
  "project": {
    "id": 1,
    "name": "Gitlab Test",
    "description": "Aut reprehenderit ut est.",
    "web_url": "http://example.com/gitlabhq/gitlab-test",
    "avatar_url": null,
    "git_ssh_url": "git@example.com:gitlabhq/gitlab-test.git",
    "git_http_url": "http://example.com/gitlabhq/gitlab-test.git",
    "namespace": "GitlabHQ",
    "visibility_level": 20,
    "path_with_namespace": "gitlabhq/gitlab-test",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "http://example.com/gitlabhq/gitlab-test",
    "url": "http://example.com/gitlabhq/gitlab-test.git",
    "ssh_url": "git@example.com:gitlabhq/gitlab-test.git",
    "http_url": "http://example.com/gitlabhq/gitlab-test.git"
  },
  "object_attributes": {
    "id": 61,
    "iid": 10,
    "title": "v1.0",
    "description": "First stable release",
    "state": "active",
    "created_at": "2025-06-16T14:10:57.000Z",
    "updated_at": "2025-06-16T14:10:57.000Z",
    "due_date": "2025-06-30",
    "start_date": "2025-06-16",
    "group_id": null,
    "project_id": 1
  },
  "action": "create"
}
```

## Événements emoji {#emoji-events}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/123952) dans GitLab 16.2 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `emoji_webhooks`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/417288) dans GitLab 16.3.
- [Activé par défaut](https://gitlab.com/gitlab-org/gitlab/-/issues/417288) dans GitLab 16.4.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/417288) dans GitLab 17.5. Le feature flag `emoji_webhooks` a été supprimé.

{{< /history >}}

Un événement emoji est déclenché lorsqu'une [réaction emoji](../../emoji_reactions.md) est ajoutée ou supprimée sur :

- Les tickets
- Les merge requests
- Extraits de code de projet
- Les pages wiki
- Commentaires sur :
  - Les tickets
  - Les merge requests
  - Extraits de code de projet
  - Les pages wiki
  - Commits

Les valeurs disponibles pour `object_attributes.action` dans le payload sont :

- `award` pour ajouter une réaction
- `revoke` pour supprimer une réaction

En-tête de requête :

```plaintext
X-Gitlab-Event: Emoji Hook
```

Exemple de payload :

```json
{
  "object_kind": "emoji",
  "event_type": "award",
  "user": {
    "id": 1,
    "name": "Blake Bergstrom",
    "username": "root",
    "avatar_url": "http://example.com/uploads/-/system/user/avatar/1/avatar.png",
    "email": "[REDACTED]"
  },
  "project_id": 6,
  "project": {
    "id": 6,
    "name": "Flight",
    "description": "Velit fugit aperiam illum deleniti odio sequi.",
    "web_url": "http://example.com/flightjs/Flight",
    "avatar_url": null,
    "git_ssh_url": "ssh://git@example.com/flightjs/Flight.git",
    "git_http_url": "http://example.com/flightjs/Flight.git",
    "namespace": "Flightjs",
    "visibility_level": 20,
    "path_with_namespace": "flightjs/Flight",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "http://example.com/flightjs/Flight",
    "url": "ssh://git@example.com/flightjs/Flight.git",
    "ssh_url": "ssh://git@example.com/flightjs/Flight.git",
    "http_url": "http://example.com/flightjs/Flight.git"
  },
  "object_attributes": {
    "user_id": 1,
    "created_at": "2023-07-04T20:44:11.000Z",
    "id": 1,
    "name": "thumbsup",
    "awardable_type": "Note",
    "awardable_id": 363,
    "updated_at": "2023-07-04T20:44:11.000Z",
    "action": "award",
    "awarded_on_url": "http://example.com/flightjs/Flight/-/issues/42#note_363"
  },
  "note": {
    "attachment": null,
    "author_id": 1,
    "change_position": null,
    "commit_id": null,
    "created_at": "2023-07-04T15:09:55.000Z",
    "discussion_id": "c3d97fd471f210a5dc8b97a409e3bea95ee06c14",
    "id": 363,
    "line_code": null,
    "note": "Testing 123",
    "noteable_id": 635,
    "noteable_type": "Issue",
    "original_position": null,
    "position": null,
    "project_id": 6,
    "resolved_at": null,
    "resolved_by_id": null,
    "resolved_by_push": null,
    "st_diff": null,
    "system": false,
    "type": null,
    "updated_at": "2023-07-04T19:58:46.000Z",
    "updated_by_id": null,
    "description": "Testing 123",
    "url": "http://example.com/flightjs/Flight/-/issues/42#note_363"
  },
  "issue": {
    "author_id": 1,
    "closed_at": null,
    "confidential": false,
    "created_at": "2023-07-04T14:59:43.000Z",
    "description": "Issue description!",
    "discussion_locked": null,
    "due_date": null,
    "id": 635,
    "iid": 42,
    "last_edited_at": null,
    "last_edited_by_id": null,
    "milestone_id": null,
    "moved_to_id": null,
    "duplicated_to_id": null,
    "project_id": 6,
    "relative_position": 18981,
    "state_id": 1,
    "time_estimate": 0,
    "title": "New issue!",
    "updated_at": "2023-07-04T15:09:55.000Z",
    "updated_by_id": null,
    "weight": null,
    "health_status": null,
    "url": "http://example.com/flightjs/Flight/-/issues/42",
    "total_time_spent": 0,
    "time_change": 0,
    "human_total_time_spent": null,
    "human_time_change": null,
    "human_time_estimate": null,
    "assignee_ids": [
      1
    ],
    "assignee_id": 1,
    "labels": [

    ],
    "state": "opened",
    "severity": "unknown"
  }
}
```

## Événements de jeton d'accès au projet et au groupe {#project-and-group-access-token-events}

{{< history >}}

- Attribut `full_path` [ajouté](https://gitlab.com/gitlab-org/gitlab/-/issues/465421) dans GitLab 17.4.
- Notifications à 60 et 30 jours [généralement disponibles](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/173792) dans GitLab 17.7.

{{< /history >}}

Les événements d'expiration de jeton d'accès se déclenchent avant l'expiration d'un [jeton d'accès](../../../security/tokens/_index.md). Ces événements se déclenchent :

- Sept jours avant l'expiration du jeton
- 30 jours avant l'expiration du jeton (nécessite une configuration)
- 60 jours avant l'expiration du jeton (nécessite une configuration)

Pour plus d'informations sur la configuration des notifications à 30 et 60 jours, consultez :

- [Ajouter des déclencheurs webhook supplémentaires pour l'expiration des jetons d'accès au projet](../settings/_index.md#add-additional-webhook-triggers-for-project-access-token-expiration).
- [Ajouter des déclencheurs webhook supplémentaires pour l'expiration des jetons d'accès au groupe](../../group/manage.md#add-additional-webhook-triggers-for-group-access-token-expiration).

Les valeurs disponibles pour `event_name` dans le payload sont :

- `expiring_access_token`

En-tête de requête :

```plaintext
X-Gitlab-Event: Resource Access Token Hook
```

Exemple de payload pour un projet :

```json
{
  "object_kind": "access_token",
  "project": {
    "id": 7,
    "name": "Flight",
    "description": "Eum dolore maxime atque reprehenderit voluptatem.",
    "web_url": "https://example.com/flightjs/Flight",
    "avatar_url": null,
    "git_ssh_url": "ssh://git@example.com/flightjs/Flight.git",
    "git_http_url": "https://example.com/flightjs/Flight.git",
    "namespace": "Flightjs",
    "visibility_level": 0,
    "path_with_namespace": "flightjs/Flight",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "https://example.com/flightjs/Flight",
    "url": "ssh://git@example.com/flightjs/Flight.git",
    "ssh_url": "ssh://git@example.com/flightjs/Flight.git",
    "http_url": "https://example.com/flightjs/Flight.git"
  },
  "object_attributes": {
    "user_id": 90,
    "created_at": "2024-01-24T16:27:40.000Z",
    "id": 25,
    "name": "acd",
    "expires_at": "2024-01-26",
    "last_used_at": "2024-01-20T10:15:30.000Z"
  },
  "event_name": "expiring_access_token"
}
```

Exemple de payload pour un groupe :

```json
{
  "object_kind": "access_token",
  "group": {
    "group_name": "Twitter",
    "group_path": "twitter",
    "group_id": 35,
    "full_path": "twitter"
  },
  "object_attributes": {
    "user_id": 90,
    "created_at": "2024-01-24T16:27:40.000Z",
    "id": 25,
    "name": "acd",
    "expires_at": "2024-01-26",
    "last_used_at": "2024-01-20T10:15:30.000Z"
  },
  "event_name": "expiring_access_token"
}
```

## Événements de jeton de déploiement de projet et de groupe {#project-and-group-deploy-token-events}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/196804) dans GitLab 18.4 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `project_deploy_token_expiring_notifications`. Fonctionnalité désactivée par défaut.

{{< /history >}}

Les événements d'expiration de jeton de déploiement se déclenchent avant l'expiration d'un [jeton de déploiement](../../../security/tokens/_index.md). Ces événements se déclenchent :

- Sept jours avant l'expiration du jeton.
- 30 jours avant l'expiration du jeton.
- 60 jours avant l'expiration du jeton.

Les valeurs disponibles pour `event_name` dans le payload sont :

- `expiring_deploy_token`

En-tête de requête :

```plaintext
X-Gitlab-Event: Resource Deploy Token Hook
```

Exemple de payload pour un projet :

```json
{
  "object_kind": "deploy_token",
  "project": {
    "id": 2,
    "name": "Gitlab Test",
    "description": "Voluptates sit architecto quos distinctio.",
    "web_url": "https://gitlab.example.com/gitlab-org/gitlab-test",
    "avatar_url": null,
    "git_ssh_url": "ssh://git@gitlab.example.com:2222/gitlab-org/gitlab-test.git",
    "git_http_url": "https://gitlab.example.com/gitlab-org/gitlab-test.git",
    "namespace": "Gitlab Org",
    "visibility_level": 10,
    "path_with_namespace": "gitlab-org/gitlab-test",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "https://gitlab.example.com/gitlab-org/gitlab-test",
    "url": "ssh://git@gitlab.example.com:2222/gitlab-org/gitlab-test.git",
    "ssh_url": "ssh://git@gitlab.example.com:2222/gitlab-org/gitlab-test.git",
    "http_url": "https://gitlab.example.com/gitlab-org/gitlab-test.git"
  },
  "object_attributes": {
    "id": 79,
    "name": "seven-days-6days",
    "expires_at": "2025-08-03T07:57:25.000Z",
    "created_at": "2025-07-28T07:57:25.000Z",
    "revoked": false,
    "deploy_token_type": "project_type"
  },
  "event_name": "expiring_deploy_token"
}
```

## Événements de vulnérabilité {#vulnerability-events}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169701) dans GitLab 17.7 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `vulnerabilities_as_webhook_events`. Fonctionnalité désactivée par défaut.
- La création d'un événement lorsqu'une vulnérabilité est créée ou lorsqu'un ticket est lié à une vulnérabilité a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/176064) dans GitLab 17.8.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/528397) dans GitLab 17.11. Le feature flag `vulnerabilities_as_webhook_events` a été supprimé.

{{< /history >}}

Un événement de vulnérabilité est déclenché dans les cas suivants :

- Une vulnérabilité est créée.
- Le [statut d'une vulnérabilité est modifié](../../application_security/vulnerabilities/_index.md#vulnerability-status-values).
- Un ticket est lié à une vulnérabilité.

En-tête de requête :

```plaintext
X-Gitlab-Event: Vulnerability Hook
```

Exemple de payload :

```json
{
  "object_kind": "vulnerability",
  "object_attributes": {
    "url": "https://example.com/flightjs/Flight/-/security/vulnerabilities/1",
    "title": "REXML DoS vulnerability",
    "state": "confirmed",
    "project_id": 50,
    "location": {
      "file": "Gemfile.lock",
      "dependency": {
        "package": {
          "name": "rexml"
        },
        "version": "3.3.1"
      }
    },
    "cvss": [
      {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "vendor": "NVD"
      }
    ],
    "severity": "high",
    "severity_overridden": false,
    "identifiers": [
      {
        "name": "Gemnasium-29dce398-220a-4315-8c84-16cd8b6d9b05",
        "external_id": "29dce398-220a-4315-8c84-16cd8b6d9b05",
        "external_type": "gemnasium",
        "url": "https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/blob/master/gem/rexml/CVE-2024-41123.yml"
      },
      {
        "name": "CVE-2024-41123",
        "external_id": "CVE-2024-41123",
        "external_type": "cve",
        "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41123"
      }
    ],
    "issues": [
      {
        "title": "REXML ReDoS vulnerability",
        "url": "https://example.com/flightjs/Flight/-/issues/1",
        "created_at": "2025-01-08T00:46:14.429Z",
        "updated_at": "2025-01-08T00:46:14.429Z"
      }
    ],
    "report_type": "dependency_scanning",
    "scanner_external_id": "gitlab-sbom-vulnerability-scanner",
    "confidence": "unknown",
    "confidence_overridden": false,
    "confirmed_at": "2025-01-08T00:46:14.413Z",
    "confirmed_by_id": 1,
    "dismissed_at": null,
    "dismissed_by_id": null,
    "resolved_at": null,
    "resolved_by_id": null,
    "auto_resolved": false,
    "resolved_on_default_branch": false,
    "created_at": "2025-01-08T00:46:14.413Z",
    "updated_at": "2025-01-08T00:46:14.413Z"
  }
}
```

## Événements GitLab Duo flow {#gitlab-duo-flow-events}

{{< details >}}

- Édition : [Gratuite](../../../subscriptions/gitlab_credits.md#for-the-free-tier), GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed
- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249145) dans GitLab 19.4 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `duo_flow_callback_hooks`. Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique. Cette fonctionnalité est disponible à des fins de test, mais n'est pas prête pour une utilisation en production.

Un événement GitLab Duo flow est déclenché lorsqu'un [GitLab Duo flow](../../duo_agent_platform/flows/_index.md) qui référence le webhook change d'état.

Pour recevoir des événements GitLab Duo flow, activez les [rappels webhook](../../duo_agent_platform/flows/webhook_callbacks.md) pour le webhook, puis référencez le webhook lorsque vous déclenchez un flow. GitLab envoie des événements uniquement pour les flows qui référencent le webhook.

Contrairement aux autres types d'événements, les événements GitLab Duo flow ne sont pas sélectionnés dans la section **Déclencheur** du webhook.

En-tête de requête :

```plaintext
X-Gitlab-Event: Duo Flow Callback
```

GitLab envoie les événements suivants :

| Événement            | Déclencheur |
|------------------|---------|
| `flow.started`   | L'agent commence à travailler sur le flow. |
| `flow.completed` | Le flow se termine et produit un message final. |
| `flow.failed`    | Le flow échoue ou se termine sans message final. |

Exemple de charge utile pour `flow.completed` :

```json
{
  "object_kind": "duo_workflow",
  "version": "1",
  "event": "flow.completed",
  "event_id": "f5e5f430-f57b-4e6e-9fac-d9128cd7232f",
  "client_reference": "run-abc123",
  "result": {
    "message": "I corrected the indentation in .gitlab-ci.yml and pushed the change."
  },
  "project": {
    "id": 5,
    "name": "Flight",
    "description": "Example project",
    "web_url": "https://gitlab.example.com/flightjs/Flight",
    "avatar_url": null,
    "git_ssh_url": "git@gitlab.example.com:flightjs/Flight.git",
    "git_http_url": "https://gitlab.example.com/flightjs/Flight.git",
    "namespace": "Flightjs",
    "visibility_level": 20,
    "path_with_namespace": "flightjs/Flight",
    "default_branch": "main",
    "ci_config_path": null,
    "homepage": "https://gitlab.example.com/flightjs/Flight",
    "url": "git@gitlab.example.com:flightjs/Flight.git",
    "ssh_url": "git@gitlab.example.com:flightjs/Flight.git",
    "http_url": "https://gitlab.example.com/flightjs/Flight.git"
  },
  "user": {
    "id": 1,
    "name": "Sidney Jones",
    "username": "sidney_jones",
    "avatar_url": "https://gitlab.example.com/uploads/-/system/user/avatar/1/avatar.png",
    "email": "[REDACTED]"
  },
  "workflow": {
    "id": 1,
    "status": "finished",
    "web_url": "https://gitlab.example.com/flightjs/Flight/-/automate/agent-sessions/1"
  }
}
```

Attributs de la charge utile :

| Attribut          | Type    | Description |
|--------------------|---------|-------------|
| `client_reference` | Chaîne  | Valeur de l'attribut `client_reference` de la requête qui a déclenché le flow. Omis lorsque la requête ne l'a pas défini. |
| `error`            | object  | Raison de l'échec du flow. Présent uniquement pour `flow.failed`. Contient uniquement `reason`. |
| `error.reason`     | Chaîne  | Raison d'échec lisible par machine. `flow_failed` lorsque le flow lui-même a échoué, ou `no_response` lorsque le flow s'est terminé sans message final. Un événement `no_response` a un `workflow.status` de valeur `finished`. |
| `event`            | Chaîne  | Nom de l'événement. L'une des valeurs `flow.started`, `flow.completed` ou `flow.failed`. |
| `event_id`         | Chaîne  | Identifiant de l'événement. Répété lorsque GitLab retente une livraison. Utilisez-le pour ignorer un événement que vous avez déjà traité. |
| `object_kind`      | Chaîne  | Toujours `duo_workflow`. |
| `project`          | object  | Projet dans lequel le flow s'est exécuté. Omis pour un flow exécuté dans un groupe. |
| `result`           | object  | Résultat final du flow. Présent uniquement pour `flow.completed`. |
| `result.message`   | Chaîne  | Message final de l'agent. |
| `user`             | object  | Utilisateur qui a déclenché le flow. |
| `version`          | Chaîne  | Version de la structure de la charge utile. Toujours `1`. |
| `workflow`         | object  | Le flow. |
| `workflow.id`      | Entier | Identifiant du flow. |
| `workflow.status`  | Chaîne  | Statut du flow au moment où GitLab a envoyé l'événement. |
| `workflow.web_url` | Chaîne  | URL de la session de flow dans GitLab. Omis pour un flow exécuté dans un groupe. |

GitLab omet un attribut de niveau supérieur sans valeur plutôt que de l'envoyer comme `null`. Les attributs imbriqués dans les objets `project` et `user` peuvent être `null`.

Une charge utile `flow.failed` contient un objet `error` au lieu d'un objet `result`. L'exemple suivant montre uniquement les attributs qui diffèrent de `flow.completed`. GitLab envoie également `project` et `user` :

```json
{
  "object_kind": "duo_workflow",
  "version": "1",
  "event": "flow.failed",
  "event_id": "02affd2d-2cba-4033-917d-ec22d5dc4b38",
  "client_reference": "run-abc123",
  "error": {
    "reason": "flow_failed"
  },
  "workflow": {
    "id": 1,
    "status": "failed",
    "web_url": "https://gitlab.example.com/flightjs/Flight/-/automate/agent-sessions/1"
  }
}
```

Pour les garanties de livraison de ces événements, consultez [les rappels webhook](../../duo_agent_platform/flows/webhook_callbacks.md#handling-callbacks-in-your-endpoint).
