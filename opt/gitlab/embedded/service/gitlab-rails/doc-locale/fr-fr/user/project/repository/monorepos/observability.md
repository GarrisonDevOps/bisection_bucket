---
stage: Tenant Scale
group: Gitaly
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Métriques pour mesurer les performances des monodépôts
---

Pour mesurer les performances côté serveur de votre monodépôt, utilisez ces métriques. Bien qu'il s'agisse de métriques générales pour mesurer les performances de Gitaly, elles sont particulièrement pertinentes pour les dépôts volumineux.

Les clones et les fetches sont les opérations coûteuses les plus fréquentes. Exprimées en pourcentage des ressources système consommées, ces opérations contribuent souvent à 90 % ou plus des ressources système sur les nœuds Gitaly. Vos logs et métriques fournissent des indications sur l'état de santé de votre dépôt.

## CPU et mémoire {#cpu-and-memory}

Deux RPC (appels de procédure distante) principaux gèrent les clones et les fetches. Utilisez ces champs dans vos logs Gitaly pour vérifier dans quelle mesure les clones et les fetches de dépôt consomment des ressources système. Filtrez vos logs Gitaly selon l'un de ces champs pour en savoir plus :

| Champ de log                         | Valeurs sur lesquelles filtrer                                                                          | Description |
|:----------------------------------|:---------------------------------------------------------------------------------------------|:------------|
| `json.grpc.method`                | `PostReceivePack`                                                                            | Le RPC qui gère les clones et fetches HTTP. |
| `json.grpc.method`                | `SSHReceivePack`                                                                             | Le RPC qui gère les clones et fetches SSH. |
| `json.grpc.code`                  | `OK`                                                                                         | Indique si le RPC a traité sa requête avec succès. |
| `json.grpc.code`                  | `Canceled`                                                                                   | Peut indiquer si le client a interrompu la connexion. Souvent dû à un délai d'expiration. |
| `json.grpc.code`                  | `ResourceExhausted`                                                                          | Indique si la machine lance trop de processus Git simultanément. |
| `json.user_id`                    | Le `user_id` initiant le clone ou le fetch, sous la forme `user-<user_id>`, comme `user-22345` | Identifiez les opérations de clone ou de fetch excessives initiées par un seul utilisateur. |
| `json.username`                   | Le nom d'utilisateur qui a initié le clone ou le fetch.                                               | Identifiez les opérations de clone ou de fetch excessives initiées par un seul utilisateur. |
| `json.grpc.request.glRepository`  | Un dépôt, sous la forme `project-<project_id>`, comme `project-214`                      | Trouvez le nombre total de clones et de fetches pour un seul dépôt. |
| `json.grpc.request.glProjectPath` | Un dépôt, sous la forme d'un chemin de projet, comme `my-org/coolproject`                       | Trouvez le nombre total de clones et de fetches pour un dépôt donné. |

Ces champs d'entrée de log fournissent des informations sur le CPU et la mémoire :

| Champ de log à inspecter       | Description |
|:---------------------------|:------------|
| `json.command.cpu_time_ms` | Temps CPU utilisé par les sous-processus issus de ce RPC. |
| `json.command.maxrss`      | Consommation mémoire des sous-processus issus de ce RPC. |

Dans cet exemple, le message de log `json.command.cpu_time_ms` était `420`, et `json.command.maxrss` était `3342152` :

```json
{
    "command.count":2,
    "command.cpu_time_ms":420,
    "command.inblock":0,
    "command.majflt":0,
    "command.maxrss":3342152,
    "command.minflt":24316,
    "command.oublock":56,
    "command.real_time_ms":626,
    "command.spawn_token_fork_ms":4,
    "command.spawn_token_wait_ms":0,
    "command.system_time_ms":172,
    "command.user_time_ms":248,
    "component":"gitaly.StreamServerInterceptor",
    "correlation_id":"20HCB3DAEPLV08UGNIYT9HJ4JW",
    "environment":"gprd",
    "feature_flags":"",
    "fqdn":"file-99-stor-gprd.c.gitlab-production.internal",
    "grpc.code":"OK",
    "grpc.meta.auth_version":"v2",
    "grpc.meta.client_name":"gitlab-workhorse",
    "grpc.meta.deadline_type":"none",
    "grpc.meta.method_operation":"mutator",
    "grpc.meta.method_scope":"repository",
    "grpc.meta.method_type":"bidi_stream",
    "grpc.method":"PostReceivePack",
    "grpc.request.fullMethod":"/gitaly.SmartHTTPService/PostReceivePack",
    "grpc.request.glProjectPath":"r2414/revenir/development/machinelearning/protein-ddg",
    "grpc.request.glRepository":"project-47506374",
    "grpc.request.payload_bytes":911,
    "grpc.request.repoPath":"@hashed/db/ab/dbabf83f57affedc9a001dc6c6f6b47bb431bd47d7254edd1daf24f0c38793a9.git",
    "grpc.request.repoStorage":"nfs-file99",
    "grpc.response.payload_bytes":54,
    "grpc.service":"gitaly.SmartHTTPService",
    "grpc.start_time":"2023-10-16T20:40:08.836",
    "grpc.time_ms":631.486,
    "hostname":"file-99-stor-gprd",
    "level":"info",
    "msg":"finished streaming call with code OK",
    "pid":1741362,
    "remote_ip":"108.163.136.48",
    "shard":"default",
    "span.kind":"server",
    "stage":"main",
    "system":"grpc",
    "tag":"gitaly",
    "tier":"stor",
    "time":"2023-10-16T20:40:09.467Z",
    "trace.traceid":"AAB3QAeD8G+H9VNmzOi2CztMAcJv1+g4+l1cAgA=",
    "type":"gitaly",
    "user_id":"user-14857500",
    "username":"ctx_ckottke",
  }
```

## Distribution des lectures {#read-distribution}

Pour vérifier le nombre de lectures sur chaque nœud Gitaly, consultez `gitaly_praefect_read_distribution`. Cette métrique Prometheus est un [compteur](https://prometheus.io/docs/concepts/metric_types/#counter) et comporte deux vecteurs :

| Nom de la métrique                         | Vecteur            | Description |
|-------------------------------------|-------------------|-------------|
| `gitaly_praefect_read_distribution` | `virtual_storage` | Le nom du [stockage virtuel](../../../../administration/gitaly/praefect/_index.md). |
| `gitaly_praefect_read_distribution` | `storage`         | Le nom du stockage Gitaly. |

## Cache pack objects {#pack-objects-cache}

Pour vérifier le [cache pack objects](../../../../administration/gitaly/configure_gitaly.md#pack-objects-cache), consultez vos logs et vos métriques Prometheus :

| Nom du champ de log                        | Description |
|:--------------------------------------|:------------|
| `pack_objects_cache.hit`              | Indique si le cache pack-objects actuel a été atteint. (`true` ou `false`) |
| `pack_objects_cache.key`              | Clé de cache utilisée pour le cache pack-objects. |
| `pack_objects_cache.generated_bytes`  | Taille en octets du nouveau cache en cours d'écriture. |
| `pack_objects_cache.served_bytes`     | Taille en octets du cache en cours de distribution. |
| `pack_objects.compression_statistics` | Statistiques pour la génération de pack-objects. |
| `pack_objects.enumerate_objects_ms`   | Temps total, en ms, passé à énumérer les objets envoyés par les clients. |
| `pack_objects.prepare_pack_ms`        | Temps total, en ms, passé à préparer le packfile avant de le renvoyer au client |
| `pack_objects.write_pack_file_ms`     | Temps total, en ms, passé à renvoyer le packfile au client. Très dépendant de la connexion internet du client. |
| `pack_objects.written_object_count`   | Nombre total d'objets que Gitaly a renvoyés au client. |

Exemple de message de log :

```json
{
"bytes":26186490,
"correlation_id":"01F1MY8JXC3FZN14JBG1H42G9F",
"grpc.meta.deadline_type":"none",
"grpc.method":"PackObjectsHook",
"grpc.request.fullMethod":"/gitaly.HookService/PackObjectsHook",
"grpc.request.glProjectPath":"root/gitlab-workhorse",
"grpc.request.glRepository":"project-2",
"grpc.request.repoPath":"@hashed/d4/73/d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35.git",
"grpc.request.repoStorage":"default",
"grpc.request.topLevelGroup":"@hashed",
"grpc.service":"gitaly.HookService",
"grpc.start_time":"2021-03-25T14:57:52.747Z",
"level":"info",
"msg":"finished unary call with code OK",
"peer.address":"@",
"pid":20961,
"span.kind":"server",
"system":"grpc",
"time":"2021-03-25T14:57:53.543Z",
"pack_objects.compression_statistics": "Total 145991 (delta 68), reused 6 (delta 2), pack-reused 145911",
"pack_objects.enumerate_objects_ms": 170,
"pack_objects.prepare_pack_ms": 7,
"pack_objects.write_pack_file_ms": 786,
"pack_objects.written_object_count": 145991,
"pack_objects_cache.generated_bytes": 49533030,
"pack_objects_cache.hit": "false",
"pack_objects_cache.key": "123456789",
"pack_objects_cache.served_bytes": 49533030,
"peer.address": "127.0.0.1",
"pid": 8813,
}
```

| Nom de la métrique Prometheus                    | Vecteur   | Description |
|:------------------------------------------|:---------|:------------|
| `gitaly_pack_objects_served_bytes_total`  |          | Taille (en octets) du cache en cours de distribution. |
| `gitaly_pack_objects_cache_lookups_total` | `result` | Indique si une recherche dans le cache a abouti à un `hit` ou un `miss`. |
