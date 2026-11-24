---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Configurer l'agent GitLab pour Kubernetes afin de prendre en charge les workspaces."
title: Paramètres du workspace
---

Les paramètres du workspace configurent la façon dont l'agent GitLab pour Kubernetes gère les environnements de développement à distance dans votre cluster Kubernetes. Ces paramètres contrôlent :

- Allocation des ressources
- Sécurité
- Mise en réseau
- Gestion du cycle de vie

## Configurer une configuration de workspace de base {#set-up-a-basic-workspace-configuration}

Pour configurer une configuration de workspace de base :

1. Ouvrez votre fichier de configuration YAML.
1. Ajoutez ces paramètres minimaux requis :

   ```yaml
   remote_development:
     enabled: true
     dns_zone: "<workspaces.example.dev>"
   ```

1. Commitez les modifications.

Si votre configuration de workspace ne fonctionne pas, consultez [Dépannage des workspaces](workspaces_troubleshooting.md).

> [!note]
> Si un paramètre a une valeur non valide, il n'est pas possible de mettre à jour un quelconque paramètre tant que vous n'avez pas corrigé cette valeur. La mise à jour de ces paramètres, à l'exception de `enabled`, n'affecte pas les workspaces existants.

## Référence de configuration {#configuration-reference}

| Paramètre                                                                                   | Description                                                                                   | Format                                                      | Valeur par défaut                           | Obligatoire |
|-------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|-------------------------------------------------------------|-----------------------------------------|----------|
| [`enabled`](#enabled)                                                                     | Indique si le développement à distance est activé pour l'agent GitLab pour Kubernetes.                         | Booléen                                                     | `false`                                 | Oui      |
| [`dns_zone`](#dns_zone)                                                                   | Zone DNS où les workspaces sont disponibles.                                                      | Chaîne. Format DNS valide.                                   | Aucune                                    | Oui      |
| [`gitlab_workspaces_proxy`](#gitlab_workspaces_proxy)                                     | Espace de nommage où [`gitlab-workspaces-proxy`](set_up_gitlab_agent_and_proxies.md) est installé. | Chaîne. Nom d'espace de nommage Kubernetes valide.                    | `gitlab-workspaces`                     | Non       |
| [`network_policy`](#network_policy)                                                       | Règles de pare-feu pour les workspaces.                                                                | Objet contenant les champs `enabled` et `egress`.            | Voir [`network_policy`](#network_policy) | Non       |
| [`default_resources_per_workspace_container`](#default_resources_per_workspace_container) | Requêtes et limites par défaut pour le CPU et la mémoire par conteneur de workspace.                       | Objet avec `requests` et `limits` pour le CPU et la mémoire.     | `{}`                                    | Non       |
| [`max_resources_per_workspace`](#max_resources_per_workspace)                             | Requêtes et limites maximales pour le CPU et la mémoire par workspace.                                 | Objet avec `requests` et `limits` pour le CPU et la mémoire      | `{}`                                    | Non       |
| [`workspaces_quota`](#workspaces_quota)                                                   | Nombre maximal de workspaces pour l'agent GitLab pour Kubernetes.                                            | Entier                                                     | `-1`                                    | Non       |
| [`workspaces_per_user_quota`](#workspaces_per_user_quota)                                 | Nombre maximal de workspaces par utilisateur.                                                        | Entier                                                     | `-1`                                    | Non       |
| [`use_kubernetes_user_namespaces`](#use_kubernetes_user_namespaces)                       | Indique s'il faut utiliser les espaces de nommage utilisateur dans Kubernetes.                                       | Booléen : `true` ou `false`                                  | `false`                                 | Non       |
| [`default_runtime_class`](#default_runtime_class)                                         | `RuntimeClass` Kubernetes par défaut.                                                            | Chaîne. Nom `RuntimeClass` valide.                          | `""`                                    | Non       |
| [`allow_privilege_escalation`](#allow_privilege_escalation)                               | Autoriser l'élévation de privilèges.                                                                   | Booléen                                                     | `false`                                 | Non       |
| [`image_pull_secrets`](#image_pull_secrets)                                               | Secrets Kubernetes existants pour extraire des images privées pour les workspaces.                            | Tableau d'objets avec les champs `name` et `namespace`.        | `[]`                                    | Non       |
| [`annotations`](#annotations)                                                             | Annotations à appliquer aux objets Kubernetes.                                                   | Carte de paires clé-valeur. Format d'annotation Kubernetes valide. | `{}`                                    | Non       |
| [`labels`](#labels)                                                                       | Labels à appliquer aux objets Kubernetes.                                                        | Carte de paires clé-valeur. Format de label Kubernetes valide       | `{}`                                    | Non       |
| [`max_active_hours_before_stop`](#max_active_hours_before_stop)                           | Nombre maximal d'heures pendant lesquelles un workspace peut être actif avant d'être arrêté.                       | Entier                                                     | `36`                                    | Non       |
| [`max_stopped_hours_before_termination`](#max_stopped_hours_before_termination)           | Nombre maximal d'heures pendant lesquelles un workspace peut être arrêté avant d'être terminé.                   | Entier                                                     | `744`                                   | Non       |
| [`shared_namespace`](#shared_namespace)                                                   | Indique s'il faut utiliser un espace de nommage Kubernetes partagé.                                    | Chaîne                                                      | `""`                                    | Non       |

### `enabled` {#enabled}

Utilisez ce paramètre pour définir si :

- L'agent GitLab pour Kubernetes peut communiquer avec l'instance GitLab.
- Vous pouvez [créer un workspace](configuration.md#create-a-workspace) avec l'agent GitLab pour Kubernetes.

La valeur par défaut est `false`.

Pour activer le développement à distance dans la configuration de l'agent, définissez `enabled` sur `true` :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  enabled: true
```

> [!note]
> Si `enabled` est défini sur `false` pour un agent qui a des workspaces actifs ou arrêtés, ces workspaces deviennent orphelins et inutilisables.
>
> Avant de désactiver le développement à distance sur un agent :
>
> - Assurez-vous que tous les workspaces associés ne sont plus nécessaires.
> - Supprimez manuellement tous les workspaces en cours d'exécution pour les retirer du cluster Kubernetes.

### `dns_zone` {#dns_zone}

Utilisez ce paramètre pour définir la zone DNS de l'URL où les workspaces sont disponibles.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  dns_zone: "<workspaces.example.dev>"
```

### `gitlab_workspaces_proxy` {#gitlab_workspaces_proxy}

Utilisez ce paramètre pour définir l'espace de nommage où [`gitlab-workspaces-proxy`](set_up_gitlab_agent_and_proxies.md) est installé. La valeur par défaut de `gitlab_workspaces_proxy.namespace` est `gitlab-workspaces`.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  gitlab_workspaces_proxy:
    namespace: "<custom-gitlab-workspaces-proxy-namespace>"
```

### `network_policy` {#network_policy}

Utilisez ce paramètre pour définir la politique réseau de chaque workspace. Ce paramètre contrôle le trafic réseau pour les workspaces.

La valeur par défaut est :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  network_policy:
    enabled: true
    egress:
      - allow: "0.0.0.0/0"
        except:
          - "10.0.0.0/8"
          - "172.16.0.0/12"
          - "192.168.0.0/16"
```

Dans cette configuration :

- La politique réseau est générée pour chaque workspace car `enabled` est `true`.
- Les règles d'egress autorisent tout le trafic vers Internet (`0.0.0.0/0`) sauf vers les plages IP CIDR `10.0.0.0/8`, `172.16.0.0/12` et `192.168.0.0/16`.

Le comportement de la politique réseau dépend du plugin réseau Kubernetes. Pour plus d'informations, consultez la [documentation Kubernetes](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

#### `network_policy.enabled` {#network_policyenabled}

Utilisez ce paramètre pour définir si la politique réseau est générée pour chaque workspace. La valeur par défaut de `network_policy.enabled` est `true`.

#### `network_policy.egress` {#network_policyegress}

Utilisez ce paramètre pour définir une liste de plages IP CIDR à autoriser comme destinations d'egress depuis un workspace.

Définissez des règles d'egress dans les cas suivants :

- L'instance GitLab se trouve sur une plage IP privée.
- Le workspace doit accéder à une ressource cloud sur une plage IP privée.

Chaque élément de la liste définit un attribut `allow` avec un attribut facultatif `except`. `allow` définit une plage IP pour autoriser le trafic. `except` liste les plages IP à exclure de la plage `allow`.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  network_policy:
    egress:
      - allow: "0.0.0.0/0"
        except:
          - "10.0.0.0/8"
          - "172.16.0.0/12"
          - "192.168.0.0/16"
      - allow: "172.16.123.1/32"
```

Dans cet exemple, le trafic en provenance du workspace est autorisé si :

- L'IP de destination correspond à n'importe quelle plage sauf `10.0.0.0/8`, `172.16.0.0/12` ou `192.168.0.0/16`.
- L'IP de destination est `172.16.123.1/32`.

### `default_resources_per_workspace_container` {#default_resources_per_workspace_container}

Utilisez ce paramètre pour définir les [requêtes et limites](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits) par défaut pour le CPU et la mémoire par conteneur de workspace. Toutes les ressources que vous définissez dans votre [devfile](_index.md#devfile) remplacent ce paramètre.

Pour `default_resources_per_workspace_container`, `requests` et `limits` sont requis. Pour plus d'informations sur les valeurs possibles de CPU et de mémoire, consultez [Unités de ressources dans Kubernetes](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#resource-units-in-kubernetes).

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  default_resources_per_workspace_container:
    requests:
      cpu: "0.5"
      memory: "512Mi"
    limits:
      cpu: "1"
      memory: "1Gi"
```

### `max_resources_per_workspace` {#max_resources_per_workspace}

Utilisez ce paramètre pour définir les [requêtes et limites](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits) maximales pour le CPU et la mémoire par workspace.

Pour `max_resources_per_workspace`, `requests` et `limits` sont requis. Pour plus d'informations sur les valeurs possibles de CPU et de mémoire, consultez :

- [Unités de ressources dans Kubernetes](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#resource-units-in-kubernetes)
- [Quotas de ressources](https://kubernetes.io/docs/concepts/policy/resource-quotas/)

Les workspaces échouent lorsqu'ils dépassent les valeurs que vous avez définies pour `requests` et `limits`.

> [!note]
> Si [`shared_namespace`](#shared_namespace) est défini, `max_resources_per_workspace` doit être un hachage vide. Les utilisateurs peuvent créer un [quota de ressources](https://kubernetes.io/docs/concepts/policy/resource-quotas/) Kubernetes dans le `shared_namespace` pour obtenir le même résultat que la spécification de cette valeur ici.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  max_resources_per_workspace:
    requests:
      cpu: "1"
      memory: "1Gi"
    limits:
      cpu: "2"
      memory: "2Gi"
```

Les ressources maximales que vous définissez doivent inclure toutes les ressources requises par les conteneurs init pour effectuer des opérations d'amorçage telles que le clonage du dépôt du projet.

### `workspaces_quota` {#workspaces_quota}

Utilisez ce paramètre pour définir le nombre maximal de workspaces pour l'agent GitLab pour Kubernetes.

Vous ne pouvez pas créer de nouveaux workspaces pour un agent dans les cas suivants :

- Le nombre de workspaces pour l'agent a atteint le `workspaces_quota` défini.
- `workspaces_quota` est défini sur `0`.

Si `workspaces_quota` est défini sur une valeur inférieure au nombre de workspaces non terminés pour un agent, les workspaces de l'agent ne sont pas terminés automatiquement.

La valeur par défaut est `-1` (illimité). Les valeurs possibles sont supérieures ou égales à `-1`.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  workspaces_quota: 10
```

### `workspaces_per_user_quota` {#workspaces_per_user_quota}

Utilisez ce paramètre pour définir le nombre maximal de workspaces par utilisateur.

Vous ne pouvez pas créer de nouveaux workspaces pour un utilisateur dans les cas suivants :

- Le nombre de workspaces pour l'utilisateur a atteint le `workspaces_per_user_quota` défini.
- `workspaces_per_user_quota` est défini sur `0`.

Si `workspaces_per_user_quota` est défini sur une valeur inférieure au nombre de workspaces non terminés pour un utilisateur, les workspaces de l'utilisateur ne sont pas terminés automatiquement.

La valeur par défaut est `-1` (illimité). Les valeurs possibles sont supérieures ou égales à `-1`.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  workspaces_per_user_quota: 3
```

### `use_kubernetes_user_namespaces` {#use_kubernetes_user_namespaces}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/13983) dans GitLab 17.4.

{{< /history >}}

Utilisez ce paramètre pour spécifier si la fonctionnalité d'espaces de nommage utilisateur doit être utilisée dans Kubernetes.

Les [espaces de nommage utilisateur](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/) isolent l'utilisateur exécuté dans le conteneur de l'utilisateur sur l'hôte.

La valeur par défaut est `false`. Avant de définir la valeur sur `true`, assurez-vous que votre cluster Kubernetes prend en charge les espaces de nommage utilisateur.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  use_kubernetes_user_namespaces: true
```

Pour plus d'informations sur `use_kubernetes_user_namespaces`, consultez [les espaces de nommage utilisateur](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/).

### `default_runtime_class` {#default_runtime_class}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/13983) dans GitLab 17.4.

{{< /history >}}

Utilisez ce paramètre pour sélectionner la configuration du runtime de conteneur utilisée pour exécuter les conteneurs dans le workspace.

La valeur par défaut est `""`, ce qui indique l'absence de valeur.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  default_runtime_class: "example-runtime-class-name"
```

Une valeur valide :

- Contient 253 caractères ou moins.
- Contient uniquement des lettres minuscules, des chiffres, `-` ou `.`.
- Commence par un caractère alphanumérique
- Se termine par un caractère alphanumérique.

Pour plus d'informations sur `default_runtime_class`, consultez [Runtime Class](https://kubernetes.io/docs/concepts/containers/runtime-class/).

### `allow_privilege_escalation` {#allow_privilege_escalation}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/13983) dans GitLab 17.4.

{{< /history >}}

Utilisez ce paramètre pour contrôler si un processus peut obtenir plus de privilèges que son processus parent.

Ce paramètre contrôle directement si le flag [`no_new_privs`](https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt) est défini sur le processus du conteneur.

La valeur par défaut est `false`. La valeur peut être définie sur `true` uniquement si l'une des conditions suivantes est remplie :

- [`default_runtime_class`](#default_runtime_class) est défini sur une valeur non vide.
- [`use_kubernetes_user_namespaces`](#use_kubernetes_user_namespaces) est défini sur `true`.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  default_runtime_class: "example-runtime-class-name"
  allow_privilege_escalation: true
```

Pour plus d'informations sur `allow_privilege_escalation`, consultez [Configurer un contexte de sécurité pour un pod ou un conteneur](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

### `image_pull_secrets` {#image_pull_secrets}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/14664) dans GitLab 17.6.

{{< /history >}}

Utilisez ce paramètre pour spécifier les secrets Kubernetes existants de type `kubernetes.io/dockercfg` ou `kubernetes.io/dockerconfigjson` requis par les workspaces pour extraire des images privées.

La valeur par défaut est `[]`.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  image_pull_secrets:
    - name: "image-pull-secret-name"
      namespace: "image-pull-secret-namespace"
```

Dans cet exemple, le secret `image-pull-secret-name` de l'espace de nommage `image-pull-secret-namespace` est synchronisé avec l'espace de nommage du workspace.

Pour `image_pull_secrets`, les attributs `name` et `namespace` sont requis. Le nom du secret doit être unique. Si [`shared_namespace`](#shared_namespace) est défini, l'espace de nommage du secret doit être identique au `shared_namespace`.

Si le secret que vous avez spécifié n'existe pas dans le cluster Kubernetes, le secret est ignoré. Lorsque vous supprimez ou mettez à jour le secret, celui-ci est supprimé ou mis à jour dans tous les espaces de nommage des workspaces où le secret est référencé.

### `annotations` {#annotations}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/13983) dans GitLab 17.4.

{{< /history >}}

Utilisez ce paramètre pour attacher des métadonnées arbitraires non identifiantes aux objets Kubernetes.

La valeur par défaut est `{}`.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  annotations:
    "example.com/key": "value"
```

Une clé d'annotation valide est une chaîne composée de deux parties :

- Facultatif. Un préfixe. Le préfixe doit contenir 253 caractères ou moins et des labels DNS séparés par des points. Le préfixe doit se terminer par une barre oblique (`/`).
- Un nom. Le nom doit contenir 63 caractères ou moins et uniquement des caractères alphanumériques, des tirets (`-`), des traits de soulignement (`_`) et des points (`.`). Le nom doit commencer et se terminer par un caractère alphanumérique.

Vous ne devriez pas utiliser de préfixes se terminant par `kubernetes.io` et `k8s.io` car ils sont réservés aux composants Kubernetes principaux. Les préfixes se terminant par `gitlab.com` sont également réservés.

Une valeur d'annotation valide est une chaîne.

Pour plus d'informations sur `annotations`, consultez [Annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/).

### `labels` {#labels}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/13983) dans GitLab 17.4.

{{< /history >}}

Utilisez ce paramètre pour attacher des métadonnées d'identification arbitraires aux objets Kubernetes.

La valeur par défaut est `{}`.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  labels:
    "example.com/key": "value"
```

Une clé de label est une chaîne composée de deux parties :

- Facultatif. Un préfixe. Le préfixe doit contenir 253 caractères ou moins et des labels DNS séparés par des points. Le préfixe doit se terminer par une barre oblique (`/`).
- Un nom. Le nom doit contenir 63 caractères ou moins et uniquement des caractères alphanumériques, des tirets (`-`), des traits de soulignement (`_`) et des points (`.`). Le nom doit commencer et se terminer par un caractère alphanumérique.

Vous ne devriez pas utiliser de préfixes se terminant par `kubernetes.io` et `k8s.io` car ils sont réservés aux composants Kubernetes principaux. Les préfixes se terminant par `gitlab.com` sont également réservés.

Une valeur de label valide :

- Contient 63 caractères ou moins. La valeur peut être vide.
- Commence et se termine par un caractère alphanumérique.
- Peut contenir des tirets (`-`), des traits de soulignement (`_`) et des points (`.`).

Pour plus d'informations sur `labels`, consultez [Labels](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/).

### `max_active_hours_before_stop` {#max_active_hours_before_stop}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/14910) dans GitLab 17.6.

{{< /history >}}

Ce paramètre arrête automatiquement les workspaces de l'agent après qu'ils ont été actifs pendant le nombre d'heures spécifié. Un état actif est tout état autre qu'arrêté ou terminé.

Le minuteur de ce paramètre démarre lorsque vous créez le workspace et est réinitialisé chaque fois que vous redémarrez le workspace. Il s'applique également même si le workspace est dans un état d'erreur ou d'échec.

La valeur par défaut est `36`, soit un jour et demi. Cela évite d'arrêter le workspace pendant les heures de travail habituelles de l'utilisateur.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  max_active_hours_before_stop: 60
```

Une valeur valide :

- Est un entier.
- Est supérieure ou égale à `1`.
- Est inférieure ou égale à `8760` (un an).
- `max_active_hours_before_stop` + `max_stopped_hours_before_termination` doit être inférieur ou égal à `8760`.

L'arrêt automatique est uniquement déclenché lors d'une réconciliation complète, qui a lieu toutes les heures. Cela signifie que le workspace peut rester actif jusqu'à une heure de plus que la valeur configurée.

### `max_stopped_hours_before_termination` {#max_stopped_hours_before_termination}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/14910) dans GitLab 17.6.

{{< /history >}}

Utilisez ce paramètre pour terminer automatiquement les workspaces de l'agent après qu'ils ont été dans l'état arrêté pendant le nombre d'heures spécifié.

La valeur par défaut est `722`, soit environ un mois.

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  max_stopped_hours_before_termination: 4332
```

Une valeur valide :

- Est un entier.
- Est supérieure ou égale à `1`.
- Est inférieure ou égale à `8760` (un an).
- `max_active_hours_before_stop` + `max_stopped_hours_before_termination` doit être inférieur ou égal à `8760`.

La terminaison automatique est uniquement déclenchée lors d'une réconciliation complète, qui a lieu toutes les heures. Cela signifie que le workspace peut rester arrêté jusqu'à une heure de plus que la valeur configurée.

### `shared_namespace` {#shared_namespace}

{{< history >}}

- [Introduite](https://gitlab.com/groups/gitlab-org/-/epics/12327) dans GitLab 18.0.

{{< /history >}}

Utilisez ce paramètre pour spécifier un espace de nommage Kubernetes partagé pour tous les workspaces.

La valeur par défaut est `""`, ce qui crée chaque nouveau workspace dans son propre espace de nommage Kubernetes distinct.

Lorsque vous spécifiez une valeur, tous les workspaces existent dans cet espace de nommage Kubernetes plutôt que dans des espaces de nommage individuels.

La définition d'une valeur pour `shared_namespace` impose des restrictions sur les valeurs acceptables pour [`image_pull_secrets`](#image_pull_secrets) et [`max_resources_per_workspace`](#max_resources_per_workspace).

Exemple de configuration :

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  shared_namespace: "example-shared-namespace"
```

Une valeur valide :

- Contient au maximum 63 caractères.
- Contient uniquement des caractères alphanumériques minuscules ou '-'.
- Commence par un caractère alphanumérique.
- Se termine par un caractère alphanumérique.

Pour plus d'informations sur les espaces de nommage Kubernetes, consultez [Namespaces](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/).

## Exemple de configuration complète {#complete-example-configuration}

La configuration suivante est un exemple de configuration complète. Elle inclut tous les paramètres disponibles dans la [référence de configuration](#configuration-reference) :

```yaml
remote_development:
  enabled: true
  dns_zone: workspaces.dev.test
  gitlab_workspaces_proxy:
    namespace: "gitlab-workspaces"

  network_policy:
    enabled: true
    egress:
      - allow: "0.0.0.0/0"
        except:
          - "10.0.0.0/8"
          - "172.16.0.0/12"
          - "192.168.0.0/16"

  default_resources_per_workspace_container:
    requests:
      cpu: "0.5"
      memory: "512Mi"
    limits:
      cpu: "1"
      memory: "1Gi"

  max_resources_per_workspace:
    requests:
      cpu: "1"
      memory: "1Gi"
    limits:
      cpu: "2"
      memory: "4Gi"

  workspaces_quota: 10
  workspaces_per_user_quota: 3

  use_kubernetes_user_namespaces: false
  default_runtime_class: "standard"
  allow_privilege_escalation: false

  image_pull_secrets:
    - name: "registry-secret"
      namespace: "default"

  annotations:
    environment: "production"
    team: "engineering"

  labels:
    app: "workspace"
    tier: "development"

  max_active_hours_before_stop: 60
  max_stopped_hours_before_termination: 4332
  shared_namespace: ""
```
